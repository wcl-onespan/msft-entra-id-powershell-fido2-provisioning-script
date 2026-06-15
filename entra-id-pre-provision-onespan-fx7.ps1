#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-provisions OneSpan FX7 FIDO2 security keys in Microsoft Entra ID on behalf of users.
    Supports single-user registration via UPN/SerialID parameters or bulk registration via CSV.

.DESCRIPTION
    Connects to Microsoft Graph using delegated admin credentials and registers OneSpan FX7
    FIDO2 passkeys on behalf of target users without requiring end-user interaction.

    - Validates the tenant FIDO2 policy (self-service setup flag and key restriction allow/block
      lists) before attempting any credential ceremony.
    - Drives the WebAuthn credential ceremony using DSInternals.Passkeys (Get-EntraPasskeyRegistrationOptions
      and New-Passkey), then posts the credential directly to the Graph Beta API, bypassing the
      DSInternals serialiser which changed behaviour in v3.2.0.
    - Extracts the AAGUID from the returned authenticatorData and warns if a different
      authenticator (e.g. Windows Hello) intercepted the ceremony.
    - On BadRequest, performs a live FIDO Alliance MDS3 lookup to validate the connected key's
      AAGUID against known OneSpan devices and emits a detailed diagnostic.
    - Verifies successful registration by querying Get-MgBetaUserAuthenticationFido2Method.

    Requires Windows. DSInternals.Passkeys uses the Windows WebAuthn API (webauthn.dll),
    which is not available on Linux or macOS.

.PARAMETER TenantId
    The Microsoft Entra ID tenant identifier, e.g. "contoso.onmicrosoft.com" or a tenant GUID.
    If omitted, the script prompts interactively.

.PARAMETER UPN
    User Principal Name of the target user, e.g. "user@contoso.com".
    Required for single-user mode. If omitted (and -CsvFilePath is not provided), the script prompts interactively.

.PARAMETER SerialID
    Serial number of the OneSpan FX7 device being assigned to the user, e.g. "FX7-12345678".
    Hyphens are stripped automatically. If omitted (and -CsvFilePath is not provided), the script prompts interactively.

.PARAMETER CsvFilePath
    Path to a CSV file for bulk registration. The file must include a header row with columns UPN and SerialID.
    If omitted and UPN/SerialID are also not provided, the script prompts interactively.

.PARAMETER DisplayName
    Override for the passkey display name. Defaults to "OneSpan FX7 {SerialID}" (with hyphens stripped).
    Rarely needed; the default matches the display name used for verification and duplicate detection.

.EXAMPLE
    # Single-user registration
    .\entra-id-pre-provision-onespan-fx7.ps1 -TenantId "contoso.onmicrosoft.com" -UPN "user@contoso.com" -SerialID "FX7-12345678"

.EXAMPLE
    # Bulk registration from CSV
    .\entra-id-pre-provision-onespan-fx7.ps1 -TenantId "contoso.onmicrosoft.com" -CsvFilePath ".\users.csv"

.NOTES
    Author:       Will LaSala (OneSpan)
    Company:      OneSpan
    License:      MIT
    Version:      1.1.0
    Changelog:    See CHANGELOG.md
    Dependencies: Microsoft.Graph.Identity.SignIns (MinimumVersion 2.26.0)
                  DSInternals.Passkeys             (MinimumVersion 3.1.0)

    CSV Schema (bulk mode):
        UPN        — User Principal Name of the target user
        SerialID   — Serial number of the OneSpan FX7 device (hyphens optional)

.PRIVACY
    No telemetry or data is collected. All operations remain local unless interacting
    with the Microsoft Graph API and the FIDO Alliance MDS3 metadata service (queried
    only on BadRequest to validate the connected key's AAGUID).
#>

param (
    [string]$TenantId, # Your tenant ID, example: "xyz.onmicrosoft.com"

    [string]$CsvFilePath, # Path to the CSV file containing UPN and SerialID

    [string]$UPN,  # User Principal Name of the user you want to register the OneSpan FX7 key for, example: "user@zyx.domain.com"

    [string]$SerialID, # Serial number of the OneSpan FX device being assigned to the user.

    [string]$DisplayName = "OneSpan FX7 $SerialID"
)

function Ensure-Module {
    param (
        [string]$ModuleName,
        [version]$MinimumVersion
    )
    $installed = Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $installed -or ($MinimumVersion -and $installed.Version -lt $MinimumVersion)) {
        Install-Module -Name $ModuleName -Scope CurrentUser -Force -ErrorAction Stop
    }
}

# Function to connect to Microsoft Graph
function Connect-ToMsGraph {
    param (
        [string]$TenantId
    )
    try {
        Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All","Policy.Read.All" -TenantId $TenantId -ErrorAction Stop
    } catch {
        # -ErrorAction Continue so the error is written to the stream before we re-throw.
        # Functions should not call exit; the caller (main script body) terminates the process.
        Write-Error "Failed to connect to Microsoft Graph: $_" -ErrorAction Continue
        throw
    }
}

# Fetches all FIDO2 authenticator AAGUIDs for a given vendor from the FIDO Alliance MDS3.
# MDS3 is a signed JWT; we decode the payload without verifying the signature (informational use only).
# Returns an array of lowercase hyphenated AAGUID strings.
function Get-FidoMdsAAGUIDs {
    param (
        [string]$VendorPattern = 'OneSpan'
    )
    try {
        Write-Verbose "Querying FIDO Alliance MDS3 for '$VendorPattern' authenticators..."
        $response = Invoke-WebRequest -Uri 'https://mds.fidoalliance.org/' -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
        # JWT has three dot-separated sections; we want the payload (index 1)
        $b64 = $response.Content.Trim().Split('.')[1]
        $remainder = $b64.Length % 4
        if ($remainder -ne 0) { $b64 += '=' * (4 - $remainder) }
        $b64 = $b64.Replace('-', '+').Replace('_', '/')
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
        $mds = $json | ConvertFrom-Json
        $vendorEntries = $mds.entries | Where-Object {
            $_.aaguid -and (
                ($_.metadataStatement -and $_.metadataStatement.description -match $VendorPattern) -or
                ($_.description -match $VendorPattern)
            )
        }
        $aaGuids = @($vendorEntries | ForEach-Object { $_.aaguid.ToLower() })
        Write-Verbose "Found $($aaGuids.Count) AAGUID(s) for '$VendorPattern' in FIDO MDS."
        return $aaGuids
    } catch {
        Write-Verbose "Could not fetch FIDO MDS: $_"
        return @()
    }
}

# Converts a value that may be either a byte[] or already a base64url string into a base64url string.
# DSInternals.Passkeys credential response properties changed representation across versions.
function ConvertTo-Base64Url {
    param ([object]$Value)
    if ($Value -is [byte[]]) {
        return [Convert]::ToBase64String($Value).Replace('+', '-').Replace('/', '_').TrimEnd('=')
    }
    # Already a string — assume it is base64url (no padding, url-safe alphabet)
    return [string]$Value
}

# Function to register the passkey on the FIDO2 key
function Create-and-Register-Passkey {
    param (
        [string]$UPN,
        [string]$DisplayName
    )
    try {
        $options    = Get-EntraPasskeyRegistrationOptions -UserId $UPN -ErrorAction Stop
        $credential = $options | New-Passkey -ErrorAction Stop

        # Build the POST body ourselves instead of using Register-EntraPasskey.
        # DSInternals.Passkeys 3.2.0 changed MicrosoftGraphWebauthnAttestationResponse.ToString()
        # to emit the raw OS credential JSON, omitting the {displayName, publicKeyCredential} wrapper
        # that the Graph API requires. PowerShell 5.1 cannot unload the in-process DLL to downgrade,
        # so we bypass the broken serializer entirely and call Invoke-MgGraphRequest directly.
        #
        # Response properties are byte[] in 3.1.0 and may be strings in 3.2.0 verbatim-JSON mode;
        # ConvertTo-Base64Url handles both.
        # Id is byte[] in all versions — base64url-encode it.
        $credId = ConvertTo-Base64Url $credential.Id

        # AuthenticatorResponse.ClientData (byte[]) serializes as JSON property "clientDataJSON".
        # ClientDataJson (string) is [JsonIgnore] — a computed decoded string, never serialized.
        # AuthenticatorAttestationResponse.AttestationObject (byte[]) serializes as "attestationObject".
        $clientDataJSON    = ConvertTo-Base64Url $credential.Response.ClientData
        $attestationObject = ConvertTo-Base64Url $credential.Response.AttestationObject

        # Extract the AAGUID from authenticatorData (offset 37, 16 bytes) to detect if Windows
        # Hello intercepted the credential ceremony instead of the physical FX7.
        # AuthenticatorData layout: rpIdHash[32] + flags[1] + signCount[4] + aaguid[16] + ...
        # The try/catch IS the type/length guard — null or short authData causes indexing to throw,
        # which is caught and logged at Verbose. The if-guard was removed because it made the
        # catch unreachable (PS 5.1 silently swallows ScriptProperty throws, so the only reliable
        # way to test the catch is to provide null authData and rely on "Cannot index into a null array").
        $credentialAaGuid = $null
        try {
            $authData = $credential.Response.AuthenticatorData
            $hex = [BitConverter]::ToString($authData[37..52]).Replace('-','').ToLower()
            $credentialAaGuid = '{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0,8),$hex.Substring(8,4),$hex.Substring(12,4),$hex.Substring(16,4),$hex.Substring(20,12)
            Write-Verbose "Credential AAGUID (from authenticatorData): $credentialAaGuid"
            if ($script:ConnectedKeyAaGuid -and $credentialAaGuid -ne $script:ConnectedKeyAaGuid) {
                Write-Warning "The credential was signed by AAGUID $credentialAaGuid but the pre-flight detected the FX7 as $($script:ConnectedKeyAaGuid). Windows may have routed the request to a different authenticator (e.g. Windows Hello)."
            }
        } catch {
            Write-Verbose "Could not extract AAGUID from authenticatorData: $_"
        }

        # Build the POST body matching the Graph fido2AuthenticationMethod schema exactly.
        # rawId, type, and authenticatorAttachment are intentionally omitted — the Graph API
        # schema does not include them and may reject the body if they are present.
        $body = [ordered]@{
            displayName         = $DisplayName
            publicKeyCredential = [ordered]@{
                id       = $credId
                response = [ordered]@{
                    clientDataJSON    = $clientDataJSON
                    attestationObject = $attestationObject
                }
            }
        } | ConvertTo-Json -Depth 5 -Compress

        Write-Verbose "POST body: $body"

        # Pass the body as UTF-8 bytes rather than a string.
        # Some versions of the Microsoft.Graph SDK re-serialize a string body as a JSON string
        # literal (double-encoding it), which causes the server to see a quoted string at the root
        # rather than an object. Byte arrays bypass all SDK serialization logic.
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $registrationUrl = '/beta/users/{0}/authentication/fido2Methods' -f [uri]::EscapeDataString($UPN)
        $responseJson = Invoke-MgGraphRequest -Method POST -Uri $registrationUrl -Body $bodyBytes -ContentType 'application/json' -OutputType Json -ErrorAction Stop
        return $responseJson | ConvertFrom-Json
    } catch {
        # Walk the full inner exception chain — DSInternals rethrows and discards ErrorDetails,
        # so the actual Graph API response body is buried in the inner exceptions
        $msgs = [System.Collections.Generic.List[string]]::new()
        $ex = $_.Exception
        while ($ex) {
            if ($ex.Message -and -not $msgs.Contains($ex.Message)) { $msgs.Add($ex.Message) }
            $ex = $ex.InnerException
        }
        if ($_.ErrorDetails.Message) { $msgs.Add("Graph response: $($_.ErrorDetails.Message)") }
        $msg = $msgs -join "`n  -> "

        if ($msg -match 'canceled by the user') {
            Write-Warning "Registration canceled for user $UPN - the device was not inserted or touched in time. Please re-run for this user."
            return $null
        } elseif ($msg -match 'BadRequest') {
            # The preflight already read the AAGUID via Get-PasskeyAuthenticator and verified key
            # restrictions. If we got here, restrictions passed; the cause is something else.
            $diagLines = [System.Collections.Generic.List[string]]::new()
            $diagLines.Add("Registration failed for user $UPN (BadRequest).")
            $diagLines.Add("Error: $msg")
            $diagLines.Add("")
            $diagLines.Add("POST body sent:")
            $diagLines.Add($body)

            if ($script:ConnectedKeyAaGuid) {
                $diagLines.Add("")
                $diagLines.Add("Key AAGUID: $($script:ConnectedKeyAaGuid)")

                if ($script:PolicyKeyRestrictions) {
                    $diagLines.Add(("  -> Key restriction check: PASSED (enforcement: {0})" -f $script:PolicyKeyRestrictions.enforcementType))
                }

                # Live FIDO MDS lookup — only done here on failure, not during preflight
                $diagLines.Add("")
                $diagLines.Add("Checking FIDO Alliance MDS3 for known OneSpan devices (this may take a few seconds)...")
                Write-Warning ($diagLines -join "`n")
                $diagLines.Clear()

                $oneSpanAAGUIDs = Get-FidoMdsAAGUIDs -VendorPattern 'OneSpan'
                if ($oneSpanAAGUIDs.Count -gt 0) {
                    if ($script:ConnectedKeyAaGuid -in $oneSpanAAGUIDs) {
                        $diagLines.Add("  -> AAGUID is a recognised OneSpan device per the FIDO Alliance MDS.")
                    } else {
                        $diagLines.Add("  -> AAGUID '$($script:ConnectedKeyAaGuid)' was NOT found in the FIDO MDS under OneSpan.")
                        $diagLines.Add("     All OneSpan AAGUIDs currently listed in the MDS:")
                        foreach ($id in ($oneSpanAAGUIDs | Sort-Object)) { $diagLines.Add("       $id") }
                        $diagLines.Add("     The device may have a new AAGUID not yet in the MDS, or it may not be an FX7.")
                    }
                } else {
                    $diagLines.Add("  -> Could not retrieve FIDO MDS data (network unavailable or request timed out).")
                }
            }

            $diagLines.Add("")
            $diagLines.Add("Other common causes of BadRequest:")
            $diagLines.Add("  - Attestation enforcement is on and the key's attestation chain is not trusted by Microsoft Entra")
            $diagLines.Add("  - The tenant's FIDO2 policy does not target this user or their group")
            $diagLines.Add("  - The key has already been registered under a different credential ID")
            Write-Warning ($diagLines -join "`n")
            return $null
        } else {
            Write-Error "Failed to register the passkey: $msg"
            throw
        }
    }
}

# Function to verify the FIDO2 policy allows self-service setup (required by the Graph API)
function Assert-Fido2PolicyEnabled {
    # Note: Get-PasskeyAuthenticator calls WebAuthNGetPlatformCredentialList, which only enumerates
    # platform authenticators (Windows Hello / TPM). USB FIDO2 security keys like the FX7 are
    # roaming authenticators and will never appear in its output — "Object was not found" is the
    # expected return on any machine that has no stored Windows Hello passkeys. We do not attempt
    # to enumerate the connected key here; the AAGUID is captured from the credential after
    # New-Passkey completes (in Create-and-Register-Passkey) and compared there.

    # Only the API call is inside try/catch — insufficient permissions is a non-fatal warning.
    # Validation failures (policy disabled, AAGUID blocked) must propagate as terminating errors
    # so that the caller (main script body) can decide to exit. Wrapping validation in the same
    # try/catch would silently swallow those throws and turn fatal policy violations into warnings.
    $policy = $null
    try {
        $policy = Invoke-MgGraphRequest -Method GET -Uri '/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2' -OutputType PSObject
    } catch {
        Write-Warning "Could not verify FIDO2 policy (insufficient permissions or policy not configured): $_"
        return
    }

    if ($policy.isSelfServiceRegistrationAllowed -ne $true) {
        Write-Error @"
The FIDO2 authentication method policy does not have 'Allow self-service setup' enabled in this tenant.
Despite the misleading name, this setting is also required for admin-provisioned FIDO2 registration via the Microsoft Graph API.
Enabling it does NOT allow end users to self-register without admin involvement - it is a prerequisite for the provisioning API to function.
To fix this:
  1. Sign in to https://entra.microsoft.com as an Authentication Policy Administrator
  2. Browse to: Entra ID > Security > Authentication methods > Policies
  3. Select 'Passkey (FIDO2)' > Configure tab
  4. Set 'Allow self-service setup' to Yes, then Save
See: https://learn.microsoft.com/en-us/graph/known-issues#fido2-provisioning-api-requires-self-service-setup-to-be-enabled
"@ -ErrorAction Continue
        throw "FIDO2 self-service setup is not enabled in this tenant."
    }
    Write-Verbose "FIDO2 self-service setup policy: enabled."

    # Check key restrictions against the connected key's AAGUID and fail fast if blocked.
    if ($policy.keyRestrictions.isEnforced -eq $true) {
        $script:PolicyKeyRestrictions = $policy.keyRestrictions
        $enforcementType = $policy.keyRestrictions.enforcementType
        $policyAAGUIDs = @($policy.keyRestrictions.aaGuids | ForEach-Object { $_.ToLower() })
        Write-Verbose ("FIDO2 key restrictions enabled (enforcement: {0}, {1} AAGUID(s))." -f $enforcementType, $policyAAGUIDs.Count)

        if ($script:ConnectedKeyAaGuid) {
            if ($enforcementType -eq 'allow' -and $script:ConnectedKeyAaGuid -notin $policyAAGUIDs) {
                Write-Error @"
The connected key's AAGUID ($($script:ConnectedKeyAaGuid)) is NOT in the tenant's FIDO2 allow list.
Allowed AAGUIDs: $($policyAAGUIDs -join ', ')
Add the AAGUID to the allow list in:
  entra.microsoft.com > Entra ID > Security > Authentication methods > Policies > Passkey (FIDO2) > Configure > Key Restriction Policy
"@ -ErrorAction Continue
                throw "FIDO2 allow-list restriction: the connected key's AAGUID is not permitted."
            } elseif ($enforcementType -eq 'block' -and $script:ConnectedKeyAaGuid -in $policyAAGUIDs) {
                Write-Error "The connected key's AAGUID ($($script:ConnectedKeyAaGuid)) is explicitly BLOCKED by the tenant's FIDO2 key restriction policy." -ErrorAction Continue
                throw "FIDO2 block-list restriction: the connected key's AAGUID is explicitly blocked."
            } else {
                Write-Verbose "Key AAGUID ($($script:ConnectedKeyAaGuid)) passes the '$enforcementType' key restriction check."
            }
        }
    }
}

# Function to verify the registration
function Verify-Registration {
    param (
        [string]$UPN,
        [string]$DisplayName
    )
    try {
        $RegisteredKey = Get-MgBetaUserAuthenticationFido2Method -UserId $UPN | Where-Object { $_.DisplayName -eq $DisplayName }
        if ($RegisteredKey) {
            Write-Host "Passkey registered successfully for user $UPN."
        } else {
            # -ErrorAction Continue is required so this non-fatal diagnostic write-error
            # does not terminate the caller under $ErrorActionPreference = 'Stop' (the
            # GitHub Actions default). The caller decides whether to continue.
            Write-Error "Failed to verify the registration of the passkey." -ErrorAction Continue
        }
    } catch {
        Write-Error "Failed to verify the registration: $_"
        throw
    }
}

function Process-User {
    param (
        [string]$UPN,
        [string]$SerialID,
        [string]$DisplayName
    )
    $SerialID = $SerialID -replace '-', ''
    $DisplayName = "OneSpan FX7 $SerialID"
    $RegisteredKey = Get-MgBetaUserAuthenticationFido2Method -UserId $UPN | Where-Object { $_.DisplayName -eq $DisplayName }
    if ($RegisteredKey) {
        Write-Host "Passkey already registered for user $UPN. Verifying..."
        Verify-Registration -UPN $UPN -DisplayName $DisplayName
    } else {
        $result = Create-and-Register-Passkey -UPN $UPN -DisplayName $DisplayName
        if ($result) {
            Verify-Registration -UPN $UPN -DisplayName $DisplayName
        }
    }
}

# DSInternals.Passkeys uses the Windows WebAuthn API (webauthn.dll), which is only
# available on Windows. Fail fast with a clear message rather than a cryptic error
# inside New-Passkey. PS 5.1 is always Windows so no check is needed there.
if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
    throw "This script requires Windows. DSInternals.Passkeys relies on the Windows WebAuthn API (webauthn.dll), which is not available on Linux or macOS."
}

Ensure-Module -ModuleName "Microsoft.Graph.Identity.SignIns" -MinimumVersion "2.26.0"
Ensure-Module -ModuleName "DSInternals.Passkeys" -MinimumVersion "3.1.0"

if (-not $TenantId) {
    $TenantId = Read-Host "Enter Tenant ID"
}

Connect-ToMsGraph -TenantId $TenantId
Assert-Fido2PolicyEnabled

if (-not $CsvFilePath -and (-not $UPN -or -not $SerialID)) {
    $CsvFilePath = Read-Host "Enter CSV file path (leave blank if not using CSV)"
}

if ($CsvFilePath) {
    $csvData = Import-Csv -Path $CsvFilePath
    if (-not $csvData) {
        Write-Error "The CSV file is empty. Please provide a valid CSV file." -ErrorAction Continue
        throw "The CSV file is empty. Please provide a CSV with at least one data row."
    }
    if ($csvData -is [array]) {
        $totalEntries = $csvData.Count
    } else {
        $totalEntries = 1
        $csvData = @($csvData)
    }
    $currentEntry = 0
    foreach ($row in $csvData) {
        $currentEntry++
        Write-Host "Processing user $($row.UPN) with OneSpan FX7 serial number $($row.SerialID) ($currentEntry of $totalEntries)..."
        try {
            Process-User -UPN $row.UPN -SerialID $row.SerialID -DisplayName $DisplayName
        } catch {
            # -ErrorAction Continue keeps the batch running; a single user failure must
            # not abort the remaining CSV rows (same reason as Verify-Registration above).
            Write-Error "Error processing user $($row.UPN) with serial number $($row.SerialID): $_" -ErrorAction Continue
        }
    }
} else {
    if (-not $UPN) {
        $UPN = Read-Host "Enter User Principal Name (UPN)"
    }
    if (-not $SerialID) {
        $SerialID = Read-Host "Enter Serial ID"
    }
    Process-User -UPN $UPN -SerialID $SerialID -DisplayName $DisplayName
}
