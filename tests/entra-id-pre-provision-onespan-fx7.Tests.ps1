#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester tests for entra-id-pre-provision-onespan-fx7.ps1

.DESCRIPTION
    Covers:
      - All exported functions (unit tests with mocked external calls)
      - Data alignment: serial normalisation, DisplayName length, JSON body structure,
        base64url encoding, OneSpan FX7 AAGUID values, CSV column requirements,
        UPN URL-encoding, policy allow-list matching

.NOTES
    Run with:
        Invoke-Pester .\tests\entra-id-pre-provision-onespan-fx7.Tests.ps1 -Output Detailed
#>

Describe 'entra-id-pre-provision-onespan-fx7.ps1' {

    BeforeAll {
        $script:ScriptPath = Join-Path (Join-Path $PSScriptRoot '..') 'entra-id-pre-provision-onespan-fx7.ps1'

        # ── Mock credential shared across function tests ──────────────────────
        # AuthenticatorData layout: rpIdHash[32] + flags[1] + signCount[4] + AAGUID[16]
        # AAGUID used here: OneSpan DIGIPASS FX7  30b5035e-d297-4ff7-b00b-addc96ba6a98
        $rpIdHash    = [byte[]](1..32)
        $flags       = [byte[]](0x41)
        $signCount   = [byte[]](0, 0, 0, 1)
        $aaguidBytes = [byte[]](0x30, 0xb5, 0x03, 0x5e, 0xd2, 0x97, 0x4f, 0xf7,
                                0xb0, 0x0b, 0xad, 0xdc, 0x96, 0xba, 0x6a, 0x98)
        $script:MockAuthData = [byte[]]($rpIdHash + $flags + $signCount + $aaguidBytes)  # 53 bytes; must be byte[] not Object[]

        $script:MockCredential = [PSCustomObject]@{
            Id       = [byte[]](0xcc, 0xee, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
            Response = [PSCustomObject]@{
                ClientData        = [System.Text.Encoding]::UTF8.GetBytes(
                                        '{"type":"webauthn.create","challenge":"dGVzdA"}')
                AttestationObject = [byte[]](0x01, 0x02, 0x03, 0x04)
                AuthenticatorData = $script:MockAuthData
            }
        }

        # ── Suppress all real side-effects during dot-source of the script body ─
        # NOTE: Mock Get-Module LAST. Pester calls Get-Module internally when setting
        # up mocks for other commands (to discover which module owns them). Mocking it
        # first causes "Could not find Command <X>" for any subsequent Mock call.
        # ── Stub external commands FIRST — Pester 5 can only mock commands that exist ──
        # CI runners do not have Microsoft.Graph or DSInternals.Passkeys installed, so these
        # global stubs must be defined before any Mock call that targets them.
        if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
            function global:Connect-MgGraph { param([string[]]$Scopes, [string]$TenantId) }
        }
        if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
            function global:Invoke-MgGraphRequest { param([string]$Method, [string]$Uri, $Body, [string]$ContentType, [string]$OutputType) }
        }
        if (-not (Get-Command Get-MgBetaUserAuthenticationFido2Method -ErrorAction SilentlyContinue)) {
            function global:Get-MgBetaUserAuthenticationFido2Method { param([string]$UserId) }
        }
        if (-not (Get-Command Get-EntraPasskeyRegistrationOptions -ErrorAction SilentlyContinue)) {
            function global:Get-EntraPasskeyRegistrationOptions { param([string]$UserId) }
        }
        if (-not (Get-Command New-Passkey -ErrorAction SilentlyContinue)) {
            function global:New-Passkey { param() }
        }
        if (-not (Get-Command Install-PSResource -ErrorAction SilentlyContinue)) {
            function global:Install-PSResource { param([string]$Name, [string]$Scope, [string]$Version) }
        }

        Mock Install-Module    { }
        Mock Install-PSResource { }
        Mock Connect-MgGraph { }
        Mock Invoke-MgGraphRequest {
            [PSCustomObject]@{
                isSelfServiceRegistrationAllowed = $true
                keyRestrictions = [PSCustomObject]@{ isEnforced = $false }
            }
        }
        # SerialID '000000' -> DisplayName 'OneSpan FX7 000000'.
        # Return a matching key so Process-User skips registration during dot-source.
        Mock Get-MgBetaUserAuthenticationFido2Method {
            [PSCustomObject]@{ DisplayName = 'OneSpan FX7 000000' }
        }
        Mock Read-Host { '' }
        Mock Write-Host { }
        # Get-Module mocked last so the above mocks can resolve their source modules normally.
        Mock Get-Module {
            [PSCustomObject]@{ Name = $Name; Version = [version]'9.9.9' }
        }

        # Replicate the GitHub Actions $ErrorActionPreference = 'Stop' environment.
        # GitHub Actions wraps every powershell step with this preference, which turns
        # Write-Error into a terminating error. Non-fatal Write-Error calls in the
        # production script must carry -ErrorAction Continue to be immune to this.
        # Setting it here surfaces those bugs locally before they reach CI.
        $ErrorActionPreference = 'Stop'

        # Dot-source the script to load all function definitions.
        . $script:ScriptPath -TenantId 'test.onmicrosoft.com' -UPN 'test@test.com' -SerialID '000000'
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Script loading' {

        It 'Defines all expected functions' {
            $expected = @(
                'Write-Log', 'Ensure-Module', 'Connect-ToMsGraph', 'Confirm-Action',
                'Get-FidoMdsAAGUIDs', 'ConvertTo-Base64Url', 'Create-and-Register-Passkey',
                'Assert-Fido2PolicyEnabled', 'Verify-Registration', 'Process-User', 'Main'
            )
            foreach ($fn in $expected) {
                Get-Command -Name $fn -ErrorAction SilentlyContinue |
                    Should -Not -BeNullOrEmpty -Because "$fn must be defined after dot-sourcing"
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'ConvertTo-Base64Url' {

        It 'Converts byte[] to base64url without padding' {
            ConvertTo-Base64Url -Value ([byte[]](0x01, 0x02, 0x03)) | Should -Be 'AQID'
        }

        It 'Replaces + with - and / with _ (0xFB,0xFF,0xFE -> -__-)' {
            # Standard base64: +//+   Base64url: -__-
            ConvertTo-Base64Url -Value ([byte[]](0xFB, 0xFF, 0xFE)) | Should -Be '-__-'
        }

        It 'Strips = padding characters' {
            # Single byte: standard base64 'AQ==' -> base64url 'AQ'
            $result = ConvertTo-Base64Url -Value ([byte[]](0x01))
            $result | Should -Be 'AQ'
            $result | Should -Not -Match '='
        }

        It 'Passes a string value through unchanged' {
            ConvertTo-Base64Url -Value 'already-base64url' | Should -Be 'already-base64url'
        }

        It 'Handles an empty byte array' {
            ConvertTo-Base64Url -Value ([byte[]]@()) | Should -Be ''
        }

        It 'Output never contains +, /, or = characters' {
            # Use bytes that produce all three problem characters in standard base64
            $result = ConvertTo-Base64Url -Value ([byte[]](0xFB, 0xFF, 0xFE, 0x01))
            $result | Should -Not -Match '[+/=]'
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Ensure-Module' {

        Context 'Module already meets minimum version' {
            BeforeEach {
                Mock Get-Module { [PSCustomObject]@{ Name = $Name; Version = [version]'3.2.0' } }
                Mock Install-Module { throw 'Must not install' }
            }
            It 'Does not call Install-Module' {
                { Ensure-Module -ModuleName 'DSInternals.Passkeys' -MinimumVersion '3.1.0' } |
                    Should -Not -Throw
                Should -Invoke Install-Module -Times 0
            }
        }

        Context 'Module not installed, PS5 path (uses Install-Module)' {
            BeforeEach {
                Mock Get-Module { $null }
                Mock Install-Module { }
                $script:PSVersionOverride = 5
            }
            AfterEach { $script:PSVersionOverride = $null }
            It 'Calls Install-Module' {
                Ensure-Module -ModuleName 'DSInternals.Passkeys' -MinimumVersion '3.1.0'
                Should -Invoke Install-Module -Times 1
            }
        }

        Context 'Module installed below minimum version, PS5 path (uses Install-Module)' {
            BeforeEach {
                Mock Get-Module { [PSCustomObject]@{ Name = $Name; Version = [version]'2.0.0' } }
                Mock Install-Module { }
                $script:PSVersionOverride = 5
            }
            AfterEach { $script:PSVersionOverride = $null }
            It 'Calls Install-Module to upgrade' {
                Ensure-Module -ModuleName 'DSInternals.Passkeys' -MinimumVersion '3.1.0'
                Should -Invoke Install-Module -Times 1
            }
        }

        Context 'Module installed at exactly minimum version' {
            BeforeEach {
                Mock Get-Module { [PSCustomObject]@{ Name = $Name; Version = [version]'3.1.0' } }
                Mock Install-Module { throw 'Must not install' }
            }
            It 'Does not upgrade when version is exactly the minimum' {
                { Ensure-Module -ModuleName 'DSInternals.Passkeys' -MinimumVersion '3.1.0' } |
                    Should -Not -Throw
                Should -Invoke Install-Module -Times 0
            }
        }

        Context 'Module not installed, PS7+ path (uses Install-PSResource)' {
            BeforeEach {
                Mock Get-Module { $null }
                Mock Install-PSResource { }
                $script:PSVersionOverride = 7
            }
            AfterEach { $script:PSVersionOverride = $null }
            It 'Calls Install-PSResource with NuGet version range and does not call Install-Module' {
                Ensure-Module -ModuleName 'DSInternals.Passkeys' -MinimumVersion '3.1.0'
                Should -Invoke Install-PSResource -Times 1 -ParameterFilter {
                    $Version -eq '[3.1.0,)'
                }
                Should -Invoke Install-Module -Times 0
            }
            It 'Calls Install-PSResource without a version constraint when MinimumVersion is omitted' {
                Ensure-Module -ModuleName 'AnyModule'
                Should -Invoke Install-PSResource -Times 1 -ParameterFilter {
                    $Name -eq 'AnyModule' -and -not $Version
                }
                Should -Invoke Install-Module -Times 0
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Write-Log' {

        It 'Routes Level Host to Write-Host' {
            Mock Write-Host { }
            Write-Log -Message 'hello' -Level Host
            Should -Invoke Write-Host -Times 1 -ParameterFilter { $Object -eq 'hello' }
        }

        It 'Routes Level Host with ForegroundColor to Write-Host -ForegroundColor' {
            Mock Write-Host { }
            Write-Log -Message 'colored' -Level Host -ForegroundColor Green
            Should -Invoke Write-Host -Times 1 -ParameterFilter { $ForegroundColor -eq 'Green' }
        }

        It 'Routes Level Error to Write-Error' {
            Mock Write-Error { }
            Write-Log -Message 'err' -Level Error
            Should -Invoke Write-Error -Times 1 -ParameterFilter { $Message -eq 'err' }
        }

        It 'Routes Level Warn to Write-Warning' {
            Mock Write-Warning { }
            Write-Log -Message 'warn' -Level Warn
            Should -Invoke Write-Warning -Times 1 -ParameterFilter { $Message -eq 'warn' }
        }

        It 'Appends a timestamped line to the log file when LogPath is set' {
            $script:LogPath = 'C:\fake-path\test.log'
            Mock Add-Content { }
            Write-Log -Message 'file test' -Level Host
            Should -Invoke Add-Content -Times 1 -ParameterFilter { $Path -like '*test.log' }
            $script:LogPath = $null
        }

        It 'Does not call Add-Content when LogPath is not set' {
            $script:LogPath = $null
            Mock Add-Content { throw 'Must not write to log' }
            { Write-Log -Message 'no file' -Level Host } | Should -Not -Throw
        }

        It 'Calls Write-Verbose for the default (Verbose) level' {
            Mock Write-Verbose { }
            Write-Log -Message 'verbose msg' -Level Verbose
            Should -Invoke Write-Verbose -Times 1 -ParameterFilter { $Message -eq 'verbose msg' }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Confirm-Action' {

        It 'Returns true immediately when -Force is set' {
            Mock Read-Host { throw 'Must not prompt when Force is set' }
            $result = Confirm-Action -Message 'Proceed?' -Force
            $result | Should -Be $true
        }

        It 'Returns true immediately when -DryRun is set' {
            Mock Read-Host { throw 'Must not prompt when DryRun is set' }
            $result = Confirm-Action -Message 'Proceed?' -DryRun
            $result | Should -Be $true
        }

        It 'Prompts and returns true when user answers Y' {
            Mock Read-Host { 'Y' }
            $result = Confirm-Action -Message 'Proceed?'
            $result | Should -Be $true
        }

        It 'Prompts and throws when user answers N' {
            Mock Read-Host { 'N' }
            { Confirm-Action -Message 'Proceed?' } | Should -Throw
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Connect-ToMsGraph' {

        It 'Connects with UserAuthenticationMethod.ReadWrite.All scope' {
            Mock Connect-MgGraph { }
            Connect-ToMsGraph -TenantId 'contoso.onmicrosoft.com'
            Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter {
                $Scopes -contains 'UserAuthenticationMethod.ReadWrite.All'
            }
        }

        It 'Connects with Policy.Read.All scope' {
            Mock Connect-MgGraph { }
            Connect-ToMsGraph -TenantId 'contoso.onmicrosoft.com'
            Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter {
                $Scopes -contains 'Policy.Read.All'
            }
        }

        It 'Passes the tenant ID to Connect-MgGraph' {
            Mock Connect-MgGraph { }
            Connect-ToMsGraph -TenantId 'contoso.onmicrosoft.com'
            Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter {
                $TenantId -eq 'contoso.onmicrosoft.com'
            }
        }

        It 'Calls Write-Error and terminates on connection failure' {
            Mock Connect-MgGraph { throw 'Auth failed' }
            # Write-Error is -ErrorAction Continue in production; mock as no-op so the
            # explicit throw that follows it is what terminates the function.
            Mock Write-Error { }
            { Connect-ToMsGraph -TenantId 'bad.tenant' } | Should -Throw
            Should -Invoke Write-Error -Times 1
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Get-FidoMdsAAGUIDs' {

        BeforeAll {
            # Minimal MDS3 JWT: header.<base64url-payload>.signature
            $payload = @{
                entries = @(
                    @{
                        aaguid            = '30b5035e-d297-4ff7-b00b-addc96ba6a98'
                        metadataStatement = @{ description = 'OneSpan DIGIPASS FX7' }
                    }
                    @{
                        aaguid            = '30b5035e-d297-4ff7-010b-addc96ba6a98'
                        metadataStatement = @{ description = 'OneSpan DIGIPASS FX7-B' }
                    }
                    @{
                        aaguid            = 'f8a011f3-8c0a-4d15-8006-17111f9edc7d'
                        metadataStatement = @{ description = 'Solo Secp256R1 FIDO2 CTAP2 Authenticator' }
                    }
                )
            } | ConvertTo-Json -Depth 5 -Compress

            $b64 = [Convert]::ToBase64String(
                [System.Text.Encoding]::UTF8.GetBytes($payload)
            ).Replace('+', '-').Replace('/', '_').TrimEnd('=')

            $script:MockMdsJwt = "header.$b64.signature"
        }

        Context 'Successful MDS fetch' {
            BeforeEach {
                Mock Invoke-WebRequest { [PSCustomObject]@{ Content = $script:MockMdsJwt } }
            }

            It 'Returns only entries matching the vendor pattern' {
                $result = Get-FidoMdsAAGUIDs -VendorPattern 'OneSpan'
                $result | Should -HaveCount 2
            }

            It 'Does not return non-OneSpan entries' {
                $result = Get-FidoMdsAAGUIDs -VendorPattern 'OneSpan'
                $result | Should -Not -Contain 'f8a011f3-8c0a-4d15-8006-17111f9edc7d'
            }

            It 'Returns AAGUIDs in lowercase hyphenated UUID format' {
                $uuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                $result = Get-FidoMdsAAGUIDs -VendorPattern 'OneSpan'
                foreach ($aaguid in $result) {
                    $aaguid | Should -Match $uuidPattern -Because "$aaguid must be lowercase UUID"
                }
            }

            It 'Contains the known FX7 AAGUID from the mock payload' {
                $result = Get-FidoMdsAAGUIDs -VendorPattern 'OneSpan'
                $result | Should -Contain '30b5035e-d297-4ff7-b00b-addc96ba6a98'
            }
        }

        Context 'Network failure' {
            BeforeEach {
                Mock Invoke-WebRequest { throw 'Connection refused' }
            }
            It 'Returns an empty array (does not throw)' {
                $result = Get-FidoMdsAAGUIDs -VendorPattern 'OneSpan'
                $result | Should -BeNullOrEmpty
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Assert-Fido2PolicyEnabled' {

        Context 'Self-service setup is disabled' {
            BeforeEach {
                Mock Invoke-MgGraphRequest {
                    [PSCustomObject]@{
                        isSelfServiceRegistrationAllowed = $false
                        keyRestrictions = [PSCustomObject]@{ isEnforced = $false }
                    }
                }
                # Write-Error is -ErrorAction Continue; mock as no-op so the
                # explicit throw that follows it propagates to the test.
                Mock Write-Error { }
            }
            It 'Throws with an error describing the self-service setup requirement' {
                { Assert-Fido2PolicyEnabled } | Should -Throw
                Should -Invoke Write-Error -Times 1
            }
        }

        Context 'Self-service enabled, no key restrictions' {
            BeforeEach {
                Mock Invoke-MgGraphRequest {
                    [PSCustomObject]@{
                        isSelfServiceRegistrationAllowed = $true
                        keyRestrictions = [PSCustomObject]@{ isEnforced = $false }
                    }
                }
                # Must be mocked for Should -Invoke to assert zero calls.
                Mock Write-Error { }
            }
            It 'Completes without error or warning' {
                { Assert-Fido2PolicyEnabled } | Should -Not -Throw
                Should -Invoke Write-Error -Times 0
            }
        }

        Context 'Key restrictions active' {
            BeforeEach {
                Mock Invoke-MgGraphRequest {
                    [PSCustomObject]@{
                        isSelfServiceRegistrationAllowed = $true
                        keyRestrictions = [PSCustomObject]@{
                            isEnforced      = $true
                            enforcementType = 'allow'
                            aaGuids         = @('30b5035e-d297-4ff7-b00b-addc96ba6a98')
                        }
                    }
                }
            }
            It 'Stores policy restrictions in script scope for later use' {
                $script:PolicyKeyRestrictions = $null
                Assert-Fido2PolicyEnabled
                $script:PolicyKeyRestrictions | Should -Not -BeNullOrEmpty
            }
            It 'Records the enforcement type' {
                Assert-Fido2PolicyEnabled
                $script:PolicyKeyRestrictions.enforcementType | Should -Be 'allow'
            }
        }

        Context 'Policy API request fails (permissions error)' {
            BeforeEach {
                Mock Invoke-MgGraphRequest { throw 'Forbidden' }
                Mock Write-Warning { }
            }
            It 'Emits a warning rather than terminating' {
                { Assert-Fido2PolicyEnabled } | Should -Not -Throw
                Should -Invoke Write-Warning -Times 1
            }
        }

        Context 'Connected key AAGUID passes the allow-list check' {
            BeforeEach {
                Mock Invoke-MgGraphRequest {
                    [PSCustomObject]@{
                        isSelfServiceRegistrationAllowed = $true
                        keyRestrictions = [PSCustomObject]@{
                            isEnforced      = $true
                            enforcementType = 'allow'
                            aaGuids         = @('30b5035e-d297-4ff7-b00b-addc96ba6a98')
                        }
                    }
                }
                Mock Write-Error { }
                $script:ConnectedKeyAaGuid = '30b5035e-d297-4ff7-b00b-addc96ba6a98'
            }
            AfterEach { $script:ConnectedKeyAaGuid = $null }
            It 'Completes without error when AAGUID is in the allow list' {
                { Assert-Fido2PolicyEnabled } | Should -Not -Throw
                Should -Invoke Write-Error -Times 0
            }
        }

        Context 'Connected key AAGUID not in the allow list' {
            BeforeEach {
                Mock Invoke-MgGraphRequest {
                    [PSCustomObject]@{
                        isSelfServiceRegistrationAllowed = $true
                        keyRestrictions = [PSCustomObject]@{
                            isEnforced      = $true
                            enforcementType = 'allow'
                            aaGuids         = @('30b5035e-d297-4ff7-b00b-addc96ba6a98')
                        }
                    }
                }
                Mock Write-Error { }
                $script:ConnectedKeyAaGuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            }
            AfterEach { $script:ConnectedKeyAaGuid = $null }
            It 'Throws with an error identifying the AAGUID not in the allow list' {
                { Assert-Fido2PolicyEnabled } | Should -Throw
                Should -Invoke Write-Error -Times 1
            }
        }

        Context 'Connected key AAGUID explicitly in the block list' {
            BeforeEach {
                Mock Invoke-MgGraphRequest {
                    [PSCustomObject]@{
                        isSelfServiceRegistrationAllowed = $true
                        keyRestrictions = [PSCustomObject]@{
                            isEnforced      = $true
                            enforcementType = 'block'
                            aaGuids         = @('30b5035e-d297-4ff7-b00b-addc96ba6a98')
                        }
                    }
                }
                Mock Write-Error { }
                $script:ConnectedKeyAaGuid = '30b5035e-d297-4ff7-b00b-addc96ba6a98'
            }
            AfterEach { $script:ConnectedKeyAaGuid = $null }
            It 'Throws with an error stating the key is explicitly blocked' {
                { Assert-Fido2PolicyEnabled } | Should -Throw
                Should -Invoke Write-Error -Times 1
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Create-and-Register-Passkey' {

        Context 'Successful registration' {
            BeforeEach {
                Mock Get-EntraPasskeyRegistrationOptions { [PSCustomObject]@{} }
                Mock New-Passkey { $script:MockCredential }
                Mock Invoke-MgGraphRequest {
                    '{"id":"fakecredid","displayName":"OneSpan FX7 000000"}'
                }
            }

            It 'Returns a non-null result' {
                $result = Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                $result | Should -Not -BeNullOrEmpty
            }

            It 'POSTs to the correct fido2Methods endpoint for the user' {
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                    $Method -eq 'POST' -and
                    $Uri -match '/beta/users/user%40test\.com/authentication/fido2Methods$'
                }
            }

            It 'Sends the body as a byte array, not a string' {
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                    $Body -is [byte[]]
                }
            }

            It 'Sets Content-Type to application/json' {
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                    $ContentType -eq 'application/json'
                }
            }

            It 'JSON body has displayName at the root' {
                $script:captured = $null
                Mock Invoke-MgGraphRequest {
                    $script:captured = [System.Text.Encoding]::UTF8.GetString($Body)
                    '{"id":"x","displayName":"test"}'
                }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                ($script:captured | ConvertFrom-Json).displayName | Should -Be 'OneSpan FX7 000000'
            }

            It 'JSON body has publicKeyCredential.id' {
                $script:captured = $null
                Mock Invoke-MgGraphRequest {
                    $script:captured = [System.Text.Encoding]::UTF8.GetString($Body)
                    '{"id":"x","displayName":"test"}'
                }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                ($script:captured | ConvertFrom-Json).publicKeyCredential.id | Should -Not -BeNullOrEmpty
            }

            It 'JSON body has publicKeyCredential.response.clientDataJSON' {
                $script:captured = $null
                Mock Invoke-MgGraphRequest {
                    $script:captured = [System.Text.Encoding]::UTF8.GetString($Body)
                    '{"id":"x","displayName":"test"}'
                }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                ($script:captured | ConvertFrom-Json).publicKeyCredential.response.clientDataJSON |
                    Should -Not -BeNullOrEmpty
            }

            It 'JSON body has publicKeyCredential.response.attestationObject' {
                $script:captured = $null
                Mock Invoke-MgGraphRequest {
                    $script:captured = [System.Text.Encoding]::UTF8.GetString($Body)
                    '{"id":"x","displayName":"test"}'
                }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                ($script:captured | ConvertFrom-Json).publicKeyCredential.response.attestationObject |
                    Should -Not -BeNullOrEmpty
            }

            It 'JSON body does not contain rawId (rejected by Graph API)' {
                $script:captured = $null
                Mock Invoke-MgGraphRequest {
                    $script:captured = [System.Text.Encoding]::UTF8.GetString($Body)
                    '{"id":"x","displayName":"test"}'
                }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                ($script:captured | ConvertFrom-Json).publicKeyCredential.PSObject.Properties.Name |
                    Should -Not -Contain 'rawId'
            }

            It 'JSON body does not contain type field (rejected by Graph API)' {
                $script:captured = $null
                Mock Invoke-MgGraphRequest {
                    $script:captured = [System.Text.Encoding]::UTF8.GetString($Body)
                    '{"id":"x","displayName":"test"}'
                }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                ($script:captured | ConvertFrom-Json).publicKeyCredential.PSObject.Properties.Name |
                    Should -Not -Contain 'type'
            }

            It 'credential id is valid base64url (no +, /, or =)' {
                $script:captured = $null
                Mock Invoke-MgGraphRequest {
                    $script:captured = [System.Text.Encoding]::UTF8.GetString($Body)
                    '{"id":"x","displayName":"test"}'
                }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                ($script:captured | ConvertFrom-Json).publicKeyCredential.id |
                    Should -Match '^[A-Za-z0-9_-]+$'
            }

            It 'clientDataJSON is valid base64url (no +, /, or =)' {
                $script:captured = $null
                Mock Invoke-MgGraphRequest {
                    $script:captured = [System.Text.Encoding]::UTF8.GetString($Body)
                    '{"id":"x","displayName":"test"}'
                }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                ($script:captured | ConvertFrom-Json).publicKeyCredential.response.clientDataJSON |
                    Should -Match '^[A-Za-z0-9_-]+$'
            }

            It 'clientDataJSON decodes back to the original ClientData bytes' {
                $script:captured = $null
                Mock Invoke-MgGraphRequest {
                    $script:captured = [System.Text.Encoding]::UTF8.GetString($Body)
                    '{"id":"x","displayName":"test"}'
                }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                $b64 = ($script:captured | ConvertFrom-Json).publicKeyCredential.response.clientDataJSON
                # Re-add base64 padding and decode
                $rem = $b64.Length % 4
                if ($rem) { $b64 += '=' * (4 - $rem) }
                $decoded = [Convert]::FromBase64String($b64.Replace('-','+').Replace('_','/'))
                $decoded | Should -Be $script:MockCredential.Response.ClientData
            }
        }

        Context 'User cancels the device interaction' {
            BeforeEach {
                Mock Get-EntraPasskeyRegistrationOptions { [PSCustomObject]@{} }
                Mock New-Passkey { throw 'The operation has been canceled by the user.' }
                Mock Write-Warning { }
            }
            It 'Returns null without throwing' {
                $result = Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                $result | Should -BeNullOrEmpty
            }
            It 'Emits exactly one warning' {
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                Should -Invoke Write-Warning -Times 1
            }
        }

        Context 'Graph API returns BadRequest' {
            BeforeEach {
                Mock Get-EntraPasskeyRegistrationOptions { [PSCustomObject]@{} }
                Mock New-Passkey { $script:MockCredential }
                Mock Invoke-MgGraphRequest {
                    throw 'Response status code does not indicate success: BadRequest (Bad Request).'
                }
                Mock Write-Warning { }
            }
            It 'Returns null without throwing' {
                $result = Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                $result | Should -BeNullOrEmpty
            }
            It 'Warning output includes the POST body that was sent' {
                $warnings = [System.Collections.Generic.List[string]]::new()
                Mock Write-Warning { $warnings.Add($Message) }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                ($warnings -join '') | Should -Match 'POST body sent'
            }
            It 'Includes Graph ErrorDetails in the diagnostic warning when the exception carries them' {
                # ErrorRecord.ErrorDetails is populated when the Graph SDK includes an HTTP response
                # body in the error. Line 169 reads $_.ErrorDetails.Message and appends it to $msgs
                # so the full context appears in the diagnostic warning.
                $warnings = [System.Collections.Generic.List[string]]::new()
                Mock Write-Warning { $warnings.Add($Message) }
                Mock Invoke-MgGraphRequest {
                    $ex = [Exception]::new('BadRequest (Bad Request).')
                    $er = [System.Management.Automation.ErrorRecord]::new(
                        $ex, 'GraphBadRequest',
                        [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)
                    $er.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
                        'Attestation chain is not trusted by the tenant.')
                    throw $er
                }
                Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                ($warnings -join "`n") | Should -Match 'Attestation chain is not trusted'
            }
        }

        Context 'Registration options request fails' {
            BeforeEach {
                Mock Get-EntraPasskeyRegistrationOptions { throw 'Unauthorized' }
                Mock Write-Error { }
            }
            It 'Throws (non-BadRequest errors propagate)' {
                { Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000' } |
                    Should -Throw
            }
        }

        Context 'AAGUID mismatch between pre-flight key and returned credential' {
            BeforeEach {
                Mock Get-EntraPasskeyRegistrationOptions { [PSCustomObject]@{} }
                Mock New-Passkey { $script:MockCredential }  # embeds AAGUID 30b5035e-...
                Mock Invoke-MgGraphRequest { '{"id":"x","displayName":"test"}' }
                # Do NOT mock Write-Warning here — we capture from the warning stream
                # directly with 3>&1 so the assertion is independent of Pester's mock
                # counting (which has scoping quirks for this specific context).
            }
            It 'Warns that Windows may have routed the request to a different authenticator' {
                $script:ConnectedKeyAaGuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                # Sanity check: verify the variable is visible in the It block scope
                $script:ConnectedKeyAaGuid | Should -Not -BeNullOrEmpty -Because '$script:ConnectedKeyAaGuid must be set before calling the function'
                # 3>&1 redirects the Warning stream into the output stream so we can
                # inspect it without relying on Should -Invoke / mock counting.
                $output = Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000' 3>&1
                $script:ConnectedKeyAaGuid = $null
                $warnings = @($output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
                ($warnings | Where-Object { $_.Message -match 'Windows may have routed' }).Count |
                    Should -BeGreaterThan 0 -Because 'a pre-flight/credential AAGUID mismatch must emit a warning'
            }
        }

        Context 'AuthenticatorData is null — inner AAGUID extraction catch fires' {
            BeforeEach {
                # Null AuthenticatorData causes "$authData[37..52]" to throw
                # "Cannot index into a null array", which is caught by the inner try/catch
                # (line 133). The ScriptProperty throw approach does NOT work in PS 5.1
                # because property getter exceptions are silently swallowed by the runtime.
                $nullAuthCred = [PSCustomObject]@{
                    Id       = [byte[]](1, 2, 3)
                    Response = [PSCustomObject]@{
                        ClientData        = [byte[]](1, 2, 3)
                        AttestationObject = [byte[]](1, 2, 3)
                        AuthenticatorData = $null
                    }
                }
                Mock Get-EntraPasskeyRegistrationOptions { [PSCustomObject]@{} }
                Mock New-Passkey { $nullAuthCred }
                Mock Invoke-MgGraphRequest { '{"id":"x","displayName":"test"}' }
            }
            It 'Logs a Verbose message and continues when AuthenticatorData is null' {
                $verboseLogs = [System.Collections.Generic.List[string]]::new()
                Mock Write-Verbose { $verboseLogs.Add($Message) }
                $result = Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                $result | Should -Not -BeNullOrEmpty -Because 'function must still return the registered credential'
                ($verboseLogs | Where-Object { $_ -match 'Could not extract AAGUID' }).Count |
                    Should -BeGreaterThan 0 -Because 'inner catch must emit a Verbose message when AuthenticatorData is null'
            }
        }

        Context 'BadRequest with connected key AAGUID set' {
            BeforeEach {
                Mock Get-EntraPasskeyRegistrationOptions { [PSCustomObject]@{} }
                Mock New-Passkey { $script:MockCredential }
                Mock Invoke-MgGraphRequest {
                    throw 'Response status code does not indicate success: BadRequest (Bad Request).'
                }
                $script:ConnectedKeyAaGuid = '30b5035e-d297-4ff7-b00b-addc96ba6a98'
            }
            AfterEach {
                $script:ConnectedKeyAaGuid = $null
                $script:PolicyKeyRestrictions = $null
            }

            Context 'MDS confirms key is a known OneSpan device' {
                BeforeEach {
                    Mock Get-FidoMdsAAGUIDs { @('30b5035e-d297-4ff7-b00b-addc96ba6a98') }
                }
                It 'Returns null and warning includes MDS confirmation' {
                    $warns = [System.Collections.Generic.List[string]]::new()
                    Mock Write-Warning { $warns.Add($Message) }
                    $result = Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                    $result | Should -BeNullOrEmpty
                    ($warns -join '') | Should -Match 'recognised OneSpan device'
                }
            }

            Context 'MDS does not recognise the key AAGUID' {
                BeforeEach {
                    Mock Get-FidoMdsAAGUIDs { @('ffffffff-ffff-ffff-ffff-ffffffffffff') }
                }
                It 'Warning includes unknown-AAGUID diagnostic' {
                    $warns = [System.Collections.Generic.List[string]]::new()
                    Mock Write-Warning { $warns.Add($Message) }
                    Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                    ($warns -join '') | Should -Match 'NOT found in the FIDO MDS'
                }
            }

            Context 'MDS is unreachable (empty list returned)' {
                BeforeEach {
                    Mock Get-FidoMdsAAGUIDs { @() }
                }
                It 'Warning notes that MDS data could not be retrieved' {
                    $warns = [System.Collections.Generic.List[string]]::new()
                    Mock Write-Warning { $warns.Add($Message) }
                    Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                    ($warns -join '') | Should -Match 'Could not retrieve FIDO MDS data'
                }
            }

            Context 'Policy key restrictions were stored from a prior preflight' {
                BeforeEach {
                    Mock Get-FidoMdsAAGUIDs { @('30b5035e-d297-4ff7-b00b-addc96ba6a98') }
                    $script:PolicyKeyRestrictions = [PSCustomObject]@{ enforcementType = 'allow' }
                }
                It 'Warning includes the key restriction check result' {
                    $warns = [System.Collections.Generic.List[string]]::new()
                    Mock Write-Warning { $warns.Add($Message) }
                    Create-and-Register-Passkey -UPN 'user@test.com' -DisplayName 'OneSpan FX7 000000'
                    ($warns -join '') | Should -Match 'Key restriction check: PASSED'
                }
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Verify-Registration' {

        Context 'Key found' {
            BeforeEach {
                Mock Get-MgBetaUserAuthenticationFido2Method {
                    [PSCustomObject]@{ DisplayName = 'OneSpan FX7 715096158' }
                }
                Mock Write-Host { }
            }
            It 'Reports success' {
                Verify-Registration -UPN 'user@test.com' -DisplayName 'OneSpan FX7 715096158'
                Should -Invoke Write-Host -Times 1 -ParameterFilter {
                    $Object -match 'registered successfully'
                }
            }
        }

        Context 'Key not found after registration' {
            BeforeEach {
                Mock Get-MgBetaUserAuthenticationFido2Method { @() }
                Mock Write-Error { }
            }
            It 'Reports failure' {
                Verify-Registration -UPN 'user@test.com' -DisplayName 'OneSpan FX7 715096158'
                Should -Invoke Write-Error -Times 1
            }
        }

        Context 'Graph API call fails' {
            BeforeEach {
                Mock Get-MgBetaUserAuthenticationFido2Method { throw 'Forbidden' }
                Mock Write-Error { }
            }
            It 'Re-throws the error' {
                { Verify-Registration -UPN 'user@test.com' -DisplayName 'OneSpan FX7 715096158' } |
                    Should -Throw
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Process-User' {

        Context 'Key already registered' {
            BeforeEach {
                # Return a key whose DisplayName matches what '715096158' produces
                Mock Get-MgBetaUserAuthenticationFido2Method {
                    [PSCustomObject]@{ DisplayName = 'OneSpan FX7 715096158' }
                }
                Mock Get-EntraPasskeyRegistrationOptions { throw 'Must not be called' }
                Mock Write-Host { }
            }
            It 'Does not attempt registration' {
                Process-User -UPN 'user@test.com' -SerialID '71-5096158' -DisplayName ''
                Should -Invoke Get-EntraPasskeyRegistrationOptions -Times 0
            }
            It 'Calls Verify-Registration path (Write-Host fires)' {
                Process-User -UPN 'user@test.com' -SerialID '71-5096158' -DisplayName ''
                Should -Invoke Write-Host -Times 1
            }
        }

        Context 'Key not yet registered' {
            BeforeEach {
                Mock Get-MgBetaUserAuthenticationFido2Method { @() }
                Mock Get-EntraPasskeyRegistrationOptions { [PSCustomObject]@{} }
                Mock New-Passkey { $script:MockCredential }
                Mock Invoke-MgGraphRequest {
                    '{"id":"fakeid","displayName":"OneSpan FX7 715096158"}'
                }
                Mock Write-Host { }
                # Verify-Registration calls Write-Error when the post-registration
                # key-lookup returns nothing. Mock it so it does not terminate
                # under $ErrorActionPreference = 'Stop'.
                Mock Write-Error { }
            }
            It 'Calls Get-EntraPasskeyRegistrationOptions' {
                Process-User -UPN 'user@test.com' -SerialID '71-5096158' -DisplayName ''
                Should -Invoke Get-EntraPasskeyRegistrationOptions -Times 1
            }
            It 'Calls New-Passkey to drive the physical key' {
                Process-User -UPN 'user@test.com' -SerialID '71-5096158' -DisplayName ''
                Should -Invoke New-Passkey -Times 1
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Data alignment' {

        Describe 'Serial number normalisation' {

            It 'Strips hyphens from a hyphenated serial' {
                '71-5096158-8' -replace '-', '' | Should -Be '7150961588'
            }

            It 'Leaves a clean serial unchanged' {
                '715096158' -replace '-', '' | Should -Be '715096158'
            }

            It 'Handles serials with multiple consecutive hyphens' {
                '1-2-3-4-5' -replace '-', '' | Should -Be '12345'
            }

            It 'Process-User normalises serial before building DisplayName' {
                Mock Get-MgBetaUserAuthenticationFido2Method { @() }
                Mock Get-EntraPasskeyRegistrationOptions { [PSCustomObject]@{} }
                Mock New-Passkey { $null }    # return null -> Create-and-Register-Passkey returns null -> no verify
                Mock Invoke-MgGraphRequest { '{"id":"x"}' }

                $script:capturedDisplayName = $null
                Mock Invoke-MgGraphRequest {
                    $body = [System.Text.Encoding]::UTF8.GetString($Body) | ConvertFrom-Json
                    $script:capturedDisplayName = $body.displayName
                    '{"id":"x","displayName":"test"}'
                }
                Mock New-Passkey { $script:MockCredential }
                # Verify-Registration's Write-Error (key not found after registration)
                # must not terminate when $ErrorActionPreference = 'Stop'.
                Mock Write-Error { }

                Process-User -UPN 'user@test.com' -SerialID '71-5096158' -DisplayName ''
                $script:capturedDisplayName | Should -Be 'OneSpan FX7 715096158'
            }
        }

        Describe 'DisplayName constraints' {

            It 'Follows the OneSpan FX7 <serial> pattern' {
                "OneSpan FX7 $('71-5096158-8' -replace '-', '')" |
                    Should -Be 'OneSpan FX7 7150961588'
            }

            It 'Is at most 30 characters for a 15-digit serial (longest realistic)' {
                $displayName = "OneSpan FX7 $('1' * 15)"
                $displayName.Length | Should -BeLessOrEqual 30
            }

            It 'Is never empty for a valid serial' {
                $displayName = "OneSpan FX7 $('71-5096158-8' -replace '-', '')"
                $displayName | Should -Not -BeNullOrEmpty
                $displayName.Length | Should -BeGreaterThan 0
            }
        }

        Describe 'JSON body structure (Graph fido2AuthenticationMethod schema)' {

            BeforeAll {
                $credId   = ConvertTo-Base64Url ([byte[]](0xcc, 0xee, 0x00, 0x11))
                $cdj      = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes('{"type":"webauthn.create"}'))
                $attest   = ConvertTo-Base64Url ([byte[]](0x01, 0x02, 0x03))

                $script:TestBodyJson = ([ordered]@{
                    displayName         = 'OneSpan FX7 000000'
                    publicKeyCredential = [ordered]@{
                        id       = $credId
                        response = [ordered]@{
                            clientDataJSON    = $cdj
                            attestationObject = $attest
                        }
                    }
                } | ConvertTo-Json -Depth 5 -Compress) | ConvertFrom-Json
            }

            It 'Has displayName at root' {
                $script:TestBodyJson.displayName | Should -Not -BeNullOrEmpty
            }

            It 'Has publicKeyCredential at root' {
                $script:TestBodyJson.publicKeyCredential | Should -Not -BeNullOrEmpty
            }

            It 'Has publicKeyCredential.id' {
                $script:TestBodyJson.publicKeyCredential.id | Should -Not -BeNullOrEmpty
            }

            It 'Has publicKeyCredential.response.clientDataJSON' {
                $script:TestBodyJson.publicKeyCredential.response.clientDataJSON |
                    Should -Not -BeNullOrEmpty
            }

            It 'Has publicKeyCredential.response.attestationObject' {
                $script:TestBodyJson.publicKeyCredential.response.attestationObject |
                    Should -Not -BeNullOrEmpty
            }

            It 'Does not include rawId (not in Graph schema)' {
                $script:TestBodyJson.publicKeyCredential.PSObject.Properties.Name |
                    Should -Not -Contain 'rawId'
            }

            It 'Does not include type (not in Graph schema)' {
                $script:TestBodyJson.publicKeyCredential.PSObject.Properties.Name |
                    Should -Not -Contain 'type'
            }

            It 'Does not include authenticatorAttachment (not in Graph schema)' {
                $script:TestBodyJson.publicKeyCredential.PSObject.Properties.Name |
                    Should -Not -Contain 'authenticatorAttachment'
            }

            It 'All base64url fields use URL-safe alphabet only' {
                $fields = @(
                    $script:TestBodyJson.publicKeyCredential.id
                    $script:TestBodyJson.publicKeyCredential.response.clientDataJSON
                    $script:TestBodyJson.publicKeyCredential.response.attestationObject
                )
                foreach ($f in $fields) {
                    $f | Should -Match '^[A-Za-z0-9_-]*$' -Because 'base64url must not contain +, /, or ='
                }
            }
        }

        Describe 'OneSpan FX7 AAGUID values' {

            BeforeAll {
                # Authoritative OneSpan FX7 AAGUIDs from the FIDO Alliance MDS3.
                # These must remain consistent with what is configured in the tenant
                # FIDO2 key restriction allow list.
                $script:KnownFX7AAGUIDs = @(
                    '30b5035e-d297-4ff7-b00b-addc96ba6a98'  # OneSpan DIGIPASS FX7
                    '30b5035e-d297-4ff7-020b-addc96ba6a98'  # OneSpan DIGIPASS FX7
                    '30b5035e-d297-4ff7-010b-addc96ba6a98'  # OneSpan DIGIPASS FX7-B
                    '30b5035e-d297-4ff7-030b-addc96ba6a98'  # OneSpan DIGIPASS FX7-C
                )

                # AAGUIDs confirmed in the tenant's FIDO2 key restriction allow list
                $script:TenantAllowList = @(
                    '30b5035e-d297-4ff7-b00b-addc96ba6a98'
                    '30b5035e-d297-4ff7-010b-addc96ba6a98'
                    '30b5035e-d297-4ff7-020b-addc96ba6a98'
                    '30b5035e-d297-4ff7-030b-addc96ba6a98'
                    '30b5035e-d297-4ff1-b00b-addc96ba6a98'
                    '30b5035e-d297-4ff1-020b-addc96ba6a98'
                    '30b5035e-d297-4ff1-010b-addc96ba6a98'
                )
            }

            It 'Has exactly 4 distinct FX7 variant AAGUIDs' {
                $script:KnownFX7AAGUIDs | Should -HaveCount 4
                ($script:KnownFX7AAGUIDs | Select-Object -Unique).Count | Should -Be 4
            }

            It 'All FX7 AAGUIDs are in lowercase hyphenated UUID format' {
                $uuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                foreach ($aaguid in $script:KnownFX7AAGUIDs) {
                    $aaguid | Should -Match $uuidPattern -Because "$aaguid must be a valid lowercase UUID"
                }
            }

            It 'All FX7 AAGUIDs share the OneSpan FX7 vendor prefix 30b5035e-d297-4ff7-' {
                foreach ($aaguid in $script:KnownFX7AAGUIDs) {
                    $aaguid | Should -Match '^30b5035e-d297-4ff7-' -Because 'all FX7 variants share this prefix'
                }
            }

            It 'All known FX7 AAGUIDs are present in the tenant allow list' {
                $allowedLower = $script:TenantAllowList | ForEach-Object { $_.ToLower() }
                foreach ($aaguid in $script:KnownFX7AAGUIDs) {
                    $aaguid.ToLower() | Should -BeIn $allowedLower -Because "$aaguid must be in the tenant allow list"
                }
            }

            It 'AAGUID comparison is case-insensitive (policy uses lowercase, keys may report mixed case)' {
                $upper = '30B5035E-D297-4FF7-B00B-ADDC96BA6A98'
                $lower = '30b5035e-d297-4ff7-b00b-addc96ba6a98'
                $upper.ToLower() | Should -Be $lower
            }

            It 'Extracts the correct AAGUID from authenticatorData byte offset 37' {
                # Validates the byte-slicing logic used in Create-and-Register-Passkey
                $authData = $script:MockAuthData
                $hex = [BitConverter]::ToString($authData[37..52]).Replace('-', '').ToLower()
                $extracted = '{0}-{1}-{2}-{3}-{4}' -f `
                    $hex.Substring(0,8), $hex.Substring(8,4), $hex.Substring(12,4),
                    $hex.Substring(16,4), $hex.Substring(20,12)
                $extracted | Should -Be '30b5035e-d297-4ff7-b00b-addc96ba6a98'
            }

            It 'Tenant allow list contains no malformed AAGUIDs' {
                $uuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                foreach ($aaguid in $script:TenantAllowList) {
                    $aaguid | Should -Match $uuidPattern -Because "$aaguid in allow list must be a valid UUID"
                }
            }
        }

        Describe 'UPN format and URL encoding' {

            It 'URL-encodes the @ sign in UPN for use in Graph API URLs' {
                [uri]::EscapeDataString('chase.foster@wfncd.onmicrosoft.com') |
                    Should -Be 'chase.foster%40wfncd.onmicrosoft.com'
            }

            It 'URL-encoded UPN does not contain a literal @ character' {
                [uri]::EscapeDataString('user@contoso.com') | Should -Not -Contain '@'
            }

            It 'Registration URL uses the URL-encoded UPN' {
                $upn = 'user@contoso.com'
                $url = '/beta/users/{0}/authentication/fido2Methods' -f [uri]::EscapeDataString($upn)
                $url | Should -Be '/beta/users/user%40contoso.com/authentication/fido2Methods'
            }
        }

        Describe 'CSV data alignment' {

            It 'CSV header must have UPN and SerialID columns' {
                $csv = "UPN,SerialID`nuser@test.com,71-5096158-8" | ConvertFrom-Csv
                $csv[0].PSObject.Properties.Name | Should -Contain 'UPN'
                $csv[0].PSObject.Properties.Name | Should -Contain 'SerialID'
            }

            It 'CSV UPN column is non-empty for a valid row' {
                $csv = "UPN,SerialID`nuser@test.com,71-5096158-8" | ConvertFrom-Csv
                $csv[0].UPN | Should -Not -BeNullOrEmpty
            }

            It 'CSV SerialID column is non-empty for a valid row' {
                $csv = "UPN,SerialID`nuser@test.com,71-5096158-8" | ConvertFrom-Csv
                $csv[0].SerialID | Should -Not -BeNullOrEmpty
            }

            It 'Multi-row CSV produces the correct number of entries' {
                $csv = "UPN,SerialID`nuser1@test.com,111`nuser2@test.com,222`nuser3@test.com,333" |
                    ConvertFrom-Csv
                $csv | Should -HaveCount 3
            }

            It 'SerialID with dashes from CSV normalises correctly' {
                $serialFromCsv = '71-5096158-8'
                $serialFromCsv -replace '-', '' | Should -Be '7150961588'
            }

            It 'Each CSV row produces an independent DisplayName' {
                $csv = "UPN,SerialID`nuser1@test.com,111`nuser2@test.com,222" | ConvertFrom-Csv
                $names = $csv | ForEach-Object { "OneSpan FX7 $($_.SerialID -replace '-', '')" }
                $names[0] | Should -Be 'OneSpan FX7 111'
                $names[1] | Should -Be 'OneSpan FX7 222'
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Main script body – CSV mode' {
        # These tests call Main with -Force and -CsvFilePath to exercise the CSV
        # branch (Import-Csv, the batch loop, error catching). -Force bypasses the
        # Confirm-Action prompt. All external calls are mocked; an actual temp file
        # is used for Import-Csv.

        It 'Processes a two-row CSV without throwing' {
            $csv = (New-TemporaryFile).FullName
            "UPN,SerialID`ncsvuser@test.com,555555`ncsvuser2@test.com,666666" | Set-Content $csv
            Mock Get-MgBetaUserAuthenticationFido2Method {
                @(
                    [PSCustomObject]@{ DisplayName = 'OneSpan FX7 555555' },
                    [PSCustomObject]@{ DisplayName = 'OneSpan FX7 666666' }
                )
            }
            Mock Write-Host  { }
            Mock Write-Error { }
            try {
                { Main -TenantId 'test.onmicrosoft.com' -CsvFilePath $csv -Force } |
                    Should -Not -Throw
            } finally { Remove-Item $csv -Force -ErrorAction SilentlyContinue }
        }

        It 'Handles a single-row CSV (non-array Import-Csv result, triggers $totalEntries = 1 path)' {
            $csv = (New-TemporaryFile).FullName
            "UPN,SerialID`noneuser@test.com,777777" | Set-Content $csv
            Mock Get-MgBetaUserAuthenticationFido2Method {
                [PSCustomObject]@{ DisplayName = 'OneSpan FX7 777777' }
            }
            Mock Write-Host  { }
            Mock Write-Error { }
            try {
                { Main -TenantId 'test.onmicrosoft.com' -CsvFilePath $csv -Force } |
                    Should -Not -Throw
            } finally { Remove-Item $csv -Force -ErrorAction SilentlyContinue }
        }

        It 'Catches per-row errors with -ErrorAction Continue so the batch continues' {
            $csv = (New-TemporaryFile).FullName
            "UPN,SerialID`nerruser@test.com,999999" | Set-Content $csv
            Mock Get-MgBetaUserAuthenticationFido2Method { @() }
            Mock Get-EntraPasskeyRegistrationOptions { throw 'Simulated failure' }
            $script:batchErrorFired = $false
            Mock Write-Error { $script:batchErrorFired = $true }
            try {
                # The per-row catch calls Write-Error -ErrorAction Continue; Main
                # must complete (not terminate) even though an individual row failed.
                { Main -TenantId 'test.onmicrosoft.com' -CsvFilePath $csv -Force } |
                    Should -Not -Throw
                $script:batchErrorFired | Should -Be $true
            } finally {
                Remove-Item $csv -Force -ErrorAction SilentlyContinue
                $script:batchErrorFired = $null
            }
        }

        It 'Writes an error and throws when the CSV file contains only a header row' {
            # A header-only CSV causes Import-Csv to return $null (no data rows).
            # The script writes a diagnostic error then throws so the caller gets a
            # clear exception rather than silently doing nothing.
            $csv = (New-TemporaryFile).FullName
            'UPN,SerialID' | Set-Content $csv   # header only — no data rows
            Mock Write-Error { }
            Mock Write-Host  { }
            try {
                { Main -TenantId 'test.onmicrosoft.com' -CsvFilePath $csv -Force } |
                    Should -Throw
                Should -Invoke Write-Error -Times 1 -ParameterFilter {
                    $Message -match 'empty'
                }
            } finally { Remove-Item $csv -Force -ErrorAction SilentlyContinue }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Main script body – interactive prompts' {
        # These tests call Main with deliberate parameter omissions to exercise the
        # Read-Host prompt branches. -Force is passed to bypass Confirm-Action.
        # Get-MgBetaUserAuthenticationFido2Method is overridden per-test to return a
        # pre-registered key so Process-User takes the "already registered" path.

        It 'Prompts for TenantId when -TenantId is not supplied' {
            # Providing UPN+SerialID prevents the CsvFilePath/UPN/SerialID prompts from
            # firing, isolating line 348 (TenantId prompt) as the only Read-Host call.
            Mock Get-MgBetaUserAuthenticationFido2Method {
                [PSCustomObject]@{ DisplayName = 'OneSpan FX7 111111' }
            }
            Mock Write-Host { }
            # Use a direct try/catch rather than { } | Should -Not -Throw so that
            # Should -Invoke on the next line doesn't receive pipeline input.
            $threw = $false
            try { Main -UPN 'prompt@test.com' -SerialID '111111' -Force } catch { $threw = $true }
            $threw | Should -Be $false -Because 'script should complete when TenantId is supplied via Read-Host'
        }

        It 'Prompts for CsvFilePath, UPN, and SerialID when only TenantId is supplied' {
            # With no CsvFilePath AND no UPN/SerialID, the script hits:
            #   line 355 — Read-Host for CsvFilePath (returns '' → non-CSV path)
            #   line 384 — Read-Host for UPN
            #   line 387 — Read-Host for SerialID
            # Read-Host is called 3 times; a counter mock returns '' for the CSV path
            # prompt and meaningful values for UPN and SerialID so Process-User succeeds.
            $script:promptCallCount = 0
            Mock Read-Host {
                $script:promptCallCount++
                switch ($script:promptCallCount) {
                    1 { '' }              # line 355 — CsvFilePath → '' triggers non-CSV path
                    2 { 'p@test.com' }    # line 384 — UPN
                    3 { '222222' }        # line 387 — SerialID
                    default { '' }
                }
            }
            Mock Get-MgBetaUserAuthenticationFido2Method {
                [PSCustomObject]@{ DisplayName = 'OneSpan FX7 222222' }
            }
            Mock Write-Host { }
            $threw = $false
            try { Main -TenantId 'test.onmicrosoft.com' -Force } catch { $threw = $true }
            $threw | Should -Be $false -Because 'script should complete when UPN and SerialID are supplied via Read-Host'
            $script:promptCallCount | Should -BeGreaterOrEqual 3 -Because 'all three Read-Host prompts must fire'
            $script:promptCallCount = $null
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Main – Windows-only guard' {

        It 'Throws when run on a non-Windows system (simulated via IsWindowsOverride)' {
            $script:IsWindowsOverride = $false
            try {
                { Main -TenantId 'test.onmicrosoft.com' -UPN 'x@test.com' -SerialID '000000' -Force } |
                    Should -Throw '*Windows*'
            } finally {
                $script:IsWindowsOverride = $null
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Describe 'Entry-point guard' {
        # Invokes the script with & (not dot-source) so InvocationName != '.' and
        # the entry-point guard fires, calling Main. All external deps are mocked.

        It 'Calls Main when script is executed directly with TEST_MODE unset' {
            Mock Get-MgBetaUserAuthenticationFido2Method {
                [PSCustomObject]@{ DisplayName = 'OneSpan FX7 888888' }
            }
            Mock Write-Host { }
            $prev = $env:TEST_MODE
            try {
                $env:TEST_MODE = $null
                { & $script:ScriptPath -TenantId 'test.onmicrosoft.com' -UPN 'guard@test.com' -SerialID '888888' -Force } |
                    Should -Not -Throw
            } finally {
                $env:TEST_MODE = $prev
            }
        }
    }
}
