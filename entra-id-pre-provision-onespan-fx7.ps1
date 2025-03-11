<#
.SYNOPSIS
    Register OneSpan FX7 FIDO2 device on behalf of a user or bulk users from a csv file
.DESCRIPTION
    This script registers a OneSpan FX7 FIDO2 key on behalf of a user. The script requires the admin to have a OneSpan FX7 key and the user's UPN.
    The script will connect to Microsoft Graph and register the OneSpan FX7 key on behalf of the user specified.
    The script will also register the OneSpan FX7 key in Entra ID.
    If a CSV file is used, the first line in the file should be "UPN,SerialID", then each user should be listed one user per line with a serial number.
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
        [string]$ModuleName
    )
    if (-not (Get-Module -Name $ModuleName -ListAvailable)) {
        Install-Module -Name $ModuleName -Scope CurrentUser -Force -ErrorAction Stop
    }
}

# Function to connect to Microsoft Graph
function Connect-ToMsGraph {
    param (
        [string]$TenantId
    )
    try {
        Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All" -TenantId $TenantId -ErrorAction Stop
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }
}

# Function to register the passkey on the FIDO2 key
function Create-and-Register-Passkey {
    param (
        [string]$UPN,
        [string]$DisplayName
    )
    try {
        # $FIDO2Options = Get-PasskeyRegistrationOptions -UserId $UPN -ErrorAction Stop
        # $FIDO2 = New-Passkey -Options $FIDO2Options -DisplayName $DisplayName -ErrorAction Stop
        # $Registered = Register-Passkey -DisplayName $DisplayName -UserId $UPN -ErrorAction Stop
        $Registered = Get-PasskeyRegistrationOptions -UserId $UPN -ErrorAction Stop | New-Passkey -DisplayName $DisplayName -ErrorAction Stop | Register-Passkey -UserID $UPN -ErrorAction Stop
        return $Registered
    } catch {
        Write-Error "Failed to register the passkey: $_"
        exit 1
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
            Write-Error "Failed to verify the registration of the passkey."
        }
    } catch {
        Write-Error "Failed to verify the registration: $_"
        exit 1
    }
}

function Process-User {
    param (
        [string]$UPN,
        [string]$SerialID,
        [string]$DisplayName
    )
    $DisplayName = "OneSpan FX7 $SerialID"
    $RegisteredKey = Get-MgBetaUserAuthenticationFido2Method -UserId $UPN | Where-Object { $_.DisplayName -eq $DisplayName }
    if ($RegisteredKey) {
        Write-Host "Passkey already registered for user $UPN. Verifying..."
        Verify-Registration -UPN $UPN -DisplayName $DisplayName
    } else {
        Create-and-Register-Passkey -UPN $UPN -DisplayName $DisplayName
        Verify-Registration -UPN $UPN -DisplayName $DisplayName
    }
}

Ensure-Module -ModuleName "Microsoft.Graph.Beta.Identity.SignIns"
Ensure-Module -ModuleName "DSInternals.Passkeys"

if (-not $TenantId) {
    $TenantId = Read-Host "Enter Tenant ID"
}

Connect-ToMsGraph -TenantId $TenantId

if (-not $CsvFilePath -and (-not $UPN -or -not $SerialID)) {
    $CsvFilePath = Read-Host "Enter CSV file path (leave blank if not using CSV)"
}

if ($CsvFilePath) {
    $csvData = Import-Csv -Path $CsvFilePath
    if (-not $csvData) {
        Write-Error "The CSV file is empty. Please provide a valid CSV file."
        exit 1
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
            Write-Error "Error processing user $($row.UPN) with serial number $($row.SerialID): $_"
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
