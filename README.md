# Microsoft Entra ID PowerShell FIDO2 Provisioning Script for OneSpan FIDO2 FX Series Hardware Authenticators

This PowerShell script allows administrators to pre-provision **OneSpan FX7 FIDO2 security keys** in **Microsoft Entra ID**, either for a **single user** or in **bulk** via CSV. It registers FIDO2 passkeys on behalf of users using **Microsoft Graph** and the **DSInternals.Passkeys** module.

### Further documentation can be found at 
- https://docs.onespan.com/sec/docs/hwrd-fx7-microsoft-entraid-registering-a-passkey-in-entraid-using-powershell
- https://docs.onespan.com/sec/docs/hwrd-fx7-microsoft-entraid-registering-multiple-passkeys-in-entraid-using-powershell-and-csv

---

## 🔧 Features

- 💠 Supports **OneSpan FX7 FIDO2** security keys (all AAGUID variants)
- 👤 Register **a single user's** passkey by UPN and device serial
- 📂 Register **multiple users** using a CSV file
- 🔐 Verifies key registration via Microsoft Graph Beta endpoint
- 🛡️ Pre-flight FIDO2 policy check — validates self-service setup and key restriction allow/block lists before attempting registration
- 🔎 AAGUID detection from `authenticatorData` — warns if Windows Hello intercepts the credential ceremony instead of the physical FX7
- 🌐 Live FIDO Alliance MDS3 lookup on `BadRequest` to validate the connected key against known OneSpan device AAGUIDs
- 🧩 Uses `DSInternals.Passkeys` and `Microsoft.Graph.Beta.Identity.SignIns` modules

---

## 📦 Prerequisites

- PowerShell 5.1 or later (PowerShell 7.x recommended)
- Microsoft Graph PowerShell SDK
- DSInternals.Passkeys PowerShell module (≥ 3.1.0)

The script installs missing modules automatically.

> **Entra ID policy requirement:** The FIDO2 authentication method policy must have **Allow self-service setup** set to **Yes**, even for admin-provisioned registration. This is a Graph API requirement, not an end-user permission. See [Microsoft's known issue](https://learn.microsoft.com/en-us/graph/known-issues#fido2-provisioning-api-requires-self-service-setup-to-be-enabled) for details.

---

## 📄 CSV Format (for bulk registration)

The CSV must include a header row:

```csv
UPN,SerialID
user1@domain.com,FX7-12345678
user2@domain.com,FX7-87654321
```

---

## 🚀 Usage

### 🔹 Single User Registration

```powershell
.\entra-id-pre-provision-onespan-fx7.ps1 -TenantId "yourtenant.onmicrosoft.com" -UPN "user@domain.com" -SerialID "FX7-12345678"
```

### 🔹 Bulk Registration via CSV

```powershell
.\entra-id-pre-provision-onespan-fx7.ps1 -TenantId "yourtenant.onmicrosoft.com" -CsvFilePath ".\users.csv"
```

You can also run the script interactively and it will prompt for missing values.

---

## 📘 How It Works

1. Ensures required modules (`Microsoft.Graph.Identity.SignIns`, `DSInternals.Passkeys`) are installed, installing them if needed.
2. Connects to Microsoft Graph using the provided tenant ID with `UserAuthenticationMethod.ReadWrite.All` and `Policy.Read.All` scopes.
3. Runs a FIDO2 policy preflight (`Assert-Fido2PolicyEnabled`):
   - Verifies that **Allow self-service setup** is enabled (required by the Graph provisioning API).
   - If key restrictions are enforced, checks that the connected key's AAGUID is on the allow list (or not on the block list) before proceeding.
4. For each user, checks whether a passkey with the expected `DisplayName` already exists; if so, verifies it and skips registration.
5. If not already registered, drives the credential ceremony via:
   - `Get-EntraPasskeyRegistrationOptions` — fetches challenge options from Entra ID for the target user.
   - `New-Passkey` — performs the WebAuthn credential creation ceremony against the connected FX7.
   - `Invoke-MgGraphRequest POST /beta/users/{upn}/authentication/fido2Methods` — posts a manually constructed JSON body (bypassing the DSInternals serialiser, which changed in v3.2.0).
6. Extracts the AAGUID from the returned `authenticatorData` and warns if the credential was signed by a different authenticator (e.g. Windows Hello intercepted the request).
7. Verifies registration by querying `Get-MgBetaUserAuthenticationFido2Method` and confirming the new key appears.

---

## ✅ Example Output

```text
Processing user user1@domain.com with OneSpan FX7 serial number FX7-12345678 (1 of 2)...
Passkey registered successfully for user user1@domain.com.
```

---

## 🧪 Testing

The project includes a Pester 5 test suite covering all functions with mocked external dependencies. No real Graph API calls or physical hardware are required to run the tests.

```powershell
# Install Pester if needed
Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force

# Run all tests
Invoke-Pester .\tests\entra-id-pre-provision-onespan-fx7.Tests.ps1 -Output Detailed
```

All 98 tests should pass on both **Windows PowerShell 5.1** and **PowerShell 7+**.

> **Module-independence:** The test suite does **not** require `Microsoft.Graph` or `DSInternals.Passkeys` to be installed. All external commands (`Connect-MgGraph`, `Invoke-MgGraphRequest`, `Get-MgBetaUserAuthenticationFido2Method`, `Get-EntraPasskeyRegistrationOptions`, `New-Passkey`) are stubbed with `function global:` definitions in `BeforeAll` if they are absent, then overridden per-test with Pester mocks. This allows the suite to run in any environment — including CI runners, the VS Code PowerShell Extension terminal (which uses `pwsh`), and machines that only have Pester installed.

---

## 📝 Notes

- Display name for each passkey is automatically set to `OneSpan FX7 {SerialID}` (hyphens stripped from the serial).
- Assumes the administrator running the script has a OneSpan FX7 device connected and available for the WebAuthn credential ceremony.
- The script is compatible with Windows PowerShell 5.1. The `DSInternals.Passkeys` module requires a Windows environment for the WebAuthn API.

---

## 📄 License

This script is provided under the MIT License. See `LICENSE` for details.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Please open an issue or submit a PR.

---

## 📫 Contact

For enterprise support or integration questions, contact [OneSpan](https://www.onespan.com).
