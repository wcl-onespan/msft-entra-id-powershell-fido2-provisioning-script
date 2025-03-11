# Microsoft Entra ID PowerShell FIDO2 Provisioning Script for OneSpan FIDO2 FX Series Hardware Authenticators

This PowerShell script allows administrators to pre-provision **OneSpan FX7 FIDO2 security keys** in **Microsoft Entra ID**, either for a **single user** or in **bulk** via CSV. It registers FIDO2 passkeys on behalf of users using **Microsoft Graph** and the **DSInternals.Passkeys** module.

---

## 🔧 Features

- 💠 Supports **OneSpan FX7 FIDO2** security keys
- 👤 Register **a single user's** passkey by UPN and device serial
- 📂 Register **multiple users** using a CSV file
- 🔐 Verifies key registration via Microsoft Graph Beta endpoint
- 🧩 Uses `DSInternals.Passkeys` and `Microsoft.Graph.Beta.Identity.SignIns` modules

---

## 📦 Prerequisites

- PowerShell 7.x (recommended)
- Microsoft Graph PowerShell SDK
- DSInternals.Passkeys PowerShell module

The script installs missing modules automatically.

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

1. Connects to Microsoft Graph using the provided tenant.
2. For each user, checks if a passkey with the given display name already exists.
3. If not present, it calls:
   - `Get-PasskeyRegistrationOptions`
   - `New-Passkey`
   - `Register-Passkey`
4. Verifies registration by querying `Get-MgBetaUserAuthenticationFido2Method`.

---

## ✅ Example Output

```text
Processing user user1@domain.com with OneSpan FX7 serial number FX7-12345678 (1 of 2)...
Passkey registered successfully for user user1@domain.com.
```

---

## 📝 Notes

- Display name for each passkey is automatically set to `OneSpan FX7 {SerialID}`.
- Assumes the administrator running the script has access to a OneSpan FX7 device for signing the passkey.

---

## 📄 License

This script is provided under the MIT License. See `LICENSE` for details.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Please open an issue or submit a PR.

---

## 📫 Contact

For enterprise support or integration questions, contact [OneSpan](https://www.onespan.com).
