# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [1.1.0] - 2026-06-15

### Added

- **`Write-Log`** — centralised logging function routing to `Write-Host`, `Write-Error`, `Write-Warning`, or `Write-Verbose` based on a `Level` parameter (`Host`, `Error`, `Warn`, `Verbose`). Optionally appends timestamped entries to a log file when `$script:LogPath` is set.
- **`Confirm-Action`** — interactive confirmation gate before any credential ceremony. Skipped automatically when `-Force` or `-DryRun` is supplied; throws on user rejection.
- **`Main`** function — wraps the entire execution body so the script can be dot-sourced (by Pester or for module reuse) without immediately running against a live tenant.
- **Dual entry-point guard** — `Main` is called only when the script is invoked directly (`$MyInvocation.InvocationName -ne '.'`) and `$env:TEST_MODE` is not set, preventing accidental execution during dot-source.
- **`-LogPath`** parameter — optional path to a log file; `Write-Log` appends a timestamped entry for every message when set.
- **`-DryRun`** switch — suppresses the confirmation prompt and emits a warning instead; useful for validating connectivity and policy checks without modifying any credentials.
- **`-Force`** switch — suppresses the interactive confirmation prompt; intended for unattended automation.
- **`$script:PSVersionOverride`** — script-level variable for unit-test isolation; set to `5` or `7` in a `BeforeEach` to force the PS5/PS7 branch of `Ensure-Module` without running under that version.
- **`$script:IsWindowsOverride`** — script-level variable for unit-test isolation; set to `$false` in a `BeforeEach` to test the non-Windows guard in `Main` without running on Linux or macOS.
- **`Get-FidoMdsAAGUIDs`** — queries the FIDO Alliance MDS3 metadata service to enumerate all AAGUIDs registered under a vendor name (default `OneSpan`). Used during `BadRequest` diagnostics to verify whether the connected key is a recognised device.
- **`ConvertTo-Base64Url`** — helper that converts either a `byte[]` or an already-encoded string to base64url (URL-safe alphabet, no padding). Handles the representation change introduced in DSInternals.Passkeys 3.2.0, where response properties changed from `byte[]` to pre-encoded strings.
- **`Assert-Fido2PolicyEnabled`** — reads the tenant's FIDO2 authentication method policy via the Graph Beta API and:
  - Validates that `isSelfServiceRegistrationAllowed` is `true` (required by the provisioning API even for admin-driven registration) and surfaces an actionable remediation message if not.
  - Performs a preflight key-restriction check: if key restrictions are enforced, verifies the connected key's AAGUID against the allow/block list and fails fast with a clear error before attempting registration.
  - Stores `$script:PolicyKeyRestrictions` for use in `BadRequest` diagnostics downstream.
- **`Process-User`** — encapsulates per-user orchestration: normalises the serial number (strips hyphens), builds the canonical `DisplayName`, checks whether the key is already registered (skip-and-verify path), and drives `Create-and-Register-Passkey` followed by `Verify-Registration`.
- **Pester test suite** (`tests/entra-id-pre-provision-onespan-fx7.Tests.ps1`) — 113 tests covering all functions with mocked external dependencies (no real Graph calls or hardware required), plus CI-verified on both Windows PowerShell 5.1 and PowerShell 7.
- **GitHub Actions CI workflow** (`.github/workflows/pester.yml`) — runs on every push and pull request to `main` against both **Windows PowerShell 5.1** and **PowerShell 7** using a matrix strategy:
  - Installs Pester 5 from PSGallery
  - Executes the full test suite with JaCoCo code coverage scoped to `entra-id-pre-provision-onespan-fx7.ps1`
  - Publishes per-version test results to the Checks tab via `dorny/test-reporter`
  - Writes a per-version coverage table to the GitHub Actions job summary
  - Fails the build if coverage falls below 90 % or any test fails
  - Uploads per-version coverage XML and JUnit XML as 30-day workflow artifacts

### Changed

- **`Ensure-Module`** now uses `Install-PSResource` on PowerShell 7+ (the modern replacement for the deprecated `Install-Module`) and falls back to `Install-Module` on Windows PowerShell 5.1. When a `MinimumVersion` is specified, the NuGet range syntax `[version,)` is passed to `Install-PSResource`.
- **Registration no longer uses `Register-EntraPasskey`** (DSInternals.Passkeys). In version 3.2.0 that cmdlet's `ToString()` serialisation changed to emit raw OS credential JSON, omitting the `{displayName, publicKeyCredential}` wrapper required by the Graph API. The function now manually constructs the POST body and calls `Invoke-MgGraphRequest` directly, bypassing the broken serialiser entirely.
- **POST body sent as UTF-8 bytes** (`byte[]`) rather than a string. Some versions of the Microsoft Graph SDK re-serialise a string body as a JSON string literal (double-encoding it). Sending bytes bypasses all SDK serialisation logic and guarantees the server receives a JSON object at the root.
- **UPN URL-encoded** in the Graph API endpoint path using `[uri]::EscapeDataString()`, ensuring addresses with `@` and other special characters are correctly escaped (`user%40domain.com`).
- **AAGUID extracted from `AuthenticatorData`** at byte offset 37 (after the 32-byte rpIdHash, 1-byte flags, and 4-byte sign count). If the extracted AAGUID differs from the pre-flight value detected on the connected key, a warning is emitted indicating that Windows Hello may have intercepted the credential ceremony.
- **`BadRequest` error handling** overhauled: the full inner-exception chain is now walked to surface the actual Graph API response body (previously swallowed by DSInternals rethrows). The diagnostic output includes the exact POST body sent, the connected key's AAGUID, the key-restriction check result, and a live FIDO Alliance MDS3 lookup to validate whether the AAGUID is a known OneSpan device.
- **User-cancellation** (`The operation has been canceled by the user`) now returns `$null` with a `Write-Warning` prompt to retry, rather than propagating an unhandled exception.
- **`Assert-Fido2PolicyEnabled`** is now called in the main script flow immediately after connecting to Microsoft Graph, providing an early-exit policy preflight before any credential ceremony begins.

### Fixed

- DSInternals.Passkeys 3.2.0 compatibility: the broken `Register-EntraPasskey` serialiser is bypassed by posting directly via `Invoke-MgGraphRequest` with a manually built body.
- Fields `rawId`, `type`, and `authenticatorAttachment` are explicitly excluded from the POST body; the Graph API rejects requests that include them.
- **`Connect-ToMsGraph`** no longer calls `exit 1` on connection failure; it now uses `Write-Error -ErrorAction Continue` followed by `throw` so the error propagates correctly to the caller and is testable.
- **`Assert-Fido2PolicyEnabled`** restructured: only the Graph API call lives inside `try/catch` (network/permissions failure → non-fatal warning). Validation failures (self-service disabled, AAGUID blocked/not-allowed) now `throw` outside the catch so they propagate to the caller rather than being silently swallowed.
- **Empty CSV** (`Import-Csv` returns `$null`) now throws after writing a diagnostic error instead of calling `exit 1`, keeping behaviour consistent with the rest of the script and allowing the condition to be tested.
- **`Write-Error` calls that are non-fatal** (in `Verify-Registration` and the CSV batch loop) now carry `-ErrorAction Continue` so they do not terminate under `$ErrorActionPreference = 'Stop'` (the GitHub Actions default for `powershell` and `pwsh` steps).
- **`#Requires -Version 5.1`** added at the top of the script; PowerShell enforces this before any parsing, giving a clean version error on unsupported hosts.
- **Windows-only guard** moved inside `Main` and made testable via `$script:IsWindowsOverride`; on PowerShell 6+ non-Windows hosts the script throws immediately with a message pointing to the `webauthn.dll` dependency.

---

## [1.0.0] - Initial Release

### Added

- `Ensure-Module` — auto-installs `Microsoft.Graph.Beta.Identity.SignIns` and `DSInternals.Passkeys` if not present (no minimum version enforced).
- `Connect-ToMsGraph` — connects to Microsoft Graph with the `UserAuthenticationMethod.ReadWrite.All` scope.
- `Create-and-Register-Passkey` — drives the WebAuthn credential ceremony using the DSInternals.Passkeys pipeline: `Get-PasskeyRegistrationOptions | New-Passkey | Register-Passkey`.
- `Verify-Registration` — confirms a registered passkey is visible in the Graph API after provisioning.
- `Process-User` — per-user orchestration: checks if a passkey already exists, registers if absent, and verifies on completion.
- Single-user registration via `-UPN` and `-SerialID` parameters.
- Bulk registration via `-CsvFilePath` (CSV format: `UPN,SerialID`).
- Interactive prompts for any missing parameter values.
- `DisplayName` automatically set to `OneSpan FX7 {SerialID}`.
