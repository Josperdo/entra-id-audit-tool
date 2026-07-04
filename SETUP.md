# Setup Guide

## Prerequisites

- **PowerShell 7+** ([Install guide](https://learn.microsoft.com/powershell/scripting/install/installing-powershell))
- **Microsoft.Graph PowerShell SDK module**
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```
- **An Entra ID account or app registration** with at least the following Graph API permission scopes (read-only):
  - `User.Read.All`
  - `AuditLog.Read.All`
  - `Policy.Read.All`
  - `RoleManagement.Read.Directory`
  - `Application.Read.All`
- A modern browser (Chrome/Edge/Firefox) to view the dashboard — no server required.

## App Registration Setup (Entra ID)

Before running the script you need an App Registration in your Entra ID tenant with the required read-only Graph API permissions.

### 1. Create the App Registration

1. Go to [portal.azure.com](https://portal.azure.com) → **Microsoft Entra ID** → **App registrations** → **New registration**
2. Fill in:
   - **Name:** `entra-audit-tool` (or any name you'll recognise)
   - **Supported account types:** Accounts in this organizational directory only (single tenant)
   - **Redirect URI:** leave blank
3. Click **Register**
4. On the overview page, copy and save:
   - **Application (client) ID** → this is `appOnly.clientId` in your config
   - **Directory (tenant) ID** → this is `tenantId` in your config

### 2. Grant API Permissions

1. In your App Registration → **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions**
2. Search for and add each of the following:
   - `User.Read.All`
   - `AuditLog.Read.All`
   - `Policy.Read.All`
   - `RoleManagement.Read.Directory`
   - `Application.Read.All`
3. Click **Grant admin consent for [your tenant]** — required for application permissions

> These are all read-only scopes. The app cannot modify any directory data.

### 3. Add a Certificate (App-Only Auth)

App-only auth requires a certificate rather than a client secret (secrets are less secure for unattended use).

```powershell
# Generate a self-signed certificate (run once, save the thumbprint)
$cert = New-SelfSignedCertificate `
    -Subject "CN=entra-audit-tool" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears(2)

Write-Host "Thumbprint: $($cert.Thumbprint)"
```

Then in the portal: App Registration → **Certificates & secrets** → **Certificates** → **Upload certificate** → select the `.cer` export of the cert above.

Copy the thumbprint into `appOnly.certificateThumbprint` in your config.

> **Delegated auth alternative:** If you just want to run interactively (browser sign-in), leave `authMode` as `"delegated"` in your config and skip the certificate step entirely.

---

## Local Development Setup

```powershell
# Clone the repository
git clone <your-repo-url>
cd entra-id-audit-tool

# Install the Graph SDK module (if not already installed)
Install-Module Microsoft.Graph -Scope CurrentUser

# Copy the example config and fill in your tenant-specific values
Copy-Item .\scripts\config\audit-config.example.json .\scripts\config\audit-config.json
```

> `audit-config.json` is gitignored — never commit tenant IDs, client secrets, or other tenant-specific values. See [Security.md](Security.md).

## Running the Script Locally

```powershell
# Authenticate interactively and run all checks
.\scripts\Invoke-EntraAudit.ps1 -ConfigPath .\scripts\config\audit-config.json

# Output is written to reports/ as JSON (and optionally CSV)
```

## Testing the Dashboard with Sample Data

Before connecting to a real tenant, validate the dashboard against the bundled sample data:

```powershell
# Sample data lives in samples/output/sample-data.json
# Open the dashboard directly in a browser
start .\dashboard\index.html
```

Point the dashboard's data loader at `samples/output/sample-data.json` to confirm rendering, filtering, and CSV export work end-to-end without needing live tenant access.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `Connect-MgGraph` fails with insufficient privileges | Missing admin consent for requested scopes | Have a tenant admin grant consent for the scopes listed above |
| Script returns empty results for a check | Wrong Graph API version (`v1.0` vs `beta`) or missing scope | Confirm the scope is granted and check `GraphAPI.psm1` for the endpoint used |
| Dashboard shows blank page | JSON file not found or malformed | Open browser dev tools console; verify the JSON path and that it's valid JSON |
| `Install-Module` fails with execution policy error | PowerShell execution policy restricts script execution | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (or follow your org's policy) |
| Throttled by Graph API (HTTP 429) | Large tenant, too many rapid requests | `GraphAPI.psm1` should implement retry-with-backoff; reduce check frequency for very large tenants |
