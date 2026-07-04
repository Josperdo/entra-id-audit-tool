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
- A modern browser (Chrome/Edge/Firefox) to view the dashboard — no server required for loading a JSON report or sample data.
- **Live Dashboard Mode only**: a local static file server (e.g. `npx serve dashboard` or `python -m http.server 5500`) and a SPA platform added to your App Registration — see "SPA App Registration Setup (Live Dashboard Mode)" below. Not required for the file-upload or sample-data dashboard modes.

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

### 4. SPA App Registration Setup (Live Dashboard Mode)

The dashboard's optional **"Connect Live"** button authenticates directly from the browser (via MSAL.js) and calls Microsoft Graph itself, without the PowerShell step. This requires an `http(s)://` origin — it does not work by opening `index.html` via `file://`. Run a local static server before using Live Mode:

```powershell
# From the repo root, either works — both pin port 5500 explicitly so it
# matches the redirect URI registered below (npx serve without -l picks
# whatever port is free, which won't match):
npx serve dashboard -l 5500
# or
python -m http.server 5500 --directory dashboard
```

This guide assumes `http://localhost:5500` — if you use a different port, make sure the redirect URI you register below matches it exactly.

1. In the **same App Registration** created above (no need for a second one — Entra ID App Registrations support multiple platform configs on one app object) → **Authentication** → **Add a platform** → **Single-page application**.
2. Redirect URI: `http://localhost:5500` (Entra ID explicitly allows plain-`http://localhost` redirect URIs for SPA platforms as a documented local-development exception to its usual https-only rule).
3. **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions** (not Application — that's what the app-only cert flow above already has) → add the same five scopes: `User.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All`.
4. Click **Grant admin consent for [your tenant]**. `RoleManagement.Read.Directory` and `Application.Read.All` typically require admin consent even as delegated scopes (they're tenant-wide directory reads) — without this step, a non-admin user clicking Connect Live will hit a consent-required error.
5. Do **not** add a client secret or certificate for this platform — the SPA flow uses PKCE (no secret exists or is needed for a public client).
6. Copy the **Application (client) ID** and **Directory (tenant) ID** — these get typed into the dashboard's Connect Live form the first time you use it (persisted in your browser's `localStorage` for convenience, never committed to a file).
7. **Verify**: serve the dashboard, open `http://localhost:5500`, click **Connect Live**, enter the two IDs. The tab will navigate to a Microsoft sign-in page (this is expected — Live Mode uses a full-page redirect, not a popup), followed by a consent screen listing the five scopes. After accepting, you'll land back on the dashboard, and the live-status panel should automatically run all six checks.

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
| Live Mode: "Connect Live" does nothing | The page was opened via `file://` instead of `http://` | Confirm you're viewing the dashboard over `http://localhost:...` (serve it — see above), not a `file://` URL |
| Live Mode: `redirect_uri_mismatch` error from Microsoft | The redirect URI in your App Registration doesn't exactly match the URL the dashboard is actually being served from | Make sure the SPA platform's redirect URI matches your server's actual origin+port byte-for-byte (e.g. if you're on `http://localhost:3000`, register that exact URI, not `5500`) |
| Live Mode: consent/interaction-required error | Admin consent wasn't granted for the SPA's delegated scopes | Have a tenant admin click **Grant admin consent** on the SPA platform's API permissions |
| Live Mode: a check shows "skipped — requires Azure AD Premium P1/P2" | Tenant lacks the license those Graph endpoints require | Expected on non-premium tenants — see README.md Known Limitations; not a bug |
