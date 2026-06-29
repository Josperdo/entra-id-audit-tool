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

> `audit-config.json` is gitignored — never commit tenant IDs, client secrets, or other tenant-specific values. See [SECURITY.md](Security.md).

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
