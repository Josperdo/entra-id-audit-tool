# Entra ID Audit Tool

Automated identity governance audit for Azure/Entra ID

## Why This Exists

Identity sprawl is one of the most common root causes behind cloud security incidents — stale guest accounts, users without MFA, orphaned admin roles, and over-privileged service principals accumulate silently in most Entra ID tenants. Manually auditing these conditions through the Azure portal doesn't scale and is easy to skip. This tool automates a repeatable identity governance audit against Microsoft Graph so findings are consistent, documented, and reviewable over time.

## What It Does

The tool runs six audit checks against a tenant via Microsoft Graph API and produces a structured report:

1. **Stale/inactive accounts** — users with no sign-in activity past a defined threshold
2. **Users without MFA** — accounts not enrolled in multi-factor authentication
3. **Guest account review** — external/guest accounts and their access scope
4. **Privileged role assignments** — users holding admin roles (Global Admin, Privileged Role Admin, etc.)
5. **Stale/orphaned service principals & app registrations** — unused or overly permissioned apps
6. **Conditional Access policy gaps** — coverage gaps in CA policy enforcement

Results are exported to JSON and rendered in a self-contained HTML dashboard for review.

## Quick Start

> Full setup instructions: see [SETUP.md](SETUP.md)

```powershell
# Install dependencies
Install-Module Microsoft.Graph -Scope CurrentUser

# Run the audit
.\scripts\Invoke-EntraAudit.ps1 -ConfigPath .\scripts\config\audit-config.json

# Open the dashboard
.\dashboard\index.html
```

## Project Status

**In development** — see [ROADMAP.md](ROADMAP.md) for current phase and progress.

## Documentation

- [ROADMAP.md](ROADMAP.md) — phased build plan
- [SETUP.md](SETUP.md) — prerequisites and local setup
- [TECHNICAL.md](TECHNICAL.md) — architecture and design decisions
- [AUDIT-CHECKS.md](AUDIT-CHECKS.md) — details on each audit check
- [SECURITY.md](Security.md) — security standards for this project
- [CLOUD.md](CLOUD.md) — cloud architecture and integration notes
