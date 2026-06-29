# Technical Overview

This document covers the architecture, component responsibilities, and technology choices behind the Entra ID Audit Tool. It's intended for anyone reviewing or extending the codebase.

## Architecture Diagram

```
                    ┌──────────────────────┐
                    │   Microsoft Graph    │
                    │   (Entra ID tenant)  │
                    └──────────┬───────────┘
                               │ Graph API calls
                               ▼
                    ┌──────────────────────┐
                    │   GraphAPI.psm1      │
                    │   (auth + requests)  │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │  AuditChecks.psm1    │
                    │  (6 audit checks)    │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │  Reporting.psm1      │
                    │  (assemble findings) │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │   reports/*.json     │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │  dashboard/index.html│
                    │  (HTML/CSS/JS, no    │
                    │   build step)        │
                    └──────────────────────┘
```

## Component Breakdown

### PowerShell Audit Script

- **`GraphAPI.psm1`** — handles authentication (`Connect-MgGraph` or app-only auth) and wraps Graph API requests, including pagination and throttling/retry handling.
- **`AuditChecks.psm1`** — one function per audit check (see [AUDIT-CHECKS.md](AUDIT-CHECKS.md)). Each function returns a normalized findings array.
- **`Reporting.psm1`** — merges findings from all checks into a single report object and writes JSON/CSV output.
- **`audit-config.json`** — tenant-specific settings (thresholds, output paths, which checks to run). Not committed to source control (see [SECURITY.md](Security.md)).

### HTML/CSS/JS Dashboard

A self-contained `dashboard/` bundle (`index.html`, `styles.css`, `app.js` — no build tooling, no external dependencies) that reads the audit JSON and renders:

- Summary cards and metrics grid
- A sortable, searchable findings table
- CSV export of the currently filtered view

Self-contained by design — it should be possible to open `dashboard/index.html` directly in a browser with no server required.

### JSON Data Format

The script writes a JSON report consumed by the dashboard. The schema is defined once both components depend on it directly (see `CLOUD.md` for the data flow contract).

## Technology Choices

- **Why PowerShell:** Native Microsoft Graph SDK support (`Microsoft.Graph` module), first-class Windows/Entra tooling, and directly relevant to the target role (Compliance/Security Analyst working with Microsoft identity stacks).
- **Why HTML/CSS/JS (no framework):** Zero build step, zero dependency risk, and trivially portable — a report can be emailed or opened from any machine without npm/node installed.
- **Why JSON as the interchange format:** Native to both PowerShell (`ConvertTo-Json`) and JavaScript (no parsing library needed), human-readable for debugging, and diffable in git for sample data.

## Scope and Limitations

- Designed for a single tenant, run on-demand or on a schedule — not a continuously running service.
- Read-only by design: the tool audits and reports; it does not remediate findings automatically.
- Dashboard is for local/manual review; it is not a multi-user web application (no auth, no persistence layer).

## Future Considerations

- Azure Automation runbook for scheduled, unattended runs (see [ROADMAP.md](ROADMAP.md) Phase 4).
- Historical trend tracking across multiple audit runs (would require persistent storage beyond a single JSON snapshot).
- Multi-tenant support if used beyond a single organization.
