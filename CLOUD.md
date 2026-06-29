# Cloud Architecture Standards

This document defines how this project integrates with cloud services and how it could scale beyond a local script. Fill in the TODOs as architecture decisions are made.

## Architecture Overview

How the pieces connect, end to end.

- [ ] TODO: Diagram/describe the high-level flow: PowerShell script → Microsoft Graph API → JSON output → HTML dashboard (see [TECHNICAL.md](TECHNICAL.md) for the ASCII diagram)
- [ ] TODO: Document which components run where (local machine vs. Azure, if Phase 4 is implemented)

## Entra ID / Microsoft Graph Integration

- [ ] TODO: Document which Graph API endpoints are used per audit check (e.g. `/users`, `/auditLogs/signIns`, `/roleManagement/directory/roleAssignments`, `/identity/conditionalAccess/policies`)
- [ ] TODO: Document Graph API versioning decisions (`v1.0` vs `beta`) and why
- [ ] TODO: Document rate limiting / throttling handling for large tenants

## Data Flow

- [ ] TODO: Document the JSON schema contract between the PowerShell script and the dashboard (what fields each finding object must have)
- [ ] TODO: Document whether data passes through any intermediate storage (local file only, or Azure Storage/Blob in Phase 4)

## Scalability Considerations

- [ ] TODO: Document expected tenant size this tool is designed for (e.g. small/mid-size tenant, <10k objects) and where it would need rework for larger tenants
- [ ] TODO: Document pagination handling for large result sets from Graph API

## Deployment Targets

- [ ] TODO: **Local** — run as a standalone PowerShell script + static HTML file (current default)
- [ ] TODO: **Azure Automation** — scheduled runbook executing the audit on a recurring basis (Phase 4)
- [ ] TODO: **Azure Static Web Apps** — hosting the dashboard for shared/team access (Phase 4, optional)

## Cost Considerations

- [ ] TODO: Document expected cost for local-only usage (none — local script + Graph API calls within free tier limits)
- [ ] TODO: Document expected cost if deployed to Azure Automation/Static Web Apps (Phase 4)
