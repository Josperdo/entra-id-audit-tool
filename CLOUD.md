# Cloud Architecture Standards

This document defines how this project integrates with cloud services and how it is designed to scale beyond a local script. It will be updated as architecture decisions are finalized during implementation.

## Architecture Overview

The tool follows a linear, single-direction data flow: a PowerShell script queries Microsoft Graph, normalizes the results into a JSON report, and a static HTML dashboard renders that report. There is no persistent backend or always-on service — each run produces a self-contained snapshot. See [TECHNICAL.md](TECHNICAL.md) for the full architecture diagram.

In its current form, every component runs on the operator's local machine. An optional future deployment would move the script's execution to Azure Automation while keeping the same data contract, so the dashboard would not need to change.

The dashboard has two hosting modes today. Loading a pre-generated JSON report or the bundled sample data works via a plain `file://` URL — no server, no network access needed. **Live Mode** (`dashboard/live.js`) is a third identity flow alongside the PowerShell script's delegated/app-only modes: the browser authenticates directly to Entra ID (MSAL.js, PKCE) and calls Graph itself. This requires the dashboard be served over `http(s)://`, since browser OAuth flows don't work from `file://` — a local static server (documented in SETUP.md) satisfies this today; if the dashboard is ever hosted on Azure Static Web Apps (below), that requirement is met automatically. The local server is not "application infrastructure" — it exists solely to give the browser a real origin to redirect through.

## Entra ID / Microsoft Graph Integration

Each audit check queries a specific Microsoft Graph endpoint — for example `/users` and `/reports/authenticationMethods/userRegistrationDetails` for identity and MFA checks, `/roleManagement/directory/roleAssignments` for privileged role review, and `/identity/conditionalAccess/policies` for Conditional Access coverage. The full endpoint-to-check mapping is documented in [AUDIT-CHECKS.md](AUDIT-CHECKS.md).

The tool targets the stable `v1.0` Graph API surface wherever a check can be satisfied there, falling back to `beta` only where no `v1.0` equivalent exists. Any `beta` dependency will be called out explicitly in the relevant module, since beta endpoints are subject to breaking changes without notice.

Graph API throttling (HTTP 429) is handled with retry-and-backoff in the `GraphAPI.psm1` request wrapper, so individual audit checks don't need to implement their own retry logic.

## Data Flow

The PowerShell script and the HTML dashboard communicate through a single JSON file written to `reports/`. That file is the data contract between the two components: each finding is a normalized object with consistent fields (check name, severity, affected object, detail, remediation hint) regardless of which audit check produced it. There is no intermediate storage layer — the JSON file on disk is the only state.

## Scalability Considerations

The tool is designed for small to mid-size tenants. Microsoft Graph responses are paginated by default, and `GraphAPI.psm1` follows `@odata.nextLink` to retrieve complete result sets rather than truncating at the first page. For very large tenants, the practical constraint is runtime rather than correctness — sequential paginated requests across six checks will take proportionally longer as object counts grow. Parallelizing checks or batching requests would be the natural next step if tenant size becomes a bottleneck.

## Deployment Targets

- **Local (current):** the script and dashboard run entirely on the operator's machine. This is the only supported target today and requires no cloud infrastructure beyond the Graph API calls themselves.
- **Azure Automation (Phase 4, optional):** the audit script would run as a scheduled runbook, producing the same JSON report on a recurring basis without manual intervention.
- **Azure Static Web Apps (Phase 4, optional):** the dashboard could be hosted for shared team access instead of opened locally, if reports need to be reviewed by more than one person.

## Cost Considerations

Run locally, the tool has no cloud infrastructure cost — Graph API read calls fall within Microsoft's standard API limits at no additional charge. If the optional Azure Automation or Static Web Apps deployment is implemented, costs would be limited to modest consumption-based charges (Automation runbook minutes, static hosting), both of which fall within or near Azure's free tier for a single-tenant audit workload.
