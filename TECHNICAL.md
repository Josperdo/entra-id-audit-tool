# Technical Overview

This document covers the architecture, component responsibilities, and technology choices behind the Entra ID Audit Tool. It's intended for anyone reviewing or extending the codebase.

## Architecture Diagram

Two independent paths produce the same report shape and feed the same dashboard. The PowerShell path (left) is the original, scheduled/batch-friendly pipeline; Live Mode (right) is a browser-only alternative added later — see "Live Dashboard Mode" below.

```
   PowerShell path                          Live Mode (browser) path
   ────────────────                         ─────────────────────────
┌───────────────────────┐               ┌───────────────────────────┐
│ Invoke-EntraAudit.ps1  │               │ dashboard: "Connect Live" │
│ (entry point)          │               │ button (live.js)          │
└───────────┬────────────┘               └────────────┬──────────────┘
            │ Connect-EntraAudit                       │ MSAL.js login (PKCE)
            ▼                                          ▼
┌────────────────────────────────────────────────────────────────────┐
│                  Microsoft Graph (Entra ID tenant)                  │
└───────────┬────────────────────────────────────────────┬────────────┘
            │ GraphAPI.psm1                               │ live.js: graphQuery()
            ▼                                              ▼
┌───────────────────────┐               ┌───────────────────────────┐
│ AuditChecks.psm1       │               │ live.js: 6 check          │
│ (6 audit checks)       │               │ functions — faithful port │
└───────────┬────────────┘               │ of AuditChecks.psm1       │
            ▼                            └────────────┬──────────────┘
┌───────────────────────┐                             ▼
│ Reporting.psm1         │               ┌───────────────────────────┐
│ (assemble findings)    │               │ live.js: runLiveAudit()   │
└───────────┬────────────┘               │ (assembles same shape)   │
            ▼                            └────────────┬──────────────┘
┌───────────────────────┐                             │
│ reports/*.json         │                             │
└───────────┬────────────┘                             │
            └───────────────────┬────────────────────────┘
                                 ▼
                    ┌─────────────────────────────┐
                    │ dashboard/app.js: loadData() │
                    │ — the one seam both paths    │
                    │   feed into                  │
                    └─────────────────────────────┘
```

## Component Breakdown

### PowerShell Audit Script

- **`GraphAPI.psm1`** — handles authentication (`Connect-MgGraph` or app-only auth) and wraps Graph API requests, including pagination and throttling/retry handling.
- **`AuditChecks.psm1`** — one function per audit check (see [AUDIT-CHECKS.md](AUDIT-CHECKS.md)). Each function returns a normalized findings array.
- **`Reporting.psm1`** — merges findings from all checks into a single report object and writes JSON/CSV output.
- **`audit-config.json`** — tenant-specific settings (thresholds, output paths, which checks to run). Not committed to source control (see [Security.md](Security.md)).
- **`Invoke-EntraAudit.ps1`** — the entry point. Loads config, authenticates, runs each enabled check in its own `try/catch` (so one check failing doesn't stop the others), and hands the combined findings to `Reporting.psm1`.

### HTML/CSS/JS Dashboard

A self-contained `dashboard/` bundle (`index.html`, `styles.css`, `app.js` — no build tooling, no external dependencies) that reads the audit JSON and renders:

- Summary cards and metrics grid
- A sortable, searchable findings table
- CSV export of the currently filtered view

Self-contained by design — it should be possible to open `dashboard/index.html` directly in a browser with no server required, for the file-upload and sample-data modes.

**Severity colors** (`--critical`/`--high`/`--medium`/`--low` in `styles.css`) were chosen deliberately, not picked by eye. The original palette had High and Medium only 2.1 ΔE apart under deuteranopia simulation — close enough that a colorblind reviewer could misread one for the other, a real problem in a tool meant to communicate risk severity. The current set (`#b91c1c` / `#b45309` / `#854d0e` / `#15803d`) was chosen by spanning distinct hues (red → orange → gold → green) and validated for CVD separation; severity badges and summary cards also carry a shape icon (▲/◆/●/○) alongside color, so severity is never color-alone. Don't swap individual hues without re-checking separation — the failure mode is easy to reintroduce by picking two colors that merely *look* different to typical vision.

### Live Dashboard Mode (Browser-Only)

`dashboard/live.js` adds a "Connect Live" alternative to loading a pre-generated report: the browser authenticates directly to Entra ID (via the vendored `msal-browser.min.js`, MSAL's PKCE public-client flow — no client secret) and calls Microsoft Graph itself, running a **faithful port** of the same 6 checks in `AuditChecks.psm1`. "Faithful" is a deliberate constraint, not an oversight — the JS versions intentionally preserve the PowerShell checks' known simplifications (e.g. `privileged-roles` can't distinguish a permanent assignment from a currently-active PIM one; `ca-policy-gaps` has no coverage-gap analysis) so the two artifacts never silently disagree about what counts as a finding for the same tenant. The resulting report is assembled in the same `metadata`/`summary`/`findings` shape and handed to `app.js`'s existing `loadData()` — the same integration point the file-upload and sample-data buttons already use, via a single `window.EntraAuditDashboard.loadData` export.

This is a hard requirement, not a preference: MSAL.js's browser auth needs a real `http(s)://` origin, so Live Mode only works when the dashboard is served by a local static file server — it does not work via `file://`. File-upload and sample-data are unaffected and still need no server.

The interactive sign-in uses MSAL's **redirect flow** (`loginRedirect`), not a popup: the tab navigates to Microsoft's sign-in page and back rather than opening a second window. This was a deliberate change from an earlier popup-based implementation — popup flows require the opener tab to continuously poll the popup's address bar to detect completion, and privacy-focused browsers (confirmed in Brave) can block that polling outright, so the opener never learns a genuinely successful login happened. Redirect sidesteps that entirely: no cross-window communication is needed, since the same tab's own code resumes after the navigation. `sessionStorage` carries a small flag across the redirect so the audit automatically resumes once the tab returns, rather than requiring a second click. Subsequent runs ("Re-run Live Checks") reuse the cached session via `acquireTokenSilent` with no navigation at all.

No automated test exercises the MSAL/OAuth flow itself (see Testing below); it's verified manually against the same M365 dev tenant used to validate the PowerShell backend.

### JSON Data Format

The script writes a JSON report consumed by the dashboard. The schema is defined once both components depend on it directly (see `CLOUD.md` for the data flow contract).

## Technology Choices

- **Why PowerShell:** Native Microsoft Graph SDK support (`Microsoft.Graph` module), first-class Windows/Entra tooling, and directly relevant to the target role (Compliance/Security Analyst working with Microsoft identity stacks).
- **Why HTML/CSS/JS (no framework):** Zero build step, zero dependency risk, and trivially portable — a report can be emailed or opened from any machine without npm/node installed. Live Mode's one dependency, MSAL.js, is vendored as a committed static file rather than loaded from a CDN, specifically so this property still holds for file-upload/sample-data use even if a CDN were ever unreachable — see [Security.md](Security.md).
- **Why JSON as the interchange format:** Native to both PowerShell (`ConvertTo-Json`) and JavaScript (no parsing library needed), human-readable for debugging, and diffable in git for sample data.

## Testing

- **Pester** (`tests/AuditChecks.Tests.ps1`) covers the schema contract: `New-AuditFinding` always produces the 10 fields the dashboard expects, rejects invalid severities, and generates unique IDs; `New-AuditReport` correctly aggregates findings by severity and by check, including the zero-findings/zero-checks-run case.
- **Dashboard rendering** is verified against both `samples/output/sample-data.json` (fabricated demo data, safe to commit) and a real report generated end-to-end against the M365 dev tenant — confirming the schema `Reporting.psm1` produces is actually consumable by the dashboard, not just schema-valid in isolation.
- The six `Get-*Findings` check functions themselves are not unit tested — doing so would require mocking Microsoft Graph responses. They're validated by running against a real tenant instead (see [README.md](README.md#known-limitations) for current coverage).
- **Live Mode** has no automated coverage of the MSAL/OAuth flow itself (mocking a full PKCE redirect exchange isn't a good cost/benefit fit for this repo's zero-build-step scope) — verified manually via `tests/LiveMode-Manual-Checklist.md` against the real M365 dev tenant, same as the PowerShell backend's own verification. Because each of the 6 JS check functions and the orchestrator take their Graph-calling function as an injected parameter rather than a global, they are cheaply unit-testable against a stubbed response — a reasonable fast-follow, not yet done, consistent with the PS check functions' own untested status above.

## Scope and Limitations

- Designed for a single tenant, run on-demand or on a schedule — not a continuously running service.
- Read-only by design: the tool audits and reports; it does not remediate findings automatically.
- The dashboard is for local/manual review, not a multi-user web application, and has no persistence layer beyond the current in-memory report — true for both data-loading paths. Where they differ: file-upload and sample-data need no auth and no server (`file://` works fine); Live Mode requires `http(s)://` hosting and a delegated PKCE sign-in, since that's what lets the browser call Graph directly.

## Future Considerations

- Azure Automation runbook for scheduled, unattended runs.
- Historical trend tracking across multiple audit runs (would require persistent storage beyond a single JSON snapshot).
- Multi-tenant support if used beyond a single organization.
