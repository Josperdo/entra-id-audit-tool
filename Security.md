# Security Considerations

This document covers how the Entra ID Audit Tool handles authentication, credentials, error output, and audit data. It's intended for anyone reviewing the codebase or evaluating whether to run this against a real tenant.

## Authentication

The tool supports two auth modes, selected via `authMode` in `audit-config.json`, both branching from a single function (`Connect-EntraAudit` in `GraphAPI.psm1`) so the auth logic isn't scattered through the codebase:

- **Delegated** — interactive browser sign-in via `Connect-MgGraph -UseDeviceAuthentication`. Intended for ad-hoc/manual runs where a human is present to authenticate.
- **App-only** — unattended auth via a registered App Registration and a certificate thumbprint (`Connect-MgGraph -ClientId -CertificateThumbprint`). Intended for scheduled/unattended runs. Certificate-based auth is used instead of a client secret, since certificates are harder to accidentally leak (no plaintext secret string to paste into a config file or log) and don't need periodic manual rotation the way secrets do.

Both modes request the same five Graph scopes, and all five are **read-only**:

| Scope | Used for |
|---|---|
| `User.Read.All` | Stale account / guest review checks |
| `AuditLog.Read.All` | Sign-in activity, MFA registration report |
| `Policy.Read.All` | Conditional Access policy gaps |
| `RoleManagement.Read.Directory` | Privileged role assignments |
| `Application.Read.All` | Stale service principal / app credential check |

The tool has no write scopes and cannot modify directory data, roles, policies, or credentials — it audits and reports only.

After connecting, `Connect-EntraAudit` verifies the session via `Get-MgContext` and, for app-only mode, confirms the authenticated App ID matches the configured `clientId` — catching a misconfigured certificate/app pairing before any Graph calls are made.

### Live Dashboard Mode (Browser, Delegated Auth)

`dashboard/live.js` adds a third auth flow alongside the two above: **MSAL.js's PKCE public-client flow**, running entirely in the browser via the same App Registration with an added SPA platform (see [SETUP.md](SETUP.md#4-spa-app-registration-setup-live-dashboard-mode)). Same posture as the other two modes:

- The same 5 read-only scopes as delegated permissions — no new/broader permissions introduced for the browser flow.
- No client secret exists or is needed — PKCE public clients don't use one; this is the correct auth type for code running in a browser, where any embedded secret would be visible to the user.
- `RoleManagement.Read.Directory` and `Application.Read.All` typically require admin consent even as delegated scopes; SETUP.md calls this out explicitly so it isn't a surprise the first time a non-admin clicks Connect Live.

**Token storage:** MSAL's cache is configured with `cacheLocation: "sessionStorage"`, not `localStorage`. Tokens are materially more sensitive than the non-secret `tenantId`/`clientId` connection values (see Credential Handling below), and `sessionStorage` clears when the tab/browser closes, bounding how long a token can sit on disk. This means re-opening the dashboard in a new tab requires signing in again — an intentional trade-off favoring a shorter token lifetime over cross-tab convenience.

The existing invariant still holds for this mode: nothing in `live.js` writes a token, account identifier beyond the displayed UPN, or credential value to console output, logs, or the generated report — the same guarantee already stated below for the PowerShell backend.

## Credential Handling

- `audit-config.json` (the real, tenant-specific config containing `tenantId` and, for app-only mode, `clientId`/`certificateThumbprint`) is gitignored and never committed. Only `audit-config.example.json`, which contains placeholder values, ships in the repo.
- Certificates for app-only auth are referenced by thumbprint only; the certificate itself lives in the local certificate store (`Cert:\CurrentUser\My`), not in the repo or config file.
- No client secrets are used anywhere in this tool — certificate-based auth is the only unattended option.
- Nothing in the codebase writes a token, certificate, or credential value to console output, logs, or the generated report.
- **Live Mode's `tenantId`/`clientId`** (entered once via an in-page form) are persisted to the browser's `localStorage` for convenience — these are not secrets (the same two values are visible in the App Registration's overview page to anyone with portal access) and are the same category of tenant-identifying value `audit-config.json` already keeps outside source control. Access/ID/refresh tokens are never written there; they live only in MSAL's `sessionStorage` cache (see Authentication above).

## Error Handling

`Invoke-GraphQuery` (the single function through which every Graph API call is made) deliberately catches Graph API errors and re-throws a short, generic message — the HTTP status and the failing URI — rather than surfacing Graph's raw error response body:

```
Graph request to 'https://graph.microsoft.com/v1.0/users?...' failed: Response status code does not indicate success: Forbidden (Forbidden).
```

This is a deliberate trade-off: raw Graph error payloads can contain tenant-specific detail, and this tool's console output/warnings are the kind of thing that ends up in a screenshot or a shared terminal log during a review. The cost is that diagnosing *why* a specific check failed (a licensing gap vs. a missing consent vs. a malformed query — all of which look identical at the "BadRequest"/"Forbidden" level) requires re-running the failing query directly with `Invoke-MgGraphRequest` to see the underlying `error.code`/`error.message`. That's an accepted trade-off for a tool whose primary audience is a compliance review, not interactive debugging.

Throttling (HTTP 429/503) is retried automatically with exponential backoff, honoring the `Retry-After` header when Graph provides one, and only surfaces as a `Write-Warning` if retries are exhausted — a transient throttle doesn't fail the whole check.

Each of the six audit checks runs independently in its own `try/catch` in `Invoke-EntraAudit.ps1`; one check failing (e.g. due to a licensing gap — see [README.md](README.md#known-limitations)) doesn't stop the others from running or block the report from being generated.

`dashboard/live.js`'s `graphQuery` helper mirrors this posture in the browser: failures throw a generic message the same shape as above, with the Graph `error.code` attached as a separate (non-message) property rather than folded into the displayed text — enough for the live-status panel to detect and label a licensing-gap skip (`Authentication_RequestFromNonPremiumTenantOrB2CTenant`) without surfacing the raw error body. `runLiveAudit` isolates each of the 6 checks the same way `Invoke-EntraAudit.ps1` does — one failing never blocks the other 5.

## Data Retention

- `reports/` is gitignored. Every report contains real tenant identity data (user principal names, role assignments, app registration details) and must never be committed.
- Each run writes a new timestamped file (`audit-report-<UTC timestamp>.json`) rather than overwriting the previous one, so consecutive runs don't silently destroy prior findings.
- There is currently no automated retention/cleanup policy — old reports accumulate in `reports/` until manually deleted. For a real deployment, this would need an explicit retention window (see Known Gaps below).
- `samples/output/sample-data.json` is explicitly fabricated demo data (not a real tenant export) and is the one JSON file allowed past the `.gitignore` rule, specifically so the dashboard can be demoed without any tenant access.

## Known Gaps

Honest accounting of what this document does *not* claim:

- No automated secrets-scanning is wired into a CI pipeline before commits — this is currently a manual discipline (checking `git status`/`git diff` before committing), not an enforced gate.
- No formal code-review policy exists yet beyond "changes to `GraphAPI.psm1` (auth) and the audit check query logic (`AuditChecks.psm1`) warrant extra scrutiny," since the former is the only path to Graph and the latter has direct compliance impact if a check silently stops detecting something it should.
- No automated report-retention/expiry policy (see Data Retention above).
- This tool has been validated end-to-end against one M365 developer tenant. It has not been tested against a production tenant with real user/guest volume, nested PIM-eligible role assignments, or CA policies in report-only mode — behavior there is expected to work based on the Graph API contract, but isn't yet confirmed.
- **The vendored `dashboard/msal-browser.min.js` is a supply-chain surface.** It's committed as a static file rather than loaded from a CDN specifically to avoid a *runtime* third-party dependency (see TECHNICAL.md), but that only shifts the trust decision to update time: pulling in a newer version means trusting whatever that npm release contains. Mitigated by pinning one exact version, recording its source/SHA-256 in a header comment in the file itself, and treating changes to it with the same review scrutiny already called out above for `GraphAPI.psm1`/`AuditChecks.psm1`.
- **Live Mode originally used MSAL's popup login flow; it was replaced with the redirect flow after testing surfaced a real browser-compatibility gap:** Brave (and likely other privacy-hardened Chromium forks) blocks the cross-window polling the popup flow depends on to detect that the popup finished, so the opener tab never learned a genuinely successful login had happened, and the user saw a misleading timeout error despite Graph having issued a valid token. This wasn't caught until manual testing in Brave specifically — Chrome/Edge testing alone would have missed it. Worth remembering if any future feature needs a popup-based flow again: test it in a privacy-focused browser before considering it done.
