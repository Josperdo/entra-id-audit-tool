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

## Credential Handling

- `audit-config.json` (the real, tenant-specific config containing `tenantId` and, for app-only mode, `clientId`/`certificateThumbprint`) is gitignored and never committed. Only `audit-config.example.json`, which contains placeholder values, ships in the repo.
- Certificates for app-only auth are referenced by thumbprint only; the certificate itself lives in the local certificate store (`Cert:\CurrentUser\My`), not in the repo or config file.
- No client secrets are used anywhere in this tool — certificate-based auth is the only unattended option.
- Nothing in the codebase writes a token, certificate, or credential value to console output, logs, or the generated report.

## Error Handling

`Invoke-GraphQuery` (the single function through which every Graph API call is made) deliberately catches Graph API errors and re-throws a short, generic message — the HTTP status and the failing URI — rather than surfacing Graph's raw error response body:

```
Graph request to 'https://graph.microsoft.com/v1.0/users?...' failed: Response status code does not indicate success: Forbidden (Forbidden).
```

This is a deliberate trade-off: raw Graph error payloads can contain tenant-specific detail, and this tool's console output/warnings are the kind of thing that ends up in a screenshot or a shared terminal log during a review. The cost is that diagnosing *why* a specific check failed (a licensing gap vs. a missing consent vs. a malformed query — all of which look identical at the "BadRequest"/"Forbidden" level) requires re-running the failing query directly with `Invoke-MgGraphRequest` to see the underlying `error.code`/`error.message`. That's an accepted trade-off for a tool whose primary audience is a compliance review, not interactive debugging.

Throttling (HTTP 429/503) is retried automatically with exponential backoff, honoring the `Retry-After` header when Graph provides one, and only surfaces as a `Write-Warning` if retries are exhausted — a transient throttle doesn't fail the whole check.

Each of the six audit checks runs independently in its own `try/catch` in `Invoke-EntraAudit.ps1`; one check failing (e.g. due to a licensing gap — see [README.md](README.md#known-limitations)) doesn't stop the others from running or block the report from being generated.

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
