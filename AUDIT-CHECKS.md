# Audit Checks

This document details each of the six audit checks performed by this tool: what it looks for, why it matters, how severe a finding is, how to remediate it, and the high-level query logic used to detect it.

---

## 1. Stale / Inactive Accounts

**Why it matters:** Accounts with no recent sign-in activity are a common target for compromise — they're often unmonitored, may retain stale permissions, and are easy for an attacker to use without detection. Compliance frameworks (SOC 2, ISO 27001, NIST) typically require periodic access reviews to catch these.

**Severity:** Medium

**Remediation guidance:** Disable or remove accounts with no sign-in activity beyond an organization-defined threshold (commonly 60-90 days). Confirm with the account owner/manager before deletion.

**Query logic:** Query `/users` with `signInActivity` (requires `AuditLog.Read.All`), compare `lastSignInDateTime` against the configured threshold in `audit-config.json`.

---

## 2. Users Without MFA

**Why it matters:** Password-only authentication is the single most exploited weakness in identity systems. Accounts without MFA are vulnerable to credential stuffing, phishing, and password spray attacks.

**Severity:** Critical

**Remediation guidance:** Enforce MFA registration via Conditional Access or per-user MFA. Prioritize privileged accounts first if rolling out incrementally.

**Query logic:** Query `/reports/authenticationMethods/userRegistrationDetails` (requires `Reports.Read.All` or `AuditLog.Read.All`) and flag users where `isMfaRegistered` is `false`.

---

## 3. Guest Account Review

**Why it matters:** Guest/external accounts often retain access long after a collaboration ends, and their access scope is harder to govern than internal accounts. Unreviewed guest access is a frequent audit finding.

**Severity:** Medium

**Remediation guidance:** Review guest account list against current business need; remove guests with no recent activity or no active collaboration; ensure guest access reviews are scheduled (Entra ID Access Reviews).

**Query logic:** Query `/users` filtered by `userType eq 'Guest'`, cross-reference with sign-in activity and group/resource membership.

---

## 4. Privileged Role Assignments

**Why it matters:** Excess standing privileged access (Global Admin, Privileged Role Admin, etc.) increases blast radius if any one account is compromised. Least-privilege and just-in-time access are core Zero Trust principles.

**Severity:** Critical

**Remediation guidance:** Reduce the number of permanent Global Admin assignments; move to Privileged Identity Management (PIM) for just-in-time elevation; review role assignments quarterly.

**Query logic:** Query `/roleManagement/directory/roleAssignments` (requires `RoleManagement.Read.Directory`), join against `/directoryRoles` to resolve role names, flag highly-privileged roles assigned permanently (not via PIM eligibility).

---

## 5. Stale / Orphaned Service Principals & App Registrations

**Why it matters:** App registrations and service principals often outlive their original purpose, retain credentials (secrets/certs), and may hold broad API permissions. Unused apps with valid credentials are an under-monitored attack surface.

**Severity:** High

**Remediation guidance:** Identify apps with no recent sign-in activity or expired/soon-to-expire credentials; remove unused registrations; review API permissions for over-provisioning (e.g. `Directory.ReadWrite.All` when read-only would suffice).

**Query logic:** Query `/servicePrincipals` and `/applications` (requires `Application.Read.All`), cross-reference sign-in logs for service principal activity, flag those with no activity beyond the configured threshold or with credentials expiring soon.

---

## 6. Conditional Access Policy Gaps

**Why it matters:** Conditional Access is the primary control for enforcing MFA, blocking legacy auth, and restricting access by risk signal. Gaps in coverage (e.g. a user group excluded from all CA policies) undermine every other control.

**Severity:** High

**Remediation guidance:** Ensure all users are covered by at least a baseline CA policy (MFA + block legacy auth); review policy exclusions for unjustified scope; avoid policies in "Report-only" mode indefinitely.

**Query logic:** Query `/identity/conditionalAccess/policies` (requires `Policy.Read.All`), evaluate `state` (enabled/disabled/reportOnly) and `conditions.users` to identify users/groups not covered by any enabled policy.

---

## Severity Reference

| Severity | Definition |
|---|---|
| **Critical** | Direct path to tenant compromise or major data exposure if exploited |
| **High** | Significant risk increase; should be remediated promptly |
| **Medium** | Hygiene/governance issue; remediate on a regular review cycle |
