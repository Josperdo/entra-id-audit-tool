# Audit Checks

This document details each of the six audit checks: what it looks for, why it matters, how severe a finding is, how to remediate it, and exactly what the query logic does. Each section ends with what the check deliberately does **not** cover, so the scope is clear.

All thresholds come from `thresholds` in `audit-config.json` (defaults: 90 / 90 / 30 days).

---

## 1. Stale / Inactive Accounts (`stale-accounts`)

**Why it matters:** Accounts with no recent sign-in activity are a common target for compromise. They're often unmonitored, may retain stale permissions, and are easy for an attacker to use without detection. Compliance frameworks (SOC 2, ISO 27001, NIST) typically require periodic access reviews to catch these.

**Severity:** Medium

**Query logic:** `GET /users?$select=...,userType,signInActivity` (needs `AuditLog.Read.All` and an Entra ID P1/P2 licence). For **enabled member** accounts, flag any whose `signInActivity.lastSignInDateTime` is older than `staleAccountDays`, or that has no sign-in recorded at all. Guests are excluded here because check 3 covers them, so nobody is counted twice.

**Remediation:** Confirm with the account owner/manager, then disable or remove accounts that are no longer needed.

**Not covered:** non-interactive sign-ins (`lastNonInteractiveSignInDateTime`), a grace period for newly created accounts, and licence/group context for each account.

---

## 2. Users Without MFA (`no-mfa`)

**Why it matters:** Password-only authentication is the most exploited weakness in identity systems. Accounts without MFA are exposed to credential stuffing, phishing, and password spray.

**Severity:** Critical

**Query logic:** `GET /reports/authenticationMethods/userRegistrationDetails` (needs `AuditLog.Read.All` and P1/P2). Flag every record where `isMfaRegistered` is not `true`.

**Remediation:** Enforce MFA registration through Conditional Access. Prioritise privileged accounts first if rolling out in stages.

**Not covered:** whether MFA is actually *enforced* at sign-in (registration ≠ enforcement), and method strength (SMS vs. phishing-resistant).

---

## 3. Guest Account Review (`guest-review`)

**Why it matters:** Guest accounts often keep access long after a collaboration ends, and are harder to govern than internal accounts.

**Severity:** Medium

**Query logic:** Same `/users` query as check 1, restricted to **enabled** accounts with `userType eq 'Guest'`. Flags guests who have never signed in (invited but unused) or haven't signed in within `staleGuestDays`.

**Remediation:** Confirm the collaboration is still active with the sponsoring owner; remove guests that are no longer needed; schedule Entra ID Access Reviews for guests.

**Not covered:** group/resource membership for each guest, or invite redemption state.

---

## 4. Privileged Role Assignments (`privileged-roles`)

**Why it matters:** Standing privileged access increases the blast radius if any one account is compromised. Least privilege and just-in-time access are core Zero Trust principles.

**Severity:** Critical

**Query logic:** `GET /roleManagement/directory/roleAssignments?$expand=principal` (needs `RoleManagement.Read.Directory`). Flags every assignment to one of seven high-privilege built-in roles, matched by well-known role template ID: Global Administrator, Privileged Role Administrator, Security Administrator, User Administrator, Application Administrator, Cloud Application Administrator, Conditional Access Administrator. The principal type (User / Group / ServicePrincipal) comes from the principal's `@odata.type`.

**Important limitation:** this endpoint returns every assignment that is *active at scan time*. That includes standing (permanent) assignments **and** PIM-eligible roles a user happens to have activated right then. The findings therefore say "active assignment", not "permanent". Telling the two apart needs the PIM schedule APIs (`roleAssignmentScheduleInstances`, Entra ID P2), which is the natural next step.

**Remediation:** Check in PIM whether the assignment is permanent. If it is, convert it to PIM-eligible. Reserve permanent assignments for break-glass accounts.

**Not covered:** custom roles, administrative-unit-scoped assignments, PIM-eligible assignments (which are not active), and expanding group membership for role-assignable groups.

---

## 5. App Registration Credential Expiry (`stale-service-principals`)

> The check ID keeps its original slug for config and report compatibility. The name was changed to describe what the check actually does.

**Why it matters:** An expired credential still attached to an app is clutter, and is often a sign the app has been abandoned. If the app is still in use, it points to a silent outage. Credentials close to expiry need rotation before they break something.

**Severity:** High (expired) / Medium (expiring within `secretExpiryWarningDays`)

**Query logic:** `GET /applications?$select=displayName,passwordCredentials,keyCredentials` (needs `Application.Read.All`). Every client secret and certificate with an `endDateTime` is compared to now.

**Remediation:** If the app is still in use, rotate the credential and update the consuming service. If not, remove the app registration. Either way, delete the expired credential.

**Not covered:** service principal sign-in activity (finding truly unused apps), over-broad API permissions (e.g. `Directory.ReadWrite.All`), and credentials on service principals rather than app registrations.

---

## 6. Conditional Access Policy Gaps (`ca-policy-gaps`)

**Why it matters:** Conditional Access is the primary control for enforcing MFA, blocking legacy authentication, and restricting access by risk. Policies that exist but don't enforce give a false sense of coverage.

**Severity:** High (no policies at all, or policy disabled) / Medium (report-only)

**Query logic:** `GET /identity/conditionalAccess/policies` (needs `Policy.Read.All` and P1/P2). Raises one finding if the tenant has no policies at all, then evaluates each policy's `state`: `disabled` → High, `enabledForReportingButNotEnforcing` (report-only) → Medium.

**Remediation:** Make sure all users are covered by a baseline (require MFA + block legacy auth); don't leave policies in report-only indefinitely; delete policies you've abandoned.

**Not covered:** coverage analysis of `conditions.users` (which users/groups are excluded from every enabled policy). That is the most valuable next addition to this check.

---

## Failed checks

If a check can't run (missing consent, missing licence, transient error), it is recorded in the report's `metadata.checksFailed` with a short reason. The dashboard shows an **Incomplete audit** banner listing those checks, so a check that didn't run is never mistaken for a clean result.

## Severity Reference

| Severity | Definition |
|---|---|
| **Critical** | Direct path to tenant compromise or major data exposure if exploited |
| **High** | Significant risk increase; should be remediated promptly |
| **Medium** | Hygiene/governance issue; remediate on a regular review cycle |
