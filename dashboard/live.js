(function () {
  "use strict";

  // ---------------------------------------------------------------------
  // Live Mode: authenticates to Microsoft Graph directly in the browser
  // (via the vendored MSAL.js in msal-browser.min.js) and runs a faithful
  // JS port of the 6 PowerShell audit checks (scripts/Modules/AuditChecks.psm1),
  // then feeds the resulting report into app.js's existing loadData() seam
  // via window.EntraAuditDashboard. See Security.md "Live Dashboard Mode"
  // and TECHNICAL.md for the full design rationale.
  //
  // Deliberately NOT "smarter" than the PowerShell checks — same endpoints,
  // same thresholds, same simplifications (e.g. privileged-roles can't
  // distinguish permanent vs. active-PIM assignments; ca-policy-gaps has no
  // coverage-gap analysis). Keeping the two artifacts in parity matters more
  // than either one being more clever on its own.
  // ---------------------------------------------------------------------

  var GRAPH_BASE = "https://graph.microsoft.com/v1.0";
  var GRAPH_SCOPES = [
    "User.Read.All",
    "AuditLog.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.Directory",
    "Application.Read.All"
  ];
  var CONFIG_STORAGE_KEY = "entraLiveConfig";
  var AUTO_RUN_FLAG = "entraLiveAutoRun";
  var PREMIUM_LICENSE_ERROR = "Authentication_RequestFromNonPremiumTenantOrB2CTenant";

  // Same 7 well-known built-in role template IDs as the PS AuditChecks.psm1
  // Get-PrivilegedRoleFindings hardcoded map — copy verbatim, do not expand.
  var HIGH_PRIVILEGE_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator"
  };

  var CHECKS = [
    ["stale-accounts", "Stale/Inactive Accounts", getStaleAccountFindings],
    ["no-mfa", "Users Without MFA", getNoMfaFindings],
    ["guest-review", "Guest Account Review", getGuestReviewFindings],
    ["privileged-roles", "Privileged Role Assignments", getPrivilegedRoleFindings],
    ["stale-service-principals", "Stale/Orphaned Service Principals & App Registrations", getStaleServicePrincipalFindings],
    ["ca-policy-gaps", "Conditional Access Policy Gaps", getConditionalAccessGapFindings]
  ];

  var DEFAULT_THRESHOLDS = {
    staleAccountDays: 90,
    staleGuestDays: 90,
    secretExpiryWarningDays: 30
  };

  var el = {
    connectBtn: document.getElementById("connect-live-btn"),
    disconnectBtn: document.getElementById("live-disconnect-btn"),
    connectedBadge: document.getElementById("live-connected-badge"),
    form: document.getElementById("live-connect-form"),
    tenantInput: document.getElementById("live-tenant-id"),
    clientInput: document.getElementById("live-client-id"),
    formSubmit: document.getElementById("live-connect-submit"),
    formCancel: document.getElementById("live-connect-cancel"),
    formError: document.getElementById("live-connect-error"),
    statusPanel: document.getElementById("live-status-panel"),
    statusList: document.getElementById("live-status-list")
  };

  var pca = null;
  var pcaReadyPromise = null;

  // -----------------------------------------------------------------
  // localStorage config (tenantId/clientId only — never a token, never
  // a secret; this pair is not sensitive, matching audit-config.json's
  // own tenantId/clientId fields already living outside source control)
  // -----------------------------------------------------------------

  function getStoredConfig() {
    try {
      var raw = localStorage.getItem(CONFIG_STORAGE_KEY);
      if (!raw) return null;
      var parsed = JSON.parse(raw);
      if (parsed && parsed.tenantId && parsed.clientId) return parsed;
      return null;
    } catch (err) {
      return null;
    }
  }

  function setStoredConfig(tenantId, clientId) {
    localStorage.setItem(CONFIG_STORAGE_KEY, JSON.stringify({ tenantId: tenantId, clientId: clientId }));
  }

  function clearStoredConfig() {
    localStorage.removeItem(CONFIG_STORAGE_KEY);
  }

  // -----------------------------------------------------------------
  // MSAL setup
  // -----------------------------------------------------------------

  function ensurePca(tenantId, clientId) {
    if (pca) return pcaReadyPromise;
    pca = new msal.PublicClientApplication({
      auth: {
        clientId: clientId,
        authority: "https://login.microsoftonline.com/" + tenantId,
        redirectUri: window.location.origin + window.location.pathname
      },
      cache: {
        // Tokens are more sensitive than the non-secret tenantId/clientId
        // pair above; sessionStorage bounds their lifetime to this tab.
        cacheLocation: "sessionStorage",
        storeAuthStateInCookie: false
      },
      system: {
        // Only relevant to acquireTokenSilent's hidden-iframe renewal path;
        // the interactive login itself uses a full-page redirect (below),
        // not a popup, so it isn't subject to a popup-window timeout at all.
        iframeHashTimeout: 10000
      }
    });
    pcaReadyPromise = pca.initialize();
    return pcaReadyPromise;
  }

  function clearMsalSessionCache() {
    var keys = [];
    for (var i = 0; i < sessionStorage.length; i++) {
      var key = sessionStorage.key(i);
      if (key && key.indexOf("msal.") === 0) keys.push(key);
    }
    keys.forEach(function (key) { sessionStorage.removeItem(key); });
  }

  async function acquireToken() {
    var account = pca.getActiveAccount();
    var result = await pca.acquireTokenSilent({ scopes: GRAPH_SCOPES, account: account });
    return result.accessToken;
  }

  // -----------------------------------------------------------------
  // Redirect-based interactive login. A popup requires the tab that
  // opened it to continuously peek at the popup's address bar to detect
  // when it comes back — some privacy-focused browsers (observed in
  // Brave) block that peek outright, so the opener never finds out the
  // login succeeded even though it genuinely did. A full-page redirect
  // sidesteps that whole class of problem: the same tab navigates to
  // Microsoft and back, and the code that runs after it returns is the
  // same code already running here — no cross-window communication
  // needed at all.
  //
  // This must run unconditionally on every page load (not just after a
  // button click) so it can pick up the result when the tab navigates
  // back after redirecting away.
  // -----------------------------------------------------------------

  async function bootstrapRedirectReturn() {
    var stored = getStoredConfig();
    if (!stored) return;

    await ensurePca(stored.tenantId, stored.clientId);
    var result = await pca.handleRedirectPromise();
    if (!result) return;

    pca.setActiveAccount(result.account);
    setConnectedUi(result.account);

    if (sessionStorage.getItem(AUTO_RUN_FLAG)) {
      sessionStorage.removeItem(AUTO_RUN_FLAG);
      await runAndRender(stored.tenantId, stored.clientId);
    }
  }

  // -----------------------------------------------------------------
  // Graph query helper — faithful JS port of Invoke-GraphQuery
  // (scripts/Modules/GraphAPI.psm1): v1.0 prefix, @odata.nextLink
  // pagination, 429/503 retry with Retry-After/backoff, generic error
  // message (no raw Graph error body) with the error code attached
  // separately so licensing gaps can be detected without leaking detail.
  // -----------------------------------------------------------------

  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  async function graphQuery(uri, maxRetries) {
    if (maxRetries === undefined) maxRetries = 5;
    var nextUri = /^https?:\/\//.test(uri) ? uri : GRAPH_BASE + uri;
    var results = [];
    var attempt = 0;

    while (nextUri) {
      var token = await acquireToken();
      var response = await fetch(nextUri, { headers: { Authorization: "Bearer " + token } });

      if (!response.ok) {
        if ((response.status === 429 || response.status === 503) && attempt < maxRetries) {
          attempt++;
          var retryAfter = response.headers.get("Retry-After");
          var delaySeconds = retryAfter ? parseInt(retryAfter, 10) : Math.pow(2, attempt);
          await sleep(delaySeconds * 1000);
          continue;
        }

        var errorCode = null;
        try {
          var errorBody = await response.json();
          errorCode = errorBody && errorBody.error && errorBody.error.code;
        } catch (parseErr) {
          // response body wasn't JSON; leave errorCode null
        }
        var err = new Error("Graph request to '" + nextUri + "' failed: " + response.status + " " + response.statusText);
        err.graphErrorCode = errorCode;
        throw err;
      }

      var data = await response.json();
      if (Array.isArray(data.value)) {
        results = results.concat(data.value);
      } else if (data) {
        results.push(data);
      }
      nextUri = data["@odata.nextLink"] || null;
      attempt = 0;
    }

    return results;
  }

  // -----------------------------------------------------------------
  // Finding schema helper — mirrors New-AuditFinding's 10 fields exactly
  // -----------------------------------------------------------------

  function nowIso() {
    return new Date().toISOString().replace(/\.\d+Z$/, "Z");
  }

  function isoDate(d) {
    return d.toISOString().slice(0, 10);
  }

  function newFinding(checkId, checkName, severity, objectType, affectedObject, title, description, remediation) {
    return {
      id: crypto.randomUUID(),
      checkId: checkId,
      checkName: checkName,
      severity: severity,
      objectType: objectType,
      affectedObject: affectedObject,
      title: title,
      description: description,
      detectedAt: nowIso(),
      remediation: remediation
    };
  }

  // -----------------------------------------------------------------
  // The 6 checks — ported endpoint-for-endpoint, threshold-for-threshold,
  // severity-for-severity from AuditChecks.psm1. See that file for the
  // PowerShell source of truth; do not "improve" these beyond parity.
  // -----------------------------------------------------------------

  async function getStaleAccountFindings(query, config) {
    var findings = [];
    var users = await query("/users?$select=id,userPrincipalName,displayName,accountEnabled,signInActivity");
    var staleDays = config.thresholds.staleAccountDays;
    var now = new Date();
    var cutoff = new Date(now.getTime() - staleDays * 86400000);

    users.forEach(function (user) {
      if (user.accountEnabled !== true) return;
      var lastSignInRaw = user.signInActivity && user.signInActivity.lastSignInDateTime;

      if (!lastSignInRaw) {
        findings.push(newFinding(
          "stale-accounts", "Stale/Inactive Accounts", "Medium", "User", user.userPrincipalName,
          "Account has never signed in",
          user.displayName + " (" + user.userPrincipalName + ") has no recorded sign-in activity.",
          "Review whether this account is still needed. If not, disable or delete it in Entra ID."
        ));
        return;
      }

      var lastSignIn = new Date(lastSignInRaw);
      if (lastSignIn < cutoff) {
        var daysSince = Math.floor((now - lastSignIn) / 86400000);
        findings.push(newFinding(
          "stale-accounts", "Stale/Inactive Accounts", "Medium", "User", user.userPrincipalName,
          "Account inactive for " + daysSince + " days",
          user.displayName + " (" + user.userPrincipalName + ") last signed in on " + isoDate(lastSignIn) + " (" + daysSince + " days ago). Threshold: " + staleDays + " days.",
          "Review whether this account is still needed. If active, confirm with the user. If stale, disable or delete it in Entra ID."
        ));
      }
    });

    return findings;
  }

  async function getNoMfaFindings(query, config) {
    var findings = [];
    var records = await query("/reports/authenticationMethods/userRegistrationDetails");

    records.forEach(function (record) {
      if (record.isMfaRegistered !== true) {
        findings.push(newFinding(
          "no-mfa", "Users Without MFA", "Critical", "User", record.userPrincipalName,
          "User has no MFA method registered",
          record.userPrincipalName + " has not registered any MFA authentication method and is vulnerable to password-only attacks.",
          "Require the user to register an MFA method via aka.ms/mfasetup. Enforce registration through a Conditional Access policy targeting all users."
        ));
      }
    });

    return findings;
  }

  async function getGuestReviewFindings(query, config) {
    var findings = [];
    var users = await query("/users?$select=id,userPrincipalName,displayName,accountEnabled,userType,signInActivity");
    var staleDays = config.thresholds.staleGuestDays;
    var now = new Date();
    var cutoff = new Date(now.getTime() - staleDays * 86400000);

    users.forEach(function (user) {
      if (user.userType !== "Guest") return;
      if (user.accountEnabled !== true) return;
      var lastSignInRaw = user.signInActivity && user.signInActivity.lastSignInDateTime;

      if (!lastSignInRaw) {
        findings.push(newFinding(
          "guest-review", "Guest Account Review", "Medium", "Guest", user.userPrincipalName,
          "Guest account has never signed in",
          user.displayName + " (" + user.userPrincipalName + ") is an enabled guest account with no recorded sign-in activity.",
          "Confirm whether this guest still requires access. If not, remove the guest account to reduce the external attack surface."
        ));
        return;
      }

      var lastSignIn = new Date(lastSignInRaw);
      if (lastSignIn < cutoff) {
        var daysSince = Math.floor((now - lastSignIn) / 86400000);
        findings.push(newFinding(
          "guest-review", "Guest Account Review", "Medium", "Guest", user.userPrincipalName,
          "Guest account inactive for " + daysSince + " days",
          user.displayName + " (" + user.userPrincipalName + ") last signed in on " + isoDate(lastSignIn) + " (" + daysSince + " days ago). Threshold: " + staleDays + " days.",
          "Review whether this guest still requires access. If access is no longer needed, remove the guest account."
        ));
      }
    });

    return findings;
  }

  async function getPrivilegedRoleFindings(query, config) {
    var findings = [];
    var assignments = await query("/roleManagement/directory/roleAssignments?$expand=principal");

    assignments.forEach(function (assignment) {
      var roleName = HIGH_PRIVILEGE_ROLES[assignment.roleDefinitionId];
      if (!roleName) return;
      if (!assignment.principal) return;

      var affectedObject = assignment.principal.userPrincipalName || assignment.principal.displayName;
      findings.push(newFinding(
        "privileged-roles", "Privileged Role Assignments", "Critical", "User", affectedObject,
        "Permanent assignment to " + roleName,
        affectedObject + " holds a permanent (non-PIM) assignment to '" + roleName + "'. Permanent assignments are always active, increasing exposure if the account is compromised.",
        "Convert to a PIM-eligible assignment in Entra ID Privileged Identity Management. The user can then activate the role on-demand with justification and time limits."
      ));
    });

    return findings;
  }

  async function getStaleServicePrincipalFindings(query, config) {
    var findings = [];
    var apps = await query("/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials");
    var warnDays = config.thresholds.secretExpiryWarningDays;
    var now = new Date();
    var warnCutoff = new Date(now.getTime() + warnDays * 86400000);

    apps.forEach(function (app) {
      var creds = (app.passwordCredentials || []).map(function (c) {
        return { endDateTime: c.endDateTime, displayName: c.displayName, keyId: c.keyId, credType: "Secret" };
      }).concat((app.keyCredentials || []).map(function (c) {
        return { endDateTime: c.endDateTime, displayName: c.displayName, keyId: c.keyId, credType: "Certificate" };
      }));

      creds.forEach(function (cred) {
        if (!cred.endDateTime) return;
        var expiry = new Date(cred.endDateTime);
        var credName = cred.displayName || cred.keyId;

        if (expiry < now) {
          var daysPast = Math.floor((now - expiry) / 86400000);
          findings.push(newFinding(
            "stale-service-principals", "Stale/Orphaned Service Principals & App Registrations", "High", "ServicePrincipal", app.displayName,
            cred.credType + " '" + credName + "' expired " + daysPast + " days ago",
            "App registration '" + app.displayName + "' has an expired " + cred.credType.toLowerCase() + " ('" + credName + "') that expired on " + isoDate(expiry) + ". Any service using this credential is likely failing silently.",
            "Rotate the credential in the App Registration and update the consuming service. Remove the expired credential once the new one is confirmed working."
          ));
        } else if (expiry < warnCutoff) {
          var daysLeft = Math.ceil((expiry - now) / 86400000);
          findings.push(newFinding(
            "stale-service-principals", "Stale/Orphaned Service Principals & App Registrations", "Medium", "ServicePrincipal", app.displayName,
            cred.credType + " '" + credName + "' expiring in " + daysLeft + " days",
            "App registration '" + app.displayName + "' has a " + cred.credType.toLowerCase() + " ('" + credName + "') expiring on " + isoDate(expiry) + " (" + daysLeft + " days). Threshold: " + warnDays + " days.",
            "Rotate the credential before it expires to avoid service disruption. Update the consuming service and remove the old credential."
          ));
        }
      });
    });

    return findings;
  }

  async function getConditionalAccessGapFindings(query, config) {
    var findings = [];
    var policies = await query("/identity/conditionalAccess/policies");

    if (policies.length === 0) {
      findings.push(newFinding(
        "ca-policy-gaps", "Conditional Access Policy Gaps", "High", "Policy", "Tenant",
        "No Conditional Access policies found",
        "No Conditional Access policies are configured in this tenant. All users and applications can authenticate without any additional access controls beyond username and password.",
        "Create baseline CA policies: require MFA for all users, block legacy authentication protocols, and consider restricting access from high-risk locations or sign-in risk levels."
      ));
      return findings;
    }

    policies.forEach(function (policy) {
      if (policy.state === "disabled") {
        findings.push(newFinding(
          "ca-policy-gaps", "Conditional Access Policy Gaps", "High", "Policy", policy.displayName,
          "CA policy is disabled: " + policy.displayName,
          "The Conditional Access policy '" + policy.displayName + "' exists but is disabled and not enforcing any controls. It was likely created with intent but never enabled, or was turned off.",
          "Review the policy and re-enable it if it is still needed. If it is no longer relevant, delete it to reduce confusion."
        ));
      } else if (policy.state === "enabledForReportingButNotEnforcing") {
        findings.push(newFinding(
          "ca-policy-gaps", "Conditional Access Policy Gaps", "Medium", "Policy", policy.displayName,
          "CA policy in report-only mode: " + policy.displayName,
          "The Conditional Access policy '" + policy.displayName + "' is in report-only mode. It logs what it would enforce but is not blocking or requiring anything.",
          "Review the sign-in logs to assess the policy's impact. Once comfortable with the results, switch the policy state from report-only to enabled."
        ));
      }
    });

    return findings;
  }

  // -----------------------------------------------------------------
  // Report assembly — mirrors Reporting.psm1's New-AuditReport
  // -----------------------------------------------------------------

  function buildSummary(findings) {
    var bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    var byCheck = {};
    findings.forEach(function (f) {
      if (f.severity in bySeverity) bySeverity[f.severity]++;
      if (!byCheck[f.checkId]) byCheck[f.checkId] = 0;
      byCheck[f.checkId]++;
    });
    return { totalFindings: findings.length, bySeverity: bySeverity, byCheck: byCheck };
  }

  // -----------------------------------------------------------------
  // Orchestrator — mirrors Invoke-EntraAudit.ps1's per-check isolation:
  // one check failing (most commonly a P1/P2 licensing 403) never blocks
  // the other 5.
  // -----------------------------------------------------------------

  async function runLiveAudit(query, config, onProgress) {
    var findings = [];
    var checksRun = [];

    for (var i = 0; i < CHECKS.length; i++) {
      var checkId = CHECKS[i][0];
      var fn = CHECKS[i][2];
      onProgress(checkId, "running");
      try {
        var result = await fn(query, config);
        findings = findings.concat(result);
        checksRun.push(checkId);
        onProgress(checkId, "success", result.length);
      } catch (err) {
        if (err.graphErrorCode === PREMIUM_LICENSE_ERROR) {
          onProgress(checkId, "skipped-premium");
        } else {
          onProgress(checkId, "error", err.message);
        }
      }
    }

    return {
      metadata: {
        tenantDomain: config.tenantId,
        generatedAt: nowIso(),
        toolVersion: "0.1.0-live",
        checksRun: checksRun
      },
      summary: buildSummary(findings),
      findings: findings
    };
  }

  // -----------------------------------------------------------------
  // UI wiring
  // -----------------------------------------------------------------

  function showForm() {
    el.formError.textContent = "";
    el.form.style.display = "block";
    el.tenantInput.focus();
  }

  function hideForm() {
    el.form.style.display = "none";
  }

  function renderStatusPanel() {
    el.statusList.innerHTML = "";
    CHECKS.forEach(function (entry) {
      var row = document.createElement("div");
      row.className = "live-status-row";
      row.dataset.checkId = entry[0];

      var icon = document.createElement("span");
      icon.className = "live-status-icon";
      icon.textContent = "·";

      var name = document.createElement("span");
      name.className = "live-status-name";
      name.textContent = entry[1];

      var detail = document.createElement("span");
      detail.className = "live-status-detail";
      detail.textContent = "queued";

      row.appendChild(icon);
      row.appendChild(name);
      row.appendChild(detail);
      el.statusList.appendChild(row);
    });
    el.statusPanel.style.display = "block";
  }

  function updateCheckStatus(checkId, status, extra) {
    var row = el.statusList.querySelector('[data-check-id="' + checkId + '"]');
    if (!row) return;
    var icon = row.querySelector(".live-status-icon");
    var detail = row.querySelector(".live-status-detail");
    row.className = "live-status-row " + status;

    if (status === "running") {
      icon.textContent = "…";
      detail.textContent = "running…";
    } else if (status === "success") {
      icon.textContent = "✓";
      detail.textContent = "complete — " + extra + " finding(s)";
    } else if (status === "skipped-premium") {
      icon.textContent = "⚠";
      detail.textContent = "skipped — requires Azure AD Premium P1/P2";
    } else if (status === "error") {
      icon.textContent = "✕";
      detail.textContent = "failed — " + extra;
    }
  }

  function setConnectedUi(account) {
    el.connectBtn.textContent = "Re-run Live Checks";
    el.disconnectBtn.style.display = "inline-block";
    el.connectedBadge.className = "live-badge connected";
    el.connectedBadge.textContent = "Connected as " + account.username;
  }

  function setDisconnectedUi() {
    el.connectBtn.textContent = "Connect Live";
    el.disconnectBtn.style.display = "none";
    el.connectedBadge.className = "live-badge not-connected";
    el.connectedBadge.textContent = "Not connected live";
    el.statusPanel.style.display = "none";
  }

  async function runAndRender(tenantId, clientId) {
    var config = { tenantId: tenantId, thresholds: DEFAULT_THRESHOLDS };
    renderStatusPanel();
    el.connectBtn.disabled = true;
    try {
      var report = await runLiveAudit(graphQuery, config, updateCheckStatus);
      window.EntraAuditDashboard.loadData(report);
    } finally {
      el.connectBtn.disabled = false;
    }
  }

  async function handleConnectClick() {
    var stored = getStoredConfig();
    if (!stored) {
      showForm();
      return;
    }

    el.connectBtn.disabled = true;
    try {
      await ensurePca(stored.tenantId, stored.clientId);
      var existing = pca.getActiveAccount() || pca.getAllAccounts()[0];
      if (existing) {
        pca.setActiveAccount(existing);
        setConnectedUi(existing);
        await runAndRender(stored.tenantId, stored.clientId);
      } else {
        // Navigates the tab away to Microsoft's sign-in page; execution
        // resumes in bootstrapRedirectReturn() once it comes back. The
        // flag lets that resumption know to auto-run the audit, since
        // that was this click's whole intent before the forced navigation.
        sessionStorage.setItem(AUTO_RUN_FLAG, "1");
        await pca.loginRedirect({ scopes: GRAPH_SCOPES });
      }
    } catch (err) {
      alert("Live Mode connection failed: " + err.message);
    } finally {
      el.connectBtn.disabled = false;
    }
  }

  async function handleFormSubmit() {
    var tenantId = el.tenantInput.value.trim();
    var clientId = el.clientInput.value.trim();
    if (!tenantId || !clientId) {
      el.formError.textContent = "Both Tenant ID and Client ID are required.";
      return;
    }

    setStoredConfig(tenantId, clientId);
    hideForm();

    el.connectBtn.disabled = true;
    try {
      await ensurePca(tenantId, clientId);
      sessionStorage.setItem(AUTO_RUN_FLAG, "1");
      await pca.loginRedirect({ scopes: GRAPH_SCOPES });
    } catch (err) {
      alert("Live Mode connection failed: " + err.message);
    } finally {
      el.connectBtn.disabled = false;
    }
  }

  function handleDisconnectClick() {
    if (pca) {
      pca.setActiveAccount(null);
    }
    clearMsalSessionCache();
    setDisconnectedUi();
  }

  el.connectBtn.addEventListener("click", handleConnectClick);
  el.disconnectBtn.addEventListener("click", handleDisconnectClick);
  el.formSubmit.addEventListener("click", handleFormSubmit);
  el.formCancel.addEventListener("click", hideForm);

  // Must run on every load to catch the tab navigating back after a
  // redirect login. No-ops quickly if there's no stored config or no
  // pending redirect to process.
  bootstrapRedirectReturn();
})();
