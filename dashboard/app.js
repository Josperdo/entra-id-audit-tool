(function () {
  "use strict";

  var SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

  // Embedded sample data so the dashboard is fully self-contained and
  // demonstrable with zero setup. "Load Report (JSON)" loads real output
  // via FileReader (works from a file:// URL without a server).
  var SAMPLE_DATA = {
    "metadata": {
      "tenantDomain": "contoso.onmicrosoft.com",
      "generatedAt": "2026-06-28T14:32:00Z",
      "toolVersion": "0.1.0",
      "checksRun": ["stale-accounts", "no-mfa", "guest-review", "privileged-roles", "stale-service-principals", "ca-policy-gaps"]
    },
    "summary": {
      "totalFindings": 17,
      "bySeverity": { "Critical": 5, "High": 5, "Medium": 7 },
      "byCheck": {
        "stale-accounts": 4,
        "no-mfa": 3,
        "guest-review": 3,
        "privileged-roles": 2,
        "stale-service-principals": 3,
        "ca-policy-gaps": 2
      }
    },
    "findings": [
      { "id": "F-001", "checkId": "stale-accounts", "checkName": "Stale/Inactive Accounts", "severity": "Medium", "objectType": "User", "affectedObject": "jmartinez@contoso.com", "title": "No sign-in activity in 104 days", "description": "User account has not signed in since 2026-03-16. Account is enabled and retains all assigned licenses and group memberships.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Confirm with the user's manager whether the account is still needed. Disable if no longer required, or document the reason for continued inactivity." },
      { "id": "F-002", "checkId": "stale-accounts", "checkName": "Stale/Inactive Accounts", "severity": "Medium", "objectType": "User", "affectedObject": "bsingh@contoso.com", "title": "No sign-in activity in 88 days", "description": "User account has not signed in since 2026-04-01. Account is enabled and holds membership in 2 security groups.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Confirm with the user's manager whether the account is still needed. Disable if no longer required, or document the reason for continued inactivity." },
      { "id": "F-003", "checkId": "stale-accounts", "checkName": "Stale/Inactive Accounts", "severity": "Medium", "objectType": "User", "affectedObject": "svc-reports@contoso.com", "title": "No sign-in activity in 142 days", "description": "Account naming suggests automated/service use, but is provisioned as a standard user account rather than a service principal. No sign-in since 2026-02-06.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Determine the original purpose of this account. If it is functioning as a service identity, migrate it to an app registration/service principal. Otherwise disable." },
      { "id": "F-004", "checkId": "stale-accounts", "checkName": "Stale/Inactive Accounts", "severity": "Medium", "objectType": "User", "affectedObject": "kwilliams@contoso.com", "title": "No sign-in activity in 61 days", "description": "User account has not signed in since 2026-04-28. Just past the 60-day organizational threshold.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Confirm with the user's manager whether the account is still needed. Disable if no longer required, or document the reason for continued inactivity." },
      { "id": "F-005", "checkId": "no-mfa", "checkName": "Users Without MFA", "severity": "Critical", "objectType": "User", "affectedObject": "achen@contoso.com", "title": "MFA not registered", "description": "User has no multi-factor authentication method registered. Authentication relies on password only.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Enforce MFA registration via Conditional Access or per-user MFA. Notify the user and require enrollment before next sign-in." },
      { "id": "F-006", "checkId": "no-mfa", "checkName": "Users Without MFA", "severity": "Critical", "objectType": "User", "affectedObject": "dthompson@contoso.com", "title": "MFA not registered", "description": "User has no multi-factor authentication method registered. Authentication relies on password only.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Enforce MFA registration via Conditional Access or per-user MFA. Notify the user and require enrollment before next sign-in." },
      { "id": "F-007", "checkId": "no-mfa", "checkName": "Users Without MFA", "severity": "Critical", "objectType": "User", "affectedObject": "rpatel@contoso.com", "title": "MFA not registered", "description": "User has no multi-factor authentication method registered. Account also holds membership in a privileged-access group.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Treat as high priority given group membership. Enforce MFA registration immediately and review associated access." },
      { "id": "F-008", "checkId": "guest-review", "checkName": "Guest Account Review", "severity": "Medium", "objectType": "Guest", "affectedObject": "lwong_partnerco.com#EXT#@contoso.onmicrosoft.com", "title": "Guest account inactive 75 days, retains access to 3 groups", "description": "External guest account has not signed in since 2026-04-14 but remains a member of 3 groups, including a shared document library.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Confirm the collaboration is still active with the sponsoring internal owner. Remove guest access if the engagement has ended." },
      { "id": "F-009", "checkId": "guest-review", "checkName": "Guest Account Review", "severity": "Medium", "objectType": "Guest", "affectedObject": "mgarcia_vendorllc.com#EXT#@contoso.onmicrosoft.com", "title": "Guest account inactive 120 days, retains access to 1 group", "description": "External guest account has not signed in since 2026-02-28. Sponsoring owner could not be determined from available metadata.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Identify the sponsoring owner. If none can be found, remove the guest account as part of routine cleanup." },
      { "id": "F-010", "checkId": "guest-review", "checkName": "Guest Account Review", "severity": "Medium", "objectType": "Guest", "affectedObject": "tnguyen_consultingco.com#EXT#@contoso.onmicrosoft.com", "title": "Guest account never signed in since invite, 30 days ago", "description": "Guest invitation accepted on 2026-05-29 but no sign-in has occurred since.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Confirm whether the collaboration is still expected to proceed. Remove if the invitation is no longer needed." },
      { "id": "F-011", "checkId": "privileged-roles", "checkName": "Privileged Role Assignments", "severity": "Critical", "objectType": "User", "affectedObject": "ssmith@contoso.com", "title": "Permanent Global Administrator assignment (not via PIM)", "description": "User holds a standing, permanent assignment to the Global Administrator role. No eligible/just-in-time activation is configured.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Convert to a Privileged Identity Management (PIM) eligible assignment requiring justification and time-bound activation. Reserve permanent assignments for break-glass accounts only." },
      { "id": "F-012", "checkId": "privileged-roles", "checkName": "Privileged Role Assignments", "severity": "Critical", "objectType": "User", "affectedObject": "jlee@contoso.com", "title": "Permanent Privileged Role Administrator assignment (not via PIM)", "description": "User holds a standing, permanent assignment to the Privileged Role Administrator role, which can grant role assignments to any other user.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Convert to a PIM-eligible assignment. Review whether this user requires the role at all given its scope to grant further privileged access." },
      { "id": "F-013", "checkId": "stale-service-principals", "checkName": "Stale/Orphaned Service Principals & App Registrations", "severity": "High", "objectType": "ServicePrincipal", "affectedObject": "Internal Reporting App", "title": "No sign-in activity in 210 days; client secret expires in 14 days", "description": "Service principal has not authenticated in 210 days. Its client secret is set to expire 2026-07-12.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Confirm whether the application is still in use. If not, remove the registration. If it is, rotate the expiring secret and investigate the lack of recent activity." },
      { "id": "F-014", "checkId": "stale-service-principals", "checkName": "Stale/Orphaned Service Principals & App Registrations", "severity": "High", "objectType": "ServicePrincipal", "affectedObject": "Legacy SharePoint Connector", "title": "No sign-in activity in 365+ days; credential never rotated", "description": "Service principal has shown no authentication activity in over a year. The application credential has never been rotated since creation.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Remove this app registration if it is confirmed unused. If retained for any reason, rotate credentials immediately and document the business justification." },
      { "id": "F-015", "checkId": "stale-service-principals", "checkName": "Stale/Orphaned Service Principals & App Registrations", "severity": "High", "objectType": "ServicePrincipal", "affectedObject": "Vendor Integration Service", "title": "Holds Directory.ReadWrite.All; last used 95 days ago", "description": "Service principal is granted the broad Directory.ReadWrite.All application permission but has not authenticated in 95 days.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Review whether the granted permission scope matches actual usage. Reduce to a narrower read-only scope if possible, or remove the registration if no longer needed." },
      { "id": "F-016", "checkId": "ca-policy-gaps", "checkName": "Conditional Access Policy Gaps", "severity": "High", "objectType": "Group", "affectedObject": "Contractors", "title": "Group excluded from all enabled Conditional Access policies", "description": "The 'Contractors' group is listed as an exclusion on every enabled Conditional Access policy, including the baseline MFA-enforcement policy.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Review the exclusion's original justification. Remove the exclusion or apply a scoped policy covering this group rather than leaving it fully uncovered." },
      { "id": "F-017", "checkId": "ca-policy-gaps", "checkName": "Conditional Access Policy Gaps", "severity": "High", "objectType": "Policy", "affectedObject": "Require MFA for All Users", "title": "Policy is in Report-only mode 45 days past pilot window", "description": "The 'Require MFA for All Users' Conditional Access policy has remained in Report-only mode since 2026-05-14, well past its intended 2-week pilot window, providing no actual enforcement.", "detectedAt": "2026-06-28T14:32:00Z", "remediation": "Review sign-in logs captured during the report-only period for unexpected impact, then switch the policy to 'On' to begin enforcement." }
    ]
  };

  var state = {
    data: null,
    filters: { search: "", severity: "", check: "" },
    sort: { key: "severity", dir: "asc" },
    expanded: new Set()
  };

  var el = {
    metaTenant: document.getElementById("meta-tenant"),
    metaGenerated: document.getElementById("meta-generated"),
    metaVersion: document.getElementById("meta-version"),
    summaryCards: document.getElementById("summary-cards"),
    metricsGrid: document.getElementById("metrics-grid"),
    tbody: document.getElementById("findings-tbody"),
    emptyState: document.getElementById("empty-state"),
    resultCount: document.getElementById("result-count"),
    searchInput: document.getElementById("search-input"),
    severityFilter: document.getElementById("severity-filter"),
    checkFilter: document.getElementById("check-filter"),
    clearFiltersBtn: document.getElementById("clear-filters-btn"),
    fileInput: document.getElementById("file-input"),
    loadSampleBtn: document.getElementById("load-sample-btn"),
    exportCsvBtn: document.getElementById("export-csv-btn"),
    table: document.getElementById("findings-table")
  };

  function fmtDate(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) +
      " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }

  function severityClass(sev) {
    return (sev || "low").toLowerCase();
  }

  // Distinct shapes, not just color, so severity is never color-alone —
  // matters for colorblind users and still reads in grayscale/print.
  var SEVERITY_ICON = { Critical: "▲", High: "◆", Medium: "●", Low: "○" };

  function severityIcon(sev) {
    return SEVERITY_ICON[sev] || SEVERITY_ICON.Low;
  }

  function loadData(json) {
    if (!json || !Array.isArray(json.findings)) {
      alert("That file doesn't look like a valid audit report (missing a 'findings' array).");
      return;
    }
    state.data = json;
    state.expanded = new Set();
    state.filters = { search: "", severity: "", check: "" };
    el.searchInput.value = "";
    el.severityFilter.value = "";
    el.checkFilter.value = "";
    renderMeta();
    renderCheckFilterOptions();
    renderSummaryCards();
    renderMetricsGrid();
    renderTable();
  }

  function renderMeta() {
    var meta = state.data.metadata || {};
    el.metaTenant.textContent = meta.tenantDomain || "—";
    el.metaGenerated.textContent = meta.generatedAt ? fmtDate(meta.generatedAt) : "—";
    el.metaVersion.textContent = meta.toolVersion || "—";
  }

  function renderCheckFilterOptions() {
    var checks = {};
    state.data.findings.forEach(function (f) {
      checks[f.checkId] = f.checkName;
    });
    el.checkFilter.innerHTML = "";
    var allOpt = document.createElement("option");
    allOpt.value = "";
    allOpt.textContent = "All Checks";
    el.checkFilter.appendChild(allOpt);
    Object.keys(checks).sort().forEach(function (checkId) {
      var opt = document.createElement("option");
      opt.value = checkId;
      opt.textContent = checks[checkId];
      el.checkFilter.appendChild(opt);
    });
  }

  function renderSummaryCards() {
    var findings = state.data.findings;
    var bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    findings.forEach(function (f) {
      var sev = f.severity in bySeverity ? f.severity : "Low";
      bySeverity[sev]++;
    });

    var cards = [
      { label: "Total Findings", value: findings.length, cls: "total", icon: "" },
      { label: "Critical", value: bySeverity.Critical, cls: "critical", icon: severityIcon("Critical") },
      { label: "High", value: bySeverity.High, cls: "high", icon: severityIcon("High") },
      { label: "Medium", value: bySeverity.Medium, cls: "medium", icon: severityIcon("Medium") }
    ];

    el.summaryCards.innerHTML = "";
    cards.forEach(function (c) {
      var div = document.createElement("div");
      div.className = "card " + c.cls;
      var value = document.createElement("div");
      value.className = "value";
      value.textContent = String(c.value);
      var label = document.createElement("div");
      label.className = "label";
      if (c.icon) {
        var labelIcon = document.createElement("span");
        labelIcon.className = "label-icon";
        labelIcon.textContent = c.icon;
        labelIcon.setAttribute("aria-hidden", "true");
        label.appendChild(labelIcon);
      }
      label.appendChild(document.createTextNode(c.label));
      div.appendChild(value);
      div.appendChild(label);
      el.summaryCards.appendChild(div);
    });
  }

  function renderMetricsGrid() {
    var byCheck = {};
    state.data.findings.forEach(function (f) {
      if (!byCheck[f.checkId]) byCheck[f.checkId] = { name: f.checkName, count: 0 };
      byCheck[f.checkId].count++;
    });

    el.metricsGrid.innerHTML = "";
    Object.keys(byCheck).sort(function (a, b) {
      return byCheck[b].count - byCheck[a].count;
    }).forEach(function (checkId) {
      var div = document.createElement("div");
      div.className = "metric";
      var count = document.createElement("div");
      count.className = "count";
      count.textContent = String(byCheck[checkId].count);
      var name = document.createElement("div");
      name.className = "name";
      name.textContent = byCheck[checkId].name;
      div.appendChild(count);
      div.appendChild(name);
      el.metricsGrid.appendChild(div);
    });
  }

  function getFilteredSortedFindings() {
    var search = state.filters.search.trim().toLowerCase();
    var filtered = state.data.findings.filter(function (f) {
      if (state.filters.severity && f.severity !== state.filters.severity) return false;
      if (state.filters.check && f.checkId !== state.filters.check) return false;
      if (search) {
        var haystack = [f.affectedObject, f.title, f.description, f.checkName]
          .filter(Boolean).join(" ").toLowerCase();
        if (haystack.indexOf(search) === -1) return false;
      }
      return true;
    });

    var key = state.sort.key;
    var dir = state.sort.dir === "asc" ? 1 : -1;
    filtered.sort(function (a, b) {
      var av, bv;
      if (key === "severity") {
        av = SEVERITY_ORDER[a.severity] !== undefined ? SEVERITY_ORDER[a.severity] : 99;
        bv = SEVERITY_ORDER[b.severity] !== undefined ? SEVERITY_ORDER[b.severity] : 99;
      } else if (key === "detectedAt") {
        av = new Date(a.detectedAt).getTime() || 0;
        bv = new Date(b.detectedAt).getTime() || 0;
      } else {
        av = (a[key] || "").toString().toLowerCase();
        bv = (b[key] || "").toString().toLowerCase();
      }
      if (av < bv) return -1 * dir;
      if (av > bv) return 1 * dir;
      return 0;
    });

    return filtered;
  }

  function renderTable() {
    var findings = getFilteredSortedFindings();
    el.tbody.innerHTML = "";

    el.resultCount.textContent = findings.length + " of " + state.data.findings.length + " findings";
    el.emptyState.style.display = findings.length === 0 ? "block" : "none";
    el.table.style.display = findings.length === 0 ? "none" : "table";

    findings.forEach(function (f) {
      var row = document.createElement("tr");
      row.className = "finding-row";
      if (state.expanded.has(f.id)) row.classList.add("expanded");
      row.dataset.id = f.id;

      var tdSeverity = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "badge " + severityClass(f.severity);
      var badgeIcon = document.createElement("span");
      badgeIcon.className = "badge-icon";
      badgeIcon.textContent = severityIcon(f.severity);
      badgeIcon.setAttribute("aria-hidden", "true");
      badge.appendChild(badgeIcon);
      badge.appendChild(document.createTextNode(f.severity || "Unknown"));
      tdSeverity.appendChild(badge);

      var tdCheck = document.createElement("td");
      tdCheck.textContent = f.checkName || "";

      var tdObject = document.createElement("td");
      tdObject.textContent = f.affectedObject || "";

      var tdTitle = document.createElement("td");
      tdTitle.textContent = f.title || "";

      var tdDetected = document.createElement("td");
      tdDetected.textContent = fmtDate(f.detectedAt);

      var tdChevron = document.createElement("td");
      var chevron = document.createElement("span");
      chevron.className = "chevron";
      chevron.textContent = "▸";
      tdChevron.appendChild(chevron);

      row.appendChild(tdSeverity);
      row.appendChild(tdCheck);
      row.appendChild(tdObject);
      row.appendChild(tdTitle);
      row.appendChild(tdDetected);
      row.appendChild(tdChevron);

      row.addEventListener("click", function () {
        toggleExpand(f.id);
      });

      el.tbody.appendChild(row);

      if (state.expanded.has(f.id)) {
        el.tbody.appendChild(buildDetailRow(f));
      }
    });
  }

  function buildDetailRow(f) {
    var detailRow = document.createElement("tr");
    detailRow.className = "detail-row";
    var td = document.createElement("td");
    td.colSpan = 6;

    var grid = document.createElement("div");
    grid.className = "detail-grid";

    var descBlock = document.createElement("div");
    var descH = document.createElement("h4");
    descH.textContent = "Description";
    var descP = document.createElement("p");
    descP.textContent = f.description || "No description provided.";
    descBlock.appendChild(descH);
    descBlock.appendChild(descP);

    var remBlock = document.createElement("div");
    var remH = document.createElement("h4");
    remH.textContent = "Remediation";
    var remP = document.createElement("p");
    remP.textContent = f.remediation || "No remediation guidance provided.";
    remBlock.appendChild(remH);
    remBlock.appendChild(remP);

    grid.appendChild(descBlock);
    grid.appendChild(remBlock);
    td.appendChild(grid);
    detailRow.appendChild(td);
    return detailRow;
  }

  function toggleExpand(id) {
    if (state.expanded.has(id)) {
      state.expanded.delete(id);
    } else {
      state.expanded.add(id);
    }
    renderTable();
  }

  function csvEscape(value) {
    var s = value === undefined || value === null ? "" : String(value);
    if (/[",\n]/.test(s)) {
      s = "\"" + s.replace(/"/g, "\"\"") + "\"";
    }
    return s;
  }

  function exportCsv() {
    if (!state.data) return;
    var findings = getFilteredSortedFindings();
    var columns = ["id", "severity", "checkName", "objectType", "affectedObject", "title", "description", "detectedAt", "remediation"];
    var headerRow = columns.join(",");
    var rows = findings.map(function (f) {
      return columns.map(function (col) { return csvEscape(f[col]); }).join(",");
    });
    var csv = [headerRow].concat(rows).join("\r\n");

    var blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    var ts = new Date().toISOString().replace(/[:.]/g, "-");
    a.href = url;
    a.download = "entra-audit-findings-" + ts + ".csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function updateSortIndicators() {
    var ths = el.table.querySelectorAll("thead th[data-key]");
    ths.forEach(function (th) {
      th.innerHTML = "";
      var label = th.dataset.key === "checkName" ? "Check"
        : th.dataset.key === "affectedObject" ? "Affected Object"
        : th.dataset.key === "detectedAt" ? "Detected"
        : th.dataset.key === "title" ? "Finding"
        : "Severity";
      th.appendChild(document.createTextNode(label));
      if (state.sort.key === th.dataset.key) {
        var arrow = document.createElement("span");
        arrow.className = "arrow";
        arrow.textContent = state.sort.dir === "asc" ? "▲" : "▼";
        th.appendChild(arrow);
      }
    });
  }

  // Wire up events
  el.table.querySelectorAll("thead th[data-key]").forEach(function (th) {
    th.addEventListener("click", function () {
      var key = th.dataset.key;
      if (state.sort.key === key) {
        state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
      } else {
        state.sort.key = key;
        state.sort.dir = "asc";
      }
      updateSortIndicators();
      renderTable();
    });
  });
  updateSortIndicators();

  el.searchInput.addEventListener("input", function () {
    state.filters.search = el.searchInput.value;
    renderTable();
  });

  el.severityFilter.addEventListener("change", function () {
    state.filters.severity = el.severityFilter.value;
    renderTable();
  });

  el.checkFilter.addEventListener("change", function () {
    state.filters.check = el.checkFilter.value;
    renderTable();
  });

  el.clearFiltersBtn.addEventListener("click", function () {
    state.filters = { search: "", severity: "", check: "" };
    el.searchInput.value = "";
    el.severityFilter.value = "";
    el.checkFilter.value = "";
    renderTable();
  });

  el.loadSampleBtn.addEventListener("click", function () {
    loadData(JSON.parse(JSON.stringify(SAMPLE_DATA)));
  });

  el.exportCsvBtn.addEventListener("click", exportCsv);

  el.fileInput.addEventListener("change", function (evt) {
    var file = evt.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      try {
        var json = JSON.parse(reader.result);
        loadData(json);
      } catch (err) {
        alert("Could not parse that file as JSON: " + err.message);
      }
    };
    reader.onerror = function () {
      alert("Could not read that file.");
    };
    reader.readAsText(file);
    el.fileInput.value = "";
  });

  // Load sample data by default so the dashboard is immediately viewable.
  loadData(JSON.parse(JSON.stringify(SAMPLE_DATA)));

  // Single integration seam for Live Mode (live.js) to feed a client-built
  // report into the same render pipeline file-upload/sample-data already use.
  window.EntraAuditDashboard = { loadData: loadData };
})();
