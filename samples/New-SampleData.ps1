#Requires -Version 7.0
# Regenerates samples/output/sample-data.json by running the REAL check functions
# against a fictional Contoso fixture, so the sample can't claim anything the
# code doesn't produce.
# Usage: pwsh ./samples/New-SampleData.ps1, then paste the JSON into SAMPLE_DATA in dashboard/app.js.
param([string]$RepoRoot = (Split-Path $PSScriptRoot -Parent))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$mods = Join-Path $RepoRoot 'scripts\Modules'
Import-Module (Join-Path $mods 'AuditChecks.psm1') -Force
Import-Module (Join-Path $mods 'Reporting.psm1') -Force

function D([int]$days) { (Get-Date).ToUniversalTime().AddDays($days).ToString('yyyy-MM-ddTHH:mm:ssZ') }

$fixture = @{
    users = @"
[
 {"userPrincipalName":"jmartinez@contoso.com","displayName":"Jordan Martinez","accountEnabled":true,"userType":"Member","signInActivity":{"lastSignInDateTime":"$(D -104)"}},
 {"userPrincipalName":"bsingh@contoso.com","displayName":"Bal Singh","accountEnabled":true,"userType":"Member","signInActivity":null},
 {"userPrincipalName":"svc-reports@contoso.com","displayName":"svc-reports","accountEnabled":true,"userType":"Member","signInActivity":{"lastSignInDateTime":"$(D -142)"}},
 {"userPrincipalName":"kwilliams@contoso.com","displayName":"Kim Williams","accountEnabled":true,"userType":"Member","signInActivity":{"lastSignInDateTime":"$(D -95)"}},
 {"userPrincipalName":"achen@contoso.com","displayName":"Alex Chen","accountEnabled":true,"userType":"Member","signInActivity":{"lastSignInDateTime":"$(D -2)"}},
 {"userPrincipalName":"former@contoso.com","displayName":"Former Employee","accountEnabled":false,"userType":"Member","signInActivity":null},
 {"userPrincipalName":"lwong_partnerco.com#EXT#@contoso.onmicrosoft.com","displayName":"Lee Wong (PartnerCo)","accountEnabled":true,"userType":"Guest","signInActivity":{"lastSignInDateTime":"$(D -121)"}},
 {"userPrincipalName":"mgarcia_vendorllc.com#EXT#@contoso.onmicrosoft.com","displayName":"M. Garcia (Vendor LLC)","accountEnabled":true,"userType":"Guest","signInActivity":null},
 {"userPrincipalName":"tnguyen_consultingco.com#EXT#@contoso.onmicrosoft.com","displayName":"T. Nguyen (ConsultingCo)","accountEnabled":true,"userType":"Guest","signInActivity":{"lastSignInDateTime":"$(D -203)"}},
 {"userPrincipalName":"active_partnerco.com#EXT#@contoso.onmicrosoft.com","displayName":"Active Guest","accountEnabled":true,"userType":"Guest","signInActivity":{"lastSignInDateTime":"$(D -7)"}}
]
"@
    mfa = @'
[
 {"userPrincipalName":"achen@contoso.com","isMfaRegistered":false},
 {"userPrincipalName":"dthompson@contoso.com","isMfaRegistered":false},
 {"userPrincipalName":"rpatel@contoso.com","isMfaRegistered":false},
 {"userPrincipalName":"ssmith@contoso.com","isMfaRegistered":true}
]
'@
    roles = @'
[
 {"roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","principal":{"@odata.type":"#microsoft.graph.user","userPrincipalName":"ssmith@contoso.com","displayName":"Sam Smith"}},
 {"roleDefinitionId":"e8611ab8-c189-46e8-94e1-60213ab1f814","principal":{"@odata.type":"#microsoft.graph.user","userPrincipalName":"jlee@contoso.com","displayName":"Jamie Lee"}},
 {"roleDefinitionId":"fe930be7-5e62-47db-91af-98c3a49a38b1","principal":{"@odata.type":"#microsoft.graph.group","displayName":"Tier1-UserAdmins"}},
 {"roleDefinitionId":"88d8e3e3-8f55-4a1e-953a-9b9898b8876b","principal":{"@odata.type":"#microsoft.graph.user","userPrincipalName":"reader@contoso.com"}}
]
'@
    apps = @"
[
 {"displayName":"Internal Reporting App","passwordCredentials":[{"displayName":"prod-secret","keyId":"a1","endDateTime":"$(D 14)"}],"keyCredentials":[]},
 {"displayName":"Legacy SharePoint Connector","passwordCredentials":[{"displayName":"initial","keyId":"b1","endDateTime":"$(D -210)"}],"keyCredentials":[]},
 {"displayName":"Vendor Integration Service","passwordCredentials":[],"keyCredentials":[{"displayName":"CN=vendor-int","keyId":"c1","endDateTime":"$(D -35)"}]},
 {"displayName":"HR Sync","passwordCredentials":[{"displayName":"current","keyId":"d1","endDateTime":"$(D 300)"}],"keyCredentials":[]}
]
"@
    ca = @'
[
 {"displayName":"Require MFA for All Users","state":"enabledForReportingButNotEnforcing"},
 {"displayName":"Block Legacy Authentication","state":"disabled"},
 {"displayName":"Require Compliant Device for Admins","state":"enabled"}
]
'@
}

# Shadow Invoke-GraphQuery inside the AuditChecks module scope with a fixture lookup.
& (Get-Module AuditChecks) {
    param($fx)
    $script:fx = $fx
    function script:Invoke-GraphQuery {
        param([string]$Uri)
        $key = switch -Wildcard ($Uri) {
            '/users*'                  { 'users' }
            '/reports/*'               { 'mfa' }
            '/roleManagement/*'        { 'roles' }
            '/applications*'           { 'apps' }
            '/identity/conditional*'   { 'ca' }
        }
        , [System.Collections.Generic.List[object]]@($script:fx[$key] | ConvertFrom-Json)
    }
} $fixture

$config = [PSCustomObject]@{ thresholds = [PSCustomObject]@{ staleAccountDays = 90; staleGuestDays = 90; secretExpiryWarningDays = 30 } }
$findings = @(
    Get-StaleAccountFindings          -Config $config
    Get-NoMfaFindings                 -Config $config
    Get-GuestReviewFindings           -Config $config
    Get-PrivilegedRoleFindings        -Config $config
    Get-StaleServicePrincipalFindings -Config $config
    Get-ConditionalAccessGapFindings  -Config $config
)

$checks = 'stale-accounts', 'no-mfa', 'guest-review', 'privileged-roles', 'stale-service-principals', 'ca-policy-gaps'
$report = New-AuditReport -TenantDomain 'contoso.onmicrosoft.com' -ToolVersion '0.2.0' -ChecksRun $checks -Findings $findings

$out = Join-Path $RepoRoot 'samples\output\sample-data.json'
($report | ConvertTo-Json -Depth 6) | Set-Content -Path $out -Encoding utf8NoBOM
"Wrote $($findings.Count) findings to $out"
$report.summary | ConvertTo-Json -Compress
