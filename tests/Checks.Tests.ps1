#Requires -Version 7.0
#Requires -Modules @{ ModuleName = "Pester"; ModuleVersion = "5.0" }

<#
.SYNOPSIS
    Behavioural tests for the six Get-*Findings checks and Invoke-GraphQuery.
.DESCRIPTION
    Every check reaches Graph only through Invoke-GraphQuery, so mocking that
    one function inside the AuditChecks module is enough to feed each check
    canned Graph responses - no tenant, no network, no Microsoft.Graph SDK.
    Fixtures are built from JSON so they go through the same ConvertFrom-Json
    deserialisation (including ISO date -> DateTime conversion) as real responses.
    Run with: Invoke-Pester .\tests -Output Detailed
#>

BeforeAll {
    # Invoke-MgGraphRequest only needs to exist so Pester can mock it; CI
    # doesn't install the Graph SDK.
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        function global:Invoke-MgGraphRequest { param($Method, $Uri, $OutputType) }
    }

    $moduleRoot = Join-Path $PSScriptRoot '..\scripts\Modules'
    Import-Module (Join-Path $moduleRoot 'GraphAPI.psm1')    -Force
    Import-Module (Join-Path $moduleRoot 'AuditChecks.psm1') -Force
    Import-Module (Join-Path $moduleRoot 'Reporting.psm1')   -Force

    $script:config = [PSCustomObject]@{
        thresholds = [PSCustomObject]@{ staleAccountDays = 90; staleGuestDays = 60; secretExpiryWarningDays = 30 }
    }

    function script:IsoDaysAgo([int]$days) { (Get-Date).ToUniversalTime().AddDays(-$days).ToString('yyyy-MM-ddTHH:mm:ssZ') }
    function script:FromJson([string]$json) { , @($json | ConvertFrom-Json) }

    # Exception shaped like the Graph SDK's HttpResponseException
    class FakeHttpException : System.Exception {
        [System.Net.Http.HttpResponseMessage]$Response
        FakeHttpException([int]$status, [int]$retryAfterSeconds) : base("HTTP $status") {
            $this.Response = [System.Net.Http.HttpResponseMessage]::new($status)
            if ($retryAfterSeconds -ge 0) {
                $this.Response.Headers.RetryAfter = [System.Net.Http.Headers.RetryConditionHeaderValue]::new([TimeSpan]::FromSeconds($retryAfterSeconds))
            }
        }
    }
}

Describe 'Get-StaleAccountFindings' {
    BeforeAll {
        $users = FromJson @"
[
  { "userPrincipalName": "never@t.com",   "displayName": "Never",   "accountEnabled": true,  "userType": "Member", "signInActivity": null },
  { "userPrincipalName": "noprop@t.com",  "displayName": "NoProp",  "accountEnabled": true,  "userType": "Member" },
  { "userPrincipalName": "old@t.com",     "displayName": "Old",     "accountEnabled": true,  "userType": "Member", "signInActivity": { "lastSignInDateTime": "$(IsoDaysAgo 120)" } },
  { "userPrincipalName": "recent@t.com",  "displayName": "Recent",  "accountEnabled": true,  "userType": "Member", "signInActivity": { "lastSignInDateTime": "$(IsoDaysAgo 5)" } },
  { "userPrincipalName": "disabled@t.com","displayName": "Disabled","accountEnabled": false, "userType": "Member", "signInActivity": null },
  { "userPrincipalName": "guest@t.com",   "displayName": "Guest",   "accountEnabled": true,  "userType": "Guest",  "signInActivity": null }
]
"@
        Mock Invoke-GraphQuery -ModuleName AuditChecks { $users }
        $script:result = @(Get-StaleAccountFindings -Config $script:config)
    }

    It 'does not crash on null or missing signInActivity (StrictMode regression)' {
        $script:result.affectedObject | Should -Contain 'never@t.com'
        $script:result.affectedObject | Should -Contain 'noprop@t.com'
    }

    It 'flags members inactive past the threshold with the day count' {
        $old = $script:result | Where-Object affectedObject -eq 'old@t.com'
        $old.title | Should -Match 'inactive for 1(19|20) days'
    }

    It 'ignores recent, disabled, and guest accounts' {
        $script:result.affectedObject | Should -Not -Contain 'recent@t.com'
        $script:result.affectedObject | Should -Not -Contain 'disabled@t.com'
        $script:result.affectedObject | Should -Not -Contain 'guest@t.com'
        $script:result.Count | Should -Be 3
    }
}

Describe 'Get-GuestReviewFindings' {
    BeforeAll {
        $users = FromJson @"
[
  { "userPrincipalName": "g-old@t.com",    "displayName": "G Old",    "accountEnabled": true, "userType": "Guest",  "signInActivity": { "lastSignInDateTime": "$(IsoDaysAgo 75)" } },
  { "userPrincipalName": "g-recent@t.com", "displayName": "G Recent", "accountEnabled": true, "userType": "Guest",  "signInActivity": { "lastSignInDateTime": "$(IsoDaysAgo 10)" } },
  { "userPrincipalName": "member@t.com",   "displayName": "Member",   "accountEnabled": true, "userType": "Member", "signInActivity": null }
]
"@
        Mock Invoke-GraphQuery -ModuleName AuditChecks { $users }
        $script:result = @(Get-GuestReviewFindings -Config $script:config)
    }

    It 'flags only guests past the guest threshold' {
        $script:result.Count            | Should -Be 1
        $script:result[0].affectedObject | Should -Be 'g-old@t.com'
        $script:result[0].objectType     | Should -Be 'Guest'
        $script:result[0].checkId        | Should -Be 'guest-review'
    }
}

Describe 'Get-NoMfaFindings' {
    It 'flags users without MFA registered as Critical' {
        $records = FromJson '[{"userPrincipalName":"a@t.com","isMfaRegistered":false},{"userPrincipalName":"b@t.com","isMfaRegistered":true}]'
        Mock Invoke-GraphQuery -ModuleName AuditChecks { $records }

        $result = @(Get-NoMfaFindings -Config $script:config)
        $result.Count             | Should -Be 1
        $result[0].affectedObject | Should -Be 'a@t.com'
        $result[0].severity       | Should -Be 'Critical'
    }
}

Describe 'Get-PrivilegedRoleFindings' {
    BeforeAll {
        $assignments = FromJson @'
[
  { "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
    "principal": { "@odata.type": "#microsoft.graph.user", "userPrincipalName": "admin@t.com", "displayName": "Admin" } },
  { "roleDefinitionId": "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "principal": { "@odata.type": "#microsoft.graph.group", "displayName": "PRA Group" } },
  { "roleDefinitionId": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b",
    "principal": { "@odata.type": "#microsoft.graph.user", "userPrincipalName": "reader@t.com" } },
  { "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "principal": null }
]
'@
        Mock Invoke-GraphQuery -ModuleName AuditChecks { $assignments }
        $script:result = @(Get-PrivilegedRoleFindings -Config $script:config)
    }

    It 'flags only high-privilege roles with a resolvable principal' {
        $script:result.Count | Should -Be 2
        $script:result.affectedObject | Should -Not -Contain 'reader@t.com'
    }

    It 'reports the real principal type rather than assuming User' {
        ($script:result | Where-Object affectedObject -eq 'admin@t.com').objectType | Should -Be 'User'
        ($script:result | Where-Object affectedObject -eq 'PRA Group').objectType   | Should -Be 'Group'
    }

    It 'describes assignments as active, not permanent (the API cannot tell them apart)' {
        $script:result[0].title | Should -BeLike 'Active assignment to *'
    }
}

Describe 'Get-StaleServicePrincipalFindings' {
    BeforeAll {
        $future  = (Get-Date).ToUniversalTime().AddDays(10).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $farOut  = (Get-Date).ToUniversalTime().AddDays(400).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $apps = FromJson @"
[
  { "displayName": "App A",
    "passwordCredentials": [ { "displayName": "old-secret", "keyId": "k1", "endDateTime": "$(IsoDaysAgo 40)" } ],
    "keyCredentials":      [ { "displayName": "",           "keyId": "k2", "endDateTime": "$future" } ] },
  { "displayName": "App B",
    "passwordCredentials": [ { "displayName": "fine", "keyId": "k3", "endDateTime": "$farOut" } ],
    "keyCredentials": [] },
  { "displayName": "App C", "passwordCredentials": null, "keyCredentials": null }
]
"@
        Mock Invoke-GraphQuery -ModuleName AuditChecks { $apps }
        $script:result = @(Get-StaleServicePrincipalFindings -Config $script:config)
    }

    It 'flags expired (High) and soon-expiring (Medium) credentials only' {
        $script:result.Count | Should -Be 2
        ($script:result | Where-Object severity -eq 'High').title   | Should -Match "Secret 'old-secret' expired"
        ($script:result | Where-Object severity -eq 'Medium').title | Should -Match "Certificate 'k2' expiring in"
    }

    It 'labels findings as Application objects' {
        $script:result.objectType | Sort-Object -Unique | Should -Be 'Application'
    }
}

Describe 'Get-ConditionalAccessGapFindings' {
    It 'raises a single High finding when the tenant has no policies' {
        Mock Invoke-GraphQuery -ModuleName AuditChecks { , [System.Collections.Generic.List[object]]::new() }
        $result = @(Get-ConditionalAccessGapFindings -Config $script:config)
        $result.Count       | Should -Be 1
        $result[0].severity | Should -Be 'High'
        $result[0].title    | Should -Be 'No Conditional Access policies found'
    }

    It 'flags disabled (High) and report-only (Medium) policies but not enabled ones' {
        $policies = FromJson '[{"displayName":"Off","state":"disabled"},{"displayName":"Pilot","state":"enabledForReportingButNotEnforcing"},{"displayName":"On","state":"enabled"}]'
        Mock Invoke-GraphQuery -ModuleName AuditChecks { $policies }
        $result = @(Get-ConditionalAccessGapFindings -Config $script:config)
        $result.Count | Should -Be 2
        ($result | Where-Object affectedObject -eq 'Off').severity   | Should -Be 'High'
        ($result | Where-Object affectedObject -eq 'Pilot').severity | Should -Be 'Medium'
    }
}

Describe 'Invoke-GraphQuery' {
    BeforeEach {
        Mock Start-Sleep -ModuleName GraphAPI { }
    }

    It 'follows @odata.nextLink across pages' {
        Mock Invoke-MgGraphRequest -ModuleName GraphAPI -ParameterFilter { $Uri -like '*page=2' } {
            [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 3 }) }
        }
        Mock Invoke-MgGraphRequest -ModuleName GraphAPI -ParameterFilter { $Uri -notlike '*page=2' } {
            [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 1 }, [PSCustomObject]@{ id = 2 }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?page=2' }
        }
        $result = Invoke-GraphQuery -Uri '/users'
        $result.id | Should -Be @(1, 2, 3)
    }

    It 'retries a throttled (429) request, honouring Retry-After' {
        $script:calls = 0
        Mock Invoke-MgGraphRequest -ModuleName GraphAPI {
            $script:calls++
            if ($script:calls -eq 1) { throw [FakeHttpException]::new(429, 7) }
            [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'ok' }) }
        }
        $result = Invoke-GraphQuery -Uri '/users' -WarningAction SilentlyContinue
        $result.id | Should -Be 'ok'
        Should -Invoke Start-Sleep -ModuleName GraphAPI -Times 1 -Exactly -ParameterFilter { $Seconds -eq 7 }
    }

    It 'surfaces the real error for non-HTTP failures (StrictMode regression)' {
        Mock Invoke-MgGraphRequest -ModuleName GraphAPI { throw [System.Net.Http.HttpRequestException]::new('No such host is known') }
        { Invoke-GraphQuery -Uri '/users' } | Should -Throw '*No such host is known*'
    }

    It 'gives up after MaxRetries on persistent throttling' {
        Mock Invoke-MgGraphRequest -ModuleName GraphAPI { throw [FakeHttpException]::new(429, -1) }
        { Invoke-GraphQuery -Uri '/users' -MaxRetries 2 -WarningAction SilentlyContinue } | Should -Throw '*HTTP 429*'
        Should -Invoke Start-Sleep -ModuleName GraphAPI -Times 2 -Exactly
    }
}

Describe 'Reporting safeguards' {
    It 'records failed checks in report metadata' {
        $failed = @([PSCustomObject]@{ checkId = 'no-mfa'; reason = 'Access denied' })
        $report = New-AuditReport -TenantDomain 't' -ToolVersion '0.2.0' -ChecksRun @('privileged-roles') -Findings @() -ChecksFailed $failed
        $report.metadata.checksFailed[0].checkId | Should -Be 'no-mfa'
    }

    It 'defaults checksFailed to an empty array' {
        $report = New-AuditReport -TenantDomain 't' -ToolVersion '0.2.0' -ChecksRun @() -Findings @()
        @($report.metadata.checksFailed).Count | Should -Be 0
    }

    It 'neutralises spreadsheet formula injection in CSV rows' {
        $row = [PSCustomObject]@{ affectedObject = '=HYPERLINK("http://evil","x")'; title = '+cmd'; description = 'normal text' }
        $safe = $row | ConvertTo-SafeCsvRow
        $safe.affectedObject | Should -Be "'=HYPERLINK(`"http://evil`",`"x`")"
        $safe.title          | Should -Be "'+cmd"
        $safe.description    | Should -Be 'normal text'
    }
}
