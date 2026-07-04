#Requires -Version 7.0
#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for AuditChecks.psm1 and Reporting.psm1.
    Validates the JSON schema contract between PowerShell output and the dashboard.
    Run with: Invoke-Pester .\tests\AuditChecks.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '..\scripts\Modules'
    Import-Module (Join-Path $moduleRoot 'AuditChecks.psm1') -Force
    Import-Module (Join-Path $moduleRoot 'Reporting.psm1')   -Force

    # Minimal valid New-AuditFinding call reused across tests
    $script:minimalParams = @{
        CheckId        = 'test-check'
        CheckName      = 'Test Check'
        Severity       = 'High'
        ObjectType     = 'User'
        AffectedObject = 'user@contoso.com'
        Title          = 'Test finding title'
        Description    = 'Test description.'
        Remediation    = 'Test remediation.'
    }
}

Describe 'New-AuditFinding' {

    It 'returns an object with all 10 required schema fields' {
        $finding = New-AuditFinding @script:minimalParams

        $expected = @('id','checkId','checkName','severity','objectType','affectedObject','title','description','detectedAt','remediation')
        $actual   = $finding.PSObject.Properties.Name

        foreach ($prop in $expected) {
            $actual | Should -Contain $prop
        }
    }

    It 'maps each parameter to the correct output field' {
        $finding = New-AuditFinding @script:minimalParams

        $finding.checkId        | Should -Be 'test-check'
        $finding.checkName      | Should -Be 'Test Check'
        $finding.severity       | Should -Be 'High'
        $finding.objectType     | Should -Be 'User'
        $finding.affectedObject | Should -Be 'user@contoso.com'
        $finding.title          | Should -Be 'Test finding title'
        $finding.description    | Should -Be 'Test description.'
        $finding.remediation    | Should -Be 'Test remediation.'
    }

    It 'generates a valid GUID for id when not specified' {
        $finding = New-AuditFinding @script:minimalParams
        $finding.id | Should -Not -BeNullOrEmpty
        { [guid]$finding.id } | Should -Not -Throw
    }

    It 'uses the caller-supplied id when provided' {
        $customId = [guid]::NewGuid().ToString()
        $finding  = New-AuditFinding @script:minimalParams -Id $customId
        $finding.id | Should -Be $customId
    }

    It 'sets detectedAt to a valid ISO 8601 UTC timestamp' {
        $finding = New-AuditFinding @script:minimalParams
        $finding.detectedAt | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        { [datetime]::ParseExact($finding.detectedAt, 'yyyy-MM-ddTHH:mm:ssZ', $null) } | Should -Not -Throw
    }

    It 'accepts all valid severity values' {
        foreach ($sev in @('Critical', 'High', 'Medium', 'Low')) {
            { New-AuditFinding @script:minimalParams -Severity $sev } | Should -Not -Throw
        }
    }

    It 'rejects an invalid severity value' {
        { New-AuditFinding @script:minimalParams -Severity 'Catastrophic' } | Should -Throw
    }

    It 'each call produces a unique id' {
        $a = New-AuditFinding @script:minimalParams
        $b = New-AuditFinding @script:minimalParams
        $a.id | Should -Not -Be $b.id
    }
}

Describe 'New-AuditReport' {

    It 'returns an object with metadata, summary, and findings keys' {
        $report = New-AuditReport -TenantDomain 'contoso.onmicrosoft.com' `
                                  -ToolVersion  '0.1.0' `
                                  -ChecksRun    @('no-mfa') `
                                  -Findings     @()

        $report.metadata | Should -Not -BeNullOrEmpty
        $report.summary  | Should -Not -BeNullOrEmpty
        $report.findings | Should -Not -BeNull
    }

    It 'populates metadata fields correctly' {
        $report = New-AuditReport -TenantDomain 'contoso.onmicrosoft.com' `
                                  -ToolVersion  '0.1.0' `
                                  -ChecksRun    @('stale-accounts', 'no-mfa') `
                                  -Findings     @()

        $report.metadata.tenantDomain | Should -Be 'contoso.onmicrosoft.com'
        $report.metadata.toolVersion  | Should -Be '0.1.0'
        $report.metadata.checksRun    | Should -Contain 'stale-accounts'
        $report.metadata.checksRun    | Should -Contain 'no-mfa'
        $report.metadata.generatedAt  | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
    }

    It 'counts totalFindings correctly' {
        $findings = @(
            (New-AuditFinding @script:minimalParams -AffectedObject 'a@test.com')
            (New-AuditFinding @script:minimalParams -AffectedObject 'b@test.com')
        )
        $report = New-AuditReport -TenantDomain 't' -ToolVersion '0.1.0' -ChecksRun @('test-check') -Findings $findings
        $report.summary.totalFindings | Should -Be 2
    }

    It 'counts bySeverity correctly across mixed severities' {
        $findings = @(
            (New-AuditFinding @script:minimalParams -Severity 'Critical' -AffectedObject 'a@t.com')
            (New-AuditFinding @script:minimalParams -Severity 'Critical' -AffectedObject 'b@t.com')
            (New-AuditFinding @script:minimalParams -Severity 'High'     -AffectedObject 'c@t.com')
            (New-AuditFinding @script:minimalParams -Severity 'Low'      -AffectedObject 'd@t.com')
        )
        $report = New-AuditReport -TenantDomain 't' -ToolVersion '0.1.0' -ChecksRun @('test-check') -Findings $findings

        $report.summary.totalFindings       | Should -Be 4
        $report.summary.bySeverity.Critical | Should -Be 2
        $report.summary.bySeverity.High     | Should -Be 1
        $report.summary.bySeverity.Medium   | Should -Be 0
        $report.summary.bySeverity.Low      | Should -Be 1
    }

    It 'counts byCheck correctly' {
        $findings = @(
            (New-AuditFinding @script:minimalParams -CheckId 'no-mfa'        -AffectedObject 'a@t.com')
            (New-AuditFinding @script:minimalParams -CheckId 'no-mfa'        -AffectedObject 'b@t.com')
            (New-AuditFinding @script:minimalParams -CheckId 'stale-accounts' -AffectedObject 'c@t.com')
        )
        $report = New-AuditReport -TenantDomain 't' -ToolVersion '0.1.0' -ChecksRun @('no-mfa','stale-accounts') -Findings $findings

        $report.summary.byCheck.'no-mfa'        | Should -Be 2
        $report.summary.byCheck.'stale-accounts' | Should -Be 1
    }

    It 'handles zero findings without error' {
        { New-AuditReport -TenantDomain 't' -ToolVersion '0.1.0' -ChecksRun @('no-mfa') -Findings @() } | Should -Not -Throw
    }
}
