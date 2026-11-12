<#
.SYNOPSIS
    Entry point for the Entra ID Audit Tool.
.DESCRIPTION
    Reads audit-config.json, authenticates to Microsoft Graph, runs every enabled
    audit check, and writes a timestamped JSON (and optional CSV) report to reports/.
.PARAMETER ConfigPath
    Path to audit-config.json. Defaults to scripts/config/audit-config.json.
    The real config is gitignored — copy audit-config.example.json to get started.
.PARAMETER IncludeCsv
    Force CSV output even if audit-config.json has includeCsv set to false.
.EXAMPLE
    .\scripts\Invoke-EntraAudit.ps1
.EXAMPLE
    .\scripts\Invoke-EntraAudit.ps1 -ConfigPath C:\secure\my-config.json -IncludeCsv
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\audit-config.json'),
    [switch]$IncludeCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ToolVersion = '0.2.0'

function Assert-AuditConfig {
    # Fail fast with a readable message instead of a StrictMode
    # "property cannot be found" error halfway through a run.
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    foreach ($key in 'tenantId', 'authMode', 'thresholds', 'checks') {
        if (-not $Config.PSObject.Properties[$key]) {
            throw "audit-config.json is missing required key '$key'. Compare it against audit-config.example.json."
        }
    }
    if ([string]::IsNullOrWhiteSpace($Config.tenantId) -or $Config.tenantId -like '<*>') {
        throw "audit-config.json 'tenantId' is empty or still a placeholder."
    }
    foreach ($key in 'staleAccountDays', 'staleGuestDays', 'secretExpiryWarningDays') {
        $prop    = $Config.thresholds.PSObject.Properties[$key]
        $isValid = $prop -and ($prop.Value -is [int] -or $prop.Value -is [long]) -and
                   $prop.Value -ge 1 -and $prop.Value -le 3650
        if (-not $isValid) {
            throw "audit-config.json 'thresholds.$key' must be a whole number of days between 1 and 3650."
        }
    }
}

# --- Imports ---
$moduleRoot = Join-Path $PSScriptRoot 'Modules'
Import-Module (Join-Path $moduleRoot 'GraphAPI.psm1')    -Force
Import-Module (Join-Path $moduleRoot 'AuditChecks.psm1') -Force
Import-Module (Join-Path $moduleRoot 'Reporting.psm1')   -Force

# --- Config ---
if (-not (Test-Path $ConfigPath)) {
    throw "Config not found at '$ConfigPath'. Copy scripts/config/audit-config.example.json to audit-config.json and fill in your tenant details."
}
try {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
}
catch {
    throw "Config at '$ConfigPath' is not valid JSON: $($_.Exception.Message)"
}
Assert-AuditConfig -Config $config

# --- Auth ---
Write-Host "Connecting to Microsoft Graph (tenant: $($config.tenantId), mode: $($config.authMode))..."
Connect-EntraAudit -Config $config

# --- Run checks ---
$findings     = [System.Collections.Generic.List[object]]::new()
$checksRun    = [System.Collections.Generic.List[string]]::new()
$checksFailed = [System.Collections.Generic.List[object]]::new()

$checkMap = [ordered]@{
    'stale-accounts'           = { Get-StaleAccountFindings          -Config $config }
    'no-mfa'                   = { Get-NoMfaFindings                 -Config $config }
    'guest-review'             = { Get-GuestReviewFindings           -Config $config }
    'privileged-roles'         = { Get-PrivilegedRoleFindings        -Config $config }
    'stale-service-principals' = { Get-StaleServicePrincipalFindings -Config $config }
    'ca-policy-gaps'           = { Get-ConditionalAccessGapFindings  -Config $config }
}

Write-Host "Running audit checks..."
foreach ($checkId in $checkMap.Keys) {
    $prop = $config.checks.PSObject.Properties.Item($checkId)
    if ($null -eq $prop -or $prop.Value -ne $true) {
        Write-Verbose "Skipping disabled check: $checkId"
        continue
    }

    Write-Host "  [$checkId]"
    try {
        $result = & $checkMap[$checkId]
        if ($result) { $findings.AddRange(@($result)) }
        $checksRun.Add($checkId)
    }
    catch {
        # One failing check (most often a P1/P2 licensing 403) must not abort
        # the others, but it must be recorded: "0 findings" and "didn't run"
        # mean very different things in an audit.
        $message = $_.Exception.Message
        $reason  = if ($message -match 'Forbidden|403') {
            'Access denied (missing permission/consent, or tenant lacks Entra ID P1/P2)'
        } else {
            'Check failed - re-run with -Verbose and see console warnings'
        }
        Write-Warning "Check '$checkId' failed: $message"
        $checksFailed.Add([PSCustomObject]@{ checkId = $checkId; reason = $reason })
    }
}

# --- Report ---
$report = New-AuditReport `
    -TenantDomain $config.tenantId `
    -ToolVersion  $ToolVersion `
    -ChecksRun    $checksRun.ToArray() `
    -Findings     $findings.ToArray() `
    -ChecksFailed $checksFailed.ToArray()

$projectRoot = Split-Path $PSScriptRoot -Parent
$outputDir   = Join-Path $projectRoot 'reports'

$exportArgs = @{ Report = $report; OutputDirectory = $outputDir }
$configWantsCsv = $config.PSObject.Properties['output'] -and
                  $config.output.PSObject.Properties['includeCsv'] -and
                  $config.output.includeCsv -eq $true
if ($IncludeCsv -or $configWantsCsv) { $exportArgs.IncludeCsv = $true }

$reportPath = Export-AuditReport @exportArgs

# --- Summary ---
$s = $report.summary
Write-Host ""
Write-Host "Audit complete - $($s.totalFindings) finding(s) across $($checksRun.Count) check(s)."
Write-Host "  Critical : $($s.bySeverity.Critical)"
Write-Host "  High     : $($s.bySeverity.High)"
Write-Host "  Medium   : $($s.bySeverity.Medium)"
Write-Host "  Low      : $($s.bySeverity.Low)"
Write-Host "  Report   : $reportPath"
if ($checksFailed.Count -gt 0) {
    Write-Warning "$($checksFailed.Count) check(s) did not complete: $(($checksFailed | ForEach-Object checkId) -join ', '). Their absence from the report is NOT a clean result."
}
