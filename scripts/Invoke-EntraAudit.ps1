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

# --- Imports ---
$moduleRoot = Join-Path $PSScriptRoot 'Modules'
Import-Module (Join-Path $moduleRoot 'GraphAPI.psm1')    -Force
Import-Module (Join-Path $moduleRoot 'AuditChecks.psm1') -Force
Import-Module (Join-Path $moduleRoot 'Reporting.psm1')   -Force

# --- Config ---
if (-not (Test-Path $ConfigPath)) {
    throw "Config not found at '$ConfigPath'. Copy scripts/config/audit-config.example.json to audit-config.json and fill in your tenant details."
}
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

# --- Auth ---
Write-Host "Connecting to Microsoft Graph (tenant: $($config.tenantId), mode: $($config.authMode))..."
Connect-EntraAudit -Config $config

# --- Run checks ---
$findings  = [System.Collections.Generic.List[object]]::new()
$checksRun = [System.Collections.Generic.List[string]]::new()

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
        Write-Warning "Check '$checkId' failed: $($_.Exception.Message)"
    }
}

# --- Report ---
$report = New-AuditReport `
    -TenantDomain $config.tenantId `
    -ToolVersion  '0.1.0' `
    -ChecksRun    $checksRun.ToArray() `
    -Findings     $findings.ToArray()

$projectRoot = Split-Path $PSScriptRoot -Parent
$outputDir   = Join-Path $projectRoot 'reports'

$exportArgs = @{ Report = $report; OutputDirectory = $outputDir }
if ($IncludeCsv -or $config.output.includeCsv) { $exportArgs.IncludeCsv = $true }

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
