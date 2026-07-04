<#
.SYNOPSIS
    Report assembly and export for the Entra ID Audit Tool.
.DESCRIPTION
    Combines findings from every audit check into the single report object
    the dashboard expects, and writes that report to disk. See
    samples/output/sample-data.json for the reference schema this module
    must produce.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-AuditReport {
    <#
    .SYNOPSIS
        Assembles findings from all checks into the report object shape the
        dashboard expects.
    .PARAMETER TenantDomain
        The tenant domain the audit was run against.
    .PARAMETER ToolVersion
        Version string for this tool, e.g. "0.1.0".
    .PARAMETER ChecksRun
        Array of checkId slugs that were executed.
    .PARAMETER Findings
        Combined array of finding objects from New-AuditFinding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantDomain,
        [Parameter(Mandatory)][string]$ToolVersion,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ChecksRun,
        [AllowEmptyCollection()][object[]]$Findings = @()
    )

    $bySeverity = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    $byCheck = [ordered]@{}

    foreach ($finding in $Findings) {
        if ($bySeverity.Contains($finding.severity)) {
            $bySeverity[$finding.severity]++
        }
        if (-not $byCheck.Contains($finding.checkId)) {
            $byCheck[$finding.checkId] = 0
        }
        $byCheck[$finding.checkId]++
    }

    [PSCustomObject]@{
        metadata = [PSCustomObject]@{
            tenantDomain = $TenantDomain
            generatedAt  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            toolVersion  = $ToolVersion
            checksRun    = $ChecksRun
        }
        summary  = [PSCustomObject]@{
            totalFindings = $Findings.Count
            bySeverity    = [PSCustomObject]$bySeverity
            byCheck       = [PSCustomObject]$byCheck
        }
        findings = $Findings
    }
}

function Export-AuditReport {
    <#
    .SYNOPSIS
        Writes an audit report to disk as JSON (and optionally CSV).
    .DESCRIPTION
        Output is timestamped rather than overwriting a fixed filename, so
        successive runs don't clobber each other. reports/ is gitignored —
        see Security.md for the retention rationale.
    .PARAMETER Report
        The report object from New-AuditReport.
    .PARAMETER OutputDirectory
        Directory to write into. Defaults to reports/ relative to this module.
    .PARAMETER IncludeCsv
        Also write a flattened CSV of the findings array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Report,
        [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\..\reports'),
        [switch]$IncludeCsv
    )

    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $jsonPath = Join-Path $OutputDirectory "audit-report-$timestamp.json"
    $Report | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding utf8

    Write-Verbose "Wrote JSON report to $jsonPath"

    if ($IncludeCsv) {
        $csvPath = Join-Path $OutputDirectory "audit-report-$timestamp.csv"
        $Report.findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
        Write-Verbose "Wrote CSV report to $csvPath"
    }

    return $jsonPath
}

Export-ModuleMember -Function New-AuditReport, Export-AuditReport
