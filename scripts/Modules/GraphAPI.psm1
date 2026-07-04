<#
.SYNOPSIS
    Microsoft Graph authentication and request helpers for the Entra ID Audit Tool.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Connect-EntraAudit {
    <#
    .SYNOPSIS
        Establishes an authenticated Microsoft Graph session for the audit run.
    .DESCRIPTION
        Branches on authMode from audit-config.json:
          - delegated  : interactive browser sign-in (Connect-MgGraph -Scopes)
          - app-only   : certificate-based unattended auth (Connect-MgGraph -ClientId -CertificateThumbprint)
        Verifies the session after connecting and throws a clean error on failure
        without echoing credentials or raw tokens into the message.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config
    )

    $requiredScopes = @(
        'User.Read.All',
        'AuditLog.Read.All',
        'Policy.Read.All',
        'RoleManagement.Read.Directory',
        'Application.Read.All'
    )

    try {
        switch ($Config.authMode) {
            'delegated' {
                Write-Verbose "Starting interactive (delegated) authentication..."
                Connect-MgGraph -Scopes $requiredScopes -TenantId $Config.tenantId -NoWelcome -UseDeviceAuthentication
            }
            'app-only' {
                if (-not $Config.appOnly -or
                    [string]::IsNullOrWhiteSpace($Config.appOnly.clientId) -or
                    [string]::IsNullOrWhiteSpace($Config.appOnly.certificateThumbprint) -or
                    $Config.appOnly.clientId -like '<*>') {
                    throw "authMode is 'app-only' but appOnly.clientId or appOnly.certificateThumbprint is missing or still a placeholder in audit-config.json."
                }
                Write-Verbose "Starting app-only (certificate) authentication..."
                Connect-MgGraph `
                    -ClientId              $Config.appOnly.clientId `
                    -TenantId              $Config.tenantId `
                    -CertificateThumbprint $Config.appOnly.certificateThumbprint `
                    -NoWelcome
            }
            default {
                throw "Unsupported authMode '$($Config.authMode)'. Expected 'delegated' or 'app-only'."
            }
        }
    }
    catch {
        throw "Microsoft Graph authentication failed: $($_.Exception.Message)"
    }

    $ctx = Get-MgContext
    if ($null -eq $ctx) {
        throw "Authentication appeared to succeed but no active Graph context was found. Check your tenantId and credentials."
    }

    if ($Config.authMode -eq 'app-only' -and $ctx.AppId -ne $Config.appOnly.clientId) {
        throw "Authenticated App ID does not match the configured clientId. Verify your App Registration."
    }

    Write-Verbose "Graph session established. TenantId: $($ctx.TenantId) | AuthType: $($ctx.AuthType)"
}

function Invoke-GraphQuery {
    <#
    .SYNOPSIS
        Calls a Microsoft Graph endpoint and returns every page of results.
    .DESCRIPTION
        Generic read-only wrapper around Invoke-MgGraphRequest that:
          - Follows @odata.nextLink until results are exhausted, so callers
            never see a truncated first page.
          - Retries on HTTP 429 (throttled) and 503 (service unavailable),
            honoring the Retry-After header when the API provides one.
          - Surfaces a clear error on any other failure without dumping the
            raw Graph error payload, which can include tenant-specific detail.
    .PARAMETER Uri
        The Graph URI to call, e.g. "/users?$select=id,userPrincipalName".
    .PARAMETER MaxRetries
        Maximum throttling retries per page before giving up. Defaults to 5.
    .EXAMPLE
        Invoke-GraphQuery -Uri "/users?`$select=id,displayName,signInActivity"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [int]$MaxRetries = 5
    )

    if ($Uri -notmatch '^https?://') {
        $Uri = "https://graph.microsoft.com/v1.0$Uri"
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    $attempt = 0

    while ($null -ne $nextUri) {
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri -OutputType PSObject
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = $_.Exception.Response.StatusCode.value__
            }

            if (($statusCode -eq 429 -or $statusCode -eq 503) -and $attempt -lt $MaxRetries) {
                $attempt++
                $retryAfter = $null
                if ($_.Exception.Response -and $_.Exception.Response.Headers) {
                    $retryAfter = $_.Exception.Response.Headers['Retry-After']
                }
                $delaySeconds = if ($retryAfter) { [int]$retryAfter } else { [Math]::Pow(2, $attempt) }
                Write-Warning "Graph request throttled (HTTP $statusCode). Retrying in $delaySeconds second(s) - attempt $attempt of $MaxRetries."
                Start-Sleep -Seconds $delaySeconds
                continue
            }

            throw "Graph request to '$nextUri' failed: $($_.Exception.Message)"
        }

        $valueProp = $response.PSObject.Properties['value']
        if ($null -ne $valueProp) {
            $results.AddRange(@($valueProp.Value))
        }
        elseif ($response) {
            $results.Add($response)
        }

        $nextUri = $response.PSObject.Properties['@odata.nextLink']?.Value
        $attempt = 0
    }

    return ,$results
}

Export-ModuleMember -Function Connect-EntraAudit, Invoke-GraphQuery
