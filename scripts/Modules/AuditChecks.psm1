<#
.SYNOPSIS
    Audit check implementations for the Entra ID Audit Tool.
.DESCRIPTION
    Each Get-*Findings function queries Microsoft Graph for one governance
    condition and returns an array of finding objects built with
    New-AuditFinding, so every check produces output in the exact shape the
    dashboard expects (see samples/output/sample-data.json for the reference
    schema). See AUDIT-CHECKS.md for the Graph endpoint, severity, and
    remediation guidance behind each check.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-AuditFinding {
    <#
    .SYNOPSIS
        Builds a single finding object matching the dashboard's JSON contract.
    .DESCRIPTION
        Every check function should return findings built through this helper
        rather than constructing the object literally, so the schema stays
        consistent even as checks are added or changed.
    .PARAMETER CheckId
        Short slug for the check, e.g. "stale-accounts". Must match one of
        the IDs documented in AUDIT-CHECKS.md.
    .PARAMETER CheckName
        Human-readable check name, e.g. "Stale/Inactive Accounts".
    .PARAMETER Severity
        One of Critical, High, Medium, Low.
    .PARAMETER ObjectType
        The Entra object type the finding is about, e.g. User, Guest,
        ServicePrincipal, Group, Policy.
    .PARAMETER AffectedObject
        A human-identifiable reference to the object (UPN, display name, etc).
    .PARAMETER Title
        Short one-line summary of the finding.
    .PARAMETER Description
        Full detail of what was found.
    .PARAMETER Remediation
        Guidance on how to fix it.
    .PARAMETER Id
        Optional explicit finding ID. If omitted, a GUID is generated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$CheckName,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low')][string]$Severity,
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory)][string]$AffectedObject,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Remediation,
        [string]$Id = ([guid]::NewGuid().ToString())
    )

    [PSCustomObject]@{
        id             = $Id
        checkId        = $CheckId
        checkName      = $CheckName
        severity       = $Severity
        objectType     = $ObjectType
        affectedObject = $AffectedObject
        title          = $Title
        description    = $Description
        detectedAt     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        remediation    = $Remediation
    }
}

function Get-StaleAccountFindings {
    <#
    .SYNOPSIS
        Check 1: Stale/Inactive Accounts. See AUDIT-CHECKS.md section 1.
    .DESCRIPTION
        Queries all enabled users and flags anyone whose lastSignInDateTime is
        older than thresholds.staleAccountDays, or who has never signed in.
        Requires AuditLog.Read.All scope for the signInActivity field.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    $findings = [System.Collections.Generic.List[object]]::new()
    $cutoff   = (Get-Date).ToUniversalTime().AddDays(-$Config.thresholds.staleAccountDays)

    $users = Invoke-GraphQuery -Uri "/users?`$select=id,userPrincipalName,displayName,accountEnabled,signInActivity"

    foreach ($user in $users) {
        if ($user.accountEnabled -ne $true) { continue }

        $lastSignIn = $user.signInActivity.lastSignInDateTime

        if ($null -eq $lastSignIn) {
            $findings.Add((New-AuditFinding `
                -CheckId        'stale-accounts' `
                -CheckName      'Stale/Inactive Accounts' `
                -Severity       'Medium' `
                -ObjectType     'User' `
                -AffectedObject $user.userPrincipalName `
                -Title          'Account has never signed in' `
                -Description    "$($user.displayName) ($($user.userPrincipalName)) has no recorded sign-in activity." `
                -Remediation    'Review whether this account is still needed. If not, disable or delete it in Entra ID.'))
        }
        elseif ([datetime]$lastSignIn -lt $cutoff) {
            $daysSince = [int]((Get-Date).ToUniversalTime() - [datetime]$lastSignIn).TotalDays
            $findings.Add((New-AuditFinding `
                -CheckId        'stale-accounts' `
                -CheckName      'Stale/Inactive Accounts' `
                -Severity       'Medium' `
                -ObjectType     'User' `
                -AffectedObject $user.userPrincipalName `
                -Title          "Account inactive for $daysSince days" `
                -Description    "$($user.displayName) ($($user.userPrincipalName)) last signed in on $([datetime]$lastSignIn | Get-Date -Format 'yyyy-MM-dd') ($daysSince days ago). Threshold: $($Config.thresholds.staleAccountDays) days." `
                -Remediation    'Review whether this account is still needed. If active, confirm with the user. If stale, disable or delete it in Entra ID.'))
        }
    }

    return $findings.ToArray()
}

function Get-NoMfaFindings {
    <#
    .SYNOPSIS
        Check 2: Users Without MFA. See AUDIT-CHECKS.md section 2.
    .DESCRIPTION
        Queries the authentication methods registration report and flags any
        user who has not registered an MFA method.
        Requires AuditLog.Read.All or UserAuthenticationMethod.Read.All scope.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    $findings = [System.Collections.Generic.List[object]]::new()

    $users = Invoke-GraphQuery -Uri '/reports/authenticationMethods/userRegistrationDetails'

    foreach ($user in $users) {
        if ($user.isMfaRegistered -ne $true) {
            $findings.Add((New-AuditFinding `
                -CheckId        'no-mfa' `
                -CheckName      'Users Without MFA' `
                -Severity       'Critical' `
                -ObjectType     'User' `
                -AffectedObject $user.userPrincipalName `
                -Title          'User has no MFA method registered' `
                -Description    "$($user.userPrincipalName) has not registered any MFA authentication method and is vulnerable to password-only attacks." `
                -Remediation    'Require the user to register an MFA method via aka.ms/mfasetup. Enforce registration through a Conditional Access policy targeting all users.'))
        }
    }

    return $findings.ToArray()
}

function Get-GuestReviewFindings {
    <#
    .SYNOPSIS
        Check 3: Guest Account Review. See AUDIT-CHECKS.md section 3.
    .DESCRIPTION
        Flags guest accounts that have never signed in (invite accepted but
        unused) or that have not signed in within thresholds.staleGuestDays.
        Requires AuditLog.Read.All scope for signInActivity.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    $findings = [System.Collections.Generic.List[object]]::new()
    $cutoff   = (Get-Date).ToUniversalTime().AddDays(-$Config.thresholds.staleGuestDays)

    $users = Invoke-GraphQuery -Uri "/users?`$select=id,userPrincipalName,displayName,accountEnabled,userType,signInActivity"

    foreach ($user in $users) {
        if ($user.userType -ne 'Guest') { continue }
        if ($user.accountEnabled -ne $true) { continue }

        $lastSignIn = $user.signInActivity.lastSignInDateTime

        if ($null -eq $lastSignIn) {
            $findings.Add((New-AuditFinding `
                -CheckId        'guest-review' `
                -CheckName      'Guest Account Review' `
                -Severity       'Medium' `
                -ObjectType     'Guest' `
                -AffectedObject $user.userPrincipalName `
                -Title          'Guest account has never signed in' `
                -Description    "$($user.displayName) ($($user.userPrincipalName)) is an enabled guest account with no recorded sign-in activity." `
                -Remediation    'Confirm whether this guest still requires access. If not, remove the guest account to reduce the external attack surface.'))
        }
        elseif ([datetime]$lastSignIn -lt $cutoff) {
            $daysSince = [int]((Get-Date).ToUniversalTime() - [datetime]$lastSignIn).TotalDays
            $findings.Add((New-AuditFinding `
                -CheckId        'guest-review' `
                -CheckName      'Guest Account Review' `
                -Severity       'Medium' `
                -ObjectType     'Guest' `
                -AffectedObject $user.userPrincipalName `
                -Title          "Guest account inactive for $daysSince days" `
                -Description    "$($user.displayName) ($($user.userPrincipalName)) last signed in on $([datetime]$lastSignIn | Get-Date -Format 'yyyy-MM-dd') ($daysSince days ago). Threshold: $($Config.thresholds.staleGuestDays) days." `
                -Remediation    'Review whether this guest still requires access. If access is no longer needed, remove the guest account.'))
        }
    }

    return $findings.ToArray()
}

function Get-PrivilegedRoleFindings {
    <#
    .SYNOPSIS
        Check 4: Privileged Role Assignments. See AUDIT-CHECKS.md section 4.
    .DESCRIPTION
        Flags permanent (non-PIM) assignments to high-privilege Entra ID roles.
        Permanent assignments are always active; PIM-eligible assignments require
        explicit activation and are time-limited — making them significantly safer.
        Requires RoleManagement.Read.Directory scope.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    $findings = [System.Collections.Generic.List[object]]::new()

    # Well-known template IDs for high-privilege built-in Entra ID roles
    $highPrivilegeRoles = [ordered]@{
        '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
        '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    }

    # Graph only allows expanding one navigation property per request, and we
    # already know the role names above, so only principal needs expanding.
    $assignments = Invoke-GraphQuery -Uri "/roleManagement/directory/roleAssignments?`$expand=principal"

    foreach ($assignment in $assignments) {
        if (-not $highPrivilegeRoles.Contains($assignment.roleDefinitionId)) { continue }
        if ($null -eq $assignment.principal) { continue }

        $roleName       = $highPrivilegeRoles[$assignment.roleDefinitionId]
        $affectedObject = if ($assignment.principal.userPrincipalName) {
            $assignment.principal.userPrincipalName
        } else {
            $assignment.principal.displayName
        }

        $findings.Add((New-AuditFinding `
            -CheckId        'privileged-roles' `
            -CheckName      'Privileged Role Assignments' `
            -Severity       'Critical' `
            -ObjectType     'User' `
            -AffectedObject $affectedObject `
            -Title          "Permanent assignment to $roleName" `
            -Description    "$affectedObject holds a permanent (non-PIM) assignment to '$roleName'. Permanent assignments are always active, increasing exposure if the account is compromised." `
            -Remediation    "Convert to a PIM-eligible assignment in Entra ID Privileged Identity Management. The user can then activate the role on-demand with justification and time limits."))
    }

    return $findings.ToArray()
}

function Get-StaleServicePrincipalFindings {
    <#
    .SYNOPSIS
        Check 5: Stale/Orphaned Service Principals & App Registrations.
        See AUDIT-CHECKS.md section 5.
    .DESCRIPTION
        Flags app registrations with credentials (client secrets or certificates)
        that have already expired or will expire within thresholds.secretExpiryWarningDays.
        Expired credentials can cause silent outages; expiring ones need proactive rotation.
        Requires Application.Read.All scope.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    $findings    = [System.Collections.Generic.List[object]]::new()
    $now         = (Get-Date).ToUniversalTime()
    $warnCutoff  = $now.AddDays($Config.thresholds.secretExpiryWarningDays)

    $apps = Invoke-GraphQuery -Uri "/applications?`$select=id,appId,displayName,passwordCredentials,keyCredentials"

    foreach ($app in $apps) {
        $allCreds = @(
            ($app.passwordCredentials | ForEach-Object { $_ | Add-Member -NotePropertyName credType -NotePropertyValue 'Secret' -PassThru })
            ($app.keyCredentials      | ForEach-Object { $_ | Add-Member -NotePropertyName credType -NotePropertyValue 'Certificate' -PassThru })
        ) | Where-Object { $null -ne $_ }

        foreach ($cred in $allCreds) {
            if ($null -eq $cred.endDateTime) { continue }

            $expiry   = [datetime]$cred.endDateTime
            $credName = if ([string]::IsNullOrWhiteSpace($cred.displayName)) { $cred.keyId } else { $cred.displayName }

            if ($expiry -lt $now) {
                $daysPast = [int]($now - $expiry).TotalDays
                $findings.Add((New-AuditFinding `
                    -CheckId        'stale-service-principals' `
                    -CheckName      'Stale/Orphaned Service Principals & App Registrations' `
                    -Severity       'High' `
                    -ObjectType     'ServicePrincipal' `
                    -AffectedObject $app.displayName `
                    -Title          "$($cred.credType) '$credName' expired $daysPast days ago" `
                    -Description    "App registration '$($app.displayName)' has an expired $($cred.credType.ToLower()) ('$credName') that expired on $($expiry | Get-Date -Format 'yyyy-MM-dd'). Any service using this credential is likely failing silently." `
                    -Remediation    "Rotate the credential in the App Registration and update the consuming service. Remove the expired credential once the new one is confirmed working."))
            }
            elseif ($expiry -lt $warnCutoff) {
                $daysLeft = [int]($expiry - $now).TotalDays
                $findings.Add((New-AuditFinding `
                    -CheckId        'stale-service-principals' `
                    -CheckName      'Stale/Orphaned Service Principals & App Registrations' `
                    -Severity       'Medium' `
                    -ObjectType     'ServicePrincipal' `
                    -AffectedObject $app.displayName `
                    -Title          "$($cred.credType) '$credName' expiring in $daysLeft days" `
                    -Description    "App registration '$($app.displayName)' has a $($cred.credType.ToLower()) ('$credName') expiring on $($expiry | Get-Date -Format 'yyyy-MM-dd') ($daysLeft days). Threshold: $($Config.thresholds.secretExpiryWarningDays) days." `
                    -Remediation    "Rotate the credential before it expires to avoid service disruption. Update the consuming service and remove the old credential."))
            }
        }
    }

    return $findings.ToArray()
}

function Get-ConditionalAccessGapFindings {
    <#
    .SYNOPSIS
        Check 6: Conditional Access Policy Gaps. See AUDIT-CHECKS.md section 6.
    .DESCRIPTION
        Flags CA policies that are disabled (not enforcing) or in report-only mode
        (logging but not enforcing). Also flags tenants with no CA policies at all.
        Requires Policy.Read.All scope.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    $findings = [System.Collections.Generic.List[object]]::new()

    $policies = Invoke-GraphQuery -Uri '/identity/conditionalAccess/policies'

    if ($policies.Count -eq 0) {
        $findings.Add((New-AuditFinding `
            -CheckId        'ca-policy-gaps' `
            -CheckName      'Conditional Access Policy Gaps' `
            -Severity       'High' `
            -ObjectType     'Policy' `
            -AffectedObject 'Tenant' `
            -Title          'No Conditional Access policies found' `
            -Description    'No Conditional Access policies are configured in this tenant. All users and applications can authenticate without any additional access controls beyond username and password.' `
            -Remediation    'Create baseline CA policies: require MFA for all users, block legacy authentication protocols, and consider restricting access from high-risk locations or sign-in risk levels.'))
        return $findings.ToArray()
    }

    foreach ($policy in $policies) {
        switch ($policy.state) {
            'disabled' {
                $findings.Add((New-AuditFinding `
                    -CheckId        'ca-policy-gaps' `
                    -CheckName      'Conditional Access Policy Gaps' `
                    -Severity       'High' `
                    -ObjectType     'Policy' `
                    -AffectedObject $policy.displayName `
                    -Title          "CA policy is disabled: $($policy.displayName)" `
                    -Description    "The Conditional Access policy '$($policy.displayName)' exists but is disabled and not enforcing any controls. It was likely created with intent but never enabled, or was turned off." `
                    -Remediation    'Review the policy and re-enable it if it is still needed. If it is no longer relevant, delete it to reduce confusion.'))
            }
            'enabledForReportingButNotEnforcing' {
                $findings.Add((New-AuditFinding `
                    -CheckId        'ca-policy-gaps' `
                    -CheckName      'Conditional Access Policy Gaps' `
                    -Severity       'Medium' `
                    -ObjectType     'Policy' `
                    -AffectedObject $policy.displayName `
                    -Title          "CA policy in report-only mode: $($policy.displayName)" `
                    -Description    "The Conditional Access policy '$($policy.displayName)' is in report-only mode. It logs what it would enforce but is not blocking or requiring anything." `
                    -Remediation    "Review the sign-in logs to assess the policy's impact. Once comfortable with the results, switch the policy state from report-only to enabled."))
            }
        }
    }

    return $findings.ToArray()
}

Export-ModuleMember -Function `
    New-AuditFinding, `
    Get-StaleAccountFindings, `
    Get-NoMfaFindings, `
    Get-GuestReviewFindings, `
    Get-PrivilegedRoleFindings, `
    Get-StaleServicePrincipalFindings, `
    Get-ConditionalAccessGapFindings
