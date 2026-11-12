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

    All Graph access goes through Invoke-GraphQuery, which is also the single
    seam the Pester tests mock to exercise these checks without a tenant.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

function Get-OptionalProperty {
    # Graph omits or nulls properties freely (e.g. signInActivity for a user
    # who has never signed in). Under StrictMode, dotting into a missing
    # property throws, so every "may not be there" read goes through here.
    param($InputObject, [string]$Name)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject[$Name] }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function ConvertTo-UtcDateTime {
    # Graph timestamps are ISO 8601 UTC. Depending on how they were
    # deserialized they arrive as strings or as DateTime (sometimes converted
    # to local time), so normalise to UTC before comparing against cutoffs.
    param($Value)

    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse(
        [string]$Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
}

function Get-InactiveUserFindings {
    # Shared implementation behind the stale-account and guest-review checks:
    # same query, same "never / not recently signed in" logic, different
    # population and wording.
    param(
        [Parameter(Mandatory)][ValidateSet('Member', 'Guest')][string]$UserType,
        [Parameter(Mandatory)][int]$ThresholdDays
    )

    $isGuest = $UserType -eq 'Guest'
    $meta = if ($isGuest) {
        @{ CheckId = 'guest-review'; CheckName = 'Guest Account Review'; ObjectType = 'Guest'; Noun = 'Guest account' }
    } else {
        @{ CheckId = 'stale-accounts'; CheckName = 'Stale/Inactive Accounts'; ObjectType = 'User'; Noun = 'Account' }
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $now      = (Get-Date).ToUniversalTime()
    $cutoff   = $now.AddDays(-$ThresholdDays)

    $users = Invoke-GraphQuery -Uri "/users?`$select=id,userPrincipalName,displayName,accountEnabled,userType,signInActivity"

    foreach ($user in $users) {
        # Treat a missing userType as Member, matching Entra's default.
        $type = Get-OptionalProperty $user 'userType'
        $type = if ($type) { $type } else { 'Member' }
        if ($type -ne $UserType) { continue }
        if ((Get-OptionalProperty $user 'accountEnabled') -ne $true) { continue }

        $upn         = Get-OptionalProperty $user 'userPrincipalName'
        $displayName = Get-OptionalProperty $user 'displayName'
        $lastSignIn  = ConvertTo-UtcDateTime (Get-OptionalProperty (Get-OptionalProperty $user 'signInActivity') 'lastSignInDateTime')

        if ($null -eq $lastSignIn) {
            $remediation = if ($isGuest) {
                'Confirm whether this guest still requires access. If not, remove the guest account to reduce the external attack surface.'
            } else {
                'Review whether this account is still needed. If not, disable or delete it in Entra ID.'
            }
            $findings.Add((New-AuditFinding `
                -CheckId        $meta.CheckId `
                -CheckName      $meta.CheckName `
                -Severity       'Medium' `
                -ObjectType     $meta.ObjectType `
                -AffectedObject $upn `
                -Title          "$($meta.Noun) has never signed in" `
                -Description    "$displayName ($upn) is enabled but has no recorded sign-in activity." `
                -Remediation    $remediation))
        }
        elseif ($lastSignIn -lt $cutoff) {
            $daysSince   = [int][Math]::Floor(($now - $lastSignIn).TotalDays)
            $remediation = if ($isGuest) {
                'Review whether this guest still requires access. If access is no longer needed, remove the guest account.'
            } else {
                'Review whether this account is still needed. If active, confirm with the user. If stale, disable or delete it in Entra ID.'
            }
            $findings.Add((New-AuditFinding `
                -CheckId        $meta.CheckId `
                -CheckName      $meta.CheckName `
                -Severity       'Medium' `
                -ObjectType     $meta.ObjectType `
                -AffectedObject $upn `
                -Title          "$($meta.Noun) inactive for $daysSince days" `
                -Description    "$displayName ($upn) last signed in on $($lastSignIn.ToString('yyyy-MM-dd')) ($daysSince days ago). Threshold: $ThresholdDays days." `
                -Remediation    $remediation))
        }
    }

    return $findings.ToArray()
}

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

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
        Group, ServicePrincipal, Application, Policy.
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
        [Parameter(Mandatory)][AllowEmptyString()][string]$AffectedObject,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Remediation,
        [string]$Id = ([guid]::NewGuid().ToString())
    )

    if ([string]::IsNullOrWhiteSpace($AffectedObject)) { $AffectedObject = '(unnamed object)' }

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
        Flags enabled member (non-guest) users whose lastSignInDateTime is older
        than thresholds.staleAccountDays, or who have never signed in. Guests are
        covered separately by Get-GuestReviewFindings so they aren't double-counted.
        Requires AuditLog.Read.All scope and an Entra ID P1/P2 licence for signInActivity.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    Get-InactiveUserFindings -UserType Member -ThresholdDays $Config.thresholds.staleAccountDays
}

function Get-NoMfaFindings {
    <#
    .SYNOPSIS
        Check 2: Users Without MFA. See AUDIT-CHECKS.md section 2.
    .DESCRIPTION
        Queries the authentication methods registration report and flags any
        user who has not registered an MFA-capable method.
        Requires AuditLog.Read.All scope and an Entra ID P1/P2 licence.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    $findings = [System.Collections.Generic.List[object]]::new()

    $records = Invoke-GraphQuery -Uri '/reports/authenticationMethods/userRegistrationDetails'

    foreach ($record in $records) {
        if ((Get-OptionalProperty $record 'isMfaRegistered') -eq $true) { continue }

        $upn = Get-OptionalProperty $record 'userPrincipalName'
        $findings.Add((New-AuditFinding `
            -CheckId        'no-mfa' `
            -CheckName      'Users Without MFA' `
            -Severity       'Critical' `
            -ObjectType     'User' `
            -AffectedObject $upn `
            -Title          'User has no MFA method registered' `
            -Description    "$upn has not registered any MFA authentication method and is vulnerable to password-only attacks." `
            -Remediation    'Require the user to register an MFA method via aka.ms/mfasetup. Enforce registration through a Conditional Access policy targeting all users.'))
    }

    return $findings.ToArray()
}

function Get-GuestReviewFindings {
    <#
    .SYNOPSIS
        Check 3: Guest Account Review. See AUDIT-CHECKS.md section 3.
    .DESCRIPTION
        Flags enabled guest accounts that have never signed in (invited but
        unused) or that have not signed in within thresholds.staleGuestDays.
        Requires AuditLog.Read.All scope and an Entra ID P1/P2 licence for signInActivity.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    Get-InactiveUserFindings -UserType Guest -ThresholdDays $Config.thresholds.staleGuestDays
}

function Get-PrivilegedRoleFindings {
    <#
    .SYNOPSIS
        Check 4: Privileged Role Assignments. See AUDIT-CHECKS.md section 4.
    .DESCRIPTION
        Flags every principal holding an active assignment to one of seven
        high-privilege built-in Entra ID roles.

        Limitation: /roleManagement/directory/roleAssignments returns all
        assignments active at the time of the scan. That includes standing
        (permanent) assignments AND PIM-eligible roles that happen to be
        activated right now, so the finding says "active", not "permanent".
        Distinguishing the two needs the PIM schedule APIs (Entra ID P2).
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

    $principalTypes = @{
        '#microsoft.graph.user'             = 'User'
        '#microsoft.graph.group'            = 'Group'
        '#microsoft.graph.servicePrincipal' = 'ServicePrincipal'
    }

    # Graph only allows expanding one navigation property per request, and we
    # already know the role names above, so only principal needs expanding.
    $assignments = Invoke-GraphQuery -Uri "/roleManagement/directory/roleAssignments?`$expand=principal"

    foreach ($assignment in $assignments) {
        $roleId = Get-OptionalProperty $assignment 'roleDefinitionId'
        if (-not $roleId -or -not $highPrivilegeRoles.Contains($roleId)) { continue }

        $principal = Get-OptionalProperty $assignment 'principal'
        if ($null -eq $principal) { continue }

        $roleName   = $highPrivilegeRoles[$roleId]
        $odataType  = Get-OptionalProperty $principal '@odata.type'
        $objectType = if ($odataType -and $principalTypes.ContainsKey($odataType)) { $principalTypes[$odataType] } else { 'User' }

        $upn            = Get-OptionalProperty $principal 'userPrincipalName'
        $affectedObject = if ($upn) { $upn } else { Get-OptionalProperty $principal 'displayName' }

        $findings.Add((New-AuditFinding `
            -CheckId        'privileged-roles' `
            -CheckName      'Privileged Role Assignments' `
            -Severity       'Critical' `
            -ObjectType     $objectType `
            -AffectedObject $affectedObject `
            -Title          "Active assignment to $roleName" `
            -Description    "$affectedObject ($objectType) holds an active assignment to '$roleName'. This may be a standing assignment or a PIM role activated at scan time; standing assignments are always on, increasing exposure if the principal is compromised." `
            -Remediation    "Confirm in Privileged Identity Management whether this assignment is permanent. If so, convert it to PIM-eligible so the role is activated on demand with justification and time limits. Reserve permanent assignments for break-glass accounts."))
    }

    return $findings.ToArray()
}

function Get-StaleServicePrincipalFindings {
    <#
    .SYNOPSIS
        Check 5: App Registration Credential Expiry. See AUDIT-CHECKS.md section 5.
    .DESCRIPTION
        Flags app registrations with credentials (client secrets or certificates)
        that have already expired or will expire within thresholds.secretExpiryWarningDays.
        Expired credentials are leftover clutter (and often a sign the app is
        abandoned); expiring ones need proactive rotation to avoid outages.
        The checkId keeps its original 'stale-service-principals' slug for
        config/report compatibility.
        Requires Application.Read.All scope.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    $findings   = [System.Collections.Generic.List[object]]::new()
    $warnDays   = $Config.thresholds.secretExpiryWarningDays
    $now        = (Get-Date).ToUniversalTime()
    $warnCutoff = $now.AddDays($warnDays)
    $checkName  = 'App Registration Credential Expiry'

    $apps = Invoke-GraphQuery -Uri "/applications?`$select=id,appId,displayName,passwordCredentials,keyCredentials"

    foreach ($app in $apps) {
        $appName  = Get-OptionalProperty $app 'displayName'
        $allCreds = @(
            foreach ($c in @(Get-OptionalProperty $app 'passwordCredentials')) { if ($c) { @{ Cred = $c; Type = 'Secret' } } }
            foreach ($c in @(Get-OptionalProperty $app 'keyCredentials'))      { if ($c) { @{ Cred = $c; Type = 'Certificate' } } }
        )

        foreach ($entry in $allCreds) {
            $expiry = ConvertTo-UtcDateTime (Get-OptionalProperty $entry.Cred 'endDateTime')
            if ($null -eq $expiry) { continue }

            $credType = $entry.Type
            $credName = Get-OptionalProperty $entry.Cred 'displayName'
            if ([string]::IsNullOrWhiteSpace($credName)) { $credName = Get-OptionalProperty $entry.Cred 'keyId' }

            if ($expiry -lt $now) {
                $daysPast = [int][Math]::Floor(($now - $expiry).TotalDays)
                $findings.Add((New-AuditFinding `
                    -CheckId        'stale-service-principals' `
                    -CheckName      $checkName `
                    -Severity       'High' `
                    -ObjectType     'Application' `
                    -AffectedObject $appName `
                    -Title          "$credType '$credName' expired $daysPast days ago" `
                    -Description    "App registration '$appName' has an expired $($credType.ToLower()) ('$credName') that expired on $($expiry.ToString('yyyy-MM-dd')). If the app is still in use it is likely failing; if not, the registration may be abandoned." `
                    -Remediation    'Confirm whether the app is still in use. If it is, rotate the credential and update the consuming service. If not, remove the app registration. Either way, delete the expired credential.'))
            }
            elseif ($expiry -lt $warnCutoff) {
                $daysLeft = [int][Math]::Ceiling(($expiry - $now).TotalDays)
                $findings.Add((New-AuditFinding `
                    -CheckId        'stale-service-principals' `
                    -CheckName      $checkName `
                    -Severity       'Medium' `
                    -ObjectType     'Application' `
                    -AffectedObject $appName `
                    -Title          "$credType '$credName' expiring in $daysLeft days" `
                    -Description    "App registration '$appName' has a $($credType.ToLower()) ('$credName') expiring on $($expiry.ToString('yyyy-MM-dd')) ($daysLeft days). Threshold: $warnDays days." `
                    -Remediation    'Rotate the credential before it expires to avoid service disruption. Update the consuming service and remove the old credential.'))
            }
        }
    }

    return $findings.ToArray()
}

function Get-ConditionalAccessGapFindings {
    <#
    .SYNOPSIS
        Check 6: Conditional Access Policy State. See AUDIT-CHECKS.md section 6.
    .DESCRIPTION
        Flags CA policies that are disabled (not enforcing) or in report-only mode
        (logging but not enforcing), and tenants with no CA policies at all.
        Does not analyse user/group coverage or exclusions.
        Requires Policy.Read.All scope and an Entra ID P1/P2 licence.
    .PARAMETER Config
        The parsed audit-config.json object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Config)

    $findings  = [System.Collections.Generic.List[object]]::new()
    $checkName = 'Conditional Access Policy Gaps'

    # Invoke-GraphQuery returns its List as a single object (return ,$list),
    # so @(...) would wrap an empty list into a 1-element array. Enumerate it.
    $policies = @(foreach ($p in (Invoke-GraphQuery -Uri '/identity/conditionalAccess/policies')) { $p })

    if ($policies.Count -eq 0) {
        $findings.Add((New-AuditFinding `
            -CheckId        'ca-policy-gaps' `
            -CheckName      $checkName `
            -Severity       'High' `
            -ObjectType     'Policy' `
            -AffectedObject 'Tenant' `
            -Title          'No Conditional Access policies found' `
            -Description    'No Conditional Access policies are configured in this tenant. Unless Security Defaults are enabled, users can authenticate with no controls beyond username and password.' `
            -Remediation    'Create baseline CA policies: require MFA for all users, block legacy authentication protocols, and consider restricting access by sign-in risk or location.'))
        return $findings.ToArray()
    }

    foreach ($policy in $policies) {
        $name = Get-OptionalProperty $policy 'displayName'
        switch (Get-OptionalProperty $policy 'state') {
            'disabled' {
                $findings.Add((New-AuditFinding `
                    -CheckId        'ca-policy-gaps' `
                    -CheckName      $checkName `
                    -Severity       'High' `
                    -ObjectType     'Policy' `
                    -AffectedObject $name `
                    -Title          "CA policy is disabled: $name" `
                    -Description    "The Conditional Access policy '$name' exists but is disabled and not enforcing any controls." `
                    -Remediation    'Review the policy and re-enable it if it is still needed. If it is no longer relevant, delete it to reduce confusion.'))
            }
            'enabledForReportingButNotEnforcing' {
                $findings.Add((New-AuditFinding `
                    -CheckId        'ca-policy-gaps' `
                    -CheckName      $checkName `
                    -Severity       'Medium' `
                    -ObjectType     'Policy' `
                    -AffectedObject $name `
                    -Title          "CA policy in report-only mode: $name" `
                    -Description    "The Conditional Access policy '$name' is in report-only mode. It logs what it would enforce but is not blocking or requiring anything." `
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
