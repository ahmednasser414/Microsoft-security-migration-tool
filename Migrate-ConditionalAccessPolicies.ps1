<#
.SYNOPSIS
    GBG Tool for Migration - Microsoft Entra and Intune Security Policy Migration.

.DESCRIPTION
    Starts a local browser application for Conditional Access, Defender XDR custom detection rules,
    Intune Endpoint Security Antivirus policies, and Intune Endpoint Security ASR policies.
    Uses delegated Microsoft Graph browser sign-in; no custom app registration or secrets are used.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$GraphRoot = 'https://graph.microsoft.com/v1.0'
$GraphBetaRoot = 'https://graph.microsoft.com/beta'

# The unified setup requests every delegated permission needed by the four workloads.
$SourceGraphScopes = @(
    'Policy.Read.All', 'Directory.Read.All', 'Application.Read.All',
    'DeviceManagementConfiguration.Read.All', 'DeviceManagementEndpointSecurity.Read.All',
    'CustomDetection.Read.All'
)
$TargetGraphScopes = @(
    'Policy.ReadWrite.ConditionalAccess', 'Directory.Read.All', 'Application.Read.All',
    'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementEndpointSecurity.ReadWrite.All',
    'CustomDetection.ReadWrite.All'
)

function Get-ObjectProperty {
    param([AllowNull()] $Object, [Parameter(Mandatory)] [string] $Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    $property.Value
}

function Get-GraphErrorDetail {
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord)
    $details = Get-ObjectProperty -Object $ErrorRecord -Name 'ErrorDetails'
    $message = Get-ObjectProperty -Object $details -Name 'Message'
    if (-not [string]::IsNullOrWhiteSpace([string] $message)) {
        try {
            $serviceError = [string] $message | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace([string] $serviceError.Message)) { return [string] $serviceError.Message }
        } catch {}
        $jsonMatch = [regex]::Match([string] $message, '(?s)\{"error":.*\}\s*$')
        if ($jsonMatch.Success) {
            try {
                $graphError = $jsonMatch.Value | ConvertFrom-Json
                if (-not [string]::IsNullOrWhiteSpace([string] $graphError.error.message)) { return [string] $graphError.error.message }
            } catch {}
        }
        return [string] $message
    }
    $ErrorRecord.Exception.Message
}

function Copy-GraphObject {
    param($Object, [string[]] $Remove = @('id', 'createdDateTime', 'lastModifiedDateTime', 'modifiedDateTime'))
    $copy = $Object | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    foreach ($property in $Remove) { $copy.PSObject.Properties.Remove($property) }
    $copy
}

function New-ObjectIndex {
    param([object[]] $Items, [string] $Property, [string] $Description)
    $index = @{}
    foreach ($item in $Items) {
        $key = [string] (Get-ObjectProperty -Object $item -Name $Property)
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        if ($index.ContainsKey($key)) { throw "More than one $Description has the value '$key'." }
        $index[$key] = $item
    }
    $index
}

function Connect-UnifiedGraph {
    param(
        [Parameter(Mandatory)] [string[]] $Scopes,
        [Parameter(Mandatory)] [string] $Label,
        [switch] $RememberSession,
        [switch] $FreshSignIn
    )
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Microsoft.Graph.Authentication is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Authentication
    $currentContext = Get-MgContext
    if ($FreshSignIn -or $null -ne $currentContext) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
    Write-Host "Browser sign-in: $Label tenant."
    $contextScope = if ($RememberSession) { 'CurrentUser' } else { 'Process' }
    Connect-MgGraph -Scopes $Scopes -ContextScope $contextScope -NoWelcome
    $context = Get-MgContext
    if ($null -eq $context -or [string]::IsNullOrWhiteSpace($context.TenantId)) { throw "$Label sign-in did not return a tenant ID." }
    $missing = @($Scopes | Where-Object { $_ -notin @($context.Scopes) })
    if ($missing.Count -gt 0) {
        throw "$Label sign-in did not receive required delegated permissions: $($missing -join ', '). Sign in with an administrator who can grant consent."
    }
    [pscustomobject]@{
        TenantId = $context.TenantId
        Account = $context.Account
        Scopes = @($context.Scopes)
        Permissions = @($Scopes | ForEach-Object { [pscustomobject]@{ Name = $_; Granted = $true } })
        SessionMode = if ($RememberSession) { 'Remembered securely by Microsoft Graph' } else { 'Temporary process session' }
    }
}

function Invoke-Graph {
    param([ValidateSet('GET', 'POST')] [string] $Method, [string] $Path, $Body, [switch] $Beta)
    $base = if ($Beta) { $GraphBetaRoot } else { $GraphRoot }
    $parameters = @{ Method = $Method; Uri = "$base$Path"; OutputType = 'PSObject' }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 100
    }
    Invoke-MgGraphRequest @parameters
}

function Get-GraphCollection {
    param([string] $Path, [switch] $Beta)
    $items = @(); $response = Invoke-Graph -Method GET -Path $Path -Beta:$Beta
    while ($null -ne $response) {
        $items += @($response.value)
        $next = Get-ObjectProperty -Object $response -Name '@odata.nextLink'
        $response = if ([string]::IsNullOrWhiteSpace([string] $next)) { $null } else { Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject }
    }
    $items
}

function New-Result {
    param([string] $Policy, [string] $Status, [string] $Reason)
    [pscustomobject]@{ Policy = $Policy; Status = $Status; Reason = $Reason }
}

function Get-DefaultVerifiedDomain {
    $organization = @(Get-GraphCollection -Path '/organization?%24select=verifiedDomains')[0]
    $domain = @(Get-ObjectProperty -Object $organization -Name 'verifiedDomains' | Where-Object { $_.isDefault })[0].name
    if ([string]::IsNullOrWhiteSpace($domain)) { throw 'The destination tenant has no default verified domain.' }
    $domain
}

function Get-ConditionalAccessData {
    $locations = @(Get-GraphCollection -Path '/identity/conditionalAccess/namedLocations')
    $contexts = @(Get-GraphCollection -Path '/identity/conditionalAccess/authenticationContextClassReferences')
    $applications = @(Get-GraphCollection -Path '/servicePrincipals?%24select=id,appId,displayName')
    $applicationsById = @{}
    foreach ($application in $applications) {
        foreach ($key in @($application.id, $application.appId)) {
            if (-not [string]::IsNullOrWhiteSpace([string] $key)) { $applicationsById[[string] $key] = $application }
        }
    }
    [pscustomobject]@{
        Policies = @(Get-GraphCollection -Path '/identity/conditionalAccess/policies')
        Locations = $locations
        LocationsById = New-ObjectIndex -Items $locations -Property 'id' -Description 'source named location'
        Contexts = $contexts
        ContextsById = New-ObjectIndex -Items $contexts -Property 'id' -Description 'source authentication context'
        Applications = $applications
        ApplicationsById = $applicationsById
        UsersById = New-ObjectIndex -Items @(Get-GraphCollection -Path '/users?%24select=id,userPrincipalName') -Property 'id' -Description 'source user'
        GroupsById = New-ObjectIndex -Items @(Get-GraphCollection -Path '/groups?%24select=id,displayName') -Property 'id' -Description 'source group'
    }
}

function Get-ConditionalAccessDependencies {
    param($Policy, $SourceData)
    $dependencies = @()
    $conditions = Get-ObjectProperty -Object $Policy -Name 'conditions'
    $users = Get-ObjectProperty -Object $conditions -Name 'users'
    foreach ($definition in @(
        @{ Property = 'includeUsers'; Type = 'User'; Assignment = 'Include'; Index = 'UsersById'; Name = 'userPrincipalName' },
        @{ Property = 'excludeUsers'; Type = 'User'; Assignment = 'Exclude'; Index = 'UsersById'; Name = 'userPrincipalName' },
        @{ Property = 'includeGroups'; Type = 'Group'; Assignment = 'Include'; Index = 'GroupsById'; Name = 'displayName' },
        @{ Property = 'excludeGroups'; Type = 'Group'; Assignment = 'Exclude'; Index = 'GroupsById'; Name = 'displayName' }
    )) {
        foreach ($id in @(Get-ObjectProperty -Object $users -Name $definition.Property)) {
            if ([string]::IsNullOrWhiteSpace([string] $id)) { continue }
            $index = Get-ObjectProperty -Object $SourceData -Name $definition.Index
            $item = if ($index.ContainsKey([string] $id)) { $index[[string] $id] } else { $null }
            $resolvedName = if ($null -ne $item) { [string] (Get-ObjectProperty -Object $item -Name $definition.Name) } else { [string] $id }
            $dependencies += [pscustomobject]@{ Type = $definition.Type; Assignment = $definition.Assignment; Name = $resolvedName; Id = [string] $id }
        }
    }
    foreach ($definition in @(
        @{ Property = 'includeRoles'; Assignment = 'Include' },
        @{ Property = 'excludeRoles'; Assignment = 'Exclude' }
    )) {
        foreach ($id in @(Get-ObjectProperty -Object $users -Name $definition.Property)) {
            if (-not [string]::IsNullOrWhiteSpace([string] $id)) { $dependencies += [pscustomobject]@{ Type = 'Directory role'; Assignment = $definition.Assignment; Name = [string] $id; Id = [string] $id } }
        }
    }
    $applications = Get-ObjectProperty -Object $conditions -Name 'applications'
    foreach ($definition in @(
        @{ Property = 'includeApplications'; Type = 'Application'; Assignment = 'Include'; Index = 'ApplicationsById'; Name = 'displayName' },
        @{ Property = 'excludeApplications'; Type = 'Application'; Assignment = 'Exclude'; Index = 'ApplicationsById'; Name = 'displayName' },
        @{ Property = 'includeAuthenticationContextClassReferences'; Type = 'Authentication context'; Assignment = 'Include'; Index = 'ContextsById'; Name = 'displayName' },
        @{ Property = 'excludeAuthenticationContextClassReferences'; Type = 'Authentication context'; Assignment = 'Exclude'; Index = 'ContextsById'; Name = 'displayName' }
    )) {
        foreach ($id in @(Get-ObjectProperty -Object $applications -Name $definition.Property)) {
            if ([string]::IsNullOrWhiteSpace([string] $id)) { continue }
            $index = Get-ObjectProperty -Object $SourceData -Name $definition.Index
            $item = if ($index.ContainsKey([string] $id)) { $index[[string] $id] } else { $null }
            $resolvedName = if ($null -ne $item) { [string] (Get-ObjectProperty -Object $item -Name $definition.Name) } else { [string] $id }
            $dependencies += [pscustomobject]@{ Type = $definition.Type; Assignment = $definition.Assignment; Name = $resolvedName; Id = [string] $id }
        }
    }
    foreach ($action in @(Get-ObjectProperty -Object $applications -Name 'includeUserActions')) {
        if (-not [string]::IsNullOrWhiteSpace([string] $action)) { $dependencies += [pscustomobject]@{ Type = 'User action'; Assignment = 'Include'; Name = [string] $action; Id = [string] $action } }
    }
    $clientApplications = Get-ObjectProperty -Object $conditions -Name 'clientApplications'
    foreach ($definition in @(
        @{ Property = 'includeServicePrincipals'; Assignment = 'Include' },
        @{ Property = 'excludeServicePrincipals'; Assignment = 'Exclude' }
    )) {
        foreach ($id in @(Get-ObjectProperty -Object $clientApplications -Name $definition.Property)) {
            if ([string]::IsNullOrWhiteSpace([string] $id)) { continue }
            $item = if ($SourceData.ApplicationsById.ContainsKey([string] $id)) { $SourceData.ApplicationsById[[string] $id] } else { $null }
            $resolvedName = if ($null -ne $item) { [string] $item.displayName } else { [string] $id }
            $dependencies += [pscustomobject]@{ Type = 'Service principal'; Assignment = $definition.Assignment; Name = $resolvedName; Id = [string] $id }
        }
    }
    $locations = Get-ObjectProperty -Object $conditions -Name 'locations'
    foreach ($definition in @(
        @{ Property = 'includeLocations'; Assignment = 'Include' },
        @{ Property = 'excludeLocations'; Assignment = 'Exclude' }
    )) {
        foreach ($id in @(Get-ObjectProperty -Object $locations -Name $definition.Property)) {
            if ([string]::IsNullOrWhiteSpace([string] $id)) { continue }
            $item = if ($SourceData.LocationsById.ContainsKey([string] $id)) { $SourceData.LocationsById[[string] $id] } else { $null }
            $resolvedName = if ($null -ne $item) { [string] $item.displayName } else { [string] $id }
            $dependencies += [pscustomobject]@{ Type = 'Named location'; Assignment = $definition.Assignment; Name = $resolvedName; Id = [string] $id }
        }
    }
    $dependencies
}

function Resolve-ConditionalAccessAssignments {
    param($Policy, $SourceData, [hashtable] $TargetUsersByUpn, [hashtable] $TargetGroupsByName, [hashtable] $TargetLocationsByName)
    $users = Get-ObjectProperty -Object $Policy.conditions -Name 'users'
    foreach ($kind in 'includeUsers', 'excludeUsers') {
        if ($null -eq $users) { break }
        $assignment = $users.PSObject.Properties[$kind]
        if ($null -eq $assignment) { continue }
        $values = @($assignment.Value); $resolved = @()
        foreach ($value in $values) {
            if ([string]::IsNullOrWhiteSpace($value) -or $value -match '^(All|None|GuestsOrExternalUsers)$') { $resolved += $value; continue }
            if (-not $SourceData.UsersById.ContainsKey($value)) { throw "Source user '$value' was not found." }
            $sourceUser = $SourceData.UsersById[$value]
            $upn = "$(($sourceUser.userPrincipalName -split '@')[0])@$(Get-DefaultVerifiedDomain)"
            if (-not $TargetUsersByUpn.ContainsKey($upn)) { throw "Destination user '$upn' was not found." }
            $resolved += $TargetUsersByUpn[$upn].id
        }
        $assignment.Value = @($resolved)
    }
    foreach ($kind in 'includeGroups', 'excludeGroups') {
        if ($null -eq $users) { break }
        $assignment = $users.PSObject.Properties[$kind]
        if ($null -eq $assignment) { continue }
        $values = @($assignment.Value); $resolved = @()
        foreach ($value in $values) {
            if (-not $SourceData.GroupsById.ContainsKey($value)) { throw "Source group '$value' was not found." }
            $name = $SourceData.GroupsById[$value].displayName
            if (-not $TargetGroupsByName.ContainsKey($name)) { throw "Destination group '$name' was not found or is not unique." }
            $resolved += $TargetGroupsByName[$name].id
        }
        $assignment.Value = @($resolved)
    }
    $sourceLocationsById = New-ObjectIndex -Items $SourceData.Locations -Property 'id' -Description 'source named location'
    $locations = Get-ObjectProperty -Object $Policy.conditions -Name 'locations'
    foreach ($kind in 'includeLocations', 'excludeLocations') {
        if ($null -eq $locations) { break }
        $assignment = $locations.PSObject.Properties[$kind]
        if ($null -eq $assignment) { continue }
        $values = @($assignment.Value); $resolved = @()
        foreach ($value in $values) {
            if ($value -in @('All', 'AllTrusted') -or [string]::IsNullOrWhiteSpace($value)) { $resolved += $value; continue }
            if (-not $sourceLocationsById.ContainsKey($value)) { throw "Named location '$value' was not found in the source." }
            $name = $sourceLocationsById[$value].displayName
            if (-not $TargetLocationsByName.ContainsKey($name)) { throw "Named location '$name' does not exist in the destination. Create it manually, then rerun this policy." }
            $resolved += $TargetLocationsByName[$name].id
        }
        $assignment.Value = @($resolved)
    }
}

function Invoke-ConditionalAccessMigration {
    param($SourceData, [string[]] $Ids, [ValidateSet('ReportOnly', 'Enabled', 'Disabled')] [string] $State, [switch] $IncludeDisabled)
    $targetUsers = New-ObjectIndex -Items @(Get-GraphCollection -Path '/users?%24select=id,userPrincipalName') -Property 'userPrincipalName' -Description 'destination user'
    $targetGroups = New-ObjectIndex -Items @(Get-GraphCollection -Path '/groups?%24select=id,displayName') -Property 'displayName' -Description 'destination group'
    $targetLocations = New-ObjectIndex -Items @(Get-GraphCollection -Path '/identity/conditionalAccess/namedLocations') -Property 'displayName' -Description 'destination named location'
    $existingNames = @(Get-GraphCollection -Path '/identity/conditionalAccess/policies?%24select=displayName' | ForEach-Object { $_.displayName })
    $results = @(); $newState = @{ ReportOnly = 'enabledForReportingButNotEnforced'; Enabled = 'enabled'; Disabled = 'disabled' }[$State]
    foreach ($source in @($SourceData.Policies | Where-Object { $_.id -in $Ids })) {
        if ($source.displayName -in $existingNames) { $results += New-Result $source.displayName 'Skipped' 'A destination policy with the same name already exists.'; continue }
        if (-not $IncludeDisabled -and $source.state -eq 'disabled') { $results += New-Result $source.displayName 'Skipped' 'Source policy is disabled.'; continue }
        try {
            $policy = Copy-GraphObject -Object $source
            Resolve-ConditionalAccessAssignments -Policy $policy -SourceData $SourceData -TargetUsersByUpn $targetUsers -TargetGroupsByName $targetGroups -TargetLocationsByName $targetLocations
            $policy.state = $newState
            $created = Invoke-Graph -Method POST -Path '/identity/conditionalAccess/policies' -Body $policy
            $results += New-Result $created.displayName 'Created' "Created as $newState."
            $existingNames += $created.displayName
        } catch { $results += New-Result $source.displayName 'Not created' $_.Exception.Message }
    }
    $results
}

function Get-DetectionRuleName {
    param($Rule, [switch] $AllowIdFallback)
    foreach ($property in 'displayName', 'name', 'title') {
        $value = Get-ObjectProperty -Object $Rule -Name $property
        if (-not [string]::IsNullOrWhiteSpace([string] $value)) { return [string] $value }
    }
    if ($AllowIdFallback -and $Rule.id) { return "Unnamed rule [$($Rule.id)]" }
    $null
}

function Get-CustomDetectionData {
    # This Graph collection contains Defender XDR custom detection rules only, not Sentinel analytics rules.
    @(Get-GraphCollection -Path '/security/rules/detectionRules' -Beta)
}

function ConvertTo-DetectionPayload {
    param($Rule)
    $name = Get-DetectionRuleName -Rule $Rule
    if ([string]::IsNullOrWhiteSpace($name)) { throw 'Rule has no displayName, name, or title.' }
    $sourceId = [string] (Get-ObjectProperty -Object $Rule -Name 'id')
    if ([string]::IsNullOrWhiteSpace($sourceId)) { $sourceId = $name }
    $id = $sourceId -replace '[^A-Za-z0-9_-]', '-'
    if ($id -notmatch '^[A-Za-z]') { $id = "rule-$id" }
    if ($id.Length -gt 100) { $id = $id.Substring(0, 100) }
    $query = Get-ObjectProperty -Object (Get-ObjectProperty -Object $Rule -Name 'queryCondition') -Name 'queryText'
    if ([string]::IsNullOrWhiteSpace([string] $query)) { throw "Rule '$name' has no query text." }
    $sourceSchedule = Get-ObjectProperty -Object $Rule -Name 'schedule'
    $frequency = [string] (Get-ObjectProperty -Object $sourceSchedule -Name 'frequency')
    if ([string]::IsNullOrWhiteSpace($frequency)) {
        $period = [string] (Get-ObjectProperty -Object $sourceSchedule -Name 'period')
        $frequency = @{ '0' = 'PT0S'; '1H' = 'PT1H'; '3H' = 'PT3H'; '12H' = 'PT12H'; '24H' = 'P1D' }[$period]
    }
    if ([string]::IsNullOrWhiteSpace($frequency)) { throw "Rule '$name' has no supported schedule frequency." }
    $status = [string] (Get-ObjectProperty -Object $Rule -Name 'status')
    if ($status -notin @('enabled', 'disabled')) {
        $status = if ([bool] (Get-ObjectProperty -Object $Rule -Name 'isEnabled')) { 'enabled' } else { 'disabled' }
    }
    $body = [ordered]@{ id = $id; displayName = $name; status = $status; queryCondition = @{ queryText = $query }; schedule = @{ frequency = $frequency } }
    $description = Get-ObjectProperty -Object $Rule -Name 'description'
    if ($null -ne $description) { $body.description = $description }
    $sourceAction = Get-ObjectProperty -Object $Rule -Name 'detectionAction'
    if ($null -ne $sourceAction) {
        $action = Copy-GraphObject -Object $sourceAction -Remove @('@odata.type')
        $alertTemplate = Get-ObjectProperty -Object $action -Name 'alertTemplate'
        if ($null -ne $alertTemplate) {
            $legacyCategory = [string] (Get-ObjectProperty -Object $alertTemplate -Name 'category')
            foreach ($property in 'mitreTechniques', 'impactedAssets') { $alertTemplate.PSObject.Properties.Remove($property) }
            $tacticsProperty = $alertTemplate.PSObject.Properties['tactics']
            if ($null -ne $tacticsProperty) {
                $validTactics = @(); $fallbackCategory = $legacyCategory
                foreach ($tactic in @($tacticsProperty.Value)) {
                    $tacticName = [string] (Get-ObjectProperty -Object $tactic -Name 'tactic')
                    if ([string]::IsNullOrWhiteSpace($fallbackCategory) -and -not [string]::IsNullOrWhiteSpace($tacticName)) { $fallbackCategory = $tacticName }
                    $validTechniques = @(Get-ObjectProperty -Object $tactic -Name 'techniques' | Where-Object { -not [string]::IsNullOrWhiteSpace([string] (Get-ObjectProperty -Object $_ -Name 'technique')) })
                    if ([string]::IsNullOrWhiteSpace($tacticName) -or $validTechniques.Count -eq 0) { continue }
                    $tacticCopy = Copy-GraphObject -Object $tactic -Remove @('@odata.type')
                    $tacticCopy.PSObject.Properties['techniques'].Value = @($validTechniques | ForEach-Object { Copy-GraphObject -Object $_ -Remove @('@odata.type') })
                    $validTactics += $tacticCopy
                }
                if ($validTactics.Count -gt 0) {
                    $tacticsProperty.Value = @($validTactics)
                    $alertTemplate.PSObject.Properties.Remove('category')
                } else {
                    $alertTemplate.PSObject.Properties.Remove('tactics')
                    if ([string]::IsNullOrWhiteSpace($fallbackCategory)) { throw "Rule '$name' has no valid tactics or legacy category." }
                    $categoryProperty = $alertTemplate.PSObject.Properties['category']
                    if ($null -eq $categoryProperty) { $alertTemplate | Add-Member -NotePropertyName 'category' -NotePropertyValue $fallbackCategory } else { $categoryProperty.Value = $fallbackCategory }
                }
            } elseif ([string]::IsNullOrWhiteSpace($legacyCategory)) {
                throw "Rule '$name' has no valid tactics or legacy category."
            }
        }
        $body.detectionAction = $action
    }
    $body
}

function Invoke-CustomDetectionMigration {
    param([object[]] $Rules, [string[]] $Ids)
    $existing = @(Get-CustomDetectionData | ForEach-Object { Get-DetectionRuleName -Rule $_ })
    $results = @()
    foreach ($rule in @($Rules | Where-Object { $_.id -in $Ids })) {
        $name = Get-DetectionRuleName -Rule $rule -AllowIdFallback
        if ([string]::IsNullOrWhiteSpace((Get-DetectionRuleName -Rule $rule))) { $results += New-Result $name 'Not created' 'Rule has no valid name.'; continue }
        if ($name -in $existing) { $results += New-Result $name 'Skipped' 'A destination rule with the same name already exists.'; continue }
        try {
            Invoke-Graph -Method POST -Path '/security/rules/detectionRules' -Beta -Body (ConvertTo-DetectionPayload -Rule $rule) | Out-Null
            $results += New-Result $name 'Created' 'Custom detection rule created.'
            $existing += $name
            Start-Sleep -Seconds 7
        } catch { $results += New-Result $name 'Not created' (Get-GraphErrorDetail $_) }
    }
    $results
}

function Get-IntuneData {
    param([ValidateSet('Antivirus', 'Asr')] [string] $Workload)
    $match = if ($Workload -eq 'Antivirus') { 'antivirus' } else { 'attackSurfaceReduction|asr' }
    $policies = @(Get-GraphCollection -Path '/deviceManagement/configurationPolicies' -Beta | Where-Object { "$($_.templateReference.templateFamily) $($_.templateReference.templateDisplayName)" -match $match })
    foreach ($policy in $policies) {
        $settings = @(Get-GraphCollection -Path "/deviceManagement/configurationPolicies/$($policy.id)/settings" -Beta)
        $assignments = @(Get-GraphCollection -Path "/deviceManagement/configurationPolicies/$($policy.id)/assignments" -Beta)
        $policy | Add-Member -NotePropertyName 'migrationSettings' -NotePropertyValue $settings
        $policy | Add-Member -NotePropertyName 'migrationAssignments' -NotePropertyValue $assignments
    }
    [pscustomobject]@{
        Policies = $policies
        GroupsById = New-ObjectIndex -Items @(Get-GraphCollection -Path '/groups?%24select=id,displayName' -Beta) -Property 'id' -Description 'source group'
    }
}

function Invoke-IntuneMigration {
    param($SourceData, [string[]] $Ids)
    $targetGroups = New-ObjectIndex -Items @(Get-GraphCollection -Path '/groups?%24select=id,displayName' -Beta) -Property 'displayName' -Description 'destination group'
    $existingNames = @(Get-GraphCollection -Path '/deviceManagement/configurationPolicies?%24select=name' -Beta | ForEach-Object { $_.name })
    $results = @()
    foreach ($source in @($SourceData.Policies | Where-Object { $_.id -in $Ids })) {
        if ($source.name -in $existingNames) { $results += New-Result $source.name 'Skipped' 'A destination policy with the same name already exists.'; continue }
        try {
            $template = Copy-GraphObject -Object $source.templateReference -Remove @()
            $templateType = Get-ObjectProperty -Object $template -Name '@odata.type'
            if ($templateType -isnot [string] -or [string]::IsNullOrWhiteSpace($templateType)) { $template.PSObject.Properties.Remove('@odata.type') }
            $settings = @(Get-ObjectProperty -Object $source -Name 'migrationSettings' | ForEach-Object { [ordered]@{ settingInstance = $_.settingInstance } })
            if ($settings.Count -eq 0) { throw 'Source policy has no settings. Intune requires settings in the create request.' }
            $disableAssignment = Get-ObjectProperty -Object $source -Name 'disableEntraGroupPolicyAssignment'
            if ($null -eq $disableAssignment) { $disableAssignment = $false }
            $payload = [ordered]@{
                name = $source.name
                description = $source.description
                platforms = $source.platforms
                technologies = $source.technologies
                roleScopeTagIds = @($source.roleScopeTagIds)
                disableEntraGroupPolicyAssignment = [bool] $disableAssignment
                templateReference = $template
                settings = $settings
            }
            $created = Invoke-Graph -Method POST -Path '/deviceManagement/configurationPolicies' -Beta -Body $payload
            $assignments = @(Get-ObjectProperty -Object $source -Name 'migrationAssignments')
            if ($assignments.Count -gt 0) {
                $mapped = @()
                foreach ($assignment in $assignments) {
                    $target = Copy-GraphObject -Object $assignment.target -Remove @()
                    $sourceGroupId = [string] (Get-ObjectProperty -Object $target -Name 'groupId')
                    if (-not [string]::IsNullOrWhiteSpace($sourceGroupId)) {
                        if (-not $SourceData.GroupsById.ContainsKey($sourceGroupId)) { throw "Source assignment group '$sourceGroupId' was not found." }
                        $name = $SourceData.GroupsById[$sourceGroupId].displayName
                        if (-not $targetGroups.ContainsKey($name)) { throw "Destination assignment group '$name' was not found or is not unique." }
                        $target.groupId = $targetGroups[$name].id
                    }
                    $mapped += @{ target = $target }
                }
                Invoke-Graph -Method POST -Path "/deviceManagement/configurationPolicies/$($created.id)/assign" -Beta -Body @{ assignments = $mapped } | Out-Null
            }
            $results += New-Result $created.name 'Created' 'Policy settings and same-named group assignments were migrated.'
            $existingNames += $created.name
        } catch { $results += New-Result $source.name 'Not created' (Get-GraphErrorDetail $_) }
    }
    $results
}

function Connect-PurviewLabels {
    param([Parameter(Mandatory)] [string] $Account, [switch] $ReadOnly)
    if ([string]::IsNullOrWhiteSpace($Account)) { throw 'The main tenant sign-in did not return an account name for Purview authentication.' }
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw 'ExchangeOnlineManagement is required for sensitivity labels. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }
    Import-Module ExchangeOnlineManagement
    try {
        if (@(Get-ConnectionInformation -ErrorAction SilentlyContinue).Count -gt 0) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop | Out-Null
        }
    } catch {}
    $commands = if ($ReadOnly) { @('Get-Label') } else { @('Get-Label', 'New-Label', 'Set-Label') }
    Write-Host "Purview browser sign-in for $Account."
    $connectParameters = @{ UserPrincipalName = $Account; ShowBanner = $false }
    if ((Get-Command Connect-IPPSSession).Parameters.ContainsKey('DisableWAM')) { $connectParameters.DisableWAM = $true }
    try {
        # Import the complete REST session; filtering CommandName can trigger a module null-reference before RBAC is evaluated.
        Connect-IPPSSession @connectParameters
    } catch {
        throw "Purview browser sign-in failed before permissions could be checked: $($_.Exception.Message)"
    }
    foreach ($command in $commands) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Purview did not expose $command. Assign a supported Information Protection or Compliance role to $Account."
        }
    }
}

function Disconnect-PurviewLabels {
    if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
}

function Get-SensitivityLabelId {
    param($Label)
    foreach ($property in 'Guid', 'ImmutableId', 'Id', 'Identity') {
        $value = [string] (Get-ObjectProperty -Object $Label -Name $property)
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    }
    $null
}

function Get-SensitivityLabelData {
    $labels = @(Get-Label -IncludeDetailedLabelActions -ErrorAction Stop)
    foreach ($label in $labels) {
        $id = Get-SensitivityLabelId $label
        if ([string]::IsNullOrWhiteSpace($id)) { throw "Sensitivity label '$($label.DisplayName)' did not return an identifier." }
        if ($null -eq $label.PSObject.Properties['migrationId']) { $label | Add-Member -NotePropertyName 'migrationId' -NotePropertyValue $id }
    }
    $labels
}

function Convert-SensitivityLabelRights {
    param($Value, [string] $SourceDomain, [string] $TargetDomain)
    if ($null -eq $Value) { return $null }
    $rightsEntries = $null
    if ($Value -is [string]) {
        $text = $Value.Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        if ($text.StartsWith('[') -or $text.StartsWith('{')) {
            try { $rightsEntries = @($text | ConvertFrom-Json -ErrorAction Stop) } catch { throw "Encryption rights contain invalid JSON: $($_.Exception.Message)" }
        }
    } else {
        $rightsEntries = @($Value)
    }
    if ($null -ne $rightsEntries) {
        $formatted = @()
        foreach ($entry in $rightsEntries) {
            $identity = [string] (Get-ObjectProperty -Object $entry -Name 'Identity')
            $rightsValue = Get-ObjectProperty -Object $entry -Name 'Rights'
            if ([string]::IsNullOrWhiteSpace($identity) -or $null -eq $rightsValue) { throw 'Each encryption rights entry must contain Identity and Rights.' }
            if (-not [string]::IsNullOrWhiteSpace($SourceDomain) -and -not [string]::IsNullOrWhiteSpace($TargetDomain)) {
                if ($identity -ieq $SourceDomain) { $identity = $TargetDomain }
                elseif ($identity -imatch "@$([regex]::Escape($SourceDomain))$") { $identity = $identity -replace "(?i)@$([regex]::Escape($SourceDomain))$", "@$TargetDomain" }
            }
            $rights = if ($rightsValue -is [string]) {
                $rightsText = $rightsValue.Trim()
                if ($rightsText.StartsWith('[')) { @($rightsText | ConvertFrom-Json -ErrorAction Stop) -join ',' } else { $rightsText }
            } else { @($rightsValue) -join ',' }
            if ([string]::IsNullOrWhiteSpace($rights)) { throw "Encryption rights for '$identity' are empty." }
            $formatted += "$identity`:$rights"
        }
        return $formatted -join ';'
    }
    if (-not [string]::IsNullOrWhiteSpace($SourceDomain) -and -not [string]::IsNullOrWhiteSpace($TargetDomain)) {
        $text = $text -replace "(?i)@$([regex]::Escape($SourceDomain))(?=[:;,]|$)", "@$TargetDomain"
        $pattern = "(?i)(^|;)$([regex]::Escape($SourceDomain))(?=:)"
        $text = [regex]::Replace($text, $pattern, { param($match) "$($match.Groups[1].Value)$TargetDomain" })
    }
    $text
}

function New-SensitivityLabelFromSource {
    param($Source, [string] $ParentId, [string] $SourceDomain, [string] $TargetDomain)
    $name = [string] (Get-ObjectProperty -Object $Source -Name 'Name')
    $displayName = [string] (Get-ObjectProperty -Object $Source -Name 'DisplayName')
    $tooltip = [string] (Get-ObjectProperty -Object $Source -Name 'Tooltip')
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $displayName }
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $name }
    if ([string]::IsNullOrWhiteSpace($tooltip)) { $tooltip = $displayName }
    $parameters = @{ Name = $name; DisplayName = $displayName; Tooltip = $tooltip }
    $copyProperties = @(
        'ContentType', 'Comment', 'LocaleSettings', 'Conditions',
        'ApplyContentMarkingFooterAlignment', 'ApplyContentMarkingFooterEnabled', 'ApplyContentMarkingFooterFontColor', 'ApplyContentMarkingFooterFontName', 'ApplyContentMarkingFooterFontSize', 'ApplyContentMarkingFooterMargin', 'ApplyContentMarkingFooterText',
        'ApplyContentMarkingHeaderAlignment', 'ApplyContentMarkingHeaderEnabled', 'ApplyContentMarkingHeaderFontColor', 'ApplyContentMarkingHeaderFontName', 'ApplyContentMarkingHeaderFontSize', 'ApplyContentMarkingHeaderMargin', 'ApplyContentMarkingHeaderText',
        'ApplyDynamicWatermarkingEnabled', 'DynamicWatermarkDisplay', 'ApplyWaterMarkingEnabled', 'ApplyWaterMarkingFontColor', 'ApplyWaterMarkingFontName', 'ApplyWaterMarkingFontSize', 'ApplyWaterMarkingLayout', 'ApplyWaterMarkingText',
        'EncryptionEnabled', 'EncryptionContentExpiredOnDateInDaysOrNever', 'EncryptionDoNotForward', 'EncryptionEncryptOnly', 'EncryptionOfflineAccessDays', 'EncryptionPromptUser', 'EncryptionProtectionType',
        'SiteAndGroupProtectionAllowAccessToGuestUsers', 'SiteAndGroupProtectionAllowEmailFromGuestUsers', 'SiteAndGroupProtectionAllowFullAccess', 'SiteAndGroupProtectionAllowLimitedAccess', 'SiteAndGroupProtectionBlockAccess', 'SiteAndGroupProtectionEnabled', 'SiteAndGroupProtectionLevel', 'SiteAndGroupProtectionPrivacy', 'SiteExternalSharingControlType',
        'TeamsAllowedPresenters', 'TeamsAllowMeetingChat', 'TeamsAllowPrivateTeamsToBeDiscoverableUsingSearch', 'TeamsBypassLobbyForDialInUsers', 'TeamsChannelProtectionEnabled', 'TeamsChannelSharedWithExternalTenants', 'TeamsChannelSharedWithPrivateTeamsOnly', 'TeamsChannelSharedWithSameLabelOnly', 'TeamsCopyRestrictionEnforced', 'TeamsDisableLobby', 'TeamsEndToEndEncryptionEnabled', 'TeamsLobbyBypassScope', 'TeamsLobbyRestrictionEnforced', 'TeamsPresentersRestrictionEnforced', 'TeamsProtectionEnabled', 'TeamsRecordAutomatically', 'TeamsVideoWatermark', 'TeamsWhoCanRecord'
    )
    foreach ($propertyName in $copyProperties) {
        $property = $Source.PSObject.Properties[$propertyName]
        if ($null -ne $property -and $null -ne $property.Value -and -not [string]::IsNullOrWhiteSpace([string] $property.Value) -and (Get-Command New-Label).Parameters.ContainsKey($propertyName)) {
            $parameters[$propertyName] = $property.Value
        }
    }
    $rights = Convert-SensitivityLabelRights -Value (Get-ObjectProperty -Object $Source -Name 'EncryptionRightsDefinitions') -SourceDomain $SourceDomain -TargetDomain $TargetDomain
    if (-not [string]::IsNullOrWhiteSpace([string] $rights)) { $parameters.EncryptionRightsDefinitions = $rights }
    if (-not [string]::IsNullOrWhiteSpace($ParentId)) { $parameters.ParentId = $ParentId }
    $protectionType = [string] (Get-ObjectProperty -Object $Source -Name 'EncryptionProtectionType')
    $encryptionEnabled = [bool] (Get-ObjectProperty -Object $Source -Name 'EncryptionEnabled')
    if ($encryptionEnabled -and $protectionType -eq 'Template' -and [string]::IsNullOrWhiteSpace([string] $rights) -and -not [bool] (Get-ObjectProperty -Object $Source -Name 'EncryptionDoNotForward') -and -not [bool] (Get-ObjectProperty -Object $Source -Name 'EncryptionEncryptOnly')) {
        throw "Label '$displayName' uses a tenant encryption template without portable rights. Map it to an existing destination label instead."
    }
    New-Label @parameters -ErrorAction Stop
}

function Invoke-SensitivityLabelMigration {
    param([object[]] $SourceLabels, [object[]] $TargetLabels, [string[]] $Ids, [ValidateSet('Map', 'Recreate')] [string] $Mode, $Mappings, [string] $SourceDomain, [string] $TargetDomain)
    $results = @(); $targetById = @{}; $targetByName = @{}; $idMap = @{}
    foreach ($target in $TargetLabels) {
        $targetId = Get-SensitivityLabelId $target
        if (-not [string]::IsNullOrWhiteSpace($targetId)) { $targetById[$targetId] = $target }
        $targetName = [string] (Get-ObjectProperty -Object $target -Name 'DisplayName')
        if (-not [string]::IsNullOrWhiteSpace($targetName) -and -not $targetByName.ContainsKey($targetName)) { $targetByName[$targetName] = $target }
    }
    $selected = @($SourceLabels | Where-Object { (Get-SensitivityLabelId $_) -in $Ids })
    if ($Mode -eq 'Map') {
        foreach ($source in $selected) {
            $sourceId = Get-SensitivityLabelId $source; $targetId = [string] (Get-ObjectProperty -Object $Mappings -Name $sourceId)
            if (-not $targetById.ContainsKey($targetId)) { $results += New-Result $source.DisplayName 'Not mapped' 'Choose a valid destination label.'; continue }
            $target = $targetById[$targetId]; $results += New-Result $source.DisplayName 'Mapped' "Mapped to destination label '$($target.DisplayName)' [$targetId]."
        }
        return $results
    }
    foreach ($source in $SourceLabels) {
        $sourceId = Get-SensitivityLabelId $source; $name = [string] $source.DisplayName
        if ($targetByName.ContainsKey($name)) { $idMap[$sourceId] = Get-SensitivityLabelId $targetByName[$name] }
    }
    $pending = [System.Collections.ArrayList]::new(); @($selected) | ForEach-Object { [void] $pending.Add($_) }
    while ($pending.Count -gt 0) {
        $progress = $false
        foreach ($source in @($pending)) {
            $sourceId = Get-SensitivityLabelId $source; $name = [string] $source.DisplayName
            if ($idMap.ContainsKey($sourceId)) { $results += New-Result $name 'Skipped' 'A destination label with the same display name already exists and was mapped.'; [void] $pending.Remove($source); $progress = $true; continue }
            $sourceParentId = [string] (Get-ObjectProperty -Object $source -Name 'ParentId')
            if (-not [string]::IsNullOrWhiteSpace($sourceParentId) -and -not $idMap.ContainsKey($sourceParentId)) { continue }
            try {
                $parentId = if ([string]::IsNullOrWhiteSpace($sourceParentId)) { $null } else { [string] $idMap[$sourceParentId] }
                $created = New-SensitivityLabelFromSource -Source $source -ParentId $parentId -SourceDomain $SourceDomain -TargetDomain $TargetDomain
                $createdId = Get-SensitivityLabelId $created
                if ([string]::IsNullOrWhiteSpace($createdId)) { $created = Get-Label -Identity $created.Identity -ErrorAction Stop; $createdId = Get-SensitivityLabelId $created }
                $idMap[$sourceId] = $createdId; $results += New-Result $name 'Created' "Sensitivity label recreated with destination ID $createdId."
            } catch { $results += New-Result $name 'Not created' $_.Exception.Message }
            [void] $pending.Remove($source); $progress = $true
        }
        if (-not $progress) {
            foreach ($source in @($pending)) { $results += New-Result $source.DisplayName 'Not created' 'Its parent label was not selected, mapped, or found by name in the destination.'; [void] $pending.Remove($source) }
        }
    }
    $results
}

function Get-WorkloadItems {
    param([string] $Workload, $Data)
    if ($Workload -eq 'SensitivityLabels') {
        return @($Data | ForEach-Object {
            $encryption = if ([bool] (Get-ObjectProperty -Object $_ -Name 'EncryptionEnabled')) { 'Encryption enabled' } else { 'No encryption' }
            [pscustomobject]@{ id = Get-SensitivityLabelId $_; displayName = $_.DisplayName; state = "$($_.ContentType) | $encryption"; dependencies = '' }
        })
    }
    if ($Workload -eq 'CustomDetection') {
        return @($Data | ForEach-Object {
            $status = [string] (Get-ObjectProperty -Object $_ -Name 'status')
            if ([string]::IsNullOrWhiteSpace($status)) { $status = if ([bool] (Get-ObjectProperty -Object $_ -Name 'isEnabled')) { 'Enabled' } else { 'Disabled' } }
            [pscustomobject]@{ id = $_.id; displayName = Get-DetectionRuleName -Rule $_ -AllowIdFallback; state = $status }
        })
    }
    @($Data.Policies | ForEach-Object {
        $dependencies = if ($Workload -eq 'ConditionalAccess') { @(Get-ConditionalAccessDependencies -Policy $_ -SourceData $Data) } else { @() }
        $dependencySummary = @($dependencies | ForEach-Object { "$($_.Type) ($($_.Assignment)): $($_.Name)" }) -join '; '
        [pscustomobject]@{
            id = $_.id
            displayName = if ($Workload -eq 'ConditionalAccess') { $_.displayName } else { $_.name }
            state = if ($Workload -eq 'ConditionalAccess') { $_.state } else { $_.templateReference.templateDisplayName }
            dependencies = $dependencySummary
        }
    })
}

function Get-WorkloadItemDetail {
    param([string] $Workload, $Data, [string] $Id)
    $source = if ($Workload -eq 'CustomDetection') { @($Data | Where-Object { $_.id -eq $Id })[0] } elseif ($Workload -eq 'SensitivityLabels') { @($Data | Where-Object { (Get-SensitivityLabelId $_) -eq $Id })[0] } else { @($Data.Policies | Where-Object { $_.id -eq $Id })[0] }
    if ($null -eq $source) { throw "The selected $Workload source item was not found." }
    switch ($Workload) {
        'ConditionalAccess' {
            [pscustomobject]@{ Policy = $source; Dependencies = @(Get-ConditionalAccessDependencies -Policy $source -SourceData $Data) }
        }
        'CustomDetection' { [pscustomobject]@{ Rule = $source } }
        'SensitivityLabels' { [pscustomobject]@{ SensitivityLabel = $source } }
        default {
            $policy = $source | ConvertTo-Json -Depth 100 | ConvertFrom-Json
            $policy.PSObject.Properties.Remove('migrationSettings')
            $policy.PSObject.Properties.Remove('migrationAssignments')
            [pscustomobject]@{
                Policy = $policy
                Settings = @(Get-ObjectProperty -Object $source -Name 'migrationSettings')
                Assignments = @(Get-ObjectProperty -Object $source -Name 'migrationAssignments')
            }
        }
    }
}

function Send-Response {
    param([System.Net.HttpListenerResponse] $Response, [string] $Body, [int] $StatusCode = 200, [string] $ContentType = 'application/json; charset=utf-8')
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $Response.StatusCode = $StatusCode; $Response.ContentType = $ContentType; $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length); $Response.Close()
}

function Read-JsonRequest {
    param([System.Net.HttpListenerRequest] $Request)
    $reader = [System.IO.StreamReader]::new($Request.InputStream, $Request.ContentEncoding)
    try { $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
}

function Start-GbgMigrationWebApp {
    $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $probe.Start(); $port = ([System.Net.IPEndPoint] $probe.LocalEndpoint).Port; $probe.Stop()
    $url = "http://127.0.0.1:$port/"; $listener = [System.Net.HttpListener]::new(); $listener.Prefixes.Add($url); $listener.Start()
    $state = @{ Source = $null; Destination = $null; SourceData = @{}; DestinationLabels = @(); LoadErrors = @{}; Workload = $null; RememberSession = $false; FreshSignIn = $false; SourceDomain = $null; TargetDomain = $null; PurviewConnected = $false }
    $html = @'
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GBG Tool for Migration</title><style>
:root{--r:#a50000;--i:#101014;--p:#1d1d22;--l:#3a3a42;--m:#cfcfd4}*{box-sizing:border-box}body{margin:0;background:var(--i);color:#f8f8fa;font-family:Segoe UI,Arial}.head{background:#850000;padding:17px max(26px,calc((100vw - 1380px)/2));display:flex;gap:42px;align-items:center}.brand{display:flex;gap:15px;align-items:center;min-width:265px}.gbg{font-size:48px;font-weight:800;letter-spacing:-3px}.words{font-size:20px;font-weight:800;line-height:19px}.head h1{margin:0;font-size:29px}.head p{margin:5px 0 0;color:#f8d6d6}.app{max-width:1420px;margin:auto;padding:28px 32px}.card{background:var(--p);border:1px solid var(--l);border-radius:7px;padding:20px}.note{color:#e1e1e5;line-height:1.45}.setup,.choices{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.choices{grid-template-columns:repeat(4,1fr);margin:24px 0}.choice{min-height:130px;text-align:left;background:var(--p);border:1px solid var(--l);color:white;padding:17px}.choice strong{display:block;color:#f45067;font-size:17px;margin-bottom:8px}.choice:hover,.choice.active{border-color:#f45067;background:#2a1518}.choice:disabled{opacity:.45;cursor:not-allowed}.label{display:block;color:#f45067;font-size:14px;font-weight:800;margin-bottom:12px}.tenant{display:block;color:var(--m);font-size:13px;margin-top:12px;min-height:36px;word-break:break-word}button{background:var(--r);border:1px solid var(--r);color:#fff;font-weight:800;padding:9px 14px;min-height:38px;cursor:pointer}button:disabled{background:#790000;border-color:#790000;color:#f3c3c3;cursor:not-allowed}.wide{width:100%}.hidden{display:none}.panel{display:grid;grid-template-columns:1fr 1fr 235px;gap:20px}.field{font-size:12px;color:var(--m);display:block;margin-bottom:7px}select{width:100%;height:38px;background:#fff;border:1px solid var(--r);color:var(--r);font-weight:700;padding:0 8px}.check{display:flex;gap:8px;align-items:center;margin:13px 0}.check input{accent-color:var(--r)}.bar{display:flex;justify-content:space-between;align-items:center;margin-top:25px}.actions{display:flex;gap:9px}table{width:100%;border-collapse:collapse;background:#1a1a1f;border:1px solid var(--l)}thead{background:white;color:var(--r);text-align:left}th,td{padding:8px 9px;font-size:14px}td{border-top:1px solid #303036}tr:nth-child(even){background:#222228}.empty{text-align:center;color:#aaaab2}.msg{color:#f3bcc4;margin-top:14px;min-height:21px}.footer{position:sticky;bottom:0;background:#1a1a1f;border-top:1px solid #303036;color:var(--m);padding:12px 32px;font-size:13px}@media(max-width:850px){.head{padding:15px 18px;gap:15px}.words{display:none}.brand{min-width:auto}.app{padding:21px 15px}.setup,.choices,.panel{grid-template-columns:1fr}.footer{padding:12px 15px}}
</style></head><body><header class="head"><div class="brand"><div class="gbg">gbg</div><div class="words">GLOBAL<br>BRANDS<br><span style="font-size:15px">GROUP</span></div></div><div><h1>GBG Tool for Migration</h1><p>Microsoft Entra and Intune Security Policy Migration</p></div></header><main class="app"><section class="card"><span class="label">ONE-TIME TENANT SETUP</span><p class="note">Connect each tenant once. Setup requests and verifies all delegated permissions needed for Conditional Access, Custom Detection Rules, Antivirus, and ASR. Microsoft only displays a consent page when consent is not already granted.</p><div class="setup"><div><button id="sourceSetup" class="wide">CONNECT SOURCE TENANT</button><span id="sourceInfo" class="tenant">Not connected</span></div><div><button id="targetSetup" class="wide" disabled>CONNECT DESTINATION TENANT</button><span id="targetInfo" class="tenant">Connect source first</span></div><div><span class="field">SETUP STATUS</span><span id="setupStatus" class="tenant">Waiting for source connection</span></div></div></section><section class="choices"><button class="choice" data-workload="ConditionalAccess" disabled><strong>Conditional Access</strong>Selected Entra Conditional Access policies.</button><button class="choice" data-workload="CustomDetection" disabled><strong>Custom Detection Rules</strong>Custom detection rules only. Sentinel analytics rules excluded.</button><button class="choice" data-workload="Antivirus" disabled><strong>Antivirus Settings</strong>Selected Intune AV policies and same-named group assignments.</button><button class="choice" data-workload="Asr" disabled><strong>ASR Rules</strong>Selected Intune ASR policies and same-named group assignments.</button></section><section id="workspace" class="hidden"><div class="card"><div class="panel"><div><span class="label">SOURCE TENANT</span><span id="workSource" class="tenant"></span></div><div><span class="label">DESTINATION TENANT</span><span id="workTarget" class="tenant"></span></div><div><span id="stateLabel" class="field">POLICY STATE</span><select id="policyState"><option>ReportOnly</option><option>Enabled</option><option>Disabled</option></select><label id="disabledLabel" class="check"><input id="includeDisabled" type="checkbox">Include disabled policies</label><button id="migrate" class="wide" disabled>MIGRATE SELECTED</button></div></div><div id="message" class="msg"></div></div><div class="bar"><strong id="itemTitle">POLICIES TO MIGRATE</strong><div class="actions"><button id="all">SELECT ALL</button><button id="none">CLEAR ALL</button></div></div><table><thead><tr><th style="width:90px">MIGRATE</th><th>POLICY / RULE</th><th>TYPE / SOURCE STATE</th></tr></thead><tbody id="items"><tr><td colspan="3" class="empty">Choose a workload.</td></tr></tbody></table><div class="bar"><strong>MIGRATION RESULTS</strong></div><table><thead><tr><th>POLICY / RULE</th><th>STATUS</th><th>REASON</th></tr></thead><tbody id="results"><tr><td colspan="3" class="empty">No migration has been run.</td></tr></tbody></table></section></main><footer id="status" class="footer">Complete one-time tenant setup.</footer><script>
const $=id=>document.getElementById(id),api=(p,b)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(async r=>{let x=await r.json();if(!r.ok)throw Error(x.error||'Request failed');return x});let items=[],workload=null,ready=false,unavailable={};function text(x){$('status').textContent=x;$('message').textContent=x}function esc(x){return String(x??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}function render(){ $('items').innerHTML=items.length?items.map((x,i)=>`<tr><td><input type="checkbox" data-i="${i}" ${x.selected?'checked':''}></td><td>${esc(x.displayName)}</td><td>${esc(x.state)}</td></tr>`).join(''):'<tr><td colspan="3" class="empty">No matching source items were found.</td></tr>';document.querySelectorAll('[data-i]').forEach(x=>x.onchange=()=>items[+x.dataset.i].selected=x.checked)}function show(a){$('results').innerHTML=a.length?a.map(x=>`<tr><td>${esc(x.Policy)}</td><td>${esc(x.Status)}</td><td>${esc(x.Reason)}</td></tr>`).join(''):'<tr><td colspan="3" class="empty">No selected items.</td></tr>'}$('sourceSetup').onclick=async()=>{let b=$('sourceSetup');b.disabled=true;b.textContent='CONNECTING...';try{ $('setupStatus').textContent='Complete source consent. Loading all source workloads.';let x=await api('/api/setup/source');unavailable=x.unavailable||{};$('sourceInfo').textContent=`Tenant: ${x.tenantId} | Account: ${x.account}`;$('targetSetup').disabled=false;$('setupStatus').textContent='Source connected. Connect destination.';b.textContent='SOURCE CONNECTED'}catch(e){$('setupStatus').textContent=e.message;b.textContent='CONNECT SOURCE TENANT'}finally{b.disabled=false}};$('targetSetup').onclick=async()=>{let b=$('targetSetup');b.disabled=true;b.textContent='CONNECTING...';try{let x=await api('/api/setup/destination');$('targetInfo').textContent=`Tenant: ${x.tenantId} | Account: ${x.account}`;ready=true;document.querySelectorAll('[data-workload]').forEach(c=>{c.disabled=Boolean(unavailable[c.dataset.workload]);if(c.disabled)c.title=unavailable[c.dataset.workload]});$('setupStatus').textContent='All requested permissions verified. Choose a workload.';b.textContent='DESTINATION CONNECTED'}catch(e){$('setupStatus').textContent=e.message;b.textContent='CONNECT DESTINATION TENANT'}finally{b.disabled=false}};document.querySelectorAll('[data-workload]').forEach(c=>c.onclick=async()=>{if(!ready)return;workload=c.dataset.workload;document.querySelectorAll('[data-workload]').forEach(x=>x.classList.remove('active'));c.classList.add('active');try{let x=await api('/api/workload',{workload});items=x.items.map(x=>({...x,selected:true}));render();$('workspace').classList.remove('hidden');$('itemTitle').textContent=`${c.querySelector('strong').textContent.toUpperCase()} TO MIGRATE`;$('workSource').textContent=x.source;$('workTarget').textContent=x.destination;let ca=workload==='ConditionalAccess';$('stateLabel').classList.toggle('hidden',!ca);$('policyState').classList.toggle('hidden',!ca);$('disabledLabel').classList.toggle('hidden',!ca);$('migrate').disabled=false;text(`${items.length} items loaded. Select what to migrate.`)}catch(e){text(e.message)}});$('all').onclick=()=>{items.forEach(x=>x.selected=true);render()};$('none').onclick=()=>{items.forEach(x=>x.selected=false);render()};$('migrate').onclick=async()=>{let ids=items.filter(x=>x.selected).map(x=>x.id);if(!ids.length){text('Select at least one item.');return}let b=$('migrate');b.disabled=true;b.textContent='MIGRATING...';try{let x=await api('/api/migrate',{ids,state:$('policyState').value,includeDisabled:$('includeDisabled').checked});show(x.results);text(`Finished. Created: ${x.results.filter(x=>x.Status==='Created').length}. Not created: ${x.results.filter(x=>x.Status==='Not created').length}.`)}catch(e){text(e.message)}finally{b.disabled=false;b.textContent='MIGRATE SELECTED'}};
</script><script>
(()=>{const get=id=>document.getElementById(id),header=document.querySelector('.head'),app=document.querySelector('.app'),page=document.createElement('main'),style=document.createElement('style');style.textContent=`
#authPage{min-height:100vh;background:radial-gradient(circle at 85% 10%,#501015 0,transparent 34%),#101014;color:#f8f8fa;padding:48px 24px;font-family:Segoe UI,Arial}.auth-shell{max-width:1120px;margin:auto}.auth-brand{display:flex;align-items:center;gap:18px;margin-bottom:32px}.auth-mark{font-size:46px;font-weight:900;letter-spacing:-3px;color:#f45067}.auth-title h1{font-size:30px;margin:0 0 5px}.auth-title p{margin:0;color:#cfcfd4}.auth-options,.auth-tenants{display:grid;gap:18px}.auth-options{grid-template-columns:1fr 1fr;margin-bottom:18px}.auth-tenants{grid-template-columns:1fr 1fr}.auth-card{background:#1d1d22;border:1px solid #3a3a42;border-radius:8px;padding:22px}.auth-card h2{font-size:18px;margin:0 0 8px}.auth-card p{color:#cfcfd4;line-height:1.45}.auth-option{display:flex;gap:11px;align-items:flex-start}.auth-option input{margin-top:4px;accent-color:#a50000}.auth-option strong,.auth-option span{display:block}.auth-option span{font-size:13px;color:#cfcfd4;margin-top:5px}.auth-button{width:100%;margin-top:12px}.auth-detail{font-size:13px;min-height:38px;color:#cfcfd4;margin-top:12px;word-break:break-word}.permission-list{display:flex;flex-wrap:wrap;gap:7px;margin-top:13px}.permission{border:1px solid #315f45;background:#16271d;color:#9ce8b7;border-radius:20px;padding:5px 9px;font-size:11px}.auth-footer{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-top:18px}.auth-status{color:#cfcfd4}.auth-error{color:#ff8797}.auth-continue{min-width:220px}@media(max-width:760px){#authPage{padding:28px 16px}.auth-options,.auth-tenants{grid-template-columns:1fr}.auth-footer{align-items:stretch;flex-direction:column}.auth-continue{width:100%}}
`;page.id='authPage';page.innerHTML=`<div class="auth-shell"><div class="auth-brand"><div class="auth-mark">gbg</div><div class="auth-title"><h1>Tenant authentication</h1><p>Verify both tenants and every delegated permission before migration.</p></div></div><section class="auth-options"><div class="auth-card"><label class="auth-option"><input id="rememberSession" type="checkbox"><span><strong>Remember Microsoft sign-in securely</strong><span>Uses the Microsoft Graph CurrentUser token cache. This tool never saves your password or raw credentials.</span></span></label></div><div class="auth-card"><label class="auth-option"><input id="freshSignIn" type="checkbox" checked><span><strong>Start with a fresh sign-in</strong><span>Disconnects the active Graph context before each tenant connection. Turn this off to allow a remembered Microsoft session.</span></span></label></div></section><section class="auth-tenants"><article class="auth-card"><h2>1. Source tenant</h2><p>Read access for Conditional Access, AV, ASR, and Custom Detection.</p><button id="authSource" class="auth-button">SIGN IN TO SOURCE</button><div id="authSourceDetail" class="auth-detail">Not connected</div><div id="authSourcePermissions" class="permission-list"></div></article><article class="auth-card"><h2>2. Destination tenant</h2><p>Write access for Conditional Access, AV, ASR, and Custom Detection.</p><button id="authDestination" class="auth-button" disabled>SIGN IN TO DESTINATION</button><div id="authDestinationDetail" class="auth-detail">Connect and verify the source first</div><div id="authDestinationPermissions" class="permission-list"></div></article></section><div class="auth-footer"><div id="authStatus" class="auth-status">Choose a session mode, then connect the source tenant.</div><button id="authContinue" class="auth-continue" disabled>CONTINUE TO MIGRATION</button></div></div>`;document.head.append(style);document.body.prepend(page);header.classList.add('hidden');app.classList.add('hidden');let sourceVerified=false,destinationVerified=false;const options=()=>({rememberSession:get('rememberSession').checked,freshSignIn:get('freshSignIn').checked}),setStatus=(message,error=false)=>{get('authStatus').textContent=message;get('authStatus').classList.toggle('auth-error',error)},showPermissions=(id,permissions)=>{const host=get(id);host.replaceChildren(...(permissions||[]).map(permission=>{const item=document.createElement('span');item.className='permission';item.textContent=`Granted: ${permission.Name}`;return item}))};get('authSource').onclick=async()=>{const button=get('authSource');button.disabled=true;setStatus('Complete source sign-in and administrator consent in the Microsoft window.');try{const result=await api('/api/setup/source',options());sourceVerified=true;unavailable=result.unavailable||{};get('authSourceDetail').textContent=`Verified | Tenant: ${result.tenantId} | ${result.account} | ${result.sessionMode}`;showPermissions('authSourcePermissions',result.permissions);get('sourceInfo').textContent=`Tenant: ${result.tenantId} | Account: ${result.account}`;get('sourceSetup').textContent='SOURCE VERIFIED';get('sourceSetup').disabled=true;get('authDestination').disabled=false;get('rememberSession').disabled=true;get('freshSignIn').disabled=true;button.textContent='SOURCE VERIFIED';setStatus('All source permissions are granted. Connect the destination tenant.')}catch(error){sourceVerified=false;button.disabled=false;setStatus(error.message,true)}};get('authDestination').onclick=async()=>{const button=get('authDestination');button.disabled=true;setStatus('Complete destination sign-in and administrator consent in the Microsoft window.');try{const result=await api('/api/setup/destination',options());destinationVerified=true;ready=true;get('authDestinationDetail').textContent=`Verified | Tenant: ${result.tenantId} | ${result.account} | ${result.sessionMode}`;showPermissions('authDestinationPermissions',result.permissions);get('targetInfo').textContent=`Tenant: ${result.tenantId} | Account: ${result.account}`;get('targetSetup').textContent='DESTINATION VERIFIED';get('targetSetup').disabled=true;document.querySelectorAll('[data-workload]').forEach(choice=>{const error=unavailable[choice.dataset.workload];choice.disabled=!!error;choice.title=error||''});button.textContent='DESTINATION VERIFIED';get('authContinue').disabled=false;setStatus('Authentication complete. All required delegated permissions are verified.')}catch(error){destinationVerified=false;button.disabled=false;setStatus(error.message,true)}};get('authContinue').onclick=()=>{if(!sourceVerified||!destinationVerified)return;page.remove();header.classList.remove('hidden');app.classList.remove('hidden');get('setupStatus').textContent='Both tenants authenticated and all required permissions verified.'};})();
</script><script>
(()=>{const choices=document.querySelector('.choices'),choice=document.createElement('button'),table=$('items').closest('table'),options=document.createElement('section'),style=document.createElement('style');choice.className='choice';choice.dataset.workload='SensitivityLabels';choice.disabled=true;choice.innerHTML='<strong>Sensitivity Labels</strong>Map to existing destination labels or safely recreate selected Purview labels.';choices.append(choice);choices.style.gridTemplateColumns='repeat(5,1fr)';style.textContent='.label-options{border:1px solid #3a3a42;background:#18181d;padding:15px;margin:0 0 14px}.label-options-grid{display:grid;grid-template-columns:240px 1fr;gap:14px;align-items:start}.label-help{color:#cfcfd4;font-size:12px;line-height:1.45}.label-mappings{display:grid;gap:8px;margin-top:12px}.label-map-row{display:grid;grid-template-columns:minmax(180px,1fr) minmax(220px,1fr);gap:10px;align-items:center;color:#eee;font-size:12px}.label-map-row select{height:36px}@media(max-width:1050px){.choices{grid-template-columns:repeat(2,1fr)!important}}@media(max-width:700px){.choices,.label-options-grid,.label-map-row{grid-template-columns:1fr!important}}';document.head.append(style);options.className='label-options hidden';options.innerHTML='<span class="label">SENSITIVITY LABEL ACTION</span><div class="label-options-grid"><select id="labelMode"><option value="Recreate">Recreate selected labels</option><option value="Map">Map to existing labels</option></select><div id="labelModeHelp" class="label-help"></div></div><div id="labelMappings" class="label-mappings"></div>';table.before(options);const mode=options.querySelector('#labelMode'),help=options.querySelector('#labelModeHelp'),mappingHost=options.querySelector('#labelMappings');let targets=[];function explain(){const map=mode.value==='Map';help.textContent=map?'No label is created. Each selected source label is mapped to an existing destination label.':'Creates new labels when their display names do not exist. Source template IDs are never copied; portable encryption rights are recreated and source-tenant domains are changed to the destination domain.';renderMappings()}function renderMappings(){mappingHost.replaceChildren();if(workload!=='SensitivityLabels'||mode.value!=='Map')return;const selected=items.filter(item=>item.selected);if(!selected.length){mappingHost.textContent='Select one or more source labels to configure mappings.';return}selected.forEach(item=>{const row=document.createElement('label'),name=document.createElement('span'),select=document.createElement('select');row.className='label-map-row';name.textContent=item.displayName;select.dataset.sourceLabelId=item.id;select.innerHTML='<option value="">Choose destination label</option>'+targets.map(target=>`<option value="${esc(target.id)}">${esc(target.displayName)} | ${esc(target.name)}</option>`).join('');row.append(name,select);mappingHost.append(row)})}async function loadTargets(){try{const response=await api('/api/label-targets');targets=response.targets||[];renderMappings()}catch(error){targets=[];text(error.message)}}mode.onchange=explain;$('items').addEventListener('change',()=>setTimeout(renderMappings));choice.addEventListener('click',()=>{options.classList.remove('hidden');setTimeout(loadTargets,100)});document.querySelectorAll('[data-workload]:not([data-workload="SensitivityLabels"])').forEach(button=>button.addEventListener('click',()=>options.classList.add('hidden')));const migrate=$('migrate');if(migrate)migrate.addEventListener('click',async event=>{if(workload!=='SensitivityLabels')return;event.preventDefault();event.stopImmediatePropagation();const ids=items.filter(item=>item.selected).map(item=>item.id);if(!ids.length){text('Select at least one sensitivity label.');return}const mappings={};mappingHost.querySelectorAll('[data-source-label-id]').forEach(select=>mappings[select.dataset.sourceLabelId]=select.value);if(mode.value==='Map'&&ids.some(id=>!mappings[id])){text('Choose a destination label for every selected source label.');return}migrate.disabled=true;text(`${mode.value==='Map'?'Mapping':'Recreating'} selected sensitivity labels...`);try{const response=await api('/api/migrate',{ids,labelMode:mode.value,labelMappings:mappings});show(response.results||[]);text('Sensitivity label operation completed.')}catch(error){text(error.message)}finally{migrate.disabled=false}},true);const sourceText=document.querySelector('#authPage .auth-tenants article:first-child p'),targetText=document.querySelector('#authPage .auth-tenants article:last-child p');if(sourceText)sourceText.textContent='Read access for Conditional Access, AV, ASR, Custom Detection, and Purview sensitivity labels.';if(targetText)targetText.textContent='Write access for Conditional Access, AV, ASR, Custom Detection, and Purview sensitivity labels.';explain()})();
</script><script>
(()=>{const choice=document.querySelector('[data-workload="SensitivityLabels"]');choice.onclick=async()=>{if(!ready)return;workload='SensitivityLabels';document.querySelectorAll('[data-workload]').forEach(button=>button.classList.remove('active'));choice.classList.add('active');text('Loading sensitivity labels from the source tenant...');try{const response=await api('/api/workload',{workload});items=(response.items||[]).map(item=>({...item,selected:true}));render();$('workspace').classList.remove('hidden');$('itemTitle').textContent='SENSITIVITY LABELS TO MIGRATE';$('workSource').textContent=response.source;$('workTarget').textContent=response.destination;$('stateLabel').classList.add('hidden');$('policyState').classList.add('hidden');$('disabledLabel').classList.add('hidden');$('migrate').disabled=false;text(`${items.length} items loaded. Select what to migrate.`)}catch(error){text(error.message)}}})();
</script><script>
(()=>{const box=document.createElement('div'),input=document.createElement('input'),empty=document.createElement('div'),table=$('items').closest('table'),labels={ConditionalAccess:'Conditional Access policies',CustomDetection:'Custom Detection rules',Antivirus:'Antivirus policies',Asr:'ASR policies',SensitivityLabels:'Sensitivity labels'};box.className='hidden';box.style.margin='0 0 14px';input.type='search';input.placeholder='Search items';input.setAttribute('aria-label','Search migration items');input.style.cssText='width:100%;height:40px;background:#fff;border:1px solid var(--r);color:#202024;padding:0 12px;font-size:14px';empty.textContent='No items match your search.';empty.className='empty hidden';empty.style.marginTop='12px';box.append(input,empty);table.before(box);function filter(){const active=Boolean(workload);box.classList.toggle('hidden',!active);const term=input.value.trim().toLocaleLowerCase(),rows=[...$('items').querySelectorAll('tr')];let visible=0;rows.forEach(row=>{const name=row.cells[1]?.textContent||'',show=!active||!term||name.toLocaleLowerCase().includes(term);row.classList.toggle('hidden',!show);if(show)visible++});empty.classList.toggle('hidden',!active||!term||visible>0)}input.addEventListener('input',filter);new MutationObserver(filter).observe($('items'),{childList:true});document.querySelectorAll('[data-workload]').forEach(button=>button.addEventListener('click',()=>{input.value='';input.placeholder=`Search ${labels[button.dataset.workload]||'items'}`;input.setAttribute('aria-label',input.placeholder);setTimeout(filter)}));})();
</script><script>
(()=>{
const table=$('items').closest('table'),headerRow=table.tHead?.rows[0],dependencyHeader=document.createElement('th'),hint=document.createElement('div'),modal=document.createElement('div'),style=document.createElement('style');
dependencyHeader.textContent='DEPENDENCIES';dependencyHeader.className='hidden';if(headerRow)headerRow.append(dependencyHeader);
hint.textContent='Double-click any source item to view its complete details.';hint.style.cssText='color:var(--m);font-size:12px;margin:0 0 10px';table.before(hint);
style.textContent='.detail-modal{position:fixed;inset:0;z-index:1000;background:#08080bd9;display:flex;align-items:center;justify-content:center;padding:24px}.detail-modal.hidden{display:none}.detail-dialog{width:min(1100px,96vw);max-height:90vh;background:#1d1d22;border:1px solid #5a5a65;border-radius:8px;display:flex;flex-direction:column}.detail-head{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:16px 18px;border-bottom:1px solid #3a3a42}.detail-head h2{font-size:18px;margin:0}.detail-close{min-width:90px}.detail-content{padding:18px;overflow:auto;background:#111115;color:#eee}.detail-section{border:1px solid #3a3a42;border-radius:6px;background:#1a1a1f;margin-bottom:12px;padding:14px}.detail-section h3{color:#f45067;font-size:14px;margin:0 0 12px}.detail-fields{display:grid;grid-template-columns:minmax(170px,28%) 1fr;gap:1px;background:#34343c;border:1px solid #34343c}.detail-label,.detail-value{padding:8px 10px;background:#202026;word-break:break-word}.detail-label{color:#bdbdc5;font-size:12px;font-weight:700}.detail-value{color:#f5f5f7;font-size:13px}.detail-nested{margin-top:10px;border:1px solid #3a3a42;background:#17171b}.detail-nested summary{cursor:pointer;color:#f0b3bb;font-weight:700;padding:10px}.detail-nested-body{padding:0 10px 10px}.detail-empty{color:#8f8f99;font-style:italic}.dependency-cell{max-width:520px;color:#d7d7dc;font-size:12px;line-height:1.4}.source-detail-row{cursor:pointer}.source-detail-row:hover{background:#29292f}@media(max-width:700px){.detail-fields{grid-template-columns:1fr}.detail-label{padding-bottom:2px}.detail-value{padding-top:2px}}';document.head.append(style);
modal.className='detail-modal hidden';modal.innerHTML='<section class="detail-dialog" role="dialog" aria-modal="true" aria-labelledby="detailTitle"><header class="detail-head"><h2 id="detailTitle">Source item details</h2><button class="detail-close">CLOSE</button></header><div class="detail-content"></div></section>';document.body.append(modal);
const label=name=>String(name).replace(/^@odata\./i,'OData ').replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/[_-]+/g,' ').replace(/^./,character=>character.toUpperCase()),simple=value=>value===null||value===undefined||typeof value!=='object',display=value=>value===null||value===undefined||value===''?'Not set':typeof value==='boolean'?(value?'Yes':'No'):String(value);
function section(value,title,depth=0){const host=document.createElement('section');host.className='detail-section';const heading=document.createElement('h3');heading.textContent=label(title);host.append(heading);if(simple(value)){const text=document.createElement('div');text.className='detail-value';text.textContent=display(value);host.append(text);return host}const entries=Array.isArray(value)?value.map((item,index)=>[`${label(title)} ${index+1}`,item]):Object.entries(value);if(!entries.length){const empty=document.createElement('div');empty.className='detail-empty';empty.textContent='No data';host.append(empty);return host}const fields=document.createElement('div');fields.className='detail-fields';entries.filter(([,item])=>simple(item)).forEach(([name,item])=>{const key=document.createElement('div'),val=document.createElement('div');key.className='detail-label';val.className='detail-value';key.textContent=label(name);val.textContent=display(item);fields.append(key,val)});if(fields.children.length)host.append(fields);entries.filter(([,item])=>!simple(item)).forEach(([name,item])=>{const nested=document.createElement('details');nested.className='detail-nested';nested.open=depth<1;const summary=document.createElement('summary'),body=document.createElement('div');summary.textContent=`${label(name)}${Array.isArray(item)?` (${item.length})`:''}`;body.className='detail-nested-body';if(Array.isArray(item)){item.forEach((child,index)=>body.append(section(child,`${label(name)} ${index+1}`,depth+1)));if(!item.length){const empty=document.createElement('div');empty.className='detail-empty';empty.textContent='No data';body.append(empty)}}else body.append(section(item,name,depth+1));nested.append(summary,body);host.append(nested)});return host}
function render(detail){const fragment=document.createDocumentFragment();Object.entries(detail||{}).forEach(([name,value])=>fragment.append(section(value,name)));return fragment}
const close=()=>modal.classList.add('hidden'),open=async item=>{modal.classList.remove('hidden');modal.querySelector('h2').textContent=`${item.displayName} | Source details`;const content=modal.querySelector('.detail-content');content.textContent='Loading source details...';try{const detail=await api('/api/details',{workload,id:item.id});content.replaceChildren(render(detail))}catch(error){content.textContent=error.message}};
modal.querySelector('.detail-close').onclick=close;modal.addEventListener('click',event=>{if(event.target===modal)close()});document.addEventListener('keydown',event=>{if(event.key==='Escape')close()});
function decorate(){const showDependencies=workload==='ConditionalAccess';dependencyHeader.classList.toggle('hidden',!showDependencies);[...$('items').rows].forEach(row=>{const selector=row.querySelector('[data-i]');if(!selector){if(row.cells.length===1)row.cells[0].colSpan=showDependencies?4:3;return}let cell=row.querySelector('.dependency-cell');if(!cell){cell=row.insertCell();cell.className='dependency-cell'}cell.classList.toggle('hidden',!showDependencies);const item=items[+selector.dataset.i];cell.textContent=item?.dependencies||'None';row.classList.add('source-detail-row');row.title='Double-click to view source details';row.ondblclick=event=>{if(!event.target.closest('input'))open(item)}})}
new MutationObserver(decorate).observe($('items'),{childList:true});document.querySelectorAll('[data-workload]').forEach(button=>button.addEventListener('click',()=>setTimeout(decorate)));decorate();
})();
</script><script>
(()=>{const choice=document.querySelector('[data-workload="SensitivityLabels"]'),modal=document.createElement('div'),style=document.createElement('style');window.gbgLabelsReady=false;style.textContent='.label-auth-modal{position:fixed;inset:0;z-index:1100;background:#08080be8;display:flex;align-items:center;justify-content:center;padding:24px}.label-auth-modal.hidden{display:none}.label-auth-dialog{width:min(900px,96vw);max-height:92vh;overflow:auto;background:#1d1d22;border:1px solid #5a5a65;border-radius:8px;padding:22px}.label-auth-head{display:flex;align-items:start;justify-content:space-between;gap:18px;margin-bottom:18px}.label-auth-head h2{margin:0 0 6px}.label-auth-head p{color:#cfcfd4;margin:0}.label-auth-steps{display:grid;grid-template-columns:1fr 1fr;gap:14px}.label-auth-step{border:1px solid #3a3a42;background:#18181d;padding:16px}.label-auth-step h3{margin:0 0 8px;color:#f45067}.label-auth-step p{color:#cfcfd4;font-size:13px;line-height:1.45;min-height:58px}.label-auth-step button{width:100%}.label-auth-result{color:#cfcfd4;font-size:12px;line-height:1.4;margin-top:10px;min-height:34px;word-break:break-word}.label-auth-footer{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-top:16px}.label-auth-status{color:#cfcfd4}.label-auth-status.error{color:#ff8797}@media(max-width:700px){.label-auth-steps{grid-template-columns:1fr}.label-auth-footer{align-items:stretch;flex-direction:column}}';document.head.append(style);modal.className='label-auth-modal hidden';modal.innerHTML='<section class="label-auth-dialog" role="dialog" aria-modal="true" aria-labelledby="labelAuthTitle"><header class="label-auth-head"><div><h2 id="labelAuthTitle">Purview sensitivity label authentication</h2><p>This is separate from Microsoft Graph. No password or credential is stored by this tool.</p></div><button id="closeLabelAuth">CLOSE</button></header><div class="label-auth-steps"><article class="label-auth-step"><h3>1. Source Purview</h3><p>Requires permission to read sensitivity labels. The tool verifies that <b>Get-Label</b> is available.</p><button id="connectLabelSource">SIGN IN TO SOURCE PURVIEW</button><div id="labelSourceResult" class="label-auth-result">Not connected</div></article><article class="label-auth-step"><h3>2. Destination Purview</h3><p>Requires an Information Protection or Compliance role that provides <b>Get-Label</b>, <b>New-Label</b>, and <b>Set-Label</b>.</p><button id="connectLabelDestination" disabled>SIGN IN TO DESTINATION PURVIEW</button><div id="labelDestinationResult" class="label-auth-result">Connect source Purview first</div></article></div><footer class="label-auth-footer"><div id="labelAuthStatus" class="label-auth-status">Authenticate both Purview tenants to continue.</div><button id="continueLabels" disabled>CONTINUE TO LABELS</button></footer></section>';document.body.append(modal);const get=id=>modal.querySelector(`#${id}`),status=(message,error=false)=>{get('labelAuthStatus').textContent=message;get('labelAuthStatus').classList.toggle('error',error)},close=()=>modal.classList.add('hidden');choice.addEventListener('click',event=>{if(window.gbgLabelsReady)return;event.preventDefault();event.stopImmediatePropagation();modal.classList.remove('hidden')},true);get('closeLabelAuth').onclick=close;modal.addEventListener('click',event=>{if(event.target===modal)close()});get('connectLabelSource').onclick=async()=>{const button=get('connectLabelSource');button.disabled=true;status('Complete the source Purview sign-in window.');try{const response=await api('/api/setup/labels/source');get('labelSourceResult').textContent=`Verified ${response.account} | ${response.labelCount} labels | ${response.permission}`;button.textContent='SOURCE PURVIEW VERIFIED';get('connectLabelDestination').disabled=false;status('Source label read permission verified. Connect destination Purview.')}catch(error){button.disabled=false;get('labelSourceResult').textContent=error.message;status(error.message,true)}};get('connectLabelDestination').onclick=async()=>{const button=get('connectLabelDestination');button.disabled=true;status('Complete the destination Purview sign-in window.');try{const response=await api('/api/setup/labels/destination');get('labelDestinationResult').textContent=`Verified ${response.account} | ${response.labelCount} labels | ${response.permissions.join(', ')} verified`;button.textContent='DESTINATION PURVIEW VERIFIED';get('continueLabels').disabled=false;status('Both Purview tenants and required label permissions are verified.')}catch(error){button.disabled=false;get('labelDestinationResult').textContent=error.message;status(error.message,true)}};get('continueLabels').onclick=()=>{window.gbgLabelsReady=true;close();choice.click()};const sourceText=document.querySelector('#authPage .auth-tenants article:first-child p'),targetText=document.querySelector('#authPage .auth-tenants article:last-child p');if(sourceText)sourceText.textContent='Graph read access for Conditional Access, AV, ASR, and Custom Detection. Purview labels authenticate separately when selected.';if(targetText)targetText.textContent='Graph write access for Conditional Access, AV, ASR, and Custom Detection. Purview labels authenticate separately when selected.';})();
</script></body></html>
'@
    Start-Process $url; Write-Host "GBG Tool for Migration is running at $url. Close this PowerShell session to stop it."
    try { while ($listener.IsListening) { $context = $listener.GetContext(); try { switch ($context.Request.Url.AbsolutePath) {
        '/' { Send-Response $context.Response $html 200 'text/html; charset=utf-8' }
        '/api/setup/source' {
            $request=Read-JsonRequest $context.Request; $state.RememberSession=[bool](Get-ObjectProperty $request 'rememberSession'); $state.FreshSignIn=[bool](Get-ObjectProperty $request 'freshSignIn')
            $source = Connect-UnifiedGraph -Scopes $SourceGraphScopes -Label 'Source' -RememberSession:$state.RememberSession -FreshSignIn:$state.FreshSignIn; $state.Source = $source; $state.SourceData=@{}; $state.LoadErrors=@{}
            foreach ($workload in 'ConditionalAccess','CustomDetection','Antivirus','Asr') { try { $state.SourceData[$workload] = switch ($workload) { 'ConditionalAccess' { Get-ConditionalAccessData }; 'CustomDetection' { Get-CustomDetectionData }; 'Antivirus' { Get-IntuneData Antivirus }; 'Asr' { Get-IntuneData Asr } } } catch { $state.LoadErrors[$workload] = $_.Exception.Message } }
            $state.SourceDomain=Get-DefaultVerifiedDomain
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            $state.SourceData.Remove('SensitivityLabels'); $state.DestinationLabels=@(); $state.PurviewConnected=$false; $state.LoadErrors.Remove('SensitivityLabels')
            Send-Response $context.Response ([pscustomobject]@{tenantId=$source.TenantId;account=$source.Account;permissions=$source.Permissions;sessionMode=$source.SessionMode;unavailable=$state.LoadErrors}|ConvertTo-Json -Depth 15)
        }
        '/api/setup/destination' { if($null -eq $state.Source){throw 'Connect source first.'}; $target=Connect-UnifiedGraph -Scopes $TargetGraphScopes -Label 'Destination' -RememberSession:$state.RememberSession -FreshSignIn:$state.FreshSignIn; $state.Destination=$target; $state.TargetDomain=Get-DefaultVerifiedDomain; Send-Response $context.Response ([pscustomobject]@{tenantId=$target.TenantId;account=$target.Account;permissions=$target.Permissions;sessionMode=$target.SessionMode;unavailable=$state.LoadErrors}|ConvertTo-Json -Depth 15) }
        '/api/setup/labels/source' { if($null -eq $state.Source){throw 'Complete the main source tenant authentication first.'}; try { Connect-PurviewLabels -Account $state.Source.Account -ReadOnly; $state.SourceData['SensitivityLabels']=@(Get-SensitivityLabelData); $state.LoadErrors.Remove('SensitivityLabels'); Send-Response $context.Response ([pscustomobject]@{tenantId=$state.Source.TenantId;account=$state.Source.Account;labelCount=@($state.SourceData['SensitivityLabels']).Count;permission='Get-Label verified'}|ConvertTo-Json -Depth 10) } catch { $state.SourceData.Remove('SensitivityLabels'); $state.LoadErrors['SensitivityLabels']=$_.Exception.Message; throw } finally { Disconnect-PurviewLabels } }
        '/api/setup/labels/destination' { if(-not $state.SourceData.ContainsKey('SensitivityLabels')){throw 'Authenticate source Purview first.'}; if($null -eq $state.Destination){throw 'Complete the main destination tenant authentication first.'}; try { Connect-PurviewLabels -Account $state.Destination.Account; $state.DestinationLabels=@(Get-SensitivityLabelData); $state.PurviewConnected=$true; $state.LoadErrors.Remove('SensitivityLabels'); Send-Response $context.Response ([pscustomobject]@{tenantId=$state.Destination.TenantId;account=$state.Destination.Account;labelCount=@($state.DestinationLabels).Count;permissions=@('Get-Label','New-Label','Set-Label')}|ConvertTo-Json -Depth 10) } catch { $state.PurviewConnected=$false; $state.LoadErrors['SensitivityLabels']=$_.Exception.Message; Disconnect-PurviewLabels; throw } }
        '/api/workload' { $request=Read-JsonRequest $context.Request; if($null -eq $state.Source -or $null -eq $state.Destination){throw 'Complete one-time tenant setup first.'}; if(-not $state.SourceData.ContainsKey($request.workload)){throw "Source workload '$($request.workload)' is unavailable: $($state.LoadErrors[$request.workload])"}; $state.Workload=$request.workload; $items=Get-WorkloadItems $request.workload $state.SourceData[$request.workload]; Send-Response $context.Response ([pscustomobject]@{items=$items;source="Tenant: $($state.Source.TenantId) | $($state.Source.Account)";destination="Tenant: $($state.Destination.TenantId) | $($state.Destination.Account)"}|ConvertTo-Json -Depth 20) }
        '/api/details' { $request=Read-JsonRequest $context.Request; if(-not $state.SourceData.ContainsKey($request.workload)){throw "Source workload '$($request.workload)' is unavailable."}; $detail=Get-WorkloadItemDetail -Workload $request.workload -Data $state.SourceData[$request.workload] -Id $request.id; Send-Response $context.Response ($detail|ConvertTo-Json -Depth 100) }
        '/api/label-targets' { if(-not $state.PurviewConnected){throw "Destination Purview is unavailable: $($state.LoadErrors['SensitivityLabels'])"}; $state.DestinationLabels=@(Get-SensitivityLabelData); $targets=@($state.DestinationLabels|ForEach-Object{[pscustomobject]@{id=Get-SensitivityLabelId $_;displayName=$_.DisplayName;name=$_.Name}}); Send-Response $context.Response ([pscustomobject]@{targets=$targets}|ConvertTo-Json -Depth 10) }
        '/api/migrate' { $request=Read-JsonRequest $context.Request; if($null -eq $state.Workload){throw 'Choose a workload first.'}; $ids=@($request.ids); if($ids.Count -eq 0){throw 'Select at least one item.'}; $data=$state.SourceData[$state.Workload]; $results=switch($state.Workload){ 'ConditionalAccess'{Invoke-ConditionalAccessMigration $data $ids $request.state -IncludeDisabled:([bool]$request.includeDisabled)} 'CustomDetection'{Invoke-CustomDetectionMigration $data $ids} 'Antivirus'{Invoke-IntuneMigration $data $ids} 'Asr'{Invoke-IntuneMigration $data $ids} 'SensitivityLabels'{if(-not $state.PurviewConnected){throw 'Destination Purview session is not connected.'};$state.DestinationLabels=@(Get-SensitivityLabelData);Invoke-SensitivityLabelMigration -SourceLabels $data -TargetLabels $state.DestinationLabels -Ids $ids -Mode $request.labelMode -Mappings $request.labelMappings -SourceDomain $state.SourceDomain -TargetDomain $state.TargetDomain} }; Send-Response $context.Response ([pscustomobject]@{results=@($results)}|ConvertTo-Json -Depth 30) }
        default { Send-Response $context.Response (@{error='Not found.'}|ConvertTo-Json) 404 }
    }} catch { Send-Response $context.Response (@{error=$_.Exception.Message}|ConvertTo-Json) 500 } } } finally { Disconnect-PurviewLabels; if(-not $state.RememberSession){Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null}; $listener.Close() }
}

Start-GbgMigrationWebApp
