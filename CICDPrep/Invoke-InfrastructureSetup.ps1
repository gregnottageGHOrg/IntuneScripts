<#
.SYNOPSIS
    Automates the full infrastructure setup for the Intune CI/CD pipeline.

.DESCRIPTION
    This script provisions all Azure and Azure DevOps resources needed by the Intune IaC pipeline:
      - Validates and installs local prerequisites (Git, Az CLI, PowerShell modules, VS Code)
      - Creates an Azure Resource Group and User-Assigned Managed Identities (per environment)
      - Grants Microsoft Graph API permissions to each UAMI
      - Creates Workload Identity Federation credentials
      - Creates an ADO project, Git repository, and pushes local content
      - Creates ADO service connections with Workload Identity Federation
      - Creates ADO environments with approval gates (staging/production)
      - Creates an ADO variable group with all pipeline variables
      - Creates ADO pipelines from existing YAML definitions

    Supports multi-tenant deployments where dev, staging, and production Intune
    environments live in separate Entra ID tenants. Each environment gets its own
    UAMI, Graph permissions, federated credential, and ADO service connection
    targeting that environment's tenant.

    Use -ProductionOnly to skip dev/staging resource creation and deploy only
    to the production tenant (useful for initial testing).

    Use -Teardown to remove all cloud/remote resources that were provisioned
    (ADO pipelines, variable groups, service connections, environments,
    projects, Azure UAMIs, federated credentials, app registrations, and
    resource groups). Teardown NEVER deletes local files or folders — the
    local repository is always preserved as the source of truth.

.PARAMETER ADOOrganization
    Azure DevOps organization name (e.g., 'modernazlab').

.PARAMETER ADOProject
    Azure DevOps project name. Default: 'DMAC'.

.PARAMETER ADORepoName
    Azure DevOps repository name. Default: matches ADOProject.

.PARAMETER AzureSubscriptionId
    Production Azure Subscription ID (also used as default for dev/staging if not overridden).

.PARAMETER AzureSubscriptionName
    Production Azure Subscription friendly name.

.PARAMETER TenantId
    Production Entra ID Tenant GUID (also used as default for dev/staging if not overridden).

.PARAMETER DevTenantId
    Dev Entra ID Tenant GUID. Defaults to TenantId if not specified.

.PARAMETER DevSubscriptionId
    Dev Azure Subscription ID. Defaults to AzureSubscriptionId if not specified.

.PARAMETER DevSubscriptionName
    Dev Azure Subscription friendly name. Defaults to AzureSubscriptionName if not specified.

.PARAMETER StagingTenantId
    Staging Entra ID Tenant GUID. Defaults to TenantId if not specified.

.PARAMETER StagingSubscriptionId
    Staging Azure Subscription ID. Defaults to AzureSubscriptionId if not specified.

.PARAMETER StagingSubscriptionName
    Staging Azure Subscription friendly name. Defaults to AzureSubscriptionName if not specified.

.PARAMETER ResourceGroupName
    Azure resource group for UAMIs (same name in each tenant). Default: 'rg-intune-cicd'.

.PARAMETER AzureRegion
    Azure region for resources. Default: 'uksouth'.

.PARAMETER LocalRepoPath
    Path to local git repo content. Default: script's parent directory (DMAC root).

.PARAMETER StagingApprovers
    Comma-separated list of ADO user emails for staging approval gate.

.PARAMETER ProductionApprovers
    Comma-separated list of ADO user emails for production approval gate.

.PARAMETER Teardown
    Switch to remove all cloud/remote provisioned resources instead of
    creating them. Local files and folders are never deleted.

.PARAMETER Force
    Switch to skip all teardown confirmation prompts and proceed automatically.

.PARAMETER ProductionOnly
    Default behavior — provisions only the production environment. This is the
    default when no environment switches are specified. The pipeline
    PRODUCTION_ONLY variable is set to 'true' so the CI/CD pipeline skips
    dev/staging stages.

.PARAMETER AllEnvironments
    Switch to provision all three environments (dev, staging, production)
    instead of the default production-only mode.

.PARAMETER SkipPrerequisites
    Switch to skip prerequisite checks and installation.

.PARAMETER SkipADOSetup
    Switch to skip Azure DevOps project/repo/pipeline setup.

.PARAMETER SkipAzureSetup
    Switch to skip Azure resource provisioning (UAMI, federation).

.PARAMETER PatchEnrollmentAssignments
    Switch to patch group assignments and scope tags onto enrollment restriction
    policies using delegated auth. This is now handled automatically during
    the initial import, but remains available for backward compatibility —
    use it to re-apply assignments on policies that were imported before
    this capability was added. Use with -SkipADOSetup -SkipAzureSetup
    to skip other setup steps.

.PARAMETER UseSelfHostedAgent
    Switch to set the self-hosted agent (DMAC-SelfHosted pool) as the default
    for all pipeline runs. When specified, all pipeline YAML definitions are
    updated so the 'Use self-hosted agent' checkbox defaults to enabled.
    Omit this switch to keep Microsoft-hosted agents as the default.

.EXAMPLE
    .\Invoke-InfrastructureSetup.ps1 -ADOOrganization "modernazlab" -TenantId "xxxxxxxx-..."
    Sets up only production environment in a single tenant (default).

.EXAMPLE
    .\Invoke-InfrastructureSetup.ps1 -ADOOrganization "modernazlab" -TenantId "prod-tenant-guid" -AllEnvironments -DevTenantId "dev-tenant-guid" -DevSubscriptionId "dev-sub-id" -StagingTenantId "staging-tenant-guid" -StagingSubscriptionId "staging-sub-id"
    Sets up all three environments across separate tenants.

.EXAMPLE
    .\Invoke-InfrastructureSetup.ps1 -ADOOrganization "modernazlab" -Teardown -Force
    Tears down all cloud/remote resources without prompting. Local files are preserved.
#>

[CmdletBinding(SupportsShouldProcess)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DevSubscriptionId', Justification = 'Used in environment configuration block')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DevSubscriptionName', Justification = 'Used in environment configuration block')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'StagingSubscriptionId', Justification = 'Used in environment configuration block')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'StagingSubscriptionName', Justification = 'Used in environment configuration block')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Force', Justification = 'Used in teardown and confirmation blocks')]
param(
    [Parameter(Mandatory)]
    [string]$ADOOrganization,

    [Parameter()]
    [string]$ADOProject = "DMAC",

    [Parameter()]
    [string]$ADORepoName = "",

    [Parameter()]
    [string]$AzureSubscriptionId = "",

    [Parameter()]
    [string]$AzureSubscriptionName = "",

    [Parameter()]
    [string]$TenantId,

    # ── Dev tenant overrides (default to production values) ──
    [Parameter()]
    [string]$DevTenantId = "",

    [Parameter()]
    [string]$DevSubscriptionId = "",

    [Parameter()]
    [string]$DevSubscriptionName = "",

    # ── Staging tenant overrides (default to production values) ──
    [Parameter()]
    [string]$StagingTenantId = "",

    [Parameter()]
    [string]$StagingSubscriptionId = "",

    [Parameter()]
    [string]$StagingSubscriptionName = "",

    [Parameter()]
    [string]$ResourceGroupName = "rg-intune-cicd",

    [Parameter()]
    [string]$AzureRegion = "uksouth",

    [Parameter()]
    [string]$LocalRepoPath = "",

    [Parameter()]
    [string[]]$StagingApprovers = @(),

    [Parameter()]
    [string[]]$ProductionApprovers = @(),

    [Parameter()]
    [switch]$Teardown,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$ProductionOnly,

    [Parameter()]
    [switch]$AllEnvironments,

    [Parameter()]
    [switch]$SkipPrerequisites,

    [Parameter()]
    [switch]$SkipADOSetup,

    [Parameter()]
    [switch]$SkipAzureSetup,

    [Parameter()]
    [switch]$PrerequisitesOnly,

    [Parameter()]
    [switch]$PatchEnrollmentAssignments,

    [Parameter()]
    [switch]$UseSelfHostedAgent,

    [Parameter()]
    [switch]$PrepareWin32AppFolders
)

# ─────────────────────────────────────────────────────────────
# PowerShell version gate — require 7+ for full operation, allow 5.1
# for prerequisite installation only
# ─────────────────────────────────────────────────────────────
$script:RunningPS5 = $PSVersionTable.PSVersion.Major -lt 7

if ($script:RunningPS5 -and -not $PrerequisitesOnly) {
    # Quick-check: are all prerequisites already installed?
    $missingPrereqs = @()
    if (-not (Get-Command 'pwsh' -ErrorAction SilentlyContinue)) { $missingPrereqs += 'PowerShell 7' }
    if (-not (Get-Command 'git' -ErrorAction SilentlyContinue)) { $missingPrereqs += 'Git' }
    if (-not (Get-Command 'az' -ErrorAction SilentlyContinue)) { $missingPrereqs += 'Azure CLI' }
    if (-not (Get-Command 'code' -ErrorAction SilentlyContinue) -and
        -not (Get-Command 'code-insiders' -ErrorAction SilentlyContinue)) { $missingPrereqs += 'VS Code' }

    if ($missingPrereqs.Count -eq 0) {
        # All tools installed, but running in PS 5.1 — must switch to PS 7
        Write-Host "`n  [INFO]  All prerequisites are already installed." -ForegroundColor Green
        Write-Host "  [STOP]  This script requires PowerShell 7 for full operation." -ForegroundColor Red
        Write-Host "  Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
        Write-Host "`n  Re-run this script from a PowerShell 7 terminal:" -ForegroundColor Yellow
        Write-Host "    pwsh.exe -File `"$($MyInvocation.MyCommand.Path)`"" -ForegroundColor Yellow
        Write-Host "`n  Or open PowerShell 7 from Start Menu > PowerShell 7 (or Terminal > pwsh)`n" -ForegroundColor Yellow
        exit 1
    }
    else {
        # Prerequisites are missing — offer to install them from this PS 5.1 session
        Write-Host "`n  [INFO]  Running PowerShell $($PSVersionTable.PSVersion) — prerequisite installation mode." -ForegroundColor Cyan
        Write-Host "  Missing prerequisites: $($missingPrereqs -join ', ')" -ForegroundColor Yellow

        $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isElevated) {
            Write-Host "`n  [STOP]  An elevated (Run as Administrator) session is recommended" -ForegroundColor Red
            Write-Host "  to install prerequisites reliably." -ForegroundColor Red
            Write-Host "`n  Please:" -ForegroundColor Yellow
            Write-Host "    1. Right-click PowerShell > 'Run as Administrator'" -ForegroundColor Yellow
            Write-Host "    2. Re-run: .\Invoke-InfrastructureSetup.ps1 -PrerequisitesOnly" -ForegroundColor Yellow
            Write-Host "    3. Then open PowerShell 7 (pwsh.exe) and re-run the full script`n" -ForegroundColor Yellow
            exit 1
        }

        # Elevated PS 5.1 with missing prereqs — auto-switch to -PrerequisitesOnly mode
        Write-Host "  Running elevated — will install prerequisites only.`n" -ForegroundColor Green
        $PrerequisitesOnly = $true
    }
}

# ─────────────────────────────────────────────────────────────
# Strict mode and error handling
# ─────────────────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ADORepoName)) { $ADORepoName = $ADOProject }
if ([string]::IsNullOrWhiteSpace($LocalRepoPath)) {
    $LocalRepoPath = Split-Path -Parent $PSScriptRoot  # Go up from /scripts to repo root
}

$script:ADOBaseUrl = "https://dev.azure.com/$ADOOrganization"
$script:ADOProjectName = $ADOProject
$script:StepNumber = 0
$script:Errors = [System.Collections.Generic.List[string]]::new()
$script:AppRegistrationDetails = @{}
$script:FicActualValues = @{}

# Default to production-only unless -AllEnvironments is specified.
# -ProductionOnly is kept for backward compatibility but is now the default.
if ($AllEnvironments) {
    $ProductionOnly = $false
}
else {
    $ProductionOnly = $true
}
$Environments = if ($ProductionOnly) { @("production") } else { @("dev", "staging", "production") }

#region Functions
# ─────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────
function Write-StepHeader {
    param([string]$Title)
    $script:StepNumber++
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  STEP $($script:StepNumber): $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Info {
    param([string]$Message)
    Write-Host "  [INFO] $Message" -ForegroundColor Gray
}

function Write-Success {
    param([string]$Message)
    Write-Host "  [OK]   $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
    $script:Errors.Add($Message)
}

function Write-Progress2 {
    param([string]$Activity, [string]$Status)
    Write-Host "  [$Activity] $Status" -ForegroundColor DarkCyan
}

function Get-CleanErrorMessage {
    <#
    .SYNOPSIS
        Extracts a meaningful message from an error, stripping HTML/CSS if
        returned by a REST endpoint.  Invoke-RestMethod strips HTML tags from
        error responses, leaving raw CSS text (e.g. "html { height: 100%; }")
        and body content.  This function detects both raw HTML and tag-stripped
        responses.
    #>
    param([object]$ErrorRecord)
    $msg = "$ErrorRecord"

    # Detect Graph API JSON error responses — extract just the error code and message
    if ($msg -match '"error"\s*:\s*\{' -and $msg -match '"code"\s*:\s*"([^"]+)"' ) {
        $errCode = $Matches[1]
        $errMessage = ''
        if ($msg -match '"message"\s*:\s*"([^"]+)"') {
            $errMessage = $Matches[1]
        }
        return "${errCode}: $errMessage"
    }

    # Detect HTML error pages — check for raw HTML tags AND for tag-stripped
    # CSS text that Invoke-RestMethod leaves behind.
    $isHtml = $msg -match '<html' -or
    $msg -match '(?m)html\s*\{[\s\S]*?height:\s*100%' -or
    ($msg.Length -gt 500 -and $msg -match 'font-family:' -and $msg -match 'body\s*\{')

    if (-not $isHtml) { return $msg }

    # 1) Prefer the clean HTTP status from the exception itself
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and
        $ErrorRecord.Exception) {
        # HttpResponseException exposes .Response.StatusCode
        $resp = $ErrorRecord.Exception.Response
        if ($resp -and $resp.StatusCode) {
            $code = [int]$resp.StatusCode
            $phrase = $resp.ReasonPhrase
            if (-not $phrase) { $phrase = $resp.StatusCode.ToString() }
            return "HTTP ${code}: $phrase"
        }
        # Fall back to Exception.Message (e.g. "Response status code does not
        # indicate success: 404 (Not Found).")
        $exMsg = $ErrorRecord.Exception.Message
        if ($exMsg -and $exMsg.Length -lt 300 -and $exMsg -notmatch 'html\s*\{') {
            return $exMsg
        }
    }

    # 2) Try <title> tag (present when tags were NOT stripped)
    if ($msg -match '<title>([^<]+)</title>') {
        return $Matches[1].Trim()
    }

    # 3) Try NNN - description pattern from the visible page text
    if ($msg -match '(\d{3})\s*-\s*([^\r\n<]{3,80})') {
        return "HTTP $($Matches[1]): $($Matches[2].Trim())"
    }

    # 4) Grab the first non-empty, non-CSS line (often the stripped page title)
    $firstLine = ($msg -split '\r?\n' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' -and $_ -notmatch '^\s*[\.\#a-z-]+\s*\{' -and $_ -notmatch '^\s*[\w-]+\s*:' } |
        Select-Object -First 1)
    if ($firstLine -and $firstLine.Length -lt 200) {
        return $firstLine
    }

    return 'HTTP error (see URL in browser for details)'
}

function Invoke-CommandSafe {
    <#
    .SYNOPSIS
        Runs a script block and returns $true on success, $false on failure.
    #>
    param(
        [scriptblock]$ScriptBlock,
        [string]$ErrorMessage = "Command failed"
    )
    try {
        & $ScriptBlock
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            Write-Err "$ErrorMessage (exit code $LASTEXITCODE)"
            return $false
        }
        return $true
    }
    catch {
        Write-Err "$ErrorMessage : $_"
        return $false
    }
}

function Test-CommandExists {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Tests for command existence')]
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

function Sync-ScopeTagAssignments {
    <#
    .SYNOPSIS
        Ensures a scope tag in the target tenant has the group assignments
        defined in the source JSON. Adds missing assignments without removing
        any that were added out-of-band.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Syncs multiple assignments')]
    param(
        [Parameter(Mandatory)] [object]$SourceScopeTag,
        [Parameter(Mandatory)] [string]$TargetScopeTagId,
        [Parameter(Mandatory)] [hashtable]$GroupIdMap,
        [Parameter(Mandatory)] [object[]]$MigrationObjects,
        [Parameter(Mandatory)] [string]$GroupsContentPath
    )

    if (-not $SourceScopeTag.PSObject.Properties['assignments'] -or -not $SourceScopeTag.assignments) {
        return
    }
    $sourceAssignments = @($SourceScopeTag.assignments)
    if ($sourceAssignments.Count -eq 0) { return }

    # Get existing assignments on the target scope tag
    $existingAssignments = @()
    try {
        $existingResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/$TargetScopeTagId/assignments" `
            -OutputType PSObject -ErrorAction Stop
        if ($existingResp.value) { $existingAssignments = @($existingResp.value) }
    }
    catch {
        Write-Warn "    Could not read scope tag assignments: $(Get-CleanErrorMessage $_)"
        return
    }

    # Build set of existing target group IDs
    $existingGroupIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($ea in $existingAssignments) {
        if ($ea.target -and $ea.target.groupId) {
            [void]$existingGroupIds.Add($ea.target.groupId)
        }
    }

    # Determine which source assignments are missing
    $newAssignments = [System.Collections.Generic.List[object]]::new()
    foreach ($srcAssignment in $sourceAssignments) {
        if (-not $srcAssignment.target -or -not $srcAssignment.target.groupId) { continue }
        $srcGroupId = $srcAssignment.target.groupId

        # Remap group ID to target tenant
        $targetGroupId = $null
        if ($GroupIdMap.ContainsKey($srcGroupId)) {
            $targetGroupId = $GroupIdMap[$srcGroupId]
        }
        else {
            # Try to resolve via MigrationTable → look up by display name in target
            $migObj = $MigrationObjects | Where-Object { $_.Id -eq $srcGroupId -and $_.Type -eq 'Group' } | Select-Object -First 1
            if ($migObj) {
                try {
                    $grpResp = Invoke-MgGraphRequest -Method GET `
                        -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($migObj.DisplayName -replace "'","''")'&`$select=id" `
                        -OutputType PSObject -ErrorAction Stop
                    if ($grpResp.value -and $grpResp.value.Count -gt 0) {
                        $targetGroupId = $grpResp.value[0].id
                        $GroupIdMap[$srcGroupId] = $targetGroupId
                    }
                }
                catch { $null = $null }
            }
        }

        if (-not $targetGroupId) {
            # Group not found — attempt to create it from Content/Groups/ JSON definition
            if ($migObj) {
                $groupDisplayName = $migObj.DisplayName
                $groupJsonFile = Join-Path $GroupsContentPath "$groupDisplayName.json"
                if (-not (Test-Path $groupJsonFile)) {
                    Write-Warn "    Scope tag assignment group '$srcGroupId' ('$groupDisplayName') not found in target and no JSON definition at '$groupJsonFile' — skipping"
                    continue
                }

                Write-Info "    Creating group '$groupDisplayName' for scope tag assignment..."
                try {
                    $groupDef = Get-Content -Path $groupJsonFile -Raw | ConvertFrom-Json -Depth 50

                    $newGroup = @{
                        displayName     = $groupDef.displayName
                        mailEnabled     = [bool]$groupDef.mailEnabled
                        mailNickname    = if ($groupDef.mailNickname) { $groupDef.mailNickname } else { ($groupDef.displayName -replace '[^a-zA-Z0-9]', '').Substring(0, [Math]::Min(64, ($groupDef.displayName -replace '[^a-zA-Z0-9]', '').Length)) }
                        securityEnabled = [bool]$groupDef.securityEnabled
                    }
                    if ($groupDef.description) { $newGroup['description'] = $groupDef.description }
                    if ($groupDef.groupTypes -and $groupDef.groupTypes.Count -gt 0) {
                        $newGroup['groupTypes'] = @($groupDef.groupTypes)
                    }
                    else {
                        $newGroup['groupTypes'] = @()
                    }
                    if ($groupDef.membershipRule) {
                        $newGroup['membershipRule'] = $groupDef.membershipRule
                        $newGroup['membershipRuleProcessingState'] = if ($groupDef.membershipRuleProcessingState) { $groupDef.membershipRuleProcessingState } else { 'On' }
                        if ($newGroup['groupTypes'] -notcontains 'DynamicMembership') {
                            $newGroup['groupTypes'] += 'DynamicMembership'
                        }
                    }

                    $groupBody = $newGroup | ConvertTo-Json -Depth 10
                    $createdGroup = Invoke-MgGraphRequest -Method POST `
                        -Uri "https://graph.microsoft.com/v1.0/groups" `
                        -Body ([System.Text.Encoding]::UTF8.GetBytes($groupBody)) `
                        -ContentType "application/json; charset=utf-8" `
                        -OutputType PSObject -ErrorAction Stop

                    if ($createdGroup.id) {
                        Write-Success "    Created group '$groupDisplayName' (ID: $($createdGroup.id))"
                        $targetGroupId = $createdGroup.id
                        $GroupIdMap[$srcGroupId] = $targetGroupId
                    }
                }
                catch {
                    $errDetail = "$($_.ErrorDetails.Message)$($_.Exception.Message)"
                    if ($errDetail -match 'already exists' -or $errDetail -match 'ObjectConflict') {
                        Write-Info "    Group '$groupDisplayName' was created concurrently — looking it up..."
                        try {
                            $retryResp = Invoke-MgGraphRequest -Method GET `
                                -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($groupDisplayName -replace "'","''")'&`$select=id" `
                                -OutputType PSObject -ErrorAction Stop
                            if ($retryResp.value -and $retryResp.value.Count -gt 0) {
                                $targetGroupId = $retryResp.value[0].id
                                $GroupIdMap[$srcGroupId] = $targetGroupId
                                Write-Success "    Found group '$groupDisplayName' (ID: $targetGroupId)"
                            }
                        }
                        catch {
                            Write-Warn "    Could not look up group '$groupDisplayName' after conflict: $(Get-CleanErrorMessage $_)"
                        }
                    }
                    else {
                        Write-Warn "    Could not create group '$groupDisplayName': $(Get-CleanErrorMessage $_)"
                    }
                }
            }
            else {
                Write-Warn "    Scope tag assignment group '$srcGroupId' not found in MigrationTable — skipping"
                continue
            }
        }

        if (-not $targetGroupId) {
            continue
        }

        if ($existingGroupIds.Contains($targetGroupId)) {
            continue  # Already assigned
        }

        $newAssignments.Add(@{
                '@odata.type' = '#microsoft.graph.roleScopeTagAutoAssignment'
                target        = @{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId       = $targetGroupId
                }
            })
    }

    if ($newAssignments.Count -eq 0) {
        Write-Info "    Scope tag assignments are up to date"
        return
    }

    # Merge existing + new into one payload (the /assign action replaces all)
    $mergedAssignments = [System.Collections.Generic.List[object]]::new()
    foreach ($ea in $existingAssignments) {
        if (-not $ea.target -or -not $ea.target.groupId) { continue }
        $mergedAssignments.Add(@{
                '@odata.type' = '#microsoft.graph.roleScopeTagAutoAssignment'
                target        = @{
                    '@odata.type' = if ($ea.target.'@odata.type') { $ea.target.'@odata.type' } else { '#microsoft.graph.groupAssignmentTarget' }
                    groupId       = $ea.target.groupId
                }
            })
    }
    foreach ($na in $newAssignments) {
        $mergedAssignments.Add($na)
    }

    try {
        $assignBody = @{ assignments = @($mergedAssignments) } | ConvertTo-Json -Depth 20
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/$TargetScopeTagId/assign" `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($assignBody)) `
            -ContentType "application/json; charset=utf-8" `
            -ErrorAction Stop | Out-Null
        Write-Success "    Applied $($newAssignments.Count) new scope tag assignment(s) ($($mergedAssignments.Count) total)"
    }
    catch {
        Write-Warn "    Could not apply scope tag assignments: $(Get-CleanErrorMessage $_)"
    }
}

function Connect-MgGraphForIntune {
    <#
    .SYNOPSIS
        Establishes a single Microsoft Graph delegated session with the full
        superset of Intune management scopes needed by all delegated-auth
        operations in this script (enrollment restrictions, branding, assignment patches).
    .DESCRIPTION
        Designed to be called ONCE near the start of the provisioning flow.
        Subsequent callers just verify the existing session is still valid for
        the required tenant by calling Test-MgGraphIntuneSession.

        Auth strategy (to get the native Windows account picker popup rather
        than a browser redirect):
        1. If an existing MgGraph session is valid for the target tenant AND
           passes the Intune probe — reuse it with zero prompts.
        2. Try Connect-MgGraph WITH WAM (native account picker popup).
           Validate with Intune probe. If the probe passes — done.
        3. If WAM token fails the probe (cached token without Intune claims),
           disconnect and retry with MSAL_USE_BROKER=0 (browser fallback).
    #>
    param(
        [Parameter(Mandatory)]
        [string]$TenantId
    )

    $intuneProbeUri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?`$top=1&`$select=id"

    # Full superset of scopes needed by enrollment restrictions, branding, and assignment patches
    $allDelegatedScopes = @(
        "DeviceManagementServiceConfig.ReadWrite.All",
        "DeviceManagementConfiguration.ReadWrite.All",
        "Group.ReadWrite.All",
        "DeviceManagementRBAC.ReadWrite.All"
    )

    # ── Phase 1: Reuse existing session if valid ──
    $mgContext = Get-MgContext
    if ($mgContext -and $mgContext.TenantId -eq $TenantId) {
        try {
            Invoke-MgGraphRequest -Method GET -Uri $intuneProbeUri -ErrorAction Stop | Out-Null
            Write-Success "Reusing existing Microsoft Graph session ($($mgContext.Account), Tenant: $($mgContext.TenantId))"
            $script:MgGraphIntuneSessionTenantId = $TenantId
            return $true
        }
        catch {
            Write-Info "Existing Graph session lacks Intune scopes — will re-authenticate"
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { $null = $null }
        }
    }
    elseif ($mgContext) {
        # Session exists but for a different tenant — disconnect
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { $null = $null }
    }

    # ── Phase 2: Try WAM (native Windows account picker popup) ──
    Write-Info "Connecting to Microsoft Graph with delegated Intune scopes..."
    Write-Info "A sign-in prompt will appear — sign in as Intune Admin or equivalent"

    $wamConnectOk = $false
    $isWin = if (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue) { $true } else { [System.Environment]::OSVersion.Platform -eq 'Win32NT' }
    $prevBrokerSetting = $env:MSAL_USE_BROKER
    if ($isWin) {
        # Explicitly enable WAM broker to get the native account picker popup
        # instead of a full browser window.  Microsoft.Graph.Authentication v2.25+
        # removed -UseWAM; the MSAL_USE_BROKER env var is the only control.
        $env:MSAL_USE_BROKER = '1'
        try {
            Connect-MgGraph `
                -Scopes $allDelegatedScopes `
                -TenantId $TenantId `
                -NoWelcome -ErrorAction Stop

            # Brief retry for Get-MgContext race condition in Graph SDK
            $mgContext = $null
            for ($retry = 0; $retry -lt 3; $retry++) {
                $mgContext = Get-MgContext
                if ($mgContext) { break }
                Start-Sleep -Milliseconds 500
            }

            # Validate with Intune probe — WAM may return a cached token without DeviceManagement claims
            Invoke-MgGraphRequest -Method GET -Uri $intuneProbeUri -ErrorAction Stop | Out-Null
            $wamConnectOk = $true

            if ($mgContext) {
                Write-Success "Connected to Microsoft Graph as $($mgContext.Account) (Tenant: $($mgContext.TenantId))"
            }
        }
        catch {
            $wamError = Get-CleanErrorMessage $_
            # Only fall back if connect itself failed, not just the probe
            $mgCtxCheck = Get-MgContext
            if ($mgCtxCheck -and $mgCtxCheck.TenantId -eq $TenantId) {
                # WAM connected but probe failed — token lacks Intune claims.
                # Disconnect so Phase 3 can get a fresh token with proper scopes.
                Write-Info "WAM connected but token lacks Intune scopes — will retry with browser auth"
            }
            else {
                Write-Info "WAM authentication failed ($wamError) — falling back to browser auth"
            }
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { $null = $null }
        }
    }

    # ── Phase 3: Browser fallback (MSAL_USE_BROKER=0) ──
    if (-not $wamConnectOk) {
        $env:MSAL_USE_BROKER = '0'
        try {
            if (-not $isWin) {
                Write-Info "Connecting to Microsoft Graph with delegated Intune scopes..."
                Write-Info "A browser sign-in prompt will appear — sign in as Intune Admin or equivalent"
            }
            else {
                Write-Info "Retrying with browser-based auth to get a token with full Intune claims..."
            }

            Connect-MgGraph `
                -Scopes $allDelegatedScopes `
                -TenantId $TenantId `
                -NoWelcome -ErrorAction Stop

            $mgContext = $null
            for ($retry = 0; $retry -lt 3; $retry++) {
                $mgContext = Get-MgContext
                if ($mgContext) { break }
                Start-Sleep -Milliseconds 500
            }

            Invoke-MgGraphRequest -Method GET -Uri $intuneProbeUri -ErrorAction Stop | Out-Null

            if ($mgContext) {
                Write-Success "Connected to Microsoft Graph as $($mgContext.Account) (Tenant: $($mgContext.TenantId))"
            }

            $script:MgGraphIntuneSessionTenantId = $TenantId
            return $true
        }
        catch {
            Write-Err "Could not obtain a working Intune token: $(Get-CleanErrorMessage $_)"
        }
        finally {
            if ($null -eq $prevBrokerSetting) { Remove-Item Env:\MSAL_USE_BROKER -ErrorAction SilentlyContinue }
            else { $env:MSAL_USE_BROKER = $prevBrokerSetting }
        }

        # All phases failed
        Write-Err "Intune backend rejected the token. See troubleshooting steps below."
        Write-Host ""
        Write-Host "  This typically means one of:" -ForegroundColor Yellow
        Write-Host "    1. Admin consent has not been granted for the Microsoft Graph PowerShell app." -ForegroundColor Yellow
        Write-Host "       Fix: Entra ID > Enterprise Applications > 'Microsoft Graph Command Line Tools'" -ForegroundColor Yellow
        Write-Host "            > Permissions > Grant admin consent for these scopes:" -ForegroundColor Yellow
        Write-Host "            DeviceManagementServiceConfig.ReadWrite.All" -ForegroundColor Yellow
        Write-Host "            DeviceManagementConfiguration.ReadWrite.All" -ForegroundColor Yellow
        Write-Host "            DeviceManagementRBAC.ReadWrite.All" -ForegroundColor Yellow
        Write-Host "            Group.ReadWrite.All" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    2. The signed-in user lacks the Intune Administrator role or an Intune license." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    3. WAM/MSAL returned a cached token without Intune claims." -ForegroundColor Yellow
        Write-Host "       Fix: Run  Disconnect-MgGraph  then re-run this script." -ForegroundColor Yellow
        return $false
    }

    # WAM succeeded — restore broker setting and return
    if ($null -eq $prevBrokerSetting) { Remove-Item Env:\MSAL_USE_BROKER -ErrorAction SilentlyContinue }
    else { $env:MSAL_USE_BROKER = $prevBrokerSetting }
    $script:MgGraphIntuneSessionTenantId = $TenantId
    return $true
}

function Test-MgGraphIntuneSession {
    <#
    .SYNOPSIS
        Validates that the current MgGraph session is still alive and has
        working Intune scopes for the specified tenant. If the session is
        for a different tenant, attempts to re-connect (which may show
        the WAM popup once for the new tenant).
    #>
    param(
        [Parameter(Mandatory)]
        [string]$TenantId
    )

    $intuneProbeUri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?`$top=1&`$select=id"

    # Fast path: session already established for this tenant
    if ($script:MgGraphIntuneSessionTenantId -eq $TenantId) {
        $mgContext = Get-MgContext
        if ($mgContext -and $mgContext.TenantId -eq $TenantId) {
            try {
                Invoke-MgGraphRequest -Method GET -Uri $intuneProbeUri -ErrorAction Stop | Out-Null
                return $true
            }
            catch {
                Write-Info "Graph session expired — re-authenticating..."
            }
        }
    }

    # Session is for a different tenant or expired — establish a new one
    return (Connect-MgGraphForIntune -TenantId $TenantId)
}

function Invoke-ADOLogin {
    <#
    .SYNOPSIS
        Acquires an Azure DevOps bearer token and sets AZURE_DEVOPS_EXT_PAT so
        all az devops / az repos / az pipelines commands authenticate without
        triggering silent credential prompts that hang the script.
    #>
    Write-Info "Acquiring Azure DevOps access token..."

    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $adoToken = az account get-access-token `
            --scope "499b84ac-1321-427f-aa17-267ca6975798/.default" `
            --query accessToken -o tsv 2>$null
    }
    finally { $ErrorActionPreference = $prevEAP }

    if ($adoToken) {
        $env:AZURE_DEVOPS_EXT_PAT = $adoToken
        Write-Success "Azure DevOps access token acquired"
        return $true
    }

    # Token acquisition failed — trigger interactive login and retry
    Write-Warn "Cannot obtain Azure DevOps token with current session. Launching interactive login..."
    az account clear 2>$null

    $loginArgs = @('login')
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $loginArgs += '--tenant'
        $loginArgs += $TenantId
    }
    az @loginArgs --only-show-errors | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Azure login failed. Run 'az login' manually and re-run this script."
        return $false
    }

    # Re-set subscription after fresh login
    if (-not [string]::IsNullOrWhiteSpace($AzureSubscriptionId)) {
        az account set --subscription $AzureSubscriptionId --only-show-errors
    }

    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $adoToken = az account get-access-token `
            --scope "499b84ac-1321-427f-aa17-267ca6975798/.default" `
            --query accessToken -o tsv 2>$null
    }
    finally { $ErrorActionPreference = $prevEAP }

    if ($adoToken) {
        $env:AZURE_DEVOPS_EXT_PAT = $adoToken
        Write-Success "Azure DevOps access token acquired after re-login"
        return $true
    }

    Write-Err "Still cannot obtain Azure DevOps token. Verify your account has access to '$ADOOrganization'."
    return $false
}

function Get-ADOOrgGuid {
    <#
    .SYNOPSIS
        Retrieves the Azure DevOps organization GUID needed for Workload Identity Federation.
    #>
    Write-Info "Retrieving ADO organization GUID..."

    # Approach 1: get an ADO bearer token and call the connectionData REST API.
    # Uses --scope (--resource is deprecated in az CLI 2.61+).
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $token = az account get-access-token `
            --scope "499b84ac-1321-427f-aa17-267ca6975798/.default" `
            --query accessToken -o tsv 2>$null
    }
    finally { $ErrorActionPreference = $prevEAP }

    if ($token) {
        try {
            $headers = @{ "Authorization" = "Bearer $token" }
            $connData = Invoke-RestMethod -Uri "$($script:ADOBaseUrl)/_apis/connectionData" `
                -Headers $headers -TimeoutSec 30
            if ($connData -and $connData.instanceId) {
                return $connData.instanceId
            }
        }
        catch {
            Write-Warn "connectionData REST call failed: $(Get-CleanErrorMessage $_)"
        }
    }

    # Approach 2: use az devops invoke (relies on az CLI auth).
    try {
        $prevEAP2 = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $raw = az devops invoke `
                --area "connectionData" --resource "" `
                --org $script:ADOBaseUrl --api-version "7.1" `
                -o json 2>$null
        }
        finally { $ErrorActionPreference = $prevEAP2 }

        if ($raw) {
            $result = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($result -and $result.instanceId) {
                return $result.instanceId
            }
        }
    }
    catch {
        Write-Warn "az devops invoke failed: $(Get-CleanErrorMessage $_)"
    }

    return $null
}

function Set-ADOBilling {
    <#
    .SYNOPSIS
        Associates an Azure subscription with the ADO organization for billing.
        If a subscription is already linked, reports that and returns.
        If no subscription is provided and multiple are available, prompts the user.
        If only one subscription is available, auto-selects it.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Write-StepHeader "AZURE DEVOPS BILLING (SUBSCRIPTION ASSOCIATION)"

    # Need both an ADO bearer token and an Azure management token
    $adoToken = $env:AZURE_DEVOPS_EXT_PAT
    if (-not $adoToken) {
        Write-Warn "No ADO access token available — skipping billing setup."
        return
    }

    $adoHeaders = @{
        "Authorization" = "Bearer $adoToken"
        "Content-Type"  = "application/json"
    }

    # ── Check current billing status ──
    Write-Info "Checking current billing configuration..."
    $orgId = $null
    try {
        $connData = Invoke-RestMethod -Uri "$($script:ADOBaseUrl)/_apis/connectionData" `
            -Headers $adoHeaders -TimeoutSec 30
        $orgId = $connData.instanceId
    }
    catch {
        Write-Warn "Could not retrieve organization info: $(Get-CleanErrorMessage $_)"
        return
    }

    if (-not $orgId) {
        Write-Warn "Could not determine organization GUID — skipping billing setup."
        return
    }

    # Query existing billing subscription via multiple API approaches
    $billingSubId = $null

    # Approach 1: Check if pipelines have already run — if so, billing is functional
    # (either already configured, or not required for self-hosted agents)
    try {
        # Use GET-only headers (no Content-Type) for the builds query
        $getHeaders = @{ "Authorization" = "Bearer $adoToken" }
        $buildsUri = "$($script:ADOBaseUrl)/$($script:ADOProjectName)/_apis/build/builds" + '?$top=1&api-version=7.1'
        $buildsResp = Invoke-RestMethod -Uri $buildsUri -Headers $getHeaders -TimeoutSec 30
        if ($buildsResp -and $buildsResp.PSObject.Properties['count'] -and [int]$buildsResp.count -gt 0) {
            Write-Success "Billing is already functional — pipelines have run successfully"
            return
        }
    }
    catch {
        Write-Info "Could not check pipeline history: $(Get-CleanErrorMessage $_)"
    }

    # Approach 2: Commerce subscription API
    try {
        $billingResp = Invoke-RestMethod `
            -Uri "https://app.vsaex.visualstudio.com/_apis/commerce/subscription?organizationId=$orgId&api-version=7.1-preview.1" `
            -Headers $adoHeaders -TimeoutSec 30
        if ($billingResp -and $billingResp.subscriptionId -and
            $billingResp.subscriptionId -ne '00000000-0000-0000-0000-000000000000') {
            $billingSubId = $billingResp.subscriptionId
        }
    }
    catch {
        # API may not exist or return 404 — continue to attempt setup
        Write-Verbose "Commerce subscription API not available: $($_.Exception.Message)"
    }

    if ($billingSubId) {
        Write-Success "Billing is already configured — subscription: $billingSubId"
        return
    }

    # ── Determine which Azure subscription to link ──
    $targetSubId = $null
    $targetSubName = $null

    if (-not [string]::IsNullOrWhiteSpace($script:AzureSubscriptionId)) {
        # A subscription is already resolved from the Azure setup step
        $targetSubId = $script:AzureSubscriptionId
        $targetSubName = $script:AzureSubscriptionName
    }
    else {
        # Query available subscriptions from Az CLI
        $allSubs = az account list --query "[?state=='Enabled']" -o json 2>$null | ConvertFrom-Json
        if (-not $allSubs -or $allSubs.Count -eq 0) {
            Write-Warn "No enabled Azure subscriptions found — skipping billing setup."
            Write-Info "Log in with 'az login' and ensure you have at least one enabled subscription."
            return
        }

        if ($allSubs.Count -eq 1) {
            $targetSubId = $allSubs[0].id
            $targetSubName = $allSubs[0].name
            Write-Info "Single subscription detected — auto-selecting: $targetSubName ($targetSubId)"
        }
        else {
            Write-Host ""
            Write-Host "  Multiple Azure subscriptions available for billing:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $allSubs.Count; $i++) {
                $marker = if ($allSubs[$i].isDefault) { " (current)" } else { "" }
                Write-Host "    [$($i + 1)] $($allSubs[$i].name) ($($allSubs[$i].id))$marker" -ForegroundColor White
            }
            Write-Host ""
            do {
                $selection = Read-Host "  Select a subscription for ADO billing (1-$($allSubs.Count))"
                $selIndex = 0
                $validSelection = [int]::TryParse($selection, [ref]$selIndex) -and $selIndex -ge 1 -and $selIndex -le $allSubs.Count
                if (-not $validSelection) {
                    Write-Warn "Invalid selection. Enter a number between 1 and $($allSubs.Count)."
                }
            } while (-not $validSelection)

            $chosen = $allSubs[$selIndex - 1]
            $targetSubId = $chosen.id
            $targetSubName = $chosen.name
        }
    }

    if (-not $targetSubId) {
        Write-Warn "No subscription selected — skipping billing setup."
        return
    }

    # ── Associate the subscription with the ADO org ──
    Write-Info "Associating subscription '$targetSubName' ($targetSubId) with ADO organization '$ADOOrganization'..."

    # The billing setup uses the Azure management API to link the subscription
    # to the ADO organization via the Microsoft.VisualStudio resource provider.
    $mgmtToken = $null
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $mgmtToken = az account get-access-token `
            --resource "https://management.core.windows.net/" `
            --query accessToken -o tsv 2>$null
    }
    finally { $ErrorActionPreference = $prevEAP }

    if (-not $mgmtToken) {
        Write-Warn "Could not acquire Azure management token — skipping billing setup."
        Write-Info "Ensure you are logged in with 'az login' and have Contributor/Owner on the subscription."
        return
    }

    $mgmtHeaders = @{
        "Authorization" = "Bearer $mgmtToken"
        "Content-Type"  = "application/json"
    }

    # Ensure the Microsoft.VisualStudio resource provider is registered
    try {
        Write-Info "Ensuring Microsoft.VisualStudio resource provider is registered..."
        Invoke-RestMethod `
            -Uri "https://management.azure.com/subscriptions/$targetSubId/providers/Microsoft.VisualStudio/register?api-version=2021-04-01" `
            -Method POST -Headers $mgmtHeaders -TimeoutSec 60 | Out-Null
        Write-Success "Resource provider Microsoft.VisualStudio registered (or already registered)"
    }
    catch {
        Write-Warn "Could not register Microsoft.VisualStudio resource provider: $(Get-CleanErrorMessage $_)"
        Write-Info "You may need to register it manually: az provider register --namespace Microsoft.VisualStudio"
    }

    # Set billing via the Commerce SetBilling API
    $billingBody = @{
        "azureSubscriptionId" = $targetSubId
        "organizationId"      = $orgId
    } | ConvertTo-Json -Compress

    try {
        Invoke-RestMethod `
            -Uri "https://app.vsaex.visualstudio.com/_apis/commerce/subscription?api-version=7.1-preview.1" `
            -Method PUT -Headers $adoHeaders -Body $billingBody -TimeoutSec 60 | Out-Null
        Write-Success "Azure subscription '$targetSubName' ($targetSubId) associated with ADO organization '$ADOOrganization'"
    }
    catch {
        $cleanErr = Get-CleanErrorMessage $_
        # Downgrade to warning — billing association is non-blocking
        # (self-hosted agents don't require billing, and if pipelines already
        # run then billing is already configured via a different mechanism)
        Write-Warn "Could not associate subscription with ADO organization: $cleanErr"
        Write-Info "This is non-blocking if pipelines already run on self-hosted agents."
        Write-Info "To set up billing manually: ADO Org Settings > Billing > Set up billing"
    }
}

# ─────────────────────────────────────────────────────────────
# PREREQUISITES
# ─────────────────────────────────────────────────────────────
function Install-Prerequisites {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Installs multiple prerequisite tools')]
    [CmdletBinding()]
    param()
    Write-StepHeader "CHECKING & INSTALLING PREREQUISITES"

    $script:RestartRequired = $false

    $prerequisites = @(
        @{ Name = "PowerShell 7"; Command = "pwsh"; WingetId = "Microsoft.PowerShell" }
        @{ Name = "Git for Windows"; Command = "git"; WingetId = "Git.Git" }
        @{ Name = "Azure CLI"; Command = "az"; WingetId = "Microsoft.AzureCLI" }
    )

    # Check winget availability
    $hasWinget = Test-CommandExists "winget"
    if (-not $hasWinget) {
        Write-Warn "winget is not available. You may need to install prerequisites manually."
    }

    foreach ($prereq in $prerequisites) {
        if (Test-CommandExists $prereq.Command) {
            # Temporarily allow non-terminating errors so az CLI stderr warnings
            # (e.g. "You have N update(s) available") don't throw a RemoteException
            $prevEAP = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try { $versionOutput = & $prereq.Command --version 2>$null | Out-String }
            finally { $ErrorActionPreference = $prevEAP }

            $versionLine = ($versionOutput -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch 'WARNING:' } | Select-Object -First 1).Trim()
            Write-Success "$($prereq.Name) is installed ($versionLine)"

            # Azure CLI: detect available updates and offer interactive upgrade
            if ($prereq.Command -eq 'az' -and $versionOutput -match '(\d+) update\(s\) available') {
                $updateCount = $Matches[1]
                Write-Warn "Azure CLI has $updateCount update(s) available."
                Write-Info "An outdated Azure CLI can cause authentication failures or missing features."
                $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)
                if (-not $isElevated) {
                    Write-Warn "This session is NOT running elevated. A UAC prompt will appear — approve it to continue the upgrade."
                }
                Write-Host ""
                $upgradeChoice = Read-Host "  Upgrade Azure CLI now? (Y/n)"
                if ($upgradeChoice -eq '' -or $upgradeChoice -match '^[Yy]') {
                    if ($hasWinget) {
                        Write-Info "Upgrading Azure CLI via winget (silent, timeout: 10 minutes)..."
                        $proc = Start-Process -FilePath 'winget' `
                            -ArgumentList 'upgrade', '--id', 'Microsoft.AzureCLI', '--silent',
                        '--accept-source-agreements', '--accept-package-agreements' `
                            -NoNewWindow -PassThru -Wait:$false
                        $completed = $proc.WaitForExit(600000)  # 10 minutes in milliseconds
                        if (-not $completed) {
                            try { $proc.Kill() } catch {
                                # Intentionally suppressed — process may have already exited
                                $null = $null
                            }
                            Write-Err "Azure CLI upgrade timed out after 10 minutes. Run 'winget upgrade --id Microsoft.AzureCLI' manually and re-run this script."
                            exit 1
                        }
                        if ($proc.ExitCode -eq 0) {
                            # Refresh PATH so the new az version is picked up in this session
                            $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                            [System.Environment]::GetEnvironmentVariable('Path', 'User')
                            $prevEAP2 = $ErrorActionPreference
                            $ErrorActionPreference = "Continue"
                            try { $newVersion = (az version -o json 2>$null | ConvertFrom-Json).'azure-cli' }
                            finally { $ErrorActionPreference = $prevEAP2 }
                            Write-Success "Azure CLI upgraded to $newVersion"
                        }
                        else {
                            Write-Warn "Azure CLI upgrade did not complete (exit code $($proc.ExitCode)). You can run 'winget upgrade --id Microsoft.AzureCLI' manually later."
                        }
                    }
                    else {
                        Write-Warn "winget is not available — cannot perform a silent upgrade."
                        Write-Info "Please upgrade Azure CLI manually: https://aka.ms/installazurecliwindows"
                    }
                }
                else {
                    Write-Info "Skipping Azure CLI upgrade. If you encounter auth errors, run 'az upgrade' and retry."
                }
            }
        }
        else {
            Write-Warn "$($prereq.Name) is NOT installed."
            if ($hasWinget) {
                Write-Info "Installing $($prereq.Name) via winget..."
                $installResult = Invoke-CommandSafe -ScriptBlock {
                    winget install --id $prereq.WingetId --accept-source-agreements --accept-package-agreements --silent 2>&1
                } -ErrorMessage "Failed to install $($prereq.Name)"
                if ($installResult) {
                    # Refresh PATH and check if the command is now available
                    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                    [System.Environment]::GetEnvironmentVariable('Path', 'User')
                    if (Test-CommandExists $prereq.Command) {
                        Write-Success "$($prereq.Name) installed and available."
                    }
                    else {
                        Write-Success "$($prereq.Name) installed."
                        Write-Warn "'$($prereq.Command)' is not yet on PATH — a PowerShell session restart is required."
                        $script:RestartRequired = $true
                    }
                }
            }
            else {
                Write-Err "$($prereq.Name) must be installed manually. Download from the official website."
            }
        }
    }

    # Check VS Code — accept either stable or Insiders edition
    $hasCodeInsiders = Test-CommandExists "code-insiders"
    $hasCode = Test-CommandExists "code"
    if ($hasCodeInsiders) {
        $version = & code-insiders --version 2>$null | Select-Object -First 1
        Write-Success "VS Code Insiders is installed ($version)"
    }
    elseif ($hasCode) {
        $version = & code --version 2>$null | Select-Object -First 1
        Write-Success "VS Code is installed ($version)"
    }
    else {
        Write-Warn "VS Code is NOT installed."
        if ($hasWinget) {
            Write-Info "Installing VS Code via winget..."
            $installResult = Invoke-CommandSafe -ScriptBlock {
                winget install --id Microsoft.VisualStudioCode --accept-source-agreements --accept-package-agreements --silent 2>&1
            } -ErrorMessage "Failed to install VS Code"
            if ($installResult) {
                $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path', 'User')
                if ((Test-CommandExists 'code') -or (Test-CommandExists 'code-insiders')) {
                    Write-Success "VS Code installed and available."
                }
                else {
                    Write-Success "VS Code installed."
                    Write-Warn "'code' is not yet on PATH — a PowerShell session restart is required."
                    $script:RestartRequired = $true
                }
            }
        }
        else {
            Write-Err "VS Code must be installed manually. Download from https://code.visualstudio.com"
        }
    }

    # Confirm PowerShell version
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        Write-Success "PowerShell $($PSVersionTable.PSVersion) detected"
    }
    else {
        Write-Info "Running PowerShell $($PSVersionTable.PSVersion) (prerequisites mode only)"
    }

    # Check/install Azure DevOps CLI extension (skip if az CLI is not yet available)
    if (Test-CommandExists 'az') {
        Write-Info "Checking Azure CLI DevOps extension..."
        $extensions = az extension list -o json 2>$null | ConvertFrom-Json
        $devopsExt = $extensions | Where-Object { $_.name -eq "azure-devops" }
        if ($devopsExt) {
            Write-Success "Azure DevOps CLI extension is installed"
        }
        else {
            Write-Info "Installing Azure DevOps CLI extension..."
            az extension add --name azure-devops --only-show-errors 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Azure DevOps CLI extension installed"
            }
            else {
                Write-Err "Failed to install azure-devops CLI extension"
            }
        }
    }
    else {
        Write-Warn "Azure CLI not available — skipping DevOps extension check (will be installed on next run)"
    }

    # Check/install PowerShell modules (Graph SDK no longer needed — native REST API used)
    $requiredModules = @("Az.ManagedServiceIdentity", "Microsoft.Graph.Authentication")
    foreach ($modName in $requiredModules) {
        $mod = Get-Module -ListAvailable -Name $modName | Select-Object -First 1
        if ($mod) {
            Write-Success "PowerShell module '$modName' is installed (v$($mod.Version))"
        }
        else {
            Write-Info "Installing PowerShell module '$modName'..."
            try {
                Install-Module -Name $modName -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
                Write-Success "PowerShell module '$modName' installed"
            }
            catch {
                Write-Err "Failed to install PowerShell module '$modName': $_"
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────
# AZURE SETUP: Resource Group + UAMIs + Graph Permissions + Federation
# ─────────────────────────────────────────────────────────────
function Invoke-AzLogin {
    <#
    .SYNOPSIS
        Validates the current Azure CLI session and triggers interactive login if the token is expired or missing.
    #>
    Write-Info "Validating Azure CLI session..."

    # az account show returns cached info even with an expired token,
    # so we must request an actual access token to verify the session is live.
    # Temporarily allow non-terminating errors so stderr messages (e.g. expired-token
    # AADSTS errors) don't throw a RemoteException under $ErrorActionPreference = 'Stop'.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $tokenJson = az account get-access-token --scope https://management.core.windows.net/.default -o json 2>$null
        $token = $tokenJson | ConvertFrom-Json -ErrorAction SilentlyContinue
    }
    finally { $ErrorActionPreference = $prevEAP }

    if ($token -and $token.accessToken) {
        Write-Success "Azure CLI session is valid"
        return $true
    }

    # Token expired or no session — clear stale cache and trigger interactive login.
    # Clearing first avoids "Found multiple accounts with the same username" errors
    # when the MSAL cache contains entries for the same UPN across different tenants.
    Write-Info "Azure CLI session is expired or not present. Clearing account cache..."
    az account clear 2>$null

    Write-Info "Launching interactive login..."
    $loginArgs = @('login')
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $loginArgs += '--tenant'
        $loginArgs += $TenantId
    }
    az @loginArgs --only-show-errors | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Azure login failed. Please run 'az login' manually and re-run this script."
        return $false
    }
    Write-Success "Azure login successful"
    return $true
}

function New-AzureResources {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Creates multiple Azure resources')]
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Write-StepHeader "AZURE SIGN-IN & SUBSCRIPTION"

    # Validate session and trigger interactive login if token is expired
    $loginOk = Invoke-AzLogin
    if (-not $loginOk) { return }

    # Set subscription — prompt if not specified and multiple are available
    if (-not [string]::IsNullOrWhiteSpace($AzureSubscriptionId)) {
        Write-Info "Setting subscription to $AzureSubscriptionId..."
        az account set --subscription $AzureSubscriptionId --only-show-errors
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to set subscription '$AzureSubscriptionId'. Verify the ID is correct and your account has access."
            return
        }
    }
    else {
        # No subscription specified — check how many are available
        $allSubs = az account list --query "[?state=='Enabled']" -o json 2>$null | ConvertFrom-Json
        if ($allSubs -and $allSubs.Count -gt 1) {
            Write-Warn "No subscription specified and $($allSubs.Count) subscriptions detected."
            Write-Host ""
            Write-Host "  Available subscriptions:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $allSubs.Count; $i++) {
                $marker = if ($allSubs[$i].isDefault) { " (current)" } else { "" }
                Write-Host "    [$($i + 1)] $($allSubs[$i].name) ($($allSubs[$i].id))$marker" -ForegroundColor White
            }
            Write-Host ""
            do {
                $selection = Read-Host "  Select a subscription (1-$($allSubs.Count))"
                $selIndex = 0
                $validSelection = [int]::TryParse($selection, [ref]$selIndex) -and $selIndex -ge 1 -and $selIndex -le $allSubs.Count
                if (-not $validSelection) {
                    Write-Warn "Invalid selection. Enter a number between 1 and $($allSubs.Count)."
                }
            } while (-not $validSelection)

            $chosen = $allSubs[$selIndex - 1]
            $AzureSubscriptionId = $chosen.id
            $AzureSubscriptionName = $chosen.name
            $script:AzureSubscriptionName = $chosen.name
            Write-Info "Setting subscription to $($chosen.name)..."
            az account set --subscription $chosen.id --only-show-errors
            if ($LASTEXITCODE -ne 0) {
                Write-Err "Failed to set subscription '$($chosen.id)'."
                return
            }
        }
    }

    $account = az account show -o json 2>$null | ConvertFrom-Json
    if (-not $account) {
        Write-Err "Cannot read Azure account details. Run 'az login' and try again."
        return
    }

    $script:AzureSubscriptionId = $account.id
    if ([string]::IsNullOrWhiteSpace($AzureSubscriptionName)) {
        $script:AzureSubscriptionName = $account.name
    }

    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        $script:TenantId = $account.tenantId
        Write-Info "Using tenant from current session: $($script:TenantId)"
    }

    Write-Success "Subscription: $($script:AzureSubscriptionName) ($($script:AzureSubscriptionId))"
    Write-Success "Tenant:       $($script:TenantId)"

    # ── Build per-environment configuration ──
    $script:EnvConfigs = @{}
    foreach ($envName in @("dev", "staging", "production")) {
        switch ($envName) {
            "dev" {
                $script:EnvConfigs[$envName] = @{
                    TenantId         = if ($DevTenantId) { $DevTenantId } else { $script:TenantId }
                    SubscriptionId   = if ($DevSubscriptionId) { $DevSubscriptionId } else { $script:AzureSubscriptionId }
                    SubscriptionName = if ($DevSubscriptionName) { $DevSubscriptionName } else { $script:AzureSubscriptionName }
                }
            }
            "staging" {
                $script:EnvConfigs[$envName] = @{
                    TenantId         = if ($StagingTenantId) { $StagingTenantId } else { $script:TenantId }
                    SubscriptionId   = if ($StagingSubscriptionId) { $StagingSubscriptionId } else { $script:AzureSubscriptionId }
                    SubscriptionName = if ($StagingSubscriptionName) { $StagingSubscriptionName } else { $script:AzureSubscriptionName }
                }
            }
            "production" {
                $script:EnvConfigs[$envName] = @{
                    TenantId         = $script:TenantId
                    SubscriptionId   = $script:AzureSubscriptionId
                    SubscriptionName = $script:AzureSubscriptionName
                }
            }
        }
    }

    # Display cross-tenant configuration
    foreach ($envName in $Environments) {
        $cfg = $script:EnvConfigs[$envName]
        if ($cfg.TenantId -ne $script:TenantId) {
            Write-Info "  $($envName): Tenant=$($cfg.TenantId), Subscription=$($cfg.SubscriptionName)"
        }
    }

    # ── Group active environments by tenant for efficient provisioning ──
    $tenantGroups = [ordered]@{}
    foreach ($env in $Environments) {
        $tid = $script:EnvConfigs[$env].TenantId
        if (-not $tenantGroups.Contains($tid)) { $tenantGroups[$tid] = @() }
        $tenantGroups[$tid] += $env
    }

    $uamiDetails = @{}
    $currentTenant = $account.tenantId

    foreach ($tid in $tenantGroups.Keys) {
        $envsForTenant = $tenantGroups[$tid]

        # Switch tenant if needed
        if ($tid -ne $currentTenant) {
            Write-Host ""
            Write-Info "Switching to tenant '$tid' for environments: $($envsForTenant -join ', ')"
            Write-Info "You may be prompted to authenticate..."
            az login --tenant $tid --only-show-errors | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-Err "Could not login to tenant '$tid' — skipping environments: $($envsForTenant -join ', ')"
                continue
            }
            $currentTenant = $tid
        }

        $tenantSubId = $script:EnvConfigs[$envsForTenant[0]].SubscriptionId
        az account set --subscription $tenantSubId --only-show-errors
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to set subscription '$tenantSubId' in tenant '$tid'"
            continue
        }

        $tenantLabel = if ($tenantGroups.Count -gt 1) { " (Tenant: $($tid.Substring(0,8))...)" } else { "" }

        # ── Create Resource Group ──
        Write-StepHeader "CREATING RESOURCE GROUP$tenantLabel"
        $existingRg = az group show --name $ResourceGroupName -o json 2>$null | ConvertFrom-Json
        if ($existingRg) {
            Write-Success "Resource group '$ResourceGroupName' already exists in $($existingRg.location)"
        }
        else {
            Write-Info "Creating resource group '$ResourceGroupName' in '$AzureRegion'..."
            az group create --name $ResourceGroupName --location $AzureRegion --only-show-errors -o none
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Resource group '$ResourceGroupName' created"
            }
            else {
                Write-Err "Failed to create resource group '$ResourceGroupName'"
                continue
            }
        }

        # ── Create UAMIs ──
        Write-StepHeader "CREATING USER-ASSIGNED MANAGED IDENTITIES$tenantLabel"

        foreach ($env in $envsForTenant) {
            $uamiName = "uami-intune-cicd-$env"
            Write-Progress2 -Activity $env -Status "Creating UAMI '$uamiName'..."

            $existing = az identity show --name $uamiName --resource-group $ResourceGroupName -o json 2>$null | ConvertFrom-Json
            if ($existing) {
                Write-Success "UAMI '$uamiName' already exists (ClientId: $($existing.clientId))"
                $uamiDetails[$env] = @{
                    ClientId    = $existing.clientId
                    PrincipalId = $existing.principalId
                    Name        = $uamiName
                }
            }
            else {
                $result = az identity create --name $uamiName --resource-group $ResourceGroupName --location $AzureRegion -o json 2>$null | ConvertFrom-Json
                if ($result) {
                    Write-Success "UAMI '$uamiName' created (ClientId: $($result.clientId))"
                    $uamiDetails[$env] = @{
                        ClientId    = $result.clientId
                        PrincipalId = $result.principalId
                        Name        = $uamiName
                    }
                }
                else {
                    Write-Err "Failed to create UAMI '$uamiName'"
                }
            }
        }

        # ── Create App Registrations for Graph API (OIDC / Workload Identity Federation) ──
        Write-StepHeader "CREATING APP REGISTRATIONS FOR GRAPH API$tenantLabel"
        Write-Info "Each environment gets its own app registration with Graph API permissions."
        Write-Info "Federated credentials enable OIDC token exchange from ADO — no client secrets needed."
        Write-Info "This requires Privileged Role Administrator (minimum) or Global Administrator rights."

        # Acquire a Graph bearer token once
        Write-Info "Acquiring Microsoft Graph access token..."
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $graphToken = az account get-access-token `
                --scope "https://graph.microsoft.com/.default" `
                --query accessToken -o tsv 2>$null
        }
        finally { $ErrorActionPreference = $prevEAP }

        if (-not $graphToken) {
            Write-Err "Could not acquire Microsoft Graph access token. Ensure you are logged in with sufficient permissions."
            continue
        }
        $graphHeaders = @{ "Authorization" = "Bearer $graphToken" }

        # Retrieve Graph service principal ID and app roles
        Write-Info "Retrieving Microsoft Graph service principal..."
        $graphSp = $null
        try {
            $graphSp = Invoke-RestMethod `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles" `
                -Headers $graphHeaders -TimeoutSec 30
        }
        catch {
            $caeRetried = $false
            # Detect Continuous Access Evaluation (CAE) challenge — token was acquired
            # but invalidated by updated tenant policies. Force re-login and retry.
            $errDetail = "$($_.ErrorDetails.Message)"
            if ($errDetail -match 'Continuous access evaluation' -or
                $errDetail -match 'InteractionRequired' -or
                $errDetail -match 'TokenCreatedWithOutdatedPolicies') {
                Write-Warn "Graph token rejected by Continuous Access Evaluation (CAE). Re-authenticating..."
                az account clear 2>$null
                $loginArgs = @('login')
                if (-not [string]::IsNullOrWhiteSpace($tid)) {
                    $loginArgs += '--tenant'
                    $loginArgs += $tid
                }
                az @loginArgs --only-show-errors | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $tenantSubId2 = $script:EnvConfigs[$envsForTenant[0]].SubscriptionId
                    az account set --subscription $tenantSubId2 --only-show-errors
                    $prevEAP2 = $ErrorActionPreference
                    $ErrorActionPreference = "Continue"
                    try {
                        $graphToken = az account get-access-token `
                            --scope "https://graph.microsoft.com/.default" `
                            --query accessToken -o tsv 2>$null
                    }
                    finally { $ErrorActionPreference = $prevEAP2 }
                    if ($graphToken) {
                        $graphHeaders = @{ "Authorization" = "Bearer $graphToken" }
                        Write-Success "Graph token re-acquired after CAE re-authentication"
                        try {
                            $graphSp = Invoke-RestMethod `
                                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles" `
                                -Headers $graphHeaders -TimeoutSec 30
                            $caeRetried = $true
                        }
                        catch {
                            Write-Err "Graph API call failed after CAE re-auth: $(Get-CleanErrorMessage $_)"
                        }
                    }
                    else {
                        Write-Err "Could not re-acquire Graph token after CAE re-authentication"
                    }
                }
                else {
                    Write-Err "Interactive login failed during CAE re-authentication"
                }
            }
            if (-not $caeRetried) {
                Write-Err "Could not find Microsoft Graph service principal: $(Get-CleanErrorMessage $_)"
                continue
            }
        }
        if (-not $graphSp.value -or $graphSp.value.Count -eq 0) {
            Write-Err "Microsoft Graph service principal not found."
            continue
        }

        $graphSpId = $graphSp.value[0].id
        $appRoles = $graphSp.value[0].appRoles

        $permissions = @(
            "DeviceManagementConfiguration.ReadWrite.All",
            "DeviceManagementApps.ReadWrite.All",
            "DeviceManagementManagedDevices.ReadWrite.All",
            "DeviceManagementRBAC.ReadWrite.All",
            "DeviceManagementServiceConfig.ReadWrite.All",
            "DeviceManagementScripts.ReadWrite.All",
            "CloudPC.ReadWrite.All",
            "Group.ReadWrite.All",
            "Policy.ReadWrite.ConditionalAccess",
            "Policy.Read.All",
            "Application.Read.All",
            "Organization.Read.All"
        )

        # Build a lookup of required permission name → appRoleId
        $requiredRoles = @{}
        foreach ($permName in $permissions) {
            $role = $appRoles | Where-Object { $_.value -eq $permName }
            if (-not $role) {
                Write-Warn "Permission '$permName' not found in Graph app roles — skipping"
            }
            else {
                $requiredRoles[$permName] = $role.id
            }
        }

        $appDetails = @{}

        foreach ($env in $envsForTenant) {
            $appName = "app-intune-cicd-$env"
            Write-Progress2 -Activity $env -Status "Creating app registration '$appName'..."

            # Check if app registration already exists
            $existingApp = $null
            try {
                $appSearchResp = Invoke-RestMethod `
                    -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$appName'&`$select=id,appId,displayName" `
                    -Headers $graphHeaders -TimeoutSec 30
                if ($appSearchResp.value -and $appSearchResp.value.Count -gt 0) {
                    $existingApp = $appSearchResp.value[0]
                }
            }
            catch {
                Write-Warn "Could not search for existing app: $_"
            }

            if ($existingApp) {
                Write-Info "App registration '$appName' already exists (AppId: $($existingApp.appId))"
                $appClientId = $existingApp.appId
                $appObjectId = $existingApp.id
            }
            else {
                Write-Info "Creating app registration '$appName'..."
                try {
                    # Build required resource access for all Graph permissions
                    $resourceAccess = @()
                    foreach ($permName in $requiredRoles.Keys) {
                        $resourceAccess += @{ id = $requiredRoles[$permName]; type = "Role" }
                    }

                    $appBody = @{
                        displayName            = $appName
                        signInAudience         = "AzureADMyOrg"
                        requiredResourceAccess = @(
                            @{
                                resourceAppId  = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
                                resourceAccess = $resourceAccess
                            }
                        )
                    } | ConvertTo-Json -Depth 5 -Compress

                    $newApp = Invoke-RestMethod `
                        -Uri "https://graph.microsoft.com/v1.0/applications" `
                        -Method POST -Headers $graphHeaders `
                        -Body $appBody -ContentType "application/json" -TimeoutSec 30
                    $appClientId = $newApp.appId
                    $appObjectId = $newApp.id
                    Write-Success "Created app registration '$appName' (AppId: $appClientId)"
                }
                catch {
                    Write-Err "Failed to create app registration '$appName': $_"
                    continue
                }
            }

            # Ensure the app has a service principal
            $appSpId = $null
            try {
                $spResp = Invoke-RestMethod `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$appClientId'&`$select=id" `
                    -Headers $graphHeaders -TimeoutSec 30
                if ($spResp.value -and $spResp.value.Count -gt 0) {
                    $appSpId = $spResp.value[0].id
                    Write-Info "Service principal exists (ID: $appSpId)"
                }
            }
            catch {
                # Intentionally suppressed — service principal may not exist yet
                $null = $null
            }

            if (-not $appSpId) {
                try {
                    $spBody = @{ appId = $appClientId } | ConvertTo-Json -Compress
                    $newSp = Invoke-RestMethod `
                        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
                        -Method POST -Headers $graphHeaders `
                        -Body $spBody -ContentType "application/json" -TimeoutSec 30
                    $appSpId = $newSp.id
                    Write-Success "Created service principal (ID: $appSpId)"
                }
                catch {
                    Write-Err "Failed to create service principal for '$appName': $_"
                    continue
                }
            }

            $appDetails[$env] = @{
                ClientId = $appClientId
                ObjectId = $appObjectId
                SpId     = $appSpId
                Name     = $appName
            }

            # Grant Graph API permissions to the app registration's service principal
            Write-Progress2 -Activity $env -Status "Granting Graph permissions to '$appName'..."

            # Bulk-read existing assignments
            $existingRoleIds = @{}
            try {
                $assignmentsResp = Invoke-RestMethod `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSpId/appRoleAssignedTo?`$select=appRoleId,principalId&`$top=999" `
                    -Headers $graphHeaders -TimeoutSec 30
                if ($assignmentsResp -and $assignmentsResp.value) {
                    foreach ($a in $assignmentsResp.value) {
                        if ($a.principalId -eq $appSpId) {
                            $existingRoleIds[$a.appRoleId] = $true
                        }
                    }
                }
            }
            catch {
                Write-Warn "Could not read existing assignments: $_"
            }

            # Determine which permissions are missing
            $missing = @{}
            $alreadyCount = 0
            foreach ($permName in $requiredRoles.Keys) {
                if ($existingRoleIds.ContainsKey($requiredRoles[$permName])) {
                    $alreadyCount++
                }
                else {
                    $missing[$permName] = $requiredRoles[$permName]
                }
            }

            if ($alreadyCount -gt 0) {
                Write-Info "  $alreadyCount permission(s) already assigned"
            }

            if ($missing.Count -eq 0) {
                Write-Success "All permissions already assigned for '$appName'"
            }
            else {
                Write-Info "  $($missing.Count) permission(s) to grant..."

                # Use Microsoft Graph $batch endpoint
                $batchRequests = @()
                $idToName = @{}
                $reqIndex = 1
                foreach ($permName in $missing.Keys) {
                    $batchRequests += @{
                        id      = "$reqIndex"
                        method  = "POST"
                        url     = "/servicePrincipals/$graphSpId/appRoleAssignments"
                        headers = @{ "Content-Type" = "application/json" }
                        body    = @{
                            principalId = $appSpId
                            resourceId  = $graphSpId
                            appRoleId   = $missing[$permName]
                        }
                    }
                    $idToName["$reqIndex"] = $permName
                    $reqIndex++
                }

                try {
                    $batchHeaders = @{
                        "Authorization" = "Bearer $graphToken"
                        "Content-Type"  = "application/json"
                    }
                    $batchBody = @{ requests = $batchRequests } | ConvertTo-Json -Depth 5 -Compress
                    $batchResult = Invoke-RestMethod `
                        -Uri "https://graph.microsoft.com/v1.0/`$batch" `
                        -Method POST -Headers $batchHeaders `
                        -Body $batchBody -TimeoutSec 60

                    foreach ($resp in $batchResult.responses) {
                        $pName = $idToName[$resp.id]
                        if ($resp.status -ge 200 -and $resp.status -lt 300) {
                            Write-Info "  Granted: $pName"
                        }
                        elseif ($resp.body.error.message -match "Permission being assigned already exists") {
                            Write-Info "  Already assigned: $pName"
                        }
                        else {
                            Write-Warn "  Could not grant: $pName — $($resp.body.error.message)"
                        }
                    }
                }
                catch {
                    # Fallback: grant permissions individually
                    Write-Warn "Batch request failed: $_ — falling back to individual requests"
                    foreach ($permName in $missing.Keys) {
                        $body = @{
                            principalId = $appSpId
                            resourceId  = $graphSpId
                            appRoleId   = $missing[$permName]
                        } | ConvertTo-Json -Compress
                        try {
                            $postHeaders = @{
                                "Authorization" = "Bearer $graphToken"
                                "Content-Type"  = "application/json"
                            }
                            Invoke-RestMethod `
                                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSpId/appRoleAssignments" `
                                -Method POST -Headers $postHeaders `
                                -Body $body -TimeoutSec 30 | Out-Null
                            Write-Info "  Granted: $permName"
                        }
                        catch {
                            $errMsg = "$($_.ErrorDetails.Message)"
                            if ($errMsg -match "Permission being assigned already exists") {
                                Write-Info "  Already assigned: $permName"
                            }
                            else {
                                Write-Warn "  Could not grant: $permName — $_"
                            }
                        }
                    }
                }
                Write-Success "Graph permissions processed for '$appName'"
            }

            # Grant Reader role on the subscription so the AzureCLI task can set the subscription context.
            # The pipeline's AzureCLI@2 task does: az login (tenant-level) → az account set --subscription <id>
            # which fails without at least Reader on the target subscription.
            $envSubId = $script:EnvConfigs[$env].SubscriptionId
            if ($envSubId -and $appClientId) {
                Write-Progress2 -Activity $env -Status "Ensuring Reader role on subscription for '$appName'..."
                try {
                    $existingRole = az role assignment list `
                        --assignee $appClientId `
                        --role "Reader" `
                        --subscription $envSubId `
                        --scope "/subscriptions/$envSubId" `
                        -o json 2>$null | ConvertFrom-Json
                    if ($existingRole -and $existingRole.Count -gt 0) {
                        Write-Info "Reader role already assigned on subscription $envSubId"
                    }
                    else {
                        az role assignment create `
                            --assignee $appClientId `
                            --role "Reader" `
                            --subscription $envSubId `
                            --scope "/subscriptions/$envSubId" `
                            --only-show-errors | Out-Null
                        Write-Success "Granted Reader role on subscription $envSubId to '$appName'"
                    }
                }
                catch {
                    Write-Warn "Could not grant Reader role on subscription: $_"
                    Write-Info "  Grant manually: az role assignment create --assignee $appClientId --role Reader --subscription $envSubId"
                }
            }
        }

        # Store app details for use in service connection and variable group setup
        $script:AppRegistrationDetails = $appDetails

    } # end foreach tenant group

    # ── Switch back to production tenant if needed ──
    if ($currentTenant -ne $script:TenantId) {
        Write-Info "Switching back to production tenant..."
        az login --tenant $script:TenantId --only-show-errors | Out-Null
        az account set --subscription $script:AzureSubscriptionId --only-show-errors
    }

    # ── Return UAMI details for use in ADO setup ──
    return $uamiDetails
}

# ─────────────────────────────────────────────────────────────
# WORKLOAD IDENTITY FEDERATION (on App Registrations)
# ─────────────────────────────────────────────────────────────
function New-WorkloadIdentityFederation {
    [CmdletBinding(SupportsShouldProcess)]
    param([hashtable]$UamiDetails)

    Write-StepHeader "CREATING WORKLOAD IDENTITY FEDERATION CREDENTIALS"
    Write-Info "Federated credentials are created on app registrations (not UAMIs)"
    Write-Info "This enables OIDC token exchange: ADO → short-lived Graph token, no secrets needed."

    # Get ADO Org GUID
    $adoOrgGuid = Get-ADOOrgGuid
    if (-not $adoOrgGuid) {
        Write-Err "Could not retrieve ADO organization GUID. Federation credentials cannot be created."
        Write-Info "Manually find your org GUID at: $($script:ADOBaseUrl)/_apis/connectionData"
        return
    }
    Write-Success "ADO Organization GUID: $adoOrgGuid"

    if (-not $script:AppRegistrationDetails -or $script:AppRegistrationDetails.Count -eq 0) {
        Write-Warn "No app registration details available — skipping federation setup."
        return
    }

    $currentTenant = $script:TenantId
    foreach ($env in $Environments) {
        if (-not $script:AppRegistrationDetails.ContainsKey($env)) { continue }
        $appDetail = $script:AppRegistrationDetails[$env]

        # Switch to the environment's tenant/subscription if needed
        if ($script:EnvConfigs -and $script:EnvConfigs.ContainsKey($env)) {
            $envCfg = $script:EnvConfigs[$env]
            if ($envCfg.TenantId -ne $currentTenant) {
                Write-Info "Switching to tenant '$($envCfg.TenantId)' for $env federation..."
                az login --tenant $envCfg.TenantId --only-show-errors | Out-Null
                $currentTenant = $envCfg.TenantId
            }
            az account set --subscription $envCfg.SubscriptionId --only-show-errors
        }

        # Acquire Graph token for the current tenant
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $graphToken = az account get-access-token `
                --scope "https://graph.microsoft.com/.default" `
                --query accessToken -o tsv 2>$null
        }
        finally { $ErrorActionPreference = $prevEAP }

        if (-not $graphToken) {
            Write-Err "CRITICAL: Could not acquire Graph token for federation in tenant '$currentTenant' — FIC for '$env' will NOT be created."
            Write-Info "  The pipeline will fail with AADSTS700211 for this environment."
            Write-Info "  Ensure you have Graph API permissions in tenant '$currentTenant' and re-run."
            continue
        }
        $graphHeaders = @{ "Authorization" = "Bearer $graphToken"; "Content-Type" = "application/json" }

        $scName = "sc-intune-$env"
        $fedName = "ado-federation-$env"
        $issuer = "https://vstoken.dev.azure.com/$adoOrgGuid"
        $subject = "sc://$ADOOrganization/$ADOProject/$scName"

        # Cross-check: read the SC's actual issuer/subject from ADO
        # ADO may auto-populate a different issuer format than we compute
        $crossCheckSucceeded = $false
        if ($env:AZURE_DEVOPS_EXT_PAT) {
            $adoHeaders = @{ "Authorization" = "Bearer $($env:AZURE_DEVOPS_EXT_PAT)"; "Content-Type" = "application/json" }
            try {
                $scListResp = Invoke-RestMethod `
                    -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/serviceendpoint/endpoints?api-version=7.1" `
                    -Headers $adoHeaders -TimeoutSec 30
                $scEndpoint = $null
                $scApiValid = $false
                if ($scListResp -and $scListResp.PSObject.Properties['value']) {
                    $scApiValid = $true
                    $scEndpoint = $scListResp.value | Where-Object { $_.name -eq $scName }
                }
                else {
                    Write-Warn "ADO service endpoint API returned unexpected response — cross-check skipped"
                }
                if ($scEndpoint) {
                    $scActualIssuer = $scEndpoint.authorization.parameters.workloadIdentityFederationIssuer
                    $scActualSubject = $scEndpoint.authorization.parameters.workloadIdentityFederationSubject
                    if ($scActualIssuer -and $scActualIssuer -cne $issuer) {
                        Write-Warn "ADO service connection '$scName' uses issuer '$scActualIssuer' (differs from computed '$issuer')"
                        Write-Info "  Using SC's actual issuer for FIC to ensure OIDC token exchange works."
                        $issuer = $scActualIssuer
                    }
                    if ($scActualSubject -and $scActualSubject -cne $subject) {
                        Write-Warn "ADO service connection '$scName' uses subject '$scActualSubject' (differs from computed '$subject')"
                        Write-Info "  Using SC's actual subject for FIC to ensure OIDC token exchange works."
                        $subject = $scActualSubject
                    }
                    $crossCheckSucceeded = $true
                }
                elseif ($scApiValid) {
                    Write-Warn "Service connection '$scName' not found in ADO — cross-check skipped"
                }
                # Store actual values for the verification summary
                $script:FicActualValues[$env] = @{ Issuer = $issuer; Subject = $subject }
            }
            catch {
                Write-Warn "Could not read SC details from ADO (non-fatal): $_"
            }
        }
        # If SC cross-check didn't run (no PAT), store the computed values
        if (-not $script:FicActualValues.ContainsKey($env)) {
            $script:FicActualValues[$env] = @{ Issuer = $issuer; Subject = $subject }
        }

        Write-Progress2 -Activity $env -Status "Creating federated credential '$fedName' on app '$($appDetail.Name)'..."

        # Check if federated credential already exists on the app registration
        $existingFed = $null
        try {
            $fedListResp = Invoke-RestMethod `
                -Uri "https://graph.microsoft.com/v1.0/applications/$($appDetail.ObjectId)/federatedIdentityCredentials" `
                -Headers $graphHeaders -TimeoutSec 30
            $existingFed = $fedListResp.value | Where-Object { $_.name -eq $fedName }
        }
        catch {
            Write-Warn "Could not list existing federated credentials: $_"
        }

        if ($existingFed) {
            # Verify subject and issuer still match — update if stale
            if ($existingFed.subject -ceq $subject -and $existingFed.issuer -ceq $issuer) {
                Write-Success "Federated credential '$fedName' already exists on '$($appDetail.Name)' (subject matches)"
                continue
            }

            # SAFETY: If the ADO cross-check failed, the computed subject/issuer may be wrong.
            # Do NOT replace an existing FIC with unverified computed values — the existing
            # credential was likely set correctly by ADO or a previous successful run.
            if (-not $crossCheckSucceeded) {
                Write-Warn "Federated credential '$fedName' subject/issuer differs from computed values, but ADO cross-check failed."
                Write-Warn "  KEEPING existing FIC to avoid breaking a working credential."
                Write-Info "  Existing subject: $($existingFed.subject)"
                Write-Info "  Computed subject: $subject"
                Write-Err "  To fix: re-run WITHOUT -SkipADOSetup, or run Test-WorkloadIdentityFederation.ps1 -Repair"
                # Store the existing FIC values as the authoritative ones
                $script:FicActualValues[$env] = @{ Issuer = $existingFed.issuer; Subject = $existingFed.subject }
                continue
            }

            Write-Warn "Federated credential '$fedName' has stale values — updating..."
            Write-Info "  Old subject: $($existingFed.subject)"
            Write-Info "  New subject: $subject"
            if ($PSCmdlet.ShouldProcess("'$fedName' on '$($appDetail.Name)'", 'Update stale federated credential')) {
                try {
                    Invoke-RestMethod `
                        -Uri "https://graph.microsoft.com/v1.0/applications/$($appDetail.ObjectId)/federatedIdentityCredentials/$($existingFed.id)" `
                        -Method DELETE -Headers $graphHeaders -TimeoutSec 30 | Out-Null
                    Write-Info "  Deleted stale credential '$fedName'"
                }
                catch {
                    Write-Err "Failed to delete stale federated credential '$fedName': $_"
                    continue
                }
            }
        }

        # Create federated credential on the app registration
        $fedBody = @{
            name        = $fedName
            issuer      = $issuer
            subject     = $subject
            audiences   = @("api://AzureADTokenExchange")
            description = "Azure DevOps Workload Identity Federation for $scName"
        } | ConvertTo-Json -Compress

        if ($PSCmdlet.ShouldProcess("'$fedName' on '$($appDetail.Name)'", 'Create federated credential')) {
            try {
                Invoke-RestMethod `
                    -Uri "https://graph.microsoft.com/v1.0/applications/$($appDetail.ObjectId)/federatedIdentityCredentials" `
                    -Method POST -Headers $graphHeaders `
                    -Body $fedBody -TimeoutSec 30 | Out-Null
                Write-Success "Federated credential '$fedName' created on '$($appDetail.Name)' (subject: $subject)"
            }
            catch {
                Write-Err "CRITICAL: Failed to create federated credential '$fedName' on '$($appDetail.Name)': $_"
                Write-Err "  The pipeline WILL fail with AADSTS700211 until this is resolved."
                Write-Info "  Manual fix: Entra ID > App registrations > $($appDetail.Name) > Certificates & secrets > Federated credentials"
                Write-Info "  Add credential: Issuer=$issuer  Subject=$subject  Audience=api://AzureADTokenExchange"
                continue
            }

            # Post-creation verification — read back and confirm
            Start-Sleep -Seconds 2
            try {
                $verifyResp = Invoke-RestMethod `
                    -Uri "https://graph.microsoft.com/v1.0/applications/$($appDetail.ObjectId)/federatedIdentityCredentials" `
                    -Headers $graphHeaders -TimeoutSec 30
                $verified = $verifyResp.value | Where-Object { $_.name -eq $fedName }
                if ($verified -and $verified.issuer -ceq $issuer -and $verified.subject -ceq $subject) {
                    Write-Success "Verified: FIC '$fedName' exists with correct issuer and subject"
                }
                else {
                    Write-Err "CRITICAL: FIC '$fedName' verification failed — credential may not have been saved correctly."
                    Write-Info "  Expected issuer:  $issuer"
                    Write-Info "  Expected subject: $subject"
                    if ($verified) {
                        Write-Info "  Actual issuer:    $($verified.issuer)"
                        Write-Info "  Actual subject:   $($verified.subject)"
                    }
                    else {
                        Write-Info "  Credential not found after creation — possible replication delay or permission issue."
                    }
                }
            }
            catch {
                Write-Warn "Could not verify FIC creation (non-fatal): $_"
            }
        }
    }

    # Also create federated credentials on UAMIs for Azure RBAC operations (kept for future use)
    foreach ($env in $Environments) {
        if (-not $UamiDetails.ContainsKey($env)) { continue }

        if ($script:EnvConfigs -and $script:EnvConfigs.ContainsKey($env)) {
            $envCfg = $script:EnvConfigs[$env]
            if ($envCfg.TenantId -ne $currentTenant) {
                az login --tenant $envCfg.TenantId --only-show-errors | Out-Null
                $currentTenant = $envCfg.TenantId
            }
            az account set --subscription $envCfg.SubscriptionId --only-show-errors
        }

        $fedName = "ado-federation-$env"
        $uamiName = $UamiDetails[$env].Name

        $existing = az identity federated-credential show `
            --name $fedName `
            --identity-name $uamiName `
            --resource-group $ResourceGroupName `
            -o json 2>$null | ConvertFrom-Json

        $scName = "sc-intune-$env"
        $issuer = "https://vstoken.dev.azure.com/$adoOrgGuid"
        $subject = "sc://$ADOOrganization/$ADOProject/$scName"

        if ($existing) {
            # Verify subject and issuer still match — update if stale
            if ($existing.subject -ceq $subject -and $existing.issuer -ceq $issuer) {
                Write-Info "UAMI federated credential '$fedName' already exists on '$uamiName' (subject matches)"
                continue
            }

            Write-Warn "UAMI federated credential '$fedName' has stale values — updating..."
            Write-Info "  Old subject: $($existing.subject)"
            Write-Info "  New subject: $subject"
            if ($PSCmdlet.ShouldProcess("'$fedName' on '$uamiName'", 'Delete stale UAMI federated credential')) {
                az identity federated-credential delete `
                    --name $fedName `
                    --identity-name $uamiName `
                    --resource-group $ResourceGroupName `
                    --only-show-errors -o none --yes
            }
        }

        if ($PSCmdlet.ShouldProcess("'$fedName' on '$uamiName'", 'Create UAMI federated credential')) {
            az identity federated-credential create `
                --name $fedName `
                --identity-name $uamiName `
                --resource-group $ResourceGroupName `
                --issuer $issuer `
                --subject $subject `
                --audiences "api://AzureADTokenExchange" `
                --only-show-errors -o none

            if ($LASTEXITCODE -eq 0) {
                Write-Info "UAMI federated credential '$fedName' created on '$uamiName'"
            }
        }
    }

    # Switch back to production tenant if needed
    if ($currentTenant -ne $script:TenantId) {
        az login --tenant $script:TenantId --only-show-errors | Out-Null
        az account set --subscription $script:AzureSubscriptionId --only-show-errors
    }

    # ── FIC Validation Summary ──
    Write-Host ""
    Write-Info "═══ Federated Identity Credential Summary ═══"
    foreach ($env in $Environments) {
        if (-not $script:AppRegistrationDetails.ContainsKey($env)) {
            Write-Warn "  $($env.ToUpper()): App registration not found — FIC not configured"
            continue
        }
        $appDetail = $script:AppRegistrationDetails[$env]
        $scName = "sc-intune-$env"
        # Use the actual issuer/subject from FIC creation (may differ from computed values)
        if ($script:FicActualValues.ContainsKey($env)) {
            $expectedIssuer = $script:FicActualValues[$env].Issuer
            $expectedSubject = $script:FicActualValues[$env].Subject
        }
        else {
            $expectedSubject = "sc://$ADOOrganization/$ADOProject/$scName"
            $expectedIssuer = "https://vstoken.dev.azure.com/$adoOrgGuid"
        }

        # Acquire a Graph token for the environment's tenant to verify FIC
        $verifyTenantId = $script:TenantId
        if ($script:EnvConfigs -and $script:EnvConfigs.ContainsKey($env)) {
            $verifyTenantId = $script:EnvConfigs[$env].TenantId
        }
        if ($verifyTenantId -ne $currentTenant) {
            $prevEAP3 = $ErrorActionPreference; $ErrorActionPreference = "Continue"
            try { az login --tenant $verifyTenantId --only-show-errors | Out-Null }
            finally { $ErrorActionPreference = $prevEAP3 }
            $currentTenant = $verifyTenantId
        }
        $prevEAP3 = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        try {
            $verifyToken = az account get-access-token `
                --scope "https://graph.microsoft.com/.default" `
                --query accessToken -o tsv 2>$null
        }
        finally { $ErrorActionPreference = $prevEAP3 }

        if ($verifyToken) {
            $verifyHeaders = @{ "Authorization" = "Bearer $verifyToken" }
            try {
                $ficResp = Invoke-RestMethod `
                    -Uri "https://graph.microsoft.com/v1.0/applications/$($appDetail.ObjectId)/federatedIdentityCredentials" `
                    -Headers $verifyHeaders -TimeoutSec 30
                $ficMatch = $ficResp.value | Where-Object {
                    $_.issuer -ceq $expectedIssuer -and $_.subject -ceq $expectedSubject
                }
                if ($ficMatch) {
                    Write-Success "  $($env.ToUpper()): FIC verified on '$($appDetail.Name)' — issuer and subject match"
                }
                else {
                    Write-Err "  $($env.ToUpper()): NO matching FIC found on '$($appDetail.Name)'"
                    Write-Info "    Expected issuer:  $expectedIssuer"
                    Write-Info "    Expected subject: $expectedSubject"
                    if ($ficResp.value.Count -gt 0) {
                        Write-Info "    Existing FICs:"
                        foreach ($fic in $ficResp.value) {
                            Write-Info "      - Name: $($fic.name)  Issuer: $($fic.issuer)  Subject: $($fic.subject)"
                        }
                    }
                    else {
                        Write-Info "    No federated credentials exist on this app registration."
                    }
                }
            }
            catch {
                Write-Warn "  $($env.ToUpper()): Could not verify FIC (non-fatal): $_"
            }
        }
        else {
            Write-Warn "  $($env.ToUpper()): Could not acquire Graph token for verification"
        }
    }

    # Switch back to production tenant
    if ($currentTenant -ne $script:TenantId) {
        $prevEAP3 = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        try {
            az login --tenant $script:TenantId --only-show-errors | Out-Null
            az account set --subscription $script:AzureSubscriptionId --only-show-errors
        }
        finally { $ErrorActionPreference = $prevEAP3 }
    }
}

# ─────────────────────────────────────────────────────────────
# AZURE DEVOPS ORGANIZATION CREATION
# ─────────────────────────────────────────────────────────────
function New-ADOOrganization {
    <#
    .SYNOPSIS
        Creates a new Azure DevOps organization if it does not already exist.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Write-Info "Azure DevOps organization '$ADOOrganization' was not found. Attempting to create it..."

    # The VSSPS org-creation API requires a token scoped to the Azure DevOps
    # resource. Acquire one explicitly so we don't rely on AZURE_DEVOPS_EXT_PAT
    # which may have been obtained with a different scope.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $vsspsToken = az account get-access-token `
            --scope "499b84ac-1321-427f-aa17-267ca6975798/.default" `
            --query accessToken -o tsv 2>$null
    }
    finally { $ErrorActionPreference = $prevEAP }

    if (-not $vsspsToken) {
        Write-Err "Could not acquire an Azure DevOps access token. Ensure you are logged in."
        return $false
    }

    $createHeaders = @{
        "Authorization" = "Bearer $vsspsToken"
        "Content-Type"  = "application/json"
    }

    # Map Azure region to ADO region code
    $adoRegion = switch -Wildcard ($AzureRegion) {
        'uksouth' { 'UKS'; break }
        'uk*' { 'UKS'; break }
        'westeurope' { 'WEU'; break }
        'northeurope' { 'WEU'; break }
        'europe*' { 'WEU'; break }
        'eastus*' { 'EUS'; break }
        'centralus*' { 'CUS'; break }
        'westus*' { 'WUS'; break }
        'southeastasia' { 'SEA'; break }
        'australiaeast' { 'AUS'; break }
        'australia*' { 'AUS'; break }
        'brazilsouth' { 'SBR'; break }
        'india*' { 'IND'; break }
        'canada*' { 'CCA'; break }
        default { 'CUS' }
    }

    Write-Info "Using ADO region: $adoRegion (mapped from Azure region: $AzureRegion)"

    $body = @{
        collectionName  = $ADOOrganization
        preferredRegion = $adoRegion
    } | ConvertTo-Json -Compress

    # First check if the name is available — avoids opaque errors from the
    # creation endpoint when the tenant policy blocks new orgs.
    try {
        $nameCheck = Invoke-RestMethod `
            -Uri "https://app.vsaex.visualstudio.com/_apis/HostedOrganization/NameAvailability/$ADOOrganization`?api-version=5.0-preview.1" `
            -Headers $createHeaders -TimeoutSec 30
        if ($nameCheck -and $nameCheck.name -and (-not $nameCheck.isAvailable)) {
            # The org name is taken — it exists, we just can't reach it with this account
            Write-Err "Azure DevOps organization '$ADOOrganization' exists but your account does not have access."
            Write-Info "Ask an organization admin to grant you access, or verify the organization name."
            return $false
        }
    }
    catch {
        Write-Warn "Could not check organization name availability: $(Get-CleanErrorMessage $_)"
    }

    try {
        $result = Invoke-RestMethod `
            -Uri "https://app.vsaex.visualstudio.com/_apis/HostedOrganization?api-version=5.0-preview.1" `
            -Method POST -Headers $createHeaders -Body $body -TimeoutSec 120

        if ($result) {
            $script:ADOBaseUrl = "https://dev.azure.com/$ADOOrganization"
            Write-Success "Azure DevOps organization '$ADOOrganization' created successfully"
            Write-Info "Waiting for organization provisioning to complete..."
            Start-Sleep -Seconds 15

            # Refresh the ADO token for the newly created org
            $adoLoginRefreshed = Invoke-ADOLogin
            if (-not $adoLoginRefreshed) {
                Write-Warn "Could not refresh ADO token after org creation."
            }
            return $true
        }
    }
    catch {
        # Check the raw ErrorDetails and Exception for "already exists" signals
        $rawMsg = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { "$_" }
        if ($rawMsg -match "already exists" -or $rawMsg -match "name is already taken") {
            Write-Success "Azure DevOps organization '$ADOOrganization' already exists"
            return $true
        }
        # Also check HTTP status code directly
        $httpStatus = $null
        if ($_.Exception.Response) { $httpStatus = [int]$_.Exception.Response.StatusCode }

        $cleanErr = Get-CleanErrorMessage $_
        Write-Err "Failed to create Azure DevOps organization '$ADOOrganization': $cleanErr"
        if ($httpStatus -eq 403 -or $cleanErr -match '403|not allowed|do not have access|requires authentication') {
            Write-Info "Your tenant policy may restrict Azure DevOps organization creation."
            Write-Info "Ask your Entra ID admin to allow it, or create the organization manually at: https://dev.azure.com"
        }
        else {
            Write-Info "Create the organization manually at: https://dev.azure.com"
        }
        return $false
    }

    return $false
}

# ─────────────────────────────────────────────────────────────
# ENROLLMENT RESTRICTIONS IMPORT (delegated permissions)
# ─────────────────────────────────────────────────────────────
function Import-EnrollmentRestrictions {
    <#
    .SYNOPSIS
        Imports enrollment restriction policies using the interactive user's
        delegated Graph token: creates prerequisite groups and scope tags,
        imports policies, and applies assignments — all in a single pass.
    .DESCRIPTION
        Enrollment restriction endpoints require delegated permissions with
        Intune management scopes — app-only (UAMI/service principal)
        tokens are rejected with HTTP 403.  This function expects a valid
        MgGraph session to already be established via Connect-MgGraphForIntune
        (called once in the main flow). If the session is stale or for a
        different tenant, Test-MgGraphIntuneSession will transparently
        re-connect.

        The function resolves dependencies in-line so that no second run is
        needed after the first pipeline deployment:

        1. Reads the enrollment restriction JSON files and extracts referenced
           group IDs, scope tag IDs, and assignment filter IDs.
        2. Resolves group display names via MigrationTable.json, checks whether
           the groups exist in the target tenant, and creates any that are
           missing (using the matching JSON definition from Content/Groups/).
        3. Resolves source scope tag display names, checks the target tenant,
           and creates any missing scope tags (using the matching JSON from
           Content/ScopeTags/).
        4. Resolves assignment filter display names via MigrationTable, checks
           the target tenant, and recreates any missing filters from the
           Content/AssignmentFilters/ JSON definitions.
        5. Imports each enrollment restriction with the correct (remapped)
           scope tag IDs.
        6. Immediately applies group assignments with remapped group and
           assignment filter IDs.

        If a policy with the same displayName already exists in the target
        tenant it is gracefully skipped — no duplicate is created.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Imports multiple enrollment restriction policies')]
    param(
        [Parameter(Mandatory)]
        [string]$Environment
    )

    $contentPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/EnrollmentRestrictions"
    if (-not (Test-Path $contentPath)) {
        Write-Info "No EnrollmentRestrictions content folder found for '$Environment' — skipping"
        return
    }

    $jsonFiles = Get-ChildItem -Path $contentPath -Filter '*.json' -File -ErrorAction SilentlyContinue
    if (-not $jsonFiles -or $jsonFiles.Count -eq 0) {
        Write-Info "No enrollment restriction files found in '$contentPath' — skipping"
        return
    }

    Write-StepHeader "IMPORTING ENROLLMENT RESTRICTIONS ($($Environment.ToUpper()))"
    Write-Info "Using Microsoft Graph delegated auth — required for enrollment config endpoints"
    Write-Info "Will ensure prerequisite groups and scope tags exist before importing"
    Write-Info "Found $($jsonFiles.Count) enrollment restriction file(s) to process"

    # ── Load migration table for ID remapping ──
    $migrationFile = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/MigrationTable.json"
    $migrationTable = $null
    if (Test-Path $migrationFile) {
        $migrationTable = Get-Content -Path $migrationFile -Raw | ConvertFrom-Json
        Write-Info "Loaded migration table: $($migrationTable.Objects.Count) objects"
    }
    else {
        Write-Warn "No MigrationTable.json found — group ID remapping will be skipped"
    }

    # ── Load source scope tags for ID remapping ──
    $scopeTagPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/ScopeTags"
    $sourceScopeTags = @()
    if (Test-Path $scopeTagPath) {
        $sourceScopeTags = @(Get-ChildItem -Path $scopeTagPath -Filter '*.json' -File | ForEach-Object {
                Get-Content $_.FullName -Raw | ConvertFrom-Json
            })
        Write-Info "Loaded $($sourceScopeTags.Count) source scope tag(s) for remapping"
    }

    # ── Load source group definitions for creation ──
    $groupsContentPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/Groups"

    # ── Validate delegated MgGraph session for Intune operations ──
    $envTenantId = if ($script:EnvConfigs -and $script:EnvConfigs.ContainsKey($Environment)) {
        $script:EnvConfigs[$Environment].TenantId
    }
    else {
        $script:TenantId
    }

    if (-not (Test-MgGraphIntuneSession -TenantId $envTenantId)) {
        Write-Err "Cannot proceed without a valid Intune delegated session."
        return
    }

    # Get existing enrollment configurations in target tenant
    $existingConfigs = @()
    try {
        $existingResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations" `
            -OutputType PSObject -ErrorAction Stop
        if ($existingResp.value) {
            $existingConfigs = $existingResp.value
            Write-Info "Found $($existingConfigs.Count) existing enrollment configuration(s) in target tenant"
        }
        else {
            Write-Info "No existing enrollment configurations found in target tenant"
        }
    }
    catch {
        Write-Warn "Could not retrieve existing enrollment configurations: $(Get-CleanErrorMessage $_)"
        Write-Warn "Will attempt imports individually — duplicates may cause errors that will be handled gracefully"
    }

    # ── PHASE 1: Ensure prerequisite groups and scope tags exist ──
    # Parse all enrollment restriction files to discover referenced group IDs
    # and scope tag IDs, then create any that are missing in the target tenant.
    $allSourceObjs = @()
    foreach ($file in $jsonFiles) {
        try {
            $rawJson = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
            $allSourceObjs += $rawJson | ConvertFrom-Json -Depth 50 -ErrorAction Stop
        }
        catch {
            Write-Warn "Could not parse '$($file.Name)' for prerequisite scan — skipping"
        }
    }

    # ── Collect referenced group IDs from assignments ──
    $referencedGroupIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($srcObj in $allSourceObjs) {
        if ($srcObj.PSObject.Properties['assignments'] -and $srcObj.assignments) {
            foreach ($assignment in $srcObj.assignments) {
                if ($assignment.target -and $assignment.target.groupId) {
                    [void]$referencedGroupIds.Add($assignment.target.groupId)
                }
            }
        }
    }

    # ── Collect referenced scope tag IDs ──
    $referencedScopeTagIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($srcObj in $allSourceObjs) {
        if ($srcObj.PSObject.Properties['roleScopeTagIds'] -and $srcObj.roleScopeTagIds) {
            foreach ($tagId in $srcObj.roleScopeTagIds) {
                if ("$tagId" -ne '0') {
                    [void]$referencedScopeTagIds.Add("$tagId")
                }
            }
        }
    }

    # ── Create missing scope tags ──
    $targetScopeTags = @()
    try {
        $scopeTagResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" `
            -OutputType PSObject -ErrorAction Stop
        if ($scopeTagResp.value) { $targetScopeTags = $scopeTagResp.value }
    }
    catch {
        Write-Warn "Could not retrieve target scope tags: $(Get-CleanErrorMessage $_)"
    }

    # Initialize group ID map early — Sync-ScopeTagAssignments may need it
    $groupIdMap = @{}

    # Build a map of source scope tag ID → remapped target scope tag ID
    $scopeTagIdMap = @{}
    $scopeTagIdMap['0'] = '0'
    if ($referencedScopeTagIds.Count -gt 0 -and $sourceScopeTags.Count -gt 0) {
        Write-Info "Checking $($referencedScopeTagIds.Count) referenced scope tag(s)..."
        foreach ($srcId in $referencedScopeTagIds) {
            $srcTag = $sourceScopeTags | Where-Object { "$($_.id)" -eq "$srcId" } | Select-Object -First 1
            if (-not $srcTag) {
                Write-Warn "  Source scope tag ID $srcId not found in Content/$Environment/ScopeTags — will use default"
                continue
            }
            $targetTag = $targetScopeTags | Where-Object { $_.displayName -eq $srcTag.displayName } | Select-Object -First 1
            if ($targetTag) {
                Write-Success "  Scope tag '$($srcTag.displayName)' already exists (ID: $($targetTag.id))"
                $scopeTagIdMap[$srcId] = "$($targetTag.id)"
                # Ensure group assignments match the source definition
                Sync-ScopeTagAssignments -SourceScopeTag $srcTag `
                    -TargetScopeTagId "$($targetTag.id)" `
                    -GroupIdMap $groupIdMap `
                    -MigrationObjects $migrationTable.Objects `
                    -GroupsContentPath $groupsContentPath
            }
            else {
                # Create the scope tag
                Write-Info "  Creating scope tag '$($srcTag.displayName)'..."
                try {
                    $newTag = @{
                        displayName = $srcTag.displayName
                        description = if ($srcTag.description) { $srcTag.description } else { "" }
                    } | ConvertTo-Json -Compress
                    $createdTag = Invoke-MgGraphRequest -Method POST `
                        -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" `
                        -Body ([System.Text.Encoding]::UTF8.GetBytes($newTag)) `
                        -ContentType "application/json; charset=utf-8" `
                        -OutputType PSObject -ErrorAction Stop
                    if ($createdTag.id) {
                        Write-Success "  Created scope tag '$($srcTag.displayName)' (ID: $($createdTag.id))"
                        $scopeTagIdMap[$srcId] = "$($createdTag.id)"
                        $targetScopeTags += $createdTag
                        # Apply group assignments from source definition
                        Sync-ScopeTagAssignments -SourceScopeTag $srcTag `
                            -TargetScopeTagId "$($createdTag.id)" `
                            -GroupIdMap $groupIdMap `
                            -MigrationObjects $migrationTable.Objects `
                            -GroupsContentPath $groupsContentPath
                    }
                }
                catch {
                    Write-Warn "  Could not create scope tag '$($srcTag.displayName)': $(Get-CleanErrorMessage $_)"
                }
            }
        }
    }

    # ── Create missing groups ──
    # (groupIdMap already initialized above for scope tag assignment sync)
    if ($referencedGroupIds.Count -gt 0 -and $migrationTable) {
        Write-Info "Checking $($referencedGroupIds.Count) referenced group(s)..."
        foreach ($srcGroupId in $referencedGroupIds) {
            $migObj = $migrationTable.Objects | Where-Object { $_.Id -eq $srcGroupId -and $_.Type -eq 'Group' } | Select-Object -First 1
            if (-not $migObj) {
                Write-Warn "  Group ID $srcGroupId not found in MigrationTable — will skip this assignment target"
                continue
            }

            $groupDisplayName = $migObj.DisplayName
            # Check if group exists in target tenant
            try {
                $groupResp = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($groupDisplayName -replace "'","''")'&`$select=id,displayName" `
                    -OutputType PSObject -ErrorAction Stop
                if ($groupResp.value -and $groupResp.value.Count -gt 0) {
                    $targetGroupId = $groupResp.value[0].id
                    Write-Success "  Group '$groupDisplayName' already exists (ID: $targetGroupId)"
                    $groupIdMap[$srcGroupId] = $targetGroupId
                    continue
                }
            }
            catch {
                Write-Warn "  Could not check for group '$groupDisplayName': $(Get-CleanErrorMessage $_)"
            }

            # Group not found — create it from the Content/Groups/ JSON definition
            $groupJsonFile = Join-Path $groupsContentPath "$groupDisplayName.json"
            if (-not (Test-Path $groupJsonFile)) {
                Write-Warn "  Group '$groupDisplayName' not found in target and no JSON definition at '$groupJsonFile' — will skip"
                continue
            }

            Write-Info "  Creating group '$groupDisplayName'..."
            try {
                $groupDef = Get-Content -Path $groupJsonFile -Raw | ConvertFrom-Json -Depth 50

                # Build minimal group creation payload
                $newGroup = @{
                    displayName     = $groupDef.displayName
                    mailEnabled     = [bool]$groupDef.mailEnabled
                    mailNickname    = if ($groupDef.mailNickname) { $groupDef.mailNickname } else { ($groupDef.displayName -replace '[^a-zA-Z0-9]', '').Substring(0, [Math]::Min(64, ($groupDef.displayName -replace '[^a-zA-Z0-9]', '').Length)) }
                    securityEnabled = [bool]$groupDef.securityEnabled
                }
                if ($groupDef.description) { $newGroup['description'] = $groupDef.description }
                if ($groupDef.groupTypes -and $groupDef.groupTypes.Count -gt 0) {
                    $newGroup['groupTypes'] = @($groupDef.groupTypes)
                }
                else {
                    $newGroup['groupTypes'] = @()
                }
                if ($groupDef.membershipRule) {
                    $newGroup['membershipRule'] = $groupDef.membershipRule
                    $newGroup['membershipRuleProcessingState'] = if ($groupDef.membershipRuleProcessingState) { $groupDef.membershipRuleProcessingState } else { 'On' }
                    if ($newGroup['groupTypes'] -notcontains 'DynamicMembership') {
                        $newGroup['groupTypes'] += 'DynamicMembership'
                    }
                }

                $groupBody = $newGroup | ConvertTo-Json -Depth 10
                $createdGroup = Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/v1.0/groups" `
                    -Body ([System.Text.Encoding]::UTF8.GetBytes($groupBody)) `
                    -ContentType "application/json; charset=utf-8" `
                    -OutputType PSObject -ErrorAction Stop

                if ($createdGroup.id) {
                    Write-Success "  Created group '$groupDisplayName' (ID: $($createdGroup.id))"
                    $groupIdMap[$srcGroupId] = $createdGroup.id
                }
            }
            catch {
                $errMsg = Get-CleanErrorMessage $_
                $errDetail = "$($_.ErrorDetails.Message)$($_.Exception.Message)"
                # Handle "already exists" race condition
                if ($errDetail -match 'already exists' -or $errDetail -match 'ObjectConflict') {
                    Write-Info "  Group '$groupDisplayName' was created concurrently — looking it up..."
                    try {
                        $retryResp = Invoke-MgGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($groupDisplayName -replace "'","''")'&`$select=id" `
                            -OutputType PSObject -ErrorAction Stop
                        if ($retryResp.value -and $retryResp.value.Count -gt 0) {
                            $groupIdMap[$srcGroupId] = $retryResp.value[0].id
                            Write-Success "  Found group '$groupDisplayName' (ID: $($retryResp.value[0].id))"
                        }
                    }
                    catch {
                        Write-Warn "  Could not look up group '$groupDisplayName' after conflict: $(Get-CleanErrorMessage $_)"
                    }
                }
                else {
                    Write-Warn "  Could not create group '$groupDisplayName': $errMsg"
                }
            }
        }
    }

    # ── Resolve assignment filter IDs via MigrationTable — create missing from Content folder ──
    # Assignment filters referenced in enrollment restriction assignments need
    # the same MigrationTable-based display-name lookup as groups.
    # If a filter does not exist in the target tenant, recreate it from the
    # Content/<Environment>/AssignmentFilters/ JSON definitions so that policy
    # group assignments can reference the correct filter IDs.
    $filterIdMap = @{}
    $assignmentFiltersContentPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/AssignmentFilters"
    $referencedFilterIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($srcObj in $allSourceObjs) {
        if ($srcObj.PSObject.Properties['assignments'] -and $srcObj.assignments) {
            foreach ($assignment in $srcObj.assignments) {
                if ($assignment.target -and $assignment.target.deviceAndAppManagementAssignmentFilterId `
                        -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne '00000000-0000-0000-0000-000000000000') {
                    [void]$referencedFilterIds.Add($assignment.target.deviceAndAppManagementAssignmentFilterId)
                }
            }
        }
    }
    if ($referencedFilterIds.Count -gt 0 -and $migrationTable) {
        Write-Info "Resolving $($referencedFilterIds.Count) referenced assignment filter(s)..."
        # Fetch all assignment filters once — the API does not support OData $filter on displayName
        try {
            $allFiltersResp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters?$select=id,displayName' `
                -OutputType PSObject -ErrorAction Stop
            $allFilters = @($allFiltersResp.value)
        }
        catch {
            Write-Warn "  Could not retrieve assignment filters: $(Get-CleanErrorMessage $_)"
            $allFilters = @()
        }
        foreach ($srcFilterId in $referencedFilterIds) {
            $migFilter = $migrationTable.Objects | Where-Object { $_.Id -eq $srcFilterId -and $_.Type -eq 'AssignmentFilter' } | Select-Object -First 1
            if (-not $migFilter) {
                Write-Warn "  Assignment filter ID $srcFilterId not found in MigrationTable — will clear on assignment"
                continue
            }
            $match = $allFilters | Where-Object { $_.displayName -eq $migFilter.DisplayName } | Select-Object -First 1
            if ($match) {
                $filterIdMap[$srcFilterId] = $match.id
                Write-Info "  Filter '$($migFilter.DisplayName)' already exists [$srcFilterId -> $($match.id)]"
            }
            else {
                # Filter not found in target — create from Content/AssignmentFilters/ JSON
                $filterJsonFile = Join-Path $assignmentFiltersContentPath "$($migFilter.DisplayName).json"
                if (-not (Test-Path $filterJsonFile)) {
                    Write-Warn "  Assignment filter '$($migFilter.DisplayName)' not found in target and no JSON at '$filterJsonFile' — will clear on assignment"
                    continue
                }

                Write-Info "  Creating assignment filter '$($migFilter.DisplayName)'..."
                try {
                    $filterDef = Get-Content -Path $filterJsonFile -Raw | ConvertFrom-Json -Depth 50

                    # Build creation payload with only the required/writable properties
                    $newFilter = @{
                        displayName                    = $filterDef.displayName
                        platform                       = $filterDef.platform
                        rule                           = $filterDef.rule
                        assignmentFilterManagementType = $filterDef.assignmentFilterManagementType
                    }
                    if ($filterDef.description) { $newFilter['description'] = $filterDef.description }

                    # Remap roleScopeTags to target tenant IDs
                    if ($filterDef.PSObject.Properties['roleScopeTags'] -and $filterDef.roleScopeTags) {
                        $remappedFilterTags = [System.Collections.Generic.List[string]]::new()
                        foreach ($tagId in $filterDef.roleScopeTags) {
                            if ($scopeTagIdMap.ContainsKey("$tagId")) {
                                $remappedFilterTags.Add($scopeTagIdMap["$tagId"])
                            }
                            elseif ("$tagId" -eq '0') {
                                $remappedFilterTags.Add('0')
                            }
                        }
                        if ($remappedFilterTags.Count -eq 0) { $remappedFilterTags.Add('0') }
                        $newFilter['roleScopeTags'] = @($remappedFilterTags)
                    }

                    $filterBody = $newFilter | ConvertTo-Json -Depth 10
                    $createdFilter = Invoke-MgGraphRequest -Method POST `
                        -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters' `
                        -Body ([System.Text.Encoding]::UTF8.GetBytes($filterBody)) `
                        -ContentType "application/json; charset=utf-8" `
                        -OutputType PSObject -ErrorAction Stop

                    if ($createdFilter.id) {
                        Write-Success "  Created assignment filter '$($migFilter.DisplayName)' (ID: $($createdFilter.id))"
                        $filterIdMap[$srcFilterId] = $createdFilter.id
                        $allFilters += $createdFilter
                    }
                }
                catch {
                    $errMsg = Get-CleanErrorMessage $_
                    $errDetail = "$($_.ErrorDetails.Message)$($_.Exception.Message)"
                    if ($errDetail -match 'already exists' -or $errDetail -match 'conflict') {
                        Write-Info "  Assignment filter '$($migFilter.DisplayName)' was created concurrently — looking it up..."
                        $retryMatch = $allFilters | Where-Object { $_.displayName -eq $migFilter.DisplayName } | Select-Object -First 1
                        if (-not $retryMatch) {
                            # Re-fetch all filters to pick up the concurrent creation
                            try {
                                $retryResp = Invoke-MgGraphRequest -Method GET `
                                    -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters?$select=id,displayName' `
                                    -OutputType PSObject -ErrorAction Stop
                                $allFilters = @($retryResp.value)
                                $retryMatch = $allFilters | Where-Object { $_.displayName -eq $migFilter.DisplayName } | Select-Object -First 1
                            }
                            catch {
                                Write-Warn "  Could not re-fetch assignment filters: $(Get-CleanErrorMessage $_)"
                            }
                        }
                        if ($retryMatch) {
                            $filterIdMap[$srcFilterId] = $retryMatch.id
                            Write-Success "  Found assignment filter '$($migFilter.DisplayName)' (ID: $($retryMatch.id))"
                        }
                        else {
                            Write-Warn "  Could not resolve assignment filter '$($migFilter.DisplayName)' after conflict — will clear on assignment"
                        }
                    }
                    else {
                        Write-Warn "  Could not create assignment filter '$($migFilter.DisplayName)': $errMsg"
                    }
                }
            }
        }
    }

    $importedCount = 0
    $skippedCount = 0
    $failedCount = 0

    # Parse and sort files by priority (lowest first) so priority order is preserved
    $sortedFiles = @()
    foreach ($file in $jsonFiles) {
        try {
            $rawJson = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
            $obj = $rawJson | ConvertFrom-Json -Depth 50 -ErrorAction Stop
            $sortedFiles += [PSCustomObject]@{
                File     = $file
                Object   = $obj
                Priority = if ($obj.priority) { [int]$obj.priority } else { 999 }
            }
        }
        catch {
            Write-Warn "Could not parse '$($file.Name)' — skipping ($(Get-CleanErrorMessage $_))"
            $skippedCount++
        }
    }
    $sortedFiles = $sortedFiles | Sort-Object -Property Priority

    if ($sortedFiles.Count -eq 0) {
        Write-Info "No valid enrollment restriction files to process"
        return
    }

    foreach ($entry in $sortedFiles) {
        $file = $entry.File
        $sourceObj = $entry.Object
        $objectName = $sourceObj.displayName

        if (-not $objectName) {
            Write-Warn "Skipping '$($file.Name)' — no displayName property found in JSON"
            $skippedCount++
            continue
        }

        Write-Progress2 -Activity "EnrollmentRestrictions" -Status "Processing '$objectName'..."

        # Check if this policy already exists (match by displayName)
        $existingObj = $existingConfigs | Where-Object { $_.displayName -eq $objectName } | Select-Object -First 1
        if ($existingObj) {
            Write-Success "'$objectName' already exists in target tenant (ID: $($existingObj.id)) — validating configuration"

            $validationChanges = 0

            # ── Validate scope tags ──
            if ($sourceObj.PSObject.Properties['roleScopeTagIds'] -and $sourceObj.roleScopeTagIds) {
                $desiredTags = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($tagId in $sourceObj.roleScopeTagIds) {
                    if ($scopeTagIdMap.ContainsKey("$tagId")) { [void]$desiredTags.Add($scopeTagIdMap["$tagId"]) }
                    elseif ("$tagId" -eq '0') { [void]$desiredTags.Add('0') }
                }
                $currentTags = @()
                if ($existingObj.PSObject.Properties['roleScopeTagIds']) { $currentTags = @($existingObj.roleScopeTagIds) }
                $missingTags = @($desiredTags | Where-Object { $_ -notin $currentTags })
                if ($missingTags.Count -gt 0) {
                    $mergedTags = @($currentTags) + $missingTags | Select-Object -Unique
                    # Enrollment configurations require @odata.type in PATCH body
                    $patchPayload = @{ roleScopeTagIds = @($mergedTags) }
                    if ($existingObj.'@odata.type') {
                        $patchPayload['@odata.type'] = $existingObj.'@odata.type'
                    }
                    try {
                        $patchBody = $patchPayload | ConvertTo-Json -Compress
                        Invoke-MgGraphRequest -Method PATCH `
                            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$($existingObj.id)" `
                            -Body ([System.Text.Encoding]::UTF8.GetBytes($patchBody)) `
                            -ContentType "application/json; charset=utf-8" `
                            -ErrorAction Stop | Out-Null
                        Write-Success "  Added $($missingTags.Count) missing scope tag(s)"
                        $validationChanges++
                    }
                    catch {
                        # Re-read to check if scope tags already match despite the PATCH error
                        try {
                            $recheck = Invoke-MgGraphRequest -Method GET `
                                -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$($existingObj.id)?`$select=roleScopeTagIds" `
                                -OutputType PSObject -ErrorAction Stop
                            $recheckTags = @($recheck.roleScopeTagIds)
                            $stillMissing = @($desiredTags | Where-Object { $_ -notin $recheckTags })
                            if ($stillMissing.Count -eq 0) {
                                Write-Info "  Scope tags already correct on this enrollment configuration"
                            }
                            else {
                                Write-Warn "  Could not patch scope tags (missing: $($stillMissing -join ', ')): $(Get-CleanErrorMessage $_)"
                            }
                        }
                        catch {
                            Write-Warn "  Could not patch scope tags: $(Get-CleanErrorMessage $_)"
                        }
                    }
                }
            }

            # ── Validate assignments (groups + filters) ──
            if ($sourceObj.PSObject.Properties['assignments'] -and $sourceObj.assignments.Count -gt 0) {
                # Get current assignments
                $currentAssignments = @()
                try {
                    $assignResp = Invoke-MgGraphRequest -Method GET `
                        -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$($existingObj.id)?`$expand=assignments" `
                        -OutputType PSObject -ErrorAction Stop
                    if ($assignResp.assignments) { $currentAssignments = @($assignResp.assignments) }
                }
                catch {
                    Write-Warn "  Could not read current assignments: $(Get-CleanErrorMessage $_)"
                }

                # Build lookup of existing assignments by target type + groupId (to detect filter mismatches)
                # Key includes target type (include/exclude) to avoid collisions if the same group
                # appears as both an include and exclude target.
                $existingByKey = @{}
                foreach ($ca in $currentAssignments) {
                    if ($ca.target -and $ca.target.groupId) {
                        $caType = $ca.target.'@odata.type'
                        $caPrefix = if ($caType -match 'exclusionGroupAssignmentTarget') { 'exclude' } else { 'include' }
                        $existingByKey["${caPrefix}:$($ca.target.groupId)"] = $ca
                    }
                }

                # Compare each desired assignment against what exists
                $needsReassign = $false
                $mergedAssignments = [System.Collections.Generic.List[object]]::new()
                $changeDescriptions = [System.Collections.Generic.List[string]]::new()

                # Start with a copy of all existing assignments (we'll replace individual entries as needed)
                foreach ($ca in $currentAssignments) {
                    $mergedAssignments.Add([PSCustomObject]@{ target = $ca.target })
                }

                foreach ($assignment in $sourceObj.assignments) {
                    $target = $assignment.target | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10
                    if (-not $target) { continue }

                    # Determine target type for key generation
                    $targetType = $target.'@odata.type'
                    $targetPrefix = if ($targetType -match 'exclusionGroupAssignmentTarget') { 'exclude' } else { 'include' }

                    # Remap group ID
                    if ($target.groupId) {
                        if ($groupIdMap.ContainsKey($target.groupId)) {
                            $target.groupId = $groupIdMap[$target.groupId]
                        }
                        else { continue }
                    }

                    # Remap assignment filter ID
                    $desiredFilterId = $null
                    $desiredFilterType = 'none'
                    if ($target.deviceAndAppManagementAssignmentFilterId `
                            -and $target.deviceAndAppManagementAssignmentFilterId -ne '00000000-0000-0000-0000-000000000000') {
                        if ($filterIdMap.ContainsKey($target.deviceAndAppManagementAssignmentFilterId)) {
                            $desiredFilterId = $filterIdMap[$target.deviceAndAppManagementAssignmentFilterId]
                            $desiredFilterType = if ($target.deviceAndAppManagementAssignmentFilterType) { $target.deviceAndAppManagementAssignmentFilterType } else { 'include' }
                        }
                    }

                    $lookupKey = "${targetPrefix}:$($target.groupId)"
                    if ($existingByKey.ContainsKey($lookupKey)) {
                        # Group assignment exists — check if filter matches
                        $existingAssign = $existingByKey[$lookupKey]
                        $currentFilterId = $existingAssign.target.deviceAndAppManagementAssignmentFilterId
                        if ([string]::IsNullOrEmpty($currentFilterId)) { $currentFilterId = $null }
                        if ($currentFilterId -eq '00000000-0000-0000-0000-000000000000') { $currentFilterId = $null }

                        if ($desiredFilterId -and $currentFilterId -ne $desiredFilterId) {
                            # Filter is missing or different — update the entry in merged list
                            $needsReassign = $true
                            $matchIdx = -1
                            for ($i = 0; $i -lt $mergedAssignments.Count; $i++) {
                                $mTargetType = $mergedAssignments[$i].target.'@odata.type'
                                $mPrefix = if ($mTargetType -match 'exclusionGroupAssignmentTarget') { 'exclude' } else { 'include' }
                                if ($mergedAssignments[$i].target.groupId -eq $target.groupId -and $mPrefix -eq $targetPrefix) {
                                    $matchIdx = $i
                                    break
                                }
                            }
                            if ($matchIdx -ge 0) {
                                $updatedTarget = $mergedAssignments[$matchIdx].target | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10
                                $updatedTarget.deviceAndAppManagementAssignmentFilterId = $desiredFilterId
                                $updatedTarget.deviceAndAppManagementAssignmentFilterType = $desiredFilterType
                                $mergedAssignments[$matchIdx] = [PSCustomObject]@{ target = $updatedTarget }
                            }
                            $filterName = if ($desiredFilterId) { $desiredFilterId.Substring(0, [Math]::Min(8, $desiredFilterId.Length)) + '...' } else { 'none' }
                            $changeDescriptions.Add("filter on group $($target.groupId.Substring(0,8))... -> $filterName")
                        }
                        # else: group + filter already correct, nothing to do
                    }
                    else {
                        # Group assignment is entirely missing — add it
                        $needsReassign = $true
                        if ($desiredFilterId) {
                            $target.deviceAndAppManagementAssignmentFilterId = $desiredFilterId
                            $target.deviceAndAppManagementAssignmentFilterType = $desiredFilterType
                        }
                        elseif (-not $target.PSObject.Properties['deviceAndAppManagementAssignmentFilterId']) {
                            # Ensure filter properties exist even if not set
                        }
                        $mergedAssignments.Add([PSCustomObject]@{ target = $target })
                        $changeDescriptions.Add("added group $($target.groupId.Substring(0,8))...")
                    }
                }

                if ($needsReassign) {
                    try {
                        $assignBody = @{
                            enrollmentConfigurationAssignments = @($mergedAssignments)
                        } | ConvertTo-Json -Depth 20
                        Invoke-MgGraphRequest -Method POST `
                            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$($existingObj.id)/assign" `
                            -Body ([System.Text.Encoding]::UTF8.GetBytes($assignBody)) `
                            -ContentType "application/json; charset=utf-8" `
                            -ErrorAction Stop | Out-Null
                        Write-Success "  Updated assignments: $($changeDescriptions -join '; ')"
                        $validationChanges++
                    }
                    catch {
                        Write-Warn "  Could not apply assignment updates: $(Get-CleanErrorMessage $_)"
                    }
                }
            }

            if ($validationChanges -eq 0) {
                Write-Info "  Configuration is up to date — no changes needed"
            }
            $skippedCount++
            continue
        }

        # Clone and strip properties that must not be sent on create
        $importObj = $sourceObj | ConvertTo-Json -Depth 50 | ConvertFrom-Json -Depth 50

        # Remove read-only / OData / action properties
        $removeProps = @(
            'id', 'createdDateTime', 'lastModifiedDateTime', 'version', 'priority',
            'deviceEnrollmentConfigurationType', 'assignments',
            '#microsoft.graph.assign', '#microsoft.graph.setPriority'
        )
        foreach ($prop in $removeProps) {
            if ($importObj.PSObject.Properties[$prop]) {
                $importObj.PSObject.Properties.Remove($prop)
            }
        }

        # Remove all OData metadata properties (annotations, navigation links, etc.)
        $odataProps = @($importObj.PSObject.Properties | Where-Object {
                ($_.Name -like '@odata.*' -and $_.Name -ne '@odata.type') -or
                $_.Name -match '.+@odata\.' -or
                $_.Name -like '#*'
            } | ForEach-Object { $_.Name })
        foreach ($prop in $odataProps) {
            $importObj.PSObject.Properties.Remove($prop)
        }

        # Remap scope tags to target tenant IDs
        if ($importObj.PSObject.Properties['roleScopeTagIds']) {
            $remappedTags = [System.Collections.Generic.List[string]]::new()
            foreach ($tagId in $sourceObj.roleScopeTagIds) {
                if ($scopeTagIdMap.ContainsKey("$tagId")) {
                    $remappedTags.Add($scopeTagIdMap["$tagId"])
                }
                elseif ("$tagId" -eq '0') {
                    $remappedTags.Add('0')
                }
                # else: scope tag not found, skip it
            }
            if ($remappedTags.Count -eq 0) { $remappedTags.Add('0') }
            $importObj.roleScopeTagIds = @($remappedTags)
        }

        # POST the enrollment configuration
        try {
            $body = $importObj | ConvertTo-Json -Depth 50
            $result = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations" `
                -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
                -ContentType "application/json; charset=utf-8" `
                -OutputType PSObject -ErrorAction Stop

            if ($result.id) {
                Write-Success "Created '$objectName' (ID: $($result.id))"
                $importedCount++

                # Set priority if specified in source
                if ($entry.Priority -and $entry.Priority -ne 999) {
                    try {
                        $priorityBody = @{ priority = $entry.Priority } | ConvertTo-Json -Compress
                        Invoke-MgGraphRequest -Method POST `
                            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$($result.id)/setPriority" `
                            -Body $priorityBody -ContentType "application/json" `
                            -ErrorAction Stop | Out-Null
                        Write-Info "  Priority set to $($entry.Priority)"
                    }
                    catch {
                        Write-Warn "  Could not set priority: $(Get-CleanErrorMessage $_)"
                    }
                }

                # ── Apply assignments with remapped group IDs ──
                if ($sourceObj.PSObject.Properties['assignments'] -and $sourceObj.assignments.Count -gt 0) {
                    $cleanAssignments = [System.Collections.Generic.List[object]]::new()
                    foreach ($assignment in $sourceObj.assignments) {
                        $target = $assignment.target | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10
                        if (-not $target) { continue }

                        # Remap group ID
                        if ($target.groupId) {
                            if ($groupIdMap.ContainsKey($target.groupId)) {
                                $target.groupId = $groupIdMap[$target.groupId]
                            }
                            else {
                                Write-Warn "  Skipping assignment — group '$($target.groupId)' could not be resolved"
                                continue
                            }
                        }

                        # Remap assignment filter ID
                        if ($target.deviceAndAppManagementAssignmentFilterId `
                                -and $target.deviceAndAppManagementAssignmentFilterId -ne '00000000-0000-0000-0000-000000000000') {
                            if ($filterIdMap.ContainsKey($target.deviceAndAppManagementAssignmentFilterId)) {
                                $target.deviceAndAppManagementAssignmentFilterId = $filterIdMap[$target.deviceAndAppManagementAssignmentFilterId]
                            }
                            else {
                                # Filter not found in target — clear the filter reference
                                $target.deviceAndAppManagementAssignmentFilterId = '00000000-0000-0000-0000-000000000000'
                                $target.deviceAndAppManagementAssignmentFilterType = 'none'
                                Write-Warn "  Assignment filter not found in target — cleared filter reference"
                            }
                        }

                        $cleanAssignments.Add([PSCustomObject]@{
                                target = $target
                            })
                    }

                    if ($cleanAssignments.Count -gt 0) {
                        try {
                            $assignBody = @{
                                enrollmentConfigurationAssignments = @($cleanAssignments)
                            } | ConvertTo-Json -Depth 20
                            Invoke-MgGraphRequest -Method POST `
                                -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$($result.id)/assign" `
                                -Body ([System.Text.Encoding]::UTF8.GetBytes($assignBody)) `
                                -ContentType "application/json; charset=utf-8" `
                                -ErrorAction Stop | Out-Null
                            Write-Success "  Applied $($cleanAssignments.Count) assignment(s)"
                        }
                        catch {
                            Write-Warn "  Could not apply assignments: $(Get-CleanErrorMessage $_)"
                        }
                    }
                }
            }
            else {
                Write-Err "POST returned no ID for '$objectName'"
                $failedCount++
            }
        }
        catch {
            $errMsg = Get-CleanErrorMessage $_
            $errDetail = "$($_.ErrorDetails.Message)$($_.Exception.Message)"

            # Detect duplicate/conflict — Graph API returns 409 Conflict or a message
            # indicating the object already exists (race condition or stale cache)
            $isDuplicate = $false
            $httpStatus = $null
            if ($_.Exception.Response) {
                try { $httpStatus = [int]$_.Exception.Response.StatusCode } catch {
                    # Intentionally suppressed — response may not expose a parseable status code
                    $null = $null
                }
            }
            if (-not $httpStatus -and $errDetail -match 'Status(?:Code)?\s*[:=]\s*(\d{3})') {
                try { $httpStatus = [int]$Matches[1] } catch { $null = $null }
            }
            if ($httpStatus -eq 409 -or $errDetail -match 'already exists' -or $errDetail -match 'conflict') {
                $isDuplicate = $true
            }

            if ($isDuplicate) {
                Write-Success "'$objectName' already exists in target tenant (detected via API response) — skipping"
                $skippedCount++
            }
            elseif ($httpStatus -eq 403) {
                Write-Err "Permission denied creating '$objectName' (HTTP 403). Ensure you are signed in with an account that has Intune management permissions (e.g., Intune Administrator)."
                $failedCount++
            }
            elseif ($httpStatus -eq 401) {
                Write-Err "Authentication expired creating '$objectName' (HTTP 401). Re-run the script to refresh the token."
                $failedCount++
            }
            else {
                Write-Err "Failed to create '$objectName': $errMsg"
                $failedCount++
            }
        }
    }

    # Print summary
    Write-Host ""
    Write-Host ("  " + "-" * 50) -ForegroundColor Gray
    Write-Info "Enrollment restrictions import summary for $($Environment.ToUpper()):"
    if ($importedCount -gt 0) { Write-Success "  $importedCount policy/policies created" }
    if ($skippedCount -gt 0) { Write-Success "  $skippedCount policy/policies already existed — skipped" }
    if ($failedCount -gt 0) { Write-Err "  $failedCount policy/policies failed" }
    if ($importedCount -eq 0 -and $skippedCount -gt 0 -and $failedCount -eq 0) {
        Write-Success "All enrollment restriction policies already exist — nothing to do"
    }
    if ($importedCount -gt 0) {
        Write-Success "Enrollment restrictions imported with scope tags and assignments applied"
    }
    Write-Host ("  " + "-" * 50) -ForegroundColor Gray
}

# ─────────────────────────────────────────────────────────────
# ENROLLMENT RESTRICTIONS — PATCH ASSIGNMENTS & SCOPE TAGS
# ─────────────────────────────────────────────────────────────
function Update-EnrollmentRestrictionAssignments {
    <#
    .SYNOPSIS
        Patches group assignments and scope tags onto enrollment restriction policies.
    .DESCRIPTION
        Enrollment restriction endpoints require delegated permissions (Intune Admin
        or Global Admin). The pipeline's service principal cannot PATCH assignments or
        scope tags (HTTP 403). This function uses the interactive admin's delegated
        token to apply those settings after the pipeline has created the targeting
        groups and scope tags.

        Should be run after the first successful pipeline deployment that creates
        groups and scope tags in the target tenant.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Updates assignments on multiple enrollment restrictions')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Environment
    )

    $contentPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/EnrollmentRestrictions"
    if (-not (Test-Path $contentPath)) {
        Write-Info "No EnrollmentRestrictions content folder found for '$Environment' — skipping"
        return
    }

    $jsonFiles = Get-ChildItem -Path $contentPath -Filter '*.json' -File -ErrorAction SilentlyContinue
    if (-not $jsonFiles -or $jsonFiles.Count -eq 0) {
        Write-Info "No enrollment restriction files found — skipping"
        return
    }

    Write-StepHeader "PATCHING ENROLLMENT RESTRICTION ASSIGNMENTS & SCOPE TAGS ($($Environment.ToUpper()))"
    Write-Info "Using Microsoft Graph delegated auth — required for enrollment config endpoints"

    # ── Load migration table for ID remapping ──
    $migrationFile = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/MigrationTable.json"
    $migrationTable = $null
    if (Test-Path $migrationFile) {
        $migrationTable = Get-Content -Path $migrationFile -Raw | ConvertFrom-Json
        Write-Info "Loaded migration table: $($migrationTable.Objects.Count) objects"
    }
    else {
        Write-Warn "No MigrationTable.json found — group ID remapping will be skipped"
    }

    # ── Load source scope tags for ID remapping ──
    $scopeTagPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/ScopeTags"
    $sourceScopeTags = @()
    if (Test-Path $scopeTagPath) {
        $sourceScopeTags = @(Get-ChildItem -Path $scopeTagPath -Filter '*.json' -File | ForEach-Object {
                Get-Content $_.FullName -Raw | ConvertFrom-Json
            })
        Write-Info "Loaded $($sourceScopeTags.Count) source scope tag(s) for remapping"
    }

    # ── Validate delegated MgGraph session for Intune operations ──
    $envTenantId = if ($script:EnvConfigs -and $script:EnvConfigs.ContainsKey($Environment)) {
        $script:EnvConfigs[$Environment].TenantId
    }
    else {
        $script:TenantId
    }

    if (-not (Test-MgGraphIntuneSession -TenantId $envTenantId)) {
        Write-Err "Cannot proceed without a valid Intune delegated session."
        return
    }

    # ── Get existing enrollment configs in target tenant ──
    $existingConfigs = @()
    try {
        $existingResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations" `
            -OutputType PSObject -ErrorAction Stop
        if ($existingResp.value) {
            $existingConfigs = $existingResp.value
        }
    }
    catch {
        Write-Err "Could not retrieve existing enrollment configurations: $(Get-CleanErrorMessage $_)"
        return
    }

    # ── Get target tenant scope tags for ID remapping ──
    $targetScopeTags = @()
    try {
        $scopeTagResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" `
            -OutputType PSObject -ErrorAction Stop
        if ($scopeTagResp.value) { $targetScopeTags = $scopeTagResp.value }
    }
    catch {
        Write-Warn "Could not retrieve target scope tags: $(Get-CleanErrorMessage $_)"
    }

    $patchedCount = 0
    $skippedCount = 0
    $failedCount = 0

    foreach ($file in $jsonFiles) {
        try {
            $sourceObj = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json -Depth 50
        }
        catch {
            Write-Warn "Could not parse '$($file.Name)' — skipping"
            $skippedCount++
            continue
        }

        $objectName = $sourceObj.displayName
        if (-not $objectName) {
            $skippedCount++
            continue
        }

        # Find existing policy in target tenant
        $existingObj = $existingConfigs | Where-Object { $_.displayName -eq $objectName } | Select-Object -First 1
        if (-not $existingObj) {
            Write-Warn "'$objectName' not found in target tenant — run the initial import first"
            $skippedCount++
            continue
        }

        $policyId = $existingObj.id
        $patched = $false

        # ── Patch scope tags ──
        if ($sourceObj.PSObject.Properties['roleScopeTagIds'] -and $sourceObj.roleScopeTagIds.Count -gt 0) {
            $remappedScopeTagIds = [System.Collections.Generic.List[string]]::new()
            foreach ($srcId in $sourceObj.roleScopeTagIds) {
                if ("$srcId" -eq '0') {
                    $remappedScopeTagIds.Add("0")
                    continue
                }
                $srcTag = $sourceScopeTags | Where-Object { "$($_.id)" -eq "$srcId" } | Select-Object -First 1
                if ($srcTag) {
                    $targetTag = $targetScopeTags | Where-Object { $_.displayName -eq $srcTag.displayName } | Select-Object -First 1
                    if ($targetTag) {
                        $remappedScopeTagIds.Add("$($targetTag.id)")
                        Write-Info "  Scope tag: $($srcTag.displayName) [$srcId -> $($targetTag.id)]"
                    }
                    else {
                        Write-Warn "  Target scope tag '$($srcTag.displayName)' not found — skipping"
                    }
                }
                else {
                    Write-Warn "  Source scope tag ID $srcId not found in content — keeping as-is"
                    $remappedScopeTagIds.Add("$srcId")
                }
            }

            if ($remappedScopeTagIds.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess("'$objectName' (ID: $policyId)", 'Patch scope tags')) {
                    # Enrollment configurations require @odata.type in PATCH body
                    $scopePayload = @{ roleScopeTagIds = @($remappedScopeTagIds) }
                    $existingEnrollConfig = $existingConfigs | Where-Object { $_.id -eq $policyId } | Select-Object -First 1
                    if ($existingEnrollConfig -and $existingEnrollConfig.'@odata.type') {
                        $scopePayload['@odata.type'] = $existingEnrollConfig.'@odata.type'
                    }
                    try {
                        $scopeBody = $scopePayload | ConvertTo-Json -Compress
                        Invoke-MgGraphRequest -Method PATCH `
                            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$policyId" `
                            -Body ([System.Text.Encoding]::UTF8.GetBytes($scopeBody)) `
                            -ContentType "application/json; charset=utf-8" `
                            -ErrorAction Stop | Out-Null
                        Write-Success "  Patched scope tags on '$objectName'"
                        $patched = $true
                    }
                    catch {
                        # Re-read to check if scope tags already match despite the PATCH error
                        try {
                            $recheck = Invoke-MgGraphRequest -Method GET `
                                -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$policyId`?`$select=roleScopeTagIds" `
                                -OutputType PSObject -ErrorAction Stop
                            $recheckTags = @($recheck.roleScopeTagIds)
                            $stillMissing = @($remappedScopeTagIds | Where-Object { $_ -notin $recheckTags })
                            if ($stillMissing.Count -eq 0) {
                                Write-Info "  Scope tags already correct on '$objectName'"
                            }
                            else {
                                Write-Warn "  Could not patch scope tags on '$objectName' (missing: $($stillMissing -join ', ')): $(Get-CleanErrorMessage $_)"
                            }
                        }
                        catch {
                            Write-Warn "  Could not patch scope tags on '$objectName': $(Get-CleanErrorMessage $_)"
                        }
                    }
                }
            }
        }

        # ── Patch assignments ──
        if ($sourceObj.PSObject.Properties['assignments'] -and $sourceObj.assignments.Count -gt 0) {
            $cleanAssignments = [System.Collections.Generic.List[object]]::new()

            foreach ($assignment in $sourceObj.assignments) {
                $target = $assignment.target
                if (-not $target) { continue }

                # Remap group IDs
                if ($target.groupId -and $migrationTable) {
                    $migObj = $migrationTable.Objects | Where-Object { $_.Id -eq $target.groupId } | Select-Object -First 1
                    if ($migObj) {
                        # Look up target group by display name
                        try {
                            $encoded = [System.Web.HttpUtility]::UrlEncode($migObj.DisplayName)
                            $groupResp = Invoke-MgGraphRequest -Method GET `
                                -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$encoded'" `
                                -OutputType PSObject -ErrorAction Stop
                            if ($groupResp.value -and $groupResp.value.Count -gt 0) {
                                $newGroupId = $groupResp.value[0].id
                                Write-Info "  Group: $($migObj.DisplayName) [$($target.groupId) -> $newGroupId]"
                                $target.groupId = $newGroupId
                            }
                            else {
                                Write-Warn "  Group '$($migObj.DisplayName)' not found in target — skipping assignment"
                                continue
                            }
                        }
                        catch {
                            Write-Warn "  Could not look up group '$($migObj.DisplayName)': $(Get-CleanErrorMessage $_)"
                            continue
                        }
                    }
                }

                $cleanAssignments.Add([PSCustomObject]@{
                        target = $target
                    })
            }

            if ($cleanAssignments.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess("'$objectName' (ID: $policyId)", "Patch $($cleanAssignments.Count) assignment(s)")) {
                    try {
                        $assignBody = @{
                            enrollmentConfigurationAssignments = @($cleanAssignments)
                        } | ConvertTo-Json -Depth 20
                        Invoke-MgGraphRequest -Method POST `
                            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$policyId/assign" `
                            -Body ([System.Text.Encoding]::UTF8.GetBytes($assignBody)) `
                            -ContentType "application/json; charset=utf-8" `
                            -ErrorAction Stop | Out-Null
                        Write-Success "  Patched $($cleanAssignments.Count) assignment(s) on '$objectName'"
                        $patched = $true
                    }
                    catch {
                        Write-Err "  Could not patch assignments on '$objectName': $(Get-CleanErrorMessage $_)"
                        $failedCount++
                    }
                }
            }
        }

        if ($patched) { $patchedCount++ } else { $skippedCount++ }
    }

    Write-Host ""
    Write-Host ("  " + "-" * 50) -ForegroundColor Gray
    Write-Info "Enrollment restriction assignment patching summary for $($Environment.ToUpper()):"
    if ($patchedCount -gt 0) { Write-Success "  $patchedCount policy/policies updated" }
    if ($skippedCount -gt 0) { Write-Info "  $skippedCount policy/policies skipped (no changes needed)" }
    if ($failedCount -gt 0) { Write-Err "  $failedCount policy/policies failed" }
    Write-Host ("  " + "-" * 50) -ForegroundColor Gray
}

# ─────────────────────────────────────────────────────────────
# INTUNE BRANDING IMPORT (delegated permissions)
# ─────────────────────────────────────────────────────────────
function Import-IntuneBranding {
    <#
    .SYNOPSIS
        Imports Intune Branding Profiles using the interactive user's delegated
        Graph token: creates prerequisite groups and scope tags, imports
        branding profiles, and applies group assignments — all in a single pass.
    .DESCRIPTION
        Intune Branding profile assignment endpoints require delegated
        permissions — app-only (UAMI/service principal) tokens are rejected
        or return "No OData route exists" errors when attempting to POST to
        the /assign action.  This function expects a valid MgGraph session
        to already be established via Connect-MgGraphForIntune (called once
        in the main flow). If the session is stale or for a different tenant,
        Test-MgGraphIntuneSession will transparently re-connect.

        The function resolves dependencies in-line:

        1. Reads the branding profile JSON files and extracts referenced
           group IDs, scope tag IDs, and assignment filter IDs from the
           assignments and roleScopeTagIds arrays.
        2. Resolves group display names via MigrationTable.json, checks
           whether the groups exist in the target tenant, and creates any
           that are missing (using the matching JSON definition from
           Content/Groups/).
        3. Resolves source scope tag display names, checks the target
           tenant, and creates any missing scope tags (using the matching
           JSON from Content/ScopeTags/).
        4. Resolves assignment filter display names via MigrationTable,
           checks the target tenant, and recreates any missing filters
           from the Content/AssignmentFilters/ JSON definitions.
        5. Imports each branding profile with the correct (remapped) scope
           tag IDs.
        6. Waits for Intune backend replication, then applies group
           assignments (include and exclude) using the bulk /assign action,
           with remapped group and assignment filter IDs.

        If a branding profile with the same profileName already exists in the
        target tenant it is gracefully skipped — no duplicate is created.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Environment
    )

    $contentPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/IntuneBranding"
    if (-not (Test-Path $contentPath)) {
        Write-Info "No IntuneBranding content folder found for '$Environment' — skipping"
        return
    }

    $jsonFiles = @(Get-ChildItem -Path $contentPath -Filter '*.json' -File -ErrorAction SilentlyContinue)
    if ($jsonFiles.Count -eq 0) {
        Write-Info "No branding profile files found in '$contentPath' — skipping"
        return
    }

    Write-StepHeader "IMPORTING INTUNE BRANDING PROFILES ($($Environment.ToUpper()))"
    Write-Info "Using Microsoft Graph delegated auth — required for branding assignment endpoints"
    Write-Info "Will ensure prerequisite groups and scope tags exist before importing"
    Write-Info "Found $($jsonFiles.Count) branding profile file(s) to process"

    # ── Load migration table for ID remapping ──
    $migrationFile = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/MigrationTable.json"
    $migrationTable = $null
    if (Test-Path $migrationFile) {
        $migrationTable = Get-Content -Path $migrationFile -Raw | ConvertFrom-Json
        Write-Info "Loaded migration table: $($migrationTable.Objects.Count) objects"
    }
    else {
        Write-Warn "No MigrationTable.json found — group ID remapping will be skipped"
    }

    # ── Load source scope tags for ID remapping ──
    $scopeTagPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/ScopeTags"
    $sourceScopeTags = @()
    if (Test-Path $scopeTagPath) {
        $sourceScopeTags = @(Get-ChildItem -Path $scopeTagPath -Filter '*.json' -File | ForEach-Object {
                Get-Content $_.FullName -Raw | ConvertFrom-Json
            })
        Write-Info "Loaded $($sourceScopeTags.Count) source scope tag(s) for remapping"
    }

    # ── Load source group definitions for creation ──
    $groupsContentPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/Groups"

    # ── Validate delegated MgGraph session for Intune operations ──
    $envTenantId = if ($script:EnvConfigs -and $script:EnvConfigs.ContainsKey($Environment)) {
        $script:EnvConfigs[$Environment].TenantId
    }
    else {
        $script:TenantId
    }

    if (-not (Test-MgGraphIntuneSession -TenantId $envTenantId)) {
        Write-Err "Cannot proceed without a valid Intune delegated session."
        return
    }

    # ── Get existing branding profiles in target tenant ──
    $existingProfiles = @()
    try {
        $existingResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles" `
            -OutputType PSObject -ErrorAction Stop
        if ($existingResp.value) {
            $existingProfiles = $existingResp.value
            Write-Info "Found $($existingProfiles.Count) existing branding profile(s) in target tenant"
        }
        else {
            Write-Info "No existing branding profiles found in target tenant"
        }
    }
    catch {
        Write-Warn "Could not retrieve existing branding profiles: $(Get-CleanErrorMessage $_)"
        Write-Warn "Will attempt imports individually — duplicates may cause errors that will be handled gracefully"
    }

    # ── Parse all branding files to discover referenced group IDs, scope tags, and assignment filters ──
    $allSourceObjs = @()
    foreach ($file in $jsonFiles) {
        try {
            $rawJson = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
            $allSourceObjs += $rawJson | ConvertFrom-Json -Depth 50 -ErrorAction Stop
        }
        catch {
            Write-Warn "Could not parse '$($file.Name)' for prerequisite scan — skipping"
        }
    }

    # ── Collect referenced group IDs from assignments ──
    $referencedGroupIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    # Also collect referenced assignment filter IDs from assignments
    $referencedFilterIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($srcObj in $allSourceObjs) {
        if ($srcObj.PSObject.Properties['assignments'] -and $srcObj.assignments) {
            foreach ($assignment in $srcObj.assignments) {
                if ($assignment.target -and $assignment.target.groupId) {
                    [void]$referencedGroupIds.Add($assignment.target.groupId)
                }
                if ($assignment.target -and $assignment.target.deviceAndAppManagementAssignmentFilterId `
                        -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne '00000000-0000-0000-0000-000000000000') {
                    [void]$referencedFilterIds.Add($assignment.target.deviceAndAppManagementAssignmentFilterId)
                }
            }
        }
    }

    # ── Collect referenced scope tag IDs ──
    $referencedScopeTagIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($srcObj in $allSourceObjs) {
        if ($srcObj.PSObject.Properties['roleScopeTagIds'] -and $srcObj.roleScopeTagIds) {
            foreach ($tagId in $srcObj.roleScopeTagIds) {
                if ("$tagId" -ne '0') {
                    [void]$referencedScopeTagIds.Add("$tagId")
                }
            }
        }
    }

    # ── Create missing scope tags ──
    $targetScopeTags = @()
    try {
        $scopeTagResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" `
            -OutputType PSObject -ErrorAction Stop
        if ($scopeTagResp.value) { $targetScopeTags = $scopeTagResp.value }
    }
    catch {
        Write-Warn "Could not retrieve target scope tags: $(Get-CleanErrorMessage $_)"
    }

    # Initialize group ID map early — Sync-ScopeTagAssignments may need it
    $groupIdMap = @{}

    $scopeTagIdMap = @{}
    $scopeTagIdMap['0'] = '0'
    if ($referencedScopeTagIds.Count -gt 0 -and $sourceScopeTags.Count -gt 0) {
        Write-Info "Checking $($referencedScopeTagIds.Count) referenced scope tag(s)..."
        foreach ($srcId in $referencedScopeTagIds) {
            $srcTag = $sourceScopeTags | Where-Object { "$($_.id)" -eq "$srcId" } | Select-Object -First 1
            if (-not $srcTag) {
                Write-Warn "  Source scope tag ID $srcId not found in Content/$Environment/ScopeTags — will use default"
                continue
            }
            $targetTag = $targetScopeTags | Where-Object { $_.displayName -eq $srcTag.displayName } | Select-Object -First 1
            if ($targetTag) {
                Write-Success "  Scope tag '$($srcTag.displayName)' already exists (ID: $($targetTag.id))"
                $scopeTagIdMap[$srcId] = "$($targetTag.id)"
                # Ensure group assignments match the source definition
                Sync-ScopeTagAssignments -SourceScopeTag $srcTag `
                    -TargetScopeTagId "$($targetTag.id)" `
                    -GroupIdMap $groupIdMap `
                    -MigrationObjects $migrationTable.Objects `
                    -GroupsContentPath $groupsContentPath
            }
            else {
                Write-Info "  Creating scope tag '$($srcTag.displayName)'..."
                try {
                    $newTag = @{
                        displayName = $srcTag.displayName
                        description = if ($srcTag.description) { $srcTag.description } else { "" }
                    } | ConvertTo-Json -Compress
                    $createdTag = Invoke-MgGraphRequest -Method POST `
                        -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" `
                        -Body ([System.Text.Encoding]::UTF8.GetBytes($newTag)) `
                        -ContentType "application/json; charset=utf-8" `
                        -OutputType PSObject -ErrorAction Stop
                    if ($createdTag.id) {
                        Write-Success "  Created scope tag '$($srcTag.displayName)' (ID: $($createdTag.id))"
                        $scopeTagIdMap[$srcId] = "$($createdTag.id)"
                        $targetScopeTags += $createdTag
                        # Apply group assignments from source definition
                        Sync-ScopeTagAssignments -SourceScopeTag $srcTag `
                            -TargetScopeTagId "$($createdTag.id)" `
                            -GroupIdMap $groupIdMap `
                            -MigrationObjects $migrationTable.Objects `
                            -GroupsContentPath $groupsContentPath
                    }
                }
                catch {
                    Write-Warn "  Could not create scope tag '$($srcTag.displayName)': $(Get-CleanErrorMessage $_)"
                }
            }
        }
    }

    # ── Create missing groups ──
    # (groupIdMap already initialized above for scope tag assignment sync)
    if ($referencedGroupIds.Count -gt 0 -and $migrationTable) {
        Write-Info "Checking $($referencedGroupIds.Count) referenced group(s)..."
        foreach ($srcGroupId in $referencedGroupIds) {
            $migObj = $migrationTable.Objects | Where-Object { $_.Id -eq $srcGroupId -and $_.Type -eq 'Group' } | Select-Object -First 1
            if (-not $migObj) {
                Write-Warn "  Group ID $srcGroupId not found in MigrationTable — will skip this assignment target"
                continue
            }

            $groupDisplayName = $migObj.DisplayName
            try {
                $groupResp = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($groupDisplayName -replace "'","''")'&`$select=id,displayName" `
                    -OutputType PSObject -ErrorAction Stop
                if ($groupResp.value -and $groupResp.value.Count -gt 0) {
                    $targetGroupId = $groupResp.value[0].id
                    Write-Success "  Group '$groupDisplayName' already exists (ID: $targetGroupId)"
                    $groupIdMap[$srcGroupId] = $targetGroupId
                    continue
                }
            }
            catch {
                Write-Warn "  Could not check for group '$groupDisplayName': $(Get-CleanErrorMessage $_)"
            }

            # Group not found — create from Content/Groups/ JSON definition
            $groupJsonFile = Join-Path $groupsContentPath "$groupDisplayName.json"
            if (-not (Test-Path $groupJsonFile)) {
                Write-Warn "  Group '$groupDisplayName' not found in target and no JSON definition at '$groupJsonFile' — will skip"
                continue
            }

            Write-Info "  Creating group '$groupDisplayName'..."
            try {
                $groupDef = Get-Content -Path $groupJsonFile -Raw | ConvertFrom-Json -Depth 50

                $newGroup = @{
                    displayName     = $groupDef.displayName
                    mailEnabled     = [bool]$groupDef.mailEnabled
                    mailNickname    = if ($groupDef.mailNickname) { $groupDef.mailNickname } else { ($groupDef.displayName -replace '[^a-zA-Z0-9]', '').Substring(0, [Math]::Min(64, ($groupDef.displayName -replace '[^a-zA-Z0-9]', '').Length)) }
                    securityEnabled = [bool]$groupDef.securityEnabled
                }
                if ($groupDef.description) { $newGroup['description'] = $groupDef.description }
                if ($groupDef.groupTypes -and $groupDef.groupTypes.Count -gt 0) {
                    $newGroup['groupTypes'] = @($groupDef.groupTypes)
                }
                else {
                    $newGroup['groupTypes'] = @()
                }
                if ($groupDef.membershipRule) {
                    $newGroup['membershipRule'] = $groupDef.membershipRule
                    $newGroup['membershipRuleProcessingState'] = if ($groupDef.membershipRuleProcessingState) { $groupDef.membershipRuleProcessingState } else { 'On' }
                    if ($newGroup['groupTypes'] -notcontains 'DynamicMembership') {
                        $newGroup['groupTypes'] += 'DynamicMembership'
                    }
                }

                $groupBody = $newGroup | ConvertTo-Json -Depth 10
                $createdGroup = Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/v1.0/groups" `
                    -Body ([System.Text.Encoding]::UTF8.GetBytes($groupBody)) `
                    -ContentType "application/json; charset=utf-8" `
                    -OutputType PSObject -ErrorAction Stop

                if ($createdGroup.id) {
                    Write-Success "  Created group '$groupDisplayName' (ID: $($createdGroup.id))"
                    $groupIdMap[$srcGroupId] = $createdGroup.id
                }
            }
            catch {
                $errMsg = Get-CleanErrorMessage $_
                $errDetail = "$($_.ErrorDetails.Message)$($_.Exception.Message)"
                if ($errDetail -match 'already exists' -or $errDetail -match 'ObjectConflict') {
                    Write-Info "  Group '$groupDisplayName' was created concurrently — looking it up..."
                    try {
                        $retryResp = Invoke-MgGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($groupDisplayName -replace "'","''")'&`$select=id" `
                            -OutputType PSObject -ErrorAction Stop
                        if ($retryResp.value -and $retryResp.value.Count -gt 0) {
                            $groupIdMap[$srcGroupId] = $retryResp.value[0].id
                            Write-Success "  Found group '$groupDisplayName' (ID: $($retryResp.value[0].id))"
                        }
                    }
                    catch {
                        Write-Warn "  Could not look up group '$groupDisplayName' after conflict: $(Get-CleanErrorMessage $_)"
                    }
                }
                else {
                    Write-Warn "  Could not create group '$groupDisplayName': $errMsg"
                }
            }
        }
    }

    # ── Resolve assignment filter IDs via MigrationTable — create missing from Content folder ──
    $filterIdMap = @{}
    $assignmentFiltersContentPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/AssignmentFilters"
    if ($referencedFilterIds.Count -gt 0 -and $migrationTable) {
        Write-Info "Resolving $($referencedFilterIds.Count) referenced assignment filter(s)..."
        # Fetch all assignment filters once
        $allFilters = @()
        try {
            $allFiltersResp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters?$select=id,displayName' `
                -OutputType PSObject -ErrorAction Stop
            $allFilters = @($allFiltersResp.value)
        }
        catch {
            Write-Warn "  Could not retrieve assignment filters: $(Get-CleanErrorMessage $_)"
        }
        foreach ($srcFilterId in $referencedFilterIds) {
            $migFilter = $migrationTable.Objects | Where-Object { $_.Id -eq $srcFilterId -and $_.Type -eq 'AssignmentFilter' } | Select-Object -First 1
            if (-not $migFilter) {
                Write-Warn "  Assignment filter ID $srcFilterId not found in MigrationTable — will clear on assignment"
                continue
            }
            $matchFilter = $allFilters | Where-Object { $_.displayName -eq $migFilter.DisplayName } | Select-Object -First 1
            if ($matchFilter) {
                $filterIdMap[$srcFilterId] = $matchFilter.id
                Write-Info "  Filter '$($migFilter.DisplayName)' already exists [$srcFilterId -> $($matchFilter.id)]"
            }
            else {
                # Filter not found in target — create from Content/AssignmentFilters/ JSON
                $filterJsonFile = Join-Path $assignmentFiltersContentPath "$($migFilter.DisplayName).json"
                if (-not (Test-Path $filterJsonFile)) {
                    Write-Warn "  Assignment filter '$($migFilter.DisplayName)' not found in target and no JSON at '$filterJsonFile' — will clear on assignment"
                    continue
                }

                Write-Info "  Creating assignment filter '$($migFilter.DisplayName)'..."
                try {
                    $filterDef = Get-Content -Path $filterJsonFile -Raw | ConvertFrom-Json -Depth 50

                    $newFilter = @{
                        displayName                    = $filterDef.displayName
                        platform                       = $filterDef.platform
                        rule                           = $filterDef.rule
                        assignmentFilterManagementType = $filterDef.assignmentFilterManagementType
                    }
                    if ($filterDef.description) { $newFilter['description'] = $filterDef.description }

                    # Remap roleScopeTags to target tenant IDs
                    if ($filterDef.PSObject.Properties['roleScopeTags'] -and $filterDef.roleScopeTags) {
                        $remappedFilterTags = [System.Collections.Generic.List[string]]::new()
                        foreach ($tagId in $filterDef.roleScopeTags) {
                            if ($scopeTagIdMap.ContainsKey("$tagId")) {
                                $remappedFilterTags.Add($scopeTagIdMap["$tagId"])
                            }
                            elseif ("$tagId" -eq '0') {
                                $remappedFilterTags.Add('0')
                            }
                        }
                        if ($remappedFilterTags.Count -eq 0) { $remappedFilterTags.Add('0') }
                        $newFilter['roleScopeTags'] = @($remappedFilterTags)
                    }

                    $filterBody = $newFilter | ConvertTo-Json -Depth 10
                    $createdFilter = Invoke-MgGraphRequest -Method POST `
                        -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters' `
                        -Body ([System.Text.Encoding]::UTF8.GetBytes($filterBody)) `
                        -ContentType "application/json; charset=utf-8" `
                        -OutputType PSObject -ErrorAction Stop

                    if ($createdFilter.id) {
                        Write-Success "  Created assignment filter '$($migFilter.DisplayName)' (ID: $($createdFilter.id))"
                        $filterIdMap[$srcFilterId] = $createdFilter.id
                        $allFilters += $createdFilter
                    }
                }
                catch {
                    $errMsg = Get-CleanErrorMessage $_
                    $errDetail = "$($_.ErrorDetails.Message)$($_.Exception.Message)"
                    if ($errDetail -match 'already exists' -or $errDetail -match 'conflict') {
                        Write-Info "  Assignment filter '$($migFilter.DisplayName)' was created concurrently — looking it up..."
                        try {
                            $retryResp = Invoke-MgGraphRequest -Method GET `
                                -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters?$select=id,displayName' `
                                -OutputType PSObject -ErrorAction Stop
                            $allFilters = @($retryResp.value)
                            $retryMatch = $allFilters | Where-Object { $_.displayName -eq $migFilter.DisplayName } | Select-Object -First 1
                        }
                        catch {
                            Write-Warn "  Could not re-fetch assignment filters: $(Get-CleanErrorMessage $_)"
                            $retryMatch = $null
                        }
                        if ($retryMatch) {
                            $filterIdMap[$srcFilterId] = $retryMatch.id
                            Write-Success "  Found assignment filter '$($migFilter.DisplayName)' (ID: $($retryMatch.id))"
                        }
                        else {
                            Write-Warn "  Could not resolve assignment filter '$($migFilter.DisplayName)' after conflict — will clear on assignment"
                        }
                    }
                    else {
                        Write-Warn "  Could not create assignment filter '$($migFilter.DisplayName)': $errMsg"
                    }
                }
            }
        }
    }

    $importedCount = 0
    $skippedCount = 0
    $failedCount = 0
    $assignedCount = 0

    foreach ($file in $jsonFiles) {
        $sourceObj = $null
        try {
            $rawJson = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
            $sourceObj = $rawJson | ConvertFrom-Json -Depth 50 -ErrorAction Stop
        }
        catch {
            Write-Warn "Could not parse '$($file.Name)' — skipping ($(Get-CleanErrorMessage $_))"
            $skippedCount++
            continue
        }

        $profileName = $sourceObj.profileName
        if (-not $profileName) {
            Write-Warn "Skipping '$($file.Name)' — no profileName property found in JSON"
            $skippedCount++
            continue
        }

        Write-Progress2 -Activity "IntuneBranding" -Status "Processing '$profileName'..."

        # Check if this branding profile already exists (match by profileName)
        $existingObj = $existingProfiles | Where-Object { $_.profileName -eq $profileName } | Select-Object -First 1
        $profileId = $null
        $wasCreated = $false

        if ($existingObj) {
            Write-Success "'$profileName' already exists in target tenant (ID: $($existingObj.id)) — will update assignments"
            $profileId = $existingObj.id
        }
        else {
            # ── Clone and strip properties that must not be sent on create ──
            $importObj = $sourceObj | ConvertTo-Json -Depth 50 | ConvertFrom-Json -Depth 50

            $removeProps = @(
                'id', 'createdDateTime', 'lastModifiedDateTime', 'assignments',
                '#microsoft.graph.assign'
            )
            foreach ($prop in $removeProps) {
                if ($importObj.PSObject.Properties[$prop]) {
                    $importObj.PSObject.Properties.Remove($prop)
                }
            }

            # Remove all OData metadata properties except @odata.type
            $odataProps = @($importObj.PSObject.Properties | Where-Object {
                    ($_.Name -like '@odata.*' -and $_.Name -ne '@odata.type') -or
                    $_.Name -match '.+@odata\.' -or
                    $_.Name -like '#*'
                } | ForEach-Object { $_.Name })
            foreach ($prop in $odataProps) {
                $importObj.PSObject.Properties.Remove($prop)
            }

            # Remap scope tags to target tenant IDs
            if ($importObj.PSObject.Properties['roleScopeTagIds']) {
                $remappedTags = [System.Collections.Generic.List[string]]::new()
                foreach ($tagId in $sourceObj.roleScopeTagIds) {
                    if ($scopeTagIdMap.ContainsKey("$tagId")) {
                        $remappedTags.Add($scopeTagIdMap["$tagId"])
                    }
                    elseif ("$tagId" -eq '0') {
                        $remappedTags.Add('0')
                    }
                }
                if ($remappedTags.Count -eq 0) { $remappedTags.Add('0') }
                $importObj.roleScopeTagIds = @($remappedTags)
            }

            # POST the branding profile
            try {
                $body = $importObj | ConvertTo-Json -Depth 50
                $result = Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles" `
                    -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
                    -ContentType "application/json; charset=utf-8" `
                    -OutputType PSObject -ErrorAction Stop

                if ($result.id) {
                    Write-Success "Created '$profileName' (ID: $($result.id))"
                    $profileId = $result.id
                    $wasCreated = $true
                    $importedCount++
                }
                else {
                    Write-Err "POST returned no ID for '$profileName'"
                    $failedCount++
                    continue
                }
            }
            catch {
                $errMsg = Get-CleanErrorMessage $_
                $errDetail = "$($_.ErrorDetails.Message)$($_.Exception.Message)"

                $isDuplicate = $false
                $httpStatus = $null
                if ($_.Exception.Response) {
                    try { $httpStatus = [int]$_.Exception.Response.StatusCode } catch { $null = $null }
                }
                if (-not $httpStatus -and $errDetail -match 'Status(?:Code)?\s*[:=]\s*(\d{3})') {
                    try { $httpStatus = [int]$Matches[1] } catch { $null = $null }
                }
                if ($httpStatus -eq 409 -or $errDetail -match 'already exists' -or $errDetail -match 'conflict') {
                    $isDuplicate = $true
                }

                if ($isDuplicate) {
                    Write-Success "'$profileName' already exists in target tenant (detected via API response) — looking up ID"
                    try {
                        $lookupResp = Invoke-MgGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles?`$filter=profileName eq '$($profileName -replace "'","''")'&`$select=id,profileName" `
                            -OutputType PSObject -ErrorAction Stop
                        if ($lookupResp.value -and $lookupResp.value.Count -gt 0) {
                            $profileId = $lookupResp.value[0].id
                            Write-Info "  Found existing profile ID: $profileId"
                        }
                    }
                    catch {
                        Write-Warn "  Could not look up existing profile: $(Get-CleanErrorMessage $_)"
                    }
                    $skippedCount++
                }
                elseif ($httpStatus -eq 403) {
                    Write-Err "Permission denied creating '$profileName' (HTTP 403). Ensure you are signed in with Intune Administrator permissions."
                    $failedCount++
                }
                elseif ($httpStatus -eq 401) {
                    Write-Err "Authentication expired creating '$profileName' (HTTP 401). Re-run the script to refresh the token."
                    $failedCount++
                }
                else {
                    Write-Err "Failed to create '$profileName': $errMsg"
                    $failedCount++
                }

                if (-not $profileId) { continue }
            }
        }

        # ── Ensure scope tags include the desired values on existing profiles ──
        if (-not $wasCreated -and $profileId) {
            if ($sourceObj.PSObject.Properties['roleScopeTagIds'] -and $sourceObj.roleScopeTagIds.Count -gt 0) {
                $desiredTags = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($tagId in $sourceObj.roleScopeTagIds) {
                    if ($scopeTagIdMap.ContainsKey("$tagId")) { [void]$desiredTags.Add($scopeTagIdMap["$tagId"]) }
                    elseif ("$tagId" -eq '0') { [void]$desiredTags.Add('0') }
                }

                # Read current scope tags on the profile
                $currentTags = @()
                try {
                    $profileResp = Invoke-MgGraphRequest -Method GET `
                        -Uri "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles/$profileId`?`$select=roleScopeTagIds" `
                        -OutputType PSObject -ErrorAction Stop
                    if ($profileResp.roleScopeTagIds) { $currentTags = @($profileResp.roleScopeTagIds) }
                }
                catch { $null = $null }

                $missingTags = @($desiredTags | Where-Object { $_ -notin $currentTags })
                if ($missingTags.Count -gt 0) {
                    $mergedTags = @($currentTags) + $missingTags | Select-Object -Unique
                    try {
                        $scopeBody = @{ roleScopeTagIds = @($mergedTags) } | ConvertTo-Json -Compress
                        Invoke-MgGraphRequest -Method PATCH `
                            -Uri "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles/$profileId" `
                            -Body ([System.Text.Encoding]::UTF8.GetBytes($scopeBody)) `
                            -ContentType "application/json; charset=utf-8" `
                            -ErrorAction Stop | Out-Null
                        Write-Success "  Added $($missingTags.Count) missing scope tag(s) on '$profileName'"
                    }
                    catch {
                        # Re-read to check if scope tags already match despite the PATCH error
                        try {
                            $recheck = Invoke-MgGraphRequest -Method GET `
                                -Uri "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles/$profileId`?`$select=roleScopeTagIds" `
                                -OutputType PSObject -ErrorAction Stop
                            $recheckTags = @($recheck.roleScopeTagIds)
                            $stillMissing = @($desiredTags | Where-Object { $_ -notin $recheckTags })
                            if ($stillMissing.Count -eq 0) {
                                Write-Info "  Scope tags already correct on '$profileName'"
                            }
                            else {
                                Write-Warn "  Could not patch scope tags on '$profileName' (missing: $($stillMissing -join ', ')): $(Get-CleanErrorMessage $_)"
                            }
                        }
                        catch {
                            Write-Warn "  Could not patch scope tags on '$profileName': $(Get-CleanErrorMessage $_)"
                        }
                    }
                }
            }
        }

        # ── Wait for backend replication before assigning ──
        # Newly created branding profiles need a short settle period for the
        # Intune backend to register the object. If the /assignments endpoint
        # isn't ready yet, the retry logic on the POST /assign call handles it.
        if ($wasCreated) {
            $settleSeconds = 2
            Write-Info "  Waiting ${settleSeconds}s for Intune backend replication before applying assignments..."
            Start-Sleep -Seconds $settleSeconds
        }

        # ── Readiness probe: poll /assignments until the backend is ready ──
        if ($sourceObj.PSObject.Properties['assignments'] -and $sourceObj.assignments.Count -gt 0) {
            $probeUri = "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles/$profileId/assignments"
            $probeReady = $false
            $probeMaxAttempts = 3
            $probeIntervalSec = 5
            for ($probe = 1; $probe -le $probeMaxAttempts; $probe++) {
                try {
                    Invoke-MgGraphRequest -Method GET -Uri $probeUri -ErrorAction Stop | Out-Null
                    $probeReady = $true
                    break
                }
                catch {
                    if ($probe -lt $probeMaxAttempts) {
                        Write-Info "  Waiting for branding profile backend replication (probe $probe/$probeMaxAttempts)..."
                    }
                    Start-Sleep -Seconds $probeIntervalSec
                }
            }

            if (-not $probeReady) {
                $totalWait = ($probeMaxAttempts * $probeIntervalSec) + $(if ($wasCreated) { 15 } else { 0 })
                Write-Warn "  Backend did not become ready for '$profileName' after ~${totalWait}s — will attempt assignment anyway"
            }

            # ── Read existing assignments for merge ──
            $existingAssignments = @()
            try {
                $existingAssignResp = Invoke-MgGraphRequest -Method GET -Uri $probeUri `
                    -OutputType PSObject -ErrorAction Stop
                if ($existingAssignResp.value) {
                    $existingAssignments = @($existingAssignResp.value)
                }
            }
            catch {
                Write-Warn "  Could not read existing assignments for merge: $(Get-CleanErrorMessage $_)"
            }

            # Build a dedup key set from existing assignments
            $existingKeys = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            foreach ($ea in $existingAssignments) {
                if (-not $ea.target -or -not $ea.target.groupId) { continue }
                $targetType = $ea.target.'@odata.type'
                $prefix = if ($targetType -match 'exclusionGroupAssignmentTarget') { 'exclude' } else { 'include' }
                [void]$existingKeys.Add("${prefix}:$($ea.target.groupId)")
            }

            # ── Build desired assignments from source ──
            $desiredAssignments = [System.Collections.Generic.List[object]]::new()
            foreach ($assignment in $sourceObj.assignments) {
                $target = $assignment.target
                if (-not $target -or -not $target.groupId) { continue }

                # Determine include vs exclude from source @odata.type
                $srcTargetType = $target.'@odata.type'
                $isExclude = $srcTargetType -match 'exclusionGroupAssignmentTarget'

                # Remap group ID
                $remappedGroupId = $null
                if ($groupIdMap.ContainsKey($target.groupId)) {
                    $remappedGroupId = $groupIdMap[$target.groupId]
                }
                else {
                    Write-Warn "  Skipping assignment — group '$($target.groupId)' could not be resolved"
                    continue
                }

                # Dedup key check
                $prefix = if ($isExclude) { 'exclude' } else { 'include' }
                $key = "${prefix}:$remappedGroupId"
                if ($existingKeys.Contains($key)) {
                    Write-Info "  Assignment '$key' already exists — skipping"
                    continue
                }

                # Build the Intune branding assignment object with required @odata.type annotations
                $assignTarget = @{
                    '@odata.type' = if ($isExclude) {
                        '#microsoft.graph.exclusionGroupAssignmentTarget'
                    }
                    else {
                        '#microsoft.graph.groupAssignmentTarget'
                    }
                    groupId       = $remappedGroupId
                }

                # Remap and preserve assignment filter properties when present
                if ($target.deviceAndAppManagementAssignmentFilterId `
                        -and $target.deviceAndAppManagementAssignmentFilterId -ne '00000000-0000-0000-0000-000000000000') {
                    if ($filterIdMap.ContainsKey($target.deviceAndAppManagementAssignmentFilterId)) {
                        $assignTarget['deviceAndAppManagementAssignmentFilterId'] = $filterIdMap[$target.deviceAndAppManagementAssignmentFilterId]
                        $assignTarget['deviceAndAppManagementAssignmentFilterType'] = if ($target.deviceAndAppManagementAssignmentFilterType) { $target.deviceAndAppManagementAssignmentFilterType } else { 'include' }
                    }
                    else {
                        Write-Warn "  Assignment filter not found in target for group $($remappedGroupId.Substring(0,8))... — cleared filter reference"
                    }
                }

                $assignmentObj = @{
                    '@odata.type' = '#microsoft.graph.intuneBrandingProfileAssignment'
                    target        = $assignTarget
                }
                $desiredAssignments.Add($assignmentObj)
                [void]$existingKeys.Add($key)
            }

            if ($desiredAssignments.Count -eq 0) {
                Write-Info "  All assignments for '$profileName' already exist — nothing to apply"
                continue
            }

            # ── Merge: combine existing + new into the final set ──
            # The /assign action replaces ALL assignments, so we must include
            # existing assignments in the payload to preserve them.
            $mergedAssignments = [System.Collections.Generic.List[object]]::new()

            # Add existing as minimal objects (preserving filter properties)
            foreach ($ea in $existingAssignments) {
                if (-not $ea.target -or -not $ea.target.groupId) { continue }
                $eaTargetType = $ea.target.'@odata.type'
                $eaTarget = @{
                    '@odata.type' = if ($eaTargetType -match 'exclusionGroupAssignmentTarget') {
                        '#microsoft.graph.exclusionGroupAssignmentTarget'
                    }
                    else {
                        '#microsoft.graph.groupAssignmentTarget'
                    }
                    groupId       = $ea.target.groupId
                }

                # Preserve existing assignment filter properties
                if ($ea.target.deviceAndAppManagementAssignmentFilterId `
                        -and $ea.target.deviceAndAppManagementAssignmentFilterId -ne '00000000-0000-0000-0000-000000000000') {
                    $eaTarget['deviceAndAppManagementAssignmentFilterId'] = $ea.target.deviceAndAppManagementAssignmentFilterId
                    $eaTarget['deviceAndAppManagementAssignmentFilterType'] = if ($ea.target.deviceAndAppManagementAssignmentFilterType) { $ea.target.deviceAndAppManagementAssignmentFilterType } else { 'include' }
                }

                $mergedAssignments.Add(@{
                        '@odata.type' = '#microsoft.graph.intuneBrandingProfileAssignment'
                        target        = $eaTarget
                    })
            }

            # Add new desired assignments
            foreach ($da in $desiredAssignments) {
                $mergedAssignments.Add($da)
            }

            # ── POST /assign with retry ──
            $assignBody = @{
                assignments = @($mergedAssignments)
            } | ConvertTo-Json -Depth 20
            $assignUri = "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles/$profileId/assign"

            $assignSuccess = $false
            $maxRetries = 3
            $retryDelay = 10
            for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
                try {
                    Invoke-MgGraphRequest -Method POST -Uri $assignUri `
                        -Body ([System.Text.Encoding]::UTF8.GetBytes($assignBody)) `
                        -ContentType "application/json; charset=utf-8" `
                        -ErrorAction Stop | Out-Null
                    $assignSuccess = $true
                    break
                }
                catch {
                    $assignErr = Get-CleanErrorMessage $_
                    if ($attempt -lt $maxRetries) {
                        Write-Warn "  Assignment attempt $attempt/$maxRetries failed: $assignErr — retrying in ${retryDelay}s..."
                        Start-Sleep -Seconds $retryDelay
                        $retryDelay = [Math]::Min(60, $retryDelay * 2)
                    }
                    else {
                        Write-Err "  Could not apply assignments on '$profileName' after $maxRetries attempts: $assignErr"
                    }
                }
            }

            if ($assignSuccess) {
                Write-Success "  Applied $($desiredAssignments.Count) new assignment(s) on '$profileName' ($($mergedAssignments.Count) total)"
                $assignedCount++
            }
            else {
                $failedCount++
            }
        }
    }

    # Print summary
    Write-Host ""
    Write-Host ("  " + "-" * 50) -ForegroundColor Gray
    Write-Info "Intune Branding import summary for $($Environment.ToUpper()):"
    if ($importedCount -gt 0) { Write-Success "  $importedCount profile(s) created" }
    if ($skippedCount -gt 0) { Write-Success "  $skippedCount profile(s) already existed — skipped creation" }
    if ($assignedCount -gt 0) { Write-Success "  $assignedCount profile(s) had assignments applied" }
    if ($failedCount -gt 0) { Write-Err "  $failedCount profile(s) failed" }
    if ($importedCount -eq 0 -and $skippedCount -gt 0 -and $failedCount -eq 0 -and $assignedCount -eq 0) {
        Write-Success "All branding profiles already exist with assignments — nothing to do"
    }
    Write-Host ("  " + "-" * 50) -ForegroundColor Gray
}

# ─────────────────────────────────────────────────────────────
# AZURE DEVOPS SETUP
# ─────────────────────────────────────────────────────────────
function New-ADOResources {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Creates multiple ADO resources')]
    [CmdletBinding(SupportsShouldProcess)]
    param([hashtable]$UamiDetails)

    # All commands in this function are native executables (az, git).
    # Under $ErrorActionPreference = 'Stop', stderr output from native commands
    # (even when redirected with 2>$null) can cause RemoteException hangs.
    # Switch to 'Continue' for the entire function and restore on exit.
    $prevEAPFunc = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        # (function body follows — restored in finally block at the end)

        # ── Login to ADO ──
        Write-StepHeader "AZURE DEVOPS AUTHENTICATION"

        # Acquire an ADO bearer token and set AZURE_DEVOPS_EXT_PAT
        # so az devops commands never trigger silent credential prompts that hang.
        $adoLoginOk = Invoke-ADOLogin
        if (-not $adoLoginOk) { return }

        # Verify connection via REST with a timeout — az devops project list can hang
        # even with AZURE_DEVOPS_EXT_PAT set if NTLM negotiate is attempted.
        Write-Info "Verifying connection to Azure DevOps..."
        $orgExists = $false
        $projects = $null
        try {
            $headers = @{ "Authorization" = "Bearer $($env:AZURE_DEVOPS_EXT_PAT)" }
            $projectsResponse = Invoke-RestMethod `
                -Uri "$($script:ADOBaseUrl)/_apis/projects?api-version=7.1" `
                -Headers $headers -TimeoutSec 30
            $orgExists = $true
            if ($projectsResponse) {
                $projects = $projectsResponse
            }
        }
        catch {
            Write-Warn "Could not reach organization '$ADOOrganization': $(Get-CleanErrorMessage $_)"
        }

        # If the organization doesn't exist, attempt to create it
        if (-not $orgExists) {
            $orgCreated = New-ADOOrganization
            if (-not $orgCreated) {
                Write-Err "Cannot connect to or create ADO organization '$ADOOrganization'."
                return
            }

            # Retry connection after org creation (with back-off for provisioning)
            $retryDelays = @(5, 10, 15)
            foreach ($delay in $retryDelays) {
                Start-Sleep -Seconds $delay
                try {
                    $headers = @{ "Authorization" = "Bearer $($env:AZURE_DEVOPS_EXT_PAT)" }
                    $projectsResponse = Invoke-RestMethod `
                        -Uri "$($script:ADOBaseUrl)/_apis/projects?api-version=7.1" `
                        -Headers $headers -TimeoutSec 30
                    $orgExists = $true
                    if ($projectsResponse) {
                        $projects = $projectsResponse
                    }
                    break
                }
                catch {
                    Write-Info "Organization not yet reachable, retrying in $delay seconds..."
                }
            }

            if (-not $orgExists) {
                Write-Err "Organization '$ADOOrganization' was created but cannot be reached. It may still be provisioning — retry in a minute."
                return
            }
        }

        Write-Success "Connected to Azure DevOps organization '$ADOOrganization'"

        # ── Associate Azure subscription for billing ──
        Set-ADOBilling

        # ── Create or verify ADO project ──
        Write-StepHeader "CREATING AZURE DEVOPS PROJECT"
        $existingProject = $projects.value | Where-Object { $_.name -eq $ADOProject }
        if ($existingProject) {
            Write-Success "Project '$ADOProject' already exists (ID: $($existingProject.id))"
            $projectId = $existingProject.id
        }
        else {
            Write-Info "Creating project '$ADOProject'..."
            $newProject = az devops project create --name $ADOProject --visibility private --source-control git --org $script:ADOBaseUrl -o json 2>$null | ConvertFrom-Json
            if ($newProject) {
                Write-Success "Project '$ADOProject' created (ID: $($newProject.id))"
                $projectId = $newProject.id
            }
            else {
                Write-Err "Failed to create project '$ADOProject'"
                return
            }
        }

        # ── Create or verify Git repository ──
        Write-StepHeader "CREATING GIT REPOSITORY"
        $adoHeaders = @{ "Authorization" = "Bearer $($env:AZURE_DEVOPS_EXT_PAT)"; "Content-Type" = "application/json" }
        $repos = $null
        try {
            $reposResp = Invoke-RestMethod `
                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/git/repositories?api-version=7.1" `
                -Headers $adoHeaders -TimeoutSec 30
            $repos = $reposResp.value
        }
        catch {
            Write-Warn "Could not list repositories: $_"
        }

        $existingRepo = $repos | Where-Object { $_.name -eq $ADORepoName }

        if ($existingRepo) {
            Write-Success "Repository '$ADORepoName' already exists"
        }
        else {
            Write-Info "Creating repository '$ADORepoName'..."
            try {
                $repoBody = @{ name = $ADORepoName; project = @{ id = $projectId } } | ConvertTo-Json -Compress
                $newRepo = Invoke-RestMethod `
                    -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/git/repositories?api-version=7.1" `
                    -Method POST -Headers $adoHeaders -Body $repoBody -TimeoutSec 30
                if ($newRepo.id) {
                    Write-Success "Repository '$ADORepoName' created"
                }
                else {
                    Write-Err "Failed to create repository '$ADORepoName'"
                    return
                }
            }
            catch {
                Write-Err "Failed to create repository '$ADORepoName': $_"
                return
            }
        }

        # ── Push local content ──
        Write-StepHeader "PUSHING LOCAL CONTENT TO ADO REPOSITORY"
        $remoteUrl = "https://$ADOOrganization@dev.azure.com/$ADOOrganization/$ADOProject/_git/$ADORepoName"

        Push-Location $LocalRepoPath
        try {
            # Initialize git if needed
            if (-not (Test-Path ".git")) {
                Write-Info "Initializing git repository..."
                git init 2>$null | Out-Null
                git add -A 2>$null | Out-Null
                git commit -m "Initial commit - Intune IaC configuration" 2>$null | Out-Null
                Write-Success "Local repository initialized and committed"
            }

            # Check for existing remote
            $existingRemotes = git remote 2>$null
            if ($existingRemotes -contains "origin") {
                $currentUrl = git remote get-url origin 2>$null
                if ($currentUrl -eq $remoteUrl) {
                    Write-Success "Remote 'origin' already set to correct URL"
                }
                else {
                    Write-Info "Updating remote 'origin' URL..."
                    git remote set-url origin $remoteUrl 2>$null
                    Write-Success "Remote 'origin' updated to $remoteUrl"
                }
            }
            else {
                Write-Info "Adding remote 'origin'..."
                git remote add origin $remoteUrl 2>$null
                Write-Success "Remote 'origin' added: $remoteUrl"
            }

            # Push
            $branchName = git branch --show-current 2>$null
            if (-not $branchName) { $branchName = "main" }

            Write-Info "Pushing branch '$branchName' to origin..."
            $pushResult = git push -u origin $branchName 2>&1
            $pushStr = $pushResult | Out-String
            if ($pushStr -match "Everything up-to-date" -or $pushStr -match "new branch" -or $pushStr -match "->") {
                Write-Success "Content pushed to ADO repository"
            }
            elseif ($pushStr -match "rejected") {
                Write-Warn "Push was rejected. Attempting pull with --allow-unrelated-histories..."
                git pull origin $branchName --allow-unrelated-histories --no-edit 2>&1 | Out-Null
                git push -u origin $branchName 2>&1 | Out-Null
                Write-Success "Content pushed to ADO repository (after merge)"
            }
            else {
                # Push may have succeeded despite non-standard output
                Write-Success "Push command completed"
            }
        }
        finally {
            Pop-Location
        }

        # ── Grant Build Service permission to push to repository ──
        # The export stage commits content back to the repo. The Build Service
        # identity needs "Contribute" permission to do this (GenericContribute bit = 4).
        Write-StepHeader "GRANTING BUILD SERVICE CONTRIBUTE PERMISSION ON REPOSITORY"
        try {
            # Resolve the repo ID
            $repoId = if ($existingRepo) { $existingRepo.id } elseif ($newRepo) { $newRepo.id } else { $null }
            if (-not $repoId) {
                Write-Warn "Could not determine repository ID — skipping Build Service permission grant."
                Write-Info "Manually grant Contribute permission: Project Settings > Repos > $ADORepoName > Security > Build Service > Contribute = Allow"
            }
            else {
                # Git Repositories security namespace ID (constant across all ADO orgs)
                $gitRepoSecurityNamespace = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
                # Security token for a specific repo: repoV2/{projectId}/{repoId}
                $securityToken = "repoV2/$projectId/$repoId"
                # GenericContribute permission bit
                $contributeBit = 4

                # Resolve the project-scoped Build Service identity
                # Format: "{ProjectName} Build Service ({OrgName})"
                $buildServiceName = "$ADOProject Build Service ($ADOOrganization)"
                Write-Info "Resolving identity: '$buildServiceName'..."

                # Use the Graph Subject Query API — more reliable for finding service identities
                $subjectQueryBody = @{ query = $buildServiceName; subjectKind = @('User') } | ConvertTo-Json -Compress
                $subjectResp = $null
                try {
                    $subjectResp = Invoke-RestMethod `
                        -Uri "https://vssps.dev.azure.com/$ADOOrganization/_apis/graph/subjectquery?api-version=7.1-preview.1" `
                        -Method POST -Headers $adoHeaders -Body $subjectQueryBody -TimeoutSec 30
                }
                catch {
                    Write-Info "Subject query API returned: $_"
                }

                $buildServiceSubject = $null
                if ($subjectResp -and $subjectResp.value) {
                    $buildServiceSubject = $subjectResp.value | Where-Object {
                        $_.displayName -eq $buildServiceName -or
                        $_.principalName -like "*Build*Service*"
                    } | Select-Object -First 1
                }

                # Fall back to VSSPS identities API if subject query didn't find it
                if (-not $buildServiceSubject) {
                    Write-Info "Trying VSSPS identities API..."
                    $identityResp = Invoke-RestMethod `
                        -Uri "https://vssps.dev.azure.com/$ADOOrganization/_apis/identities?searchFilter=General&filterValue=$([uri]::EscapeDataString($buildServiceName))&queryMembership=None&api-version=7.1" `
                        -Headers $adoHeaders -TimeoutSec 30

                    if ($identityResp.value -and $identityResp.value.Count -gt 0) {
                        $buildServiceSubject = $identityResp.value | Select-Object -First 1
                    }
                }

                # Last resort: try "Project Collection Build Service Accounts" group
                if (-not $buildServiceSubject) {
                    Write-Info "Trying 'Project Collection Build Service Accounts'..."
                    $subjectQueryBody2 = @{ query = 'Project Collection Build Service Accounts'; subjectKind = @('Group') } | ConvertTo-Json -Compress
                    try {
                        $subjectResp2 = Invoke-RestMethod `
                            -Uri "https://vssps.dev.azure.com/$ADOOrganization/_apis/graph/subjectquery?api-version=7.1-preview.1" `
                            -Method POST -Headers $adoHeaders -Body $subjectQueryBody2 -TimeoutSec 30
                        if ($subjectResp2.value -and $subjectResp2.value.Count -gt 0) {
                            $buildServiceSubject = $subjectResp2.value | Select-Object -First 1
                        }
                    }
                    catch {
                        Write-Info "Group subject query returned: $_"
                    }
                }

                if (-not $buildServiceSubject) {
                    Write-Warn "Could not resolve Build Service identity — skipping permission grant."
                    Write-Info "Manually grant Contribute permission: Project Settings > Repos > $ADORepoName > Security > Build Service > Contribute = Allow"
                }
                else {
                    # Build the identity descriptor from the subject
                    $identityDescriptor = $null
                    if ($buildServiceSubject.PSObject.Properties['descriptor']) {
                        $identityDescriptor = $buildServiceSubject.descriptor
                    }
                    elseif ($buildServiceSubject.PSObject.Properties['subjectDescriptor']) {
                        # Graph subject query returns subjectDescriptor — need to resolve to legacy descriptor
                        $identityDescriptor = $buildServiceSubject.subjectDescriptor
                    }

                    $identityName = if ($buildServiceSubject.PSObject.Properties['displayName']) {
                        $buildServiceSubject.displayName
                    }
                    elseif ($buildServiceSubject.PSObject.Properties['providerDisplayName']) {
                        $buildServiceSubject.providerDisplayName
                    }
                    else { $buildServiceName }

                    Write-Info "Found identity: $identityName"

                    # If we got a subjectDescriptor (from Graph API), resolve it to the
                    # legacy security descriptor needed for ACL operations
                    if ($identityDescriptor -and $identityDescriptor -match '^(svc|aad|vssgp)\.' -and
                        -not ($identityDescriptor -match '^Microsoft\.')) {
                        try {
                            $resolveResp = Invoke-RestMethod `
                                -Uri "https://vssps.dev.azure.com/$ADOOrganization/_apis/identities?subjectDescriptors=$identityDescriptor&api-version=7.1" `
                                -Headers $adoHeaders -TimeoutSec 30
                            if ($resolveResp.value -and $resolveResp.value.Count -gt 0) {
                                $legacyDescriptor = $resolveResp.value[0].descriptor
                                Write-Info "Resolved security descriptor: $legacyDescriptor"
                                $identityDescriptor = $legacyDescriptor
                            }
                        }
                        catch {
                            Write-Info "Could not resolve subject to security descriptor: $_"
                        }
                    }

                    if (-not $identityDescriptor) {
                        Write-Warn "Could not determine security descriptor — skipping permission grant."
                        Write-Info "Manually grant: Project Settings > Repos > $ADORepoName > Security > Build Service > Contribute = Allow"
                    }
                    else {
                        # Check current ACL for this identity on this repo
                        $aclResp = Invoke-RestMethod `
                            -Uri "$($script:ADOBaseUrl)/_apis/accesscontrollists/$($gitRepoSecurityNamespace)?token=$([uri]::EscapeDataString($securityToken))&api-version=7.1" `
                            -Headers $adoHeaders -TimeoutSec 30

                        # Use bracket notation — descriptors contain dots, semicolons, colons
                        # that break PowerShell's dot-notation property access
                        $existingAce = $null
                        if ($aclResp.value -and $aclResp.value.Count -gt 0 -and $aclResp.value[0].acesDictionary) {
                            $acesDict = $aclResp.value[0].acesDictionary
                            if ($acesDict -is [System.Collections.IDictionary]) {
                                $existingAce = $acesDict[$identityDescriptor]
                            }
                            elseif ($acesDict.PSObject.Properties[$identityDescriptor]) {
                                $existingAce = $acesDict.PSObject.Properties[$identityDescriptor].Value
                            }
                        }
                        $alreadyAllowed = $false
                        if ($existingAce) {
                            # Check if Contribute bit is already in the Allow mask
                            $alreadyAllowed = ($existingAce.allow -band $contributeBit) -eq $contributeBit
                        }

                        if ($alreadyAllowed) {
                            Write-Success "Build Service already has Contribute permission on '$ADORepoName'"
                        }
                        else {
                            # Grant Contribute via Access Control Entries API
                            $aceBody = @{
                                token                = $securityToken
                                merge                = $true
                                accessControlEntries = @(
                                    @{
                                        descriptor   = $identityDescriptor
                                        allow        = $contributeBit
                                        deny         = 0
                                        extendedInfo = @{}
                                    }
                                )
                            } | ConvertTo-Json -Depth 5

                            Invoke-RestMethod `
                                -Uri "$($script:ADOBaseUrl)/_apis/accesscontrolentries/$($gitRepoSecurityNamespace)?api-version=7.1" `
                                -Method POST -Headers $adoHeaders -Body $aceBody -TimeoutSec 30 | Out-Null

                            Write-Success "Granted Contribute permission to Build Service on '$ADORepoName'"
                        }
                    } # end descriptor null-check else
                }
            }
        }
        catch {
            Write-Warn "Could not grant Build Service Contribute permission: $_"
            Write-Info "Manually grant: Project Settings > Repos > $ADORepoName > Security > Build Service > Contribute = Allow"
        }

        # ── Create Service Connections ──
        Write-StepHeader "CREATING ADO SERVICE CONNECTIONS"

        if (-not $UamiDetails -or $UamiDetails.Count -eq 0) {
            Write-Warn "No UAMI details available — skipping service connection creation."
            Write-Info "Run without -SkipAzureSetup to create UAMIs and service connections together."
        }
        elseif (-not $script:AppRegistrationDetails -or $script:AppRegistrationDetails.Count -eq 0) {
            Write-Warn "No app registration details available — skipping service connection creation."
            Write-Info "Run without -SkipAzureSetup to create app registrations and service connections together."
        }
        else {
            foreach ($env in $Environments) {
                if (-not $script:AppRegistrationDetails.ContainsKey($env)) { continue }
                $appDetail = $script:AppRegistrationDetails[$env]
                $scName = "sc-intune-$env"

                Write-Progress2 -Activity $env -Status "Creating service connection '$scName' (app reg: $($appDetail.Name))..."

                # Check if it already exists via REST
                $existingSc = $null
                try {
                    $scListResp = Invoke-RestMethod `
                        -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/serviceendpoint/endpoints?api-version=7.1" `
                        -Headers $adoHeaders -TimeoutSec 30
                    $existingSc = $scListResp.value | Where-Object { $_.name -eq $scName }
                }
                catch {
                    Write-Warn "Could not list service endpoints: $_"
                }

                if ($existingSc) {
                    Write-Success "Service connection '$scName' already exists (ID: $($existingSc.id))"

                    # Verify the service principal ID matches the current app registration.
                    # After a teardown that rebuilds Azure resources, the app reg gets a new
                    # Client ID and the existing SC becomes stale.
                    $existingSpId = $existingSc.authorization.parameters.serviceprincipalid
                    $currentSpId = $appDetail.ClientId
                    if ($existingSpId -and $currentSpId -and $existingSpId -ne $currentSpId) {
                        Write-Warn "  Service principal ID mismatch — updating service connection..."
                        Write-Info "  Old: $existingSpId  →  New: $currentSpId"
                        try {
                            $envCfg = $script:EnvConfigs[$env]
                            $existingSc.authorization.parameters.serviceprincipalid = $currentSpId
                            $existingSc.authorization.parameters.tenantid = $envCfg.TenantId
                            $existingSc.data.subscriptionId = $envCfg.SubscriptionId
                            $existingSc.data.subscriptionName = $envCfg.SubscriptionName
                            $updateScBody = $existingSc | ConvertTo-Json -Depth 10 -Compress
                            Invoke-RestMethod `
                                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/serviceendpoint/endpoints/$($existingSc.id)?api-version=7.1" `
                                -Method PUT -Headers $adoHeaders -Body $updateScBody -TimeoutSec 30 | Out-Null
                            Write-Success "  Service connection '$scName' updated with new app registration"
                        }
                        catch {
                            Write-Err "  Could not update service connection '$scName': $_"
                            Write-Info "  Delete it manually in Project Settings > Service Connections and re-run."
                        }
                    }

                    # Ensure it is authorized for all pipelines
                    try {
                        $patchBody = @{
                            allPipelines = @{ authorized = $true }
                        } | ConvertTo-Json -Depth 5 -Compress
                        Invoke-RestMethod `
                            -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/pipelines/pipelinepermissions/endpoint/$($existingSc.id)?api-version=7.1-preview.1" `
                            -Method PATCH -Headers $adoHeaders -Body $patchBody -TimeoutSec 30 | Out-Null
                        Write-Success "  Authorized for all pipelines"
                    }
                    catch {
                        Write-Warn "  Could not auto-authorize for pipelines: $_"
                        Write-Info "  Authorize manually: Project Settings > Service Connections > $scName > ⋮ > Security > Grant access to all pipelines"
                    }
                    continue
                }

                # Create ARM service connection with Workload Identity Federation via REST
                # Uses the app registration as the service principal (for Graph API access)
                $envCfg = $script:EnvConfigs[$env]
                $scConfig = @{
                    data                             = @{
                        subscriptionId   = $envCfg.SubscriptionId
                        subscriptionName = $envCfg.SubscriptionName
                    }
                    name                             = $scName
                    type                             = "AzureRM"
                    url                              = "https://management.azure.com/"
                    authorization                    = @{
                        parameters = @{
                            tenantid           = $envCfg.TenantId
                            serviceprincipalid = $appDetail.ClientId
                        }
                        scheme     = "WorkloadIdentityFederation"
                    }
                    isShared                         = $false
                    isReady                          = $true
                    serviceEndpointProjectReferences = @(
                        @{
                            projectReference = @{ id = $projectId; name = $ADOProject }
                            name             = $scName
                        }
                    )
                }

                try {
                    $scBody = $scConfig | ConvertTo-Json -Depth 10 -Compress
                    $createdScObj = Invoke-RestMethod `
                        -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/serviceendpoint/endpoints?api-version=7.1" `
                        -Method POST -Headers $adoHeaders -Body $scBody -TimeoutSec 30

                    if ($createdScObj.id) {
                        Write-Success "Service connection '$scName' created (ID: $($createdScObj.id))"
                        # Grant access to all pipelines via REST
                        try {
                            $patchBody = @{
                                allPipelines = @{
                                    authorized = $true
                                }
                            } | ConvertTo-Json -Depth 5 -Compress
                            # Use the pipeline permissions API
                            Invoke-RestMethod `
                                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/pipelines/pipelinepermissions/endpoint/$($createdScObj.id)?api-version=7.1-preview.1" `
                                -Method PATCH -Headers $adoHeaders -Body $patchBody -TimeoutSec 30 | Out-Null
                            Write-Info "  Granted access to all pipelines"
                        }
                        catch {
                            Write-Warn "  Could not auto-grant pipeline access: $_"
                            Write-Info "  Grant access manually in Project Settings > Service Connections"
                        }
                    }
                    else {
                        Write-Warn "Service connection '$scName' may need manual creation via ADO portal."
                        Write-Info "  Use: Project Settings > Service Connections > Azure Resource Manager > Workload Identity Federation (manual)"
                        Write-Info "  Service Principal Id (App Registration): $($appDetail.ClientId)"
                    }
                }
                catch {
                    Write-Warn "Service connection '$scName' creation failed: $_"
                    Write-Info "  Create manually: Project Settings > Service Connections > Azure Resource Manager > Workload Identity Federation (manual)"
                    Write-Info "  Service Principal Id (App Registration): $($appDetail.ClientId)"
                }
            }
        }

        # ── Create Environments ──
        Write-StepHeader "CREATING ADO ENVIRONMENTS"

        foreach ($env in $Environments) {
            $envName = "intune-$env"
            Write-Progress2 -Activity $env -Status "Creating environment '$envName'..."

            # Check if environment exists via REST
            $existingEnv = $null
            try {
                $envListResp = Invoke-RestMethod `
                    -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/distributedtask/environments?api-version=7.1" `
                    -Headers $adoHeaders -TimeoutSec 30
                $existingEnv = $envListResp.value | Where-Object { $_.name -eq $envName }
            }
            catch {
                Write-Warn "Could not list environments: $_"
            }

            if ($existingEnv) {
                Write-Success "Environment '$envName' already exists"
                # Ensure it is authorized for all pipelines
                try {
                    $patchBody = @{
                        allPipelines = @{ authorized = $true }
                    } | ConvertTo-Json -Depth 5 -Compress
                    Invoke-RestMethod `
                        -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/pipelines/pipelinepermissions/environment/$($existingEnv.id)?api-version=7.1-preview.1" `
                        -Method PATCH -Headers $adoHeaders -Body $patchBody -TimeoutSec 30 | Out-Null
                    Write-Success "  Authorized for all pipelines"
                }
                catch {
                    Write-Warn "  Could not auto-authorize environment for pipelines: $_"
                    Write-Info "  Authorize manually: Pipelines > Environments > $envName > ⋮ > Security > Grant access to all pipelines"
                }
            }
            else {
                try {
                    $envBody = @{ name = $envName; description = "Intune $env environment" } | ConvertTo-Json -Compress
                    $newEnv = Invoke-RestMethod `
                        -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/distributedtask/environments?api-version=7.1" `
                        -Method POST -Headers $adoHeaders -Body $envBody -TimeoutSec 30

                    if ($newEnv.id) {
                        Write-Success "Environment '$envName' created (ID: $($newEnv.id))"
                        # Grant access to all pipelines
                        try {
                            $patchBody = @{
                                allPipelines = @{ authorized = $true }
                            } | ConvertTo-Json -Depth 5 -Compress
                            Invoke-RestMethod `
                                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/pipelines/pipelinepermissions/environment/$($newEnv.id)?api-version=7.1-preview.1" `
                                -Method PATCH -Headers $adoHeaders -Body $patchBody -TimeoutSec 30 | Out-Null
                            Write-Info "  Granted access to all pipelines"
                        }
                        catch {
                            Write-Warn "  Could not auto-grant pipeline access: $_"
                            Write-Info "  Grant access manually: Pipelines > Environments > $envName > ⋮ > Security > Grant access to all pipelines"
                        }
                    }
                    else {
                        Write-Err "Failed to create environment '$envName'"
                    }
                }
                catch {
                    Write-Err "Failed to create environment '$envName': $_"
                }
            }
        }

        # ── Create Approval Gates ──
        if ($StagingApprovers.Count -gt 0 -or $ProductionApprovers.Count -gt 0) {
            Write-StepHeader "CREATING APPROVAL GATES ON ENVIRONMENTS"

            # List environments to get their IDs
            $envListForApproval = $null
            try {
                $envListResp2 = Invoke-RestMethod `
                    -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/distributedtask/environments?api-version=7.1" `
                    -Headers $adoHeaders -TimeoutSec 30
                $envListForApproval = $envListResp2.value
            }
            catch {
                Write-Warn "Could not list environments for approval gates: $_"
            }

            if ($envListForApproval) {
                $approvalConfigs = @(
                    @{ EnvName = "intune-staging"; Approvers = $StagingApprovers }
                    @{ EnvName = "intune-production"; Approvers = $ProductionApprovers }
                )

                foreach ($ac in $approvalConfigs) {
                    if ($ac.Approvers.Count -eq 0) { continue }
                    $targetEnv = $envListForApproval | Where-Object { $_.name -eq $ac.EnvName }
                    if (-not $targetEnv) {
                        Write-Warn "Environment '$($ac.EnvName)' not found — skipping approval gate"
                        continue
                    }

                    Write-Progress2 -Activity $ac.EnvName -Status "Adding approval check..."

                    # Check if an approval already exists
                    $existingChecks = $null
                    try {
                        $checksResp = Invoke-RestMethod `
                            -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/pipelines/checks/configurations?resourceType=environment&resourceId=$($targetEnv.id)&api-version=7.1-preview.1" `
                            -Headers $adoHeaders -TimeoutSec 30
                        $existingChecks = $checksResp.value | Where-Object { $_.type.name -eq "Approval" }
                    }
                    catch {
                        Write-Warn "Could not check existing approvals: $_"
                    }

                    if ($existingChecks) {
                        Write-Success "Approval check already exists on '$($ac.EnvName)'"
                        continue
                    }

                    # Create approval check
                    $approverList = @()
                    foreach ($approver in $ac.Approvers) {
                        $approverList += @{ displayName = $approver; uniqueName = $approver }
                    }

                    $checkBody = @{
                        type     = @{ id = "8C6F20A7-A545-4486-9777-F762FAFE0D4D"; name = "Approval" }
                        settings = @{
                            approvers                 = $approverList
                            executionOrder            = "anyOrder"
                            minRequiredApprovers      = 1
                            instructions              = "Approve deployment to $($ac.EnvName)"
                            blockedApprovers          = @()
                            requesterCannotBeApprover = $false
                        }
                        resource = @{ type = "environment"; id = "$($targetEnv.id)" }
                    } | ConvertTo-Json -Depth 5 -Compress

                    try {
                        $checkResult = Invoke-RestMethod `
                            -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/pipelines/checks/configurations?api-version=7.1-preview.1" `
                            -Method POST -Headers $adoHeaders -Body $checkBody -TimeoutSec 30
                        if ($checkResult.id) {
                            Write-Success "Approval gate created on '$($ac.EnvName)' (approvers: $($ac.Approvers -join ', '))"
                        }
                        else {
                            Write-Warn "Could not create approval gate on '$($ac.EnvName)'"
                        }
                    }
                    catch {
                        Write-Warn "Could not create approval gate on '$($ac.EnvName)': $_"
                        Write-Info "  Add manually: Pipelines > Environments > $($ac.EnvName) > Approvals and checks"
                    }
                }
            }
        }

        # ── Create Variable Group ──
        Write-StepHeader "CREATING ADO VARIABLE GROUP"
        $vgName = "intune-pipeline-vars"

        $matchVg = $null
        try {
            $vgListResp = Invoke-RestMethod `
                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/distributedtask/variablegroups?api-version=7.1" `
                -Headers $adoHeaders -TimeoutSec 30
            $matchVg = $vgListResp.value | Where-Object { $_.name -eq $vgName }
        }
        catch {
            Write-Warn "Could not list variable groups: $_"
        }

        if ($matchVg) {
            Write-Success "Variable group '$vgName' already exists (ID: $($matchVg.id))"

            # Sync variables that may have changed since last run.
            $vgNeedsUpdate = $false
            $existingVars = $matchVg.variables

            # Verify environment-specific variables still match current app registrations.
            # After a teardown that rebuilds Azure resources, Client IDs and Tenant IDs
            # may have changed. Update any stale values in-place.
            if ($script:AppRegistrationDetails -and $script:AppRegistrationDetails.Count -gt 0) {

                foreach ($env in $Environments) {
                    $prefix = $env.ToUpper()

                    # Check UAMI Client ID (actually the app registration Client ID)
                    $clientIdKey = "$($prefix)_UAMI_CLIENT_ID"
                    if ($script:AppRegistrationDetails.ContainsKey($env)) {
                        $currentClientId = $script:AppRegistrationDetails[$env].ClientId
                        $hasProp = $existingVars.PSObject.Properties.Match($clientIdKey).Count -gt 0
                        $existingClientId = if ($hasProp) { $existingVars.$clientIdKey.value } else { $null }
                        if ($currentClientId -and $existingClientId -ne $currentClientId) {
                            Write-Info "  Updating ${clientIdKey}: $existingClientId → $currentClientId"
                            if (-not $hasProp) {
                                $existingVars | Add-Member -NotePropertyName $clientIdKey -NotePropertyValue @{ value = $currentClientId }
                            }
                            else {
                                $existingVars.$clientIdKey.value = $currentClientId
                            }
                            $vgNeedsUpdate = $true
                        }
                    }

                    # Check Tenant ID
                    $tenantIdKey = "$($prefix)_TENANT_ID"
                    $currentTenantVal = if ($script:EnvConfigs -and $script:EnvConfigs.ContainsKey($env)) { $script:EnvConfigs[$env].TenantId } else { $script:TenantId }
                    $hasTenantProp = $existingVars.PSObject.Properties.Match($tenantIdKey).Count -gt 0
                    $existingTenantVal = if ($hasTenantProp) { $existingVars.$tenantIdKey.value } else { $null }
                    if ($currentTenantVal -and $existingTenantVal -ne $currentTenantVal) {
                        Write-Info "  Updating ${tenantIdKey}: $existingTenantVal → $currentTenantVal"
                        if (-not $hasTenantProp) {
                            $existingVars | Add-Member -NotePropertyName $tenantIdKey -NotePropertyValue @{ value = $currentTenantVal }
                        }
                        else {
                            $existingVars.$tenantIdKey.value = $currentTenantVal
                        }
                        $vgNeedsUpdate = $true
                    }
                }
            }

            # Sync PRODUCTION_ONLY flag to match run mode (always, even without app reg details)
            $prodOnlyVal = if ($ProductionOnly) { "true" } else { "false" }
            $hasProdOnlyProp = $existingVars.PSObject.Properties.Match('PRODUCTION_ONLY').Count -gt 0
            $existingProdOnly = if ($hasProdOnlyProp) { $existingVars.PRODUCTION_ONLY.value } else { $null }
            if ($existingProdOnly -ne $prodOnlyVal) {
                Write-Info "  Updating PRODUCTION_ONLY: $existingProdOnly → $prodOnlyVal"
                if (-not $hasProdOnlyProp) {
                    $existingVars | Add-Member -NotePropertyName "PRODUCTION_ONLY" -NotePropertyValue @{ value = $prodOnlyVal }
                }
                else {
                    $existingVars.PRODUCTION_ONLY.value = $prodOnlyVal
                }
                $vgNeedsUpdate = $true
            }

            if ($vgNeedsUpdate) {
                Write-Info "Updating variable group with current values..."
                try {
                    $updateVgBody = @{
                        id                             = $matchVg.id
                        name                           = $vgName
                        type                           = "Vsts"
                        variables                      = $existingVars
                        variableGroupProjectReferences = @(
                            @{
                                projectReference = @{ id = $projectId; name = $ADOProject }
                                name             = $vgName
                            }
                        )
                    } | ConvertTo-Json -Depth 10 -Compress
                    Invoke-RestMethod `
                        -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/distributedtask/variablegroups/$($matchVg.id)?api-version=7.1" `
                        -Method PUT -Headers $adoHeaders -Body $updateVgBody -TimeoutSec 30 | Out-Null
                    Write-Success "Variable group '$vgName' updated with current values"
                }
                catch {
                    Write-Err "Could not update variable group: $_"
                    Write-Info "Update stale values manually: Pipelines > Library > $vgName"
                }
            }
            else {
                Write-Info "Variable group values are up to date"
            }

            # Ensure it is authorized for all pipelines
            try {
                $authBody = @{
                    allPipelines = @{ authorized = $true }
                } | ConvertTo-Json -Depth 5 -Compress
                Invoke-RestMethod `
                    -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/pipelines/pipelinepermissions/variablegroup/$($matchVg.id)?api-version=7.1-preview.1" `
                    -Method PATCH -Headers $adoHeaders -Body $authBody -TimeoutSec 30 | Out-Null
                Write-Success "Variable group authorized for all pipelines"
            }
            catch {
                Write-Warn "Could not auto-authorize variable group for pipelines: $_"
                Write-Info "Manually authorize: Pipelines > Library > $vgName > Pipeline permissions > Open access"
            }
        }
        else {
            Write-Info "Creating variable group '$vgName'..."

            # Build variables hashtable
            $varsHash = @{}
            foreach ($env in $Environments) {
                $prefix = $env.ToUpper()
                $tenantVal = if ($script:EnvConfigs -and $script:EnvConfigs.ContainsKey($env)) { $script:EnvConfigs[$env].TenantId } else { $script:TenantId }
                # Use app registration client ID (for Graph API via OIDC)
                $clientVal = if ($script:AppRegistrationDetails -and $script:AppRegistrationDetails.ContainsKey($env)) { $script:AppRegistrationDetails[$env].ClientId } else { "<SET-ME>" }
                $scVal = "sc-intune-$env"

                $varsHash["$($prefix)_TENANT_ID"] = @{ value = $tenantVal }
                $varsHash["$($prefix)_UAMI_CLIENT_ID"] = @{ value = $clientVal }
                $varsHash["$($prefix)_SERVICE_CONNECTION"] = @{ value = $scVal }
            }

            # Add PRODUCTION_ONLY flag
            $varsHash["PRODUCTION_ONLY"] = @{ value = if ($ProductionOnly) { "true" } else { "false" } }

            # Optional feature flags (all disabled by default)
            $varsHash["ENABLE_UPDATE_EXISTING"] = @{ value = "false" }
            $varsHash["WHATIF_ONLY"] = @{ value = "false" }
            $varsHash["ENABLE_TRANSFORMATIONS"] = @{ value = "false" }
            $varsHash["ENABLE_BACKUP_TO_REPO"] = @{ value = "false" }
            $varsHash["LOG_ANALYTICS_WORKSPACE_ID"] = @{ value = "" }
            $varsHash["LOG_ANALYTICS_SHARED_KEY"] = @{ value = ""; isSecret = $true }

            # Additional optional features
            $varsHash["ENABLE_DRIFT_DETECTION"] = @{ value = "false" }
            $varsHash["ENABLE_POST_IMPORT_HEALTHCHECK"] = @{ value = "false" }
            $varsHash["ENABLE_NOTIFICATIONS"] = @{ value = "false" }
            $varsHash["NOTIFICATION_WEBHOOK_URL"] = @{ value = "" }
            $varsHash["ENABLE_ASSIGNMENT_PREVALIDATION"] = @{ value = "false" }
            $varsHash["ENABLE_GIT_TAGGING"] = @{ value = "false" }
            $varsHash["ENABLE_INVENTORY_REPORT"] = @{ value = "false" }
            $varsHash["ENABLE_STALE_CONTENT_DETECTION"] = @{ value = "false" }
            $varsHash["STALE_CONTENT_DAYS"] = @{ value = "180" }
            $varsHash["IMPORT_TYPES"] = @{ value = "" }
            $varsHash["EXPORT_TYPES"] = @{ value = "" }
            $varsHash["ENABLE_CONTENT_FILTERING"] = @{ value = "false" }
            $varsHash["CONTENT_NAME_INCLUDE_FILTER"] = @{ value = "" }
            $varsHash["CONTENT_NAME_EXCLUDE_FILTER"] = @{ value = "" }
            $varsHash["CONTENT_TYPE_INCLUDE_FILTER"] = @{ value = "" }
            $varsHash["CONTENT_TYPE_EXCLUDE_FILTER"] = @{ value = "" }
            $varsHash["ENABLE_CHANGED_ONLY_IMPORT"] = @{ value = "false" }

            $vgBody = @{
                name                           = $vgName
                type                           = "Vsts"
                variables                      = $varsHash
                variableGroupProjectReferences = @(
                    @{
                        projectReference = @{ id = $projectId; name = $ADOProject }
                        name             = $vgName
                    }
                )
            } | ConvertTo-Json -Depth 5 -Compress

            try {
                $vgResult = Invoke-RestMethod `
                    -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/distributedtask/variablegroups?api-version=7.1" `
                    -Method POST -Headers $adoHeaders -Body $vgBody -TimeoutSec 30
                if ($vgResult.id) {
                    Write-Success "Variable group '$vgName' created (ID: $($vgResult.id))"
                    # Authorize for all pipelines
                    try {
                        $authBody = @{
                            allPipelines = @{ authorized = $true }
                        } | ConvertTo-Json -Depth 5 -Compress
                        Invoke-RestMethod `
                            -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/pipelines/pipelinepermissions/variablegroup/$($vgResult.id)?api-version=7.1-preview.1" `
                            -Method PATCH -Headers $adoHeaders -Body $authBody -TimeoutSec 30 | Out-Null
                    }
                    catch {
                        Write-Warn "Could not auto-authorize variable group for pipelines: $_"
                    }
                }
                else {
                    Write-Warn "Could not create variable group via REST. Create it manually in ADO > Pipelines > Library."
                }
            }
            catch {
                Write-Warn "Could not create variable group: $_"
                Write-Info "Create it manually in ADO > Pipelines > Library."
            }
        }

        # ── Create Pipelines ──
        Write-StepHeader "CREATING ADO PIPELINES"

        # Get repository ID for pipeline creation
        $repoId = $null
        try {
            $reposResp2 = Invoke-RestMethod `
                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/git/repositories?api-version=7.1" `
                -Headers $adoHeaders -TimeoutSec 30
            $targetRepo = $reposResp2.value | Where-Object { $_.name -eq $ADORepoName }
            if ($targetRepo) { $repoId = $targetRepo.id }
        }
        catch {
            Write-Warn "Could not look up repository ID: $_"
        }

        $pipelineConfigs = @(
            @{
                Name      = "Intune CICD"
                YamlPath  = "/azure-pipelines.yml"
                DisableCI = $false
            }
            @{
                Name      = "Intune Rollback"
                YamlPath  = "/pipelines/templates/rollback-pipeline.yml"
                DisableCI = $true
            }
            @{
                Name      = "Intune Drift Detection"
                YamlPath  = "/pipelines/templates/drift-detection-pipeline.yml"
                DisableCI = $true
            }
        )

        foreach ($config in $pipelineConfigs) {
            Write-Progress2 -Activity "Pipeline" -Status "Creating '$($config.Name)'..."

            # List existing pipelines via REST
            $pipelineId = $null
            $matchPl = $null
            try {
                $plListResp = Invoke-RestMethod `
                    -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/pipelines?api-version=7.1" `
                    -Headers $adoHeaders -TimeoutSec 30
                $matchPl = $plListResp.value | Where-Object { $_.name -eq $config.Name }
            }
            catch {
                Write-Warn "Could not list pipelines: $_"
            }

            if ($matchPl) {
                Write-Success "Pipeline '$($config.Name)' already exists"
                $pipelineId = $matchPl.id
            }
            elseif (-not $repoId) {
                Write-Warn "Cannot create pipeline '$($config.Name)' — repository ID not found. Create it manually in ADO."
                continue
            }
            else {
                try {
                    $plBody = @{
                        name          = $config.Name
                        configuration = @{
                            type       = "yaml"
                            path       = $config.YamlPath
                            repository = @{
                                id   = $repoId
                                type = "azureReposGit"
                            }
                        }
                    } | ConvertTo-Json -Depth 5 -Compress

                    $pl = Invoke-RestMethod `
                        -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/pipelines?api-version=7.1" `
                        -Method POST -Headers $adoHeaders -Body $plBody -TimeoutSec 30

                    if ($pl.id) {
                        Write-Success "Pipeline '$($config.Name)' created (ID: $($pl.id))"
                        $pipelineId = $pl.id
                    }
                    else {
                        Write-Warn "Could not create pipeline '$($config.Name)'. Create it manually in ADO."
                        continue
                    }
                }
                catch {
                    Write-Warn "Could not create pipeline '$($config.Name)': $_"
                    Write-Info "Create it manually in ADO > Pipelines."
                    continue
                }
            }

            # Disable CI triggers for pipelines that should only be run manually (e.g., Rollback).
            # Uses "Override the YAML continuous integration trigger from here" + "Disable CI"
            # via the Build Definitions REST API (api-version 7.1-preview.7 is required for the
            # trigger override to be persisted reliably).  This is idempotent — if the override
            # is already in place, the PUT is skipped unless the state has drifted.
            # YAML 'trigger: none' in the pipeline file provides a secondary defense.
            if ($config.DisableCI -and $pipelineId) {
                try {
                    $defApiVersion = "7.1-preview.7"
                    $defUri = "$($script:ADOBaseUrl)/$ADOProject/_apis/build/definitions/$($pipelineId)?api-version=$defApiVersion"

                    # GET the full build definition
                    $defResp = Invoke-RestMethod -Uri $defUri -Headers $adoHeaders -TimeoutSec 30

                    # Idempotency check: see if CI override is already configured
                    $alreadyDisabled = $false
                    if ($defResp.PSObject.Properties['triggers'] -and $defResp.triggers) {
                        $ciTrigger = @($defResp.triggers) | Where-Object {
                            $_.triggerType -eq 'continuousIntegration' -or $_.triggerType -eq 2
                        } | Select-Object -First 1
                        if ($ciTrigger -and
                            $ciTrigger.settingsSourceType -eq 2 -and
                            @($ciTrigger.branchFilters).Count -eq 0 -and
                            @($ciTrigger.pathFilters).Count -eq 0) {
                            $alreadyDisabled = $true
                        }
                    }

                    if ($alreadyDisabled) {
                        Write-Success "CI override already disabled on '$($config.Name)' — no update needed"
                    }
                    else {
                        # Preserve any non-CI triggers (e.g., scheduled) and replace/add the CI override
                        $existingTriggers = @()
                        if ($defResp.PSObject.Properties['triggers'] -and $defResp.triggers) {
                            $existingTriggers = @($defResp.triggers)
                        }
                        $otherTriggers = @($existingTriggers | Where-Object {
                                $_.triggerType -ne 'continuousIntegration' -and $_.triggerType -ne 2
                            })

                        $disabledCiTrigger = @{
                            triggerType                  = "continuousIntegration"
                            settingsSourceType           = 2   # Override YAML, use definition settings
                            batchChanges                 = $false
                            maxConcurrentBuildsPerBranch = 1
                            branchFilters                = @()
                            pathFilters                  = @()
                        }
                        $newTriggers = @($disabledCiTrigger) + $otherTriggers
                        $defResp | Add-Member -NotePropertyName 'triggers' -NotePropertyValue $newTriggers -Force

                        $defBody = $defResp | ConvertTo-Json -Depth 100 -Compress
                        $putHeaders = @{ "Content-Type" = "application/json" } + $adoHeaders
                        Invoke-RestMethod -Uri $defUri -Method PUT -Headers $putHeaders `
                            -Body $defBody -TimeoutSec 30 | Out-Null

                        Write-Success "CI override disabled on '$($config.Name)' (YAML CI trigger overridden + CI disabled)"
                    }
                }
                catch {
                    Write-Warn "Could not update build definition for '$($config.Name)': $(Get-CleanErrorMessage $_)"
                    Write-Info "CI auto-triggering is still disabled via YAML 'trigger: none' in the pipeline file."
                }
            }
        }

    } # end try
    finally { $ErrorActionPreference = $prevEAPFunc }
}

# ─────────────────────────────────────────────────────────────
# TEARDOWN: Remove cloud/remote resources only
# ─────────────────────────────────────────────────────────────
# !! SAFETY INVARIANT — DO NOT VIOLATE !!
# This function must NEVER delete, modify, or overwrite local files or
# folders (Content/, scripts/, pipelines/, config/, tests/, etc.).
# The local repository is the single source of truth. If it were deleted,
# there would be no way to rebuild the infrastructure.
# Only remote/cloud resources (ADO pipelines, variable groups, service
# connections, environments, projects, Azure UAMIs, federated credentials,
# app registrations, resource groups) and the local git remote reference
# ('origin') are removed. Local files, folders, and git history are
# always preserved.
# ─────────────────────────────────────────────────────────────
function Remove-AllResources {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Removes all cloud resources during teardown')]
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Write-Host ""
    Write-Host ("!" * 70) -ForegroundColor Red
    Write-Host "  TEARDOWN MODE — This will DELETE all cloud/remote resources!" -ForegroundColor Red
    Write-Host "  Local files and folders will NOT be affected." -ForegroundColor Yellow
    Write-Host ("!" * 70) -ForegroundColor Red
    Write-Host ""

    if (-not $Force) {
        $userConfirm = Read-Host "  Type 'YES' to confirm teardown of all resources"
        if ($userConfirm -ne "YES") {
            Write-Info "Teardown cancelled."
            return
        }
    }
    else {
        Write-Info "Auto-confirmed via -Force switch"
    }

    # All commands in this function are native executables (az, git).
    # Switch to 'Continue' to prevent stderr-induced hangs.
    $prevEAPFunc = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {

        # Ensure logged in
        $account = az account show -o json 2>$null | ConvertFrom-Json
        if (-not $account) {
            Write-Info "Not logged into Azure CLI. Launching login..."
            az login --only-show-errors | Out-Null
        }

        if (-not [string]::IsNullOrWhiteSpace($AzureSubscriptionId)) {
            az account set --subscription $AzureSubscriptionId --only-show-errors
        }

        # Acquire ADO token so REST calls work
        $adoLoginOk = Invoke-ADOLogin
        if (-not $adoLoginOk) {
            Write-Warn "Could not acquire ADO token — ADO resource teardown will be skipped."
        }

        $adoHeaders = @{ "Authorization" = "Bearer $($env:AZURE_DEVOPS_EXT_PAT)"; "Content-Type" = "application/json" }
        $adoDeleteHeaders = @{ "Authorization" = "Bearer $($env:AZURE_DEVOPS_EXT_PAT)" }

        # Get project ID (needed for service endpoint deletion)
        $projectId = $null
        try {
            $projResp = Invoke-RestMethod `
                -Uri "$($script:ADOBaseUrl)/_apis/projects/$($ADOProject)?api-version=7.1" `
                -Headers $adoHeaders -TimeoutSec 30
            $projectId = $projResp.id
        }
        catch {
            Write-Warn "Could not retrieve project ID: $_"
        }

        # ── Remove ADO Pipelines ──
        Write-StepHeader "REMOVING ADO PIPELINES"
        try {
            # Use build definitions API for delete support (pipelines API doesn't support DELETE)
            $buildDefs = Invoke-RestMethod `
                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/build/definitions?api-version=7.1" `
                -Headers $adoHeaders -TimeoutSec 30
            if ($buildDefs.value) {
                foreach ($pl in $buildDefs.value) {
                    Write-Info "Deleting pipeline '$($pl.name)' (ID: $($pl.id))..."
                    try {
                        Invoke-RestMethod `
                            -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/build/definitions/$($pl.id)?api-version=7.1" `
                            -Method DELETE -Headers $adoDeleteHeaders -TimeoutSec 30 | Out-Null
                        Write-Success "Pipeline '$($pl.name)' deleted"
                    }
                    catch {
                        Write-Warn "Could not delete pipeline '$($pl.name)': $_"
                    }
                }
            }
            else {
                Write-Info "No pipelines found"
            }
        }
        catch {
            Write-Warn "Could not list pipelines: $_"
        }

        # ── Remove Variable Groups ──
        Write-StepHeader "REMOVING ADO VARIABLE GROUPS"
        try {
            $vgsResp = Invoke-RestMethod `
                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/distributedtask/variablegroups?api-version=7.1" `
                -Headers $adoHeaders -TimeoutSec 30
            if ($vgsResp.value) {
                foreach ($vg in $vgsResp.value) {
                    Write-Info "Deleting variable group '$($vg.name)' (ID: $($vg.id))..."
                    try {
                        $vgProjectRefs = $vg.variableGroupProjectReferences
                        if ($vgProjectRefs -and $vgProjectRefs.Count -gt 0) {
                            $vgProjIds = ($vgProjectRefs | ForEach-Object { $_.projectReference.id }) -join ","
                        }
                        else {
                            $vgProjIds = $projectId
                        }
                        Invoke-RestMethod `
                            -Uri "$($script:ADOBaseUrl)/_apis/distributedtask/variablegroups/$($vg.id)?projectIds=$vgProjIds&api-version=7.1-preview.2" `
                            -Method DELETE -Headers $adoDeleteHeaders -TimeoutSec 30 | Out-Null
                        Write-Success "Variable group '$($vg.name)' deleted"
                    }
                    catch {
                        Write-Warn "Could not delete variable group '$($vg.name)': $_"
                    }
                }
            }
        }
        catch {
            Write-Warn "Could not list variable groups: $_"
        }

        # ── Remove Service Connections ──
        Write-StepHeader "REMOVING ADO SERVICE CONNECTIONS"
        try {
            $epResp = Invoke-RestMethod `
                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/serviceendpoint/endpoints?api-version=7.1" `
                -Headers $adoHeaders -TimeoutSec 30
            if ($epResp.value) {
                foreach ($ep in $epResp.value) {
                    if ($ep.name -like "sc-intune-*") {
                        Write-Info "Deleting service connection '$($ep.name)' (ID: $($ep.id))..."
                        try {
                            Invoke-RestMethod `
                                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/serviceendpoint/endpoints/$($ep.id)?projectIds=$projectId&api-version=7.1" `
                                -Method DELETE -Headers $adoDeleteHeaders -TimeoutSec 30 | Out-Null
                            Write-Success "Service connection '$($ep.name)' deleted"
                        }
                        catch {
                            Write-Warn "Could not delete service connection '$($ep.name)': $_"
                        }
                    }
                }
            }
        }
        catch {
            Write-Warn "Could not list service connections: $_"
        }

        # ── Remove ADO Environments ──
        Write-StepHeader "REMOVING ADO ENVIRONMENTS"
        try {
            $envListResp = Invoke-RestMethod `
                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/distributedtask/environments?api-version=7.1" `
                -Headers $adoHeaders -TimeoutSec 30

            if ($envListResp.value) {
                foreach ($envItem in $envListResp.value) {
                    if ($envItem.name -like "intune-*") {
                        Write-Info "Deleting environment '$($envItem.name)' (ID: $($envItem.id))..."
                        try {
                            Invoke-RestMethod `
                                -Uri "$($script:ADOBaseUrl)/$ADOProject/_apis/distributedtask/environments/$($envItem.id)?api-version=7.1" `
                                -Method DELETE -Headers $adoDeleteHeaders -TimeoutSec 30 | Out-Null
                            Write-Success "Environment '$($envItem.name)' deleted"
                        }
                        catch {
                            Write-Warn "Could not delete environment '$($envItem.name)': $_"
                        }
                    }
                }
            }
        }
        catch {
            Write-Warn "Could not list environments: $_"
        }

        # ── Remove ADO Project (optional) ──
        Write-StepHeader "REMOVING ADO PROJECT"
        $removeProject = if ($Force) { "yes" } else { Read-Host "  Delete ADO project '$ADOProject'? (yes/no)" }
        if ($removeProject -eq "yes") {
            try {
                $projListResp = Invoke-RestMethod `
                    -Uri "$($script:ADOBaseUrl)/_apis/projects?api-version=7.1" `
                    -Headers $adoHeaders -TimeoutSec 30
                $proj = $projListResp.value | Where-Object { $_.name -eq $ADOProject }
                if ($proj) {
                    Invoke-RestMethod `
                        -Uri "$($script:ADOBaseUrl)/_apis/projects/$($proj.id)?api-version=7.1" `
                        -Method DELETE -Headers $adoDeleteHeaders -TimeoutSec 30 | Out-Null
                    Write-Success "ADO project '$ADOProject' deleted"
                }
            }
            catch {
                Write-Err "Failed to delete ADO project '$ADOProject': $_"
            }
        }
        else {
            Write-Info "Skipping ADO project deletion"
        }

        # ── Remove Azure Resources ──
        Write-StepHeader "REMOVING AZURE RESOURCES"

        # Build EnvConfigs for teardown (needed for multi-tenant switching)
        $account = az account show -o json 2>$null | ConvertFrom-Json
        $currentTenantId = if ($account) { $account.tenantId } else { $TenantId }
        if ([string]::IsNullOrWhiteSpace($script:TenantId)) { $script:TenantId = $currentTenantId }
        if ([string]::IsNullOrWhiteSpace($script:AzureSubscriptionId) -and $account) { $script:AzureSubscriptionId = $account.id }
        if ([string]::IsNullOrWhiteSpace($script:AzureSubscriptionName) -and $account) { $script:AzureSubscriptionName = $account.name }

        if (-not $script:EnvConfigs) {
            $script:EnvConfigs = @{}
            foreach ($envName in @("dev", "staging", "production")) {
                switch ($envName) {
                    "dev" {
                        $script:EnvConfigs[$envName] = @{
                            TenantId         = if ($DevTenantId) { $DevTenantId } else { $script:TenantId }
                            SubscriptionId   = if ($DevSubscriptionId) { $DevSubscriptionId } else { $script:AzureSubscriptionId }
                            SubscriptionName = if ($DevSubscriptionName) { $DevSubscriptionName } else { $script:AzureSubscriptionName }
                        }
                    }
                    "staging" {
                        $script:EnvConfigs[$envName] = @{
                            TenantId         = if ($StagingTenantId) { $StagingTenantId } else { $script:TenantId }
                            SubscriptionId   = if ($StagingSubscriptionId) { $StagingSubscriptionId } else { $script:AzureSubscriptionId }
                            SubscriptionName = if ($StagingSubscriptionName) { $StagingSubscriptionName } else { $script:AzureSubscriptionName }
                        }
                    }
                    "production" {
                        $script:EnvConfigs[$envName] = @{
                            TenantId         = $script:TenantId
                            SubscriptionId   = $script:AzureSubscriptionId
                            SubscriptionName = $script:AzureSubscriptionName
                        }
                    }
                }
            }
        }

        # Group environments by tenant for teardown
        $teardownTenantGroups = [ordered]@{}
        foreach ($env in $Environments) {
            $tid = $script:EnvConfigs[$env].TenantId
            if (-not $teardownTenantGroups.Contains($tid)) { $teardownTenantGroups[$tid] = @() }
            $teardownTenantGroups[$tid] += $env
        }

        $currentTenant = $currentTenantId
        foreach ($tid in $teardownTenantGroups.Keys) {
            $envsForTenant = $teardownTenantGroups[$tid]

            # Switch tenant if needed
            if ($tid -ne $currentTenant) {
                Write-Info "Switching to tenant '$tid' for teardown of: $($envsForTenant -join ', ')"
                az login --tenant $tid --only-show-errors | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Write-Err "Could not login to tenant '$tid' — skipping teardown for: $($envsForTenant -join ', ')"
                    continue
                }
                $currentTenant = $tid
            }

            $tenantSubId = $script:EnvConfigs[$envsForTenant[0]].SubscriptionId
            az account set --subscription $tenantSubId --only-show-errors

            # Remove federated credentials
            foreach ($env in $envsForTenant) {
                $uamiName = "uami-intune-cicd-$env"
                $fedName = "ado-federation-$env"
                Write-Info "Removing federated credential '$fedName' from '$uamiName'..."
                az identity federated-credential delete `
                    --name $fedName `
                    --identity-name $uamiName `
                    --resource-group $ResourceGroupName `
                    --yes -o none 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "Federated credential '$fedName' removed"
                }
                else {
                    Write-Info "Federated credential '$fedName' not found or already removed"
                }
            }

            # Remove Graph API permissions from UAMIs (legacy cleanup)
            Write-Info "Removing Graph API role assignments from UAMIs..."
            $graphSpId = az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query "[0].id" -o tsv 2>$null
            if ($graphSpId) {
                foreach ($env in $envsForTenant) {
                    $uamiName = "uami-intune-cicd-$env"
                    $uami = az identity show --name $uamiName --resource-group $ResourceGroupName -o json 2>$null | ConvertFrom-Json
                    if (-not $uami) { continue }

                    $assignments = az rest --method GET `
                        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSpId/appRoleAssignedTo" `
                        -o json 2>$null | ConvertFrom-Json

                    if ($assignments.value) {
                        $uamiAssignments = $assignments.value | Where-Object { $_.principalId -eq $uami.principalId }
                        foreach ($assignment in $uamiAssignments) {
                            az rest --method DELETE `
                                --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSpId/appRoleAssignedTo/$($assignment.id)" `
                                -o none 2>$null
                            Write-Info "  Removed role assignment: $($assignment.id)"
                        }
                    }
                    Write-Success "Graph permissions removed from '$uamiName'"
                }
            }

            # Remove app registrations and their service principals, federated credentials, and Graph permissions
            Write-StepHeader "REMOVING APP REGISTRATIONS"
            Write-Info "Acquiring Graph token for app registration cleanup..."
            $prevEAP3 = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                $teardownGraphToken = az account get-access-token `
                    --scope "https://graph.microsoft.com/.default" `
                    --query accessToken -o tsv 2>$null
            }
            finally { $ErrorActionPreference = $prevEAP3 }

            if ($teardownGraphToken) {
                $teardownHeaders = @{ "Authorization" = "Bearer $teardownGraphToken" }

                foreach ($env in $envsForTenant) {
                    $appName = "app-intune-cicd-$env"
                    Write-Info "Removing app registration '$appName'..."

                    try {
                        $appSearchResp = Invoke-RestMethod `
                            -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$appName'&`$select=id,appId" `
                            -Headers $teardownHeaders -TimeoutSec 30

                        if ($appSearchResp.value -and $appSearchResp.value.Count -gt 0) {
                            $appObjId = $appSearchResp.value[0].id
                            $appClientId = $appSearchResp.value[0].appId

                            # Remove Graph API role assignments from the app's service principal
                            try {
                                $spResp = Invoke-RestMethod `
                                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$appClientId'&`$select=id" `
                                    -Headers $teardownHeaders -TimeoutSec 30
                                if ($spResp.value -and $spResp.value.Count -gt 0 -and $graphSpId) {
                                    $spId = $spResp.value[0].id
                                    $roleAssignments = az rest --method GET `
                                        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSpId/appRoleAssignedTo" `
                                        -o json 2>$null | ConvertFrom-Json
                                    if ($roleAssignments.value) {
                                        $appAssignments = $roleAssignments.value | Where-Object { $_.principalId -eq $spId }
                                        foreach ($assignment in $appAssignments) {
                                            az rest --method DELETE `
                                                --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSpId/appRoleAssignedTo/$($assignment.id)" `
                                                -o none 2>$null
                                        }
                                        Write-Info "  Removed $($appAssignments.Count) Graph role assignment(s)"
                                    }
                                }
                            }
                            catch {
                                Write-Warn "  Could not clean up Graph role assignments: $_"
                            }

                            # Delete the app registration (also deletes service principal and federated credentials)
                            Invoke-RestMethod `
                                -Uri "https://graph.microsoft.com/v1.0/applications/$appObjId" `
                                -Method DELETE -Headers $teardownHeaders -TimeoutSec 30 | Out-Null
                            Write-Success "App registration '$appName' deleted"
                        }
                        else {
                            Write-Info "App registration '$appName' not found or already removed"
                        }
                    }
                    catch {
                        Write-Warn "Could not remove app registration '$appName': $_"
                    }
                }

                # Also remove the legacy privileged app registration if it exists
                $legacyAppName = "app-intune-cicd-privileged"
                try {
                    $legacyAppSearch = Invoke-RestMethod `
                        -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$legacyAppName'&`$select=id" `
                        -Headers $teardownHeaders -TimeoutSec 30
                    if ($legacyAppSearch.value -and $legacyAppSearch.value.Count -gt 0) {
                        Invoke-RestMethod `
                            -Uri "https://graph.microsoft.com/v1.0/applications/$($legacyAppSearch.value[0].id)" `
                            -Method DELETE -Headers $teardownHeaders -TimeoutSec 30 | Out-Null
                        Write-Success "Legacy privileged app registration '$legacyAppName' deleted"
                    }
                }
                catch {
                    Write-Info "Legacy app '$legacyAppName' not found or already removed"
                }
            }
            else {
                Write-Warn "Could not acquire Graph token — app registration cleanup skipped."
                Write-Info "Manually delete app registrations 'app-intune-cicd-*' in Entra ID."
            }

            # Remove UAMIs
            foreach ($env in $envsForTenant) {
                $uamiName = "uami-intune-cicd-$env"
                Write-Info "Deleting UAMI '$uamiName'..."
                az identity delete --name $uamiName --resource-group $ResourceGroupName -o none 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "UAMI '$uamiName' deleted"
                }
                else {
                    Write-Info "UAMI '$uamiName' not found or already removed"
                }
            }

            # Remove resource group for this tenant
            $removeRg = if ($Force) { "yes" } else { Read-Host "  Delete resource group '$ResourceGroupName' in tenant $($tid.Substring(0,8))...? (yes/no)" }
            if ($removeRg -eq "yes") {
                Write-Info "Deleting resource group '$ResourceGroupName' (this may take a minute)..."
                az group delete --name $ResourceGroupName --yes --no-wait -o none 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "Resource group '$ResourceGroupName' deletion initiated"
                }
                else {
                    Write-Warn "Could not delete resource group '$ResourceGroupName'"
                }
            }
            else {
                Write-Info "Skipping resource group deletion"
            }

        } # end foreach tenant group

        # Switch back to production tenant if needed
        if ($currentTenant -ne $script:TenantId) {
            az login --tenant $script:TenantId --only-show-errors | Out-Null
            az account set --subscription $script:AzureSubscriptionId --only-show-errors
        }

        # ── Remove local git remote ──
        Write-StepHeader "CLEANING UP LOCAL GIT REMOTE"
        Push-Location $LocalRepoPath
        try {
            $remotes = git remote 2>$null
            if ($remotes -contains "origin") {
                git remote remove origin 2>$null
                Write-Success "Removed git remote 'origin'"
            }
            else {
                Write-Info "No 'origin' remote found"
            }
        }
        finally {
            Pop-Location
        }

    } # end try
    finally { $ErrorActionPreference = $prevEAPFunc }
}

# W365 CLOUD PC PROVISIONING POLICIES IMPORT (delegated permissions)
# ─────────────────────────────────────────────────────────────
function Import-W365ProvisioningPolicies {
    <#
    .SYNOPSIS
        Imports W365 Cloud PC provisioning policies using the interactive user's
        delegated Graph token with full cross-tenant translation.
    .DESCRIPTION
        The Autopatch service rejects app-only (UAMI/service principal) tokens
        with HTTP 403 "AutopatchAuthenticationFailed: Application is not supported
        to use autopatch." This function expects a valid MgGraph session to already
        be established via Connect-MgGraphForIntune.

        Before creating a policy, it validates:
        1. W365 service plan (SKU) licenses are available in the target tenant
        2. The gallery image referenced in the JSON exists and is supported
        3. Autopilot device preparation profile partial-name matching (CPC)
        4. Windows Autopatch group discovery from existing policies
        5. Scope tag remapping (scopeIds)
        6. Group assignment remapping via MigrationTable

        If a policy with the same displayName already exists in the target
        tenant it is gracefully skipped — no duplicate is created.
    .PARAMETER Environment
        The environment name (dev, staging, production).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Imports multiple provisioning policies')]
    param(
        [Parameter(Mandatory)]
        [string]$Environment
    )

    $contentPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/W365ProvisioningPolicies"
    if (-not (Test-Path $contentPath)) {
        Write-Info "No W365ProvisioningPolicies content folder found for '$Environment' — skipping"
        return
    }

    $jsonFiles = @(Get-ChildItem -Path $contentPath -Filter '*.json' -File -ErrorAction SilentlyContinue)
    if ($jsonFiles.Count -eq 0) {
        Write-Info "No W365 provisioning policy files found in '$contentPath' — skipping"
        return
    }

    Write-StepHeader "IMPORTING W365 CLOUD PC PROVISIONING POLICIES ($($Environment.ToUpper()))"
    Write-Info "Using Microsoft Graph delegated auth — required for Autopatch service integration"
    Write-Info "Will validate SKU, gallery image, Autopilot, and Autopatch before importing"
    Write-Info "Found $($jsonFiles.Count) provisioning policy file(s) to process"

    # ── Load migration table for ID remapping ──
    $migrationFile = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/MigrationTable.json"
    $migrationTable = $null
    if (Test-Path $migrationFile) {
        $migrationTable = Get-Content -Path $migrationFile -Raw | ConvertFrom-Json
        Write-Info "Loaded migration table: $($migrationTable.Objects.Count) objects"
    }
    else {
        Write-Warn "No MigrationTable.json found — group ID remapping will be skipped"
    }

    # ── Load source scope tags for scopeId remapping ──
    $scopeTagPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/ScopeTags"
    $sourceScopeTags = @()
    if (Test-Path $scopeTagPath) {
        $sourceScopeTags = @(Get-ChildItem -Path $scopeTagPath -Filter '*.json' -File | ForEach-Object {
                Get-Content $_.FullName -Raw | ConvertFrom-Json
            })
        Write-Info "Loaded $($sourceScopeTags.Count) source scope tag(s) for remapping"
    }

    # ── Load source group definitions for creation ──
    $groupsContentPath = Join-Path -Path $LocalRepoPath -ChildPath "Content/$Environment/Groups"

    # ── Validate delegated MgGraph session for Intune operations ──
    $envTenantId = if ($script:EnvConfigs -and $script:EnvConfigs.ContainsKey($Environment)) {
        $script:EnvConfigs[$Environment].TenantId
    }
    else {
        $script:TenantId
    }

    if (-not (Test-MgGraphIntuneSession -TenantId $envTenantId)) {
        Write-Err "Cannot proceed without a valid Intune delegated session."
        return
    }

    # ── PHASE 1: Pre-flight checks (SKU, gallery images) ──
    Write-Info "Checking W365 service plans (SKU availability)..."
    $servicePlans = @()
    try {
        $spResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/servicePlans' `
            -OutputType PSObject -ErrorAction Stop
        if ($spResp.value) { $servicePlans = @($spResp.value) }
    }
    catch {
        Write-Warn "Could not query W365 service plans: $(Get-CleanErrorMessage $_)"
    }

    if ($servicePlans.Count -eq 0) {
        Write-Warn ("No Windows 365 Cloud PC service plans (SKUs) are licensed in this tenant. " +
            "A Windows 365 SKU must be licensed in the tenant first before creating/importing " +
            "W365 Cloud PC Provisioning Profile policies can proceed. Skipping all W365 provisioning policies.")
        return
    }
    Write-Success "Found $($servicePlans.Count) W365 service plan(s) — SKU prerequisite met"

    # Fetch gallery images once for all policies
    $galleryImages = @()
    try {
        $giResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/galleryImages' `
            -OutputType PSObject -ErrorAction Stop
        if ($giResp.value) { $galleryImages = @($giResp.value) }
    }
    catch {
        Write-Warn "Could not query gallery images: $(Get-CleanErrorMessage $_)"
    }

    # Fetch Autopilot deployment profiles once for matching
    $autopilotProfiles = @()
    try {
        $apResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles' `
            -OutputType PSObject -ErrorAction Stop
        if ($apResp.value) { $autopilotProfiles = @($apResp.value) }
    }
    catch {
        Write-Warn "Could not query Autopilot deployment profiles: $(Get-CleanErrorMessage $_)"
    }

    # Fetch existing W365 provisioning policies for Autopatch discovery and duplicate detection
    $existingPolicies = @()
    try {
        $epResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies' `
            -OutputType PSObject -ErrorAction Stop
        if ($epResp.value) {
            $existingPolicies = @($epResp.value)
            Write-Info "Found $($existingPolicies.Count) existing W365 provisioning policy(ies) in target tenant"
        }
    }
    catch {
        Write-Warn "Could not retrieve existing W365 provisioning policies: $(Get-CleanErrorMessage $_)"
    }

    # Discover Autopatch groups from existing policies
    $autopatchGroupId = $null
    $policiesWithAutopatch = @($existingPolicies | Where-Object {
            $_.autopatch -and $_.autopatch.autopatchGroupId -and
            $_.autopatch.autopatchGroupId -ne '00000000-0000-0000-0000-000000000000'
        })
    if ($policiesWithAutopatch.Count -gt 0) {
        $cpcAutoMatch = $policiesWithAutopatch | Where-Object { $_.displayName -like '*CPC*' } | Select-Object -First 1
        if ($cpcAutoMatch) {
            $autopatchGroupId = $cpcAutoMatch.autopatch.autopatchGroupId
            Write-Info "Discovered Autopatch group from existing CPC policy '$($cpcAutoMatch.displayName)': $autopatchGroupId"
        }
        else {
            Write-Warn ("Existing policies with Autopatch configured were found, but none have 'CPC' in " +
                "their name (found: $(($policiesWithAutopatch | ForEach-Object { $_.displayName }) -join ', ')). " +
                "Policies will be imported without Autopatch association. An admin can assign a Windows " +
                "Autopatch group post-import in the Intune portal.")
        }
    }
    else {
        Write-Warn ("No Windows Autopatch group found in the target tenant. Windows Autopatch " +
            "enrollment is a manual activity that must be completed by an admin in the Intune portal " +
            "before it can be associated with a W365 provisioning policy. Policies will be imported " +
            "without Autopatch association.")
    }

    # Fetch target scope tags once
    $targetScopeTags = @()
    try {
        $stResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/deviceManagement/roleScopeTags' `
            -OutputType PSObject -ErrorAction Stop
        if ($stResp.value) { $targetScopeTags = @($stResp.value) }
    }
    catch {
        Write-Warn "Could not retrieve target scope tags: $(Get-CleanErrorMessage $_)"
    }

    # ── PHASE 2: Parse all policy files and collect referenced group IDs ──
    $allSourceObjs = @()
    foreach ($file in $jsonFiles) {
        try {
            $rawJson = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
            $allSourceObjs += $rawJson | ConvertFrom-Json -Depth 50 -ErrorAction Stop
        }
        catch {
            Write-Warn "Could not parse '$($file.Name)' — skipping"
        }
    }

    $referencedGroupIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($srcObj in $allSourceObjs) {
        if ($srcObj.PSObject.Properties['assignments'] -and $srcObj.assignments) {
            foreach ($assignment in $srcObj.assignments) {
                if ($assignment.target -and $assignment.target.groupId) {
                    [void]$referencedGroupIds.Add($assignment.target.groupId)
                }
            }
        }
    }

    # ── PHASE 3: Resolve / create prerequisite groups ──
    $groupIdMap = @{}
    if ($referencedGroupIds.Count -gt 0 -and $migrationTable) {
        Write-Info "Resolving $($referencedGroupIds.Count) referenced group(s)..."
        foreach ($srcGroupId in $referencedGroupIds) {
            $migObj = $migrationTable.Objects | Where-Object { $_.Id -eq $srcGroupId } | Select-Object -First 1
            if (-not $migObj) {
                Write-Warn "  Group ID $srcGroupId not found in MigrationTable — assignment will be skipped"
                continue
            }

            $groupDisplayName = $migObj.DisplayName
            try {
                $groupResp = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($groupDisplayName -replace "'","''")'&`$select=id,displayName" `
                    -OutputType PSObject -ErrorAction Stop
                if ($groupResp.value -and $groupResp.value.Count -gt 0) {
                    $groupIdMap[$srcGroupId] = $groupResp.value[0].id
                    Write-Success "  Group '$groupDisplayName' exists (ID: $($groupResp.value[0].id))"
                    continue
                }
            }
            catch {
                Write-Warn "  Could not check for group '$groupDisplayName': $(Get-CleanErrorMessage $_)"
            }

            # Group not found — create from Content/Groups/ JSON definition
            $groupJsonFile = Join-Path $groupsContentPath "$groupDisplayName.json"
            if (-not (Test-Path $groupJsonFile)) {
                Write-Warn "  Group '$groupDisplayName' not found in target and no JSON at '$groupJsonFile' — assignment will be skipped"
                continue
            }

            Write-Info "  Creating group '$groupDisplayName'..."
            try {
                $groupDef = Get-Content -Path $groupJsonFile -Raw | ConvertFrom-Json -Depth 50

                $newGroup = @{
                    displayName     = $groupDef.displayName
                    mailEnabled     = [bool]$groupDef.mailEnabled
                    mailNickname    = if ($groupDef.mailNickname) { $groupDef.mailNickname } else { ($groupDef.displayName -replace '[^a-zA-Z0-9]', '').Substring(0, [Math]::Min(64, ($groupDef.displayName -replace '[^a-zA-Z0-9]', '').Length)) }
                    securityEnabled = [bool]$groupDef.securityEnabled
                }
                if ($groupDef.description) { $newGroup['description'] = $groupDef.description }
                if ($groupDef.groupTypes -and $groupDef.groupTypes.Count -gt 0) {
                    $newGroup['groupTypes'] = @($groupDef.groupTypes)
                }
                else {
                    $newGroup['groupTypes'] = @()
                }
                if ($groupDef.membershipRule) {
                    $newGroup['membershipRule'] = $groupDef.membershipRule
                    $newGroup['membershipRuleProcessingState'] = if ($groupDef.membershipRuleProcessingState) { $groupDef.membershipRuleProcessingState } else { 'On' }
                    if ($newGroup['groupTypes'] -notcontains 'DynamicMembership') {
                        $newGroup['groupTypes'] += 'DynamicMembership'
                    }
                }

                $groupBody = $newGroup | ConvertTo-Json -Depth 10
                $createdGroup = Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/v1.0/groups" `
                    -Body ([System.Text.Encoding]::UTF8.GetBytes($groupBody)) `
                    -ContentType "application/json; charset=utf-8" `
                    -OutputType PSObject -ErrorAction Stop
                if ($createdGroup.id) {
                    Write-Success "  Created group '$groupDisplayName' (ID: $($createdGroup.id))"
                    $groupIdMap[$srcGroupId] = $createdGroup.id
                }
            }
            catch {
                $errDetail = "$($_.ErrorDetails.Message)$($_.Exception.Message)"
                if ($errDetail -match 'already exists|ObjectConflict') {
                    Write-Info "  Group '$groupDisplayName' was created concurrently — looking it up..."
                    try {
                        $retryResp = Invoke-MgGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($groupDisplayName -replace "'","''")'&`$select=id" `
                            -OutputType PSObject -ErrorAction Stop
                        if ($retryResp.value -and $retryResp.value.Count -gt 0) {
                            $groupIdMap[$srcGroupId] = $retryResp.value[0].id
                            Write-Success "  Found group '$groupDisplayName' (ID: $($retryResp.value[0].id))"
                        }
                    }
                    catch {
                        Write-Warn "  Could not look up group '$groupDisplayName' after conflict: $(Get-CleanErrorMessage $_)"
                    }
                }
                else {
                    Write-Warn "  Could not create group '$groupDisplayName': $(Get-CleanErrorMessage $_)"
                }
            }
        }
    }

    # ── PHASE 4: Import each provisioning policy ──
    $importedCount = 0
    $skippedCount = 0
    $failedCount = 0
    $assignedCount = 0

    foreach ($file in $jsonFiles) {
        $sourceObj = $null
        try {
            $rawJson = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
            $sourceObj = $rawJson | ConvertFrom-Json -Depth 50 -ErrorAction Stop
        }
        catch {
            Write-Warn "Could not parse '$($file.Name)' — skipping"
            $skippedCount++
            continue
        }

        $policyName = $sourceObj.displayName
        if (-not $policyName) {
            Write-Warn "Skipping '$($file.Name)' — no displayName property"
            $skippedCount++
            continue
        }

        Write-Progress2 -Activity "W365ProvisioningPolicies" -Status "Processing '$policyName'..."

        # Check if policy already exists
        $existingObj = $existingPolicies | Where-Object { $_.displayName -eq $policyName } | Select-Object -First 1
        if ($existingObj) {
            Write-Success "'$policyName' already exists in target tenant (ID: $($existingObj.id)) — skipping"
            $skippedCount++
            continue
        }

        # ── Validate gallery image ──
        if ($sourceObj.imageType -eq 'gallery' -and $sourceObj.imageId) {
            $matchedImage = $galleryImages | Where-Object { $_.id -eq $sourceObj.imageId } | Select-Object -First 1
            if (-not $matchedImage) {
                $supportedImageList = ($galleryImages | Where-Object { $_.status -eq 'supported' } |
                    ForEach-Object { "'$($_.id)' ($($_.displayName))" }) -join '; '
                Write-Err ("Gallery image '$($sourceObj.imageId)' ('$($sourceObj.imageDisplayName)') " +
                    "is not available in the target tenant. Update the JSON with a valid imageId. " +
                    "Available: $supportedImageList")
                $failedCount++
                continue
            }
            if ($matchedImage.status -ne 'supported') {
                Write-Warn "Gallery image '$($sourceObj.imageId)' has status '$($matchedImage.status)' — may not be usable"
            }
        }

        # ── Clone and prepare the import object ──
        $importObj = $sourceObj | ConvertTo-Json -Depth 50 | ConvertFrom-Json -Depth 50

        # Strip read-only and metadata properties
        $removeProps = @(
            'id', 'createdDateTime', 'lastModifiedDateTime', 'createdBy', 'lastModifiedBy',
            'alternateResourceUrl', 'cloudPcGroupDisplayName', 'gracePeriodInHours',
            'assignments', '@odata.context', '@odata.id', '@odata.editLink'
        )
        foreach ($prop in $removeProps) {
            if ($importObj.PSObject.Properties[$prop]) {
                $importObj.PSObject.Properties.Remove($prop)
            }
        }
        # Remove OData metadata recursively
        $odataProps = @($importObj.PSObject.Properties | Where-Object {
                ($_.Name -like '@odata.*' -and $_.Name -ne '@odata.type') -or
                $_.Name -match '.+@odata\.' -or
                $_.Name -like '#*'
            } | ForEach-Object { $_.Name })
        foreach ($prop in $odataProps) {
            $importObj.PSObject.Properties.Remove($prop)
        }

        # ── Autopilot device preparation profile matching ──
        if ($importObj.autopilotConfiguration -and $importObj.autopilotConfiguration.devicePreparationProfileId) {
            $matchedProfile = $null
            if ($autopilotProfiles.Count -gt 0) {
                $cpcProfiles = @($autopilotProfiles | Where-Object { $_.displayName -like '*CPC*' })
                if ($cpcProfiles.Count -gt 0) {
                    $matchedProfile = $cpcProfiles | Select-Object -First 1
                    Write-Info "  Matched Autopilot device preparation profile: '$($matchedProfile.displayName)'"
                }
            }
            if ($matchedProfile) {
                $importObj.autopilotConfiguration.devicePreparationProfileId = $matchedProfile.id
            }
            else {
                Write-Warn "  No Autopilot device preparation profile with 'CPC' in its name — removing association"
                $importObj.PSObject.Properties.Remove('autopilotConfiguration')
            }
        }

        # ── Autopatch group matching ──
        if ($importObj.autopatch -and $importObj.autopatch.autopatchGroupId) {
            if ($autopatchGroupId) {
                $importObj.autopatch.autopatchGroupId = $autopatchGroupId
                Write-Info "  Using Autopatch group: $autopatchGroupId"
            }
            else {
                Write-Warn "  No Autopatch group available — disabling Autopatch association"
                $importObj.autopatch = @{ autopatchGroupId = $null }
                if ($importObj.microsoftManagedDesktop -and
                    ($importObj.microsoftManagedDesktop.managedType -eq 'starterManaged' -or
                    $importObj.microsoftManagedDesktop.type -eq 'starterManaged')) {
                    $importObj.microsoftManagedDesktop.managedType = 'notManaged'
                    if ($importObj.microsoftManagedDesktop.PSObject.Properties['type']) {
                        $importObj.microsoftManagedDesktop.type = 'notManaged'
                    }
                    Write-Warn "  Set microsoftManagedDesktop.managedType to 'notManaged'"
                }
            }
        }

        # ── Remap scopeIds ──
        if ($importObj.PSObject.Properties['scopeIds'] -and $importObj.scopeIds -and $sourceScopeTags.Count -gt 0) {
            $remappedScopeIds = [System.Collections.Generic.List[string]]::new()
            foreach ($srcId in $importObj.scopeIds) {
                if ("$srcId" -eq '0') { $remappedScopeIds.Add('0'); continue }
                $srcTag = $sourceScopeTags | Where-Object { "$($_.id)" -eq "$srcId" } | Select-Object -First 1
                if (-not $srcTag) {
                    Write-Warn "  Source scope tag ID $srcId not found — using default (0)"
                    $remappedScopeIds.Add('0'); continue
                }
                $tgtTag = $targetScopeTags | Where-Object { $_.displayName -eq $srcTag.displayName } | Select-Object -First 1
                if ($tgtTag) {
                    $remappedScopeIds.Add("$($tgtTag.id)")
                    Write-Info "  Remapped scopeId '$srcId' ($($srcTag.displayName)) -> '$($tgtTag.id)'"
                }
                else {
                    Write-Warn "  Scope tag '$($srcTag.displayName)' not found in target — using default (0)"
                    $remappedScopeIds.Add('0')
                }
            }
            $importObj.scopeIds = @($remappedScopeIds)
        }

        # ── Clean deprecated properties ──
        if ($importObj.PSObject.Properties['domainJoinConfiguration'] -and
            $importObj.PSObject.Properties['domainJoinConfigurations']) {
            $importObj.PSObject.Properties.Remove('domainJoinConfiguration')
        }
        if ($importObj.PSObject.Properties['windowsSettings'] -and
            $importObj.PSObject.Properties['windowsSetting']) {
            $importObj.PSObject.Properties.Remove('windowsSettings')
        }

        # Remove inner OData type annotations from nested objects
        if ($importObj.PSObject.Properties['domainJoinConfigurations'] -and $importObj.domainJoinConfigurations) {
            foreach ($djc in @($importObj.domainJoinConfigurations)) {
                if ($djc -is [PSCustomObject]) {
                    $innerOdata = @($djc.PSObject.Properties | Where-Object { $_.Name -match '@odata\.' } | ForEach-Object { $_.Name })
                    foreach ($p in $innerOdata) { $djc.PSObject.Properties.Remove($p) }
                }
            }
        }
        if ($importObj.PSObject.Properties['microsoftManagedDesktop'] -and $importObj.microsoftManagedDesktop -is [PSCustomObject]) {
            $innerOdata = @($importObj.microsoftManagedDesktop.PSObject.Properties | Where-Object { $_.Name -match '@odata\.' } | ForEach-Object { $_.Name })
            foreach ($p in $innerOdata) { $importObj.microsoftManagedDesktop.PSObject.Properties.Remove($p) }
        }
        if ($importObj.PSObject.Properties['autopatch'] -and $importObj.autopatch -is [PSCustomObject]) {
            $innerOdata = @($importObj.autopatch.PSObject.Properties | Where-Object { $_.Name -match '@odata\.' } | ForEach-Object { $_.Name })
            foreach ($p in $innerOdata) { $importObj.autopatch.PSObject.Properties.Remove($p) }
        }
        if ($importObj.PSObject.Properties['windowsSetting'] -and $importObj.windowsSetting -is [PSCustomObject]) {
            $innerOdata = @($importObj.windowsSetting.PSObject.Properties | Where-Object { $_.Name -match '@odata\.' } | ForEach-Object { $_.Name })
            foreach ($p in $innerOdata) { $importObj.windowsSetting.PSObject.Properties.Remove($p) }
        }
        if ($importObj.PSObject.Properties['autopilotConfiguration'] -and $importObj.autopilotConfiguration -is [PSCustomObject]) {
            $innerOdata = @($importObj.autopilotConfiguration.PSObject.Properties | Where-Object { $_.Name -match '@odata\.' } | ForEach-Object { $_.Name })
            foreach ($p in $innerOdata) { $importObj.autopilotConfiguration.PSObject.Properties.Remove($p) }
        }

        # ── Create the provisioning policy ──
        Write-Info "Creating W365 provisioning policy '$policyName'..."
        $createdPolicy = $null
        try {
            $importBody = $importObj | ConvertTo-Json -Depth 50
            $createdPolicy = Invoke-MgGraphRequest -Method POST `
                -Uri 'https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies' `
                -Body ([System.Text.Encoding]::UTF8.GetBytes($importBody)) `
                -ContentType "application/json; charset=utf-8" `
                -OutputType PSObject -ErrorAction Stop
        }
        catch {
            Write-Err "Failed to create '$policyName': $(Get-CleanErrorMessage $_)"
            $failedCount++
            continue
        }

        if (-not $createdPolicy -or -not $createdPolicy.id) {
            Write-Err "Failed to create '$policyName' — no ID returned"
            $failedCount++
            continue
        }

        Write-Success "Created '$policyName' (ID: $($createdPolicy.id))"
        $importedCount++

        # ── Apply group assignments ──
        if ($sourceObj.PSObject.Properties['assignments'] -and $sourceObj.assignments -and $sourceObj.assignments.Count -gt 0) {
            $cleanAssignments = [System.Collections.Generic.List[object]]::new()

            foreach ($assignment in $sourceObj.assignments) {
                if (-not $assignment.target -or -not $assignment.target.groupId) { continue }

                $srcGroupId = $assignment.target.groupId
                $targetGroupId = $null
                if ($groupIdMap.ContainsKey($srcGroupId)) {
                    $targetGroupId = $groupIdMap[$srcGroupId]
                }
                elseif ($migrationTable) {
                    $migObj = $migrationTable.Objects | Where-Object { $_.Id -eq $srcGroupId } | Select-Object -First 1
                    if ($migObj) {
                        try {
                            $gR = Invoke-MgGraphRequest -Method GET `
                                -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($migObj.DisplayName -replace "'","''")'&`$select=id" `
                                -OutputType PSObject -ErrorAction Stop
                            if ($gR.value -and $gR.value.Count -gt 0) {
                                $targetGroupId = $gR.value[0].id
                                $groupIdMap[$srcGroupId] = $targetGroupId
                            }
                        }
                        catch {
                            Write-Warn "  Could not look up group '$($migObj.DisplayName)' for assignment"
                        }
                    }
                }

                if (-not $targetGroupId) {
                    Write-Warn "  Cannot remap group '$srcGroupId' — skipping assignment"
                    continue
                }

                $cleanTarget = @{
                    '@odata.type' = 'microsoft.graph.cloudPcManagementGroupAssignmentTarget'
                    groupId       = $targetGroupId
                }
                $cleanAssignments.Add(@{ target = $cleanTarget })
            }

            if ($cleanAssignments.Count -gt 0) {
                try {
                    $assignBody = @{ assignments = @($cleanAssignments) } | ConvertTo-Json -Depth 20
                    Invoke-MgGraphRequest -Method POST `
                        -Uri "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies/$($createdPolicy.id)/assign" `
                        -Body ([System.Text.Encoding]::UTF8.GetBytes($assignBody)) `
                        -ContentType "application/json; charset=utf-8" `
                        -ErrorAction Stop | Out-Null
                    Write-Success "  Assigned $($cleanAssignments.Count) group(s) to '$policyName'"
                    $assignedCount++
                }
                catch {
                    Write-Warn "  Could not apply assignments to '$policyName': $(Get-CleanErrorMessage $_)"
                    Write-Warn "  The policy was created successfully — assignments must be applied manually"
                }
            }
        }
    }

    # ── Summary ──
    Write-Info "W365 provisioning policies import complete: $importedCount created, $skippedCount skipped, $failedCount failed, $assignedCount assigned"
}

function Set-SelfHostedAgentDefault {
    <#
    .SYNOPSIS
        Updates pipeline YAML files to set the useSelfHostedAgent parameter default.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [bool]$Enabled
    )

    Write-StepHeader "CONFIGURING SELF-HOSTED AGENT DEFAULT"

    $defaultValue = if ($Enabled) { 'true' } else { 'false' }
    $pipelineFiles = @(
        (Join-Path $LocalRepoPath 'azure-pipelines.yml'),
        (Join-Path $LocalRepoPath 'pipelines/templates/backup-pipeline.yml'),
        (Join-Path $LocalRepoPath 'pipelines/templates/drift-detection-pipeline.yml'),
        (Join-Path $LocalRepoPath 'pipelines/templates/rollback-pipeline.yml')
    )

    $updatedCount = 0
    $alreadyCount = 0

    foreach ($file in $pipelineFiles) {
        if (-not (Test-Path $file)) {
            Write-Warn "Pipeline file not found: $file"
            continue
        }

        $content = Get-Content -Path $file -Raw
        $fileName = [System.IO.Path]::GetFileName($file)

        # Match the useSelfHostedAgent parameter block and replace the default value
        $pattern = '(?m)(- name: useSelfHostedAgent\s*\n\s*displayName:.*\n\s*type: boolean\s*\n\s*default:\s*)(true|false)'
        if ($content -match $pattern) {
            $currentDefault = $Matches[2]
            if ($currentDefault -eq $defaultValue) {
                Write-Info "  $fileName — already set to $defaultValue"
                $alreadyCount++
            }
            elseif ($PSCmdlet.ShouldProcess($fileName, "Set useSelfHostedAgent default to $defaultValue")) {
                $newContent = $content -replace $pattern, "`${1}$defaultValue"
                Set-Content -Path $file -Value $newContent -NoNewline
                Write-Success "  $fileName — default changed to $defaultValue"
                $updatedCount++
            }
        }
        else {
            Write-Warn "  $fileName — useSelfHostedAgent parameter not found"
        }
    }

    if ($updatedCount -gt 0) {
        Write-Success "Updated $updatedCount pipeline file(s) to default self-hosted agent to $defaultValue"
    }
    elseif ($alreadyCount -eq $pipelineFiles.Count) {
        Write-Info "All pipeline files already configured (default: $defaultValue)"
    }
}

function Initialize-Win32AppFolders {
    <#
    .SYNOPSIS
        Organizes Win32 app JSON exports into per-app subfolders under Applications.
    .DESCRIPTION
        Scans each environment's Applications folder (and ManualAppImport folder if present)
        for Win32 app JSON files (odata.type = #microsoft.graph.win32LobApp). Moves each
        JSON into a subfolder named after the app's displayName so the user can place the
        corresponding .intunewin file alongside it for pipeline import.
    #>

    Write-StepHeader "PREPARING WIN32 APP FOLDERS"

    $contentRoot = Join-Path -Path $LocalRepoPath -ChildPath 'Content'
    $script:Win32AppFolderResults = [System.Collections.Generic.List[object]]::new()

    foreach ($envName in $Environments) {
        $envContentPath = Join-Path -Path $contentRoot -ChildPath $envName
        if (-not (Test-Path $envContentPath)) {
            Write-Info "No content folder for environment '$envName' — skipping"
            continue
        }

        $applicationsPath = Join-Path -Path $envContentPath -ChildPath 'Applications'
        $appsPath = Join-Path -Path $envContentPath -ChildPath 'Apps'

        # Collect existing App display names from the Apps folder for cross-reference
        $existingAppNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if (Test-Path $appsPath) {
            $appSubfolders = Get-ChildItem -Path $appsPath -Directory -ErrorAction SilentlyContinue
            foreach ($sub in $appSubfolders) {
                # Read display name from Config.xml or Config.json if present
                $configXml = Join-Path -Path $sub.FullName -ChildPath 'Config.xml'
                $configJson = Join-Path -Path $sub.FullName -ChildPath 'Config.json'
                $appName = $null
                if (Test-Path $configXml) {
                    try {
                        [xml]$xml = Get-Content -Path $configXml -Raw
                        $appName = $xml.AppConfig.Name
                    }
                    catch { $appName = $null }
                }
                elseif (Test-Path $configJson) {
                    try {
                        $json = Get-Content -Path $configJson -Raw | ConvertFrom-Json -Depth 10
                        $appName = $json.Name
                    }
                    catch { $appName = $null }
                }
                if ($appName) {
                    [void]$existingAppNames.Add($appName)
                }
                # Also add the folder name as a fallback reference
                [void]$existingAppNames.Add($sub.Name)
            }
        }

        # Source folders to scan for Win32 app JSON files
        $sourceFolders = @()
        if (Test-Path $applicationsPath) { $sourceFolders += $applicationsPath }
        $manualImportPath = Join-Path -Path $envContentPath -ChildPath 'ManualAppImport'
        if (Test-Path $manualImportPath) { $sourceFolders += $manualImportPath }

        if ($sourceFolders.Count -eq 0) {
            Write-Info "[$envName] No Applications or ManualAppImport folders found — skipping"
            continue
        }

        # Ensure Applications folder exists (target for subfolders)
        if (-not (Test-Path $applicationsPath)) {
            New-Item -ItemType Directory -Path $applicationsPath -Force | Out-Null
        }

        $movedCount = 0
        $skippedCount = 0
        $alreadyOrganized = 0

        foreach ($sourceFolder in $sourceFolders) {
            $sourceName = Split-Path -Leaf $sourceFolder
            $jsonFiles = Get-ChildItem -Path $sourceFolder -Filter '*.json' -File -ErrorAction SilentlyContinue
            if (-not $jsonFiles) { continue }

            foreach ($jsonFile in $jsonFiles) {
                try {
                    $rawContent = Get-Content -Path $jsonFile.FullName -Raw
                    # Handle UTF-16 BOM — detect and re-read with correct encoding
                    $bytes = [System.IO.File]::ReadAllBytes($jsonFile.FullName)
                    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
                        $rawContent = [System.Text.Encoding]::Unicode.GetString($bytes)
                    }
                    $appObj = $rawContent | ConvertFrom-Json -Depth 10

                    # Only process Win32 LOB apps
                    if ($appObj.'@odata.type' -ne '#microsoft.graph.win32LobApp') {
                        continue
                    }

                    $displayName = $appObj.displayName
                    if ([string]::IsNullOrWhiteSpace($displayName)) {
                        Write-Warn "[$envName] File '$($jsonFile.Name)' has no displayName — skipping"
                        $skippedCount++
                        continue
                    }

                    # Sanitize display name for folder use (remove invalid path characters)
                    $safeFolderName = $displayName -replace '[<>:"/\\|?*]', '-'

                    $targetFolder = Join-Path -Path $applicationsPath -ChildPath $safeFolderName

                    # Check if already organized in a subfolder
                    if ($jsonFile.DirectoryName -eq $targetFolder) {
                        $alreadyOrganized++
                        continue
                    }

                    # Create target subfolder
                    if (-not (Test-Path $targetFolder)) {
                        New-Item -ItemType Directory -Path $targetFolder -Force | Out-Null
                    }

                    $targetFile = Join-Path -Path $targetFolder -ChildPath $jsonFile.Name
                    if (Test-Path $targetFile) {
                        Write-Warn "[$envName] Target file already exists: $targetFile — skipping"
                        $skippedCount++
                        continue
                    }

                    Move-Item -Path $jsonFile.FullName -Destination $targetFile -Force
                    $movedCount++

                    # Extract base64 logo from the JSON and save as an image file
                    if ($appObj.largeIcon -and $appObj.largeIcon.value) {
                        try {
                            $mimeType = $appObj.largeIcon.type
                            $ext = switch -Regex ($mimeType) {
                                'jpeg|jpg' { '.jpg' }
                                'png'      { '.png' }
                                default    { '.png' }
                            }
                            $logoFile = Join-Path -Path $targetFolder -ChildPath "logo$ext"
                            if (-not (Test-Path $logoFile)) {
                                $logoBytes = [System.Convert]::FromBase64String($appObj.largeIcon.value)
                                [System.IO.File]::WriteAllBytes($logoFile, $logoBytes)
                                Write-Info "[$envName]   Extracted logo → logo$ext"
                            }
                        }
                        catch {
                            Write-Warn "[$envName]   Could not extract logo for '$displayName': $($_.Exception.Message)"
                        }
                    }

                    # Check for .intunewin file in the subfolder
                    $hasIntuneWin = (Get-ChildItem -Path $targetFolder -Filter '*.intunewin' -File -ErrorAction SilentlyContinue).Count -gt 0

                    # Check if this app also exists in the Apps folder
                    $existsInApps = $existingAppNames.Contains($displayName) -or $existingAppNames.Contains($safeFolderName)

                    $script:Win32AppFolderResults.Add([PSCustomObject]@{
                            Environment   = $envName
                            DisplayName   = $displayName
                            FolderPath    = $targetFolder
                            HasIntuneWin  = $hasIntuneWin
                            ExistsInApps  = $existsInApps
                            SourceFolder  = $sourceName
                        })

                    Write-Info "[$envName] Moved '$displayName' → Applications\$safeFolderName\ (from $sourceName)"
                }
                catch {
                    Write-Warn "[$envName] Could not process '$($jsonFile.Name)': $($_.Exception.Message)"
                    $skippedCount++
                }
            }
        }

        # Also scan existing subfolders to report their status
        $existingSubfolders = Get-ChildItem -Path $applicationsPath -Directory -ErrorAction SilentlyContinue
        foreach ($sub in $existingSubfolders) {
            $jsonFiles = Get-ChildItem -Path $sub.FullName -Filter '*.json' -File -ErrorAction SilentlyContinue
            foreach ($jf in $jsonFiles) {
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($jf.FullName)
                    $raw = if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
                        [System.Text.Encoding]::Unicode.GetString($bytes)
                    } else { [System.Text.Encoding]::UTF8.GetString($bytes) }
                    $obj = $raw | ConvertFrom-Json -Depth 10
                    if ($obj.'@odata.type' -ne '#microsoft.graph.win32LobApp') { continue }

                    # Only add if not already tracked from the move phase
                    $alreadyTracked = $script:Win32AppFolderResults | Where-Object { $_.FolderPath -eq $sub.FullName -and $_.DisplayName -eq $obj.displayName }
                    if ($alreadyTracked) { continue }

                    $hasIW = (Get-ChildItem -Path $sub.FullName -Filter '*.intunewin' -File -ErrorAction SilentlyContinue).Count -gt 0
                    $inApps = $existingAppNames.Contains($obj.displayName) -or $existingAppNames.Contains($sub.Name)

                    $script:Win32AppFolderResults.Add([PSCustomObject]@{
                            Environment   = $envName
                            DisplayName   = $obj.displayName
                            FolderPath    = $sub.FullName
                            HasIntuneWin  = $hasIW
                            ExistsInApps  = $inApps
                            SourceFolder  = 'Applications'
                        })
                }
                catch { continue }
            }
        }

        if ($movedCount -gt 0) {
            Write-Success "[$envName] Organized $movedCount Win32 app(s) into subfolders"
        }
        if ($alreadyOrganized -gt 0) {
            Write-Info "[$envName] $alreadyOrganized Win32 app(s) already in subfolders"
        }
        if ($skippedCount -gt 0) {
            Write-Warn "[$envName] Skipped $skippedCount file(s) — see warnings above"
        }
    }

    # ── Display summary table ──
    if ($script:Win32AppFolderResults.Count -gt 0) {
        Write-Host ""
        Write-Host "  ── Win32 App Subfolder Status ──" -ForegroundColor Cyan
        Write-Host ""
        Write-Host ("  {0,-12} {1,-50} {2,-12} {3,-10} {4}" -f 'Environment', 'Display Name', '.IntuneWin', 'In Apps/', 'Folder Path') -ForegroundColor White
        Write-Host ("  {0,-12} {1,-50} {2,-12} {3,-10} {4}" -f ('-' * 11), ('-' * 49), ('-' * 11), ('-' * 9), ('-' * 40)) -ForegroundColor DarkGray

        foreach ($app in $script:Win32AppFolderResults) {
            $iwStatus = if ($app.HasIntuneWin) { 'READY' } else { 'MISSING' }
            $iwColor = if ($app.HasIntuneWin) { 'Green' } else { 'Red' }
            $appsStatus = if ($app.ExistsInApps) { 'Yes' } else { 'No' }

            Write-Host ("  {0,-12} " -f $app.Environment) -ForegroundColor White -NoNewline
            Write-Host ("{0,-50} " -f ($app.DisplayName.Substring(0, [Math]::Min(49, $app.DisplayName.Length)))) -ForegroundColor Gray -NoNewline
            Write-Host ("{0,-12} " -f $iwStatus) -ForegroundColor $iwColor -NoNewline
            Write-Host ("{0,-10} " -f $appsStatus) -ForegroundColor Gray -NoNewline
            Write-Host $app.FolderPath -ForegroundColor DarkGray
        }

        $needIntuneWin = @($script:Win32AppFolderResults | Where-Object { -not $_.HasIntuneWin })
        if ($needIntuneWin.Count -gt 0) {
            Write-Host ""
            Write-Host "  ACTION REQUIRED:" -ForegroundColor Yellow
            Write-Host "  The following $($needIntuneWin.Count) Win32 app subfolder(s) need .intunewin files" -ForegroundColor Yellow
            Write-Host "  before the pipeline can import them:" -ForegroundColor Yellow
            Write-Host ""
            foreach ($app in $needIntuneWin) {
                Write-Host "    - $($app.DisplayName)" -ForegroundColor Yellow
                Write-Host "      Folder: $($app.FolderPath)" -ForegroundColor DarkGray
            }
        }

        $readyApps = @($script:Win32AppFolderResults | Where-Object { $_.HasIntuneWin })
        if ($readyApps.Count -gt 0) {
            Write-Host ""
            Write-Success "$($readyApps.Count) Win32 app(s) are ready for pipeline import (JSON + .intunewin present)"
        }

        $duplicates = @($script:Win32AppFolderResults | Where-Object { $_.HasIntuneWin -and $_.ExistsInApps })
        if ($duplicates.Count -gt 0) {
            Write-Host ""
            Write-Info "$($duplicates.Count) Win32 app(s) also exist in the Apps\ folder — the Apps\ version will be skipped during import if the Applications\ version imports successfully"
        }
    }
    else {
        Write-Info "No Win32 app JSON files found in Applications or ManualAppImport folders"
    }
}
#endregion Functions

#region Main
# ─────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ─────────────────────────────────────────────────────────────

Write-Host ""
Write-Host ("*" * 70) -ForegroundColor Magenta
Write-Host "  INTUNE IaC — INFRASTRUCTURE SETUP AUTOMATION" -ForegroundColor Magenta
if ($PrepareWin32AppFolders -and -not $PrerequisitesOnly -and -not $Teardown) {
    Write-Host "  MODE: PREPARE WIN32 APP FOLDERS" -ForegroundColor Cyan
}
elseif ($PrerequisitesOnly) {
    Write-Host "  MODE: PREREQUISITES ONLY" -ForegroundColor Cyan
}
elseif ($Teardown) {
    Write-Host "  MODE: TEARDOWN (removing cloud/remote resources — local files preserved)" -ForegroundColor Red
}
elseif ($ProductionOnly) {
    Write-Host "  MODE: PROVISION — PRODUCTION ONLY (default)" -ForegroundColor Yellow
}
else {
    Write-Host "  MODE: PROVISION — ALL ENVIRONMENTS (dev, staging, production)" -ForegroundColor Green
}
Write-Host ("*" * 70) -ForegroundColor Magenta
Write-Host ""
Write-Host "  Configuration:" -ForegroundColor White
Write-Host "    ADO Organization : $ADOOrganization" -ForegroundColor White
Write-Host "    ADO Project      : $ADOProject" -ForegroundColor White
Write-Host "    ADO Repo         : $ADORepoName" -ForegroundColor White
Write-Host "    Subscription     : $AzureSubscriptionName ($AzureSubscriptionId)" -ForegroundColor White
Write-Host "    Tenant           : $TenantId" -ForegroundColor White
Write-Host "    Resource Group   : $ResourceGroupName" -ForegroundColor White
Write-Host "    Azure Region     : $AzureRegion" -ForegroundColor White
Write-Host "    Environments     : $($Environments -join ', ')" -ForegroundColor White
Write-Host "    Local Repo       : $LocalRepoPath" -ForegroundColor White
if ($DevTenantId) {
    Write-Host "    Dev Tenant       : $DevTenantId" -ForegroundColor White
}
if ($StagingTenantId) {
    Write-Host "    Staging Tenant   : $StagingTenantId" -ForegroundColor White
}
if ($UseSelfHostedAgent) {
    Write-Host "    Agent Pool       : DMAC-SelfHosted (default)" -ForegroundColor White
}
Write-Host ""

if ($PrepareWin32AppFolders -and -not $PrerequisitesOnly -and -not $Teardown) {
    # ── PREPARE WIN32 APP FOLDERS ONLY ──
    Initialize-Win32AppFolders

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Green
    Write-Host "  Win32 app folder preparation complete." -ForegroundColor Green
    Write-Host ("=" * 70) -ForegroundColor Green
    Write-Host ""
    # Fall through to summary
}
elseif ($PrerequisitesOnly) {
    # ── PREREQUISITES-ONLY FLOW ──
    Install-Prerequisites

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Green
    Write-Host "  Prerequisites installation complete." -ForegroundColor Green
    if ($script:RunningPS5) {
        Write-Host "" -ForegroundColor Yellow
        Write-Host "  NEXT: Open a PowerShell 7 terminal and re-run the full script:" -ForegroundColor Yellow
        Write-Host "    pwsh.exe" -ForegroundColor White
        Write-Host "    cd $LocalRepoPath" -ForegroundColor White
        Write-Host "    .\scripts\Invoke-InfrastructureSetup.ps1 -ADOOrganization `"$ADOOrganization`" ..." -ForegroundColor White
    }
    else {
        Write-Host "  Please restart your PowerShell session to ensure all new tools" -ForegroundColor Yellow
        Write-Host "  and modules are available on your PATH, then re-run this script" -ForegroundColor Yellow
        Write-Host "  without -PrerequisitesOnly to continue setup." -ForegroundColor Yellow
    }
    Write-Host ("=" * 70) -ForegroundColor Green
    Write-Host ""
    exit 0
}
elseif ($Teardown) {
    # ── TEARDOWN FLOW ──
    if (-not $SkipPrerequisites) { Install-Prerequisites }
    if ($script:RestartRequired) {
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor Yellow
        Write-Host "  One or more prerequisites were installed that require a" -ForegroundColor Yellow
        Write-Host "  PowerShell session restart before they are available on PATH." -ForegroundColor Yellow
        Write-Host "  Please close this terminal, open a new PowerShell session," -ForegroundColor Yellow
        Write-Host "  and re-run this script." -ForegroundColor Yellow
        Write-Host ("=" * 70) -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }
    Remove-AllResources
}
else {
    # ── PROVISION FLOW ──
    if (-not $SkipPrerequisites) { Install-Prerequisites }
    if ($script:RestartRequired) {
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor Yellow
        Write-Host "  One or more prerequisites were installed that require a" -ForegroundColor Yellow
        Write-Host "  PowerShell session restart before they are available on PATH." -ForegroundColor Yellow
        Write-Host "  Please close this terminal, open a new PowerShell session," -ForegroundColor Yellow
        Write-Host "  and re-run this script." -ForegroundColor Yellow
        Write-Host ("=" * 70) -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }

    # ── Configure self-hosted agent default (local YAML change) ──
    if ($UseSelfHostedAgent) {
        Set-SelfHostedAgentDefault -Enabled $true
    }

    $uamiDetails = @{}

    if (-not $SkipAzureSetup) {
        $uamiDetails = New-AzureResources
    }
    else {
        Write-Info "Skipping Azure setup (-SkipAzureSetup specified)"
    }

    if (-not $SkipADOSetup) {
        New-ADOResources -UamiDetails $uamiDetails
    }
    else {
        Write-Info "Skipping ADO setup (-SkipADOSetup specified)"
        # Acquire an ADO bearer token so that New-WorkloadIdentityFederation
        # can cross-check the service connection's actual issuer/subject values.
        # Normally Invoke-ADOLogin runs inside New-ADOResources, but that was skipped.
        if (-not $env:AZURE_DEVOPS_EXT_PAT) {
            Invoke-ADOLogin | Out-Null
        }
    }

    # Federation depends on both UAMIs (Azure setup) and the ADO org GUID (ADO setup).
    # Run it after both are in place.
    if (-not $SkipAzureSetup -and $uamiDetails) {
        New-WorkloadIdentityFederation -UamiDetails $uamiDetails
    }

    # ── Import enrollment restrictions, branding, and apply assignment patches ──
    # These endpoints reject app-only tokens (UAMI/service principal) with HTTP 403,
    # so they must be imported here while the admin is authenticated interactively.
    # A single delegated MgGraph session is established upfront and reused across
    # all environments to avoid multiple auth prompts.
    $needsDelegatedAuth = (-not $SkipAzureSetup) -or $PatchEnrollmentAssignments
    $mgAuthOk = $false
    if ($needsDelegatedAuth) {
        # Determine the unique tenant IDs across all environments
        $delegatedTenantIds = [System.Collections.Generic.List[string]]::new()
        foreach ($envName in $Environments) {
            $tid = if ($script:EnvConfigs -and $script:EnvConfigs.ContainsKey($envName)) {
                $script:EnvConfigs[$envName].TenantId
            }
            else { $script:TenantId }
            if (-not $delegatedTenantIds.Contains($tid)) {
                $delegatedTenantIds.Add($tid)
            }
        }

        # Establish the MgGraph session for the first (usually only) tenant.
        # If multiple tenants are in play, Test-MgGraphIntuneSession will
        # transparently re-connect when the tenant changes — showing the WAM
        # popup at most once per distinct tenant.
        $primaryTenantId = $delegatedTenantIds[0]
        $mgAuthOk = Connect-MgGraphForIntune -TenantId $primaryTenantId
        if (-not $mgAuthOk) {
            Write-Err "Could not establish a delegated Microsoft Graph session. Enrollment restrictions, branding profiles, W365 provisioning policies, and assignment patches will be skipped."
        }
    }

    if (-not $SkipAzureSetup -and $mgAuthOk) {
        foreach ($envName in $Environments) {
            Import-EnrollmentRestrictions -Environment $envName
        }

        foreach ($envName in $Environments) {
            Import-IntuneBranding -Environment $envName
        }

        foreach ($envName in $Environments) {
            Import-W365ProvisioningPolicies -Environment $envName
        }
    }

    # ── Patch enrollment restriction assignments and scope tags (backward compat) ──
    # The initial import now handles assignments in-line, but this remains for
    # policies imported before that capability was added.
    if ($PatchEnrollmentAssignments -and $mgAuthOk) {
        foreach ($envName in $Environments) {
            Update-EnrollmentRestrictionAssignments -Environment $envName
        }
    }

    # NOTE: MgGraph session is intentionally left connected so subsequent
    # script runs can reuse it at Phase 1 (zero prompts). The session will
    # expire naturally after the token lifetime (~1 hour).

    # ── Prepare Win32 app subfolders ──
    Initialize-Win32AppFolders

    # ── Ensure Azure CLI is back on the production tenant ──
    if (-not $SkipAzureSetup) {
        $currentAccount = az account show -o json 2>$null | ConvertFrom-Json
        if ($currentAccount -and $currentAccount.tenantId -ne $script:TenantId) {
            az login --tenant $script:TenantId --only-show-errors | Out-Null
            az account set --subscription $script:AzureSubscriptionId --only-show-errors
        }
    }

    # ── Ensure local workspace is a properly cloned repo linked to ADO ──
    if (-not $SkipADOSetup) {
        Write-StepHeader "VERIFYING LOCAL WORKSPACE GIT STATE"
        $remoteUrl = "https://$ADOOrganization@dev.azure.com/$ADOOrganization/$ADOProject/_git/$ADORepoName"

        Push-Location $LocalRepoPath
        try {
            $isGitRepo = Test-Path ".git"
            $currentRemote = if ($isGitRepo) { git remote get-url origin 2>$null } else { $null }

            if ($isGitRepo -and $currentRemote -eq $remoteUrl) {
                # Already a proper clone — fetch latest and ensure tracking is set
                Write-Success "Local workspace is already linked to $remoteUrl"
                $branchName = git branch --show-current 2>$null
                if (-not $branchName) { $branchName = "main" }

                Write-Info "Fetching latest from origin..."
                git fetch origin 2>$null | Out-Null

                # Ensure the local branch tracks the remote
                $trackingBranch = git config "branch.$branchName.remote" 2>$null
                if ($trackingBranch -ne "origin") {
                    git branch --set-upstream-to="origin/$branchName" $branchName 2>$null | Out-Null
                    Write-Success "Branch '$branchName' now tracks origin/$branchName"
                }
                else {
                    Write-Success "Branch '$branchName' is tracking origin/$branchName"
                }
            }
            elseif ($isGitRepo) {
                # Git repo exists but remote doesn't match — the push stage already handled
                # this. Just verify tracking is set correctly.
                Write-Info "Git repo exists. Verifying remote and tracking..."
                $branchName = git branch --show-current 2>$null
                if (-not $branchName) { $branchName = "main" }
                git fetch origin 2>$null | Out-Null
                $trackingBranch = git config "branch.$branchName.remote" 2>$null
                if ($trackingBranch -ne "origin") {
                    git branch --set-upstream-to="origin/$branchName" $branchName 2>$null | Out-Null
                    Write-Success "Branch '$branchName' now tracks origin/$branchName"
                }
                else {
                    Write-Success "Branch '$branchName' is tracking origin/$branchName"
                }
            }
            else {
                # Not a git repo at all (should have been handled by the push step, but
                # handle the edge case where -SkipADOSetup was used previously and re-running
                # without it now). Re-clone from ADO into a temp dir, then move .git into place.
                Write-Warn "Local folder is not a git repository. Cloning from ADO..."
                $tempClonePath = Join-Path -Path $env:TEMP -ChildPath "intune-iac-clone-$(Get-Date -Format 'yyyyMMddHHmmss')"
                try {
                    git clone $remoteUrl $tempClonePath 2>$null | Out-Null
                    if (Test-Path (Join-Path $tempClonePath ".git")) {
                        # Move the .git directory into the local repo path
                        Move-Item -Path (Join-Path $tempClonePath ".git") -Destination (Join-Path $LocalRepoPath ".git") -Force
                        Write-Success "Git repository linked from ADO clone"

                        # Reset to reconcile any differences between local files and remote
                        git fetch origin 2>$null | Out-Null
                        $branchName = git branch --show-current 2>$null
                        if (-not $branchName) { $branchName = "main" }
                        git branch --set-upstream-to="origin/$branchName" $branchName 2>$null | Out-Null

                        # Stage any local differences so they can be committed
                        $statusOutput = git status --porcelain 2>$null
                        if ($statusOutput) {
                            Write-Info "Local files differ from remote. Staging changes..."
                            git add -A 2>$null | Out-Null
                            Write-Success "Local changes staged. Run 'git status' to review, then 'git commit' + 'git push' to sync."
                        }
                        else {
                            Write-Success "Local workspace is in sync with remote"
                        }
                    }
                    else {
                        Write-Err "Clone failed — no .git directory created. Verify the ADO repo exists and you have access."
                    }
                }
                finally {
                    if (Test-Path $tempClonePath) {
                        Remove-Item -Path $tempClonePath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }

            # Open the workspace in VS Code (or VS Code Insiders) if not already open
            $codeCmd = $null
            if (Test-CommandExists "code-insiders") { $codeCmd = "code-insiders" }
            elseif (Test-CommandExists "code") { $codeCmd = "code" }

            if ($codeCmd) {
                # Check if VS Code already has this folder open by looking for the lock file
                # or by checking running instances
                $alreadyOpen = $false
                try {
                    # VS Code writes workspace state — check if a code process has this path
                    $codeProcesses = Get-Process -Name ($codeCmd -replace '-', '') -ErrorAction SilentlyContinue
                    if (-not $codeProcesses) {
                        $codeProcesses = Get-Process -Name "Code*" -ErrorAction SilentlyContinue
                    }
                    # Heuristic: if VS Code is running and we're executing from this path, it's likely open
                    if ($codeProcesses -and $PSScriptRoot -like "$LocalRepoPath*") {
                        $alreadyOpen = $true
                    }
                }
                catch {
                    # Intentionally suppressed — VS Code workspace detection is best-effort
                    $null = $null
                }

                if ($alreadyOpen) {
                    Write-Success "VS Code appears to have this workspace open"
                }
                else {
                    Write-Info "Opening workspace in $codeCmd..."
                    & $codeCmd $LocalRepoPath 2>$null
                    Write-Success "Workspace opened in $codeCmd"
                }
            }
            else {
                Write-Warn "VS Code not found on PATH. Open the workspace manually: $LocalRepoPath"
            }

            Write-Success "Local workspace is ready for branching, committing, and pushing to ADO"
        }
        finally {
            Pop-Location
        }
    }
}

# ── Summary ──
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan

if ($script:Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "  Errors encountered ($($script:Errors.Count)):" -ForegroundColor Red
    foreach ($err in $script:Errors) {
        Write-Host "    - $err" -ForegroundColor Red
    }
}
else {
    Write-Host ""
    Write-Host "  All steps completed successfully!" -ForegroundColor Green
}

if (-not $Teardown) {
    Write-Host ""
    Write-Host "  NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "    1. Verify Graph permissions: Entra ID > Enterprise Apps > Managed Identities" -ForegroundColor Yellow
    Write-Host "    2. Review service connections in ADO: Project Settings > Service Connections" -ForegroundColor Yellow
    Write-Host "    3. Link variable group 'intune-pipeline-vars' to the 'Intune CICD' pipeline" -ForegroundColor Yellow
    if ($StagingApprovers.Count -eq 0 -or $ProductionApprovers.Count -eq 0) {
        Write-Host "    4. Add approval gates on staging/production environments (or re-run with -StagingApprovers/-ProductionApprovers)" -ForegroundColor Yellow
    }
    Write-Host "    5. Run the 'Intune CICD' pipeline to test validation" -ForegroundColor Yellow
    if ($ProductionOnly) {
        Write-Host "    6. To enable dev/staging, re-run with -AllEnvironments and set PRODUCTION_ONLY=false in variable group" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  OPTIONAL FEATURES (enable in variable group):" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_UPDATE_EXISTING=true   — Compare & update existing objects (default: skip)" -ForegroundColor DarkCyan
    Write-Host "    WHATIF_ONLY=true               — Dry-run mode: report changes without applying" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_TRANSFORMATIONS=true    — Per-environment value overrides via transformations.json" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_BACKUP_TO_REPO=true     — Save tenant config snapshot to Backups/ folder in repo" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_DRIFT_DETECTION=true    — Scheduled drift detection (compare tenant vs repo)" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_POST_IMPORT_HEALTHCHECK — Verify objects exist after import" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_NOTIFICATIONS=true      — Post summary to Teams/Slack webhook" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_ASSIGNMENT_PREVALIDATION — Verify assignment groups exist before import" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_GIT_TAGGING=true        — Tag git commit on successful deploy" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_INVENTORY_REPORT=true   — Generate markdown inventory of policies" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_STALE_CONTENT_DETECTION — Warn about old content files (>180 days)" -ForegroundColor DarkCyan
    Write-Host "    IMPORT_TYPES / EXPORT_TYPES    — Comma-separated list to filter object types" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_CONTENT_FILTERING=true  — Master switch for content name/type/changed-only filters" -ForegroundColor DarkCyan
    Write-Host "    CONTENT_NAME_INCLUDE_FILTER    — Only import content whose name contains this string" -ForegroundColor DarkCyan
    Write-Host "    CONTENT_NAME_EXCLUDE_FILTER    — Exclude content whose name contains this string" -ForegroundColor DarkCyan
    Write-Host "    CONTENT_TYPE_INCLUDE_FILTER    — Only import specified content types (comma-separated)" -ForegroundColor DarkCyan
    Write-Host "    CONTENT_TYPE_EXCLUDE_FILTER    — Exclude specified content types (comma-separated)" -ForegroundColor DarkCyan
    Write-Host "    ENABLE_CHANGED_ONLY_IMPORT     — Only import new or changed content (skip identical)" -ForegroundColor DarkCyan
    Write-Host "    LOG_ANALYTICS_WORKSPACE_ID     — Send structured logs to Azure Log Analytics" -ForegroundColor DarkCyan
    Write-Host "    LOG_ANALYTICS_SHARED_KEY        — Shared key for Log Analytics workspace" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  USEFUL URLS:" -ForegroundColor Cyan
    Write-Host "    ADO Project : $($script:ADOBaseUrl)/$ADOProject" -ForegroundColor Cyan
    Write-Host "    Repository  : $($script:ADOBaseUrl)/$ADOProject/_git/$ADORepoName" -ForegroundColor Cyan
    Write-Host "    Pipelines   : $($script:ADOBaseUrl)/$ADOProject/_build" -ForegroundColor Cyan
    Write-Host ""
}

Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""
#endregion Main
