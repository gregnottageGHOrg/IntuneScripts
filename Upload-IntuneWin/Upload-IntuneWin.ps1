# Module requirement handled in script initialization - checks PSScriptRoot if not installed
# #Requires -Module Microsoft.Graph.Authentication
#region Initialisation...
<#

.SYNOPSIS
    Creates and uploads Win32 application packages to Microsoft Intune.

.DESCRIPTION
    This script automates the creation and upload of Win32 application packages (.intunewin) to Microsoft Intune.
    It supports MSI, EXE, PS1, and Edge application types with configurable detection rules, return codes,
    and Entra ID group assignments.

    The script reads configuration from either a Config.json or Config.xml file in the package folder
    (JSON takes precedence if both exist) and can authenticate using interactive login, certificate-based
    authentication, or client secret.

    Key features:
    - Creates .intunewin packages using IntuneWinAppUtil.exe
    - Uploads packages to Intune via Microsoft Graph API
    - Creates and assigns Entra ID groups for Required, Available, and Uninstall targeting
    - Supports custom scope tags for application management
    - Configurable detection rules (File, Registry, MSI, PowerShell script)

.PARAMETER IntuneAdmin
    Specifies the Intune Administrator user name for interactive authentication.
    Uses Connect-MgGraph with interactive login.

.PARAMETER PackagePath
    Mandatory. Specifies the path to the package folder containing the Config.xml file.
    The folder should contain a 'Source' subfolder with the application files.
    If the 'Source' subfolder does not exist but an 'OrigSource' subfolder exists,
    the script will use 'OrigSource' as the source folder for creating the .intunewin package.
    Alias: PackageName

.PARAMETER IntuneWinAppUtilPath
    Specifies the folder path containing IntuneWinAppUtil.exe.
    If not specified, the script looks for IntuneWinAppUtil.exe in the script's directory.

.PARAMETER ClientID
    Specifies the Azure App Registration (Service Principal) Application (client) ID.
    Required when using certificate or client secret authentication.
    Can also be used with -IntuneAdmin for delegated authentication using a custom app registration
    instead of the default Microsoft Graph PowerShell SDK app. This is useful when the default app
    is not consented in the tenant or when specific API permissions are required.
    Alias: AppID

.PARAMETER TenantID
    Specifies the Azure Tenant ID.
    Required when using certificate or client secret authentication.

.PARAMETER ClientSecret
    Specifies the Azure App Registration (Service Principal) Client Secret.
    Used for non-interactive authentication with a service principal.
    Alias: Secret

.PARAMETER CertName
    Specifies the Azure App Registration (Service Principal) Certificate name.
    The certificate must be installed in the current user's personal certificate store.

.PARAMETER IntuneWinPackageOnly
    Switch parameter that creates the .IntuneWin file only without uploading to Intune.
    Useful for pre-creating packages for later upload.

.PARAMETER AssignGroupsOnly
    Switch parameter that assigns the AAD targeting groups only.
    Use when the application already exists in Intune and you only want to update group assignments.

.PARAMETER SkipGroupAssignment
    Switch parameter that creates the Win32 package with no targeting groups assigned.
    Useful when you want to manually assign groups later.

.PARAMETER SkipPackageRemoval
    Switch parameter that skips the deletion of the .IntuneWin file after upload.
    Useful for keeping local copies of packages.

.PARAMETER RequiredAADGroupName
    Specifies one or more Entra ID group names for required assignment targeting.
    Supports multiple groups: -RequiredAADGroupName "Group1","Group2"
    If a group doesn't exist, it will be created.
    Alias: RequiredEntraGroupName

.PARAMETER AvailableAADGroupName
    Specifies one or more Entra ID group names for available assignment targeting.
    Supports multiple groups: -AvailableAADGroupName "Group1","Group2"
    If a group doesn't exist, it will be created.
    Alias: AvailableEntraGroupName

.PARAMETER UninstallAADGroupName
    Specifies one or more Entra ID group names for uninstall assignment targeting.
    Supports multiple groups: -UninstallAADGroupName "Group1","Group2"
    If a group doesn't exist, it will be created.
    Alias: UninstallEntraGroupName

.PARAMETER NewTagPath
    Switch parameter that changes the tagfile path to %PROGRAMDATA%\IntuneManagementExtension\Logs.
    This ensures logs are captured during an Intune diagnostic log capture.

.PARAMETER ScopeTagName
    Specifies one or more Intune scope tag names to apply to the uploaded application.
    Supports multiple scope tags: -ScopeTagName "Tag1","Tag2"
    This parameter takes precedence over the ScopeTag attribute in Config.xml/Config.json.
    If a scope tag doesn't exist in the tenant, it will be created automatically.
    The specified scope tags replace any existing scope tags on the application (including the Default scope tag).
    Config files also support multiple scope tags as comma-separated values (e.g., "Tag1,Tag2").

.PARAMETER ReplaceExistingContent
    Switch parameter that replaces only the IntuneWin content of an existing application.
    If the application exists in Intune, all other configuration (assignments, detection rules,
    requirements, scope tags, etc.) will be preserved and only the package content is updated.
    If the application does not exist, it will be created as a new application.
    Useful for updating an application's installer without recreating the entire app configuration.

.PARAMETER ReplaceExistingAssignments
    Switch parameter that removes all existing assignments before applying new ones.
    Can be used standalone to replace assignments on an existing app without changing package content.
    Can also be combined with -ReplaceExistingContent to replace both content and assignments.
    Requires at least one assignment group parameter (-RequiredAADGroupName, -AvailableAADGroupName, or -UninstallAADGroupName).

.PARAMETER DisconnectGraph
    Switch parameter that disconnects from Microsoft Graph after the script completes.
    By default, when using -IntuneAdmin, the Graph connection is preserved to allow running
    multiple scripts without re-authentication. Use this switch to explicitly disconnect
    when you're done with all operations.
    Note: For ClientSecret and CertName authentication methods, the connection is always
    disconnected regardless of this switch.

.PARAMETER DeleteApp
    Switch parameter that deletes an application from Intune instead of uploading.
    When used with -PackagePath, reads the displayName from the Config.json or Config.xml file
    and deletes that application. Can also be combined with -AppNameToDelete to specify app
    names directly without requiring a config file.

.PARAMETER AppNameToDelete
    Specifies the display name(s) of the application(s) to delete from Intune.
    Can be a single string or an array of strings. Supports pipeline input.
    When used with -DeleteApp, the -PackagePath parameter becomes optional.
    If both -PackagePath and -AppNameToDelete are provided, all specified apps are deleted.

.PARAMETER WhatIf
    Shows what would happen if the script runs. The script performs all validation and
    displays the actions that would be taken without actually making any changes to Intune.
    Use this parameter to preview operations before executing them.

.PARAMETER Confirm
    Prompts you for confirmation before executing any operation that modifies Intune.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com"

    Uploads a package using interactive authentication with the specified admin account.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -ClientID "12345678-1234-1234-1234-123456789012" -TenantID "87654321-4321-4321-4321-210987654321" -ClientSecret "MySecret"

    Uploads a package using client secret authentication.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -ClientID "12345678-1234-1234-1234-123456789012" -TenantID "87654321-4321-4321-4321-210987654321" -CertName "MyCertificate"

    Uploads a package using certificate-based authentication.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -IntuneWinPackageOnly

    Creates the .intunewin package file only without uploading to Intune.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -RequiredAADGroupName "App-MyApp-Required" -AvailableAADGroupName "App-MyApp-Available"

    Uploads a package and assigns specific Entra ID groups for required and available targeting.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -ScopeTagName "CloudPC-Apps"

    Uploads a package and applies the "CloudPC-Apps" scope tag. If the scope tag doesn't exist, it will be created.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -ClientID "12345678-1234-1234-1234-123456789012"

    Uploads a package using delegated (interactive) authentication with a custom app registration.
    The user signs in interactively, but authentication flows through the specified app registration
    instead of the default Microsoft Graph PowerShell SDK app.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -ClientID "12345678-1234-1234-1234-123456789012" -TenantID "87654321-4321-4321-4321-210987654321"

    Uploads a package using delegated authentication with a custom app registration and explicit tenant.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -SkipGroupAssignment -ScopeTagName "Production"

    Uploads a package without group assignments but applies the "Production" scope tag.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -ReplaceExistingContent

    Updates only the IntuneWin package content of an existing application. All configuration
    (assignments, detection rules, requirements, etc.) is preserved. The application must already
    exist in Intune with a matching displayName from the Config.xml or Config.json.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -ReplaceExistingAssignments -AvailableAADGroupName "App-MyApp-Available"

    Removes all existing assignments from the application and applies the new Available assignment.
    The application content and other configuration are not modified.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -ReplaceExistingContent -ReplaceExistingAssignments -RequiredAADGroupName "App-MyApp-Required"

    Updates the IntuneWin package content AND replaces all existing assignments with the new Required assignment.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -DeleteApp

    Deletes the application specified in the Config.json or Config.xml file from Intune.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" -DeleteApp -AppNameToDelete "My Old Application"

    Deletes the application named "My Old Application" from Intune without requiring a config file.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" -DeleteApp -AppNameToDelete "App1", "App2", "App3"

    Deletes multiple applications from Intune in a single operation.

.EXAMPLE
    "App1", "App2" | .\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" -DeleteApp

    Deletes multiple applications from Intune using pipeline input.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -WhatIf

    Shows what would happen when uploading a package without actually making any changes.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" -DeleteApp -AppNameToDelete "OldApp" -WhatIf

    Shows what would happen when deleting an application without actually deleting it.

.NOTES
    File Name      : Upload-IntuneWin.ps1
    Version        : 1.96
    Prerequisite   : Microsoft.Graph.Authentication module
                     IntuneWinAppUtil.exe (Microsoft Win32 Content Prep Tool) - automatically downloaded if not present

    Upload Resilience & Feature Parity (v1.92):
    Backported improvements from the CI/CD pipeline solution for parity:
    - SAS readiness probing: Pre-checks Azure Storage SAS token propagation (403/404) before upload
    - Per-chunk upload retry: 3 retries per chunk with automatic SAS URI renewal on 403 failures
    - File commit retry loop: 6 attempts for file commit when SAS state hasn't transitioned yet
    - Upload attempt retry: Up to 3 full upload attempts with fresh content versions on failure
    - 412 Precondition Failed: Now retryable in Invoke-GraphRequestWithRetry (content version conflicts)
    - Logo auto-detection: Auto-scans package folder for PNG/JPG/JPEG if not specified in config
    - Logo JPEG MIME type: Correctly sets image/jpeg for .jpg/.jpeg files (was hardcoded to image/png)
    - Logo persistence PATCH: Applies logo via dedicated PATCH after content commit to prevent loss

    DelegatedImport Parity Enhancements (v1.93):
    Backported additional capabilities from Invoke-DelegatedImport.ps1 for full parity:
    - 401 token refresh: Invoke-GraphRequestWithRetry now detects HTTP 401 (expired token),
      disconnects, re-authenticates using stored connection params, and retries the request.
    - Expanded network error patterns: Retry now matches 'forcibly closed', 'Error while copying
      content to a stream', 'ResponseEnded', 'response ended prematurely', 'ended prematurely',
      'request was canceled', and 'send the request' in addition to existing patterns.
    - Chunk transient error handling: Per-chunk upload retry now handles HTTP 500/502/503/504
      with exponential backoff (10s * 2^attempt), increased from 3 to 5 retries per chunk.
    - App publishingState check: Before replacing content on an existing app, checks the
      publishingState. If the app is stuck in 'notPublished', deletes and falls through to
      full upload path (via Wait-AppPublishingState helper function).
    - Stuck app delete/recreate: When upload fails in Send-Win32Lob, the stuck app is deleted
      and recreated before the next retry attempt (prevents HTTP 400 on new content versions).
    - Escalating upload retry backoff: Upload retry delay now uses 30s * attempt number instead
      of a flat 10s delay, matching the DelegatedImport backoff strategy.
    - OrigSource to Source robocopy: When an OrigSource folder exists, copies it to Source via
      robocopy /MIR /MT:4 before packaging, ensuring a clean reproducible build. Previously
      only fell back to using OrigSource directly.

    Dependency and Supersedence Fixes (v1.94):
    Application dependencies and supersedence declared in Config.xml/Config.json never applied.
    - Parameter mismatch: Set-IntuneAppDependency / Set-IntuneAppSupersedence were called with
      -SourceAppId / -TargetAppDisplayName, which the functions did not declare. Canonical names
      are now used and the old names are retained as parameter aliases.
    - Name to ID resolution: Config supplies display names but the Graph payload requires an
      application ID. New Resolve-IntuneAppReference accepts either a GUID or a display name.
    - Correct Graph endpoint: POST .../mobileApps/{id}/relationships is not supported for Win32
      apps. Replaced with the updateRelationships action used by the Intune portal.
    - @odata.type ordering: The payload is built with ordered dictionaries so '@odata.type' is the
      first property of each relationship object. An unordered hashtable could serialise it later,
      which Graph rejects with HTTP 400 "The annotation 'odata.type' was found...".
    - Relationship merge: updateRelationships replaces the entire child relationship set, so the
      existing relationships are read back and re-posted alongside the new one. Adding a
      dependency no longer wipes supersedence (and vice versa).
    - Self-reference guard, OData single-quote escaping in the display-name lookup, and -WhatIf is
      now genuinely read-only for relationship changes.

    Per-App Relationship Types and Proxy Auth (v1.95):
    - Per-app dependency/supersedence types: previously one <DependencyType> applied to the whole
      <Dependencies> list. Each app can now carry its own type, either by repeating the element
      pair (matched by position) or with an inline 'Name:Type' suffix on any entry. An inline type
      overrides the element type. Config.json also accepts [{ name, type }] objects.
      Repeating <Dependencies> previously produced a space-joined string and silently mangled the
      app names; repeated elements are now read as a list.
    - HTTP 407 handling: a client-credentials token request through an authenticating proxy failed
      with 407, but the error was non-terminating, so the run continued with a null token and
      still printed "Successfully authenticated to Microsoft Graph". The request is now wrapped,
      the token is validated, and failures throw with proxy guidance.
    - Automatic proxy credential retry: on a 407 with no explicit -ProxyUri, the script attaches
      the caller's Windows credentials to the system default proxy and retries once, which covers
      the common NTLM/Negotiate corporate proxy.

    PowerShell Script Installer Type (v1.96):
    Supports the portal's Program tab "Installer type: PowerShell script" / "Uninstaller type:
    PowerShell script" options (Graph beta win32LobAppInstallPowerShellScript /
    win32LobAppUninstallPowerShellScript).
    - Config keys: InstallScriptFile / UninstallScriptFile, each with optional
      *ScriptEnforceSignatureCheck and *ScriptRunAs32Bit. Paths may be absolute or relative to the
      package folder. Config.json uses the camelCase equivalents.
    - Install and uninstall are independent, so all four portal combinations work: script+script,
      script+command, command+script, and command+command (the existing default).
    - Scripts are uploaded to the app's committed content version and activated by pointing
      activeInstallScript / activeUninstallScript at them. Where a script is set, Intune ignores
      the matching command line.
    - Scripts are re-applied whenever content is replaced, because they belong to the content
      version rather than the app.
    - Graph still requires both command lines, so a placeholder is generated when only a script is
      configured. Script content is capped at 100KB by the service and is rejected before upload
      if it exceeds that.

    WhatIf Support (v1.9):
    The script supports -WhatIf to preview operations without making changes:
    - Shows what applications would be uploaded, updated, or deleted
    - Shows what Entra ID groups would be created
    - Shows what assignments would be applied or cleared
    Use -WhatIf to safely preview operations before executing them.

    Automatic Tool Download and Update (v1.7):
    The script automatically manages IntuneWinAppUtil.exe:
    - If not found locally, downloads from GitHub automatically
    - If found locally, checks GitHub for updates and downloads newer versions
    - Provides clear user feedback about tool status and updates

    Automatic Version Detection (v1.6):
    For EXE and MSI packages, the script automatically detects the installer version:
    - EXE files: Uses FileVersionInfo.GetVersionInfo() to read FileVersion or ProductVersion
    - MSI files: Uses Windows Installer COM object to query ProductVersion from the database

    If the detected version differs from the displayVersion in Config.xml/Config.json:
    - User is prompted to use the detected version (Y/N)
    - Prompt times out after 30 seconds
    - On timeout: Uses config version if present, otherwise uses detected version
    - If user accepts or config version is empty, the config file is automatically updated

    The script supports two configuration file formats (Config.json takes precedence if both exist):

    Config.json properties:
    - appType: MSI, EXE, PS1, or Edge
    - ruleType: TAGFILE, FILE, REGISTRY, or MSI (for detection)
    - returnCodeType: DEFAULT or custom
    - installExperience: System or User
    - packageName: Name of the setup file (without extension)
    - displayName: Display name in Intune
    - displayVersion: Version string to display
    - description: App description
    - publisher: Publisher name
    - category: App category or comma-separated categories (e.g., "Business" or "Communication,Productivity,Computer Management")
    - logoFile: Path to logo file (PNG/JPG)
    - scopetag: Name of the Intune scope tag (optional, overridden by -ScopeTagName parameter)
    - entraGroupName: Entra ID group name for assignments (preferred)
    - aadGroupName: Entra ID group name for assignments (legacy, still supported)
    - allowAvailableUninstall: Enable/disable available uninstall - accepts yes/no or true/false (default: yes if not specified)
    - coreApp: Boolean for core app designation
    - espApp: Boolean for ESP app designation

    Extended Settings (v1.5 - all optional):
    - isFeatured: Show as featured app in Company Portal
    - informationUrl: URL for more information
    - privacyInformationUrl: URL for privacy information
    - developer: Developer name
    - owner: Owner name
    - notes: Additional notes
    - maxRunTimeInMinutes: Maximum install time (default 60)
    - deviceRestartBehavior: basedOnReturnCode, allow, suppress (default), force
    - minimumFreeDiskSpaceInMB: Minimum disk space requirement
    - minimumMemoryInMB: Minimum memory requirement
    - minimumNumberOfProcessors: Minimum CPU count requirement
    - minimumCpuSpeedInMHz: Minimum CPU speed requirement
    - allowedArchitectures: x64, x86, arm, arm64 (comma-separated)
    - minimumSupportedOS: Accepts short names (v10_1903, v11_23H2) or full names (Windows 10 1903, Windows 11 23H2).
                          Falls back to latest confirmed version if the specified version isn't yet in the Graph API schema.
    - customReturnCodes: Custom return code handling (array or comma-separated code:type)
    - dependencies: Apps this app depends on (array or comma-separated names)
    - dependencyType: autoInstall or detect
    - supersedence: Apps this app supersedes (array or comma-separated names)
    - supersedenceType: update or replace
    - detectionScriptFile: Path to PowerShell detection script
    - detectionScriptEnforceSignatureCheck: Require signed detection script
    - detectionScriptRunAs32Bit: Run detection script as 32-bit
    - installScriptFile / uninstallScriptFile: Path to a PowerShell install/uninstall script,
      replacing the matching command line (portal "Installer type: PowerShell script")
    - installScriptEnforceSignatureCheck / uninstallScriptEnforceSignatureCheck: Require signed script
    - installScriptRunAs32Bit / uninstallScriptRunAs32Bit: Run the script as 32-bit

    Config.xml supports the same attributes in the IntuneWin_Settings section:
    - AppType: MSI, EXE, PS1, or Edge
    - RuleType: TAGFILE, FILE, REGISTRY, or MSI (for detection)
    - InstallExperience: System or User
    - ScopeTag: Name of the Intune scope tag to apply (optional, overridden by -ScopeTagName parameter)

.COPYRIGHT
    Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
    See LICENSE in the project root for license information.

#>
#Script to create and upload IntuneWin packages
####################################################
####################################################
#Instantiate Vars
####################################################
[CmdLetBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Provide Intune Administrator user name'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $IntuneAdmin,

    [Parameter(Position = 3, ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Please enter path to package folder, containing Config.json or Config.xml file. Required unless using -DeleteApp with -AppNameToDelete.'
    )]
    [Alias("PackageName")]
    [string[]] $PackagePath,

    [Parameter(Position = 4,
        HelpMessage = 'Please enter folder path containing IntuneWinAppUtil.exe'
    )]
    [string] $IntuneWinAppUtilPath,

    [Parameter(Position = 5, ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $True,
        HelpMessage = 'Please specify Azure App Registration (Service Principal) Application (client) ID'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("AppID")]
    [string] $ClientID,

    [Parameter(Position = 6, ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $True,
        HelpMessage = 'Please specify Azure Tenant ID'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $TenantID,

    [Parameter(Position = 7, ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $True,
        HelpMessage = 'Please specify Azure App Registration (Service Principal) Client Secret'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("Secret")]
    [string] $ClientSecret,

    [Parameter(Position = 8, ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Provide Azure App Registration (Service Principal) Certificate name'
    )]
    [string] $CertName,

    [Parameter(HelpMessage = 'Creates the .IntuneWin file only')]
    [switch] $IntuneWinPackageOnly,

    [Parameter(HelpMessage = 'Assigns the AAD targeting groups only')]
    [switch] $AssignGroupsOnly,

    [Parameter(HelpMessage = 'Creates the Win32 package with no targeting groups assigned')]
    [switch] $SkipGroupAssignment,

    [Parameter(HelpMessage = 'Skips the deletion of the .IntuneWin file')]
    [switch] $SkipPackageRemoval,

    [Parameter(HelpMessage = 'Applies one or more Entra ID groups with required assignment targeting'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("RequiredEntraGroupName")]
    [string[]] $RequiredAADGroupName,

    [Parameter(HelpMessage = 'Applies one or more Entra ID groups with available assignment targeting'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("AvailableEntraGroupName")]
    [string[]] $AvailableAADGroupName,

    [Parameter(HelpMessage = 'Applies one or more Entra ID groups with uninstall assignment targeting'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("UninstallEntraGroupName")]
    [string[]] $UninstallAADGroupName,

    [Parameter(HelpMessage = 'Changes the tagfile path to %PROGRAMDATA%\IntuneManagementExtension\Logs - this is so that the logs are captured during an Intune diagnostic log capture'
    )]
    [switch] $NewTagPath,

    [Parameter(HelpMessage = 'Specifies one or more Intune scope tag names to apply to the uploaded application. Takes precedence over ScopeTag in Config.xml. If a scope tag does not exist, it will be created.'
    )]
    [string[]] $ScopeTagName,

    [Parameter(HelpMessage = 'Replaces the IntuneWin content of an existing application while keeping all other configuration intact. If the app does not exist, creates it as a new application.'
    )]
    [switch] $ReplaceExistingContent,

    [Parameter(HelpMessage = 'Removes all existing assignments before applying new ones. Can be used standalone or with -ReplaceExistingContent. Requires at least one assignment group parameter.'
    )]
    [switch] $ReplaceExistingAssignments,

    [Parameter(HelpMessage = 'Disconnects from Microsoft Graph after the script completes. By default, the Graph connection is preserved when using -IntuneAdmin for running multiple scripts without re-authentication.'
    )]
    [switch] $DisconnectGraph,

    [Parameter(HelpMessage = 'Deletes the application from Intune instead of uploading. Uses displayName from config file or -AppNameToDelete parameter.'
    )]
    [switch] $DeleteApp,

    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Specifies the display name(s) of the application(s) to delete from Intune. Supports pipeline input.'
    )]
    [Alias("DisplayName", "Name")]
    [string[]] $AppNameToDelete,

    # ── Proxy authentication (opt-in; mirrors the standalone proxy module). ──
    # Presence of -ProxyUri (or $env:INTUNEWIN_PROXY_URI) opts the run into routing every
    # outbound HTTP/S call through a corporate proxy. The same PSCredential serves
    # the proxy server, MSAL.NET token acquisition, the Microsoft.Graph SDK's
    # HttpClient (via HTTPS_PROXY / HTTP_PROXY env vars), the Azure Storage
    # block-blob SAS upload path, and the GitHub IntuneWinAppUtil download.
    [Parameter(HelpMessage = 'Absolute URI of the outbound HTTP/HTTPS proxy (e.g., http://saas-proxy.contoso.com:443). Falls back to $env:INTUNEWIN_PROXY_URI. When neither is set the script runs WITHOUT proxy.')]
    [Alias('Proxy', 'HttpsProxy')]
    [uri] $ProxyUri,

    [Parameter(HelpMessage = 'PSCredential used to authenticate against the proxy server. If -ProxyUri is supplied but no -ProxyCredential is, the script prompts ONCE via Get-Credential and reuses the result. Mutually exclusive with -ProxyUseDefaultCredentials.')]
    [PSCredential] $ProxyCredential,

    [Parameter(HelpMessage = 'Use Windows-integrated authentication (Kerberos / NTLM) for the proxy instead of explicit credentials. Skips the credential prompt. Falls back to $env:INTUNEWIN_PROXY_USE_DEFAULT_CREDENTIALS.')]
    [switch] $ProxyUseDefaultCredentials,

    [Parameter(HelpMessage = 'Wildcard hostname patterns to bypass the proxy for (e.g., *.contoso.com). Falls back to $env:INTUNEWIN_PROXY_BYPASS (semicolon-separated).')]
    [string[]] $ProxyBypassList,

    [Parameter(HelpMessage = 'Disable the default behaviour of bypassing the proxy for local-name addresses. Falls back to $env:INTUNEWIN_PROXY_BYPASS_ON_LOCAL=false.')]
    [switch] $NoProxyBypassLocal,

    [Parameter(HelpMessage = 'Alternate execution path: validate direct vs proxy connectivity to Microsoft Graph and Entra ID, print a report, and exit. Exit codes: 0 = PASS, 1 = FAIL, 2 = init error.')]
    [switch] $TestProxyConnectivity
)
$script:exitCode = 0
$script:contentReplaced = $false
$script:noExistingAssignments = $false
$script:replaceAssignmentsMode = $false

$BuildVer = "1.96"
$ProgramFiles = $env:ProgramFiles
$ScriptName = $myInvocation.MyCommand.Name
$ScriptName = $ScriptName.Substring(0, $ScriptName.Length - 4)
Add-Type -AssemblyName Microsoft.VisualBasic
$script:EventLogName = "Application"
$script:EventLogSource = "EventSystem"
if ($packagePath) {
    $packagePath = $packagePath.Trim()
}

####################################################
# Log file path
####################################################
# Mirror the transcript-logging convention from Invoke-DelegatedImport.ps1:
# write to a 'Logs' subfolder alongside the script, with a per-run timestamped
# file name and rotation (see Remove-OldLogFiles below). Additionally embed the
# package displayName (read from Config.json / Config.xml) so each log file
# clearly maps to the package upload it relates to.
$logTimestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm'
$packageLogName = $null
if ($packagePath) {
    # When multiple package paths are supplied, name the log after the first one.
    $firstPkgPath = @($packagePath)[0]
    if (-not [string]::IsNullOrWhiteSpace($firstPkgPath)) {
        $firstPkgPath = ([string]$firstPkgPath).Trim()
        $pkgJsonPath = Join-Path -Path $firstPkgPath -ChildPath 'Config.json'
        $pkgXmlPath = Join-Path -Path $firstPkgPath -ChildPath 'Config.xml'
        try {
            if (Test-Path -LiteralPath $pkgJsonPath) {
                $packageLogName = (Get-Content -LiteralPath $pkgJsonPath -Raw | ConvertFrom-Json).displayName
            }
            elseif (Test-Path -LiteralPath $pkgXmlPath) {
                [xml]$pkgXmlDoc = Get-Content -LiteralPath $pkgXmlPath
                $packageLogName = $pkgXmlDoc.CONFIG.IntuneWin_Settings.displayName
            }
        }
        catch {
            # Non-fatal this early in startup; fall back to a generic name below.
            $packageLogName = $null
        }
    }
}
if ([string]::IsNullOrWhiteSpace($packageLogName) -and $AppNameToDelete) {
    $packageLogName = @($AppNameToDelete)[0]
}
if ([string]::IsNullOrWhiteSpace($packageLogName)) {
    $packageLogName = 'NoPackage'
}
# Sanitise for use in a file name: replace illegal characters and collapse whitespace.
$packageLogNameSafe = ([string]$packageLogName -replace '[\\/:*?"<>|]', '_' -replace '\s+', '-').Trim('-_')
if ([string]::IsNullOrWhiteSpace($packageLogNameSafe)) { $packageLogNameSafe = 'NoPackage' }
if ($packageLogNameSafe.Length -gt 80) { $packageLogNameSafe = $packageLogNameSafe.Substring(0, 80) }
# Log file name prefix (intentionally shorter than $ScriptName for tidier file names).
$logPrefix = 'Upload'
$LogName = "${logPrefix}_${packageLogNameSafe}_${logTimestamp}"
$logPath = Join-Path -Path $PSScriptRoot -ChildPath 'Logs'
$logFile = Join-Path -Path $logPath -ChildPath "$LogName.log"

# Determine source path - use Source folder if it exists, otherwise fall back to OrigSource
$SourcePath = if ($packagePath) { "$packagePath\Source" } else { $null }
$OrigSourcePath = if ($packagePath) { "$packagePath\OrigSource" } else { $null }

if (!($intuneWinAppUtilPath)) {
    $IntuneWinAppUtil = "$PSScriptRoot\IntuneWinAppUtil.exe"
}
else {
    $intuneWinAppUtilPath = $intuneWinAppUtilPath.Trim('"')
    #Strip trailing \
    $lastChar = $intuneWinAppUtilPath.Substring($intuneWinAppUtilPath.Length - 1)
    Write-Host "lastChar: $lastChar"
    if ($lastChar -eq "\") { $script:intuneWinAppUtilPath = $intuneWinAppUtilPath.Substring(0, $intuneWinAppUtilPath.Length - 1) }
    Write-Host "script:intuneWinAppUtilPath: $script:intuneWinAppUtilPath"
    $IntuneWinAppUtil = "$intuneWinAppUtilPath\IntuneWinAppUtil.exe"
}

####################################################
# Bundled module precedence
####################################################
# Mirror Invoke-DelegatedImport.ps1: make a packaged copy of the critical
# Microsoft.Graph.Authentication module (shipped inside the script's
# 'Modules' folder) discoverable and take precedence over any installed
# copy, WITHOUT requiring the user to install it. The bundled folder is
# prepended to $env:PSModulePath so the bundled module wins over machine /
# user module locations.
#
# SECURITY: the critical Microsoft.Graph.Authentication module handles auth
# tokens, so the prepend is fail-closed — every *.psm1 under the bundled
# folder must be Authenticode-signed by a trusted publisher. A signature
# failure BLOCKS the prepend (a counterfeit module dropped into 'Modules'
# could exfiltrate Graph tokens) and the script falls back to the installed
# copy. Override the trusted-publisher allow-list with
# $env:INTUNEWIN_TRUSTED_PUBLISHERS (semicolon-separated subject substrings).
$graphModuleName = "Microsoft.Graph.Authentication"
$bundledModulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules'
if (Test-Path -LiteralPath $bundledModulesPath) {
    $trustedPublisherDefaults = @(
        'CN=Microsoft Corporation',
        'CN=Microsoft Code Signing',
        'CN=Microsoft 3rd Party Application Component',
        'CN=GitHub'
    )
    $trustedPublishers = if ($env:INTUNEWIN_TRUSTED_PUBLISHERS) {
        @($env:INTUNEWIN_TRUSTED_PUBLISHERS -split ';' | Where-Object { $_ })
    }
    else {
        $trustedPublisherDefaults
    }

    $bundledGraphPath = Join-Path -Path $bundledModulesPath -ChildPath $graphModuleName
    $bundledOk = $true
    $bundledReason = ''
    if (Test-Path -LiteralPath $bundledGraphPath) {
        try {
            $psm1Files = @(Get-ChildItem -LiteralPath $bundledGraphPath -Recurse -Filter '*.psm1' -ErrorAction Stop)
            if ($psm1Files.Count -eq 0) {
                $bundledOk = $false
                $bundledReason = "bundled module folder '$graphModuleName' contains no *.psm1 files"
            }
            else {
                foreach ($psm1 in $psm1Files) {
                    $sig = Get-AuthenticodeSignature -LiteralPath $psm1.FullName -ErrorAction Stop
                    if ($sig.Status -ne 'Valid') {
                        $bundledOk = $false
                        $bundledReason = "bundled module '$graphModuleName\$($psm1.Name)' has signature status '$($sig.Status)'"
                        break
                    }
                    $subject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' }
                    $matched = $false
                    foreach ($pub in $trustedPublishers) {
                        if ($subject -like "*$pub*") { $matched = $true; break }
                    }
                    if (-not $matched) {
                        $bundledOk = $false
                        $bundledReason = "bundled module '$graphModuleName\$($psm1.Name)' is signed by an untrusted publisher: $subject"
                        break
                    }
                }
            }
        }
        catch {
            $bundledOk = $false
            $bundledReason = "signature validation failed: $($_.Exception.Message)"
        }

        if ($bundledOk) {
            if (($env:PSModulePath -split [IO.Path]::PathSeparator) -notcontains $bundledModulesPath) {
                $env:PSModulePath = $bundledModulesPath + [IO.Path]::PathSeparator + $env:PSModulePath
                Write-Host "Bundled '$graphModuleName' module path prepended to PSModulePath: $bundledModulesPath" -ForegroundColor Green
            }
        }
        else {
            Write-Warning "Bundled modules path NOT trusted - $bundledReason. Skipping prepend of '$bundledModulesPath'; falling back to installed module."
        }
    }
}

####################################################
# Check for Microsoft.Graph.Authentication module
####################################################
$graphModule = Get-Module -Name $graphModuleName -ListAvailable -ErrorAction SilentlyContinue

if ($null -eq $graphModule) {
    # Module not installed - check if it exists in PSScriptRoot
    $localModulePath = Join-Path -Path $PSScriptRoot -ChildPath $graphModuleName

    if (Test-Path $localModulePath) {
        Write-Host "Microsoft.Graph.Authentication module not installed. Loading from script directory..." -ForegroundColor Yellow
        try {
            Import-Module $localModulePath -Force -ErrorAction Stop
            Write-Host "Microsoft.Graph.Authentication module loaded successfully from: $localModulePath" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to import Microsoft.Graph.Authentication module from script directory: $_" -ForegroundColor Red
            Write-Host "Please install the module using: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser" -ForegroundColor Yellow
            exit 1
        }
    }
    else {
        # Also check for module in a 'Modules' subfolder
        $modulesSubfolderPath = Join-Path -Path $PSScriptRoot -ChildPath "Modules\$graphModuleName"

        if (Test-Path $modulesSubfolderPath) {
            Write-Host "Microsoft.Graph.Authentication module not installed. Loading from Modules subfolder..." -ForegroundColor Yellow
            try {
                Import-Module $modulesSubfolderPath -Force -ErrorAction Stop
                Write-Host "Microsoft.Graph.Authentication module loaded successfully from: $modulesSubfolderPath" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to import Microsoft.Graph.Authentication module: $_" -ForegroundColor Red
                Write-Host "Please install the module using: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser" -ForegroundColor Yellow
                exit 1
            }
        }
        else {
            Write-Host "Microsoft.Graph.Authentication module not found." -ForegroundColor Red
            Write-Host "The module is not installed and was not found in:" -ForegroundColor Red
            Write-Host "  - $localModulePath" -ForegroundColor Red
            Write-Host "  - $modulesSubfolderPath" -ForegroundColor Red
            Write-Host "Please install the module using: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser" -ForegroundColor Yellow
            exit 1
        }
    }
}
else {
    # Module is installed - import it
    Import-Module $graphModuleName -ErrorAction SilentlyContinue
}

####################################################
####################################################
#Build Functions
####################################################

####################################################
# Embedded proxy support (standalone — no module dependency).
# Mirrors the public surface of the standalone proxy module:
# Initialize-IntuneWinProxy / Set-IntuneWinProxyConfiguration / Test-IntuneWinProxyEnabled /
# Get-IntuneWinProxyConfiguration / Add-IntuneWinProxyParameter / Test-IntuneWinGraphConnectivity /
# Invoke-IntuneWinProxyTest. State lives in $script:IntuneWinProxyState. Designed to run
# in both PowerShell 5.1 and 7+ and to degrade gracefully under Constrained
# Language Mode (per-call splat fallback when DefaultWebProxy cannot be set).
####################################################

$script:IntuneWinProxyState = @{
    Enabled                  = $false
    ProxyUri                 = $null     # [uri]
    ProxyAddress             = $null     # [string] absolute uri (cached for splats)
    ProxyCredential          = $null     # [PSCredential]
    UseDefaultCredentials    = $false
    BypassList               = @()       # [string[]]
    BypassOnLocal            = $true
    PreviousDefaultWebProxy  = $null
    PreviousHttpClientProxy  = $null
    HttpClientProxySupported = $false
    ConfiguredAt             = $null
    LanguageMode             = $ExecutionContext.SessionState.LanguageMode
    PreviousEnvHttpsProxy    = $null
    PreviousEnvHttpProxy     = $null
    PreviousEnvNoProxy       = $null
    EnvVarsSet               = $false
}

function Test-IntuneWinProxyEnabled {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return [bool]$script:IntuneWinProxyState.Enabled
}

function Get-IntuneWinProxyConfiguration {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()
    if (-not $script:IntuneWinProxyState.Enabled) { return $null }
    return [pscustomobject]@{
        Enabled                  = $script:IntuneWinProxyState.Enabled
        ProxyUri                 = $script:IntuneWinProxyState.ProxyUri
        ProxyAddress             = $script:IntuneWinProxyState.ProxyAddress
        ProxyCredential          = $script:IntuneWinProxyState.ProxyCredential
        UseDefaultCredentials    = $script:IntuneWinProxyState.UseDefaultCredentials
        BypassList               = @($script:IntuneWinProxyState.BypassList)
        BypassOnLocal            = $script:IntuneWinProxyState.BypassOnLocal
        HttpClientProxySupported = $script:IntuneWinProxyState.HttpClientProxySupported
        ConfiguredAt             = $script:IntuneWinProxyState.ConfiguredAt
    }
}

function Add-IntuneWinProxyParameter {
    <#
    .SYNOPSIS
        Mutate a splat hashtable in-place to add -Proxy / -ProxyCredential /
        -ProxyUseDefaultCredentials keys when IntuneWinProxy is enabled. No-op
        otherwise so call sites stay clean whether proxy is on or off.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$Parameters
    )
    if (-not $script:IntuneWinProxyState.Enabled) { return }

    $Parameters['Proxy'] = $script:IntuneWinProxyState.ProxyAddress
    if ($script:IntuneWinProxyState.UseDefaultCredentials) {
        $Parameters['ProxyUseDefaultCredentials'] = $true
        if ($Parameters.ContainsKey('ProxyCredential')) { $Parameters.Remove('ProxyCredential') | Out-Null }
    }
    elseif ($script:IntuneWinProxyState.ProxyCredential) {
        $Parameters['ProxyCredential'] = $script:IntuneWinProxyState.ProxyCredential
        if ($Parameters.ContainsKey('ProxyUseDefaultCredentials')) { $Parameters.Remove('ProxyUseDefaultCredentials') | Out-Null }
    }
}

function Set-IntuneWinProxyConfiguration {
    <#
    .SYNOPSIS
        Low-level setter: configure both .NET proxy stacks
        (System.Net.WebRequest.DefaultWebProxy + System.Net.Http.HttpClient.DefaultProxy
        on PS 7+) plus HTTPS_PROXY/HTTP_PROXY/NO_PROXY env vars so that
        downstream Invoke-RestMethod, Invoke-WebRequest, MSAL.NET, the
        Microsoft.Graph SDK, and any other System.Net.Http call inherit the
        same proxy without per-call splatting.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ExplicitCredential')]
    [OutputType([System.Net.WebProxy])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [uri]$ProxyUri,

        [Parameter(ParameterSetName = 'ExplicitCredential')]
        [PSCredential]$ProxyCredential,

        [Parameter(Mandatory = $true, ParameterSetName = 'DefaultCredentials')]
        [switch]$UseDefaultCredentials,

        [Parameter()]
        [string[]]$BypassList = @(),

        [Parameter()]
        [bool]$BypassOnLocal = $true
    )

    if (-not $ProxyUri.IsAbsoluteUri) {
        throw "IntuneWinProxy: ProxyUri must be an absolute URI (got '$ProxyUri')."
    }
    if ($ProxyUri.Scheme -notin @('http', 'https')) {
        throw "IntuneWinProxy: ProxyUri scheme must be 'http' or 'https' (got '$($ProxyUri.Scheme)')."
    }

    $cleanBypass = @()
    foreach ($entry in $BypassList) {
        if (-not [string]::IsNullOrWhiteSpace($entry)) { $cleanBypass += $entry.Trim() }
    }

    $proxyAddress = $ProxyUri.AbsoluteUri.TrimEnd('/')

    if (-not $PSCmdlet.ShouldProcess($proxyAddress, 'Set proxy configuration')) {
        return
    }

    $proxy = $null
    try {
        $proxy = New-Object System.Net.WebProxy -ArgumentList $ProxyUri.AbsoluteUri
    }
    catch {
        Write-Warning "IntuneWinProxy: cannot construct System.Net.WebProxy under language mode '$($ExecutionContext.SessionState.LanguageMode)' ($($_.Exception.Message)). Per-call proxy splatting via Add-IntuneWinProxyParameter will still work."
    }

    if ($proxy) {
        try { $proxy.BypassProxyOnLocal = [bool]$BypassOnLocal } catch { Write-Verbose "IntuneWinProxy: BypassProxyOnLocal could not be set ($($_.Exception.Message))." }
        foreach ($bp in $cleanBypass) {
            try { [void]$proxy.BypassArrayList.Add($bp) }
            catch { Write-Warning "IntuneWinProxy: failed to add bypass entry '$bp' - $($_.Exception.Message)" }
        }
        if ($UseDefaultCredentials) {
            try { $proxy.UseDefaultCredentials = $true } catch { Write-Verbose "IntuneWinProxy: UseDefaultCredentials assign failed ($($_.Exception.Message))." }
            try { $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials } catch { Write-Verbose "IntuneWinProxy: DefaultNetworkCredentials assign failed ($($_.Exception.Message))." }
        }
        elseif ($ProxyCredential) {
            try { $proxy.Credentials = $ProxyCredential.GetNetworkCredential() } catch { Write-Verbose "IntuneWinProxy: NetworkCredential conversion failed ($($_.Exception.Message))." }
        }
    }

    # Snapshot previous values so callers / cleanup can restore.
    $previousFrameworkProxy = $null
    try { $previousFrameworkProxy = [System.Net.WebRequest]::DefaultWebProxy } catch { $previousFrameworkProxy = $null }
    if ($proxy) {
        try { [System.Net.WebRequest]::DefaultWebProxy = $proxy }
        catch { Write-Warning "IntuneWinProxy: cannot assign [System.Net.WebRequest]::DefaultWebProxy under language mode '$($ExecutionContext.SessionState.LanguageMode)' ($($_.Exception.Message)). Per-call splat fallback in effect." }
    }

    $httpClientSupported = $false
    $previousHttpClientProxy = $null
    try {
        $httpClientType = [System.Net.Http.HttpClient]
        $defaultProxyProp = $httpClientType.GetProperty('DefaultProxy', [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
        if ($defaultProxyProp -and $defaultProxyProp.CanWrite) {
            $previousHttpClientProxy = $defaultProxyProp.GetValue($null)
            $defaultProxyProp.SetValue($null, $proxy)
            $httpClientSupported = $true
        }
    }
    catch {
        Write-Verbose "IntuneWinProxy: HttpClient.DefaultProxy is not assignable on this runtime - using WebRequest path only. ($($_.Exception.Message))"
    }

    # Microsoft.Graph.Authentication 2.x reads HTTPS_PROXY/HTTP_PROXY/NO_PROXY from
    # process environment (the .NET / curl / az CLI convention). Snapshot so a later
    # cleanup can restore the previous values.
    $previousEnvHttps = [System.Environment]::GetEnvironmentVariable('HTTPS_PROXY', 'Process')
    $previousEnvHttp = [System.Environment]::GetEnvironmentVariable('HTTP_PROXY', 'Process')
    $previousEnvNo = [System.Environment]::GetEnvironmentVariable('NO_PROXY', 'Process')
    $envVarsSet = $false
    try {
        [System.Environment]::SetEnvironmentVariable('HTTPS_PROXY', $proxyAddress, 'Process')
        [System.Environment]::SetEnvironmentVariable('HTTP_PROXY', $proxyAddress, 'Process')
        if ($cleanBypass.Count -gt 0) {
            $noProxyList = $cleanBypass | ForEach-Object {
                $entry = $_
                if ($entry.StartsWith('*.')) { $entry.Substring(2) } else { $entry }
            }
            [System.Environment]::SetEnvironmentVariable('NO_PROXY', ($noProxyList -join ','), 'Process')
        }
        else {
            [System.Environment]::SetEnvironmentVariable('NO_PROXY', $null, 'Process')
        }
        $envVarsSet = $true
    }
    catch {
        Write-Warning "IntuneWinProxy: failed to set HTTPS_PROXY/HTTP_PROXY/NO_PROXY environment variables ($($_.Exception.Message)). MSAL / Graph SDK may not pick up the proxy."
    }

    $script:IntuneWinProxyState.Enabled = $true
    $script:IntuneWinProxyState.ProxyUri = $ProxyUri
    $script:IntuneWinProxyState.ProxyAddress = $proxyAddress
    $script:IntuneWinProxyState.ProxyCredential = $ProxyCredential
    $script:IntuneWinProxyState.UseDefaultCredentials = [bool]$UseDefaultCredentials
    $script:IntuneWinProxyState.BypassList = $cleanBypass
    $script:IntuneWinProxyState.BypassOnLocal = [bool]$BypassOnLocal
    $script:IntuneWinProxyState.PreviousDefaultWebProxy = $previousFrameworkProxy
    $script:IntuneWinProxyState.PreviousHttpClientProxy = $previousHttpClientProxy
    $script:IntuneWinProxyState.HttpClientProxySupported = $httpClientSupported
    $script:IntuneWinProxyState.PreviousEnvHttpsProxy = $previousEnvHttps
    $script:IntuneWinProxyState.PreviousEnvHttpProxy = $previousEnvHttp
    $script:IntuneWinProxyState.PreviousEnvNoProxy = $previousEnvNo
    $script:IntuneWinProxyState.EnvVarsSet = $envVarsSet
    $script:IntuneWinProxyState.ConfiguredAt = Get-Date

    return $proxy
}

function Test-IntuneWinGraphConnectivity {
    <#
    .SYNOPSIS
        Read-only probe of outbound network connectivity to Microsoft Graph
        and Entra ID. TCP-connect each endpoint and (optionally) HTTPS HEAD.
        Honours whatever proxy is currently configured on the .NET stacks at
        invocation time.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Endpoint = @('graph.microsoft.com:443', 'login.microsoftonline.com:443'),

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$TimeoutSeconds = 5,

        [Parameter()]
        [switch]$IncludeHttpsProbe,

        [Parameter()]
        [ValidateRange(1, 120)]
        [int]$HttpsTimeoutSeconds = 15
    )

    $proxyAddress = $null
    $directMode = $true
    if ($script:IntuneWinProxyState.Enabled) {
        $proxyAddress = $script:IntuneWinProxyState.ProxyAddress
        $directMode = $false
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($pair in $Endpoint) {
        $hostName = $null
        $port = 443
        if ($pair -match '^(?<h>[^:/\s]+)(:(?<p>\d+))?$') {
            $hostName = $Matches['h']
            if ($Matches['p']) { $port = [int]$Matches['p'] }
        }
        else {
            $results.Add([pscustomobject]@{
                    Endpoint        = $pair
                    Host            = $pair
                    Port            = $null
                    TcpStatus       = 'FAIL'
                    TcpDurationMs   = 0
                    TcpDetail       = "Invalid endpoint format. Expected 'host:port' (got '$pair')."
                    HttpsStatus     = 'SKIP'
                    HttpsDetail     = 'Skipped (invalid endpoint)'
                    HttpsStatusCode = $null
                    HttpsDurationMs = 0
                })
            continue
        }

        # TCP probe — skipped in proxy mode (raw TCP cannot traverse HTTP CONNECT proxy).
        $tcpStatus = 'FAIL'
        $tcpDetail = $null
        $tcpDurationMs = 0
        if ($script:IntuneWinProxyState.Enabled) {
            $tcpStatus = 'SKIP'
            $tcpDetail = 'Skipped (raw TCP cannot traverse HTTP proxy - HTTPS probe is the meaningful test in proxy mode)'
        }
        else {
            $tcpStart = [DateTime]::UtcNow
            try {
                $client = $null
                try { $client = New-Object System.Net.Sockets.TcpClient } catch { $client = $null }
                if ($client) {
                    $iar = $client.BeginConnect($hostName, $port, $null, $null)
                    $reachable = $iar.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000, $false) -and $client.Connected
                    $client.Close()
                    if ($reachable) { $tcpStatus = 'OK'; $tcpDetail = 'Reachable' }
                    else { $tcpStatus = 'FAIL'; $tcpDetail = "Unreachable within $TimeoutSeconds s" }
                }
                else {
                    $previousProgress = $ProgressPreference
                    $ProgressPreference = 'SilentlyContinue'
                    try {
                        $tnc = Test-NetConnection -ComputerName $hostName -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                    }
                    finally { $ProgressPreference = $previousProgress }
                    if ($tnc) { $tcpStatus = 'OK'; $tcpDetail = 'Reachable (Test-NetConnection CLM fallback)' }
                    else { $tcpStatus = 'FAIL'; $tcpDetail = 'Unreachable (Test-NetConnection CLM fallback)' }
                }
            }
            catch {
                $tcpStatus = 'WARN'
                $tcpDetail = "Probe error: $($_.Exception.Message)"
            }
            $tcpDurationMs = [int]([DateTime]::UtcNow - $tcpStart).TotalMilliseconds
        }

        $httpsStatus = 'SKIP'
        $httpsDetail = 'Not requested'
        $httpsStatusCode = $null
        $httpsDurationMs = 0

        if ($IncludeHttpsProbe) {
            $httpsStart = [DateTime]::UtcNow
            $probeUri = "https://${hostName}:${port}/"
            try {
                $iwrParams = @{
                    Uri             = $probeUri
                    Method          = 'HEAD'
                    UseBasicParsing = $true
                    TimeoutSec      = $HttpsTimeoutSeconds
                    ErrorAction     = 'Stop'
                }
                Add-IntuneWinProxyParameter -Parameters $iwrParams
                $resp = Invoke-WebRequest @iwrParams
                $httpsStatus = 'OK'
                $httpsStatusCode = [int]$resp.StatusCode
                $httpsDetail = "HTTP $httpsStatusCode round-trip OK"
            }
            catch {
                $ex = $_.Exception
                $resp = $null
                try { $resp = $ex.Response } catch { $resp = $null }
                if ($resp) {
                    try { $httpsStatusCode = [int]$resp.StatusCode } catch { $httpsStatusCode = $null }
                    $httpsStatus = 'OK'
                    $httpsDetail = if ($httpsStatusCode) { "HTTP $httpsStatusCode (any response = network path works)" } else { 'Non-success HTTP response (network path works)' }
                }
                else {
                    $httpsStatus = 'FAIL'
                    $httpsDetail = "Transport error: $($ex.Message)"
                }
            }
            $httpsDurationMs = [int]([DateTime]::UtcNow - $httpsStart).TotalMilliseconds
        }

        $results.Add([pscustomobject]@{
                Endpoint        = $pair
                Host            = $hostName
                Port            = $port
                TcpStatus       = $tcpStatus
                TcpDurationMs   = $tcpDurationMs
                TcpDetail       = $tcpDetail
                HttpsStatus     = $httpsStatus
                HttpsStatusCode = $httpsStatusCode
                HttpsDurationMs = $httpsDurationMs
                HttpsDetail     = $httpsDetail
            })
    }

    $allOk = $true
    foreach ($r in $results) {
        if ($r.TcpStatus -ne 'OK' -and $r.TcpStatus -ne 'SKIP') { $allOk = $false; break }
        if ($IncludeHttpsProbe -and $r.HttpsStatus -ne 'OK' -and $r.HttpsStatus -ne 'SKIP') { $allOk = $false; break }
    }

    return [pscustomobject]@{
        Success      = $allOk
        DirectMode   = $directMode
        ProxyAddress = $proxyAddress
        Results      = $results.ToArray()
    }
}

function Initialize-IntuneWinProxy {
    <#
    .SYNOPSIS
        High-level entry to opt this script into proxy authentication.
        Resolves params (param -> env), optionally probes direct connectivity
        first (-OnlyIfNeeded), then calls Set-IntuneWinProxyConfiguration to apply
        both .NET stacks + HTTPS_PROXY/HTTP_PROXY/NO_PROXY env vars.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Prompt')]
    [OutputType([System.Net.WebProxy])]
    param(
        [Parameter()]
        [Alias('Proxy', 'HttpsProxy')]
        [uri]$ProxyUri,

        [Parameter(ParameterSetName = 'Prompt')]
        [PSCredential]$ProxyCredential,

        [Parameter(Mandatory = $true, ParameterSetName = 'DefaultCredentials')]
        [switch]$UseDefaultCredentials,

        [Parameter()]
        [string[]]$BypassList,

        [Parameter()]
        [Nullable[bool]]$BypassOnLocal,

        [Parameter()]
        [switch]$NonInteractive,

        [Parameter()]
        [string]$PromptMessage,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$OnlyIfNeeded,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$ProbeTimeoutSeconds = 5
    )

    # 1. Resolve effective ProxyUri (param -> env)
    $effectiveUri = $null
    if ($ProxyUri) {
        $effectiveUri = $ProxyUri
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:INTUNEWIN_PROXY_URI)) {
        try { $effectiveUri = [uri]$env:INTUNEWIN_PROXY_URI }
        catch { throw "IntuneWinProxy: `$env:INTUNEWIN_PROXY_URI is not a valid absolute URI ('$env:INTUNEWIN_PROXY_URI'): $($_.Exception.Message)" }
    }
    if (-not $effectiveUri) { return $null }

    # 2. Already configured? Skip unless -Force.
    if ((Test-IntuneWinProxyEnabled) -and -not $Force) {
        Write-Verbose "IntuneWinProxy: configuration already set for $($script:IntuneWinProxyState.ProxyAddress) - skipping (use -Force to reapply)."
        return $null
    }

    # 2b. Auto-fallback: probe direct connectivity first.
    if ($OnlyIfNeeded) {
        Write-Verbose 'IntuneWinProxy: -OnlyIfNeeded set; probing direct connectivity before configuring proxy.'
        try {
            $probe = Test-IntuneWinGraphConnectivity -TimeoutSeconds $ProbeTimeoutSeconds -IncludeHttpsProbe -ErrorAction Stop
        }
        catch {
            Write-Verbose "IntuneWinProxy: direct probe threw ($($_.Exception.Message)); proceeding with proxy configuration."
            $probe = [pscustomobject]@{ Success = $false }
        }
        if ($probe.Success) {
            Write-Verbose 'IntuneWinProxy: direct connectivity OK - skipping proxy configuration (auto-fallback).'
            return $null
        }
    }

    # 3. Resolve UseDefaultCredentials (param -> env).
    $effectiveUseDefault = [bool]$UseDefaultCredentials
    if (-not $effectiveUseDefault -and -not $ProxyCredential) {
        if ($env:INTUNEWIN_PROXY_USE_DEFAULT_CREDENTIALS) {
            $envValue = $env:INTUNEWIN_PROXY_USE_DEFAULT_CREDENTIALS.Trim().ToLowerInvariant()
            if ($envValue -in @('true', '1', 'yes', 'on')) { $effectiveUseDefault = $true }
        }
    }

    # 4. Resolve BypassList (param -> env).
    $effectiveBypass = @()
    if ($PSBoundParameters.ContainsKey('BypassList') -and $null -ne $BypassList) {
        $effectiveBypass = @($BypassList)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:INTUNEWIN_PROXY_BYPASS)) {
        $effectiveBypass = @($env:INTUNEWIN_PROXY_BYPASS -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    # 5. Resolve BypassOnLocal (param -> env -> default $true).
    $effectiveBypassLocal = $true
    if ($PSBoundParameters.ContainsKey('BypassOnLocal') -and $null -ne $BypassOnLocal) {
        $effectiveBypassLocal = [bool]$BypassOnLocal
    }
    elseif ($env:INTUNEWIN_PROXY_BYPASS_ON_LOCAL) {
        $envValue = $env:INTUNEWIN_PROXY_BYPASS_ON_LOCAL.Trim().ToLowerInvariant()
        if ($envValue -in @('false', '0', 'no', 'off')) { $effectiveBypassLocal = $false }
    }

    # 6. Detect non-interactive / CI context.
    $effectiveNonInteractive = [bool]$NonInteractive
    if (-not $effectiveNonInteractive) {
        if ($env:TF_BUILD -or $env:GITHUB_ACTIONS -or $env:CI -or $env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI) {
            $effectiveNonInteractive = $true
        }
    }

    # 7. Resolve credential (param -> prompt -> graceful fallback to default credentials).
    $effectiveCred = $ProxyCredential
    if (-not $effectiveUseDefault -and -not $effectiveCred) {
        if ($effectiveNonInteractive) {
            throw "IntuneWinProxy: a proxy credential is required for '$effectiveUri' but no -ProxyCredential was supplied and the session is non-interactive. Pass -ProxyUseDefaultCredentials or pre-build the credential."
        }
        $effectivePrompt = if ([string]::IsNullOrWhiteSpace($PromptMessage)) {
            "Enter the proxy credentials used to reach the Internet via $effectiveUri. Used for both the proxy server and the .NET default proxy credential for Graph / MSAL / Invoke-RestMethod / Azure Storage calls."
        }
        else { $PromptMessage }

        Write-Host ''
        Write-Host '  IntuneWinProxy: a credential is required for the proxy.' -ForegroundColor Yellow
        Write-Host '    A Windows credential dialog should appear (it can open BEHIND the active window) or, in some hosts, a console prompt below.' -ForegroundColor Yellow
        Write-Host '    TIP: pass -ProxyUseDefaultCredentials for Windows-integrated (NTLM/Negotiate) auth and skip the prompt entirely.' -ForegroundColor Yellow
        Write-Host ''

        try { $effectiveCred = Get-Credential -Message $effectivePrompt }
        catch {
            Write-Warning "IntuneWinProxy: Get-Credential threw in this host ($($_.Exception.Message)). Treating as no credential."
            $effectiveCred = $null
        }
        if (-not $effectiveCred) {
            $langMode = $ExecutionContext.SessionState.LanguageMode
            Write-Warning "IntuneWinProxy: no credential was returned for proxy '$($effectiveUri.AbsoluteUri)' (host language mode: '$langMode'). Falling back to Windows integrated auth (UseDefaultCredentials)."
            $effectiveUseDefault = $true
            $effectiveCred = $null
        }
    }

    if (-not $PSCmdlet.ShouldProcess($effectiveUri.AbsoluteUri, 'Initialize proxy configuration')) {
        return
    }

    $setArgs = @{
        ProxyUri      = $effectiveUri
        BypassList    = $effectiveBypass
        BypassOnLocal = $effectiveBypassLocal
    }
    if ($effectiveUseDefault) { $setArgs['UseDefaultCredentials'] = $true }
    elseif ($effectiveCred) { $setArgs['ProxyCredential'] = $effectiveCred }

    $proxy = Set-IntuneWinProxyConfiguration @setArgs

    Write-Verbose "IntuneWinProxy: configured for $($script:IntuneWinProxyState.ProxyAddress) | BypassOnLocal=$($script:IntuneWinProxyState.BypassOnLocal) | BypassList=[$($script:IntuneWinProxyState.BypassList -join ';')] | UseDefaultCredentials=$($script:IntuneWinProxyState.UseDefaultCredentials) | HttpClientProxySupported=$($script:IntuneWinProxyState.HttpClientProxySupported)"

    return $proxy
}

function Invoke-IntuneWinProxyTest {
    <#
    .SYNOPSIS
        Two-phase connectivity test (direct then proxy) for diagnostic reports.
        Returns a structured pscustomobject so callers can drive exit-code logic.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [Alias('Proxy', 'HttpsProxy')]
        [uri]$ProxyUri,

        [Parameter()]
        [PSCredential]$ProxyCredential,

        [Parameter()]
        [switch]$UseDefaultCredentials,

        [Parameter()]
        [string[]]$BypassList,

        [Parameter()]
        [Nullable[bool]]$BypassOnLocal,

        [Parameter()]
        [string[]]$Endpoint = @('graph.microsoft.com:443', 'login.microsoftonline.com:443'),

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$TimeoutSeconds = 5,

        [Parameter()]
        [ValidateRange(1, 120)]
        [int]$HttpsTimeoutSeconds = 15
    )

    Write-Host ''
    Write-Host '════════════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host '  Phase 1: Direct connectivity to Microsoft Graph / Entra ID' -ForegroundColor Cyan
    Write-Host '════════════════════════════════════════════════════════════════════' -ForegroundColor Cyan

    $directResult = Test-IntuneWinGraphConnectivity -Endpoint $Endpoint -TimeoutSeconds $TimeoutSeconds -IncludeHttpsProbe -HttpsTimeoutSeconds $HttpsTimeoutSeconds
    foreach ($r in $directResult.Results) {
        $color = if ($r.TcpStatus -eq 'OK' -and ($r.HttpsStatus -eq 'OK' -or $r.HttpsStatus -eq 'SKIP')) { 'Green' }
        elseif ($r.TcpStatus -eq 'SKIP' -and $r.HttpsStatus -eq 'OK') { 'Green' }
        else { 'Red' }
        Write-Host ("  {0,-40} TCP={1,-4} ({2}ms)  HTTPS={3,-4} ({4}ms)  {5}" -f $r.Endpoint, $r.TcpStatus, $r.TcpDurationMs, $r.HttpsStatus, $r.HttpsDurationMs, $r.HttpsDetail) -ForegroundColor $color
    }
    Write-Host ("  Verdict: {0}" -f $(if ($directResult.Success) { 'PASS' } else { 'FAIL' })) -ForegroundColor $(if ($directResult.Success) { 'Green' } else { 'Yellow' })

    $proxyResult = $null
    $effectiveProxyUri = $null
    if ($ProxyUri) { $effectiveProxyUri = $ProxyUri }
    elseif (-not [string]::IsNullOrWhiteSpace($env:INTUNEWIN_PROXY_URI)) {
        try { $effectiveProxyUri = [uri]$env:INTUNEWIN_PROXY_URI } catch { $effectiveProxyUri = $null }
    }

    if ($effectiveProxyUri) {
        Write-Host ''
        Write-Host '════════════════════════════════════════════════════════════════════' -ForegroundColor Cyan
        Write-Host "  Phase 2: Proxy connectivity via $effectiveProxyUri" -ForegroundColor Cyan
        Write-Host '════════════════════════════════════════════════════════════════════' -ForegroundColor Cyan
        try {
            $initArgs = @{ ProxyUri = $effectiveProxyUri; Force = $true }
            if ($ProxyCredential) { $initArgs['ProxyCredential'] = $ProxyCredential }
            if ($UseDefaultCredentials) { $initArgs['UseDefaultCredentials'] = $true }
            if ($PSBoundParameters.ContainsKey('BypassList')) { $initArgs['BypassList'] = $BypassList }
            if ($PSBoundParameters.ContainsKey('BypassOnLocal')) { $initArgs['BypassOnLocal'] = $BypassOnLocal }
            Initialize-IntuneWinProxy @initArgs | Out-Null

            $proxyResult = Test-IntuneWinGraphConnectivity -Endpoint $Endpoint -TimeoutSeconds $TimeoutSeconds -IncludeHttpsProbe -HttpsTimeoutSeconds $HttpsTimeoutSeconds
            foreach ($r in $proxyResult.Results) {
                $color = if (($r.TcpStatus -eq 'OK' -or $r.TcpStatus -eq 'SKIP') -and ($r.HttpsStatus -eq 'OK' -or $r.HttpsStatus -eq 'SKIP')) { 'Green' } else { 'Red' }
                Write-Host ("  {0,-40} TCP={1,-4} ({2}ms)  HTTPS={3,-4} ({4}ms)  {5}" -f $r.Endpoint, $r.TcpStatus, $r.TcpDurationMs, $r.HttpsStatus, $r.HttpsDurationMs, $r.HttpsDetail) -ForegroundColor $color
            }
            Write-Host ("  Verdict: {0}" -f $(if ($proxyResult.Success) { 'PASS' } else { 'FAIL' })) -ForegroundColor $(if ($proxyResult.Success) { 'Green' } else { 'Red' })
        }
        catch {
            Write-Host "  Proxy probe failed during init: $($_.Exception.Message)" -ForegroundColor Red
            $proxyResult = [pscustomobject]@{ Success = $false; Results = @() }
        }
    }
    else {
        Write-Host ''
        Write-Host '  Phase 2 skipped: no -ProxyUri and no $env:INTUNEWIN_PROXY_URI set.' -ForegroundColor DarkGray
    }

    $overallSuccess = if ($effectiveProxyUri) { [bool]($proxyResult -and $proxyResult.Success) } else { [bool]$directResult.Success }
    return [pscustomobject]@{
        Success      = $overallSuccess
        DirectResult = $directResult
        ProxyResult  = $proxyResult
        ProxyUri     = $effectiveProxyUri
    }
}

####################################################

function Start-Log {
    param (
        [string]$FilePath,

        [Parameter(HelpMessage = 'Deletes existing file if used with the -DeleteExistingFile switch')]
        [switch]$DeleteExistingFile
    )

    #Create Event Log source if it's not already found...
    if (!([system.diagnostics.eventlog]::SourceExists($EventLogSource))) { New-EventLog -LogName $EventLogName -Source $EventLogSource }

    try {
        # Ensure the parent (Logs) directory exists before touching the file. New-Item -Force
        # would create it implicitly, but creating it explicitly guarantees the Logs folder is
        # present even if the file itself is later removed via -DeleteExistingFile, and surfaces
        # any permission/path errors clearly at startup instead of on the first Write-Log.
        $logDirectory = Split-Path -Path $FilePath -Parent
        if (-not [string]::IsNullOrWhiteSpace($logDirectory) -and -not (Test-Path -LiteralPath $logDirectory)) {
            New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
        }

        if (!(Test-Path $FilePath)) {
            ## Create the log file
            New-Item $FilePath -Type File -Force | Out-Null
        }

        if ($DeleteExistingFile) {
            Remove-Item $FilePath -Force
        }

        ## Set the global variable to be used as the FilePath for all subsequent Write-Log
        ## calls in this session
        $script:ScriptLogFilePath = $FilePath
    }
    catch {
        Write-Error $_.Exception.Message
    }
}

####################################################

function Remove-OldLogFiles {
    <#
    .SYNOPSIS
        Retains only the N most recent log files in a directory and deletes older ones.
    .DESCRIPTION
        Mirrors the log-rotation pattern used by Invoke-DelegatedImport.ps1 so the
        Logs subfolder does not grow without bound. Matching is scoped by a prefix
        (e.g. the script name) so unrelated files are never touched.
    #>
    [CmdletBinding()]
    param(
        [string]$LogDirectory,
        [string]$LogPrefix,
        [int]$KeepCount = 10
    )

    if ([string]::IsNullOrWhiteSpace($LogDirectory) -or -not (Test-Path -LiteralPath $LogDirectory)) { return }

    $logFiles = @(Get-ChildItem -Path $LogDirectory -Filter "${LogPrefix}_*.log" -File -ErrorAction SilentlyContinue |
        Sort-Object -Property LastWriteTime -Descending)

    if ($logFiles.Count -gt $KeepCount) {
        $toDelete = $logFiles | Select-Object -Skip $KeepCount
        foreach ($file in $toDelete) {
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

####################################################

function Write-Log {
    #Write-Log -Message 'warning' -LogLevel 2
    #Write-Log -Message 'Error' -LogLevel 3
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1,

        [Parameter(HelpMessage = 'Outputs message to Event Log,when used with -WriteEventLog')]
        [switch]$WriteEventLog,

        [Parameter()]
        [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')]
        [string] $WriteHost = 'White'
    )

    if ($WriteHost) {
        Write-Host
        Write-Host $Message -ForegroundColor $WriteHost
        Write-Host
    }

    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat
    #Add-Content -Value $Line -Path $ScriptLogFilePath
    # Remove above 3 lines with $stream and uncomment line below if you want to use Out-File instead of StreamWriter as log write metod
    # Out-File -InputObject $Line -FilePath $ScriptLogFilePath -Encoding UTF8 -Append

    $stream = [System.IO.StreamWriter]::new($ScriptLogFilePath, $true, ([System.Text.Utf8Encoding]::new()))
    $stream.WriteLine("$Line")
    $stream.close()

    if ($WriteEventLog) { Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message $Message  -Id 100 -Category 0 -EntryType Information }
}

####################################################

function Test-Null($objectToCheck) {
    if ($null -eq $objectToCheck) {
        return $true
    }

    if ($objectToCheck -is [String] -and $objectToCheck -eq [String]::Empty) {
        return $true
    }

    if ($objectToCheck -is [DBNull] -or $objectToCheck -is [System.Management.Automation.Language.NullString]) {
        return $true
    }

    return $false
}

####################################################

function Invoke-GraphRequestWithRetry {
    <#
.SYNOPSIS
Invokes a Microsoft Graph API request with automatic retry logic for transient failures.
.DESCRIPTION
This function wraps Invoke-MgGraphRequest with retry logic to handle transient errors
such as throttling (429), server errors (5xx), and network issues.
.PARAMETER Method
The HTTP method to use (GET, POST, PATCH, DELETE, PUT)
.PARAMETER Uri
The Graph API URI to call
.PARAMETER Body
Optional body for POST/PATCH/PUT requests
.PARAMETER ContentType
Content type for the request (default: application/json)
.PARAMETER MaxRetries
Maximum number of retry attempts (default: 3)
.PARAMETER InitialDelaySeconds
Initial delay between retries in seconds (default: 2)
.EXAMPLE
Invoke-GraphRequestWithRetry -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
.NOTES
NAME: Invoke-GraphRequestWithRetry
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE', 'PUT')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [object]$Body,

        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [int]$InitialDelaySeconds = 2
    )

    # -WhatIf short-circuit: skip any mutating request when WhatIf is active.
    if ($Method -in @('POST', 'PATCH', 'PUT', 'DELETE') -and $WhatIfPreference) {
        Write-Log -Message "WhatIf: would $Method $Uri (skipped)"
        Write-Host "WhatIf: would $Method $Uri" -ForegroundColor Cyan
        return $null
    }

    $retryCount = 0
    $delay = $InitialDelaySeconds

    while ($true) {
        try {
            $params = @{
                Method = $Method
                Uri    = $Uri
            }

            if ($Body) {
                if ($Body -is [string]) {
                    $params['Body'] = $Body
                }
                else {
                    $params['Body'] = $Body | ConvertTo-Json -Depth 10
                }
                $params['ContentType'] = $ContentType
            }

            $result = Invoke-MgGraphRequest @params
            return $result
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            # Determine if error is retryable
            $isRetryable = $false
            $retryAfter = $delay

            if ($statusCode -eq 429) {
                # Throttling - check Retry-After header
                $isRetryable = $true
                $retryHeader = $_.Exception.Response.Headers | Where-Object { $_.Key -eq 'Retry-After' }
                if ($retryHeader) {
                    $retryAfter = [int]$retryHeader.Value[0]
                }
                Write-Log -Message "Request throttled (429). Waiting $retryAfter seconds..." -LogLevel 2
            }
            elseif ($statusCode -eq 412) {
                # Precondition failed — content version state conflict, retry after delay
                $isRetryable = $true
                $retryAfter = 10
                Write-Log -Message "Precondition failed (412) — content version state conflict. Waiting $retryAfter seconds..." -LogLevel 2
            }
            elseif ($statusCode -eq 401) {
                # Token expired or revoked — attempt silent re-authentication
                $isRetryable = $true
                $retryAfter = 5
                Write-Log -Message "Token expired (401). Attempting to refresh Graph session..." -LogLevel 2
                try {
                    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                    Start-Sleep -Seconds 2
                    # Reconnect using the same parameters that were used for the original connection
                    if ($script:MgGraphConnectParams) {
                        Invoke-MgGraphConnect -ConnectParams $script:MgGraphConnectParams
                    }
                    else {
                        Connect-MgGraph -NoWelcome -ErrorAction Stop
                    }
                    Write-Log -Message "Graph session refreshed successfully."
                }
                catch {
                    Write-Log -Message "Graph session refresh failed: $($_.Exception.Message)" -LogLevel 3
                }
            }
            elseif ($statusCode -ge 500 -and $statusCode -lt 600) {
                # Server error - retry with exponential backoff
                $isRetryable = $true
                Write-Log -Message "Server error ($statusCode). Retrying in $delay seconds..." -LogLevel 2
            }
            elseif ($_.Exception.Message -match 'network|timeout|connection|forcibly closed|Error while copying content to a stream|ResponseEnded|response ended prematurely|ended prematurely|request was canceled|send the request') {
                # Network/transport error - retry
                $isRetryable = $true
                Write-Log -Message "Network/transport error. Retrying in $delay seconds..." -LogLevel 2
            }

            if ($isRetryable -and $retryCount -lt $MaxRetries) {
                $retryCount++
                Write-Log -Message "Retry attempt $retryCount of $MaxRetries for: $Uri"
                Start-Sleep -Seconds $retryAfter
                $delay = $delay * 2  # Exponential backoff
            }
            else {
                # Not retryable or max retries exceeded
                if ($retryCount -ge $MaxRetries) {
                    Write-Log -Message "Max retries ($MaxRetries) exceeded for: $Uri" -LogLevel 3
                }
                throw
            }
        }
    }
}

####################################################

function Test-ConfigurationValidity {
    <#
.SYNOPSIS
Validates configuration parameters before processing
.DESCRIPTION
This function validates all required configuration parameters and returns
a validation result object with success status and any error messages.
.PARAMETER Config
A hashtable containing configuration parameters to validate
.PARAMETER AppType
The type of application (MSI, EXE, PS1, Edge)
.EXAMPLE
$result = Test-ConfigurationValidity -Config @{DisplayName = "Test"; AppType = "MSI"} -AppType "MSI"
.NOTES
NAME: Test-ConfigurationValidity
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory = $false)]
        [string]$AppType,

        [Parameter(Mandatory = $false)]
        [string]$PackagePath,

        [Parameter(Mandatory = $false)]
        [string[]]$RequiredAADGroupName,

        [Parameter(Mandatory = $false)]
        [string[]]$AvailableAADGroupName,

        [Parameter(Mandatory = $false)]
        [string[]]$UninstallAADGroupName
    )

    $errors = [System.Collections.ArrayList]::new()
    $warnings = [System.Collections.ArrayList]::new()

    # Validate AppType
    $validAppTypes = @('MSI', 'EXE', 'PS1', 'Edge')
    if ($AppType -and $AppType -notin $validAppTypes) {
        [void]$errors.Add("Invalid AppType '$AppType'. Valid types are: $($validAppTypes -join ', ')")
    }

    # Validate PackagePath
    if ($PackagePath -and -not (Test-Path $PackagePath)) {
        [void]$errors.Add("Package path does not exist: $PackagePath")
    }

    # Validate group name uniqueness - no group name should appear in more than one intent
    $requiredNames = @($RequiredAADGroupName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $availableNames = @($AvailableAADGroupName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $uninstallNames = @($UninstallAADGroupName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $allNames = @($requiredNames) + @($availableNames) + @($uninstallNames)
    $uniqueNames = $allNames | Select-Object -Unique
    if ($allNames.Count -ne $uniqueNames.Count) {
        [void]$errors.Add("Group names must be unique across assignment intents. The same group cannot appear in RequiredAADGroupName, AvailableAADGroupName, and UninstallAADGroupName.")
    }

    # Check for config file if PackagePath is specified
    if ($PackagePath -and (Test-Path $PackagePath)) {
        $hasConfig = (Test-Path "$PackagePath\Config.json") -or (Test-Path "$PackagePath\Config.xml")
        if (-not $hasConfig) {
            [void]$errors.Add("No Config.json or Config.xml found in package path: $PackagePath")
        }
    }

    return [PSCustomObject]@{
        IsValid  = ($errors.Count -eq 0)
        Errors   = $errors.ToArray()
        Warnings = $warnings.ToArray()
    }
}

####################################################

function Test-IntuneWinAppUtil {
    <#
.SYNOPSIS
Validates and updates IntuneWinAppUtil.exe from GitHub
.DESCRIPTION
This function checks if IntuneWinAppUtil.exe exists locally. If not, it downloads
the tool from GitHub. If it exists, it compares the local version with the GitHub
version and downloads a newer version if available.
.PARAMETER ToolPath
The full path where IntuneWinAppUtil.exe should be located
.EXAMPLE
Test-IntuneWinAppUtil -ToolPath "C:\Tools\IntuneWinAppUtil.exe"
.NOTES
NAME: Test-IntuneWinAppUtil
#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolPath
    )

    $downloadUrl = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe"
    $githubApiUrl = "https://api.github.com/repos/microsoft/Microsoft-Win32-Content-Prep-Tool/commits?path=IntuneWinAppUtil.exe&per_page=1"

    try {
        # Check if the tool exists locally
        if (Test-Path $ToolPath) {
            Write-Host "IntuneWinAppUtil.exe found at: $ToolPath" -ForegroundColor Green

            # Get local file info
            $localFile = Get-Item $ToolPath
            $localLastWriteTime = $localFile.LastWriteTimeUtc
            $localVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ToolPath)
            Write-Host "  Local version: $($localVersion.FileVersion)" -ForegroundColor Cyan
            Write-Host "  Local file date: $($localLastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC" -ForegroundColor Cyan

            # Check GitHub for the latest commit date on the file
            Write-Host "Checking GitHub for updates..." -ForegroundColor Yellow
            try {
                # Set TLS 1.2 for GitHub API
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                $headers = @{
                    "User-Agent" = "PowerShell-IntuneWinAppUtil-Updater"
                    "Accept"     = "application/vnd.github.v3+json"
                }

                $irmParams = @{
                    Uri         = $githubApiUrl
                    Headers     = $headers
                    Method      = 'Get'
                    ErrorAction = 'Stop'
                }
                Add-IntuneWinProxyParameter -Parameters $irmParams
                $response = Invoke-RestMethod @irmParams

                if ($response -and $response.Count -gt 0) {
                    # GitHub returns ISO 8601 dates (e.g. 2025-08-13T21:16:57Z). Invoke-RestMethod may
                    # already have deserialized this into a [DateTime]; if it is still a string, parse it
                    # using InvariantCulture so a non-US host locale (e.g. en-GB) does not misread the
                    # month/day order and throw "String was not recognized as a valid DateTime".
                    $rawCommitDate = $response[0].commit.committer.date
                    if ($rawCommitDate -is [DateTime]) {
                        $githubCommitDate = $rawCommitDate.ToUniversalTime()
                    }
                    else {
                        $githubCommitDate = [DateTime]::Parse(
                            [string]$rawCommitDate,
                            [System.Globalization.CultureInfo]::InvariantCulture,
                            [System.Globalization.DateTimeStyles]::RoundtripKind
                        ).ToUniversalTime()
                    }
                    Write-Host "  GitHub last commit date: $($githubCommitDate.ToString('yyyy-MM-dd HH:mm:ss')) UTC" -ForegroundColor Cyan

                    # Compare dates - if GitHub version is newer (commit date is after local file date)
                    if ($githubCommitDate -gt $localLastWriteTime.AddMinutes(5)) {
                        Write-Host "A newer version is available on GitHub. Downloading update..." -ForegroundColor Yellow

                        # Download the new version
                        $tempPath = Join-Path $env:TEMP "IntuneWinAppUtil_new.exe"
                        $dlParams = @{
                            Uri             = $downloadUrl
                            OutFile         = $tempPath
                            UseBasicParsing = $true
                        }
                        Add-IntuneWinProxyParameter -Parameters $dlParams
                        Invoke-WebRequest @dlParams

                        # Verify download
                        if (Test-Path $tempPath) {
                            $newVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($tempPath)
                            Write-Host "  Downloaded version: $($newVersion.FileVersion)" -ForegroundColor Cyan

                            # Replace the old file
                            Remove-Item $ToolPath -Force
                            Move-Item $tempPath $ToolPath -Force
                            Write-Host "IntuneWinAppUtil.exe has been updated successfully!" -ForegroundColor Green
                        }
                        else {
                            Write-Host "Failed to download the update. Continuing with existing version." -ForegroundColor Yellow
                        }
                    }
                    else {
                        Write-Host "Local version is up to date. No update required." -ForegroundColor Green
                    }
                }
                else {
                    Write-Host "Could not retrieve GitHub commit information. Using existing local version." -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "Unable to check for updates from GitHub: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "Continuing with existing local version." -ForegroundColor Yellow
            }
        }
        else {
            # Tool doesn't exist - download it
            Write-Host "IntuneWinAppUtil.exe not found at: $ToolPath" -ForegroundColor Yellow
            Write-Host "Downloading from GitHub..." -ForegroundColor Yellow

            # Set TLS 1.2 for GitHub
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            # Ensure the directory exists
            $toolDirectory = Split-Path $ToolPath -Parent
            if (!(Test-Path $toolDirectory)) {
                New-Item -Path $toolDirectory -ItemType Directory -Force | Out-Null
            }

            # Download the tool
            $dlParams = @{
                Uri             = $downloadUrl
                OutFile         = $ToolPath
                UseBasicParsing = $true
            }
            Add-IntuneWinProxyParameter -Parameters $dlParams
            Invoke-WebRequest @dlParams

            if (Test-Path $ToolPath) {
                $downloadedVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ToolPath)
                Write-Host "IntuneWinAppUtil.exe downloaded successfully!" -ForegroundColor Green
                Write-Host "  Version: $($downloadedVersion.FileVersion)" -ForegroundColor Cyan
            }
            else {
                throw "Failed to download IntuneWinAppUtil.exe from GitHub"
            }
        }

        # Final verification that the tool exists
        if (!(Test-Path $ToolPath)) {
            throw "IntuneWinAppUtil.exe is not available at: $ToolPath"
        }

        return $true
    }
    catch {
        Write-Host "Error validating IntuneWinAppUtil.exe: $($_.Exception.Message)" -ForegroundColor Red
        throw $_
    }
}

####################################################

function Get-AuthenticatedUserInfo {
    <#
.SYNOPSIS
Retrieves the authenticated user's display name and UPN from Microsoft Graph
.DESCRIPTION
This function gets the currently authenticated user's first name, last name, and UPN
for adding to the description field. Returns $null if using app registration authentication.
.EXAMPLE
$userInfo = Get-AuthenticatedUserInfo
.NOTES
NAME: Get-AuthenticatedUserInfo
#>

    [cmdletbinding()]
    param()

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        try {
            # Check if we're authenticated via interactive login (not app registration)
            $context = Get-MgContext
            if ($null -eq $context) {
                Write-Log -Message "No MgContext found - skipping user info retrieval"
                return $null
            }

            # Check authentication type - only proceed for delegated (user) authentication
            if ($context.AuthType -ne 'Delegated') {
                Write-Log -Message "Using app registration authentication - skipping user info retrieval"
                return $null
            }

            # Get the signed-in user's info from Graph
            $uri = "https://graph.microsoft.com/v1.0/me?`$select=displayName,givenName,surname,userPrincipalName"
            $userResponse = Invoke-MgGraphRequest -Uri $uri -Method Get

            if ($null -ne $userResponse) {
                $firstName = $userResponse.givenName
                $lastName = $userResponse.surname
                $upn = $userResponse.userPrincipalName
                $displayName = $userResponse.displayName

                # Build the user string - prefer first/last name, fall back to displayName
                if (-not [string]::IsNullOrWhiteSpace($firstName) -and -not [string]::IsNullOrWhiteSpace($lastName)) {
                    $userString = "$firstName $lastName ($upn)"
                }
                elseif (-not [string]::IsNullOrWhiteSpace($displayName)) {
                    $userString = "$displayName ($upn)"
                }
                else {
                    $userString = $upn
                }

                Write-Log -Message "Retrieved authenticated user info: $userString"
                return $userString
            }
        }
        catch {
            Write-Log -Message "Warning: Could not retrieve authenticated user info - $_" -LogLevel 2
            return $null
        }

        return $null
    }
}

####################################################

function Get-IntuneAppCategory {
    <#
.SYNOPSIS
Retrieves an Intune app category by name
.DESCRIPTION
This function gets an app category from Intune by display name.
Returns the category object if found, $null otherwise.
.EXAMPLE
$category = Get-IntuneAppCategory -CategoryName "Business"
.NOTES
NAME: Get-IntuneAppCategory
#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CategoryName
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "Looking for app category: [$CategoryName]"

        $graphApiVersion = "beta"
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileAppCategories"

        try {
            $result = Invoke-MgGraphRequest -Method Get -Uri $uri

            if ($result.value.Count -gt 0) {
                $category = $result.value | Where-Object { $_.displayName -eq $CategoryName }
                if ($null -ne $category) {
                    Write-Log -Message "Found category: $($category.displayName) (ID: $($category.id))"
                    return $category
                }
            }

            Write-Log -Message "Category '$CategoryName' not found" -LogLevel 2
            return $null
        }
        catch {
            Write-Log -Message "Error retrieving app categories: $_" -LogLevel 3
            return $null
        }
    }
}

####################################################

function Set-IntuneAppCategory {
    <#
.SYNOPSIS
Assigns a category to an Intune application
.DESCRIPTION
This function assigns a category to an existing Intune app using the Graph API.
.EXAMPLE
Set-IntuneAppCategory -ApplicationId "12345" -CategoryName "Business"
.NOTES
NAME: Set-IntuneAppCategory
#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
        [string]$CategoryName
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "Assigning category '$CategoryName' to application ID: $ApplicationId"

        # Get the category
        $category = Get-IntuneAppCategory -CategoryName $CategoryName
        if ($null -eq $category) {
            Write-Log -Message "Cannot assign category - category '$CategoryName' not found" -LogLevel 2
            Write-Host "Warning: Category '$CategoryName' not found in Intune" -ForegroundColor Yellow
            return $false
        }

        $graphApiVersion = "beta"
        $categoryUri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps/$ApplicationId/categories/`$ref"

        try {
            $categoryBody = @{
                "@odata.id" = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileAppCategories/$($category.id)"
            }

            $null = Invoke-MgGraphRequest -Uri $categoryUri -Method Post -Body $categoryBody

            Write-Log -Message "Category '$CategoryName' assigned successfully"
            Write-Host "Category '$CategoryName' assigned successfully" -ForegroundColor Green
            return $true
        }
        catch {
            # Check if error is because category is already assigned (409 Conflict or "already exists")
            if ($_.Exception.Message -match "already exists" -or $_.Exception.Message -match "409" -or $_.Exception.Message -match "Conflict") {
                Write-Log -Message "Category '$CategoryName' is already assigned to this application"
                Write-Host "Category '$CategoryName' is already assigned" -ForegroundColor Green
                return $true
            }
            Write-Log -Message "Error assigning category: $_" -LogLevel 2
            Write-Host "Warning: Failed to assign category - $_" -ForegroundColor Yellow
            return $false
        }
    }
}

####################################################

function ConvertTo-AppRelationshipEntry {
    <#
.SYNOPSIS
Normalises dependency/supersedence config into explicit app name + relationship type pairs
.DESCRIPTION
Flattens every supported config style into one object per referenced app, so each app can carry
its own relationship type instead of sharing a single type across the whole list:

  1. Repeated element pairs - repeat the element and its type element; the two lists are matched
     by position:
         <Dependencies>App 1.0</Dependencies><DependencyType>autoInstall</DependencyType>
         <Dependencies>App 2.0</Dependencies><DependencyType>detect</DependencyType>
  2. Inline 'Name:Type' - a per-app type suffix on any entry, using the same convention as
     CustomReturnCodes:
         <Dependencies>App 1.0:autoInstall,App 2.0:detect</Dependencies>
  3. Shared type - a plain list governed by a single type element (original behaviour):
         <Dependencies>App 1.0,App 2.0</Dependencies><DependencyType>autoInstall</DependencyType>

JSON supports all of the above plus an array of objects:
    "dependencies": [ { "name": "App 1.0", "type": "autoInstall" }, { "name": "App 2.0", "type": "detect" } ]

An inline or per-object type always wins over the positional/shared type.
.PARAMETER Value
The Dependencies/Supersedence config value - a string, an array of strings, or an array of objects
.PARAMETER TypeValue
The DependencyType/SupersedenceType config value - a string or an array of strings
.PARAMETER ValidType
The permitted relationship types, e.g. 'detect','autoInstall'
.PARAMETER DefaultType
The type used when none is supplied, or when the supplied one is not valid
.PARAMETER Label
Noun used in warning messages, e.g. 'dependency'
.EXAMPLE
ConvertTo-AppRelationshipEntry -Value 'App 1.0:detect,App 2.0' -TypeValue 'autoInstall' -ValidType 'detect','autoInstall' -DefaultType 'autoInstall' -Label 'dependency'
.NOTES
NAME: ConvertTo-AppRelationshipEntry
#>

    [cmdletbinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [object]$Value,

        [Parameter(Mandatory = $false)]
        [object]$TypeValue,

        [Parameter(Mandatory = $true)]
        [string[]]$ValidType,

        [Parameter(Mandatory = $true)]
        [string]$DefaultType,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    process {
        $groups = @($Value | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($groups.Count -eq 0) { return }

        $types = @($TypeValue | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })

        if ($types.Count -gt 1 -and $types.Count -ne $groups.Count) {
            Write-Log -Message "Config declares $($groups.Count) $Label element(s) but $($types.Count) type element(s) - matching by position, extras ignored" -LogLevel 2
            Write-Host "  Warning: $($groups.Count) $Label element(s) but $($types.Count) type element(s) - matching by position" -ForegroundColor Yellow
        }

        $parsed = @()
        for ($i = 0; $i -lt $groups.Count; $i++) {
            $group = $groups[$i]

            $groupType = if ($i -lt $types.Count) { $types[$i] }
            elseif ($types.Count -ge 1) { $types[0] }
            else { $DefaultType }

            # JSON object form: { "name": "...", "type": "..." }
            if ($group -isnot [string] -and $group.PSObject.Properties['name']) {
                $objType = if ($group.PSObject.Properties['type'] -and -not [string]::IsNullOrWhiteSpace([string]$group.type)) { [string]$group.type } else { $groupType }
                $parsed += [pscustomobject]@{ Name = ([string]$group.name).Trim(); Type = $objType.Trim() }
                continue
            }

            foreach ($token in ([string]$group -split ',')) {
                $token = $token.Trim()
                if (-not $token) { continue }

                $name = $token
                $type = $groupType

                # Only treat a trailing ':suffix' as a type when it really is one, so app names containing ':' survive
                $sep = $token.LastIndexOf(':')
                if ($sep -gt 0) {
                    $suffix = $token.Substring($sep + 1).Trim()
                    if ($ValidType -contains $suffix) {
                        $name = $token.Substring(0, $sep).Trim()
                        $type = $suffix
                    }
                }

                if ($name) { $parsed += [pscustomobject]@{ Name = $name; Type = $type } }
            }
        }

        foreach ($entry in $parsed) {
            # Graph rejects a mis-cased dependencyType/supersedenceType, so emit the canonical spelling
            $canonical = $ValidType | Where-Object { $_ -eq $entry.Type } | Select-Object -First 1
            if (-not $canonical) {
                Write-Log -Message "Invalid $Label type '$($entry.Type)' for '$($entry.Name)' - using '$DefaultType'" -LogLevel 2
                Write-Host "  Warning: invalid $Label type '$($entry.Type)' for '$($entry.Name)' - using '$DefaultType'" -ForegroundColor Yellow
                $canonical = $DefaultType
            }
            [pscustomobject]@{ Name = $entry.Name; Type = $canonical }
        }
    }
}

####################################################

function Enable-SystemProxyDefaultCredential {
    <#
.SYNOPSIS
Attaches the logged-on user's Windows credentials to the system default web proxy
.DESCRIPTION
Corporate proxies that require Windows-integrated (NTLM/Negotiate) authentication return HTTP 407
to .NET clients, because the default proxy object is created without credentials. This attaches
DefaultNetworkCredentials to the process-wide default proxy so subsequent calls authenticate.

Only relevant when the run was not started with an explicit -ProxyUri; returns $false when there
is no system proxy in play for the probe destination, so the caller can report the real problem.
.PARAMETER ProbeUri
Destination used to decide whether a proxy is actually in the path. Defaults to the Entra ID
token endpoint.
.EXAMPLE
if (Enable-SystemProxyDefaultCredential) { <retry the request> }
.NOTES
NAME: Enable-SystemProxyDefaultCredential
#>

    [cmdletbinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [uri]$ProbeUri = 'https://login.microsoftonline.com'
    )

    process {
        try {
            $proxy = [System.Net.WebRequest]::DefaultWebProxy
            if ($null -eq $proxy) { return $false }

            $resolved = $proxy.GetProxy($ProbeUri)
            if ($null -eq $resolved -or $resolved.AbsoluteUri -eq $ProbeUri.AbsoluteUri) {
                return $false
            }

            $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            Write-Log -Message "Attached default network credentials to system proxy $($resolved.AbsoluteUri)"
        }
        catch {
            Write-Log -Message "Could not attach default credentials to the system proxy: $($_.Exception.Message)" -LogLevel 2
            return $false
        }

        try {
            $prop = [System.Net.Http.HttpClient].GetProperty('DefaultProxy', [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
            if ($prop -and $prop.CanWrite) { $prop.SetValue($null, [System.Net.WebRequest]::DefaultWebProxy) }
        }
        catch {
            Write-Verbose "HttpClient.DefaultProxy not updated: $($_.Exception.Message)"
        }

        return $true
    }
}

####################################################

function Resolve-IntuneAppReference {
    <#
.SYNOPSIS
Resolves an application reference (GUID or display name) to an Intune application ID
.DESCRIPTION
Dependency and supersedence references come from Config.xml/Config.json as display names,
but the Graph relationship payload requires the target application ID. This helper accepts
either form and always returns an application ID (or $null when it cannot be resolved).
.PARAMETER AppReference
An application ID (GUID) or the display name of an application
.EXAMPLE
$id = Resolve-IntuneAppReference -AppReference "Microsoft Edge Stable"
.NOTES
NAME: Resolve-IntuneAppReference
#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppReference
    )

    process {
        $parsedGuid = [guid]::Empty
        if ([guid]::TryParse($AppReference, [ref]$parsedGuid)) {
            return $AppReference
        }

        Write-Log -Message "Resolving application reference '$AppReference' to an application ID..."
        $app = Get-IntuneAppByDisplayName -DisplayName $AppReference

        if ($null -eq $app -or [string]::IsNullOrWhiteSpace([string]$app.id)) {
            Write-Log -Message "Could not resolve application reference '$AppReference' - application not found" -LogLevel 2
            Write-Host "Warning: Application '$AppReference' not found - cannot create relationship" -ForegroundColor Yellow
            return $null
        }

        Write-Log -Message "Resolved '$AppReference' to application ID: $($app.id)"
        return [string]$app.id
    }
}

####################################################

function Set-IntuneAppRelationship {
    <#
.SYNOPSIS
Adds or updates a dependency/supersedence relationship on an Intune application
.DESCRIPTION
Graph rejects POSTs of individual relationships to /mobileApps/{id}/relationships for Win32
apps; the supported action is /mobileApps/{id}/updateRelationships, which REPLACES the entire
child relationship set. This function therefore reads the current child relationships, merges
in (or updates) the requested one, and POSTs the complete set back.

The payload is built with ordered dictionaries because Graph requires the '@odata.type'
annotation to be the first property of each relationship object - an unordered hashtable can
serialise it later and produces "The annotation 'odata.type' was found. This annotation is
either not recognized or not expected at the current position."
.PARAMETER SourceAppId
The ID of the application the relationship is being added to (the parent app)
.PARAMETER TargetAppId
The ID of the application being depended upon or superseded (the child app)
.PARAMETER OdataType
'#microsoft.graph.mobileAppDependency' or '#microsoft.graph.mobileAppSupersedence'
.PARAMETER RelationshipType
The dependencyType ('detect'/'autoInstall') or supersedenceType ('update'/'replace') value
.EXAMPLE
Set-IntuneAppRelationship -SourceAppId "12345" -TargetAppId "67890" -OdataType "#microsoft.graph.mobileAppDependency" -RelationshipType "autoInstall"
.NOTES
NAME: Set-IntuneAppRelationship
#>

    [cmdletbinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceAppId,

        [Parameter(Mandatory = $true)]
        [string]$TargetAppId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('#microsoft.graph.mobileAppDependency', '#microsoft.graph.mobileAppSupersedence')]
        [string]$OdataType,

        [Parameter(Mandatory = $true)]
        [string]$RelationshipType
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        if ($SourceAppId -eq $TargetAppId) {
            Write-Log -Message "Skipping relationship - an application cannot reference itself ($SourceAppId)" -LogLevel 2
            Write-Host "Warning: Skipped self-referencing relationship" -ForegroundColor Yellow
            return $false
        }

        $graphApiVersion = "beta"
        $typeProperty = if ($OdataType -eq '#microsoft.graph.mobileAppDependency') { 'dependencyType' } else { 'supersedenceType' }

        try {
            # updateRelationships replaces the whole child set, so seed the payload with what already exists
            $existingUri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps/$SourceAppId/relationships"
            $existing = Invoke-MgGraphRequest -Uri $existingUri -Method Get

            $relationships = @()
            foreach ($rel in @($existing.value)) {
                # 'parent' entries are owned by the other app and must not be echoed back
                if ($rel.targetType -ne 'child') { continue }

                $relOdataType = [string]$rel.'@odata.type'
                if ($relOdataType -ne '#microsoft.graph.mobileAppDependency' -and $relOdataType -ne '#microsoft.graph.mobileAppSupersedence') { continue }

                # The requested relationship is re-added below with the requested type
                if ($rel.targetId -eq $TargetAppId -and $relOdataType -eq $OdataType) { continue }

                $relTypeProperty = if ($relOdataType -eq '#microsoft.graph.mobileAppDependency') { 'dependencyType' } else { 'supersedenceType' }
                $relationships += [ordered]@{
                    '@odata.type'    = $relOdataType
                    'targetId'       = [string]$rel.targetId
                    $relTypeProperty = [string]$rel.$relTypeProperty
                }
            }

            $relationships += [ordered]@{
                '@odata.type' = $OdataType
                'targetId'    = $TargetAppId
                $typeProperty = $RelationshipType
            }

            $json = ([ordered]@{ relationships = @($relationships) } | ConvertTo-Json -Depth 10)

            $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps/$SourceAppId/updateRelationships"
            if ($PSCmdlet.ShouldProcess($SourceAppId, "Set $OdataType relationship to $TargetAppId ($RelationshipType)")) {
                $null = Invoke-MgGraphRequest -Uri $uri -Method Post -Body $json -ContentType "application/json"
                Write-Log -Message "Relationship set successfully ($OdataType -> $TargetAppId, $RelationshipType)"
            }

            return $true
        }
        catch {
            Write-Log -Message "Error setting relationship ($OdataType -> $TargetAppId): $_" -LogLevel 2
            Write-Host "Warning: Failed to set relationship - $_" -ForegroundColor Yellow
            return $false
        }
    }
}

####################################################

function Set-IntuneAppDependency {
    <#
.SYNOPSIS
Adds a dependency relationship between two Intune applications
.DESCRIPTION
This function creates a dependency relationship where the current app depends on another app.
The dependency type can be 'detect' (just check if installed) or 'autoInstall' (install automatically).
.PARAMETER ApplicationId
The ID of the application that has the dependency (the dependent app)
.PARAMETER DependencyAppId
The application that is depended upon - either an application ID (GUID) or a display name,
which is resolved to an ID before the relationship is created
.PARAMETER DependencyType
The type of dependency: 'detect' or 'autoInstall'. Default is 'autoInstall'.
.EXAMPLE
Set-IntuneAppDependency -ApplicationId "12345" -DependencyAppId "67890" -DependencyType "autoInstall"
.EXAMPLE
Set-IntuneAppDependency -ApplicationId "12345" -DependencyAppId "Microsoft Edge Stable" -DependencyType "detect"
.NOTES
NAME: Set-IntuneAppDependency
#>

    [cmdletbinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('SourceAppId')]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
        [Alias('TargetAppId', 'TargetAppDisplayName', 'DependencyAppDisplayName')]
        [string]$DependencyAppId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('detect', 'autoInstall')]
        [string]$DependencyType = 'autoInstall'
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "Adding dependency on app '$DependencyAppId' for application ID: $ApplicationId (Type: $DependencyType)"

        $targetAppId = Resolve-IntuneAppReference -AppReference $DependencyAppId
        if ([string]::IsNullOrWhiteSpace($targetAppId)) {
            return $false
        }

        $params = @{
            SourceAppId      = $ApplicationId
            TargetAppId      = $targetAppId
            OdataType        = '#microsoft.graph.mobileAppDependency'
            RelationshipType = $DependencyType
        }
        $result = Set-IntuneAppRelationship @params

        if ($result -and -not $WhatIfPreference) {
            Write-Log -Message "Dependency added successfully"
            Write-Host "Dependency on app '$DependencyAppId' added successfully" -ForegroundColor Green
        }
        return $result
    }
}

####################################################

function Set-IntuneAppSupersedence {
    <#
.SYNOPSIS
Adds a supersedence relationship between two Intune applications
.DESCRIPTION
This function creates a supersedence relationship where the current app supersedes another app.
The supersedence type can be 'update' (upgrade in place) or 'replace' (uninstall old, install new).
.PARAMETER ApplicationId
The ID of the application that supersedes (the newer app)
.PARAMETER SupersededAppId
The application being superseded - either an application ID (GUID) or a display name, which is
resolved to an ID before the relationship is created
.PARAMETER SupersedenceType
The type of supersedence: 'update' or 'replace'. Default is 'update'.
.EXAMPLE
Set-IntuneAppSupersedence -ApplicationId "12345" -SupersededAppId "67890" -SupersedenceType "update"
.EXAMPLE
Set-IntuneAppSupersedence -ApplicationId "12345" -SupersededAppId "Microsoft Edge Stable" -SupersedenceType "replace"
.NOTES
NAME: Set-IntuneAppSupersedence
#>

    [cmdletbinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('SourceAppId')]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
        [Alias('TargetAppId', 'TargetAppDisplayName', 'SupersededAppDisplayName')]
        [string]$SupersededAppId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('update', 'replace')]
        [string]$SupersedenceType = 'update'
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "Adding supersedence of app '$SupersededAppId' for application ID: $ApplicationId (Type: $SupersedenceType)"

        $targetAppId = Resolve-IntuneAppReference -AppReference $SupersededAppId
        if ([string]::IsNullOrWhiteSpace($targetAppId)) {
            return $false
        }

        $params = @{
            SourceAppId      = $ApplicationId
            TargetAppId      = $targetAppId
            OdataType        = '#microsoft.graph.mobileAppSupersedence'
            RelationshipType = $SupersedenceType
        }
        $result = Set-IntuneAppRelationship @params

        if ($result -and -not $WhatIfPreference) {
            Write-Log -Message "Supersedence added successfully"
            Write-Host "Supersedence of app '$SupersededAppId' added successfully" -ForegroundColor Green
        }
        return $result
    }
}

####################################################

function Get-IntuneAppByDisplayName {
    <#
.SYNOPSIS
Gets an Intune application by its display name
.DESCRIPTION
This function retrieves an Intune Win32 app by display name, returning the app ID and details.
Used for resolving dependency and supersedence references by name rather than ID.
.PARAMETER DisplayName
The display name of the application to find
.EXAMPLE
$app = Get-IntuneAppByDisplayName -DisplayName "Microsoft Edge Stable"
.NOTES
NAME: Get-IntuneAppByDisplayName
#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "Looking up application by display name: '$DisplayName'"

        $graphApiVersion = "beta"
        # OData string literals escape a single quote by doubling it
        $filterValue = $DisplayName -replace "'", "''"
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps?`$filter=displayName eq '$filterValue'"

        try {
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get

            if ($response.value -and $response.value.Count -gt 0) {
                $app = $response.value[0]
                Write-Log -Message "Found application: $($app.displayName) (ID: $($app.id))"
                return $app
            }
            else {
                Write-Log -Message "Application not found: '$DisplayName'" -LogLevel 2
                return $null
            }
        }
        catch {
            Write-Log -Message "Error looking up application: $_" -LogLevel 2
            return $null
        }
    }
}

####################################################

function Remove-IntuneApp {
    <#
.SYNOPSIS
Removes an Intune application by display name
.DESCRIPTION
This function deletes an Intune Win32 app by display name. Returns a result object
indicating success or failure with details. Supports -WhatIf to preview the operation.
.PARAMETER DisplayName
The display name of the application to delete
.EXAMPLE
$result = Remove-IntuneApp -DisplayName "My Application"
.NOTES
NAME: Remove-IntuneApp
#>

    [cmdletbinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        $result = [PSCustomObject]@{
            DisplayName = $DisplayName
            Status      = "Unknown"
            AppId       = $null
            Message     = ""
        }

        Write-Log -Message "Attempting to delete application: '$DisplayName'"
        Write-Host "Looking for application: '$DisplayName'..." -ForegroundColor Cyan

        # First, find the application
        $app = Get-IntuneAppByDisplayName -DisplayName $DisplayName

        if ($null -eq $app) {
            $result.Status = "NotFound"
            $result.Message = "Application not found in Intune"
            Write-Host "  Application not found: '$DisplayName'" -ForegroundColor Yellow
            Write-Log -Message "Application not found: '$DisplayName'" -LogLevel 2
            return $result
        }

        $result.AppId = $app.id
        Write-Host "  Found application with ID: $($app.id)" -ForegroundColor Green

        $graphApiVersion = "beta"
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps/$($app.id)"

        # Check WhatIf before performing destructive operation
        if (-not $PSCmdlet.ShouldProcess("Application '$DisplayName' (ID: $($app.id))", "Delete from Intune")) {
            $result.Status = "WhatIf"
            $result.Message = "Would delete application (WhatIf mode)"
            Write-Host "  WhatIf: Would delete application '$DisplayName'" -ForegroundColor Cyan
            return $result
        }

        try {
            Write-Host "  Deleting application..." -ForegroundColor Yellow
            Write-Log -Message "Deleting application with ID: $($app.id)"

            Invoke-MgGraphRequest -Uri $uri -Method Delete

            $result.Status = "Deleted"
            $result.Message = "Application successfully deleted"
            Write-Host "  Successfully deleted: '$DisplayName'" -ForegroundColor Green
            Write-Log -Message "Successfully deleted application: '$DisplayName' (ID: $($app.id))"
        }
        catch {
            $result.Status = "Error"
            $result.Message = $_.Exception.Message
            Write-Host "  Error deleting application: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Message "Error deleting application '$DisplayName': $($_.Exception.Message)" -LogLevel 3
        }

        return $result
    }
}

####################################################

function New-CustomReturnCode {
    <#
.SYNOPSIS
Creates a custom return code object for Win32 app
.DESCRIPTION
This function creates a return code object with the specified return code and type.
.PARAMETER ReturnCode
The integer return code value
.PARAMETER Type
The return code type: failed, success, softReboot, hardReboot, retry
.EXAMPLE
$code = New-CustomReturnCode -ReturnCode 3010 -Type "softReboot"
.NOTES
NAME: New-CustomReturnCode
#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ReturnCode,

        [Parameter(Mandatory = $true)]
        [ValidateSet('failed', 'success', 'softReboot', 'hardReboot', 'retry')]
        [string]$Type
    )

    return @{
        "returnCode" = $ReturnCode
        "type"       = $Type
    }
}

####################################################

function New-RequirementRule {
    <#
.SYNOPSIS
Creates a requirement rule for Win32 app additional requirements
.DESCRIPTION
This function creates requirement rule objects for file, registry, or PowerShell script requirements.
These are additional requirements beyond the default OS and architecture requirements.
.PARAMETER File
Switch to create a file-based requirement rule
.PARAMETER Registry
Switch to create a registry-based requirement rule
.PARAMETER Script
Switch to create a PowerShell script-based requirement rule
.PARAMETER Path
For File rules: The file path to check
.PARAMETER FileOrFolderName
For File rules: The file or folder name to detect
.PARAMETER DetectionType
For File and Registry rules: The detection type
.PARAMETER Operator
The comparison operator: notConfigured, equal, notEqual, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual
.PARAMETER DetectionValue
The value to compare against
.PARAMETER Check32BitOn64System
Whether to check the 32-bit path on 64-bit systems
.PARAMETER KeyPath
For Registry rules: The registry key path
.PARAMETER ValueName
For Registry rules: The registry value name
.PARAMETER ScriptFile
For Script rules: The path to the PowerShell script file
.PARAMETER RunAsAccount
For Script rules: The execution context - system or user
.PARAMETER RunAs32Bit
For Script rules: Whether to run as 32-bit
.PARAMETER EnforceSignatureCheck
For Script rules: Whether to enforce signature check
.EXAMPLE
$rule = New-RequirementRule -File -Path "C:\Program Files\MyApp" -FileOrFolderName "app.exe" -DetectionType "exists"
.NOTES
NAME: New-RequirementRule
#>

    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [Switch]$File,

        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [Switch]$Registry,

        [parameter(Mandatory = $true, ParameterSetName = "Script")]
        [Switch]$Script,

        # File parameters
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [string]$Path,

        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [string]$FileOrFolderName,

        [parameter(ParameterSetName = "File")]
        [parameter(ParameterSetName = "Registry")]
        [ValidateSet('notConfigured', 'equal', 'notEqual', 'greaterThan', 'greaterThanOrEqual', 'lessThan', 'lessThanOrEqual')]
        [string]$Operator = 'notConfigured',

        [parameter(ParameterSetName = "File")]
        [parameter(ParameterSetName = "Registry")]
        [string]$DetectionValue,

        [parameter(ParameterSetName = "File")]
        [parameter(ParameterSetName = "Registry")]
        [bool]$Check32BitOn64System = $false,

        [parameter(ParameterSetName = "File")]
        [ValidateSet('exists', 'doesNotExist', 'string', 'dateModified', 'dateCreated', 'version', 'sizeInMB', 'sizeInBytes')]
        [string]$FileDetectionType = 'exists',

        # Registry parameters
        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [string]$KeyPath,

        [parameter(ParameterSetName = "Registry")]
        [string]$ValueName,

        [parameter(ParameterSetName = "Registry")]
        [ValidateSet('exists', 'doesNotExist', 'string', 'integer', 'version')]
        [string]$RegistryDetectionType = 'exists',

        # Script parameters
        [parameter(Mandatory = $true, ParameterSetName = "Script")]
        [string]$ScriptFile,

        [parameter(ParameterSetName = "Script")]
        [ValidateSet('system', 'user')]
        [string]$RunAsAccount = 'system',

        [parameter(ParameterSetName = "Script")]
        [bool]$RunAs32Bit = $false,

        [parameter(ParameterSetName = "Script")]
        [bool]$EnforceSignatureCheck = $false,

        [parameter(ParameterSetName = "Script")]
        [string]$DisplayName,

        [parameter(ParameterSetName = "Script")]
        [string]$ScriptOutputDataType = 'notConfigured'
    )

    if ($File) {
        $rule = @{
            "@odata.type"          = "#microsoft.graph.win32LobAppFileSystemRequirement"
            "path"                 = $Path
            "fileOrFolderName"     = $FileOrFolderName
            "check32BitOn64System" = $Check32BitOn64System
            "detectionType"        = $FileDetectionType
        }
        if ($Operator -ne 'notConfigured') {
            $rule["operator"] = $Operator
            $rule["detectionValue"] = $DetectionValue
        }
        return $rule
    }
    elseif ($Registry) {
        $rule = @{
            "@odata.type"          = "#microsoft.graph.win32LobAppRegistryRequirement"
            "keyPath"              = $KeyPath
            "valueName"            = $ValueName
            "check32BitOn64System" = $Check32BitOn64System
            "detectionType"        = $RegistryDetectionType
        }
        if ($Operator -ne 'notConfigured') {
            $rule["operator"] = $Operator
            $rule["detectionValue"] = $DetectionValue
        }
        return $rule
    }
    elseif ($Script) {
        # Read and encode the script content
        if (Test-Path $ScriptFile) {
            $scriptContent = Get-Content -Path $ScriptFile -Raw -Encoding UTF8
            $encodedScript = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($scriptContent))
        }
        else {
            Write-Log -Message "Warning: Requirement script file not found: $ScriptFile" -LogLevel 2
            return $null
        }

        $rule = @{
            "@odata.type"           = "#microsoft.graph.win32LobAppPowerShellScriptRequirement"
            "scriptContent"         = $encodedScript
            "displayName"           = if ($DisplayName) { $DisplayName } else { [System.IO.Path]::GetFileNameWithoutExtension($ScriptFile) }
            "enforceSignatureCheck" = $EnforceSignatureCheck
            "runAs32Bit"            = $RunAs32Bit
            "runAsAccount"          = $RunAsAccount
            "detectionValue"        = $DetectionValue
            "operator"              = $Operator
        }
        return $rule
    }
}

####################################################

function Get-MinimumOperatingSystemObject {
    <#
.SYNOPSIS
Creates the minimum operating system properties for Win32 app requirements
.DESCRIPTION
This function resolves the specified Windows version to the correct Graph API properties.
The Graph API uses two different mechanisms:
  - minimumSupportedOperatingSystem: A complex type with boolean properties (supports up to v10_21H1)
  - minimumSupportedWindowsRelease: A string property for newer versions (Windows10_21H2, Windows11_23H2, etc.)
This function returns a hashtable with 'osObject' and 'windowsRelease' keys so callers can set
both properties appropriately.
Accepts both short names (e.g., "v10_1903", "v11_23H2") and full display names
(e.g., "Windows 10 1903", "Windows 11 23H2") from config files.
.PARAMETER MinimumOS
The minimum Windows version. Accepts either:
  - Short names: v10_1607, v10_1903, v10_21H2, v11_23H2, etc.
  - Full display names: "Windows 10 1607", "Windows 10 1903", "Windows 11 23H2", etc.
.EXAMPLE
$result = Get-MinimumOperatingSystemObject -MinimumOS "v10_1903"
# Returns: @{ osObject = @{...v10_1903=$true}; windowsRelease = $null }
.EXAMPLE
$result = Get-MinimumOperatingSystemObject -MinimumOS "Windows 11 23H2"
# Returns: @{ osObject = @{...v10_21H1=$true}; windowsRelease = "Windows11_23H2" }
.NOTES
NAME: Get-MinimumOperatingSystemObject
#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MinimumOS
    )

    # Map of accepted input values to internal version key
    # Key: user-facing input (case-insensitive), Value: internal key
    $versionMap = [ordered]@{
        # Windows 10 versions (supported by minimumSupportedOperatingSystem boolean properties)
        'v10_1507' = 'v10_1507'; 'Windows 10 1507' = 'v10_1507'
        'v10_1511' = 'v10_1511'; 'Windows 10 1511' = 'v10_1511'
        'v10_1607' = 'v10_1607'; 'Windows 10 1607' = 'v10_1607'
        'v10_1703' = 'v10_1703'; 'Windows 10 1703' = 'v10_1703'
        'v10_1709' = 'v10_1709'; 'Windows 10 1709' = 'v10_1709'
        'v10_1803' = 'v10_1803'; 'Windows 10 1803' = 'v10_1803'
        'v10_1809' = 'v10_1809'; 'Windows 10 1809' = 'v10_1809'
        'v10_1903' = 'v10_1903'; 'Windows 10 1903' = 'v10_1903'
        'v10_1909' = 'v10_1909'; 'Windows 10 1909' = 'v10_1909'
        'v10_2004' = 'v10_2004'; 'Windows 10 2004' = 'v10_2004'
        'v10_2H20' = 'v10_2H20'; 'Windows 10 20H2' = 'v10_2H20'; 'v10_20H2' = 'v10_2H20'
        'v10_21H1' = 'v10_21H1'; 'Windows 10 21H1' = 'v10_21H1'
        # Windows 10 newer versions (require minimumSupportedWindowsRelease string)
        'v10_21H2' = 'v10_21H2'; 'Windows 10 21H2' = 'v10_21H2'
        'v10_22H2' = 'v10_22H2'; 'Windows 10 22H2' = 'v10_22H2'
        # Windows 11 versions (require minimumSupportedWindowsRelease string)
        'v11_21H2' = 'v11_21H2'; 'Windows 11 21H2' = 'v11_21H2'
        'v11_22H2' = 'v11_22H2'; 'Windows 11 22H2' = 'v11_22H2'
        'v11_23H2' = 'v11_23H2'; 'Windows 11 23H2' = 'v11_23H2'
        'v11_24H2' = 'v11_24H2'; 'Windows 11 24H2' = 'v11_24H2'
        'v11_25H2' = 'v11_25H2'; 'Windows 11 25H2' = 'v11_25H2'
        'v11_26H2' = 'v11_26H2'; 'Windows 11 26H2' = 'v11_26H2'
    }

    # Versions that exist as boolean properties on windowsMinimumOperatingSystem (Graph API beta)
    $osBooleanProperties = @(
        'v10_1507', 'v10_1511', 'v10_1607', 'v10_1703', 'v10_1709', 'v10_1803', 'v10_1809',
        'v10_1903', 'v10_1909', 'v10_2004', 'v10_2H20', 'v10_21H1'
    )

    # Map internal version keys to minimumSupportedWindowsRelease string values
    # These are the string values accepted by the Graph API for the minimumSupportedWindowsRelease property
    $windowsReleaseMap = @{
        'v10_21H2' = 'Windows10_21H2'
        'v10_22H2' = 'Windows10_22H2'
        'v11_21H2' = 'Windows11_21H2'
        'v11_22H2' = 'Windows11_22H2'
        'v11_23H2' = 'Windows11_23H2'
        'v11_24H2' = 'Windows11_24H2'
        'v11_25H2' = 'Windows11_25H2'
        'v11_26H2' = 'Windows11_26H2'
    }

    # Resolve the input to an internal version key (case-insensitive)
    $versionKey = $null
    foreach ($key in $versionMap.Keys) {
        if ($key -eq $MinimumOS) {
            $versionKey = $versionMap[$key]
            break
        }
    }

    if ($null -eq $versionKey) {
        Write-Log -Message "Error: Unrecognized minimumSupportedOS value: '$MinimumOS'" -LogLevel 3
        Write-Host "Error: '$MinimumOS' is not a recognized OS version." -ForegroundColor Red
        Write-Host "Valid values: v10_1607, v10_1903, v11_23H2, 'Windows 10 1903', 'Windows 11 23H2', etc." -ForegroundColor Yellow
        $versionKey = 'v10_1607'
        Write-Log -Message "Falling back to default: $versionKey" -LogLevel 2
    }

    # Build the friendly display name for logging
    $displayName = $versionKey -replace '^v10_', 'Windows 10 ' -replace '^v11_', 'Windows 11 '

    # Determine which API mechanism to use
    if ($versionKey -in $osBooleanProperties) {
        # Use the old boolean property on minimumSupportedOperatingSystem
        Write-Log -Message "Using minimum OS: $displayName (via minimumSupportedOperatingSystem.$versionKey)"
        return @{
            osObject       = @{
                "@odata.type" = "#microsoft.graph.windowsMinimumOperatingSystem"
                $versionKey   = $true
            }
            windowsRelease = $null
        }
    }
    elseif ($windowsReleaseMap.ContainsKey($versionKey)) {
        # Use the minimumSupportedWindowsRelease string property (do NOT set minimumSupportedOperatingSystem - they conflict)
        $releaseString = $windowsReleaseMap[$versionKey]
        Write-Log -Message "Using minimum OS: $displayName (via minimumSupportedWindowsRelease = '$releaseString')"
        return @{
            osObject       = $null
            windowsRelease = $releaseString
        }
    }
    else {
        # Version not yet in either mechanism - fall back to latest boolean + warn
        Write-Log -Message "Warning: OS version '$displayName' ($versionKey) is not yet available in the Graph API. Falling back to Windows 10 21H1." -LogLevel 2
        Write-Host "Warning: OS version '$displayName' not yet available in Graph API. Using 'Windows 10 21H1' instead." -ForegroundColor Yellow
        return @{
            osObject       = @{
                "@odata.type" = "#microsoft.graph.windowsMinimumOperatingSystem"
                "v10_21H1"    = $true
            }
            windowsRelease = $null
        }
    }
}

####################################################

function Get-InstallerVersion {
    <#
.SYNOPSIS
Detects the version of an EXE or MSI file
.DESCRIPTION
This function extracts version information from EXE files (using FileVersionInfo) or MSI files (using Windows Installer COM object).
.PARAMETER FilePath
The full path to the EXE or MSI file
.PARAMETER FileType
The type of file: EXE or MSI
.EXAMPLE
$version = Get-InstallerVersion -FilePath "C:\Packages\Setup.exe" -FileType "EXE"
.NOTES
NAME: Get-InstallerVersion
#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [ValidateSet('EXE', 'MSI')]
        [string]$FileType
    )

    if (-not (Test-Path $FilePath)) {
        Write-Log -Message "File not found for version detection: $FilePath" -LogLevel 2
        return $null
    }

    try {
        if ($FileType -eq "EXE") {
            # Get version from EXE using FileVersionInfo
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)

            # Try FileVersion first, then ProductVersion
            $version = $versionInfo.FileVersion
            if ([string]::IsNullOrWhiteSpace($version)) {
                $version = $versionInfo.ProductVersion
            }

            if (-not [string]::IsNullOrWhiteSpace($version)) {
                # Clean up version string - remove any extra whitespace or text after version number
                $version = $version.Trim()
                # Extract just the version number if there's additional text
                if ($version -match '^[\d\.]+') {
                    $version = $Matches[0]
                }
                Write-Log -Message "Detected EXE version: $version (from $FilePath)"
                return $version
            }
            else {
                Write-Log -Message "No version information found in EXE: $FilePath" -LogLevel 2
                return $null
            }
        }
        elseif ($FileType -eq "MSI") {
            # Get version from MSI using Windows Installer COM object
            $windowsInstaller = New-Object -ComObject WindowsInstaller.Installer
            $database = $windowsInstaller.OpenDatabase($FilePath, 0) # 0 = msiOpenDatabaseModeReadOnly

            $view = $database.OpenView("SELECT Value FROM Property WHERE Property = 'ProductVersion'")
            $view.Execute()
            $record = $view.Fetch()

            if ($null -ne $record) {
                $version = $record.StringData(1)
                Write-Log -Message "Detected MSI version: $version (from $FilePath)"

                # Clean up COM objects
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($record) | Out-Null
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($view) | Out-Null
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($database) | Out-Null
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($windowsInstaller) | Out-Null

                return $version
            }
            else {
                Write-Log -Message "No ProductVersion found in MSI: $FilePath" -LogLevel 2

                # Clean up COM objects
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($view) | Out-Null
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($database) | Out-Null
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($windowsInstaller) | Out-Null

                return $null
            }
        }
    }
    catch {
        Write-Log -Message "Error detecting version from $FilePath : $_" -LogLevel 2
        return $null
    }
}

####################################################

function Update-ConfigFileVersion {
    <#
.SYNOPSIS
Updates the displayVersion in a Config.xml or Config.json file
.DESCRIPTION
This function updates the displayVersion field in the configuration file with a new version value.
.PARAMETER ConfigFilePath
The full path to the Config.xml or Config.json file
.PARAMETER NewVersion
The new version string to write
.EXAMPLE
Update-ConfigFileVersion -ConfigFilePath "C:\Packages\MyApp\Config.xml" -NewVersion "2.0.0"
.NOTES
NAME: Update-ConfigFileVersion
#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigFilePath,

        [Parameter(Mandatory = $true)]
        [string]$NewVersion
    )

    if (-not (Test-Path $ConfigFilePath)) {
        Write-Log -Message "Config file not found for version update: $ConfigFilePath" -LogLevel 3
        return $false
    }

    try {
        $extension = [System.IO.Path]::GetExtension($ConfigFilePath).ToLower()

        if ($extension -eq ".xml") {
            # Update XML config
            [xml]$xmlContent = Get-Content $ConfigFilePath -Encoding UTF8
            $intuneSettings = $xmlContent.SelectSingleNode("//IntuneWin_Settings")

            if ($null -ne $intuneSettings) {
                $displayVersionNode = $intuneSettings.SelectSingleNode("displayVersion")
                if ($null -ne $displayVersionNode) {
                    $displayVersionNode.InnerText = $NewVersion
                }
                else {
                    # Create the node if it doesn't exist
                    $newNode = $xmlContent.CreateElement("displayVersion")
                    $newNode.InnerText = $NewVersion
                    $intuneSettings.AppendChild($newNode) | Out-Null
                }
                $xmlContent.Save($ConfigFilePath)
                Write-Log -Message "Updated displayVersion in XML config to: $NewVersion"
                return $true
            }
            else {
                Write-Log -Message "IntuneWin_Settings node not found in XML config" -LogLevel 3
                return $false
            }
        }
        elseif ($extension -eq ".json") {
            # Update JSON config
            $jsonContent = Get-Content $ConfigFilePath -Raw | ConvertFrom-Json
            # Check if displayVersion property exists, if not add it
            if (-not ($jsonContent.PSObject.Properties.Name -contains 'displayVersion')) {
                $jsonContent | Add-Member -MemberType NoteProperty -Name 'displayVersion' -Value $NewVersion
                Write-Log -Message "Added missing displayVersion property to JSON config"
            }
            else {
                $jsonContent.displayVersion = $NewVersion
            }
            $jsonContent | ConvertTo-Json -Depth 10 | Set-Content $ConfigFilePath -Encoding UTF8
            Write-Log -Message "Updated displayVersion in JSON config to: $NewVersion"
            return $true
        }
        else {
            Write-Log -Message "Unsupported config file type: $extension" -LogLevel 3
            return $false
        }
    }
    catch {
        Write-Log -Message "Error updating config file version: $_" -LogLevel 3
        return $false
    }
}

####################################################

function Invoke-VersionCheck {
    <#
.SYNOPSIS
Checks installer version against config version and prompts user if different
.DESCRIPTION
Detects the version from an EXE or MSI file and compares it to the displayVersion in the config.
If different, prompts the user to use the detected version. Times out after 30 seconds.
.PARAMETER SourcePath
The path to the source folder containing the installer
.PARAMETER PackageName
The name of the package (without extension)
.PARAMETER AppType
The application type: EXE or MSI
.PARAMETER ConfigFilePath
The path to the config file (XML or JSON)
.PARAMETER ConfigVersion
The current displayVersion from the config
.EXAMPLE
Invoke-VersionCheck -SourcePath "C:\Packages\MyApp\Source" -PackageName "Setup" -AppType "EXE" -ConfigFilePath "C:\Packages\MyApp\Config.xml" -ConfigVersion "1.0"
.NOTES
NAME: Invoke-VersionCheck
#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$PackageName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('EXE', 'MSI')]
        [string]$AppType,

        [Parameter(Mandatory = $true)]
        [string]$ConfigFilePath,

        [Parameter(Mandatory = $false)]
        [string]$ConfigVersion
    )

    # Determine file extension based on app type
    $fileExtension = if ($AppType -eq "EXE") { ".exe" } else { ".msi" }
    $installerPath = Join-Path $SourcePath "$PackageName$fileExtension"

    # Check if installer file exists
    if (-not (Test-Path $installerPath)) {
        Write-Log -Message "Installer file not found for version detection: $installerPath"
        return
    }

    # Detect version from installer
    $detectedVersion = Get-InstallerVersion -FilePath $installerPath -FileType $AppType

    if ([string]::IsNullOrWhiteSpace($detectedVersion)) {
        Write-Log -Message "Could not detect version from installer file"
        return
    }

    # Check if config version is empty or different from detected
    $configVersionEmpty = [string]::IsNullOrWhiteSpace($ConfigVersion)
    $versionsMatch = (-not $configVersionEmpty) -and ($ConfigVersion -eq $detectedVersion)

    if ($versionsMatch) {
        Write-Log -Message "Detected version ($detectedVersion) matches config displayVersion"
        return
    }

    # Versions differ or config is empty
    Write-Host
    if ($configVersionEmpty) {
        Write-Host "Version Detection" -ForegroundColor Cyan
        Write-Host "=================" -ForegroundColor Cyan
        Write-Host "Detected version from $AppType file: " -NoNewline
        Write-Host "$detectedVersion" -ForegroundColor Green
        Write-Host "Config displayVersion: " -NoNewline
        Write-Host "(empty)" -ForegroundColor Yellow
        Write-Host
        Write-Host "The detected version will be used and saved to the config file." -ForegroundColor Cyan
        Write-Host

        # Auto-use detected version when config is empty
        $script:displayVersion = [string]$detectedVersion
        $updateResult = Update-ConfigFileVersion -ConfigFilePath $ConfigFilePath -NewVersion ([string]$detectedVersion)
        if ($updateResult) {
            Write-Host "Config file updated with version: $detectedVersion" -ForegroundColor Green
        }
        return
    }

    # Config has a version but it's different - prompt user
    Write-Host
    Write-Host "Version Mismatch Detected" -ForegroundColor Yellow
    Write-Host "=========================" -ForegroundColor Yellow
    Write-Host "Detected version from $AppType file: " -NoNewline
    Write-Host "$detectedVersion" -ForegroundColor Green
    Write-Host "Config displayVersion: " -NoNewline
    Write-Host "$ConfigVersion" -ForegroundColor Cyan
    Write-Host
    Write-Host "Do you want to use the detected version ($detectedVersion) instead?" -ForegroundColor Yellow
    Write-Host "Press 'Y' for Yes, 'N' for No, or wait 30 seconds to keep config version." -ForegroundColor Gray
    Write-Host

    # Wait for user input with timeout
    $timeout = 30
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $useDetectedVersion = $false

    while ($stopwatch.Elapsed.TotalSeconds -lt $timeout) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Y') {
                $useDetectedVersion = $true
                Write-Host "Using detected version: $detectedVersion" -ForegroundColor Green
                break
            }
            elseif ($key.Key -eq 'N') {
                $useDetectedVersion = $false
                Write-Host "Keeping config version: $ConfigVersion" -ForegroundColor Cyan
                break
            }
        }

        # Update countdown display
        $remaining = [math]::Ceiling($timeout - $stopwatch.Elapsed.TotalSeconds)
        Write-Host "`rTime remaining: $remaining seconds... " -NoNewline -ForegroundColor Gray
        Start-Sleep -Milliseconds 500
    }
    $stopwatch.Stop()

    Write-Host # New line after countdown

    if ($stopwatch.Elapsed.TotalSeconds -ge $timeout) {
        Write-Host "Timeout - keeping config version: $ConfigVersion" -ForegroundColor Cyan
        $useDetectedVersion = $false
    }

    if ($useDetectedVersion) {
        # Update the script variable and config file
        $script:displayVersion = [string]$detectedVersion
        $updateResult = Update-ConfigFileVersion -ConfigFilePath $ConfigFilePath -NewVersion ([string]$detectedVersion)
        if ($updateResult) {
            Write-Host "Config file updated with version: $detectedVersion" -ForegroundColor Green
        }
        else {
            Write-Host "Warning: Could not update config file, but will use detected version for this run" -ForegroundColor Yellow
        }
    }

    Write-Host
}

####################################################

function Get-LevenshteinDistance {
    <#
.SYNOPSIS
Calculates the Levenshtein distance between two strings
.DESCRIPTION
Returns the minimum number of single-character edits required to change one string into another
.PARAMETER Source
The source string
.PARAMETER Target
The target string
.EXAMPLE
Get-LevenshteinDistance -Source "test" -Target "tent"
.NOTES
NAME: Get-LevenshteinDistance
#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    $sourceLen = $Source.Length
    $targetLen = $Target.Length

    # Handle edge cases
    if ($sourceLen -eq 0) { return $targetLen }
    if ($targetLen -eq 0) { return $sourceLen }

    # Create distance matrix using jagged array (PowerShell-compatible)
    $matrix = @()
    for ($i = 0; $i -le $sourceLen; $i++) {
        $row = @(0) * ($targetLen + 1)
        $matrix += , $row
    }

    # Initialize first column and row
    for ($i = 0; $i -le $sourceLen; $i++) { $matrix[$i][0] = $i }
    for ($j = 0; $j -le $targetLen; $j++) { $matrix[0][$j] = $j }

    # Fill in the rest of the matrix
    for ($i = 1; $i -le $sourceLen; $i++) {
        for ($j = 1; $j -le $targetLen; $j++) {
            $cost = if ($Source[$i - 1] -eq $Target[$j - 1]) { 0 } else { 1 }

            $deletion = $matrix[$i - 1][$j] + 1
            $insertion = $matrix[$i][$j - 1] + 1
            $substitution = $matrix[$i - 1][$j - 1] + $cost

            $matrix[$i][$j] = [Math]::Min([Math]::Min($deletion, $insertion), $substitution)
        }
    }

    return $matrix[$sourceLen][$targetLen]
}

####################################################

function Update-ConfigInstallCmdLine {
    <#
.SYNOPSIS
Updates the installCmdLine and optionally PackageName in a Config.xml or Config.json file
.DESCRIPTION
This function updates the installCmdLine field in the configuration file with a corrected exe filename.
It preserves any command-line arguments from the original installCmdLine.
.PARAMETER ConfigFilePath
The full path to the Config.xml or Config.json file
.PARAMETER NewExeFileName
The corrected exe filename (just the filename, not full path)
.PARAMETER OriginalInstallCmdLine
The original installCmdLine value to extract arguments from
.PARAMETER UpdatePackageName
If specified, also update the PackageName element (without extension)
.EXAMPLE
Update-ConfigInstallCmdLine -ConfigFilePath "C:\Packages\MyApp\Config.xml" -NewExeFileName "Setup-2.0.exe" -OriginalInstallCmdLine "Setup-1.0.exe /SILENT"
.NOTES
NAME: Update-ConfigInstallCmdLine
#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigFilePath,

        [Parameter(Mandatory = $true)]
        [string]$NewExeFileName,

        [Parameter(Mandatory = $true)]
        [string]$OriginalInstallCmdLine,

        [Parameter(Mandatory = $false)]
        [switch]$UpdatePackageName
    )

    if (-not (Test-Path $ConfigFilePath)) {
        Write-Log -Message "Config file not found for installCmdLine update: $ConfigFilePath" -LogLevel 3
        return $false
    }

    try {
        # Extract arguments from original command line (everything after the first .exe)
        $arguments = ""
        if ($OriginalInstallCmdLine -match '\.exe\s+(.+)$') {
            $arguments = " " + $Matches[1]
        }

        $newInstallCmdLine = $NewExeFileName + $arguments
        $newPackageName = [System.IO.Path]::GetFileNameWithoutExtension($NewExeFileName)

        $extension = [System.IO.Path]::GetExtension($ConfigFilePath).ToLower()

        if ($extension -eq ".xml") {
            # Update XML config
            [xml]$xmlContent = Get-Content $ConfigFilePath -Encoding UTF8
            $intuneSettings = $xmlContent.SelectSingleNode("//IntuneWin_Settings")

            if ($null -ne $intuneSettings) {
                # Update installCmdLine
                $installCmdLineNode = $intuneSettings.SelectSingleNode("installCmdLine")
                if ($null -ne $installCmdLineNode) {
                    $installCmdLineNode.InnerText = $newInstallCmdLine
                }

                # Update PackageName if requested
                if ($UpdatePackageName) {
                    $packageNameNode = $intuneSettings.SelectSingleNode("PackageName")
                    if ($null -ne $packageNameNode) {
                        $packageNameNode.InnerText = $newPackageName
                    }
                }

                $xmlContent.Save($ConfigFilePath)
                Write-Log -Message "Updated installCmdLine in XML config to: $newInstallCmdLine"
                if ($UpdatePackageName) {
                    Write-Log -Message "Updated PackageName in XML config to: $newPackageName"
                }
                return $true
            }
            else {
                Write-Log -Message "IntuneWin_Settings node not found in XML config" -LogLevel 3
                return $false
            }
        }
        elseif ($extension -eq ".json") {
            # Update JSON config
            $jsonContent = Get-Content $ConfigFilePath -Raw | ConvertFrom-Json

            # Update installCmdLine
            if ($jsonContent.PSObject.Properties.Name -contains 'installCmdLine') {
                $jsonContent.installCmdLine = $newInstallCmdLine
            }

            # Update PackageName if requested
            if ($UpdatePackageName -and ($jsonContent.PSObject.Properties.Name -contains 'PackageName')) {
                $jsonContent.PackageName = $newPackageName
            }

            $jsonContent | ConvertTo-Json -Depth 10 | Set-Content $ConfigFilePath -Encoding UTF8
            Write-Log -Message "Updated installCmdLine in JSON config to: $newInstallCmdLine"
            if ($UpdatePackageName) {
                Write-Log -Message "Updated PackageName in JSON config to: $newPackageName"
            }
            return $true
        }
        else {
            Write-Log -Message "Unsupported config file type: $extension" -LogLevel 3
            return $false
        }
    }
    catch {
        Write-Log -Message "Error updating config file installCmdLine: $_" -LogLevel 3
        return $false
    }
}

####################################################

function Invoke-ExeValidation {
    <#
.SYNOPSIS
Validates that the exe file specified in installCmdLine exists in the Source folder
.DESCRIPTION
Checks if the exe file referenced in installCmdLine exists. If not found, searches for the
closest matching exe file in the Source folder using fuzzy matching and offers to update the config.
.PARAMETER SourcePath
The path to the source folder containing the installer
.PARAMETER InstallCmdLine
The current installCmdLine from the config
.PARAMETER ConfigFilePath
The path to the config file (XML or JSON)
.PARAMETER PackageName
The current PackageName from the config
.EXAMPLE
Invoke-ExeValidation -SourcePath "C:\Packages\MyApp\Source" -InstallCmdLine "Setup-1.0.exe /SILENT" -ConfigFilePath "C:\Packages\MyApp\Config.xml" -PackageName "Setup-1.0"
.NOTES
NAME: Invoke-ExeValidation
#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$InstallCmdLine,

        [Parameter(Mandatory = $true)]
        [string]$ConfigFilePath,

        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )

    # Extract exe filename from installCmdLine (first token ending in .exe)
    if ($InstallCmdLine -match '^([^\s]+\.exe)') {
        $configuredExe = $Matches[1]
    }
    else {
        Write-Log -Message "Could not extract .exe filename from installCmdLine: $InstallCmdLine"
        return
    }

    $fullExePath = Join-Path $SourcePath $configuredExe

    # Check if the configured exe exists
    if (Test-Path $fullExePath) {
        Write-Log -Message "Validated: $configuredExe exists in Source folder"
        return
    }

    Write-Log -Message "EXE file not found: $configuredExe" -LogLevel 2

    # Get all exe files in the Source folder
    $exeFiles = Get-ChildItem -Path $SourcePath -Filter "*.exe" -File -ErrorAction SilentlyContinue

    if ($null -eq $exeFiles -or $exeFiles.Count -eq 0) {
        Write-Log -Message "No .exe files found in Source folder: $SourcePath" -LogLevel 3
        Write-Host "Error: No .exe files found in Source folder!" -ForegroundColor Red
        Write-Host "Source path: $SourcePath" -ForegroundColor Red
        return
    }

    # Find the closest matching exe using Levenshtein distance
    $bestMatch = $null
    $bestDistance = [int]::MaxValue

    foreach ($exeFile in $exeFiles) {
        $distance = Get-LevenshteinDistance -Source $configuredExe.ToLower() -Target $exeFile.Name.ToLower()
        if ($distance -lt $bestDistance) {
            $bestDistance = $distance
            $bestMatch = $exeFile.Name
        }
    }

    if ($null -eq $bestMatch) {
        Write-Log -Message "Could not find a matching .exe file in Source folder" -LogLevel 3
        return
    }

    # Display the mismatch and best match to user
    Write-Host
    Write-Host "EXE File Mismatch Detected" -ForegroundColor Yellow
    Write-Host "==========================" -ForegroundColor Yellow
    Write-Host "Configured in installCmdLine: " -NoNewline
    Write-Host "$configuredExe" -ForegroundColor Red
    Write-Host "File not found in: " -NoNewline
    Write-Host "$SourcePath" -ForegroundColor Cyan
    Write-Host
    Write-Host "Available .exe files in Source folder:" -ForegroundColor Cyan
    foreach ($exeFile in $exeFiles) {
        if ($exeFile.Name -eq $bestMatch) {
            Write-Host "  * $($exeFile.Name) (best match)" -ForegroundColor Green
        }
        else {
            Write-Host "  - $($exeFile.Name)" -ForegroundColor Gray
        }
    }
    Write-Host
    Write-Host "Do you want to update the config to use: " -NoNewline -ForegroundColor Yellow
    Write-Host "$bestMatch" -ForegroundColor Green -NoNewline
    Write-Host "?" -ForegroundColor Yellow
    Write-Host "This will also update the PackageName element." -ForegroundColor Gray
    Write-Host "Press 'Y' for Yes, 'N' for No, or wait 30 seconds to cancel." -ForegroundColor Gray
    Write-Host

    # Wait for user input with timeout
    $timeout = 30
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $useNewExe = $false

    while ($stopwatch.Elapsed.TotalSeconds -lt $timeout) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Y') {
                $useNewExe = $true
                Write-Host "Using corrected exe: $bestMatch" -ForegroundColor Green
                break
            }
            elseif ($key.Key -eq 'N') {
                $useNewExe = $false
                Write-Host "Keeping original configuration (script may fail)" -ForegroundColor Yellow
                break
            }
        }

        # Update countdown display
        $remaining = [math]::Ceiling($timeout - $stopwatch.Elapsed.TotalSeconds)
        Write-Host "`rTime remaining: $remaining seconds... " -NoNewline -ForegroundColor Gray
        Start-Sleep -Milliseconds 500
    }
    $stopwatch.Stop()

    Write-Host # New line after countdown

    if ($stopwatch.Elapsed.TotalSeconds -ge $timeout) {
        Write-Host "Timeout - cancelling operation. Original configuration kept." -ForegroundColor Yellow
        return
    }

    if ($useNewExe) {
        # Extract the new package name (without extension)
        $newPackageName = [System.IO.Path]::GetFileNameWithoutExtension($bestMatch)

        # Update the script variables
        # Extract arguments from original install command line
        $arguments = ""
        if ($InstallCmdLine -match '\.exe\s+(.+)$') {
            $arguments = " " + $Matches[1]
        }
        $script:installCmdLine = $bestMatch + $arguments
        $script:PackageName = $newPackageName

        Write-Log -Message "Updated script variables - installCmdLine: $($script:installCmdLine), PackageName: $($script:PackageName)"

        # Update the config file
        $updateResult = Update-ConfigInstallCmdLine -ConfigFilePath $ConfigFilePath -NewExeFileName $bestMatch -OriginalInstallCmdLine $InstallCmdLine -UpdatePackageName
        if ($updateResult) {
            Write-Host "Config file updated successfully!" -ForegroundColor Green
            Write-Host "  installCmdLine: $($script:installCmdLine)" -ForegroundColor Cyan
            Write-Host "  PackageName: $($script:PackageName)" -ForegroundColor Cyan
        }
        else {
            Write-Host "Warning: Could not update config file, but will use corrected values for this run" -ForegroundColor Yellow
        }
    }

    Write-Host
}

####################################################

function Copy-Object($object) {

    # Deep clone via hashtable copy (replaces deprecated BinaryFormatter)
    if ($object -is [hashtable]) {
        $clone = @{}
        foreach ($key in $object.Keys) {
            $clone[$key] = $object[$key]
        }
        return $clone
    }
    # Fallback for other types via JSON round-trip
    $object | ConvertTo-Json -Depth 10 | ConvertFrom-Json
}

####################################################

function Invoke-GetRequest($collectionPath) {
    # Thin shim — delegates to Invoke-GraphRequestWithRetry so all legacy callers get retry/throttling handling.
    $uri = "$script:baseUrl$collectionPath"
    if ($logRequestUris) { Write-Host "GET $uri" }
    return Invoke-GraphRequestWithRetry -Method GET -Uri $uri
}

####################################################

function Invoke-PatchRequest($collectionPath, $body) {
    $uri = "$script:baseUrl$collectionPath"
    if ($logRequestUris) { Write-Host "PATCH $uri" }
    return Invoke-GraphRequestWithRetry -Method PATCH -Uri $uri -Body $body
}

####################################################

function Invoke-PostRequest($collectionPath, $body) {
    $uri = "$script:baseUrl$collectionPath"
    if ($logRequestUris) { Write-Host "POST $uri" }
    return Invoke-GraphRequestWithRetry -Method POST -Uri $uri -Body $body
}

####################################################

function Invoke-IntuneGraphRequest($verb, $collectionPath, $body) {
    $uri = "$script:baseUrl$collectionPath"
    if ($logRequestUris) { Write-Host "$verb $uri" }
    return Invoke-GraphRequestWithRetry -Method $verb -Uri $uri -Body $body
}

####################################################

function Format-SafeSasMessage {
    # Redacts SAS-token query parameters (sig/se/sp/sv/sr/st/skoid/sktid/skt/ske/sks/skv/spr/si/srt/ss/tn)
    # from any string so error/log output does not leak credentials.
    param([Parameter(Position = 0)] $Message)
    if ($null -eq $Message) { return $Message }
    $text = [string]$Message
    if ([string]::IsNullOrEmpty($text)) { return $text }
    $pattern = '(?i)(?<=[?&])(sig|se|sp|sv|sr|st|skoid|sktid|skt|ske|sks|skv|spr|si|srt|ss|tn)=[^&\s"'']*'
    return [regex]::Replace($text, $pattern, '$1=***REDACTED***')
}

####################################################

function Test-ZipEntrySafePath {
    # ZIP-Slip guard: reject entries whose resolved destination escapes the target directory.
    param(
        [Parameter(Mandatory = $true)][string] $EntryFullName,
        [Parameter(Mandatory = $true)][string] $DestinationDir
    )
    if ($EntryFullName -match '(^|[\\/])\.\.([\\/]|$)') {
        throw "ZIP entry path traversal detected (relative ..): '$EntryFullName'"
    }
    $rooted = [System.IO.Path]::GetFullPath((Join-Path $DestinationDir $EntryFullName))
    $rootedDir = [System.IO.Path]::GetFullPath($DestinationDir.TrimEnd('\', '/'))
    if (-not $rooted.StartsWith($rootedDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "ZIP entry resolves outside the destination directory: '$EntryFullName' -> '$rooted' (destination '$rootedDir')"
    }
}

####################################################

function Send-AzureStorageChunk($sasUri, $id, $body) {

    $uri = "$sasUri&comp=block&blockid=$id";
    $request = "PUT $uri";
    $safeRequest = Format-SafeSasMessage $request

    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
    };

    if ($logRequestUris) { Write-Host $safeRequest; }

    try {
        # Upload binary data directly without text encoding conversion
        $iwrParams = @{
            Uri             = $uri
            Method          = 'Put'
            Headers         = $headers
            Body            = $body
            UseBasicParsing = $true
        }
        Add-IntuneWinProxyParameter -Parameters $iwrParams
        $response = Invoke-WebRequest @iwrParams
    }
    catch {
        Write-Host -ForegroundColor Red $safeRequest;
        Write-Host -ForegroundColor Red (Format-SafeSasMessage $_.Exception.Message);
        throw
    }

}

####################################################

function Complete-AzureStorageUpload($sasUri, $ids) {

    $uri = "$sasUri&comp=blocklist";
    $request = "PUT $uri";

    $xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>';
    foreach ($id in $ids) {
        $xml += "<Latest>$id</Latest>";
    }
    $xml += '</BlockList>';

    if ($logRequestUris) { Write-Host $request; }
    if ($logContent) { Write-Host -ForegroundColor Gray $xml; }

    try {
        $headers = @{
            "x-ms-version" = "2017-04-17"
        }
        # Convert XML string to UTF-8 bytes to prevent formatting issues in PowerShell 7
        $xmlBytes = [System.Text.Encoding]::UTF8.GetBytes($xml)

        Write-Host -ForegroundColor Cyan "Finalizing blocklist with $($ids.Count) blocks..."
        Write-Host -ForegroundColor Cyan "XML Length: $($xmlBytes.Length) bytes"
        Write-Host -ForegroundColor Cyan "URI: $uri"

        $iwrParams = @{
            Uri             = $uri
            Method          = 'Put'
            Headers         = $headers
            Body            = $xmlBytes
            ContentType     = 'application/xml; charset=utf-8'
            UseBasicParsing = $true
        }
        Add-IntuneWinProxyParameter -Parameters $iwrParams
        $response = Invoke-WebRequest @iwrParams

        Write-Host -ForegroundColor Green "Azure Storage Response: StatusCode=$($response.StatusCode) StatusDescription=$($response.StatusDescription)"
        return $response
    }
    catch {
        Write-Host -ForegroundColor Red (Format-SafeSasMessage $request);
        Write-Host -ForegroundColor Red ("Error Message: " + (Format-SafeSasMessage $_.Exception.Message));

        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $reader.BaseStream.Position = 0
                $responseBody = $reader.ReadToEnd()
                Write-Host -ForegroundColor Red ("Response Body: " + (Format-SafeSasMessage $responseBody))
                $reader.Close()
            }
            catch {
                Write-Host -ForegroundColor Yellow "Could not read response body: $_"
            }
        }

        Write-Host -ForegroundColor Yellow "XML Content (first 500 chars): $($xml.Substring(0, [Math]::Min(500, $xml.Length)))"
        Write-Host -ForegroundColor Yellow "Block IDs in XML: $($ids -join ', ')"
        throw;
    }
}

####################################################

function Send-FileToAzureStorage($sasUri, $filepath, $fileUri) {

    try {

        # Fail fast with a clear message if the SAS URI is missing/blank. Without this guard
        # an empty $sasUri produces block URLs like "&comp=block&blockid=..." which fail with
        # the cryptic "Invalid URI: The hostname could not be parsed."
        if ([string]::IsNullOrWhiteSpace($sasUri)) {
            throw "Azure Storage SAS URI is empty — the file entry did not return an 'azureStorageUri'. Cannot upload."
        }

        $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb;

        # Start the timer for SAS URI renewal.
        $sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()

        # ── SAS readiness probe ──
        # Azure Storage stored-access-policy SAS tokens can take up to 30s to propagate.
        # A GET ?comp=blocklist on a non-existent blob returns 404 (BlobNotFound) when the
        # SAS is valid. Only a 403 indicates the SAS token hasn't propagated yet.
        $sasProbeRetries = 6
        $sasProbeWait = 10
        for ($probe = 1; $probe -le $sasProbeRetries; $probe++) {
            try {
                $probeParams = @{
                    Uri             = "$sasUri&comp=blocklist"
                    Method          = 'Get'
                    UseBasicParsing = $true
                }
                Add-IntuneWinProxyParameter -Parameters $probeParams
                Invoke-WebRequest @probeParams | Out-Null
                break
            }
            catch {
                $probeStatus = $null
                if ($_.Exception.Response) { $probeStatus = [int]$_.Exception.Response.StatusCode }
                if (-not $probeStatus -and $_.Exception.Message -match '\b(403|404)\b') { $probeStatus = [int]$Matches[1] }
                if ($probeStatus -eq 404) {
                    # 404 = SAS authenticated successfully, blob just doesn't exist yet — proceed
                    break
                }
                if ($probeStatus -eq 403 -and $probe -lt $sasProbeRetries) {
                    Write-Host "    SAS URI not ready yet (HTTP 403). Waiting ${sasProbeWait}s before retry ($probe/$sasProbeRetries)..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $sasProbeWait
                }
                elseif ($probe -eq $sasProbeRetries) {
                    Write-Host "    SAS URI failed readiness check after $sasProbeRetries probes — attempting upload anyway" -ForegroundColor Yellow
                }
                else {
                    # Non-auth error (e.g. 409) — SAS is valid, proceed
                    break
                }
            }
        }

        # Find the file size and open the file.
        $fileSize = (Get-Item $filepath).length;
        $chunks = [Math]::Ceiling($fileSize / $chunkSizeInBytes);
        $reader = New-Object System.IO.BinaryReader([System.IO.File]::Open($filepath, [System.IO.FileMode]::Open));
        $null = $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin);

        # Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed.
        $ids = @();

        for ($chunk = 0; $chunk -lt $chunks; $chunk++) {

            $id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString("0000")));
            $ids += $id;

            $start = $chunk * $chunkSizeInBytes;
            $length = [Math]::Min($chunkSizeInBytes, $fileSize - $start);
            $bytes = $reader.ReadBytes($length);

            $currentChunk = $chunk + 1;

            Write-Progress -Activity "Uploading File to Azure Storage" -Status "Uploading chunk $currentChunk of $chunks" `
                -PercentComplete ($currentChunk / $chunks * 100)

            # Retry chunk upload with SAS renewal on auth failures and transient storage errors
            $chunkRetries = 5
            for ($attempt = 1; $attempt -le $chunkRetries; $attempt++) {
                try {
                    $null = Send-AzureStorageChunk $sasUri $id $bytes
                    break
                }
                catch {
                    $httpStatus = $null
                    if ($_.Exception.Response) {
                        $httpStatus = [int]$_.Exception.Response.StatusCode
                    }
                    if (-not $httpStatus -and $_.Exception.Message -match 'status code[^\d]*(\d{3})') {
                        $httpStatus = [int]$Matches[1]
                    }
                    if ($httpStatus -eq 403 -and $attempt -lt $chunkRetries) {
                        Write-Host "    Storage auth failed (403) on chunk $currentChunk. Renewing SAS URI (attempt $attempt/$chunkRetries)..." -ForegroundColor Yellow
                        Start-Sleep -Seconds 10
                        $null = Update-AzureStorageUpload $fileUri
                        $sasRenewalTimer.Restart()
                        Start-Sleep -Seconds 5
                    }
                    elseif ($httpStatus -in @(500, 502, 503, 504) -and $attempt -lt $chunkRetries) {
                        # Transient Azure Storage errors — wait with exponential backoff and retry the chunk
                        $storageBackoff = 10 * [Math]::Pow(2, $attempt - 1)
                        Write-Host "    Transient storage error ($httpStatus) on chunk $currentChunk. Waiting ${storageBackoff}s before retry (attempt $attempt/$chunkRetries)..." -ForegroundColor Yellow
                        Start-Sleep -Seconds $storageBackoff
                    }
                    else {
                        throw
                    }
                }
            }

            # Renew the SAS URI if 7 minutes have elapsed since the upload started or was renewed last.
            if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000) {

                $null = Update-AzureStorageUpload $fileUri
                $sasRenewalTimer.Restart()

            }

        }

        Write-Progress -Completed -Activity "Uploading File to Azure Storage"

        $reader.Close();

    }

    finally {

        if ($null -ne $reader) { $reader.Dispose(); }

    }

    # Finalize the upload.
    Write-Host -ForegroundColor Magenta "`nPreparing to finalize upload with $($ids.Count) blocks..."
    Write-Host -ForegroundColor Magenta "Block IDs: $($ids -join ', ')"
    $null = Complete-AzureStorageUpload $sasUri $ids
    Write-Host -ForegroundColor Green "Finalize completed successfully!"

}

####################################################

function Update-AzureStorageUpload($fileUri) {

    $renewalUri = "$fileUri/renewUpload";
    $actionBody = "";
    $null = Invoke-PostRequest $renewalUri $actionBody;

    $null = Wait-FileProcessing $fileUri "AzureStorageUriRenewal" $azureStorageRenewSasUriBackOffTimeInSeconds;

}

####################################################

function Wait-FileProcessing($fileUri, $stage) {

    Write-Host "Wait-FileProcessing: $fileUri" -ForegroundColor Cyan

    # Hardened watchdog: 60 polls * 10 s = 10 min target, capped by a 20 min wall-clock,
    # with up to 3 retries on transient 'Failed' states.
    $maxAttempts = 60
    $waitTimeInSeconds = 10
    $maxWallClockMinutes = 20
    $maxFailedRetries = 3

    $successState = "$($stage)Success"
    $pendingState = "$($stage)Pending"
    $failedState = "$($stage)Failed"

    $wallClock = [System.Diagnostics.Stopwatch]::StartNew()
    $failedRetries = 0
    $attempt = 0
    $file = $null

    while ($attempt -lt $maxAttempts -and $wallClock.Elapsed.TotalMinutes -lt $maxWallClockMinutes) {
        $attempt++
        $file = Invoke-GetRequest $fileUri

        $currentState = if ($file) { [string]$file.uploadState } else { '<null>' }
        Write-Host "  Poll $attempt/$maxAttempts (elapsed $([int]$wallClock.Elapsed.TotalSeconds)s): uploadState='$currentState'" -ForegroundColor Yellow

        if ($currentState -eq $successState) {
            Write-Host "  Stage '$stage' reached success after $attempt polls / $([int]$wallClock.Elapsed.TotalSeconds)s." -ForegroundColor Green
            return $file
        }
        elseif ($currentState -eq $failedState) {
            $failedRetries++
            if ($failedRetries -gt $maxFailedRetries) {
                throw "File upload state '$currentState' failed $failedRetries times for stage '$stage' (uri: $fileUri)."
            }
            Write-Host "  Stage '$stage' returned '$currentState' (retry $failedRetries/$maxFailedRetries) — backing off ${waitTimeInSeconds}s..." -ForegroundColor Red
        }
        elseif ($currentState -ne $pendingState) {
            throw "File upload state is not successful: '$currentState' for stage '$stage' (uri: $fileUri)."
        }

        Start-Sleep -Seconds $waitTimeInSeconds
    }

    $wallClock.Stop()
    throw "File processing watchdog timed out after $attempt polls / $([int]$wallClock.Elapsed.TotalSeconds)s for stage '$stage' (uri: $fileUri)."
}

####################################################

function Get-Win32AppBody() {

    param
    (

        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 1)]
        [Switch]$MSI,

        [parameter(Mandatory = $true, ParameterSetName = "EXE", Position = 1)]
        [Switch]$EXE,

        [parameter(Mandatory = $true, ParameterSetName = "Edge", Position = 1)]
        [Switch]$Edge,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$displayName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$displayVersion,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$publisher,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$description,

        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        #[parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Category,

        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        #[parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$filename,

        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        #[parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SetupFileName,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        #[parameter()]
        [ValidateSet('system', 'user')]
        $installExperience = "system",

        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [parameter(Mandatory = $false, ParameterSetName = "MSI")]
        #[parameter(Mandatory = $false)]
        [string]$logo,

        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        $installCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        $uninstallCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiPackageType,

        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiProductCode,

        [parameter(Mandatory = $false, ParameterSetName = "MSI")]
        $MsiProductName,

        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiProductVersion,

        [parameter(Mandatory = $false, ParameterSetName = "MSI")]
        $MsiPublisher,

        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiRequiresReboot,

        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiUpgradeCode,

        [parameter(ParameterSetName = "MSI")]
        $msiInstallCommandLine,

        [parameter(ParameterSetName = "MSI")]
        $msiUninstallCommandLine,

        [parameter(ParameterSetName = "Edge")]
        [string] $channel,

        # New optional parameters for extended Win32 app settings
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [bool]$isFeatured = $false,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [string]$informationUrl,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [string]$privacyInformationUrl,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [string]$developer,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [string]$owner,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [string]$notes,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [int]$maxRunTimeInMinutes = 60,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [ValidateSet('basedOnReturnCode', 'allow', 'suppress', 'force')]
        [string]$deviceRestartBehavior = 'suppress',

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [int]$minimumFreeDiskSpaceInMB,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [int]$minimumMemoryInMB,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [int]$minimumNumberOfProcessors,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [int]$minimumCpuSpeedInMHz,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [ValidateSet('', 'none', 'x86', 'x64', 'arm', 'arm64', 'x64,x86', 'x86,x64', 'x86,arm', 'x64,arm64')]
        [string]$allowedArchitectures,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [string]$minimumSupportedOS,

        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "MSI")]
        [array]$requirementRules

    )

    if ($MSI) {

        $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" };
        $body.applicableArchitectures = "x64,x86";
        $body.description = $description;
        $body.developer = if ($developer) { $developer } else { "" };
        $body.displayName = $displayName;
        $body.displayVersion = $displayVersion;
        $body.fileName = $filename;
        if ( ! ( Test-Null ( $msiInstallCommandLine ) ) ) {
            $body.installCommandLine = "msiexec /i `"$SetupFileName`" $msiInstallCommandLine"
        }
        else {
            $body.installCommandLine = "msiexec /i `"$SetupFileName`""
        }
        $body.installExperience = @{
            "runAsAccount"          = "$installExperience"
            "maxRunTimeInMinutes"   = $maxRunTimeInMinutes
            "deviceRestartBehavior" = $deviceRestartBehavior
        };
        $body.informationUrl = if ($informationUrl) { $informationUrl } else { $null };
        $body.isFeatured = $isFeatured;

        # Handle minimum OS - use provided or default
        if ($minimumSupportedOS) {
            $osResult = Get-MinimumOperatingSystemObject -MinimumOS $minimumSupportedOS
            if ($null -ne $osResult.osObject) {
                $body.minimumSupportedOperatingSystem = $osResult.osObject
            }
            if ($osResult.windowsRelease) {
                $body.minimumSupportedWindowsRelease = $osResult.windowsRelease
            }
        }
        else {
            $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true };
        }

        $body.msiInformation = @{
            "packageType"    = "$MsiPackageType";
            "productCode"    = "$MsiProductCode";
            "productName"    = "$MsiProductName";
            "productVersion" = "$MsiProductVersion";
            "publisher"      = "$MsiPublisher";
            "requiresReboot" = "$MsiRequiresReboot";
            "upgradeCode"    = "$MsiUpgradeCode"
        };
        $body.notes = if ($notes) { $notes } else { "" };
        $body.owner = if ($owner) { $owner } else { "" };
        $body.privacyInformationUrl = if ($privacyInformationUrl) { $privacyInformationUrl } else { $null };
        $body.publisher = $publisher;
        $body.runAs32bit = $false;
        $body.setupFilePath = $SetupFileName;
        if ( ! ( Test-Null ( $msiUninstallCommandLine ) ) ) {
            $body.uninstallCommandLine = "msiexec /x `"$MsiProductCode`" $msiUninstallCommandLine"
        }
        else {
            $body.uninstallCommandLine = "msiexec /x `"$MsiProductCode`""
        }
        $body.allowAvailableUninstall = $script:AllowAvailableUninstall
        if (-not [string]::IsNullOrWhiteSpace($logo)) {
            # Determine image MIME type from logo file extension
            $logoImageType = "image/png"
            if (-not [string]::IsNullOrWhiteSpace($script:LogoFile)) {
                $logoExt = [System.IO.Path]::GetExtension($script:LogoFile).ToLower()
                if ($logoExt -in @('.jpg', '.jpeg')) { $logoImageType = "image/jpeg" }
            }
            $body.largeIcon = @{"type" = $logoImageType; "value" = $logo }
        }

        # Add optional system requirement properties if specified
        if ($minimumFreeDiskSpaceInMB -and $minimumFreeDiskSpaceInMB -gt 0) {
            $body.minimumFreeDiskSpaceInMB = $minimumFreeDiskSpaceInMB
        }
        if ($minimumMemoryInMB -and $minimumMemoryInMB -gt 0) {
            $body.minimumMemoryInMB = $minimumMemoryInMB
        }
        if ($minimumNumberOfProcessors -and $minimumNumberOfProcessors -gt 0) {
            $body.minimumNumberOfProcessors = $minimumNumberOfProcessors
        }
        if ($minimumCpuSpeedInMHz -and $minimumCpuSpeedInMHz -gt 0) {
            $body.minimumCpuSpeedInMHz = $minimumCpuSpeedInMHz
        }
        if ($allowedArchitectures) {
            $body.allowedArchitectures = $allowedArchitectures
        }
        if ($requirementRules -and $requirementRules.Count -gt 0) {
            $body.requirementRules = $requirementRules
        }

    }

    elseif ($EXE) {
        #"deviceRestartBehavior": "basedOnReturnCode" = Determine behavior based on return codes
        #"deviceRestartBehavior": "suppress" = No specific action
        #"deviceRestartBehavior": "allow" = App install may force a device restart
        #"deviceRestartBehavior": "force" = Intune will force a mandatory device restart

        $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" };
        $body.description = $description;
        $body.developer = if ($developer) { $developer } else { "" };
        $body.displayName = $displayName;
        $body.displayVersion = $displayVersion;
        $body.fileName = $filename;
        $body.installCommandLine = "$installCommandLine"
        $body.installExperience = @{
            "runAsAccount"          = "$installExperience"
            "maxRunTimeInMinutes"   = $maxRunTimeInMinutes
            "deviceRestartBehavior" = $deviceRestartBehavior
        };
        $body.informationUrl = if ($informationUrl) { $informationUrl } else { $null };
        $body.isFeatured = $isFeatured;

        # Handle minimum OS - use provided or default
        if ($minimumSupportedOS) {
            $osResult = Get-MinimumOperatingSystemObject -MinimumOS $minimumSupportedOS
            if ($null -ne $osResult.osObject) {
                $body.minimumSupportedOperatingSystem = $osResult.osObject
            }
            if ($osResult.windowsRelease) {
                $body.minimumSupportedWindowsRelease = $osResult.windowsRelease
            }
        }
        else {
            $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true };
        }

        $body.msiInformation = $null;
        $body.notes = if ($notes) { $notes } else { "" };
        $body.owner = if ($owner) { $owner } else { "" };
        $body.privacyInformationUrl = if ($privacyInformationUrl) { $privacyInformationUrl } else { $null };
        $body.publisher = $publisher;
        $body.runAs32bit = $false;
        $body.setupFilePath = $SetupFileName;
        $body.uninstallCommandLine = "$uninstallCommandLine";
        $body.allowAvailableUninstall = $script:AllowAvailableUninstall
        if (-not [string]::IsNullOrWhiteSpace($logo)) {
            # Determine image MIME type from logo file extension
            $logoImageType = "image/png"
            if (-not [string]::IsNullOrWhiteSpace($script:LogoFile)) {
                $logoExt = [System.IO.Path]::GetExtension($script:LogoFile).ToLower()
                if ($logoExt -in @('.jpg', '.jpeg')) { $logoImageType = "image/jpeg" }
            }
            $body.largeIcon = @{"type" = $logoImageType; "value" = $logo }
        }

        # Add optional system requirement properties if specified
        if ($minimumFreeDiskSpaceInMB -and $minimumFreeDiskSpaceInMB -gt 0) {
            $body.minimumFreeDiskSpaceInMB = $minimumFreeDiskSpaceInMB
        }
        if ($minimumMemoryInMB -and $minimumMemoryInMB -gt 0) {
            $body.minimumMemoryInMB = $minimumMemoryInMB
        }
        if ($minimumNumberOfProcessors -and $minimumNumberOfProcessors -gt 0) {
            $body.minimumNumberOfProcessors = $minimumNumberOfProcessors
        }
        if ($minimumCpuSpeedInMHz -and $minimumCpuSpeedInMHz -gt 0) {
            $body.minimumCpuSpeedInMHz = $minimumCpuSpeedInMHz
        }
        if ($allowedArchitectures) {
            $body.allowedArchitectures = $allowedArchitectures
        }
        if ($requirementRules -and $requirementRules.Count -gt 0) {
            $body.requirementRules = $requirementRules
        }

    }
    elseif ($Edge) {
        Write-Log -Message 'Building out Edge ODATA construct'
        $body = @{ "@odata.type" = "#microsoft.graph.windowsMicrosoftEdgeApp" };
        $body.displayName = $displayName;
        $body.description = $Description;
        $body.publisher = $Publisher;
        $body.largeIcon = $null;
        $body.isFeatured = $false;
        $body.privacyInformationUrl = "https://privacy.microsoft.com/en-US/privacystatement";
        $body.informationUrl = "https://www.microsoft.com/en-us/windows/microsoft-edge";
        $body.owner = "Microsoft";
        $body.developer = "Microsoft";
        $body.notes = "";
        #$body.uploadState = 1;
        #$body.publishingState = "published";
        $body.channel = $channel;
        $body.displayLanguageLocale = $null
    }

    $body;
}

####################################################

function Get-AppFileBody($name, $size, $sizeEncrypted, $manifest) {

    $body = @{ "@odata.type" = "#microsoft.graph.mobileAppContentFile" };
    $body.name = $name;
    $body.size = $size;
    $body.sizeEncrypted = $sizeEncrypted;
    $body.manifest = $manifest;
    $body.isDependency = $false;

    $body;
}

####################################################

function Get-AppCommitBody($contentVersionId, $LobType) {

    $body = @{ "@odata.type" = "#$LobType" };
    $body.committedContentVersion = $contentVersionId;

    $body;

}

####################################################

function Test-SourceFile() {

    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $SourceFile
    )

    try {

        if (!(Test-Path "$SourceFile")) {

            Write-Host
            Write-Host "Source File '$sourceFile' doesn't exist..." -ForegroundColor Red
            throw "Source file not found: $SourceFile"

        }

    }

    catch {

        Write-Host -ForegroundColor Red $_.Exception.Message;
        Write-Host
        $script:exitCode = 1
        throw

    }

}

####################################################

function New-DetectionRule() {

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true, ParameterSetName = "PowerShell", Position = 1)]
        [Switch]$PowerShell,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 1)]
        [Switch]$MSI,

        [parameter(Mandatory = $true, ParameterSetName = "File", Position = 1)]
        [Switch]$File,

        [parameter(Mandatory = $true, ParameterSetName = "Registry", Position = 1)]
        [Switch]$Registry,

        [parameter(Mandatory = $true, ParameterSetName = "PowerShell")]
        [ValidateNotNullOrEmpty()]
        [String]$ScriptFile,

        [parameter(Mandatory = $true, ParameterSetName = "PowerShell")]
        [ValidateNotNullOrEmpty()]
        $enforceSignatureCheck,

        [parameter(Mandatory = $true, ParameterSetName = "PowerShell")]
        [ValidateNotNullOrEmpty()]
        $runAs32Bit,

        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        [String]$MSIproductCode,

        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateSet("notConfigured", "equal", "notEqual", "greaterThan", "greaterThanOrEqual", "lessThan", "lessThanOrEqual")]
        [String]$MSIproductVersionOperator,

        [parameter(Mandatory = $false, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        [String]$MSIproductVersion = $null,

        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateNotNullOrEmpty()]
        [String]$Path,

        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateNotNullOrEmpty()]
        [string]$FileOrFolderName,

        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateSet("notConfigured", "exists", "modifiedDate", "createdDate", "version", "sizeInMB", "doesNotExist")]
        [string]$FileDetectionType,

        [parameter(Mandatory = $false, ParameterSetName = "File")]
        [ValidateSet("notConfigured", "equal", "notEqual", "greaterThan", "greaterThanOrEqual", "lessThan", "lessThanOrEqual")]
        [string]$FileDetectionOperator = "notConfigured",

        [parameter(Mandatory = $false, ParameterSetName = "File")]
        [string]$FileDetectionValue = $null,

        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateSet("True", "False")]
        [string]$check32BitOn64System = "False",

        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateNotNullOrEmpty()]
        [String]$RegistryKeyPath,

        [parameter(Mandatory = $false, ParameterSetName = "Registry")]
        [ValidateNotNullOrEmpty()]
        [String]$RegistryValue,

        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateSet("notConfigured", "exists", "doesNotExist", "string", "integer", "version")]
        [string]$RegistryDetectionType,

        [parameter(Mandatory = $false, ParameterSetName = "Registry")]
        [ValidateSet("notConfigured", "equal", "notEqual", "greaterThan", "greaterThanOrEqual", "lessThan", "lessThanOrEqual")]
        [string]$RegistryDetectionOperator = "notConfigured",

        [parameter(Mandatory = $false, ParameterSetName = "Registry")]
        [string]$RegistryDetectionValue = $null,

        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateSet("True", "False")]
        [string]$check32BitRegOn64System = "False"

    )

    if ($PowerShell) {

        if (!(Test-Path "$ScriptFile")) {

            Write-Host
            Write-Host "Could not find file '$ScriptFile'..." -ForegroundColor Red
            Write-Host "Script can't continue..." -ForegroundColor Red
            Write-Host
            $script:exitCode = 1
            throw "Detection script file not found: $ScriptFile"

        }

        $ScriptContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$ScriptFile"));

        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptDetection" }
        $DR.enforceSignatureCheck = $enforceSignatureCheck;
        $DR.runAs32Bit = $runAs32Bit;
        $DR.scriptContent = "$ScriptContent";

    }

    elseif ($MSI) {

        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppProductCodeDetection" }
        $DR.productVersionOperator = "$MSIproductVersionOperator";
        $DR.productCode = "$MsiProductCode";
        $DR.productVersion = "$MSIproductVersion";

    }

    elseif ($File) {

        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppFileSystemDetection" }
        $DR.check32BitOn64System = "$check32BitOn64System";
        $DR.detectionType = "$FileDetectionType";
        $DR.detectionValue = "$FileDetectionValue";
        $DR.fileOrFolderName = "$FileOrFolderName";
        $DR.operator = "$FileDetectionOperator";
        $DR.path = "$Path"

    }

    elseif ($Registry) {

        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppRegistryDetection" }
        $DR.check32BitOn64System = "$check32BitRegOn64System";
        $DR.detectionType = "$RegistryDetectionType";
        $DR.detectionValue = "$RegistryDetectionValue";
        $DR.keyPath = "$RegistryKeyPath";
        $DR.operator = "$RegistryDetectionOperator";
        $DR.valueName = "$RegistryValue"

    }

    return $DR

}

####################################################

function Get-DefaultReturnCodes() {

    @{"returnCode" = 0; "type" = "success" }, `
    @{"returnCode" = 1707; "type" = "success" }, `
    @{"returnCode" = 3010; "type" = "softReboot" }, `
    @{"returnCode" = 1641; "type" = "hardReboot" }, `
    @{"returnCode" = 1618; "type" = "retry" }

}

####################################################

function New-ReturnCode() {

    param
    (
        [parameter(Mandatory = $true)]
        [int]$returnCode,
        [parameter(Mandatory = $true)]
        [ValidateSet('success', 'softReboot', 'hardReboot', 'retry')]
        $type
    )

    @{"returnCode" = $returnCode; "type" = "$type" }

}

####################################################

function Get-IntuneWinXML() {

    param
    (
        [Parameter(Mandatory = $true)]
        $SourceFile,

        [Parameter(Mandatory = $true)]
        $fileName,

        [Parameter(Mandatory = $false)]
        [ValidateSet("false", "true")]
        [string]$removeitem = "true"
    )

    Test-SourceFile "$SourceFile"

    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")

    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")

    $zip.Entries | Where-Object { $_.Name -like "$filename" } | ForEach-Object {

        Test-ZipEntrySafePath -EntryFullName $_.FullName -DestinationDir $Directory
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)

    }

    $zip.Dispose()

    [xml]$IntuneWinXML = Get-Content "$Directory\$filename"

    if ($removeitem -eq "true") { Remove-Item "$Directory\$filename" }

    return $IntuneWinXML

}

####################################################

function Get-IntuneWinFile() {

    param
    (
        [Parameter(Mandatory = $true)]
        $SourceFile,

        [Parameter(Mandatory = $true)]
        $fileName,

        [Parameter(Mandatory = $false)]
        [string]$Folder = "win32"
    )

    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")

    if (!(Test-Path "$Directory\$folder")) {

        New-Item -ItemType Directory -Path "$Directory" -Name "$folder" | Out-Null

    }

    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")

    $zip.Entries | Where-Object { $_.Name -like "$filename" } | ForEach-Object {

        Test-ZipEntrySafePath -EntryFullName $_.FullName -DestinationDir "$Directory\$folder"
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)

    }

    $zip.Dispose()

    if ($removeitem -eq "true") { Remove-Item "$Directory\$filename" -ErrorAction SilentlyContinue }

    return "$Directory\$folder\$filename"

}

####################################################

function Wait-AppPublishingState {
    <#
.SYNOPSIS
Polls an app's publishingState to verify it has reached 'published'.
.DESCRIPTION
Checks the publishingState of a Win32 app. If the app is stuck in 'notPublished'
after max attempts, returns $false to signal the caller to delete and recreate.
.PARAMETER AppId
The Intune app ID to check.
.PARAMETER DisplayName
Display name of the app (for logging).
.PARAMETER MaxAttempts
Maximum number of polling attempts (default: 6).
.PARAMETER WaitSeconds
Seconds between polls (default: 10).
.NOTES
NAME: Wait-AppPublishingState
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter(Mandatory)]
        [string]$DisplayName,

        [int]$MaxAttempts = 6,

        [int]$WaitSeconds = 10
    )

    for ($i = 0; $i -lt $MaxAttempts; $i++) {
        try {
            $app = Get-IntuneApplicationMG -ID ([guid]$AppId)
            if (-not $app) {
                Write-Host "    App '$DisplayName' no longer found in tenant — proceeding" -ForegroundColor Yellow
                return $true
            }
            $currentState = $app.publishingState
            if ($currentState -eq 'published') {
                if ($i -gt 0) {
                    Write-Host "    App '$DisplayName' reached 'published' state after $($i * $WaitSeconds)s" -ForegroundColor Green
                }
                return $true
            }
            Write-Host "    App '$DisplayName' (ID: $AppId) publishingState: '$currentState' — waiting for 'published' (poll $($i + 1)/$MaxAttempts)..." -ForegroundColor Yellow
        }
        catch {
            Write-Host "    Could not check publishingState for '$DisplayName': $($_.Exception.Message) — proceeding" -ForegroundColor Yellow
            return $true
        }
        Start-Sleep -Seconds $WaitSeconds
    }

    Write-Host "    App '$DisplayName' (ID: $AppId) STUCK in '$currentState' state after $($MaxAttempts * $WaitSeconds)s — will delete and recreate" -ForegroundColor Red
    return $false
}

####################################################

function Resolve-AppScriptPath {
    <#
.SYNOPSIS
Resolves a configured script path against the package folder
.DESCRIPTION
Rooted paths are used as supplied; anything else is treated as relative to the package folder, so
configs can say 'Scripts\Install.ps1'. Returns an empty string when nothing is configured.
.PARAMETER Path
The raw path from Config.xml/Config.json
.EXAMPLE
$full = Resolve-AppScriptPath -Path 'Scripts\Install.ps1'
.NOTES
NAME: Resolve-AppScriptPath
#>

    [cmdletbinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Path
    )

    process {
        if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
        $trimmed = $Path.Trim()
        if ([System.IO.Path]::IsPathRooted($trimmed)) { return $trimmed }
        return (Join-Path -Path $packagePath -ChildPath $trimmed)
    }
}

####################################################

function New-IntuneWin32AppScript {
    <#
.SYNOPSIS
Uploads a PowerShell install or uninstall script to a Win32 app content version
.DESCRIPTION
Creates a win32LobAppInstallPowerShellScript or win32LobAppUninstallPowerShellScript against the
app's content version and returns the new script ID. This backs the portal's Program tab
"Installer type: PowerShell script" / "Uninstaller type: PowerShell script" options.

The script is only stored here - it does not take effect until the app's activeInstallScript /
activeUninstallScript reference points at the returned ID (see Set-IntuneWin32AppScript).
.PARAMETER ApplicationId
The mobileApp ID
.PARAMETER ContentVersionId
The content version the script belongs to - the same content version used for the .intunewin upload
.PARAMETER ScriptType
'Install' or 'Uninstall'
.PARAMETER ScriptFile
Path to the .ps1 file to upload
.PARAMETER EnforceSignatureCheck
Require the script to be signed before it will run. Default is $false.
.PARAMETER RunAs32Bit
Run the script in a 32-bit PowerShell host. Default is $false (64-bit).
.EXAMPLE
$id = New-IntuneWin32AppScript -ApplicationId $appId -ContentVersionId $cv -ScriptType Install -ScriptFile 'C:\Pkg\Scripts\Install.ps1'
.NOTES
NAME: New-IntuneWin32AppScript
#>

    [cmdletbinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
        [string]$ContentVersionId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Install', 'Uninstall')]
        [string]$ScriptType,

        [Parameter(Mandatory = $true)]
        [string]$ScriptFile,

        [Parameter(Mandatory = $false)]
        [bool]$EnforceSignatureCheck = $false,

        [Parameter(Mandatory = $false)]
        [bool]$RunAs32Bit = $false
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        if (-not (Test-Path -Path $ScriptFile -PathType Leaf)) {
            Write-Log -Message "$ScriptType script not found: $ScriptFile" -LogLevel 3
            Write-Host "Error: $ScriptType script not found: $ScriptFile" -ForegroundColor Red
            throw "$ScriptType script not found: $ScriptFile"
        }

        $bytes = [System.IO.File]::ReadAllBytes($ScriptFile)
        $encoded = [System.Convert]::ToBase64String($bytes)

        # Graph caps the content property at 100KB, and content is the base64 form
        if ($encoded.Length -gt 102400) {
            throw ("$ScriptType script '{0}' is too large: {1:N0} bytes raw / {2:N0} base64 - Graph limits script content to 100KB." -f `
                (Split-Path $ScriptFile -Leaf), $bytes.Length, $encoded.Length)
        }

        $odataType = if ($ScriptType -eq 'Install') { '#microsoft.graph.win32LobAppInstallPowerShellScript' } else { '#microsoft.graph.win32LobAppUninstallPowerShellScript' }

        # 'id' and 'state' are read-only and must not be sent
        $scriptBody = [ordered]@{
            '@odata.type'           = $odataType
            'displayName'           = [System.IO.Path]::GetFileName($ScriptFile)
            'content'               = $encoded
            'enforceSignatureCheck' = $EnforceSignatureCheck
            'runAs32Bit'            = $RunAs32Bit
        }
        $json = $scriptBody | ConvertTo-Json -Depth 5

        Write-Log -Message "Uploading $ScriptType script '$ScriptFile' ($($bytes.Length) bytes) to content version $ContentVersionId"

        if (-not $PSCmdlet.ShouldProcess($ApplicationId, "Upload $ScriptType PowerShell script '$(Split-Path $ScriptFile -Leaf)'")) {
            return $null
        }

        # contentVersions normally needs the win32LobApp cast; the documented path omits it, so try both
        $uris = @(
            "mobileApps/$ApplicationId/microsoft.graph.win32LobApp/contentVersions/$ContentVersionId/scripts"
            "mobileApps/$ApplicationId/contentVersions/$ContentVersionId/scripts"
        )

        $response = $null
        $lastError = $null
        foreach ($uri in $uris) {
            try {
                $response = Invoke-PostRequest $uri $json
                break
            }
            catch {
                $lastError = $_
                Write-Log -Message "Script upload via '$uri' failed: $($_.Exception.Message)" -LogLevel 2
            }
        }

        if ($null -eq $response -or [string]::IsNullOrWhiteSpace([string]$response.id)) {
            throw "Failed to upload $ScriptType script '$(Split-Path $ScriptFile -Leaf)': $($lastError.Exception.Message)"
        }

        if ($response.state -eq 'commitFailed') {
            throw "$ScriptType script '$(Split-Path $ScriptFile -Leaf)' was rejected by Intune (state: commitFailed)"
        }

        Write-Log -Message "$ScriptType script uploaded - ID: $($response.id), state: $($response.state)"
        Write-Host "  $ScriptType script uploaded: $(Split-Path $ScriptFile -Leaf) (state: $($response.state))" -ForegroundColor Green
        return [string]$response.id
    }
}

####################################################

function Set-IntuneWin32AppScript {
    <#
.SYNOPSIS
Applies the configured PowerShell install and/or uninstall scripts to a Win32 app
.DESCRIPTION
Uploads whichever of the install/uninstall scripts are configured, then points the app's
activeInstallScript / activeUninstallScript at them. Install and uninstall are independent, so all
four portal combinations work: script+script, script+command, command+script, command+command
(the last being the default when no script is configured).

Where a script is set, Intune ignores the corresponding command line - Graph documents the
reference as "when null, the install command line is used instead".
.PARAMETER ApplicationId
The mobileApp ID
.PARAMETER ContentVersionId
The content version the scripts belong to
.PARAMETER InstallScriptFile
Optional path to the install .ps1
.PARAMETER UninstallScriptFile
Optional path to the uninstall .ps1
.PARAMETER InstallScriptEnforceSignatureCheck
Require the install script to be signed
.PARAMETER InstallScriptRunAs32Bit
Run the install script in a 32-bit PowerShell host
.PARAMETER UninstallScriptEnforceSignatureCheck
Require the uninstall script to be signed
.PARAMETER UninstallScriptRunAs32Bit
Run the uninstall script in a 32-bit PowerShell host
.EXAMPLE
Set-IntuneWin32AppScript -ApplicationId $appId -ContentVersionId $cv -InstallScriptFile 'C:\Pkg\Install.ps1'
.NOTES
NAME: Set-IntuneWin32AppScript
#>

    [cmdletbinding(SupportsShouldProcess = $true)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
        [string]$ContentVersionId,

        [Parameter(Mandatory = $false)]
        [string]$InstallScriptFile,

        [Parameter(Mandatory = $false)]
        [string]$UninstallScriptFile,

        [Parameter(Mandatory = $false)]
        [bool]$InstallScriptEnforceSignatureCheck = $false,

        [Parameter(Mandatory = $false)]
        [bool]$InstallScriptRunAs32Bit = $false,

        [Parameter(Mandatory = $false)]
        [bool]$UninstallScriptEnforceSignatureCheck = $false,

        [Parameter(Mandatory = $false)]
        [bool]$UninstallScriptRunAs32Bit = $false
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        $hasInstall = -not [string]::IsNullOrWhiteSpace($InstallScriptFile)
        $hasUninstall = -not [string]::IsNullOrWhiteSpace($UninstallScriptFile)
        if (-not $hasInstall -and -not $hasUninstall) { return $true }

        Write-Host
        Write-Host "Applying PowerShell script installer settings..." -ForegroundColor Cyan

        $reference = [ordered]@{}

        if ($hasInstall) {
            $installId = New-IntuneWin32AppScript -ApplicationId $ApplicationId -ContentVersionId $ContentVersionId `
                -ScriptType 'Install' -ScriptFile $InstallScriptFile `
                -EnforceSignatureCheck $InstallScriptEnforceSignatureCheck -RunAs32Bit $InstallScriptRunAs32Bit
            if ($installId) {
                $reference['activeInstallScript'] = [ordered]@{
                    '@odata.type' = 'microsoft.graph.mobileAppScriptReference'
                    'targetId'    = $installId
                }
            }
        }

        if ($hasUninstall) {
            $uninstallId = New-IntuneWin32AppScript -ApplicationId $ApplicationId -ContentVersionId $ContentVersionId `
                -ScriptType 'Uninstall' -ScriptFile $UninstallScriptFile `
                -EnforceSignatureCheck $UninstallScriptEnforceSignatureCheck -RunAs32Bit $UninstallScriptRunAs32Bit
            if ($uninstallId) {
                $reference['activeUninstallScript'] = [ordered]@{
                    '@odata.type' = 'microsoft.graph.mobileAppScriptReference'
                    'targetId'    = $uninstallId
                }
            }
        }

        if ($reference.Count -eq 0) { return $false }

        $reference['@odata.type'] = '#microsoft.graph.win32LobApp'
        $json = $reference | ConvertTo-Json -Depth 5

        if (-not $PSCmdlet.ShouldProcess($ApplicationId, "Activate PowerShell script installer ($($reference.Keys -join ', '))")) {
            return $true
        }

        try {
            Invoke-PatchRequest "mobileApps/$ApplicationId" $json | Out-Null
        }
        catch {
            Write-Log -Message "Failed to activate PowerShell script installer: $($_.Exception.Message)" -LogLevel 3
            Write-Host "Error: uploaded the script(s) but could not activate them - $($_.Exception.Message)" -ForegroundColor Red
            throw
        }

        if ($reference.Contains('activeInstallScript')) {
            Write-Host "  Install uses PowerShell script (install command line ignored)" -ForegroundColor Green
        }
        if ($reference.Contains('activeUninstallScript')) {
            Write-Host "  Uninstall uses PowerShell script (uninstall command line ignored)" -ForegroundColor Green
        }
        Write-Log -Message "PowerShell script installer activated for app $ApplicationId"
        return $true
    }
}

####################################################

function Send-Win32Lob() {

    <#
.SYNOPSIS
This function is used to upload a Win32 Application to the Intune Service
.DESCRIPTION
This function is used to upload a Win32 Application to the Intune Service. Supports -WhatIf to preview the operation.
.EXAMPLE
Send-Win32Lob "C:\Packages\package.intunewin" -publisher "Microsoft" -description "Package"
This example uses all parameters required to add an intunewin File into the Intune Service
.NOTES
NAME: Send-Win32Lob
#>

    [cmdletbinding(SupportsShouldProcess = $true)]

    param
    (
        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 1)]
        [Switch] $MSI,

        [parameter(Mandatory = $true, ParameterSetName = "EXE", Position = 1)]
        [Switch] $EXE,

        [parameter(Mandatory = $true, ParameterSetName = "PS1", Position = 1)]
        [Switch] $PS1,

        [parameter(Mandatory = $true, ParameterSetName = "Edge", Position = 1)]
        [Switch] $Edge,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 1)]
        [parameter(Mandatory = $true, ParameterSetName = "EXE", Position = 1)]
        [parameter(Mandatory = $true, ParameterSetName = "PS1", Position = 1)]
        #[parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $SourceFile,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $displayName,

        [parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $publisher,

        [parameter(Mandatory = $true, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $description,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 4)]
        [parameter(Mandatory = $true, ParameterSetName = "EXE", Position = 4)]
        [parameter(Mandatory = $true, ParameterSetName = "PS1", Position = 4)]
        #[parameter(Mandatory = $true, Position = 4)]
        [ValidateNotNullOrEmpty()]
        $detectionRules,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 5)]
        [parameter(Mandatory = $true, ParameterSetName = "EXE", Position = 5)]
        [parameter(Mandatory = $true, ParameterSetName = "PS1", Position = 5)]
        #[parameter(Mandatory = $true, Position = 5)]
        [ValidateNotNullOrEmpty()]
        $returnCodes,

        [parameter(ParameterSetName = "MSI", Position = 6)]
        [parameter(ParameterSetName = "EXE", Position = 6)]
        [parameter(ParameterSetName = "PS1", Position = 6)]
        #[parameter(Mandatory = $false, Position = 6)]
        [ValidateSet('system', 'user')]
        [string] $installExperience = "system",

        [parameter(Mandatory = $false, ParameterSetName = "MSI", Position = 7)]
        [parameter(Mandatory = $false, ParameterSetName = "EXE", Position = 7)]
        [parameter(Mandatory = $false, ParameterSetName = "PS1", Position = 7)]
        #[parameter(Mandatory = $false, Position = 7)]
        $logo,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 8)]
        [parameter(Mandatory = $true, ParameterSetName = "EXE", Position = 8)]
        [parameter(Mandatory = $true, ParameterSetName = "PS1", Position = 8)]
        #[parameter(Mandatory = $true, Position = 8)]
        [ValidateNotNullOrEmpty()]
        [string] $Category,

        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string] $installCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string] $uninstallCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "PS1")]
        [ValidateNotNullOrEmpty()]
        [string] $ps1InstallCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "PS1")]
        [ValidateNotNullOrEmpty()]
        [string] $ps1UninstallCommandLine,

        [parameter(ParameterSetName = "MSI")]
        [string] $msiInstallCommandLine,

        [parameter(ParameterSetName = "MSI")]
        [string] $msiUninstallCommandLine,

        [parameter(ParameterSetName = "Edge")]
        [string] $channel,

        # Extended Settings - App Information
        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [bool] $isFeatured = $false,

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [string] $informationUrl = "",

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [string] $privacyInformationUrl = "",

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [string] $developer = "",

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [string] $owner = "",

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [string] $notes = "",

        # Extended Settings - Install Experience
        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [int] $maxRunTimeInMinutes = 60,

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [ValidateSet('basedOnReturnCode', 'allow', 'suppress', 'force')]
        [string] $deviceRestartBehavior = "suppress",

        # Extended Settings - System Requirements
        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [int] $minimumFreeDiskSpaceInMB = 0,

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [int] $minimumMemoryInMB = 0,

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [int] $minimumNumberOfProcessors = 0,

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [int] $minimumCpuSpeedInMHz = 0,

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [string] $allowedArchitectures = "",

        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [string] $minimumSupportedOS = "",

        # Extended Settings - Requirement Rules
        [parameter(ParameterSetName = "MSI")]
        [parameter(ParameterSetName = "EXE")]
        [parameter(ParameterSetName = "PS1")]
        [array] $requirementRules = @()
    )

    try	{

        # Check WhatIf before performing upload operation
        if (-not $PSCmdlet.ShouldProcess("Application '$displayName'", "Upload to Intune")) {
            Write-Host "WhatIf: Would upload application '$displayName' to Intune" -ForegroundColor Cyan
            Write-Log -Message "WhatIf: Would upload application '$displayName' to Intune"
            return
        }

        $LOBType = "microsoft.graph.win32LobApp"
        Write-Host
        Write-Host "Creating JSON data to pass to the service..." -ForegroundColor Yellow

        if ( $AppType -ne "Edge" ) {
            Write-Host "Testing if SourceFile '$SourceFile' Path is valid..." -ForegroundColor Yellow
            Test-SourceFile "$SourceFile"
            #$Win32Path = "$SourceFile"

            # Function to read Win32LOB file
            $DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

            # If displayName input don't use Name from detection.xml file
            if ($displayName) { $DisplayName = $displayName }
            else { $DisplayName = $DetectionXML.ApplicationInfo.Name }

            $FileName = $DetectionXML.ApplicationInfo.FileName

            $SetupFileName = $DetectionXML.ApplicationInfo.SetupFile

            #$Ext = [System.IO.Path]::GetExtension($SetupFileName)
        }
        #if((($Ext).contains("msi") -or ($Ext).contains("Msi")) -and (!$installCmdLine -or !$uninstallCmdLine)){
        if ($MSI) {
            # MSI
            $MsiExecutionContext = $DetectionXML.ApplicationInfo.MsiInfo.MsiExecutionContext
            $MsiPackageType = "DualPurpose";
            if ($MsiExecutionContext -eq "System") { $MsiPackageType = "PerMachine" }
            elseif ($MsiExecutionContext -eq "User") { $MsiPackageType = "PerUser" }

            $MsiProductCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode
            $MsiProductVersion = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion
            $MsiPublisher = $DetectionXML.ApplicationInfo.MsiInfo.MsiPublisher
            $MsiRequiresReboot = $DetectionXML.ApplicationInfo.MsiInfo.MsiRequiresReboot
            $MsiUpgradeCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiUpgradeCode

            if ($MsiRequiresReboot -eq "false") { $MsiRequiresReboot = $false }
            elseif ($MsiRequiresReboot -eq "true") { $MsiRequiresReboot = $true }

            $MSIRule = New-DetectionRule -MSI -MSIproductCode $MsiProductCode -MSIproductVersionOperator "equal" -MSIproductVersion $MsiProductVersion

            Write-Log -Message "MSIRule: [$($MSIRule.GetEnumerator() | ForEach-Object {"$($_.Key):$($_.Value)"})]"

            # Creating Array for detection Rule
            $detectionRules = @($MSIRule)

            if ( ! ($null -eq $msiInstallCommandLine ) ) {
                $mobileAppBody = Get-Win32AppBody `
                    -MSI `
                    -displayName "$DisplayName" `
                    -displayVersion "$DisplayVersion" `
                    -publisher "$publisher" `
                    -description $description `
                    -category $Category `
                    -filename $FileName `
                    -SetupFileName "$SetupFileName" `
                    -installExperience $installExperience `
                    -MsiPackageType $MsiPackageType `
                    -MsiProductCode $MsiProductCode `
                    -MsiProductName $displayName `
                    -MsiProductVersion $MsiProductVersion `
                    -MsiPublisher $MsiPublisher `
                    -MsiRequiresReboot $MsiRequiresReboot `
                    -MsiUpgradeCode $MsiUpgradeCode `
                    -logo $logo `
                    -msiInstallCommandLine $msiInstallCommandLine `
                    -msiUninstallCommandLine $msiUninstallCommandLine `
                    -isFeatured $isFeatured `
                    -informationUrl $informationUrl `
                    -privacyInformationUrl $privacyInformationUrl `
                    -developer $developer `
                    -owner $owner `
                    -notes $notes `
                    -maxRunTimeInMinutes $maxRunTimeInMinutes `
                    -deviceRestartBehavior $deviceRestartBehavior `
                    -minimumFreeDiskSpaceInMB $minimumFreeDiskSpaceInMB `
                    -minimumMemoryInMB $minimumMemoryInMB `
                    -minimumNumberOfProcessors $minimumNumberOfProcessors `
                    -minimumCpuSpeedInMHz $minimumCpuSpeedInMHz `
                    -allowedArchitectures $allowedArchitectures `
                    -minimumSupportedOS $minimumSupportedOS `
                    -requirementRules $requirementRules
            }
            else {
                $mobileAppBody = Get-Win32AppBody `
                    -MSI `
                    -displayName "$DisplayName" `
                    -displayVersion "$DisplayVersion" `
                    -publisher "$publisher" `
                    -description $description `
                    -category $Category `
                    -filename $FileName `
                    -SetupFileName "$SetupFileName" `
                    -installExperience $installExperience `
                    -MsiPackageType $MsiPackageType `
                    -MsiProductCode $MsiProductCode `
                    -MsiProductName $displayName `
                    -MsiProductVersion $MsiProductVersion `
                    -MsiPublisher $MsiPublisher `
                    -MsiRequiresReboot $MsiRequiresReboot `
                    -MsiUpgradeCode $MsiUpgradeCode `
                    -logo $logo `
                    -isFeatured $isFeatured `
                    -informationUrl $informationUrl `
                    -privacyInformationUrl $privacyInformationUrl `
                    -developer $developer `
                    -owner $owner `
                    -notes $notes `
                    -maxRunTimeInMinutes $maxRunTimeInMinutes `
                    -deviceRestartBehavior $deviceRestartBehavior `
                    -minimumFreeDiskSpaceInMB $minimumFreeDiskSpaceInMB `
                    -minimumMemoryInMB $minimumMemoryInMB `
                    -minimumNumberOfProcessors $minimumNumberOfProcessors `
                    -minimumCpuSpeedInMHz $minimumCpuSpeedInMHz `
                    -allowedArchitectures $allowedArchitectures `
                    -minimumSupportedOS $minimumSupportedOS `
                    -requirementRules $requirementRules
            }
        }

        if ($EXE) {
            $mobileAppBody = Get-Win32AppBody -EXE -displayName "$DisplayName" -displayVersion "$DisplayVersion" -publisher "$publisher" `
                -description $description -category $Category -filename $FileName -SetupFileName "$SetupFileName" `
                -installExperience $installExperience -logo $logo `
                -installCommandLine $installCommandLine -uninstallCommandLine $uninstallCommandLine `
                -isFeatured $isFeatured -informationUrl $informationUrl -privacyInformationUrl $privacyInformationUrl `
                -developer $developer -owner $owner -notes $notes `
                -maxRunTimeInMinutes $maxRunTimeInMinutes -deviceRestartBehavior $deviceRestartBehavior `
                -minimumFreeDiskSpaceInMB $minimumFreeDiskSpaceInMB -minimumMemoryInMB $minimumMemoryInMB `
                -minimumNumberOfProcessors $minimumNumberOfProcessors -minimumCpuSpeedInMHz $minimumCpuSpeedInMHz `
                -allowedArchitectures $allowedArchitectures -minimumSupportedOS $minimumSupportedOS `
                -requirementRules $requirementRules
        }
        elseif ($PS1) {
            $mobileAppBody = Get-Win32AppBody -EXE -displayName "$DisplayName" -displayVersion "$DisplayVersion" -publisher "$publisher" `
                -description $description -category $Category -filename $FileName -SetupFileName "$SetupFileName" `
                -installExperience $installExperience -logo $logo `
                -installCommandLine $ps1InstallCommandLine -uninstallCommandLine $ps1UninstallCommandLine `
                -isFeatured $isFeatured -informationUrl $informationUrl -privacyInformationUrl $privacyInformationUrl `
                -developer $developer -owner $owner -notes $notes `
                -maxRunTimeInMinutes $maxRunTimeInMinutes -deviceRestartBehavior $deviceRestartBehavior `
                -minimumFreeDiskSpaceInMB $minimumFreeDiskSpaceInMB -minimumMemoryInMB $minimumMemoryInMB `
                -minimumNumberOfProcessors $minimumNumberOfProcessors -minimumCpuSpeedInMHz $minimumCpuSpeedInMHz `
                -allowedArchitectures $allowedArchitectures -minimumSupportedOS $minimumSupportedOS `
                -requirementRules $requirementRules
        }
        elseif ($Edge) {
            Write-Host
            Write-Host "Creating Edge ODATA construct" -ForegroundColor Yellow

            #$Publisher = 'Microsoft'
            #$Description = 'Microsoft Edge is the browser for business with modern and legacy web compatibility, new privacy features such as Tracking prevention, and built-in productivity tools such as enterprise-grade PDF support and access to Office and corporate search right from a new tab.'
            #$displayName = 'Microsoft Edge Stable1'
            #$channel = 'stable'

            $mobileAppBody = Get-Win32AppBody -Edge -displayName "$DisplayName" -publisher "$publisher" `
                -description $description -channel $channel

            Write-Host
            Write-Host "Creating application in Intune..." -ForegroundColor Yellow
            $mobileApp = Invoke-PostRequest "mobileApps" ($mobileAppBody | ConvertTo-Json)

            return
        }


        if ($detectionRules.'@odata.type' -contains "#microsoft.graph.win32LobAppPowerShellScriptDetection" -and @($detectionRules).'@odata.type'.Count -gt 1) {

            Write-Host
            Write-Warning "A Detection Rule can either be 'Manually configure detection rules' or 'Use a custom detection script'"
            Write-Warning "It can't include both..."
            Write-Host
            $script:exitCode = 1
            throw "Invalid detection rules: Cannot combine script detection with other detection methods"

        }

        else {

            $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'detectionRules' -Value $detectionRules

        }

        #ReturnCodes

        if ($returnCodes) {

            $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'returnCodes' -Value @($returnCodes)

        }

        else {

            Write-Host
            Write-Warning "Intunewin file requires ReturnCodes to be specified"
            Write-Warning "If you want to use the default ReturnCode run 'Get-DefaultReturnCodes'"
            Write-Host
            $script:exitCode = 1
            throw "ReturnCodes must be specified for intunewin file"

        }

        Write-Host
        Write-Host "Creating application in Intune..." -ForegroundColor Yellow
        $mobileApp = Invoke-PostRequest "mobileApps" ($mobileAppBody | ConvertTo-Json);

        $appId = $mobileApp.id;

        # Encrypt file and Get File Information
        Write-Host
        Write-Host "Getting Encryption Information for '$SourceFile'..." -ForegroundColor Yellow

        $encryptionInfo = @{ };
        $encryptionInfo.encryptionKey = $DetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
        $encryptionInfo.macKey = $DetectionXML.ApplicationInfo.EncryptionInfo.macKey
        $encryptionInfo.initializationVector = $DetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
        $encryptionInfo.mac = $DetectionXML.ApplicationInfo.EncryptionInfo.mac
        $encryptionInfo.profileIdentifier = "ProfileVersion1";
        $encryptionInfo.fileDigest = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
        $encryptionInfo.fileDigestAlgorithm = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm

        $fileEncryptionInfo = @{ };
        $fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo;

        # Extracting encrypted file
        $IntuneWinFile = Get-IntuneWinFile "$SourceFile" -fileName "$filename"

        [int64]$Size = $DetectionXML.ApplicationInfo.UnencryptedContentSize
        $EncrySize = (Get-Item "$IntuneWinFile").Length

        # Upload with retry — create fresh content version per attempt
        $maxUploadAttempts = 3
        $uploadSucceeded = $false

        for ($uploadAttempt = 1; $uploadAttempt -le $maxUploadAttempts; $uploadAttempt++) {
            if ($uploadAttempt -gt 1) {
                Write-Host
                Write-Host "Starting replacement upload (attempt $uploadAttempt/$maxUploadAttempts)..." -ForegroundColor Yellow
            }

            try {
                # Get the content version for the new app.
                Write-Host
                Write-Host "Creating Content Version in the service for the application..." -ForegroundColor Yellow
                $contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions";
                $contentVersion = Invoke-PostRequest $contentVersionUri "{}";

                # Create a new file for the app.
                Write-Host
                Write-Host "Creating a new file entry in Azure for the upload..." -ForegroundColor Yellow
                $contentVersionId = $contentVersion.id;
                $fileBody = Get-AppFileBody "$FileName" $Size $EncrySize $null;
                $filesUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files";
                $file = Invoke-PostRequest $filesUri ($fileBody | ConvertTo-Json);

                # Wait for the service to process the new file request.
                Write-Host
                Write-Host "Waiting for the file entry URI to be created..." -ForegroundColor Yellow
                $fileId = $file.id;
                $fileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId";
                $file = Wait-FileProcessing $fileUri "azureStorageUriRequest";

                # Upload the content to Azure Storage.
                Write-Host
                Write-Host "Uploading file to Azure Storage..." -f Yellow

                Send-FileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri;

                # Wait a few seconds for Azure Storage to fully commit and replicate
                Write-Host "Waiting 5 seconds for Azure Storage to finalize..." -ForegroundColor Cyan
                Start-Sleep -Seconds 5

                # Commit the file — retry if SAS upload state hasn't transitioned yet
                Write-Host
                Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
                Write-Host "File Encryption Info being sent:" -ForegroundColor Cyan
                Write-Host ($fileEncryptionInfo | ConvertTo-Json -Depth 10) -ForegroundColor Gray
                $commitFileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit";

                $commitRetries = 6
                $commitOk = $false
                for ($commitAttempt = 1; $commitAttempt -le $commitRetries; $commitAttempt++) {
                    try {
                        Invoke-PostRequest $commitFileUri ($fileEncryptionInfo | ConvertTo-Json);
                        $commitOk = $true
                        break
                    }
                    catch {
                        if ($commitAttempt -lt $commitRetries -and $_.Exception.Message -match '400|SAS request') {
                            Write-Host "    Commit not ready, waiting for SAS state transition (attempt $commitAttempt/$commitRetries)..." -ForegroundColor Yellow
                            Start-Sleep -Seconds 15
                        }
                        else {
                            throw
                        }
                    }
                }
                if (-not $commitOk) {
                    throw "File commit did not succeed after $commitRetries attempts"
                }

                # Wait for the service to process the commit file request.
                Write-Host
                Write-Host "Waiting for the service to process the commit file request..." -ForegroundColor Yellow
                $file = Wait-FileProcessing $fileUri "CommitFile";

                # Commit the app.
                Write-Host
                Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
                $commitAppUri = "mobileApps/$appId";
                $commitAppBody = Get-AppCommitBody $contentVersionId $LOBType;
                Invoke-PatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json);

                Write-Host "Sleeping for $sleep seconds to allow package upload completion..." -f Magenta
                Start-Sleep $sleep
                Write-Host

                $uploadSucceeded = $true
                break
            }
            catch {
                Write-Host "Upload attempt $uploadAttempt/$maxUploadAttempts failed: $($_.Exception.Message)" -ForegroundColor Red
                if ($uploadAttempt -lt $maxUploadAttempts) {
                    $backoffSeconds = 30 * $uploadAttempt
                    Write-Host "Abandoning this upload — waiting ${backoffSeconds}s before retry..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $backoffSeconds

                    # A failed upload leaves the app stuck in 'notPublished' with an
                    # uncommitted content version.  The API rejects new content versions
                    # on a stuck app (HTTP 400).  Delete the app and recreate it fresh.
                    Write-Host "    Deleting stuck app '$displayName' (ID: $appId) to reset state..." -ForegroundColor Yellow
                    try {
                        $deleteUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId"
                        Invoke-MgGraphRequest -Method DELETE -Uri $deleteUri | Out-Null
                        Start-Sleep -Seconds 5
                        $mobileApp = Invoke-PostRequest "mobileApps" ($mobileAppBody | ConvertTo-Json)
                        $appId = $mobileApp.id
                        Write-Host "    Recreated app — new ID: $appId" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "    Could not reset app state: $($_.Exception.Message) — next attempt will try with existing app" -ForegroundColor Yellow
                    }
                }
            }
        }

        Remove-Item "$IntuneWinFile" -Force -ErrorAction SilentlyContinue

        if (-not $uploadSucceeded) {
            $script:exitCode = 1
            throw "Content upload failed for '$displayName' after $maxUploadAttempts attempts"
        }

        # Scripts hang off the committed content version, so they can only be added once the upload has landed
        $null = Set-IntuneWin32AppScript -ApplicationId $appId -ContentVersionId $contentVersionId `
            -InstallScriptFile $script:InstallScriptFile -UninstallScriptFile $script:UninstallScriptFile `
            -InstallScriptEnforceSignatureCheck ([bool]$script:InstallScriptEnforceSignatureCheck) `
            -InstallScriptRunAs32Bit ([bool]$script:InstallScriptRunAs32Bit) `
            -UninstallScriptEnforceSignatureCheck ([bool]$script:UninstallScriptEnforceSignatureCheck) `
            -UninstallScriptRunAs32Bit ([bool]$script:UninstallScriptRunAs32Bit)

    }

    catch {
        throw
    }
}

####################################################

function Update-Win32LobContent {
    <#
.SYNOPSIS
This function is used to update the content (IntuneWin file) of an existing Win32 Application in Intune
.DESCRIPTION
This function replaces only the IntuneWin package content of an existing Win32 application while
preserving all other configuration (assignments, detection rules, requirements, etc.). Supports -WhatIf.
.EXAMPLE
Update-Win32LobContent -AppId "12345678-1234-1234-1234-123456789012" -SourceFile "C:\Packages\package.intunewin"
This example updates the content of an existing Intune app with the new .intunewin file
.NOTES
NAME: Update-Win32LobContent
#>

    [cmdletbinding(SupportsShouldProcess = $true)]

    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $AppId,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $SourceFile
    )

    try {
        # Check WhatIf before performing content update
        if (-not $PSCmdlet.ShouldProcess("Application ID '$AppId'", "Update content in Intune")) {
            Write-Host "WhatIf: Would update content for application ID '$AppId'" -ForegroundColor Cyan
            Write-Log -Message "WhatIf: Would update content for application ID '$AppId'"
            return
        }

        $LOBType = "microsoft.graph.win32LobApp"

        Write-Host
        Write-Host "Updating content for existing application..." -ForegroundColor Yellow
        Write-Host "Application ID: $AppId" -ForegroundColor Cyan

        # Validate source file exists
        Write-Host "Testing if SourceFile '$SourceFile' Path is valid..." -ForegroundColor Yellow
        Test-SourceFile "$SourceFile"

        # Read the detection.xml from the IntuneWin package
        $DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"
        $FileName = $DetectionXML.ApplicationInfo.FileName

        # Get encryption information from the new package
        Write-Host
        Write-Host "Getting Encryption Information for '$SourceFile'..." -ForegroundColor Yellow

        $encryptionInfo = @{ }
        $encryptionInfo.encryptionKey = $DetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
        $encryptionInfo.macKey = $DetectionXML.ApplicationInfo.EncryptionInfo.macKey
        $encryptionInfo.initializationVector = $DetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
        $encryptionInfo.mac = $DetectionXML.ApplicationInfo.EncryptionInfo.mac
        $encryptionInfo.profileIdentifier = "ProfileVersion1"
        $encryptionInfo.fileDigest = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
        $encryptionInfo.fileDigestAlgorithm = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm

        $fileEncryptionInfo = @{ }
        $fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo

        # Extract the encrypted file from the IntuneWin package
        $IntuneWinFile = Get-IntuneWinFile "$SourceFile" -fileName "$FileName"

        [int64]$Size = $DetectionXML.ApplicationInfo.UnencryptedContentSize
        $EncrySize = (Get-Item "$IntuneWinFile").Length

        # Upload with retry — create fresh content version per attempt
        $maxUploadAttempts = 3
        $uploadSucceeded = $false

        for ($uploadAttempt = 1; $uploadAttempt -le $maxUploadAttempts; $uploadAttempt++) {
            if ($uploadAttempt -gt 1) {
                Write-Host
                Write-Host "Starting replacement upload (attempt $uploadAttempt/$maxUploadAttempts)..." -ForegroundColor Yellow
            }

            try {
                # Create a new content version for each attempt
                Write-Host
                Write-Host "Creating new Content Version for the existing application..." -ForegroundColor Yellow
                $contentVersionUri = "mobileApps/$AppId/$LOBType/contentVersions"
                $contentVersion = Invoke-PostRequest $contentVersionUri "{}"

                # Create a new file entry for the content version
                Write-Host
                Write-Host "Creating a new file entry in Azure for the upload..." -ForegroundColor Yellow
                $contentVersionId = $contentVersion.id
                $fileBody = Get-AppFileBody "$FileName" $Size $EncrySize $null
                $filesUri = "mobileApps/$AppId/$LOBType/contentVersions/$contentVersionId/files"
                $file = Invoke-PostRequest $filesUri ($fileBody | ConvertTo-Json)

                # Wait for the file entry to be ready
                Write-Host
                Write-Host "Waiting for the file entry URI to be created..." -ForegroundColor Yellow
                $fileId = $file.id
                $fileUri = "mobileApps/$AppId/$LOBType/contentVersions/$contentVersionId/files/$fileId"
                $file = Wait-FileProcessing $fileUri "azureStorageUriRequest"

                # Upload the content to Azure Storage
                Write-Host
                Write-Host "Uploading file to Azure Storage..." -ForegroundColor Yellow
                Send-FileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri

                # Wait for Azure Storage to finalize
                Write-Host "Waiting 5 seconds for Azure Storage to finalize..." -ForegroundColor Cyan
                Start-Sleep -Seconds 5

                # Commit the file — retry if SAS upload state hasn't transitioned yet
                Write-Host
                Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
                Write-Host "File Encryption Info being sent:" -ForegroundColor Cyan
                Write-Host ($fileEncryptionInfo | ConvertTo-Json -Depth 10) -ForegroundColor Gray
                $commitFileUri = "mobileApps/$AppId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit"

                $commitRetries = 6
                $commitOk = $false
                for ($commitAttempt = 1; $commitAttempt -le $commitRetries; $commitAttempt++) {
                    try {
                        Invoke-PostRequest $commitFileUri ($fileEncryptionInfo | ConvertTo-Json)
                        $commitOk = $true
                        break
                    }
                    catch {
                        if ($commitAttempt -lt $commitRetries -and $_.Exception.Message -match '400|SAS request') {
                            Write-Host "    Commit not ready, waiting for SAS state transition (attempt $commitAttempt/$commitRetries)..." -ForegroundColor Yellow
                            Start-Sleep -Seconds 15
                        }
                        else {
                            throw
                        }
                    }
                }
                if (-not $commitOk) {
                    throw "File commit did not succeed after $commitRetries attempts"
                }

                # Wait for the commit to complete
                Write-Host
                Write-Host "Waiting for the service to process the commit file request..." -ForegroundColor Yellow
                $file = Wait-FileProcessing $fileUri "CommitFile"

                # Commit the new content version to the app
                Write-Host
                Write-Host "Committing the new content version to the application..." -ForegroundColor Yellow
                $commitAppUri = "mobileApps/$AppId"
                $commitAppBody = Get-AppCommitBody $contentVersionId $LOBType
                Invoke-PatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json)

                Write-Host "Sleeping for $sleep seconds to allow package update completion..." -ForegroundColor Magenta
                Start-Sleep $sleep
                Write-Host

                $uploadSucceeded = $true
                break
            }
            catch {
                Write-Host "Upload attempt $uploadAttempt/$maxUploadAttempts failed: $($_.Exception.Message)" -ForegroundColor Red
                if ($uploadAttempt -lt $maxUploadAttempts) {
                    $backoffSeconds = 30 * $uploadAttempt
                    Write-Host "Abandoning this upload — waiting ${backoffSeconds}s before retry..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $backoffSeconds
                }
            }
        }

        # Clean up the extracted IntuneWin file
        Remove-Item "$IntuneWinFile" -Force -ErrorAction SilentlyContinue

        if (-not $uploadSucceeded) {
            throw "Content upload failed for application ID '$AppId' after $maxUploadAttempts attempts"
        }

        # Scripts belong to the new content version, so re-apply them whenever content is replaced
        $null = Set-IntuneWin32AppScript -ApplicationId $AppId -ContentVersionId $contentVersionId `
            -InstallScriptFile $script:InstallScriptFile -UninstallScriptFile $script:UninstallScriptFile `
            -InstallScriptEnforceSignatureCheck ([bool]$script:InstallScriptEnforceSignatureCheck) `
            -InstallScriptRunAs32Bit ([bool]$script:InstallScriptRunAs32Bit) `
            -UninstallScriptEnforceSignatureCheck ([bool]$script:UninstallScriptEnforceSignatureCheck) `
            -UninstallScriptRunAs32Bit ([bool]$script:UninstallScriptRunAs32Bit)

        Write-Host "Successfully updated content for application ID: $AppId" -ForegroundColor Green
        Write-Host

    }
    catch {
        Write-Host "Error updating application content: $_" -ForegroundColor Red
        throw
    }
}

####################################################

function Get-XMLConfig {
    <#
.SYNOPSIS
This function reads the supplied XML Config file
.DESCRIPTION
This function reads the supplied XML Config file
.EXAMPLE
Get-XMLConfig -XMLFile PathToXMLFile
This function reads the supplied XML Config file
.NOTES
NAME: Get-XMLConfig
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$XMLFile,

        [bool]$Skip = $false
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        if (-not(Test-Path $XMLFile)) {
            Write-Log -Message "Error - XML file not found: $XMLFile" -LogLevel 3
            return $Skip = $true
        }
        Write-Log -Message "Reading XML file: $XMLFile"
        [xml]$script:XML_Content = Get-Content $XMLFile

        foreach ($XMLEntity in $XML_Content.GetElementsByTagName("Azure_Settings")) {
            $script:baseUrl = [string]$XMLEntity.baseUrl
            $script:logRequestUris = [string]$XMLEntity.logRequestUris
            $script:logHeaders = [string]$XMLEntity.logHeaders
            $script:logContent = [string]$XMLEntity.logContent
            $script:azureStorageUploadChunkSizeInMb = [string]$XMLEntity.azureStorageUploadChunkSizeInMb
            if ([string]::IsNullOrWhiteSpace([string]$script:azureStorageUploadChunkSizeInMb) -or [int]$script:azureStorageUploadChunkSizeInMb -lt 1) {
                $script:azureStorageUploadChunkSizeInMb = 25
            }
            $script:sleep = [int32]$XMLEntity.sleep
        }

        foreach ($XMLEntity in $XML_Content.GetElementsByTagName("IntuneWin_Settings")) {
            if ($script:EntraGroupName.Length -gt 50) {
                Write-Log -Message "Error - Entra ID group name longer than 50 chars. Shorten then retry."
                exit
            }

            $script:AppType = [string]$XMLEntity.AppType
            if ( ( $AppType -eq "EXE" ) -or ( $AppType -eq "MSI" ) ) {
                Write-Log -Message "Reading commands for AppType: $AppType"
                $script:installCmdLine = [string]$XMLEntity.installCmdLine
                $script:uninstallCmdLine = [string]$XMLEntity.uninstallCmdLine
            }
            if ( $AppType -eq "Edge" ) {
                Write-Log -Message "Reading commands for AppType: $AppType"
                $script:displayName = [string]$XMLEntity.displayName
                # Store base description - user stamp will be added after authentication
                $script:BaseDescription = [string]$XMLEntity.Description
                $script:Description = $script:BaseDescription
                $script:Publisher = [string]$XMLEntity.Publisher
                $script:Channel = [string]$XMLEntity.Channel
                # Support both EntraGroupName (preferred) and AADGroupName (legacy)
                $script:EntraGroupName = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.EntraGroupName)) { [string]$XMLEntity.EntraGroupName } else { [string]$XMLEntity.AADGroupName }
                return
            }
            $script:RuleType = [string]$XMLEntity.RuleType
            if ($RuleType -eq "FILE") {
                Write-Log -Message "Reading detection for RuleType: $RuleType"
                $script:FilePath = [string]$XMLEntity.FilePath
                $script:FileDetectionType = [string]$XMLEntity.FileDetectionType
                if (($FileDetectionType -ne "exists") -and ($FileDetectionType -ne "doesNotExist")) {
                    $script:FileDetectionOperator = [string]$XMLEntity.FileDetectionOperator
                    $script:FileDetectionValue = [string]$XMLEntity.FileDetectionValue
                }
            }

            if ($RuleType -eq "REGISTRY") {
                Write-Log -Message "Reading detection for RuleType: $RuleType"
                $script:RegistryKeyPath = [string]$XMLEntity.RegistryKeyPath
                $script:RegistryValue = [string]$XMLEntity.RegistryValue
                $script:RegistryDetectionType = [string]$XMLEntity.RegistryDetectionType
                if (($RegistryDetectionType -ne "exists") -and ($RegistryDetectionType -ne "doesNotExist")) {
                    $script:RegistryDetectionOperator = [string]$XMLEntity.RegistryDetectionOperator
                    $script:RegistryDetectionValue = [string]$XMLEntity.RegistryDetectionValue
                }
            }

            if ($RuleType -eq "MSI") {
                Write-Log -Message "Reading detection for RuleType: $RuleType"
                $script:MSIProductCode = [string]$XMLEntity.MSIProductCode
                $script:MSIProductVersionOperator = [string]$XMLEntity.MSIProductVersionOperator
                if ($MSIProductVersionOperator -ne "notConfigured") {
                    $script:MSIProductVersion = [string]$XMLEntity.MSIProductVersion
                }
            }

            $script:ReturnCodeType = [string]$XMLEntity.ReturnCodeType
            $script:InstallExperience = [string]$XMLEntity.InstallExperience
            $script:PackageName = [string]$XMLEntity.PackageName
            $script:displayName = [string]$XMLEntity.displayName
            $script:displayVersion = [string]$XMLEntity.displayVersion
            # Store base description - user stamp will be added after authentication
            $script:BaseDescription = [string]$XMLEntity.Description
            $script:Description = $script:BaseDescription
            $script:Publisher = [string]$XMLEntity.Publisher
            # Read category from Config.xml (supports comma-separated for multiple categories)
            $rawCategory = [string]$XMLEntity.Category
            if (-not [string]::IsNullOrWhiteSpace($rawCategory)) {
                $script:Categories = @($rawCategory -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                $script:Category = $script:Categories[0]
                Write-Log -Message "Found categories in Config.xml: $($script:Categories -join ', ')"
            }
            else {
                $script:Categories = @()
                $script:Category = ''
            }
            $script:LogoFile = [string]$XMLEntity.LogoFile
            # Support both EntraGroupName (preferred) and AADGroupName (legacy)
            $script:EntraGroupName = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.EntraGroupName)) { [string]$XMLEntity.EntraGroupName } else { [string]$XMLEntity.AADGroupName }

            # Read optional ScopeTag from Config.xml (supports comma-separated for multiple tags)
            $rawScopeTag = [string]$XMLEntity.ScopeTag
            if (-not [string]::IsNullOrWhiteSpace($rawScopeTag)) {
                $script:ConfigScopeTag = @($rawScopeTag -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                Write-Log -Message "Found ScopeTag in Config.xml: $($script:ConfigScopeTag -join ', ')"
            }
            else {
                $script:ConfigScopeTag = @()
            }

            # Read optional allowAvailableUninstall from Config.xml (accepts yes/no or true/false, default is yes if not specified)
            $rawAllowUninstall = [string]$XMLEntity.AllowAvailableUninstall
            if (-not [string]::IsNullOrWhiteSpace($rawAllowUninstall)) {
                $script:AllowAvailableUninstall = $rawAllowUninstall.Trim() -in @('yes', 'true')
            }
            else {
                $script:AllowAvailableUninstall = $true
            }
            Write-Log -Message "AllowAvailableUninstall: $($script:AllowAvailableUninstall)"

            # Read optional extended settings from Config.xml
            # App Information
            $script:IsFeatured = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.IsFeatured)) { [bool]::Parse([string]$XMLEntity.IsFeatured) } else { $false }
            $script:InformationUrl = [string]$XMLEntity.InformationUrl
            $script:PrivacyInformationUrl = [string]$XMLEntity.PrivacyInformationUrl
            $script:Developer = [string]$XMLEntity.Developer
            $script:Owner = [string]$XMLEntity.Owner
            $script:Notes = [string]$XMLEntity.Notes

            # Install Experience settings
            $script:MaxRunTimeInMinutes = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.MaxRunTimeInMinutes)) { [int]$XMLEntity.MaxRunTimeInMinutes } else { 60 }
            $script:DeviceRestartBehavior = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.DeviceRestartBehavior)) { [string]$XMLEntity.DeviceRestartBehavior } else { "suppress" }

            # System Requirements
            $script:MinimumFreeDiskSpaceInMB = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.MinimumFreeDiskSpaceInMB)) { [int]$XMLEntity.MinimumFreeDiskSpaceInMB } else { 0 }
            $script:MinimumMemoryInMB = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.MinimumMemoryInMB)) { [int]$XMLEntity.MinimumMemoryInMB } else { 0 }
            $script:MinimumNumberOfProcessors = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.MinimumNumberOfProcessors)) { [int]$XMLEntity.MinimumNumberOfProcessors } else { 0 }
            $script:MinimumCpuSpeedInMHz = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.MinimumCpuSpeedInMHz)) { [int]$XMLEntity.MinimumCpuSpeedInMHz } else { 0 }
            $script:AllowedArchitectures = [string]$XMLEntity.AllowedArchitectures
            $script:MinimumSupportedOS = [string]$XMLEntity.MinimumSupportedOS

            # Custom Return Codes (comma-separated list of code:type pairs, e.g., "3010:softReboot,1641:hardReboot")
            $script:CustomReturnCodes = [string]$XMLEntity.CustomReturnCodes

            # Dependencies - element may be repeated to give each app its own type, and entries may use 'Name:Type'
            $script:Dependencies = @($XMLEntity.Dependencies | ForEach-Object { if ($_ -is [System.Xml.XmlElement]) { $_.InnerText } else { [string]$_ } })
            $script:DependencyType = @($XMLEntity.DependencyType | ForEach-Object { if ($_ -is [System.Xml.XmlElement]) { $_.InnerText } else { [string]$_ } })

            # Supersedence - element may be repeated to give each app its own type, and entries may use 'Name:Type'
            $script:Supersedence = @($XMLEntity.Supersedence | ForEach-Object { if ($_ -is [System.Xml.XmlElement]) { $_.InnerText } else { [string]$_ } })
            $script:SupersedenceType = @($XMLEntity.SupersedenceType | ForEach-Object { if ($_ -is [System.Xml.XmlElement]) { $_.InnerText } else { [string]$_ } })

            # PowerShell Script Detection settings
            $script:DetectionScriptFile = [string]$XMLEntity.DetectionScriptFile
            $script:DetectionScriptEnforceSignatureCheck = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.DetectionScriptEnforceSignatureCheck)) { [bool]::Parse([string]$XMLEntity.DetectionScriptEnforceSignatureCheck) } else { $false }
            $script:DetectionScriptRunAs32Bit = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.DetectionScriptRunAs32Bit)) { [bool]::Parse([string]$XMLEntity.DetectionScriptRunAs32Bit) } else { $false }

            # PowerShell script installer/uninstaller - set either, both, or neither; whichever is set replaces its command line
            $script:InstallScriptFile = Resolve-AppScriptPath ([string]$XMLEntity.InstallScriptFile)
            $script:InstallScriptEnforceSignatureCheck = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.InstallScriptEnforceSignatureCheck)) { [bool]::Parse([string]$XMLEntity.InstallScriptEnforceSignatureCheck) } else { $false }
            $script:InstallScriptRunAs32Bit = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.InstallScriptRunAs32Bit)) { [bool]::Parse([string]$XMLEntity.InstallScriptRunAs32Bit) } else { $false }
            $script:UninstallScriptFile = Resolve-AppScriptPath ([string]$XMLEntity.UninstallScriptFile)
            $script:UninstallScriptEnforceSignatureCheck = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.UninstallScriptEnforceSignatureCheck)) { [bool]::Parse([string]$XMLEntity.UninstallScriptEnforceSignatureCheck) } else { $false }
            $script:UninstallScriptRunAs32Bit = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.UninstallScriptRunAs32Bit)) { [bool]::Parse([string]$XMLEntity.UninstallScriptRunAs32Bit) } else { $false }

            # Read optional upload parameters from Config.xml
            # NewTagPath (boolean, default true)
            $rawNewTagPath = [string]$XMLEntity.NewTagPath
            if (-not [string]::IsNullOrWhiteSpace($rawNewTagPath)) {
                $script:ConfigNewTagPath = $rawNewTagPath.Trim() -in @('yes', 'true')
            }
            else {
                $script:ConfigNewTagPath = $null
            }

            # RequiredGroupName - supports RequiredEntraGroupName, RequiredAADGroupName (comma-separated for multiple)
            $rawRequiredGroup = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.RequiredEntraGroupName)) { [string]$XMLEntity.RequiredEntraGroupName } `
                elseif (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.RequiredAADGroupName)) { [string]$XMLEntity.RequiredAADGroupName } `
                else { "" }
            if (-not [string]::IsNullOrWhiteSpace($rawRequiredGroup)) {
                $script:ConfigRequiredGroupName = @($rawRequiredGroup -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                Write-Log -Message "Found RequiredGroupName in Config.xml: $($script:ConfigRequiredGroupName -join ', ')"
            }
            else {
                $script:ConfigRequiredGroupName = @()
            }

            # AvailableGroupName - supports AvailableEntraGroupName, AvailableAADGroupName (comma-separated for multiple)
            $rawAvailableGroup = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.AvailableEntraGroupName)) { [string]$XMLEntity.AvailableEntraGroupName } `
                elseif (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.AvailableAADGroupName)) { [string]$XMLEntity.AvailableAADGroupName } `
                else { "" }
            if (-not [string]::IsNullOrWhiteSpace($rawAvailableGroup)) {
                $script:ConfigAvailableGroupName = @($rawAvailableGroup -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                Write-Log -Message "Found AvailableGroupName in Config.xml: $($script:ConfigAvailableGroupName -join ', ')"
            }
            else {
                $script:ConfigAvailableGroupName = @()
            }

            # ReplaceExistingContent (boolean)
            $rawReplaceContent = [string]$XMLEntity.ReplaceExistingContent
            if (-not [string]::IsNullOrWhiteSpace($rawReplaceContent)) {
                $script:ConfigReplaceExistingContent = $rawReplaceContent.Trim() -in @('yes', 'true')
            }
            else {
                $script:ConfigReplaceExistingContent = $null
            }

            # UninstallGroupName - supports UninstallEntraGroupName, UninstallAADGroupName (comma-separated for multiple)
            $rawUninstallGroup = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.UninstallEntraGroupName)) { [string]$XMLEntity.UninstallEntraGroupName } `
                elseif (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.UninstallAADGroupName)) { [string]$XMLEntity.UninstallAADGroupName } `
                else { "" }
            if (-not [string]::IsNullOrWhiteSpace($rawUninstallGroup)) {
                $script:ConfigUninstallGroupName = @($rawUninstallGroup -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                Write-Log -Message "Found UninstallGroupName in Config.xml: $($script:ConfigUninstallGroupName -join ', ')"
            }
            else {
                $script:ConfigUninstallGroupName = @()
            }

            # SkipPackageRemoval (boolean)
            $rawSkipRemoval = [string]$XMLEntity.SkipPackageRemoval
            if (-not [string]::IsNullOrWhiteSpace($rawSkipRemoval)) {
                $script:ConfigSkipPackageRemoval = $rawSkipRemoval.Trim() -in @('yes', 'true')
            }
            else {
                $script:ConfigSkipPackageRemoval = $null
            }

            #Strip .ps1 extension, if entered into XML file...
            $lastFourChars = $PackageName.Substring($PackageName.Length - 4)
            if ($lastFourChars -eq ".ps1") { $script:PackageName = $PackageName.Substring(0, $PackageName.Length - 4) }
        }

    }

    end {
        if ($Skip) { return }# Just return without doing anything else
        Write-Log -Message "Returning..."
        return
    }

}

####################################################

function Get-JSONConfig {
    <#
.SYNOPSIS
This function reads the supplied JSON Config file
.DESCRIPTION
This function reads the supplied JSON Config file (Config.json format)
.EXAMPLE
Get-JSONConfig -JSONFile PathToJSONFile
This function reads the supplied JSON Config file
.NOTES
NAME: Get-JSONConfig
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$JSONFile,

        [bool]$Skip = $false
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        if (-not(Test-Path $JSONFile)) {
            Write-Log -Message "Error - JSON file not found: $JSONFile" -LogLevel 3
            return $Skip = $true
        }
        Write-Log -Message "Reading JSON file: $JSONFile"

        try {
            # Read raw bytes so a UTF-8 BOM can be stripped before JSON parsing.
            # ConvertFrom-Json on PS 5.1 rejects content that starts with a BOM.
            $jsonBytes = [System.IO.File]::ReadAllBytes($JSONFile)
            if ($jsonBytes.Length -ge 3 -and $jsonBytes[0] -eq 0xEF -and $jsonBytes[1] -eq 0xBB -and $jsonBytes[2] -eq 0xBF) {
                $jsonText = [System.Text.Encoding]::UTF8.GetString($jsonBytes, 3, $jsonBytes.Length - 3)
            }
            else {
                $jsonText = [System.Text.Encoding]::UTF8.GetString($jsonBytes)
            }
            $script:JSON_Content = $jsonText | ConvertFrom-Json
        }
        catch {
            Write-Log -Message "Error - Failed to parse JSON file: $JSONFile - $_" -LogLevel 3
            return $Skip = $true
        }

        # Set default Azure settings (same as XML defaults)
        $script:baseUrl = "https://graph.microsoft.com/beta/deviceAppManagement/"
        $script:logRequestUris = '$true'
        $script:logHeaders = '$false'
        $script:logContent = '$true'
        $script:azureStorageUploadChunkSizeInMb = 25
        $script:sleep = 5

        # Override Azure settings if present in JSON
        if ($JSON_Content.baseUrl) { $script:baseUrl = [string]$JSON_Content.baseUrl }
        if ($JSON_Content.logRequestUris) { $script:logRequestUris = [string]$JSON_Content.logRequestUris }
        if ($JSON_Content.logHeaders) { $script:logHeaders = [string]$JSON_Content.logHeaders }
        if ($JSON_Content.logContent) { $script:logContent = [string]$JSON_Content.logContent }
        if ($JSON_Content.azureStorageUploadChunkSizeInMb) { $script:azureStorageUploadChunkSizeInMb = [string]$JSON_Content.azureStorageUploadChunkSizeInMb }
        if ($JSON_Content.sleep) { $script:sleep = [int32]$JSON_Content.sleep }

        # Read IntuneWin settings from JSON (case-insensitive property access)
        $script:AppType = if ($JSON_Content.appType) { [string]$JSON_Content.appType } else { [string]$JSON_Content.AppType }

        if ( ( $AppType -eq "EXE" ) -or ( $AppType -eq "MSI" ) ) {
            Write-Log -Message "Reading commands for AppType: $AppType"
            $script:installCmdLine = if ($JSON_Content.installCmdLine) { [string]$JSON_Content.installCmdLine } else { [string]$JSON_Content.installCommandLine }
            $script:uninstallCmdLine = if ($JSON_Content.uninstallCmdLine) { [string]$JSON_Content.uninstallCmdLine } else { [string]$JSON_Content.uninstallCommandLine }
        }

        if ( $AppType -eq "Edge" ) {
            Write-Log -Message "Reading settings for AppType: $AppType"
            $script:displayName = if ($JSON_Content.displayName) { [string]$JSON_Content.displayName } else { [string]$JSON_Content.DisplayName }
            # Store base description - user stamp will be added after authentication
            $script:BaseDescription = if ($JSON_Content.description) { [string]$JSON_Content.description } else { [string]$JSON_Content.Description }
            $script:Description = $script:BaseDescription
            $script:Publisher = if ($JSON_Content.publisher) { [string]$JSON_Content.publisher } else { [string]$JSON_Content.Publisher }
            $script:Channel = if ($JSON_Content.channel) { [string]$JSON_Content.channel } else { [string]$JSON_Content.Channel }
            # Support both entraGroupName (preferred) and aadGroupName (legacy)
            $script:EntraGroupName = if ($JSON_Content.entraGroupName) { [string]$JSON_Content.entraGroupName } `
                elseif ($JSON_Content.EntraGroupName) { [string]$JSON_Content.EntraGroupName } `
                elseif ($JSON_Content.aadGroupName) { [string]$JSON_Content.aadGroupName } `
                else { [string]$JSON_Content.AADGroupName }
            return
        }

        $script:RuleType = if ($JSON_Content.ruleType) { [string]$JSON_Content.ruleType } else { [string]$JSON_Content.RuleType }

        if ($RuleType -eq "FILE") {
            Write-Log -Message "Reading detection for RuleType: $RuleType"
            $script:FilePath = if ($JSON_Content.filePath) { [string]$JSON_Content.filePath } else { [string]$JSON_Content.FilePath }
            $script:FileDetectionType = if ($JSON_Content.fileDetectionType) { [string]$JSON_Content.fileDetectionType } else { [string]$JSON_Content.FileDetectionType }
            if (($FileDetectionType -ne "exists") -and ($FileDetectionType -ne "doesNotExist")) {
                $script:FileDetectionOperator = if ($JSON_Content.fileDetectionOperator) { [string]$JSON_Content.fileDetectionOperator } else { [string]$JSON_Content.FileDetectionOperator }
                $script:FileDetectionValue = if ($JSON_Content.fileDetectionValue) { [string]$JSON_Content.fileDetectionValue } else { [string]$JSON_Content.FileDetectionValue }
            }
        }

        if ($RuleType -eq "REGISTRY") {
            Write-Log -Message "Reading detection for RuleType: $RuleType"
            $script:RegistryKeyPath = if ($JSON_Content.registryKeyPath) { [string]$JSON_Content.registryKeyPath } else { [string]$JSON_Content.RegistryKeyPath }
            $script:RegistryValue = if ($JSON_Content.registryValue) { [string]$JSON_Content.registryValue } else { [string]$JSON_Content.RegistryValue }
            $script:RegistryDetectionType = if ($JSON_Content.registryDetectionType) { [string]$JSON_Content.registryDetectionType } else { [string]$JSON_Content.RegistryDetectionType }
            if (($RegistryDetectionType -ne "exists") -and ($RegistryDetectionType -ne "doesNotExist")) {
                $script:RegistryDetectionOperator = if ($JSON_Content.registryDetectionOperator) { [string]$JSON_Content.registryDetectionOperator } else { [string]$JSON_Content.RegistryDetectionOperator }
                $script:RegistryDetectionValue = if ($JSON_Content.registryDetectionValue) { [string]$JSON_Content.registryDetectionValue } else { [string]$JSON_Content.RegistryDetectionValue }
            }
        }

        if ($RuleType -eq "MSI") {
            Write-Log -Message "Reading detection for RuleType: $RuleType"
            $script:MSIProductCode = if ($JSON_Content.msiProductCode) { [string]$JSON_Content.msiProductCode } else { [string]$JSON_Content.MSIProductCode }
            $script:MSIProductVersionOperator = if ($JSON_Content.msiProductVersionOperator) { [string]$JSON_Content.msiProductVersionOperator } else { [string]$JSON_Content.MSIProductVersionOperator }
            if ($MSIProductVersionOperator -ne "notConfigured") {
                $script:MSIProductVersion = if ($JSON_Content.msiProductVersion) { [string]$JSON_Content.msiProductVersion } else { [string]$JSON_Content.MSIProductVersion }
            }
        }

        $script:ReturnCodeType = if ($JSON_Content.returnCodeType) { [string]$JSON_Content.returnCodeType } else { [string]$JSON_Content.ReturnCodeType }
        $script:InstallExperience = if ($JSON_Content.installExperience) { [string]$JSON_Content.installExperience } else { [string]$JSON_Content.InstallExperience }
        $script:PackageName = if ($JSON_Content.packageName) { [string]$JSON_Content.packageName } else { [string]$JSON_Content.PackageName }
        $script:displayName = if ($JSON_Content.displayName) { [string]$JSON_Content.displayName } else { [string]$JSON_Content.DisplayName }
        $script:displayVersion = if ($JSON_Content.displayVersion) { [string]$JSON_Content.displayVersion } else { [string]$JSON_Content.DisplayVersion }
        # Store base description - user stamp will be added after authentication
        $script:BaseDescription = if ($JSON_Content.description) { [string]$JSON_Content.description } else { [string]$JSON_Content.Description }
        $script:Description = $script:BaseDescription
        $script:Publisher = if ($JSON_Content.publisher) { [string]$JSON_Content.publisher } else { [string]$JSON_Content.Publisher }
        # Read category from Config.json (supports comma-separated for multiple categories)
        $rawCategory = if ($JSON_Content.category) { [string]$JSON_Content.category } else { [string]$JSON_Content.Category }
        if (-not [string]::IsNullOrWhiteSpace($rawCategory)) {
            $script:Categories = @($rawCategory -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            $script:Category = $script:Categories[0]
            Write-Log -Message "Found categories in Config.json: $($script:Categories -join ', ')"
        }
        else {
            $script:Categories = @()
            $script:Category = ''
        }
        $script:LogoFile = if ($JSON_Content.logoFile) { [string]$JSON_Content.logoFile } else { [string]$JSON_Content.LogoFile }
        # Support both entraGroupName (preferred) and aadGroupName (legacy)
        $script:EntraGroupName = if ($JSON_Content.entraGroupName) { [string]$JSON_Content.entraGroupName } `
            elseif ($JSON_Content.EntraGroupName) { [string]$JSON_Content.EntraGroupName } `
            elseif ($JSON_Content.aadGroupName) { [string]$JSON_Content.aadGroupName } `
            else { [string]$JSON_Content.AADGroupName }

        # Read optional ScopeTag from Config.json (supports both scopetag and scopeTag, and comma-separated for multiple tags)
        $rawScopeTag = if ($JSON_Content.scopetag) { [string]$JSON_Content.scopetag } `
            elseif ($JSON_Content.scopeTag) { [string]$JSON_Content.scopeTag } `
            elseif ($JSON_Content.ScopeTag) { [string]$JSON_Content.ScopeTag } `
            else { "" }
        if (-not [string]::IsNullOrWhiteSpace($rawScopeTag)) {
            $script:ConfigScopeTag = @($rawScopeTag -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            Write-Log -Message "Found ScopeTag in Config.json: $($script:ConfigScopeTag -join ', ')"
        }
        else {
            $script:ConfigScopeTag = @()
        }

        # Read optional allowAvailableUninstall from Config.json (accepts yes/no or true/false, default is yes if not specified)
        $rawAllowUninstall = if ($null -ne $JSON_Content.allowAvailableUninstall) { $JSON_Content.allowAvailableUninstall } `
            elseif ($null -ne $JSON_Content.AllowAvailableUninstall) { $JSON_Content.AllowAvailableUninstall } `
            else { $null }
        if ($null -ne $rawAllowUninstall) {
            if ($rawAllowUninstall -is [bool]) {
                $script:AllowAvailableUninstall = $rawAllowUninstall
            }
            else {
                $script:AllowAvailableUninstall = ([string]$rawAllowUninstall).Trim() -in @('yes', 'true')
            }
        }
        else {
            $script:AllowAvailableUninstall = $true
        }
        Write-Log -Message "AllowAvailableUninstall: $($script:AllowAvailableUninstall)"

        # Read optional coreApp and espApp from Config.json
        $script:CoreApp = if ($null -ne $JSON_Content.coreApp) { [bool]$JSON_Content.coreApp } else { $false }
        $script:EspApp = if ($null -ne $JSON_Content.espApp) { [bool]$JSON_Content.espApp } else { $false }
        if ($script:CoreApp) { Write-Log -Message "CoreApp: True" }
        if ($script:EspApp) { Write-Log -Message "EspApp: True" }

        # Read optional extended settings from Config.json
        # App Information
        $script:IsFeatured = if ($null -ne $JSON_Content.isFeatured) { [bool]$JSON_Content.isFeatured } else { $false }
        $script:InformationUrl = if ($JSON_Content.informationUrl) { [string]$JSON_Content.informationUrl } else { "" }
        $script:PrivacyInformationUrl = if ($JSON_Content.privacyInformationUrl) { [string]$JSON_Content.privacyInformationUrl } else { "" }
        $script:Developer = if ($JSON_Content.developer) { [string]$JSON_Content.developer } else { "" }
        $script:Owner = if ($JSON_Content.owner) { [string]$JSON_Content.owner } else { "" }
        $script:Notes = if ($JSON_Content.notes) { [string]$JSON_Content.notes } else { "" }

        # Install Experience settings
        $script:MaxRunTimeInMinutes = if ($null -ne $JSON_Content.maxRunTimeInMinutes) { [int]$JSON_Content.maxRunTimeInMinutes } else { 60 }
        $script:DeviceRestartBehavior = if ($JSON_Content.deviceRestartBehavior) { [string]$JSON_Content.deviceRestartBehavior } else { "suppress" }

        # System Requirements
        $script:MinimumFreeDiskSpaceInMB = if ($null -ne $JSON_Content.minimumFreeDiskSpaceInMB) { [int]$JSON_Content.minimumFreeDiskSpaceInMB } else { 0 }
        $script:MinimumMemoryInMB = if ($null -ne $JSON_Content.minimumMemoryInMB) { [int]$JSON_Content.minimumMemoryInMB } else { 0 }
        $script:MinimumNumberOfProcessors = if ($null -ne $JSON_Content.minimumNumberOfProcessors) { [int]$JSON_Content.minimumNumberOfProcessors } else { 0 }
        $script:MinimumCpuSpeedInMHz = if ($null -ne $JSON_Content.minimumCpuSpeedInMHz) { [int]$JSON_Content.minimumCpuSpeedInMHz } else { 0 }
        $script:AllowedArchitectures = if ($JSON_Content.allowedArchitectures) { [string]$JSON_Content.allowedArchitectures } else { "" }
        $script:MinimumSupportedOS = if ($JSON_Content.minimumSupportedOS) { [string]$JSON_Content.minimumSupportedOS } else { "" }

        # Custom Return Codes (array of objects with returnCode and type)
        $script:CustomReturnCodes = $JSON_Content.customReturnCodes

        # Dependencies (array of app display names)
        $script:Dependencies = $JSON_Content.dependencies
        $script:DependencyType = if ($JSON_Content.dependencyType) { [string]$JSON_Content.dependencyType } else { "autoInstall" }
        # Supersedence (array of app display names)
        $script:Supersedence = $JSON_Content.supersedence
        $script:SupersedenceType = if ($JSON_Content.supersedenceType) { [string]$JSON_Content.supersedenceType } else { "update" }

        # PowerShell Script Detection settings
        $script:DetectionScriptFile = if ($JSON_Content.detectionScriptFile) { [string]$JSON_Content.detectionScriptFile } else { "" }
        $script:DetectionScriptEnforceSignatureCheck = if ($null -ne $JSON_Content.detectionScriptEnforceSignatureCheck) { [bool]$JSON_Content.detectionScriptEnforceSignatureCheck } else { $false }
        $script:DetectionScriptRunAs32Bit = if ($null -ne $JSON_Content.detectionScriptRunAs32Bit) { [bool]$JSON_Content.detectionScriptRunAs32Bit } else { $false }

        # PowerShell script installer/uninstaller - set either, both, or neither; whichever is set replaces its command line
        $script:InstallScriptFile = Resolve-AppScriptPath ([string]$JSON_Content.installScriptFile)
        $script:InstallScriptEnforceSignatureCheck = if ($null -ne $JSON_Content.installScriptEnforceSignatureCheck) { [bool]$JSON_Content.installScriptEnforceSignatureCheck } else { $false }
        $script:InstallScriptRunAs32Bit = if ($null -ne $JSON_Content.installScriptRunAs32Bit) { [bool]$JSON_Content.installScriptRunAs32Bit } else { $false }
        $script:UninstallScriptFile = Resolve-AppScriptPath ([string]$JSON_Content.uninstallScriptFile)
        $script:UninstallScriptEnforceSignatureCheck = if ($null -ne $JSON_Content.uninstallScriptEnforceSignatureCheck) { [bool]$JSON_Content.uninstallScriptEnforceSignatureCheck } else { $false }
        $script:UninstallScriptRunAs32Bit = if ($null -ne $JSON_Content.uninstallScriptRunAs32Bit) { [bool]$JSON_Content.uninstallScriptRunAs32Bit } else { $false }

        # Additional Requirement Rules (array of requirement rule objects)
        $script:RequirementRules = $JSON_Content.requirementRules

        # Read optional upload parameters from Config.json
        # NewTagPath (boolean, default true)
        $rawNewTagPath = if ($null -ne $JSON_Content.newTagPath) { $JSON_Content.newTagPath } `
            elseif ($null -ne $JSON_Content.NewTagPath) { $JSON_Content.NewTagPath } `
            else { $null }
        if ($null -ne $rawNewTagPath) {
            if ($rawNewTagPath -is [bool]) {
                $script:ConfigNewTagPath = $rawNewTagPath
            }
            else {
                $script:ConfigNewTagPath = ([string]$rawNewTagPath).Trim() -in @('yes', 'true')
            }
        }
        else {
            $script:ConfigNewTagPath = $null
        }

        # RequiredGroupName - supports requiredEntraGroupName, requiredAADGroupName (string or array)
        $rawRequiredGroup = if ($JSON_Content.requiredEntraGroupName) { $JSON_Content.requiredEntraGroupName } `
            elseif ($JSON_Content.RequiredEntraGroupName) { $JSON_Content.RequiredEntraGroupName } `
            elseif ($JSON_Content.requiredAADGroupName) { $JSON_Content.requiredAADGroupName } `
            elseif ($JSON_Content.RequiredAADGroupName) { $JSON_Content.RequiredAADGroupName } `
            else { $null }
        if ($null -ne $rawRequiredGroup) {
            if ($rawRequiredGroup -is [array]) {
                $script:ConfigRequiredGroupName = @($rawRequiredGroup | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
            }
            else {
                $script:ConfigRequiredGroupName = @(([string]$rawRequiredGroup) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            }
            Write-Log -Message "Found RequiredGroupName in Config.json: $($script:ConfigRequiredGroupName -join ', ')"
        }
        else {
            $script:ConfigRequiredGroupName = @()
        }

        # AvailableGroupName - supports availableEntraGroupName, availableAADGroupName (string or array)
        $rawAvailableGroup = if ($JSON_Content.availableEntraGroupName) { $JSON_Content.availableEntraGroupName } `
            elseif ($JSON_Content.AvailableEntraGroupName) { $JSON_Content.AvailableEntraGroupName } `
            elseif ($JSON_Content.availableAADGroupName) { $JSON_Content.availableAADGroupName } `
            elseif ($JSON_Content.AvailableAADGroupName) { $JSON_Content.AvailableAADGroupName } `
            else { $null }
        if ($null -ne $rawAvailableGroup) {
            if ($rawAvailableGroup -is [array]) {
                $script:ConfigAvailableGroupName = @($rawAvailableGroup | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
            }
            else {
                $script:ConfigAvailableGroupName = @(([string]$rawAvailableGroup) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            }
            Write-Log -Message "Found AvailableGroupName in Config.json: $($script:ConfigAvailableGroupName -join ', ')"
        }
        else {
            $script:ConfigAvailableGroupName = @()
        }

        # ReplaceExistingContent (boolean)
        $rawReplaceContent = if ($null -ne $JSON_Content.replaceExistingContent) { $JSON_Content.replaceExistingContent } `
            elseif ($null -ne $JSON_Content.ReplaceExistingContent) { $JSON_Content.ReplaceExistingContent } `
            else { $null }
        if ($null -ne $rawReplaceContent) {
            if ($rawReplaceContent -is [bool]) {
                $script:ConfigReplaceExistingContent = $rawReplaceContent
            }
            else {
                $script:ConfigReplaceExistingContent = ([string]$rawReplaceContent).Trim() -in @('yes', 'true')
            }
        }
        else {
            $script:ConfigReplaceExistingContent = $null
        }

        # UninstallGroupName - supports uninstallEntraGroupName, uninstallAADGroupName (string or array)
        $rawUninstallGroup = if ($JSON_Content.uninstallEntraGroupName) { $JSON_Content.uninstallEntraGroupName } `
            elseif ($JSON_Content.UninstallEntraGroupName) { $JSON_Content.UninstallEntraGroupName } `
            elseif ($JSON_Content.uninstallAADGroupName) { $JSON_Content.uninstallAADGroupName } `
            elseif ($JSON_Content.UninstallAADGroupName) { $JSON_Content.UninstallAADGroupName } `
            else { $null }
        if ($null -ne $rawUninstallGroup) {
            if ($rawUninstallGroup -is [array]) {
                $script:ConfigUninstallGroupName = @($rawUninstallGroup | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
            }
            else {
                $script:ConfigUninstallGroupName = @(([string]$rawUninstallGroup) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            }
            Write-Log -Message "Found UninstallGroupName in Config.json: $($script:ConfigUninstallGroupName -join ', ')"
        }
        else {
            $script:ConfigUninstallGroupName = @()
        }

        # SkipPackageRemoval (boolean)
        $rawSkipRemoval = if ($null -ne $JSON_Content.skipPackageRemoval) { $JSON_Content.skipPackageRemoval } `
            elseif ($null -ne $JSON_Content.SkipPackageRemoval) { $JSON_Content.SkipPackageRemoval } `
            else { $null }
        if ($null -ne $rawSkipRemoval) {
            if ($rawSkipRemoval -is [bool]) {
                $script:ConfigSkipPackageRemoval = $rawSkipRemoval
            }
            else {
                $script:ConfigSkipPackageRemoval = ([string]$rawSkipRemoval).Trim() -in @('yes', 'true')
            }
        }
        else {
            $script:ConfigSkipPackageRemoval = $null
        }

        # Validate group name length
        if ($script:EntraGroupName.Length -gt 50) {
            Write-Log -Message "Error - Entra ID group name longer than 50 chars. Shorten then retry."
            exit
        }

        # Strip .ps1 extension, if entered into JSON file...
        if ($PackageName -and $PackageName.Length -ge 4) {
            $lastFourChars = $PackageName.Substring($PackageName.Length - 4)
            if ($lastFourChars -eq ".ps1") { $script:PackageName = $PackageName.Substring(0, $PackageName.Length - 4) }
        }
    }

    end {
        if ($Skip) { return }# Just return without doing anything else
        Write-Log -Message "Returning..."
        return
    }

}

####################################################

function Invoke-IntuneWinAppUtil {
    <#
.SYNOPSIS
This function runs the IntuneWinAppUtil tool
.DESCRIPTION
This function runs the IntuneWinAppUtil tool
.EXAMPLE
Invoke-IntuneWinAppUtil -IntuneWinAppPath PathToIntuneWinAppExecutable -PackageSourcePath PathToPackageSource -IntuneAppPackage IntuneAppPackageName
This function runs the IntuneWinAppUtil tool
.NOTES
NAME: Invoke-IntuneWinAppUtil
$Arguments = "-q -c ""$SourcePath"" -s ""$SourcePath\$PackageName.ps1"" -o ""$PSScriptRoot\IntuneWin"""
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$AppType,
        [string]$IntuneWinAppPath,
        [string]$PackageSourcePath,
        [string]$IntuneAppPackage
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "AppType: [$AppType]"
        Write-Log -Message "Using IntuneWinAppUtil path: [$IntuneWinAppPath]"
        Write-Log -Message "Using Package Source path: [$PackageSourcePath]"
        Write-Log -Message "IntuneAppPackage: [$IntuneAppPackage]"

        if ($AppType -eq "PS1") {
            Write-Log -Message "Configuring Package Name to include .PS1 extension..."
            $IntuneAppPackage = "$IntuneAppPackage.ps1"
            Write-Log -Message "IntuneAppPackage re-written as: [$IntuneAppPackage]"
        }
        elseif ($AppType -eq "EXE") {
            Write-Log -Message "Configuring Package Name to include .EXE extension..."
            $IntuneAppPackage = "$IntuneAppPackage.exe"
            Write-Log -Message "IntuneAppPackage re-written as: [$IntuneAppPackage]"
        }
        elseif ($AppType -eq "MSI") {
            Write-Log -Message "Configuring Package Name to include .MSI extension..."
            $IntuneAppPackage = "$IntuneAppPackage.msi"
            Write-Log -Message "IntuneAppPackage re-written as: [$IntuneAppPackage]"
        }

        if (!(Test-Path $IntuneWinAppPath)) {
            Write-Log -Message "Error - $IntuneWinAppPath not found, exiting..." -LogLevel 3
            $script:exitCode = -1
            return
        }
        if (!(Test-Path "$packagePath\IntuneWin")) {
            Write-Log -Message "Output path: [$packagePath\IntuneWin] not found, creating..."
            try {
                New-Item -Path "$packagePath\IntuneWin" -ItemType Directory -Force | Out-Null
            }

            catch {
                Write-Log -Message "Error creating output path: [$packagePath\IntuneWin]" -LogLevel 3
                $script:exitCode = -1
            }

        }
        else {
            Write-Log -Message "Existing output path: [$packagePath\IntuneWin] found, re-creating..."
            try {
                Remove-Item -Path "$packagePath\IntuneWin" -Recurse -Force | Out-Null
                New-Item -Path "$packagePath\IntuneWin" -ItemType Directory -Force | Out-Null
            }

            catch {
                Write-Log -Message "Error re-creating output path: [$packagePath\IntuneWin]" -LogLevel 3
                $script:exitCode = -1
            }
        }

        Write-Log -Message "Building arguments..."
        $Arguments = "-q -c ""$PackageSourcePath"" -s ""$PackageSourcePath\$IntuneAppPackage"" -o ""$packagePath\IntuneWin"""
        Write-Log -Message "Arguments built as: $Arguments"

        Write-Log -Message "Running IntuneWinApp..."
        Start-Process -FilePath $IntuneWinAppUtil -ArgumentList $Arguments -WindowStyle Hidden -Wait

        Write-Log -Message "Checking for IntuneWin output package..."
        $script:SourceFile = "$packagePath\IntuneWin\$PackageName.intunewin"
        if (Test-Path $SourceFile) {
            Write-Log -Message "File created: [$SourceFile]"
        }
        else {
            Write-Log -Message "Error - something went wrong creating IntuneWin package: [$SourceFile]" -LogLevel 3
            $script:exitCode = -1
        }
    }

    end {
        if (!($script:exitCode -eq 0)) { return $script:exitCode }# Just return without doing anything else, error tripped
        Write-Log -Message "Returning..."
        return $script:exitCode = 0
    }

}

####################################################

function Build-IntuneAppPackage {
    <#
.SYNOPSIS
This function builds the necessary config scaffold for uploading the new IntuneWin package
.DESCRIPTION
This function builds the necessary config scaffold for uploading the new IntuneWin package
.EXAMPLE
Build-IntuneAppPackage
This function builds the necessary config scaffold for uploading the new IntuneWin package
.NOTES
NAME: Build-IntuneAppPackage -AppType IntuneAppPackageType -RuleType TAGFILE -ReturnCodeType DEFAULT -InstallExperience System (or User)
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$AppType,
        [string]$RuleType,
        [string]$ReturnCodeType,
        [string]$InstallExperience,
        [string]$LogoFile,
        [string]$EntraGroupName
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        if (-not($AssignGroupsOnly)) {
            Write-Log -Message "AppType: [$AppType]"
            Write-Log -Message "RuleType: [$RuleType]"
            Write-Log -Message "ReturnCodeType: [$ReturnCodeType]"
            Write-Log -Message "InstallExperience: [$InstallExperience]"
            Write-Log -Message "LogoFile: [$LogoFile]"
            Write-Log -Message "EntraGroupName: [$EntraGroupName]"

            if ( $AppType -ne "Edge" ) {
                if ( ( $AppType -eq "PS1" ) -and ( $RuleType -eq "TAGFILE" ) -or ( $RuleType -eq "POWERSHELL" ) ) {
                    Write-Log -Message "Building variables for AppType: $AppType with RuleType: $RuleType"

                    if ($installExperience -eq "User") {
                        <#
                        $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install -userInstall -Verbose"
                        $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall -userInstall -Verbose"
                        #>
                        $installCmdLine = "%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -command `"& '.\$PackageName.ps1' -Install -UserInstall -Verbose`""
                        $uninstallCmdLine = "%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -command `"& '.\$PackageName.ps1' -UnInstall -UserInstall -Verbose`""
                    }
                    else {
                        <#
                        $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install -Verbose"
                        $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall -Verbose"
                        #>
                        $installCmdLine = "%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -command `"& '.\$PackageName.ps1' -Install -Verbose`""
                        $uninstallCmdLine = "%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -command `"& '.\$PackageName.ps1' -UnInstall -Verbose`""
                    }

                    Write-Log -Message "installCmdLine: [$installCmdLine]"
                    Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
                }
                elseif ( ( $AppType -eq "PS1" ) -and ( $RuleType -eq "REGTAG" ) -or ( $RuleType -eq "POWERSHELL" ) ) {
                    Write-Log -Message "Building variables for AppType: $AppType with RuleType: $RuleType"

                    if ($installExperience -eq "User") {
                        <#
                        $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install -userInstall -regTag -Verbose"
                        $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall -userInstall -regTag -Verbose"
                        #>
                        $installCmdLine = "%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -command `"& '.\$PackageName.ps1' -Install -UserInstall -regTag -Verbose`""
                        $uninstallCmdLine = "%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -command `"& '.\$PackageName.ps1' -UnInstall -UserInstall -regTag -Verbose`""
                    }
                    else {
                        <#
                        $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install -regTag -Verbose"
                        $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall -regTag -Verbose"
                        #>
                        $installCmdLine = "%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -command `"& '.\$PackageName.ps1' -Install -regTag -Verbose`""
                        $uninstallCmdLine = "%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -command `"& '.\$PackageName.ps1' -UnInstall -regTag -Verbose`""
                    }

                    Write-Log -Message "installCmdLine: [$installCmdLine]"
                    Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
                }
                elseif ($AppType -eq "EXE") {
                    Write-Log -Message "Building variables for AppType: $AppType"
                    Write-Log -Message "installCmdLine: [$installCmdLine]"
                    Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
                }
                elseif ($AppType -eq "MSI") {
                    Write-Log -Message "Building variables for AppType: $AppType"
                    Write-Log -Message "installCmdLine: [$installCmdLine]"
                    Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
                }

                if ( ( $RuleType -eq "TAGFILE" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
                    Write-Log -Message "Building variables for RuleType: $RuleType"
                    if ($installExperience -eq "System") {
                        Write-Log -Message "Creating TagFile detection rule for System install"

                        if ($NewTagPath) {
                            $tagPath = "%PROGRAMDATA%\Microsoft\IntuneManagementExtension\Logs"
                            Write-Log -Message "Using new Tagfile path: $tagPath"
                        }
                        else {
                            $tagPath = "%PROGRAMDATA%\Microsoft\IntuneApps\$PackageName"
                            Write-Log -Message "Using Tagfile path: $tagPath"
                        }
                        $FileRule = New-DetectionRule -File -Path $tagPath `
                            -FileOrFolderName "$PackageName.tag" -FileDetectionType exists -check32BitOn64System False
                    }
                    elseif ($installExperience -eq "User") {
                        Write-Log -Message "Creating TagFile detection rule for User install"
                        $FileRule = New-DetectionRule -File -Path "%LOCALAPPDATA%\Microsoft\IntuneApps\$PackageName" `
                            -FileOrFolderName "$PackageName.tag" -FileDetectionType exists -check32BitOn64System False
                    }

                    #Write-Log -Message "FileRule: [$FileRule]"
                    Write-Log -Message "FileRule: [$($FileRule | Out-String)]"

                    # Creating Array for detection Rule
                    $DetectionRule = @($FileRule)
                }
                elseif ( ( $RuleType -eq "FILE" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
                    Write-Log -Message "Building variables for RuleType: $RuleType"
                    $fileDetectPath = Split-Path -Parent $FilePath
                    $fileDetectFile = Split-Path -Leaf $FilePath
                    Write-Log -Message "fileDetectPath: $fileDetectPath"
                    Write-Log -Message "fileDetectFile: $fileDetectFile"

                    $FileRule = New-DetectionRule -File -Path $fileDetectPath `
                        -FileOrFolderName $fileDetectFile -FileDetectionType exists -check32BitOn64System False
                    Write-Log -Message "FileRule: [$FileRule]"

                    # Creating Array for detection Rule
                    $DetectionRule = @($FileRule)
                }
                elseif ( ( $RuleType -eq "REGTAG" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
                    Write-Log -Message "Building variables for RuleType: $RuleType"
                    if ($installExperience -eq "System") {
                        Write-Log -Message "Creating RegTag detection rule for System install"

                        $RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$PackageName" `
                            -RegistryDetectionType exists -check32BitRegOn64System True -RegistryValue "Installed"
                    }
                    elseif ($installExperience -eq "User") {
                        Write-Log -Message "Creating RegTag detection rule for User install"

                        $RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$PackageName" `
                            -RegistryDetectionType exists -check32BitRegOn64System True -RegistryValue "Installed"
                    }
                    #Write-Log -Message "RegistryRule: [$RegistryRule]"
                    Write-Log -Message "RegistryRule: [$($RegistryRule.GetEnumerator() | ForEach-Object {"$($_.Key):$($_.Value)"})]"

                    # Creating Array for detection Rule
                    $DetectionRule = @($RegistryRule)
                }
                elseif ( ( $RuleType -eq "FILE" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
                    Write-Log -Message "Building variables for RuleType: $RuleType"
                    $fileDetectPath = Split-Path -Parent $FilePath
                    $fileDetectFile = Split-Path -Leaf $FilePath
                    Write-Log -Message "fileDetectPath: $fileDetectPath"
                    Write-Log -Message "fileDetectFile: $fileDetectFile"

                    if (($FileDetectionType -eq "exists") -or ($FileDetectionType -eq "doesNotExist")) {

                        $FileRule = New-DetectionRule -File -Path $fileDetectPath -FileOrFolderName $fileDetectFile -FileDetectionType $FileDetectionType `
                            -check32BitOn64System False
                    }
                    else {

                        $FileRule = New-DetectionRule -File -Path $fileDetectPath -FileOrFolderName $fileDetectFile -FileDetectionType $FileDetectionType `
                            -FileDetectionOperator $FileDetectionOperator -FileDetectionValue $FileDetectionValue -check32BitOn64System False

                    }
                    Write-Log -Message "FileRule: [$($FileRule.GetEnumerator() | ForEach-Object {"$($_.Key):$($_.Value)"})]"

                    # Creating Array for detection Rule
                    $DetectionRule = @($FileRule)
                }
                elseif ( ( $RuleType -eq "REGISTRY" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
                    Write-Log -Message "Building variables for RuleType: $RuleType"

                    if (($RegistryDetectionType -eq "exists") -or ($RegistryDetectionType -eq "doesNotExist")) {

                        $RegistryRule = New-DetectionRule -Registry -RegistryKeyPath $RegistryKeyPath -RegistryValue $RegistryValue `
                            -RegistryDetectionType $RegistryDetectionType -check32BitRegOn64System False
                    }
                    else {

                        $RegistryRule = New-DetectionRule -Registry -RegistryKeyPath $RegistryKeyPath -RegistryValue $RegistryValue -RegistryDetectionType $RegistryDetectionType `
                            -RegistryDetectionOperator $RegistryDetectionOperator -RegistryDetectionValue $RegistryDetectionValue -check32BitRegOn64System False

                    }

                    Write-Log -Message "RegistryRule: [$($RegistryRule.GetEnumerator() | ForEach-Object {"$($_.Key):$($_.Value)"})]"

                    # Creating Array for detection Rule
                    $DetectionRule = @($RegistryRule)
                }
                elseif ( ( $RuleType -eq "MSI" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
                    Write-Log -Message "Building variables for RuleType: $RuleType"

                    if ($MSIProductVersionOperator -ne "notConfigured") {

                        $MSIRule = New-DetectionRule -MSI -MSIProductCode $MSIProductCode -MSIProductVersionOperator $MSIProductVersionOperator `
                            -MSIProductVersion $MSIProductVersion
                    }
                    else {

                        $MSIRule = New-DetectionRule -MSI -MSIProductCode $MSIProductCode
                    }

                    Write-Log -Message "MSIRule: [$($MSIRule.GetEnumerator() | ForEach-Object {"$($_.Key):$($_.Value)"})]"

                    # Creating Array for detection Rule
                    $DetectionRule = @($MSIRule)
                }
                elseif ($RuleType -eq "POWERSHELL" ) {
                    Write-Log -Message "Building variables for RuleType: $RuleType"

                    $PowerShellDetectPath = "$packagePath" + "\Detection\" + $PackageName + "_Detect.ps1"

                    $PowerShellRule = New-DetectionRule -PowerShell -ScriptFile $PowerShellDetectPath -enforceSignatureCheck False -runAs32Bit False

                    Write-Log -Message "PowerShellRule: [$($PowerShellRule.GetEnumerator() | ForEach-Object {"$($_.Key):$($_.Value)"})]"

                    # Creating Array for detection Rule
                    $DetectionRule = @($PowerShellRule)
                }
                else {
                    Write-Log -Message "Using MSI detection rule"
                    $DetectionRule = "MSI"
                }

                if ($ReturnCodeType -eq "DEFAULT") {
                    Write-Log -Message "Building variables for ReturnCodeType: $ReturnCodeType"
                    $ReturnCodes = Get-DefaultReturnCodes
                }

                #$installExperience = "System"

                # Load logo icon from config file if specified, or auto-detect
                $Icon = $null
                if (-not [string]::IsNullOrWhiteSpace($LogoFile)) {
                    $logoFullPath = "$packagePath\$LogoFile"
                    Write-Log -Message "Checking for logo file at: $logoFullPath"
                    if (Test-Path -Path $logoFullPath) {
                        Write-Log -Message "Logo file found, loading..."
                        $Icon = New-IntuneWin32AppIcon -FilePath $logoFullPath
                        if (-not [string]::IsNullOrWhiteSpace($Icon)) {
                            Write-Log -Message "Logo icon loaded successfully (Base64 length: $($Icon.Length))"
                        }
                        else {
                            Write-Log -Message "Warning: Logo file found but failed to encode to Base64" -LogLevel 2
                        }
                    }
                    else {
                        Write-Log -Message "Warning: Logo file specified in config but not found at: $logoFullPath" -LogLevel 2
                    }
                }
                else {
                    # Auto-detect a PNG/JPG/JPEG in the package folder
                    $autoLogo = Get-ChildItem -Path $packagePath -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -match '^\.(png|jpg|jpeg)$' } |
                    Select-Object -First 1
                    if ($autoLogo) {
                        $LogoFile = $autoLogo.Name
                        $script:LogoFile = $LogoFile
                        Write-Log -Message "Auto-detected logo file: $LogoFile"
                        $Icon = New-IntuneWin32AppIcon -FilePath $autoLogo.FullName
                        if (-not [string]::IsNullOrWhiteSpace($Icon)) {
                            Write-Log -Message "Auto-detected logo icon loaded successfully (Base64 length: $($Icon.Length))"
                        }
                    }
                    else {
                        Write-Log -Message "No logo file specified in config and none auto-detected in package folder"
                    }
                }

            }

            # Process extended settings from config
            Write-Log -Message "Processing extended settings from config..."

            # Log minimum supported OS if specified (conversion happens in Get-Win32AppBody)
            if (-not [string]::IsNullOrWhiteSpace($script:MinimumSupportedOS)) {
                Write-Log -Message "MinimumSupportedOS from config: $($script:MinimumSupportedOS)"
            }

            # Process custom return codes
            $customReturnCodesList = @()
            if ($script:CustomReturnCodes) {
                if ($script:CustomReturnCodes -is [string]) {
                    # Parse comma-separated code:type pairs from XML
                    $pairs = $script:CustomReturnCodes -split ','
                    foreach ($pair in $pairs) {
                        $pair = $pair.Trim()
                        if ($pair -match '^(-?\d+):(\w+)$') {
                            $code = [int]$Matches[1]
                            $type = $Matches[2].ToLower()
                            $returnCodeObj = New-CustomReturnCode -returnCode $code -type $type
                            if ($returnCodeObj) {
                                $customReturnCodesList += $returnCodeObj
                            }
                        }
                    }
                }
                elseif ($script:CustomReturnCodes -is [array]) {
                    # Process array of objects from JSON
                    foreach ($rc in $script:CustomReturnCodes) {
                        if ($rc.returnCode -and $rc.type) {
                            $returnCodeObj = New-CustomReturnCode -returnCode $rc.returnCode -type $rc.type
                            if ($returnCodeObj) {
                                $customReturnCodesList += $returnCodeObj
                            }
                        }
                    }
                }
                if ($customReturnCodesList.Count -gt 0) {
                    Write-Log -Message "Parsed $($customReturnCodesList.Count) custom return code(s)"
                }
            }

            # Process additional requirement rules
            $additionalRequirementRules = @()
            if ($script:RequirementRules) {
                foreach ($rule in $script:RequirementRules) {
                    if ($rule.ruleType) {
                        $reqRule = New-RequirementRule -ruleType $rule.ruleType `
                            -path $rule.path `
                            -fileOrFolderName $rule.fileOrFolderName `
                            -check32BitOn64System $rule.check32BitOn64System `
                            -detectionType $rule.detectionType `
                            -operator $rule.operator `
                            -detectionValue $rule.detectionValue `
                            -keyPath $rule.keyPath `
                            -valueName $rule.valueName `
                            -scriptFile $rule.scriptFile `
                            -runAs32Bit $rule.runAs32Bit `
                            -runAsAccount $rule.runAsAccount `
                            -enforceSignatureCheck $rule.enforceSignatureCheck
                        if ($reqRule) {
                            $additionalRequirementRules += $reqRule
                        }
                    }
                }
                if ($additionalRequirementRules.Count -gt 0) {
                    Write-Log -Message "Parsed $($additionalRequirementRules.Count) additional requirement rule(s)"
                }
            }

            #If ($AppType -eq "Edge") {
            #    $displayName = 'Microsoft Edge Stable1'
            #}
            Write-Log -Message "Find application ID"
            $appID = Get-ApplicationID -AppName $displayName

            #Check if package already exists
            if ( ! ( Test-Null ( $appID ) ) ) {
                if ($ReplaceExistingContent) {
                    Write-Log -Message "Detected existing package in Intune: $displayName"
                    Write-Log -Message "ReplaceExistingContent mode: Updating content only..."
                    Write-Host
                    Write-Host "Replacing content for existing application: $displayName" -ForegroundColor Yellow
                    Write-Host "Application ID: $appID" -ForegroundColor Cyan
                    Write-Host

                    # Get the existing app details to check for logo and assignments
                    Write-Log -Message "Getting existing application details..."
                    $existingApp = Get-ApplicationAssignment -ApplicationId $appID

                    # Check if the existing application has any assignments
                    Write-Log -Message "Checking for existing assignments on application..."
                    $existingAssignments = $existingApp.assignments
                    if ($null -eq $existingAssignments -or $existingAssignments.Count -eq 0) {
                        Write-Log -Message "No existing assignments found - will apply provided assignment groups"
                        Write-Host "No existing assignments found - will apply provided assignment groups" -ForegroundColor Cyan
                        $script:noExistingAssignments = $true
                    }
                    else {
                        Write-Log -Message "Found $($existingAssignments.Count) existing assignment(s) - preserving existing assignments"
                        Write-Host "Found $($existingAssignments.Count) existing assignment(s) - preserving existing assignments" -ForegroundColor Green
                        $script:noExistingAssignments = $false
                    }

                    # Check if logo needs to be added (existing app has no logo but config defines one)
                    Write-Log -Message "Checking logo status..."

                    # First, load the logo from the config if specified (in case it wasn't loaded earlier)
                    # This can happen when ReplaceExistingContent is used and the logo loading block was skipped
                    if ($null -eq $Icon -and -not [string]::IsNullOrWhiteSpace($LogoFile)) {
                        $logoFullPath = "$packagePath\$LogoFile"
                        Write-Log -Message "Logo not loaded yet, checking for logo file at: $logoFullPath"
                        if (Test-Path -Path $logoFullPath) {
                            Write-Log -Message "Logo file found, loading..."
                            $Icon = New-IntuneWin32AppIcon -FilePath $logoFullPath
                            if (-not [string]::IsNullOrWhiteSpace($Icon)) {
                                Write-Log -Message "Logo icon loaded successfully (Base64 length: $($Icon.Length))"
                            }
                            else {
                                Write-Log -Message "Warning: Logo file found but failed to encode to Base64" -LogLevel 2
                            }
                        }
                        else {
                            Write-Log -Message "Warning: Logo file specified in config but not found at: $logoFullPath" -LogLevel 2
                        }
                    }

                    # Fetch the largeIcon property separately - Graph API doesn't return it by default
                    Write-Log -Message "Fetching existing application largeIcon property..."
                    $iconResponse = Get-ApplicationLargeIcon -ApplicationId $appID
                    $existingIcon = $null
                    if ($null -ne $iconResponse) {
                        $existingIcon = $iconResponse.largeIcon
                    }

                    # Debug: Log the state of the icon variables
                    $hasExistingIcon = ($null -ne $existingIcon -and $null -ne $existingIcon.value -and -not([string]::IsNullOrEmpty($existingIcon.value)))
                    $hasConfigIcon = ($null -ne $Icon -and -not([string]::IsNullOrEmpty($Icon)))
                    Write-Log -Message "Existing app has icon: $hasExistingIcon"
                    if ($hasExistingIcon) {
                        Write-Log -Message "Existing icon type: $($existingIcon.type)"
                        Write-Log -Message "Existing icon value length: $($existingIcon.value.Length)"
                    }
                    Write-Log -Message "Config defines icon: $hasConfigIcon"
                    if ($hasConfigIcon) {
                        Write-Log -Message "Config icon Base64 length: $($Icon.Length)"
                    }

                    if ($hasConfigIcon -and (-not $hasExistingIcon)) {
                        Write-Log -Message "Existing app has no logo but config defines one - will add logo"
                        Write-Host "Adding logo to existing application..." -ForegroundColor Cyan

                        # Determine image type based on file extension
                        $imageType = "image/png"
                        if (-not [string]::IsNullOrWhiteSpace($LogoFile)) {
                            $extension = [System.IO.Path]::GetExtension($LogoFile).ToLower()
                            switch ($extension) {
                                ".jpg" { $imageType = "image/jpeg" }
                                ".jpeg" { $imageType = "image/jpeg" }
                                ".png" { $imageType = "image/png" }
                            }
                        }
                        Write-Log -Message "Using image type: $imageType"

                        # Update the app with the logo using direct Graph API call
                        # Note: Using explicit JSON conversion with -Compress to ensure proper formatting
                        $logoBody = @{
                            "@odata.type" = "#microsoft.graph.win32LobApp"
                            "largeIcon"   = @{
                                "type"  = $imageType
                                "value" = $Icon
                            }
                        }
                        $logoUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appID"
                        Write-Log -Message "Logo PATCH URI: $logoUri"
                        Write-Log -Message "Logo icon Base64 length: $($Icon.Length)"
                        try {
                            # Convert to JSON explicitly with proper depth to ensure correct serialization
                            $logoJson = $logoBody | ConvertTo-Json -Depth 10 -Compress
                            # Using Invoke-MgGraphRequest with pre-serialized JSON string and explicit content type
                            $null = Invoke-MgGraphRequest -Uri $logoUri -Method PATCH -Body $logoJson -ContentType "application/json"
                            Write-Log -Message "Logo added successfully"
                            Write-Host "Logo added successfully" -ForegroundColor Green
                        }
                        catch {
                            Write-Log -Message "Warning: Failed to add logo - $_" -LogLevel 2
                            Write-Host "Warning: Failed to add logo - $_" -ForegroundColor Yellow
                            Write-Host "Continuing with content update..." -ForegroundColor Yellow
                        }
                    }
                    elseif ($hasExistingIcon) {
                        Write-Log -Message "Existing app already has a logo - preserving existing logo"
                        Write-Host "Existing app already has a logo - preserving existing logo" -ForegroundColor Green
                    }
                    elseif (-not $hasConfigIcon) {
                        Write-Log -Message "No logo defined in config file - skipping logo update"
                        Write-Host "No logo defined in config file" -ForegroundColor Gray
                    }

                    # Check publishingState before update — a stuck app needs to be deleted and recreated
                    $stuckAppDeleted = $false
                    $isPublished = Wait-AppPublishingState -AppId $appID -DisplayName $displayName
                    if (-not $isPublished) {
                        Write-Host "    Deleting stuck app '$displayName' (ID: $appID)..." -ForegroundColor Yellow
                        $deleteUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appID"
                        Invoke-MgGraphRequest -Method DELETE -Uri $deleteUri | Out-Null
                        Start-Sleep -Seconds 5
                        Write-Host "    Stuck app deleted — falling through to full upload path" -ForegroundColor Green
                        # Clear appID so the main flow treats this as a new app
                        $appID = $null
                        $stuckAppDeleted = $true
                    }
                    else {
                        # Call the content replacement function
                        Update-Win32LobContent -AppId $appID -SourceFile $script:SourceFile
                    }

                    # When a stuck app was deleted there is no longer an app to patch. Skip the
                    # content-replacement post-processing (settings/category PATCH calls fail with
                    # a null appID) and leave $script:contentReplaced unset so the normal upload
                    # path below recreates the application from scratch.
                    if (-not $stuckAppDeleted) {
                        Write-Log -Message "Content replacement completed for: $displayName"

                        # Set allowAvailableUninstall based on config (defaults to true)
                        $allowUninstallValue = $script:AllowAvailableUninstall
                        $allowUninstallLabel = if ($allowUninstallValue) { "Enabled" } else { "Disabled" }
                        Write-Log -Message "Setting allowAvailableUninstall to $allowUninstallValue..."
                        $uninstallBody = @{
                            "@odata.type"             = "#microsoft.graph.win32LobApp"
                            "allowAvailableUninstall" = $allowUninstallValue
                        }
                        $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appID"
                        try {
                            # Using Invoke-MgGraphRequest with hashtable
                            $null = Invoke-MgGraphRequest -Uri $appUri -Method PATCH -Body $uninstallBody
                            Write-Log -Message "allowAvailableUninstall set to $allowUninstallValue successfully"
                            Write-Host "Allow available uninstall: $allowUninstallLabel" -ForegroundColor Green
                        }
                        catch {
                            Write-Log -Message "Warning: Failed to set allowAvailableUninstall - $_" -LogLevel 2
                            Write-Host "Warning: Failed to set allowAvailableUninstall - $_" -ForegroundColor Yellow
                        }

                        # Re-apply settings from config file (description, displayVersion, publisher)
                        Write-Log -Message "Re-applying settings from config file..."
                        Write-Host "Updating application properties from config..." -ForegroundColor Cyan

                        # Build minimum supported OS properties for ReplaceExistingContent
                        $minOSResultForReplace = $null
                        if (-not [string]::IsNullOrWhiteSpace($script:MinimumSupportedOS)) {
                            $minOSResultForReplace = Get-MinimumOperatingSystemObject -MinimumOS $script:MinimumSupportedOS
                        }

                        $settingsBody = @{
                            "@odata.type"    = "#microsoft.graph.win32LobApp"
                            "description"    = $script:Description
                            "displayVersion" = $script:displayVersion
                            "publisher"      = $script:Publisher
                        }

                        # Add logo to settings body if loaded from config
                        if (-not [string]::IsNullOrWhiteSpace($Icon)) {
                            # Determine image type based on file extension
                            $imageType = "image/png"
                            if (-not [string]::IsNullOrWhiteSpace($LogoFile)) {
                                $extension = [System.IO.Path]::GetExtension($LogoFile).ToLower()
                                switch ($extension) {
                                    ".jpg" { $imageType = "image/jpeg" }
                                    ".jpeg" { $imageType = "image/jpeg" }
                                    ".png" { $imageType = "image/png" }
                                }
                            }
                            $settingsBody["largeIcon"] = @{
                                "type"  = $imageType
                                "value" = $Icon
                            }
                            Write-Log -Message "Including logo in settings update (Base64 length: $($Icon.Length))"
                        }

                        # Add extended settings if they are provided in config
                        if ($script:IsFeatured -eq $true) {
                            $settingsBody["isFeatured"] = $true
                        }
                        if (-not [string]::IsNullOrWhiteSpace($script:InformationUrl)) {
                            $settingsBody["informationUrl"] = $script:InformationUrl
                        }
                        if (-not [string]::IsNullOrWhiteSpace($script:PrivacyInformationUrl)) {
                            $settingsBody["privacyInformationUrl"] = $script:PrivacyInformationUrl
                        }
                        if (-not [string]::IsNullOrWhiteSpace($script:Developer)) {
                            $settingsBody["developer"] = $script:Developer
                        }
                        if (-not [string]::IsNullOrWhiteSpace($script:Owner)) {
                            $settingsBody["owner"] = $script:Owner
                        }
                        if (-not [string]::IsNullOrWhiteSpace($script:Notes)) {
                            $settingsBody["notes"] = $script:Notes
                        }

                        # Add install experience settings
                        $installExp = @{
                            "runAsAccount" = $script:InstallExperience
                        }
                        if ($script:MaxRunTimeInMinutes -gt 0) {
                            $installExp["maxRunTimeInMinutes"] = $script:MaxRunTimeInMinutes
                        }
                        if (-not [string]::IsNullOrWhiteSpace($script:DeviceRestartBehavior)) {
                            $installExp["deviceRestartBehavior"] = $script:DeviceRestartBehavior
                        }
                        $settingsBody["installExperience"] = $installExp

                        # Add system requirement settings
                        if ($script:MinimumFreeDiskSpaceInMB -gt 0) {
                            $settingsBody["minimumFreeDiskSpaceInMB"] = $script:MinimumFreeDiskSpaceInMB
                        }
                        if ($script:MinimumMemoryInMB -gt 0) {
                            $settingsBody["minimumMemoryInMB"] = $script:MinimumMemoryInMB
                        }
                        if ($script:MinimumNumberOfProcessors -gt 0) {
                            $settingsBody["minimumNumberOfProcessors"] = $script:MinimumNumberOfProcessors
                        }
                        if ($script:MinimumCpuSpeedInMHz -gt 0) {
                            $settingsBody["minimumCpuSpeedInMHz"] = $script:MinimumCpuSpeedInMHz
                        }
                        if (-not [string]::IsNullOrWhiteSpace($script:AllowedArchitectures)) {
                            $settingsBody["applicableArchitectures"] = $script:AllowedArchitectures
                        }
                        if ($null -ne $minOSResultForReplace) {
                            if ($null -ne $minOSResultForReplace.osObject) {
                                $settingsBody["minimumSupportedOperatingSystem"] = $minOSResultForReplace.osObject
                            }
                            if ($minOSResultForReplace.windowsRelease) {
                                $settingsBody["minimumSupportedWindowsRelease"] = $minOSResultForReplace.windowsRelease
                            }
                        }

                        try {
                            # Convert to JSON explicitly with proper depth to ensure correct serialization (especially for largeIcon)
                            $settingsJson = $settingsBody | ConvertTo-Json -Depth 10 -Compress
                            $null = Invoke-MgGraphRequest -Uri $appUri -Method PATCH -Body $settingsJson -ContentType "application/json"
                            Write-Log -Message "Settings updated: description, displayVersion, publisher and extended settings"
                            Write-Host "Description: Updated" -ForegroundColor Green
                            Write-Host "Display Version: $($script:displayVersion)" -ForegroundColor Green
                            Write-Host "Publisher: $($script:Publisher)" -ForegroundColor Green
                            if (-not [string]::IsNullOrWhiteSpace($Icon)) { Write-Host "Logo: Updated" -ForegroundColor Green }
                            if ($script:IsFeatured) { Write-Host "Featured App: $($script:IsFeatured)" -ForegroundColor Green }
                            if ($script:InformationUrl) { Write-Host "Information URL: $($script:InformationUrl)" -ForegroundColor Green }
                            if ($script:PrivacyInformationUrl) { Write-Host "Privacy URL: $($script:PrivacyInformationUrl)" -ForegroundColor Green }
                            if ($script:Developer) { Write-Host "Developer: $($script:Developer)" -ForegroundColor Green }
                            if ($script:Owner) { Write-Host "Owner: $($script:Owner)" -ForegroundColor Green }
                            if ($script:MaxRunTimeInMinutes -gt 60) { Write-Host "Max Run Time: $($script:MaxRunTimeInMinutes) minutes" -ForegroundColor Green }
                            if ($script:DeviceRestartBehavior -ne "suppress") { Write-Host "Device Restart Behavior: $($script:DeviceRestartBehavior)" -ForegroundColor Green }
                        }
                        catch {
                            Write-Log -Message "Warning: Failed to update settings - $_" -LogLevel 2
                            Write-Host "Warning: Failed to update settings - $_" -ForegroundColor Yellow
                        }

                        # Apply categories from config file (supports multiple comma-separated categories)
                        if ($script:Categories -and $script:Categories.Count -gt 0) {
                            Write-Log -Message "Applying categories from config: $($script:Categories -join ', ')"
                            foreach ($cat in $script:Categories) {
                                $categoryResult = Set-IntuneAppCategory -ApplicationId $appID -CategoryName $cat
                                if (-not $categoryResult) {
                                    Write-Log -Message "Warning: Category assignment may have failed for '$cat'" -LogLevel 2
                                }
                            }
                        }

                        # Skip the normal upload process and group assignment when just replacing content
                        # Jump to scope tag handling if specified
                        $script:contentReplaced = $true
                    }
                    else {
                        Write-Log -Message "Stuck app was deleted - proceeding with full upload to recreate the application"
                        Write-Host "Recreating application from scratch..." -ForegroundColor Cyan
                    }
                }
                elseif ($ReplaceExistingAssignments) {
                    # ReplaceExistingAssignments mode - skip content upload, just update assignments
                    Write-Log -Message "Detected existing package in Intune: $displayName"
                    Write-Log -Message "ReplaceExistingAssignments mode: Updating assignments only..."
                    Write-Host
                    Write-Host "Replacing assignments for existing application: $displayName" -ForegroundColor Yellow
                    Write-Host "Application ID: $appID" -ForegroundColor Cyan
                    Write-Host

                    # Mark content as replaced to skip upload but allow assignment processing
                    $script:contentReplaced = $true
                }
                else {
                    Write-Log -Message "Detected existing package in Intune: $displayName"
                    Write-Log -Message "Use -ReplaceExistingContent to update the IntuneWin content only."
                    Write-Log -Message "Upload content: "
                    Write-Host
                    Write-Host "$script:SourceFile" -ForegroundColor Cyan
                    Write-Host
                    Write-Host "Tip: Use -ReplaceExistingContent parameter to replace the package content while keeping all configuration." -ForegroundColor Yellow
                    Write-Host "Tip: Use -ReplaceExistingAssignments parameter to replace the assignments only." -ForegroundColor Yellow
                    Write-Host
                    Write-Host "App already exists and is published — skipping upload (use -ReplaceExistingContent to replace)" -ForegroundColor Yellow
                    Write-Log -Message "App already exists and is published — skipping upload (use -ReplaceExistingContent to replace)"
                    $script:exitCode = 0
                    return 0
                }
            }
            else {
                if ($ReplaceExistingContent) {
                    Write-Log -Message "Application not found in Intune: $displayName - will create new application instead of replacing" -LogLevel 2
                    Write-Host
                    Write-Host "Application '$displayName' not found in Intune." -ForegroundColor Yellow
                    Write-Host "Creating new application instead of replacing existing content..." -ForegroundColor Cyan
                    Write-Host
                }
                if ($ReplaceExistingAssignments) {
                    Write-Log -Message "Error: -ReplaceExistingAssignments specified but application not found: $displayName" -LogLevel 3
                    Write-Host
                    Write-Host "Error: Cannot replace assignments - application '$displayName' not found in Intune." -ForegroundColor Red
                    Write-Host "The application must already exist to use -ReplaceExistingAssignments." -ForegroundColor Yellow
                    Write-Host
                    exit
                }
                Write-Log -Message "Existing package not found"
            }

            # Skip upload if content was already replaced
            if ($script:contentReplaced) {
                Write-Log -Message "Skipping new app upload - content replacement mode"
            }
            # Win32 Application Upload
            elseif ($AppType -eq "MSI") {
                Write-Log -Message "Preparing MSI package"

                # Build common extended parameters hashtable for splatting
                $extendedParams = @{
                    isFeatured                = $script:IsFeatured
                    informationUrl            = $script:InformationUrl
                    privacyInformationUrl     = $script:PrivacyInformationUrl
                    developer                 = $script:Developer
                    owner                     = $script:Owner
                    notes                     = $script:Notes
                    maxRunTimeInMinutes       = $script:MaxRunTimeInMinutes
                    deviceRestartBehavior     = $script:DeviceRestartBehavior
                    minimumFreeDiskSpaceInMB  = $script:MinimumFreeDiskSpaceInMB
                    minimumMemoryInMB         = $script:MinimumMemoryInMB
                    minimumNumberOfProcessors = $script:MinimumNumberOfProcessors
                    minimumCpuSpeedInMHz      = $script:MinimumCpuSpeedInMHz
                    allowedArchitectures      = $script:AllowedArchitectures
                    minimumSupportedOS        = $script:MinimumSupportedOS
                    requirementRules          = $additionalRequirementRules
                }

                if ( ( ! ( Test-Null( $installCmdLine) ) ) -and ( ! ( Test-Null( $uninstallCmdLine ) ) ) ) {
                    Send-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                        -returnCodes $ReturnCodes -displayName $displayName -msiInstallCommandLine $installCmdLine -msiUninstallCommandLine $uninstallCmdLine `
                        -installExperience $installExperience -logo $Icon -Category $Category @extendedParams
                }
                elseif ( ( ! ( Test-Null( $installCmdLine ) ) ) -and ( Test-Null( $uninstallCmdLine ) ) ) {
                    Send-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                        -returnCodes $ReturnCodes -displayName $displayName -msiInstallCommandLine $installCmdLine `
                        -installExperience $installExperience -logo $Icon -Category $Category @extendedParams
                }
                elseif ( ( Test-Null( $installCmdLine ) ) -and ( ! ( Test-Null( $uninstallCmdLine ) ) ) ) {
                    Send-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                        -returnCodes $ReturnCodes -displayName $displayName -msiUninstallCommandLine $uninstallCmdLine `
                        -installExperience $installExperience -logo $Icon -Category $Category @extendedParams
                }
                elseif ( ( Test-Null( $installCmdLine ) ) -and ( Test-Null( $uninstallCmdLine ) ) ) {
                    Send-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                        -returnCodes $ReturnCodes -displayName $displayName `
                        -installExperience $installExperience -logo $Icon -Category $Category @extendedParams
                }
            }
            elseif ($AppType -eq "EXE") {
                Write-Log -Message "Preparing EXE package"

                # Build common extended parameters hashtable for splatting
                $extendedParams = @{
                    isFeatured                = $script:IsFeatured
                    informationUrl            = $script:InformationUrl
                    privacyInformationUrl     = $script:PrivacyInformationUrl
                    developer                 = $script:Developer
                    owner                     = $script:Owner
                    notes                     = $script:Notes
                    maxRunTimeInMinutes       = $script:MaxRunTimeInMinutes
                    deviceRestartBehavior     = $script:DeviceRestartBehavior
                    minimumFreeDiskSpaceInMB  = $script:MinimumFreeDiskSpaceInMB
                    minimumMemoryInMB         = $script:MinimumMemoryInMB
                    minimumNumberOfProcessors = $script:MinimumNumberOfProcessors
                    minimumCpuSpeedInMHz      = $script:MinimumCpuSpeedInMHz
                    allowedArchitectures      = $script:AllowedArchitectures
                    minimumSupportedOS        = $script:MinimumSupportedOS
                    requirementRules          = $additionalRequirementRules
                }

                # Graph still requires both command lines even when a PowerShell script supersedes them
                if ([string]::IsNullOrWhiteSpace($installCmdLine) -and -not [string]::IsNullOrWhiteSpace($script:InstallScriptFile)) {
                    $installCmdLine = "powershell.exe -ExecutionPolicy Bypass -File `".\$(Split-Path $script:InstallScriptFile -Leaf)`""
                    Write-Log -Message "No installCmdLine configured - using placeholder for script installer: $installCmdLine"
                }
                if ([string]::IsNullOrWhiteSpace($uninstallCmdLine) -and -not [string]::IsNullOrWhiteSpace($script:UninstallScriptFile)) {
                    $uninstallCmdLine = "powershell.exe -ExecutionPolicy Bypass -File `".\$(Split-Path $script:UninstallScriptFile -Leaf)`""
                    Write-Log -Message "No uninstallCmdLine configured - using placeholder for script uninstaller: $uninstallCmdLine"
                }

                Send-Win32Lob -EXE -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -installCommandLine $installCmdLine -uninstallCommandLine $uninstallCmdLine `
                    -installExperience $installExperience -logo $Icon -Category $Category @extendedParams
            }
            elseif ($AppType -eq "PS1") {
                Write-Log -Message "Preparing PS1 package"

                # Build common extended parameters hashtable for splatting
                $extendedParams = @{
                    isFeatured                = $script:IsFeatured
                    informationUrl            = $script:InformationUrl
                    privacyInformationUrl     = $script:PrivacyInformationUrl
                    developer                 = $script:Developer
                    owner                     = $script:Owner
                    notes                     = $script:Notes
                    maxRunTimeInMinutes       = $script:MaxRunTimeInMinutes
                    deviceRestartBehavior     = $script:DeviceRestartBehavior
                    minimumFreeDiskSpaceInMB  = $script:MinimumFreeDiskSpaceInMB
                    minimumMemoryInMB         = $script:MinimumMemoryInMB
                    minimumNumberOfProcessors = $script:MinimumNumberOfProcessors
                    minimumCpuSpeedInMHz      = $script:MinimumCpuSpeedInMHz
                    allowedArchitectures      = $script:AllowedArchitectures
                    minimumSupportedOS        = $script:MinimumSupportedOS
                    requirementRules          = $additionalRequirementRules
                }

                Send-Win32Lob -PS1 -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -ps1InstallCommandLine $InstallCmdLine -ps1UninstallCommandLine $UninstallCmdLine `
                    -installExperience $installExperience -logo $Icon -Category $Category @extendedParams
            }
            elseif ($AppType -eq "Edge") {
                Write-Log -Message "Preparing Edge package"
                #$Publisher = 'Microsoft'
                #$Description = 'Microsoft Edge is the browser for business with modern and legacy web compatibility, new privacy features such as Tracking prevention, and built-in productivity tools such as enterprise-grade PDF support and access to Office and corporate search right from a new tab.'
                #$displayName = 'Microsoft Edge Stable1'
                #$channel = 'stable'

                Send-Win32Lob -Edge -publisher "$Publisher" -description "$Description" `
                    -displayName $displayName -channel $channel

                <#
            $body.displayName = "";
            $body.description = "";
            $body.publisher = "";
            $body.largeIcon = $null;
            $body.isFeatured = $false;
            $body.privacyInformationUrl = "https://privacy.microsoft.com/en-US/privacystatement";
            $body.informationUrl = "https://www.microsoft.com/en-us/windows/microsoft-edge";
            $body.owner = "Microsoft";
            $body.developer = "Microsoft";
            $body.notes = "";
            $body.uploadState = 1;
            $body.publishingState = "published";
            $body.channel = "stable";
            #>
            }
        }

        # Apply logo as a dedicated PATCH after content commit to ensure persistence
        # The logo in the initial POST body can be lost during content commit processing
        if (-not $script:contentReplaced -and $AppType -ne "Edge" -and -not [string]::IsNullOrWhiteSpace($Icon)) {
            $logoAppID = Get-ApplicationID -AppName $displayName
            if (-not (Test-Null($logoAppID))) {
                # Determine image MIME type from logo file extension
                $logoImageType = "image/png"
                if (-not [string]::IsNullOrWhiteSpace($LogoFile)) {
                    $logoExt = [System.IO.Path]::GetExtension($LogoFile).ToLower()
                    if ($logoExt -in @('.jpg', '.jpeg')) { $logoImageType = "image/jpeg" }
                }
                $logoBody = @{
                    "@odata.type" = "#microsoft.graph.win32LobApp"
                    "largeIcon"   = @{ "type" = $logoImageType; "value" = $Icon }
                }
                Write-Log -Message "Applying logo to app via dedicated PATCH..."
                try {
                    $logoUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$logoAppID"
                    Invoke-MgGraphRequest -Method PATCH -Uri $logoUri -Body ($logoBody | ConvertTo-Json -Depth 5) -ContentType 'application/json' | Out-Null
                    Write-Host "Logo applied successfully via dedicated PATCH" -ForegroundColor Green
                }
                catch {
                    Write-Log -Message "Warning: Failed to apply logo via PATCH: $($_.Exception.Message)" -LogLevel 2
                    Write-Host "Warning: Logo may not have been applied — $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }

        # Process Dependencies and Supersedence after app creation/update
        # Get the app ID if we don't have it yet (for new uploads)
        if (-not $script:contentReplaced) {
            Write-Log -Message "Getting application ID for dependency/supersedence processing..."
            $appID = Get-ApplicationID -AppName $displayName
            if (Test-Null($appID)) {
                Write-Log -Message "Warning: Could not get application ID for $displayName - skipping dependencies/supersedence" -LogLevel 2
            }
        }

        if (-not (Test-Null($appID))) {
            # Process Dependencies
            $dependencyEntries = @(ConvertTo-AppRelationshipEntry -Value $script:Dependencies -TypeValue $script:DependencyType `
                    -ValidType 'detect', 'autoInstall' -DefaultType 'autoInstall' -Label 'dependency')

            if ($dependencyEntries.Count -gt 0) {
                Write-Log -Message "Processing dependencies..."
                Write-Host "Processing dependencies..." -ForegroundColor Cyan

                foreach ($dep in $dependencyEntries) {
                    Write-Log -Message "Adding dependency: $($dep.Name) ($($dep.Type))"
                    $result = Set-IntuneAppDependency -ApplicationId $appID -DependencyAppId $dep.Name -DependencyType $dep.Type
                    if ($result) {
                        Write-Host "  Dependency added: $($dep.Name) ($($dep.Type))" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  Failed to add dependency: $($dep.Name)" -ForegroundColor Yellow
                    }
                }
            }

            # Process Supersedence
            $supersedenceEntries = @(ConvertTo-AppRelationshipEntry -Value $script:Supersedence -TypeValue $script:SupersedenceType `
                    -ValidType 'update', 'replace' -DefaultType 'update' -Label 'supersedence')

            if ($supersedenceEntries.Count -gt 0) {
                Write-Log -Message "Processing supersedence..."
                Write-Host "Processing supersedence..." -ForegroundColor Cyan

                foreach ($sup in $supersedenceEntries) {
                    Write-Log -Message "Adding supersedence: $($sup.Name) ($($sup.Type))"
                    $result = Set-IntuneAppSupersedence -ApplicationId $appID -SupersededAppId $sup.Name -SupersedenceType $sup.Type
                    if ($result) {
                        Write-Host "  Supersedence added: $($sup.Name) ($($sup.Type))" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  Failed to add supersedence: $($sup.Name)" -ForegroundColor Yellow
                    }
                }
            }
        }

        # Handle ReplaceExistingAssignments mode - validate and set flag
        if ($ReplaceExistingAssignments) {
            # Validate that at least one assignment group is specified (either via parameter or config file)
            $hasAssignmentGroup = $RequiredAADGroupName -or $AvailableAADGroupName -or $UninstallAADGroupName -or (-not [string]::IsNullOrWhiteSpace($script:EntraGroupName))
            if (-not $hasAssignmentGroup) {
                Write-Log -Message "Error: -ReplaceExistingAssignments requires at least one assignment group parameter or EntraGroupName in config" -LogLevel 3
                Write-Host
                Write-Host "Error: -ReplaceExistingAssignments requires at least one of the following:" -ForegroundColor Red
                Write-Host "  Parameters:" -ForegroundColor Yellow
                Write-Host "    -RequiredAADGroupName / -RequiredEntraGroupName" -ForegroundColor Yellow
                Write-Host "    -AvailableAADGroupName / -AvailableEntraGroupName" -ForegroundColor Yellow
                Write-Host "    -UninstallAADGroupName / -UninstallEntraGroupName" -ForegroundColor Yellow
                Write-Host "  Or in Config.xml/Config.json:" -ForegroundColor Yellow
                Write-Host "    <AADGroupName> / <EntraGroupName> element" -ForegroundColor Yellow
                Write-Host
                exit
            }
            $script:replaceAssignmentsMode = $true
            if (-not($RequiredAADGroupName -or $AvailableAADGroupName -or $UninstallAADGroupName)) {
                Write-Log -Message "ReplaceExistingAssignments mode enabled - using group name from config: $($script:EntraGroupName)"
            }
            else {
                Write-Log -Message "ReplaceExistingAssignments mode enabled - will clear existing assignments before applying new ones"
            }
        }

        # Skip group assignment if content was replaced (existing assignments are preserved)
        # or if SkipGroupAssignment was explicitly specified
        # Exception: If content was replaced but there are NO existing assignments, apply provided groups
        # Exception: If ReplaceExistingAssignments is set, always allow group assignment (after clearing)
        $shouldAssignGroups = (-not($SkipGroupAssignment)) -and ((-not($script:contentReplaced)) -or ($script:noExistingAssignments -eq $true) -or ($script:replaceAssignmentsMode -eq $true))
        if ($shouldAssignGroups) {

            # If ReplaceExistingAssignments mode, clear existing assignments first
            if ($script:replaceAssignmentsMode) {
                Write-Log -Message "Getting application ID for assignment replacement..."
                if ($null -eq $appID) {
                    $appID = Get-ApplicationID -AppName $displayName
                }
                if ($null -eq $appID) {
                    Write-Log -Message "Error: Application not found: $displayName" -LogLevel 3
                    Write-Host "Error: Application '$displayName' not found in Intune." -ForegroundColor Red
                    exit
                }

                Write-Host
                Write-Host "Clearing existing assignments for: $displayName" -ForegroundColor Yellow
                Write-Host "Application ID: $appID" -ForegroundColor Cyan

                $clearResult = Clear-ApplicationAssignments -ApplicationId $appID
                if ($clearResult) {
                    Write-Host "Existing assignments cleared successfully" -ForegroundColor Green
                    Write-Host
                }
                else {
                    Write-Log -Message "Warning: Failed to clear existing assignments - continuing with assignment" -LogLevel 2
                    Write-Host "Warning: Failed to clear existing assignments - continuing with assignment" -ForegroundColor Yellow
                }
            }

            if ($RequiredAADGroupName) {
                foreach ($reqGroupName in @($RequiredAADGroupName)) {
                    Write-Log -Message "Prepare Entra ID group for required assignment targeting: $reqGroupName"
                    $script:groupsWereCreated = $false
                    $script:exitCode = New-EntraGroupMG -groupName $reqGroupName

                    if ($script:groupsWereCreated) {
                        Write-Host "Sleeping for $sleep seconds to allow Entra ID group creation..." -f Magenta
                        Start-Sleep $sleep
                        Write-Host
                    }
                    else {
                        Write-Host "Group already exists, skipping wait..." -f Green
                    }

                    #If ($script:exitCode -eq 0) {
                    Write-Log -Message "Apply Entra ID group for required assignment targeting: $reqGroupName"

                    Write-Log -Message "Find application ID"
                    $appID = Get-ApplicationID -AppName $displayName

                    Write-Log -Message "Reading group IDs"

                    $installReqGroup = Get-GroupIDMG -GroupName $reqGroupName

                    Write-Log -Message "Assigning groups to application..."
                    $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installReqGroup -InstallIntent "required"
                }
            }

            if ($AvailableAADGroupName) {
                foreach ($availGroupName in @($AvailableAADGroupName)) {
                    Write-Log -Message "Prepare Entra ID group for available assignment targeting: $availGroupName"
                    $script:groupsWereCreated = $false
                    $script:exitCode = New-EntraGroupMG -groupName $availGroupName

                    if ($script:groupsWereCreated) {
                        Write-Host "Sleeping for $sleep seconds to allow Entra ID group creation..." -f Magenta
                        Start-Sleep $sleep
                        Write-Host
                    }
                    else {
                        Write-Host "Group already exists, skipping wait..." -f Green
                    }

                    #If ($script:exitCode -eq 0) {
                    Write-Log -Message "Apply Entra ID group for available assignment targeting: $availGroupName"

                    Write-Log -Message "Find application ID"
                    $appID = Get-ApplicationID -AppName $displayName

                    Write-Log -Message "Reading group IDs"

                    $installAvailGroup = Get-GroupIDMG -GroupName $availGroupName

                    Write-Log -Message "Assigning groups to application..."
                    $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installAvailGroup -InstallIntent "available"
                }
            }

            if ($UninstallAADGroupName) {
                foreach ($uninstGroupName in @($UninstallAADGroupName)) {
                    Write-Log -Message "Prepare Entra ID group for uninstall assignment targeting: $uninstGroupName"
                    $script:groupsWereCreated = $false
                    $script:exitCode = New-EntraGroupMG -groupName $uninstGroupName

                    if ($script:groupsWereCreated) {
                        Write-Host "Sleeping for $sleep seconds to allow Entra ID group creation..." -f Magenta
                        Start-Sleep $sleep
                        Write-Host
                    }
                    else {
                        Write-Host "Group already exists, skipping wait..." -f Green
                    }

                    #If ($script:exitCode -eq 0) {
                    Write-Log -Message "Apply Entra ID group for uninstall assignment targeting: $uninstGroupName"

                    Write-Log -Message "Find application ID"
                    $appID = Get-ApplicationID -AppName $displayName

                    Write-Log -Message "Reading group IDs"

                    $uninstallGroup = Get-GroupIDMG -GroupName $uninstGroupName

                    Write-Log -Message "Assigning groups to application..."
                    $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "uninstall"
                }
            }


            if (-not($RequiredAADGroupName -or $AvailableAADGroupName -or $UninstallAADGroupName)) {
                Write-Log -Message "Create Entra ID groups for install/uninstall"
                $script:groupsWereCreated = $false
                $script:exitCode = New-EntraGroupMG -groupName $EntraGroupName

                if ($script:groupsWereCreated) {
                    Write-Host "Sleeping for $sleep seconds to allow Entra ID group creation..." -f Magenta
                    Start-Sleep $sleep
                    Write-Host
                }
                else {
                    Write-Host "All groups already exist, skipping wait..." -f Green
                }

                #If ($script:exitCode -eq 0) {
                Write-Log -Message "Assigning Entra ID groups for install/uninstall"

                Write-Log -Message "Find application ID"
                $appID = Get-ApplicationID -AppName $displayName

                Write-Log -Message "Reading group IDs"

                $installReqGroup = Get-GroupIDMG -GroupName "$EntraGroupName-Required"
                $installAvailGroup = Get-GroupIDMG -GroupName "$EntraGroupName-Available"
                $uninstallGroup = Get-GroupIDMG -GroupName "$EntraGroupName-UnInstall"

                Write-Log -Message "Assigning groups to application..."
                $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installReqGroup -InstallIntent "required"
                $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installAvailGroup -InstallIntent "available"
                $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "uninstall"
                $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "required" -exclude
                $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "available" -exclude
            }

            #}
        }
        else {
            Write-Log -Message "Skipping assignment groups"
        }

        # Apply categories to the application (for new uploads - not when content was replaced as that's handled separately)
        # Supports multiple comma-separated categories from config
        if ((-not($AssignGroupsOnly)) -and (-not($script:contentReplaced)) -and ($script:Categories -and $script:Categories.Count -gt 0)) {
            Write-Log -Message "Checking for category assignment..."
            if ($null -eq $appID) {
                Write-Log -Message "Getting application ID for category assignment..."
                $appID = Get-ApplicationID -AppName $displayName
            }
            if ($null -ne $appID) {
                foreach ($cat in $script:Categories) {
                    $categoryResult = Set-IntuneAppCategory -ApplicationId $appID -CategoryName $cat
                    if (-not $categoryResult) {
                        Write-Log -Message "Warning: Category assignment may have failed for '$cat'" -LogLevel 2
                    }
                }
            }
            else {
                Write-Log -Message "Warning: Could not get application ID for category assignment" -LogLevel 2
            }
        }

        # Apply scope tag to the application (after group assignments are complete)
        # Apply scope tag if:
        # 1. Not in AssignGroupsOnly mode, AND
        # 2. Either content wasn't replaced, OR a scope tag was explicitly specified (config or parameter)
        $hasScopeTagSpecified = ($ScopeTagName -and $ScopeTagName.Count -gt 0) -or ($script:ConfigScopeTag -and $script:ConfigScopeTag.Count -gt 0)
        $shouldApplyScopeTag = (-not($AssignGroupsOnly)) -and ((-not($script:contentReplaced)) -or $hasScopeTagSpecified)
        if ($shouldApplyScopeTag) {
            Write-Log -Message "Checking for scope tag assignment..."
            if ($null -eq $appID) {
                Write-Log -Message "Getting application ID for scope tag assignment..."
                $appID = Get-ApplicationID -AppName $displayName
            }
            if ($null -ne $appID) {
                $scopeTagResult = Invoke-ScopeTagAssignment -ApplicationId $appID
                if (-not $scopeTagResult) {
                    Write-Log -Message "Warning: Scope tag assignment may have failed" -LogLevel 2
                }
            }
            else {
                Write-Log -Message "Warning: Could not get application ID for scope tag assignment" -LogLevel 2
            }
        }
        elseif ($AssignGroupsOnly) {
            Write-Log -Message "Skipping scope tag assignment (AssignGroupsOnly mode)"
        }
        else {
            Write-Log -Message "Skipping scope tag assignment (content replaced, no scope tag specified)"
        }
    }

    end {
        if (!($script:exitCode -eq 0)) { return $script:exitCode }# Just return without doing anything else, error tripped
        Write-Log -Message "Returning..."
        return $script:exitCode = 0
    }

}

####################################################

function Get-IntuneScopeTag {
    <#
.SYNOPSIS
This function retrieves an Intune scope tag by name, or creates it if it doesn't exist
.DESCRIPTION
This function retrieves an Intune scope tag by name. If the scope tag doesn't exist,
it will be created automatically.
.EXAMPLE
Get-IntuneScopeTag -ScopeTagName "CloudPC-Apps"
Returns the scope tag object for "CloudPC-Apps", creating it if it doesn't exist.
.NOTES
NAME: Get-IntuneScopeTag
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ScopeTagName
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "Looking for scope tag: [$ScopeTagName]"

        $graphApiVersion = "beta"
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/roleScopeTags?`$filter=displayName eq '$ScopeTagName'"

        try {
            Write-Host "Querying for scope tag: $ScopeTagName" -ForegroundColor Cyan
            $result = Invoke-MgGraphRequest -Method Get -Uri $uri

            if ($result.value.Count -gt 0) {
                $scopeTag = $result.value[0]
                Write-Log -Message "Found existing scope tag: $($scopeTag.displayName) (ID: $($scopeTag.id))"
                Write-Host "Found existing scope tag: $($scopeTag.displayName) (ID: $($scopeTag.id))" -ForegroundColor Green
                return $scopeTag
            }
            else {
                Write-Log -Message "Scope tag '$ScopeTagName' not found. Creating it..."
                Write-Host "Scope tag '$ScopeTagName' not found. Creating it..." -ForegroundColor Yellow

                # Create the scope tag
                $createUri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/roleScopeTags"
                $scopeTagBody = @{
                    'displayName' = $ScopeTagName
                    'description' = "Scope tag created by Upload-IntuneWin.ps1"
                }

                $newScopeTag = Invoke-MgGraphRequest -Method Post -Uri $createUri -Body ($scopeTagBody | ConvertTo-Json -Depth 10)
                Write-Log -Message "Successfully created scope tag: $($newScopeTag.displayName) (ID: $($newScopeTag.id))"
                Write-Host "Successfully created scope tag: $($newScopeTag.displayName) (ID: $($newScopeTag.id))" -ForegroundColor Green
                return $newScopeTag
            }
        }
        catch {
            # Check for 403 Forbidden - likely missing DeviceManagementRBAC.ReadWrite.All permission
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            if ($statusCode -eq 403 -or $_.Exception.Message -match 'Forbidden') {
                Write-Log -Message "Access denied (403 Forbidden) for scope tag operation. The account/app registration requires the 'DeviceManagementRBAC.ReadWrite.All' Graph API permission." -LogLevel 3
                Write-Host ""
                Write-Host "==========================================================================" -ForegroundColor Red
                Write-Host "ACCESS DENIED: Scope tag operation failed (403 Forbidden)" -ForegroundColor Red
                Write-Host "==========================================================================" -ForegroundColor Red
                Write-Host "The authenticated account lacks permission to manage scope tags." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Required Graph API permission: DeviceManagementRBAC.ReadWrite.All" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "To fix this:" -ForegroundColor Yellow
                Write-Host "  - App registration: Add 'DeviceManagementRBAC.ReadWrite.All' permission" -ForegroundColor Yellow
                Write-Host "    in Azure Portal > App registrations > API permissions, then grant" -ForegroundColor Yellow
                Write-Host "    admin consent." -ForegroundColor Yellow
                Write-Host "  - Interactive login: Ensure the user has an Intune role with scope tag" -ForegroundColor Yellow
                Write-Host "    management permissions." -ForegroundColor Yellow
                Write-Host "==========================================================================" -ForegroundColor Red
                Write-Host ""
                return $null
            }

            Write-Log -Message "Error with scope tag operation: $($_.Exception.Message)" -LogLevel 3
            Write-Host "Error with scope tag operation: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    end {
        Write-Log -Message "Returning from Get-IntuneScopeTag..."
    }
}

####################################################

function Set-IntuneAppScopeTag {
    <#
.SYNOPSIS
This function sets the scope tags on an Intune Win32 application
.DESCRIPTION
This function sets the scope tags on an Intune Win32 application. It replaces any existing
scope tags with the specified scope tags (including removing the Default scope tag).
.EXAMPLE
Set-IntuneAppScopeTag -ApplicationId "12345678-1234-1234-1234-123456789012" -ScopeTagIds @("1", "2")
Sets scope tags with IDs 1 and 2 on the specified application.
.NOTES
NAME: Set-IntuneAppScopeTag
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
        [string[]]$ScopeTagIds,

        [Parameter(Mandatory = $false)]
        [string[]]$ScopeTagNames
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "Setting scope tags on application ID: [$ApplicationId]"
        Write-Log -Message "Scope Tag IDs: [$($ScopeTagIds -join ', ')]"

        $graphApiVersion = "beta"
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps/$ApplicationId"

        $displayNames = if ($ScopeTagNames) { $ScopeTagNames -join ', ' } else { $ScopeTagIds -join ', ' }

        try {
            # The roleScopeTagIds property accepts an array of scope tag IDs as strings
            # Setting it replaces all existing scope tags
            $body = @{
                '@odata.type'     = '#microsoft.graph.win32LobApp'
                'roleScopeTagIds' = @($ScopeTagIds)
            }

            Write-Host "Applying scope tags '$displayNames' to application..." -ForegroundColor Cyan
            $null = Invoke-MgGraphRequest -Method Patch -Uri $uri -Body ($body | ConvertTo-Json -Depth 10)

            Write-Log -Message "Successfully applied scope tags to application"
            Write-Host "Successfully applied scope tags '$displayNames' to application" -ForegroundColor Green

            return $true
        }
        catch {
            Write-Log -Message "Error setting scope tags on application: $($_.Exception.Message)" -LogLevel 3
            Write-Host "Error setting scope tags on application: $($_.Exception.Message)" -ForegroundColor Red

            # Check if it's a different app type (e.g., Edge)
            if ($_.Exception.Message -like "*does not match*" -or $_.Exception.Message -like "*invalid*") {
                Write-Host "Attempting to set scope tags without specifying app type..." -ForegroundColor Yellow
                try {
                    $body = @{
                        'roleScopeTagIds' = @($ScopeTagIds)
                    }
                    $null = Invoke-MgGraphRequest -Method Patch -Uri $uri -Body ($body | ConvertTo-Json -Depth 10)
                    Write-Log -Message "Successfully applied scope tags to application (alternate method)"
                    Write-Host "Successfully applied scope tags '$displayNames' to application" -ForegroundColor Green
                    return $true
                }
                catch {
                    Write-Log -Message "Error setting scope tags (alternate method): $($_.Exception.Message)" -LogLevel 3
                    Write-Host "Error setting scope tags (alternate method): $($_.Exception.Message)" -ForegroundColor Red
                    return $false
                }
            }
            return $false
        }
    }

    end {
        Write-Log -Message "Returning from Set-IntuneAppScopeTag..."
    }
}

####################################################

function Invoke-ScopeTagAssignment {
    <#
.SYNOPSIS
This function handles the scope tag assignment logic including parameter precedence
.DESCRIPTION
This function determines which scope tags to use (parameter vs config), validates/creates
each scope tag, and applies all of them to the specified application.
.EXAMPLE
Invoke-ScopeTagAssignment -ApplicationId "12345678-1234-1234-1234-123456789012"
Applies the appropriate scope tags to the application based on parameter or config.
.NOTES
NAME: Invoke-ScopeTagAssignment
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        # Determine which scope tags to use
        $effectiveScopeTags = @()
        $paramScopeTags = @($ScopeTagName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $configScopeTags = @($script:ConfigScopeTag) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        if ($paramScopeTags.Count -gt 0) {
            # Script parameter takes precedence
            $effectiveScopeTags = $paramScopeTags

            # Check if there are different scope tags in config and warn the user
            if ($configScopeTags.Count -gt 0) {
                $configDisplay = $configScopeTags -join ', '
                $paramDisplay = $paramScopeTags -join ', '
                if ($configDisplay -ne $paramDisplay) {
                    Write-Host "" -ForegroundColor Yellow
                    Write-Host "==========================================================================" -ForegroundColor Yellow
                    Write-Host "NOTICE: Scope tag parameter precedence" -ForegroundColor Yellow
                    Write-Host "==========================================================================" -ForegroundColor Yellow
                    Write-Host "Config defines scope tag(s): '$configDisplay'" -ForegroundColor Yellow
                    Write-Host "Script parameter specifies:  '$paramDisplay'" -ForegroundColor Yellow
                    Write-Host "Using script parameter value(s) (parameter takes precedence)" -ForegroundColor Cyan
                    Write-Host "==========================================================================" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Log -Message "Scope tag(s) from config ($configDisplay) being overridden by script parameter ($paramDisplay)"
                }
                else {
                    Write-Host "Using scope tag(s) from script parameter: '$paramDisplay'" -ForegroundColor Cyan
                }
            }
            else {
                Write-Host "Using scope tag(s) from script parameter: '$($paramScopeTags -join ', ')'" -ForegroundColor Cyan
            }
        }
        elseif ($configScopeTags.Count -gt 0) {
            # Use config scope tags
            $effectiveScopeTags = $configScopeTags
            Write-Host "Using scope tag(s) from config: '$($configScopeTags -join ', ')'" -ForegroundColor Cyan
        }
        else {
            # No scope tag specified
            Write-Log -Message "No scope tag specified (neither parameter nor config). Skipping scope tag assignment."
            Write-Host "No scope tag specified. Application will retain default scope tag." -ForegroundColor Gray
            return $true
        }

        Write-Log -Message "Effective scope tag(s) to apply: $($effectiveScopeTags -join ', ')"

        try {
            # Get or create each scope tag and collect IDs
            $scopeTagIds = @()
            $scopeTagDisplayNames = @()
            foreach ($tagName in $effectiveScopeTags) {
                $scopeTag = Get-IntuneScopeTag -ScopeTagName $tagName

                if ($null -eq $scopeTag -or [string]::IsNullOrWhiteSpace($scopeTag.id)) {
                    Write-Log -Message "Failed to get or create scope tag: $tagName" -LogLevel 3
                    Write-Host "Failed to get or create scope tag: $tagName" -ForegroundColor Red
                    return $false
                }

                $scopeTagIds += $scopeTag.id
                $scopeTagDisplayNames += $scopeTag.displayName
            }

            Write-Log -Message "Resolved scope tag IDs: $($scopeTagIds -join ', ')"

            # Apply all scope tags to the application in a single PATCH
            $result = Set-IntuneAppScopeTag -ApplicationId $ApplicationId -ScopeTagIds $scopeTagIds -ScopeTagNames $scopeTagDisplayNames

            if ($result) {
                Write-Host ""
                Write-Host "Scope tag(s) '$($scopeTagDisplayNames -join ', ')' successfully applied to application" -ForegroundColor Green
                Write-Host ""
            }

            return $result
        }
        catch {
            Write-Log -Message "Error in scope tag assignment: $($_.Exception.Message)" -LogLevel 3
            Write-Host "Error in scope tag assignment: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }

    end {
        Write-Log -Message "Returning from Invoke-ScopeTagAssignment..."
    }
}

####################################################

function New-EntraGroupMG {
    <#
.SYNOPSIS
This function creates the relevant install/uninstall Entra ID groups
.DESCRIPTION
This function creates the relevant install/uninstall Entra ID groups. Returns a hashtable with
'ExitCode' and 'GroupsCreated' properties to indicate if any groups were newly created. Supports -WhatIf.
.EXAMPLE
$result = New-EntraGroupMG -groupName "MyGroupName"
This function creates the relevant install/uninstall Entra ID groups
.NOTES
NAME: New-EntraGroupMG -groupName
#>

    [cmdletbinding(SupportsShouldProcess = $true)]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$groupName
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
        $script:groupsWereCreated = $false
    }

    process {
        Write-Log -Message "groupName: [$groupName]"

        $EntraGroups = $groupName
        if (-not($RequiredAADGroupName -or $AvailableAADGroupName -or $UninstallAADGroupName)) {
            $EntraGroups = @("$groupName-Required", "$groupName-Available", "$groupName-Uninstall")
        }

        $graphApiVersion = "v1.0"
        foreach ($group in $EntraGroups) {
            # Check if group exists using REST API
            $uri = "https://graph.microsoft.com/$graphApiVersion/groups?`$filter=displayName eq '$group'"
            try {
                $existingGroup = Invoke-MgGraphRequest -Method Get -Uri $uri
                if ($existingGroup.value.Count -gt 0) {
                    Write-Log -Message "Entra ID group $group already exists!"
                }
                else {
                    # Check WhatIf before creating group
                    if (-not $PSCmdlet.ShouldProcess("Entra ID Group '$group'", "Create")) {
                        Write-Host "WhatIf: Would create Entra ID group '$group'" -ForegroundColor Cyan
                        Write-Log -Message "WhatIf: Would create Entra ID group '$group'"
                        continue
                    }

                    Write-Log -Message "Creating Entra ID group $group"
                    # Create group using REST API
                    $createUri = "https://graph.microsoft.com/$graphApiVersion/groups"
                    # mailNickname: remove spaces and invalid chars, append '-Group', truncate to 64 chars max
                    $mailNick = ($group -replace '[^a-zA-Z0-9_\-\.]', '') + "-Group"
                    if ($mailNick.Length -gt 64) { $mailNick = $mailNick.Substring(0, 64) }
                    $groupBody = @{
                        'displayName'        = $group
                        'description'        = "Group for $group"
                        'mailNickname'       = $mailNick
                        'mailEnabled'        = $false
                        'securityEnabled'    = $true
                        'isAssignableToRole' = $false
                    }
                    $null = Invoke-MgGraphRequest -Method Post -Uri $createUri -Body ($groupBody | ConvertTo-Json -Depth 10)
                    Write-Log -Message "Successfully created Entra ID group $group"
                    $script:groupsWereCreated = $true
                }
            }
            catch {
                Write-Log -Message "Error with Entra ID group $group : $($_.Exception.Message)"
                throw
            }
        }
    }

    end {
        if (!($script:exitCode -eq 0)) { return $script:exitCode }# Just return without doing anything else, error tripped
        Write-Log -Message "Returning..."
        return $script:exitCode = 0
    }

}

####################################################

function Get-GroupIDMG {
    <#
.SYNOPSIS
This function is used to get an Entra ID group and return its object ID if found
        .DESCRIPTION
        The function is used to get an Entra ID group and return its object ID if found
.EXAMPLE
Get-GroupID -GroupName GroupNameHere
The function is used to get an Entra ID group and return its object ID if found
        .NOTES
        NAME: Get-GroupIDMG
        #>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $GroupName
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "Search for group name: $GroupName"
        $graphApiVersion = "v1.0"
        $uri = "https://graph.microsoft.com/$graphApiVersion/groups?`$filter=displayName eq '$GroupName'"

        # Retry logic for newly created groups (can take time to propagate)
        $maxRetries = 5
        $retryCount = 0
        $retryDelay = 3
        $group = $null

        while ($retryCount -lt $maxRetries) {
            try {
                if ($retryCount -eq 0) {
                    Write-Host
                    Write-Host "Querying: $uri" -ForegroundColor Cyan
                    Write-Host
                }

                $result = Invoke-MgGraphRequest -Method Get -Uri $uri
                if ($result.value.Count -gt 0) {
                    $group = $result.value[0]
                    Write-Log -Message "Found group: `n$($group.displayName)"
                    $script:exitCode = 0
                    break
                }
                else {
                    $retryCount++
                    if ($retryCount -lt $maxRetries) {
                        Write-Log -Message "Group not found yet, waiting $retryDelay seconds before retry $retryCount/$maxRetries..."
                        Start-Sleep -Seconds $retryDelay
                    }
                    else {
                        Write-Log -Message "Error - could not find group after $maxRetries attempts: $GroupName" -LogLevel 3
                        $script:exitCode = -1
                        $group = $null
                    }
                }
            }
            catch {
                Write-Log -Message "Error searching for group: $($_.Exception.Message)" -LogLevel 3
                $script:exitCode = -1
                $group = $null
                break
            }
        }
    }

    end {
        if (!($script:exitCode -eq 0)) { return $script:exitCode }# Just return without doing anything else, error tripped
        $GroupID = $($group).id
        Write-Log -Message "Returning group ID: [$GroupID]"
        return $GroupID
    }

}

####################################################

function Get-ApplicationID {
    <#
.SYNOPSIS
This function is used to get an application and return it's object ID if found
.DESCRIPTION
The function is used to get an application and return it's object ID if found
.EXAMPLE
Get-ApplicationID -AppName AppNameHere
The function is used to get an application and return it's object ID if found
.NOTES
NAME: Get-ApplicationID
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $AppName
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "Search for application name: $AppName"
        $application = Get-IntuneApplicationMG -DisplayName $AppName

        if (Test-Null($application)) {
            #Write-Log -Message "Error - could not find application: $application" -LogLevel 3
            Write-Log -Message "Existing application not found: $AppName"
            #$script:exitCode = -1
        }
        else {
            Write-Log -Message "Found application: $AppName"
            #$script:exitCode = 0

        }
        $appID = $($application).id
        Write-Log -Message "Returning application ID: [$appID]"
        return $appID
    }
}

####################################################

function Get-IntuneApplicationMG {
    <#
    .SYNOPSIS
    This function is used to get applications from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any applications added
    .PARAMETER DisplayName
    The Display Name of the app to search for
    .PARAMETER ID
    The Application ID to search for
    .EXAMPLE
    Get-IntuneApplicationMG
    Returns any applications configured in Intune
    #>
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(ParameterSetName = 'DisplayName')]
        [string] $DisplayName,

        [Parameter(Mandatory, ParameterSetName = "ID")]
        [guid] $ID
    )

    $apiVersion = 'beta'
    $resource = 'deviceAppManagement/mobileApps'

    switch ($PSCmdlet.ParameterSetName) {
        'DisplayName' {
            $resource = $resource + "?`$filter=displayName eq '$DisplayName'"
            break
        }
        'ID' {
            $resource = $resource + '/' + $ID
            break
        }
    }

    try {
        $uri = "https://graph.microsoft.com/$apiVersion/$resource"
        Write-Host "Querying: $uri" -ForegroundColor Cyan
        $return = Invoke-MgGraphRequest -Method Get -Uri $uri
    }
    catch {
        Write-Host "Error querying Graph API: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "URI attempted: $uri" -ForegroundColor Yellow
        Write-Host "Check that the Service Principal has been granted 'DeviceManagementApps.ReadWrite.All' permission with Admin Consent" -ForegroundColor Yellow
        throw $_.Exception
    }

    if ($PSCmdlet.ParameterSetName -eq 'DisplayName') {
        $return.value
    }
    else {
        $return
    }
}

####################################################

function Add-ApplicationAssignment() {

    <#
.SYNOPSIS
This function is used to add an application assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a application assignment. Supports -WhatIf.
.EXAMPLE
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignment
#>

    [cmdletbinding(SupportsShouldProcess = $true)]

    param
    (
        $ApplicationId,
        $TargetGroupId,
        [ValidateSet("available", "required", "uninstall")]
        $InstallIntent,
        [switch]$exclude
    )

    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"

    try {

        if (!$ApplicationId) {

            Write-Log -Message "No Application Id specified, specify a valid Application Id" -LogLevel 3
            $script:exitCode = 1
            return

        }

        if (!$TargetGroupId) {

            Write-Log -Message "No Target Group Id specified, specify a valid Target Group Id" -LogLevel 3
            $script:exitCode = 1
            return

        }


        if (!$InstallIntent) {

            Write-Log -Message "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -LogLevel 3
            $script:exitCode = 1
            return

        }

        # Check WhatIf before performing assignment
        $actionDescription = if ($exclude) { "Exclude from $InstallIntent" } else { "Assign as $InstallIntent" }
        if (-not $PSCmdlet.ShouldProcess("Application '$ApplicationId' to Group '$TargetGroupId'", $actionDescription)) {
            Write-Host "WhatIf: Would $actionDescription application to group" -ForegroundColor Cyan
            Write-Log -Message "WhatIf: Would $actionDescription application '$ApplicationId' to group '$TargetGroupId'"
            return
        }

        Write-Log -Message "ApplicationId: $ApplicationId"
        Write-Log -Message "TargetGroupId: $TargetGroupId"
        Write-Log -Message "InstallIntent: $InstallIntent"

        Write-Log -Message "Look for existing assignments..."
        $AssignedGroups = (Get-ApplicationAssignment -ApplicationId $ApplicationId).assignments

        Write-Log -Message "Found the following assignments: `n$AssignedGroups"

        if ($AssignedGroups) {

            $App_Count = @($AssignedGroups).count
            Write-Log -Message "Number of assignments: $App_Count"
            $i = 1

            #if($AssignedGroups.target.GroupId -contains $TargetGroupId){

            #   Write-Log -Message "'$AADGroup' is already targetted to this application, can't add an Entra group already assigned..."

            #}

            #else {

            # Determine notification setting based on install intent
            # Hide notifications for Required and Available, show for Uninstall
            $notificationSetting = if ($InstallIntent -eq "uninstall") { "showAll" } else { "hideAll" }

            if ( ! ( $exclude ) ) {
                # Creating header of JSON File
                Write-Log -Message "Creating header of JSON File for include (notifications: $notificationSetting)"

                $JSON = @"
{
    "mobileAppAssignments": [
    {
      "@odata.type": "#microsoft.graph.mobileAppAssignment",
      "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId"
      },
      "intent": "$InstallIntent",
      "settings": {
        "@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
        "notifications": "$notificationSetting",
        "installTimeSettings": {
          "useLocalTime": false,
          "deadlineDateTime": null
        },
        "deliveryOptimizationPriority": "foreground"
      }
    },
"@
            }
            elseif ( $exclude ) {
                # Creating header of JSON File
                Write-Log -Message "Creating header of JSON File for exclude"

                $JSON = @"
{
    "mobileAppAssignments": [
    {
      "@odata.type": "#microsoft.graph.mobileAppAssignment",
      "target": {
        "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
        "groupId": "$TargetGroupId"
      },
      "intent": "$InstallIntent"
    },
"@
            }

            Write-Log -Message "JSON constructed as: `n$JSON"

            # Looping through all existing assignments and adding them to the JSON object
            Write-Log -Message "Loop through any existing assignments..."
            foreach ($Assignment in $AssignedGroups) {

                $existingODataType = $Assignment.target.'@odata.type'
                $ExistingTargetGroupId = $Assignment.target.GroupId
                $ExistingInstallIntent = $Assignment.intent
                Write-Log -Message "existingODataType: $existingODataType"
                Write-Log -Message "ExistingTargetGroupId: $ExistingTargetGroupId"
                Write-Log -Message "ExistingInstallIntent: $ExistingInstallIntent"

                # Determine if this is an exclusion assignment (exclusions don't get settings)
                $isExclusion = $existingODataType -like '*exclusion*'

                if ($isExclusion) {
                    # Exclusion assignments have no settings block
                    $JSON += @"

    {
      "@odata.type": "#microsoft.graph.mobileAppAssignment",
      "target": {
        "@odata.type": "$existingODataType",
        "groupId": "$ExistingTargetGroupId"
      },
      "intent": "$ExistingInstallIntent"
"@
                }
                else {
                    # Include assignments: preserve existing settings or apply defaults
                    # Determine notification setting for this existing assignment
                    $existingNotification = "hideAll"
                    if ($Assignment.settings -and $Assignment.settings.notifications) {
                        $existingNotification = $Assignment.settings.notifications
                    }
                    elseif ($ExistingInstallIntent -eq "uninstall") {
                        $existingNotification = "showAll"
                    }

                    # Determine delivery optimization priority
                    $existingDeliveryPriority = "foreground"
                    if ($Assignment.settings -and $Assignment.settings.deliveryOptimizationPriority) {
                        $existingDeliveryPriority = $Assignment.settings.deliveryOptimizationPriority
                    }

                    $JSON += @"

    {
      "@odata.type": "#microsoft.graph.mobileAppAssignment",
      "target": {
        "@odata.type": "$existingODataType",
        "groupId": "$ExistingTargetGroupId"
      },
      "intent": "$ExistingInstallIntent",
      "settings": {
        "@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
        "notifications": "$existingNotification",
        "installTimeSettings": {
          "useLocalTime": false,
          "deadlineDateTime": null
        },
        "deliveryOptimizationPriority": "$existingDeliveryPriority"
      }
"@
                }

                if ($i -ne $App_Count) {

                    $JSON += @"
    },
"@

                }

                else {

                    $JSON += @"
    }
"@

                }

                $i++

            }

            # Adding close of JSON object
            $JSON += @"
    ]
}
"@

            Write-Log -Message "Final JSON constructed as: `n$JSON"

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
            #}

        }#Try

        else {

            # Determine notification setting based on install intent
            # Hide notifications for Required and Available, show for Uninstall
            $notificationSetting = if ($InstallIntent -eq "uninstall") { "showAll" } else { "hideAll" }

            if ( ! ( $exclude ) ) {
                # Creating header of JSON File
                Write-Log -Message "Creating header of JSON File for include with no additional assignments (notifications: $notificationSetting)"

                $JSON = @"
{
    "mobileAppAssignments": [
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId"
        },
        "intent": "$InstallIntent",
        "settings": {
          "@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
          "notifications": "$notificationSetting",
          "installTimeSettings": {
            "useLocalTime": false,
            "deadlineDateTime": null
          },
          "deliveryOptimizationPriority": "foreground"
        }
    }
    ]
}
"@
            }
            elseif ( $exclude ) {
                # Creating header of JSON File
                Write-Log -Message "Creating header of JSON File for exclude with no additional assignments"

                $JSON = @"
{
    "mobileAppAssignments": [
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
        "groupId": "$TargetGroupId"
        },
        "intent": "$InstallIntent"
    }
    ]
}
"@
            }

            Write-Log -Message "Using static JSON content: `n$JSON"

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
        }

    }

    catch {
        throw
        <#
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
        #>
    }

    Write-Host "Sleeping for $sleep seconds to allow Entra group assignment..." -f Magenta
    Start-Sleep $sleep
    Write-Host
}

####################################################

function Get-ApplicationLargeIcon() {

    <#
.SYNOPSIS
This function is used to get the largeIcon property of an application from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and retrieves the largeIcon property which must be
explicitly selected as it is not returned by default.
.EXAMPLE
Get-ApplicationLargeIcon -ApplicationId "12345678-1234-1234-1234-123456789012"
Returns the largeIcon property of the specified application
.NOTES
NAME: Get-ApplicationLargeIcon
#>

    [cmdletbinding()]

    param
    (
        $ApplicationId
    )

    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps/$ApplicationId/?`$select=largeIcon"

    try {

        if (!$ApplicationId) {
            Write-Host "No Application Id specified, specify a valid Application Id" -f Red
            return $null
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Write-Log -Message "Fetching largeIcon from: $uri"
            $response = Invoke-MgGraphRequest -Uri $uri -Method Get
            return $response
        }
    }
    catch {
        $ex = $_.Exception
        Write-Log -Message "Error fetching largeIcon: $($ex.Message)" -LogLevel 2
        Write-Host "Warning: Could not fetch largeIcon - $($ex.Message)" -f Yellow
        return $null
    }
}

####################################################

function Get-ApplicationAssignment() {

    <#
.SYNOPSIS
This function is used to get an application assignment from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets an application assignment
.EXAMPLE
Get-ApplicationAssignment
Returns an Application Assignment configured in Intune
.NOTES
NAME: Get-ApplicationAssignment
#>

    [cmdletbinding()]

    param
    (
        $ApplicationId
    )

    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps/$ApplicationId/?`$expand=categories,assignments"

    try {

        if (!$ApplicationId) {

            Write-Host "No Application Id specified, specify a valid Application Id" -f Red
            return $null

        }

        else {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Get
        }
    }

    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        $script:exitCode = 1
        throw

    }

}

####################################################

function Clear-ApplicationAssignments() {

    <#
.SYNOPSIS
This function removes all existing assignments from an application using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and clears all assignments from an application. Supports -WhatIf.
.EXAMPLE
Clear-ApplicationAssignments -ApplicationId $ApplicationId
Removes all assignments from an application in Intune
.NOTES
NAME: Clear-ApplicationAssignments
#>

    [cmdletbinding(SupportsShouldProcess = $true)]

    param
    (
        $ApplicationId
    )

    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"

    try {

        if (!$ApplicationId) {
            Write-Log -Message "No Application Id specified, specify a valid Application Id" -LogLevel 3
            $script:exitCode = 1
            return
        }

        # Check WhatIf before clearing assignments
        if (-not $PSCmdlet.ShouldProcess("Application '$ApplicationId'", "Clear all assignments")) {
            Write-Host "WhatIf: Would clear all assignments for application ID '$ApplicationId'" -ForegroundColor Cyan
            Write-Log -Message "WhatIf: Would clear all assignments for application ID '$ApplicationId'"
            return
        }

        Write-Log -Message "Clearing all assignments for application ID: $ApplicationId"

        # Send empty assignments array to clear all assignments
        $JSON = @"
{
    "mobileAppAssignments": []
}
"@

        Write-Log -Message "Sending empty assignments to clear existing assignments..."

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"

        Write-Log -Message "Successfully cleared all assignments"
        return $true
    }

    catch {
        $ex = $_.Exception
        Write-Log -Message "Error clearing assignments: $($ex.Message)" -LogLevel 3
        return $false
    }

}

####################################################

function New-IntuneWin32AppIcon {
    <#
    .SYNOPSIS
        Converts a PNG/JPG/JPEG image file available locally to a Base64 encoded string.

    .DESCRIPTION
        Converts a PNG/JPG/JPEG image file available locally to a Base64 encoded string.

    .PARAMETER FilePath
        Specify an existing local path to where the PNG/JPG/JPEG image file is located.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify an existing local path to where the PNG/JPG/JPEG image file is located.")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {
                # Check if path contains any invalid characters
                if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                    Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains invalid characters"; break
                }
                else {
                    # Check if file extension is PNG/JPG/JPEG
                    $FileExtension = [System.IO.Path]::GetExtension((Split-Path -Path $_ -Leaf))
                    if (($FileExtension -like ".png") -or ($FileExtension -like ".jpg") -or ($FileExtension -like ".jpeg")) {
                        return $true
                    }
                    else {
                        Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains unsupported file extension. Supported extensions are '.png', '.jpg' and '.jpeg'"; break
                    }
                }
            })]
        [string]$FilePath
    )
    # Handle error action preference for non-cmdlet code
    $ErrorActionPreference = "Stop"

    try {
        # Encode image file as Base64 string
        $EncodedBase64String = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$($FilePath)"))
        Write-Output -InputObject $EncodedBase64String
    }
    catch [System.Exception] {
        Write-Warning -Message "Failed to encode image file to Base64 encoded string. Error message: $($_.Exception.Message)"
    }
}

####################################################

function Invoke-MgGraphConnect {
    <#
.SYNOPSIS
Connects to Microsoft Graph with MSAL system browser auth for custom app registrations
.DESCRIPTION
When a custom ClientID is provided, uses MSAL.NET directly to perform interactive authentication
via the system browser with http://localhost redirect URI. This bypasses WAM (Web Account Manager)
which can cause authentication failures with custom app registrations.
When no custom ClientID is provided, uses standard Connect-MgGraph interactive auth.
.PARAMETER ConnectParams
Hashtable of parameters to splat to Connect-MgGraph (Scopes, ClientId, TenantId, NoWelcome)
.PARAMETER IsDeleteOperation
If true, uses simplified error messages for the delete auth path
.EXAMPLE
Invoke-MgGraphConnect -ConnectParams $connectParams
.NOTES
NAME: Invoke-MgGraphConnect
Requires: Microsoft.Graph.Authentication module (bundles MSAL.NET)
App registration must have http://localhost redirect URI configured under Mobile and desktop applications
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ConnectParams,

        [Parameter(Mandatory = $false)]
        [switch]$IsDeleteOperation
    )

    $operationLabel = if ($IsDeleteOperation) { "delete operation" } else { "Microsoft Graph" }
    $hasCustomClientId = $ConnectParams.ContainsKey('ClientId') -and $ConnectParams['ClientId']

    if ($hasCustomClientId) {
        # Use MSAL.NET directly to bypass WAM - same approach as Manage-IntuneResources.ps1
        $clientId = $ConnectParams['ClientId']
        $tenantId = if ($ConnectParams.ContainsKey('TenantId') -and $ConnectParams['TenantId']) { $ConnectParams['TenantId'] } else { 'organizations' }
        $scopes = if ($ConnectParams.ContainsKey('Scopes')) { $ConnectParams['Scopes'] } else { @() }
        $noWelcome = $ConnectParams.ContainsKey('NoWelcome') -and $ConnectParams['NoWelcome']

        try {
            Write-Log -Message "Using MSAL system browser auth for custom app registration: $clientId"

            # Check if MSAL types are already loaded
            $msalTypeLoaded = $null -ne ([System.Management.Automation.PSTypeName]'Microsoft.Identity.Client.PublicClientApplicationBuilder').Type

            if (-not $msalTypeLoaded) {
                Write-Log -Message "Loading MSAL from Microsoft.Graph.Authentication module..."

                $graphAuthModule = Get-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
                if (-not $graphAuthModule) {
                    $graphAuthModule = Import-Module Microsoft.Graph.Authentication -PassThru -ErrorAction Stop
                }

                # Check again after module import
                $msalTypeLoaded = $null -ne ([System.Management.Automation.PSTypeName]'Microsoft.Identity.Client.PublicClientApplicationBuilder').Type

                if (-not $msalTypeLoaded) {
                    $modulePath = $graphAuthModule.ModuleBase

                    $possiblePaths = @(
                        (Join-Path $modulePath "Dependencies\Desktop\Microsoft.Identity.Client.dll"),
                        (Join-Path $modulePath "Dependencies\Core\Microsoft.Identity.Client.dll"),
                        (Join-Path $modulePath "Dependencies\Microsoft.Identity.Client.dll"),
                        (Join-Path $modulePath "Microsoft.Identity.Client.dll")
                    )

                    $msalDllPath = $null
                    foreach ($path in $possiblePaths) {
                        if (Test-Path $path) {
                            $msalDllPath = $path
                            Write-Log -Message "Found MSAL at: $path"
                            break
                        }
                    }

                    if (-not $msalDllPath) {
                        throw "Could not find Microsoft.Identity.Client.dll in the Microsoft.Graph.Authentication module."
                    }

                    Add-Type -Path $msalDllPath -ErrorAction Stop
                }
            }

            Write-Host "Authenticating with custom app registration via system browser..." -ForegroundColor Cyan

            # Build MSAL public client application with http://localhost redirect
            $redirectUri = "http://localhost"
            $authority = "https://login.microsoftonline.com/$tenantId"

            $pcaBuilder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($clientId)
            $pcaBuilder = $pcaBuilder.WithAuthority($authority)
            $pcaBuilder = $pcaBuilder.WithRedirectUri($redirectUri)
            $pca = $pcaBuilder.Build()

            # Prepare scopes as .NET List<string> for MSAL
            $scopesList = [System.Collections.Generic.List[string]]::new()
            foreach ($scope in $scopes) {
                if ($scope -notlike "https://graph.microsoft.com/*") {
                    $scopesList.Add("https://graph.microsoft.com/$scope")
                }
                else {
                    $scopesList.Add($scope)
                }
            }

            Write-Log -Message "Requesting scopes: $($scopesList -join ', ')"

            # Try silent auth first (cached credentials)
            $accounts = $pca.GetAccountsAsync().GetAwaiter().GetResult()
            $result = $null

            if ($accounts -and $accounts.Count -gt 0) {
                try {
                    Write-Log -Message "Found cached account, attempting silent authentication..."
                    $result = $pca.AcquireTokenSilent($scopesList, $accounts[0]).ExecuteAsync().GetAwaiter().GetResult()
                    Write-Host "Authenticated silently using cached credentials" -ForegroundColor Green
                }
                catch {
                    Write-Log -Message "Silent auth failed, will use interactive browser: $($_.Exception.Message)" -LogLevel 2
                }
            }

            # If silent auth failed, do interactive via system browser
            if (-not $result) {
                Write-Host "Opening browser for authentication..." -ForegroundColor Yellow

                $interactiveBuilder = $pca.AcquireTokenInteractive($scopesList)
                $interactiveBuilder = $interactiveBuilder.WithUseEmbeddedWebView($false)

                $result = $interactiveBuilder.ExecuteAsync().GetAwaiter().GetResult()

                Write-Host "Authentication successful" -ForegroundColor Green
            }

            # Connect to Graph with the acquired access token
            $secureToken = ConvertTo-SecureString -String $result.AccessToken -AsPlainText -Force
            $mgConnectParams = @{
                AccessToken = $secureToken
                ErrorAction = 'Stop'
            }
            if ($noWelcome) {
                $mgConnectParams['NoWelcome'] = $true
            }

            Connect-MgGraph @mgConnectParams
            return
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Log -Message "Failed to authenticate to ${operationLabel}: $errorMessage" -LogLevel 3

            if ($IsDeleteOperation) {
                Write-Host "Authentication failed: $errorMessage" -ForegroundColor Red
                Write-Host "Ensure the app registration has the required API permissions and http://localhost redirect URI." -ForegroundColor Yellow
                Write-Host "See: Azure Portal > App registrations > Authentication > Mobile and desktop" -ForegroundColor Yellow
            }
            else {
                Write-Host "" -ForegroundColor Red
                Write-Host "==========================================================================" -ForegroundColor Red
                Write-Host "AUTHENTICATION FAILED" -ForegroundColor Red
                Write-Host "==========================================================================" -ForegroundColor Red
                Write-Host "Error: $errorMessage" -ForegroundColor Red
                Write-Host "" -ForegroundColor Yellow
                Write-Host "When using -ClientID with -IntuneAdmin (delegated auth), ensure the app" -ForegroundColor Yellow
                Write-Host "registration is correctly configured:" -ForegroundColor Yellow
                Write-Host "" -ForegroundColor Yellow
                Write-Host "  1. Go to Azure Portal > App registrations > $clientId" -ForegroundColor Yellow
                Write-Host "  2. API permissions: Add DeviceManagementApps.ReadWrite.All, Group.ReadWrite.All," -ForegroundColor Yellow
                Write-Host "     GroupMember.ReadWrite.All, DeviceManagementRBAC.ReadWrite.All (Delegated)" -ForegroundColor Yellow
                Write-Host "  3. Grant admin consent for the above permissions" -ForegroundColor Yellow
                Write-Host "  4. Authentication > Add platform > Mobile and desktop applications" -ForegroundColor Yellow
                Write-Host "  5. Add redirect URI: http://localhost" -ForegroundColor Yellow
                Write-Host "  6. Enable 'Allow public client flows' at the bottom" -ForegroundColor Yellow
                Write-Host "==========================================================================" -ForegroundColor Red
                Invoke-Cleanup -ForceDisconnect
            }
            throw "Authentication failed. Cannot continue."
        }
    }
    else {
        # No custom ClientID - use standard Connect-MgGraph interactive auth
        try {
            Connect-MgGraph @ConnectParams -ErrorAction Stop
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Log -Message "Failed to authenticate to ${operationLabel}: $errorMessage" -LogLevel 3

            if ($IsDeleteOperation) {
                Write-Host "Authentication failed: $errorMessage" -ForegroundColor Red
            }
            else {
                Write-Host "" -ForegroundColor Red
                Write-Host "==========================================================================" -ForegroundColor Red
                Write-Host "AUTHENTICATION FAILED" -ForegroundColor Red
                Write-Host "==========================================================================" -ForegroundColor Red
                Write-Host "Error: $errorMessage" -ForegroundColor Red
                Write-Host "==========================================================================" -ForegroundColor Red
                Invoke-Cleanup -ForceDisconnect
            }
            throw "Authentication failed. Cannot continue."
        }
    }
}

####################################################

function Invoke-Cleanup {
    param(
        [switch]$ForceDisconnect
    )
    if ($ForceDisconnect) {
        Write-Log -Message "Disconnecting from Microsoft Graph..."
        $null = Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}

####################################################

Start-Log -FilePath $logFile -DeleteExistingFile
# Rotate older logs in the Logs subfolder, keeping the most recent runs.
Remove-OldLogFiles -LogDirectory $logPath -LogPrefix $logPrefix -KeepCount 10
Write-Host
Write-Host "Script log file path is [$logFile]" -f Cyan
Write-Host
Write-Log -Message "Starting $ScriptName version $BuildVer" -WriteEventLog

####################################################
# Proxy initialization (opt-in via -ProxyUri or $env:INTUNEWIN_PROXY_URI).
# Must run BEFORE -DeleteApp mode AND BEFORE the regular #region auth so that
# every downstream Invoke-MgGraphRequest / Invoke-WebRequest / MSAL token call
# inherits the proxy from the start.
####################################################

# -TestProxyConnectivity: alternate path. Validate direct vs proxy connectivity
# to Microsoft Graph + Entra ID, print a report, exit with 0/1/2.
if ($TestProxyConnectivity) {
    try {
        $proxyTestArgs = @{}
        if ($ProxyUri) { $proxyTestArgs['ProxyUri'] = $ProxyUri }
        if ($ProxyCredential) { $proxyTestArgs['ProxyCredential'] = $ProxyCredential }
        if ($ProxyUseDefaultCredentials) { $proxyTestArgs['UseDefaultCredentials'] = $true }
        if ($PSBoundParameters.ContainsKey('ProxyBypassList')) { $proxyTestArgs['BypassList'] = $ProxyBypassList }
        if ($NoProxyBypassLocal) { $proxyTestArgs['BypassOnLocal'] = $false }
        $proxyTestResult = Invoke-IntuneWinProxyTest @proxyTestArgs
        Write-Host ''
        if ($proxyTestResult.Success) {
            Write-Host '  Overall: PASS' -ForegroundColor Green
            exit 0
        }
        else {
            Write-Host '  Overall: FAIL' -ForegroundColor Red
            exit 1
        }
    }
    catch {
        Write-Host "Proxy connectivity test failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 2
    }
}

if ($ProxyUri -or $env:INTUNEWIN_PROXY_URI) {
    try {
        $proxyInitArgs = @{ OnlyIfNeeded = $true }
        if ($ProxyUri) { $proxyInitArgs['ProxyUri'] = $ProxyUri }
        if ($ProxyCredential) { $proxyInitArgs['ProxyCredential'] = $ProxyCredential }
        if ($ProxyUseDefaultCredentials) { $proxyInitArgs['UseDefaultCredentials'] = $true }
        if ($PSBoundParameters.ContainsKey('ProxyBypassList')) { $proxyInitArgs['BypassList'] = $ProxyBypassList }
        if ($NoProxyBypassLocal) { $proxyInitArgs['BypassOnLocal'] = $false }
        Initialize-IntuneWinProxy @proxyInitArgs | Out-Null
        $proxyCfg = Get-IntuneWinProxyConfiguration
        if ($proxyCfg) {
            Write-Log -Message "Proxy configured: $($proxyCfg.ProxyAddress) | BypassOnLocal=$($proxyCfg.BypassOnLocal) | UseDefaultCredentials=$($proxyCfg.UseDefaultCredentials) | BypassList=[$($proxyCfg.BypassList -join ';')]" -WriteHost Green
        }
        else {
            Write-Log -Message 'Direct connectivity to Microsoft Graph / Entra ID OK - proxy not activated (auto-fallback).'
        }
    }
    catch {
        Write-Log -Message "Proxy configuration failed: $($_.Exception.Message)" -LogLevel 3 -WriteHost Red
        throw "Proxy configuration failed: $($_.Exception.Message)"
    }
}

#endregion Initialisation...
##########################################################################################################
##########################################################################################################
#region Main Script work section
##########################################################################################################
##########################################################################################################
#Main Script work section
##########################################################################################################
##########################################################################################################
#Script specific variables

<#
$ModulePath = "Z:\Management Scripts\Modules"

If ($Env:PSModulePath -NotLike "*$ModulePath*") {

    $Env:PSModulePath = $Env:PSModulePath+";$ModulePath"
}
#>

#region Delete App Mode
# Handle -DeleteApp mode early and exit
if ($DeleteApp) {
    Write-Log -Message "DeleteApp mode activated" -WriteHost Cyan

    # Validate that we have either PackagePath or AppNameToDelete
    if (-not $PackagePath -and -not $AppNameToDelete) {
        Write-Log -Message "Error - DeleteApp requires either -PackagePath or -AppNameToDelete parameter" -LogLevel 3
        Write-Host "Error: When using -DeleteApp, you must specify either -PackagePath (to read displayName from config) or -AppNameToDelete." -ForegroundColor Red
        return 1
    }

    # Collect all app names to delete
    $appsToDelete = @()

    # Add apps from -AppNameToDelete parameter
    if ($AppNameToDelete) {
        $appsToDelete += $AppNameToDelete
        Write-Log -Message "Apps to delete from -AppNameToDelete: $($AppNameToDelete -join ', ')"
    }

    # Add apps from PackagePath config files
    if ($PackagePath) {
        foreach ($path in $PackagePath) {
            $path = $path.Trim()
            if (Test-Path $path) {
                $jsonConfigPath = "$path\Config.json"
                $xmlConfigPath = "$path\Config.xml"

                $configDisplayName = $null

                if (Test-Path $jsonConfigPath) {
                    Write-Log -Message "Reading displayName from: $jsonConfigPath"
                    try {
                        $jsonConfig = Get-Content -Path $jsonConfigPath -Raw | ConvertFrom-Json
                        $configDisplayName = $jsonConfig.displayName
                    }
                    catch {
                        Write-Log -Message "Error reading Config.json: $_" -LogLevel 2
                    }
                }
                elseif (Test-Path $xmlConfigPath) {
                    Write-Log -Message "Reading displayName from: $xmlConfigPath"
                    try {
                        [xml]$xmlConfig = Get-Content -Path $xmlConfigPath
                        $configDisplayName = $xmlConfig.CONFIG.IntuneWin_Settings.displayName
                    }
                    catch {
                        Write-Log -Message "Error reading Config.xml: $_" -LogLevel 2
                    }
                }
                else {
                    Write-Log -Message "No config file found in: $path" -LogLevel 2
                }

                if ($configDisplayName) {
                    $appsToDelete += $configDisplayName
                    Write-Log -Message "Found displayName from config: $configDisplayName"
                }
            }
            else {
                Write-Log -Message "Warning - path not valid: $path" -LogLevel 2
            }
        }
    }

    # Remove duplicates
    $appsToDelete = $appsToDelete | Select-Object -Unique

    if ($appsToDelete.Count -eq 0) {
        Write-Log -Message "Error - No applications to delete. Check your config files or -AppNameToDelete parameter." -LogLevel 3
        Write-Host "Error: No applications to delete. Check your config files or -AppNameToDelete parameter." -ForegroundColor Red
        return 1
    }

    Write-Host "`nApplications to delete:" -ForegroundColor Cyan
    $appsToDelete | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
    Write-Host ""

    # Authenticate to Graph
    Write-Log -Message "Authenticating for delete operation..."
    if ($IntuneAdmin) {
        Write-Host "Using IntuneAdmin: $IntuneAdmin" -ForegroundColor Green

        $requiredScopes = @(
            "DeviceManagementApps.ReadWrite.All"
        )

        # Build Connect-MgGraph parameters for delegated auth
        $connectParams = @{
            Scopes    = $requiredScopes
            NoWelcome = $true
        }
        if ($ClientID) {
            $connectParams['ClientId'] = $ClientID
        }
        if ($TenantID) {
            $connectParams['TenantId'] = $TenantID
        }

        $context = Get-MgContext
        if ($null -ne $context) {
            $currentScopes = $context.Scopes
            $missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
            $clientIdChanged = $ClientID -and ($context.ClientId -ne $ClientID)
            if ($missingScopes.Count -gt 0 -or $clientIdChanged) {
                Write-Host "Disconnecting and reconnecting with required scopes..." -ForegroundColor Yellow
                Disconnect-MgGraph | Out-Null
                Invoke-MgGraphConnect -ConnectParams $connectParams -IsDeleteOperation
            }
            else {
                Write-Host "Already connected with required scopes" -ForegroundColor Green
            }
        }
        else {
            Invoke-MgGraphConnect -ConnectParams $connectParams -IsDeleteOperation
        }
    }
    elseif ($ClientSecret) {
        Write-Host "Authenticating with Client Secret..." -ForegroundColor Cyan
        $body = @{
            Grant_Type    = "client_credentials"
            Scope         = "https://graph.microsoft.com/.default"
            Client_Id     = $ClientID
            Client_Secret = $ClientSecret
        }

        $tokenParams = @{
            Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
            Method = 'POST'
            Body   = $body
        }
        Add-IntuneWinProxyParameter -Parameters $tokenParams
        $connection = Invoke-RestMethod @tokenParams

        $token = $connection.access_token

        $global:authToken = @{
            'Content-Type'  = 'application/json'
            'Authorization' = "Bearer " + $connection.access_token
            'ExpiresOn'     = $connection.expires_in
        }

        $targetParameter = (Get-Command Connect-MgGraph).Parameters['AccessToken']
        if ($targetParameter.ParameterType -eq [securestring]) {
            Connect-MgGraph -AccessToken ($token | ConvertTo-SecureString -AsPlainText -Force) -NoWelcome -ErrorAction Stop
        }
        else {
            Connect-MgGraph -AccessToken $token -NoWelcome -ErrorAction Stop
        }
        Write-Host "Successfully authenticated to Microsoft Graph" -ForegroundColor Green
    }
    elseif ($CertName) {
        Write-Host "Using certname: $CertName" -ForegroundColor Cyan
        if ($CertName -notmatch "CN=") {
            $CertName = "CN=$CertName"
        }
        $myCert = Get-ChildItem -Path "cert:\CurrentUser\My" | Where-Object Subject -EQ $CertName
        if ($myCert) {
            Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $myCert.Thumbprint -NoWelcome -ErrorAction Stop
        }
        else {
            Write-Host "Error - cert not found: $CertName" -ForegroundColor Red
            return 1
        }
    }
    else {
        Write-Host "Error: No authentication method specified. Use -IntuneAdmin, -ClientSecret, or -CertName." -ForegroundColor Red
        return 1
    }

    Write-Host ""

    # Delete each application and collect results
    $deleteResults = @()
    foreach ($appName in $appsToDelete) {
        $result = Remove-IntuneApp -DisplayName $appName
        $deleteResults += $result
    }

    # Display summary
    Write-Host "`n" -NoNewline
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "DELETE OPERATION SUMMARY" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan

    $deletedApps = $deleteResults | Where-Object { $_.Status -eq "Deleted" }
    $notFoundApps = $deleteResults | Where-Object { $_.Status -eq "NotFound" }
    $errorApps = $deleteResults | Where-Object { $_.Status -eq "Error" }

    if ($deletedApps.Count -gt 0) {
        Write-Host "`nSuccessfully Deleted ($($deletedApps.Count)):" -ForegroundColor Green
        $deletedApps | ForEach-Object {
            Write-Host "  ✓ $($_.DisplayName)" -ForegroundColor Green
            Write-Host "    App ID: $($_.AppId)" -ForegroundColor DarkGray
        }
    }

    if ($notFoundApps.Count -gt 0) {
        Write-Host "`nNot Found ($($notFoundApps.Count)):" -ForegroundColor Yellow
        $notFoundApps | ForEach-Object {
            Write-Host "  - $($_.DisplayName)" -ForegroundColor Yellow
        }
    }

    if ($errorApps.Count -gt 0) {
        Write-Host "`nErrors ($($errorApps.Count)):" -ForegroundColor Red
        $errorApps | ForEach-Object {
            Write-Host "  ✗ $($_.DisplayName)" -ForegroundColor Red
            Write-Host "    Error: $($_.Message)" -ForegroundColor DarkRed
        }
    }

    Write-Host "`n" -NoNewline
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "Total: $($deleteResults.Count) | Deleted: $($deletedApps.Count) | Not Found: $($notFoundApps.Count) | Errors: $($errorApps.Count)" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan

    Write-Log -Message "Delete operation completed. Deleted: $($deletedApps.Count), Not Found: $($notFoundApps.Count), Errors: $($errorApps.Count)"

    # Handle Graph disconnection
    if ($IntuneAdmin) {
        if ($DisconnectGraph) {
            Write-Log -Message "Disconnecting from Microsoft Graph as requested..."
            Invoke-Cleanup -ForceDisconnect
        }
        else {
            Write-Log -Message "Preserving Microsoft Graph connection for subsequent runs."
        }
    }
    else {
        Invoke-Cleanup -ForceDisconnect
    }

    # Return appropriate exit code
    if ($errorApps.Count -gt 0) {
        return 1
    }
    return 0
}
#endregion Delete App Mode

# Validate PackagePath is provided for non-delete operations
if (-not $PackagePath) {
    Write-Log -Message "Error - PackagePath is required for upload operations" -LogLevel 3
    Write-Host "Error: -PackagePath is required. Specify the path to the package folder containing Config.json or Config.xml." -ForegroundColor Red
    return 1
}

#Check package path is valid
if ( ! ( Test-Path $packagePath ) ) {
    Write-Log -Message "Error - path not valid: $packagePath" -LogLevel 3
    return 1
}

#Validate IntuneWinAppUtil.exe exists and is up to date
Write-Log -Message "Validating IntuneWinAppUtil.exe..." -WriteHost Yellow
try {
    Test-IntuneWinAppUtil -ToolPath $IntuneWinAppUtil
    Write-Log -Message "IntuneWinAppUtil.exe validation complete"
}
catch {
    Write-Log -Message "Error: Failed to validate IntuneWinAppUtil.exe - $($_.Exception.Message)" -LogLevel 3
    return 1
}

#Note: targeting group overlap validation is performed after config file loading (below) so that config-sourced groups are also validated.

#Read Config File (JSON takes precedence over XML)
$jsonConfigPath = "$packagePath\Config.json"
$xmlConfigPath = "$packagePath\Config.xml"

if (Test-Path $jsonConfigPath) {
    Write-Log -Message "Found Config.json, reading: [$jsonConfigPath]"
    Get-JSONConfig -JSONFile $jsonConfigPath
}
elseif (Test-Path $xmlConfigPath) {
    Write-Log -Message "Reading XML file: [$xmlConfigPath]"
    Get-XMLConfig -XMLFile $xmlConfigPath
}
else {
    Write-Log -Message "Error - No Config.json or Config.xml file found in: $packagePath" -LogLevel 3
    return 1
}

# Apply config file settings for parameters not explicitly specified on the command line
# NewTagPath defaults to $true; config can override, and command-line takes highest precedence
if ($PSBoundParameters.ContainsKey('NewTagPath')) {
    Write-Log -Message "NewTagPath explicitly set on command line: $NewTagPath"
}
elseif ($null -ne $script:ConfigNewTagPath) {
    $NewTagPath = $script:ConfigNewTagPath
    Write-Log -Message "NewTagPath set from config file: $NewTagPath"
}
else {
    $NewTagPath = $true
    Write-Log -Message "NewTagPath enabled by default"
}

# RequiredAADGroupName: command-line takes precedence, then config
if (-not $PSBoundParameters.ContainsKey('RequiredAADGroupName') -and $script:ConfigRequiredGroupName.Count -gt 0) {
    $RequiredAADGroupName = $script:ConfigRequiredGroupName
    Write-Log -Message "RequiredAADGroupName set from config file: $($RequiredAADGroupName -join ', ')"
}

# AvailableAADGroupName: command-line takes precedence, then config
if (-not $PSBoundParameters.ContainsKey('AvailableAADGroupName') -and $script:ConfigAvailableGroupName.Count -gt 0) {
    $AvailableAADGroupName = $script:ConfigAvailableGroupName
    Write-Log -Message "AvailableAADGroupName set from config file: $($AvailableAADGroupName -join ', ')"
}

# UninstallAADGroupName: command-line takes precedence, then config
if (-not $PSBoundParameters.ContainsKey('UninstallAADGroupName') -and $script:ConfigUninstallGroupName.Count -gt 0) {
    $UninstallAADGroupName = $script:ConfigUninstallGroupName
    Write-Log -Message "UninstallAADGroupName set from config file: $($UninstallAADGroupName -join ', ')"
}

# ReplaceExistingContent: command-line takes precedence, then config
if (-not $PSBoundParameters.ContainsKey('ReplaceExistingContent') -and $null -ne $script:ConfigReplaceExistingContent) {
    $ReplaceExistingContent = $script:ConfigReplaceExistingContent
    Write-Log -Message "ReplaceExistingContent set from config file: $ReplaceExistingContent"
}

# SkipPackageRemoval: command-line takes precedence, then config
if (-not $PSBoundParameters.ContainsKey('SkipPackageRemoval') -and $null -ne $script:ConfigSkipPackageRemoval) {
    $SkipPackageRemoval = $script:ConfigSkipPackageRemoval
    Write-Log -Message "SkipPackageRemoval set from config file: $SkipPackageRemoval"
}

# Validate targeting group names are different (re-check after config application)
$reqNames = @($RequiredAADGroupName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$availNames = @($AvailableAADGroupName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$uninNames = @($UninstallAADGroupName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$overlapReqAvail = $reqNames | Where-Object { $_ -in $availNames }
$overlapReqUninst = $reqNames | Where-Object { $_ -in $uninNames }
$overlapAvailUninst = $availNames | Where-Object { $_ -in $uninNames }
if ($overlapReqAvail) {
    Write-Log -Message "Error - These group names appear in both Required and Available: $($overlapReqAvail -join ', ')" -LogLevel 3
    return 1
}
if ($overlapReqUninst) {
    Write-Log -Message "Error - These group names appear in both Required and Uninstall: $($overlapReqUninst -join ', ')" -LogLevel 3
    return 1
}
if ($overlapAvailUninst) {
    Write-Log -Message "Error - These group names appear in both Available and Uninstall: $($overlapAvailUninst -join ', ')" -LogLevel 3
    return 1
}

Write-Log -Message "baseUrl: [$baseUrl]" -WriteHost Magenta
Write-Log -Message "logRequestUris: [$logRequestUris]"
Write-Log -Message "logHeaders: [$logHeaders]"
Write-Log -Message "logContent: [$logContent]"
Write-Log -Message "sleep: [$sleep]"

Write-Log -Message "AppType: [$AppType]"
if ( $AppType -eq "Edge" ) {
    Write-Log -Message "displayName: [$displayName]"
    Write-Log -Message "Description: [$Description]"
    Write-Log -Message "Publisher: [$Publisher]"
    Write-Log -Message "Channel: [$Channel]"
    $RuleType = 'skip'
    $ReturnCodeType = 'skip'
    $InstallExperience = 'skip'
    $LogoFile = 'skip'
    Write-Log -Message "RuleType: [$RuleType]"
    Write-Log -Message "ReturnCodeType: [$ReturnCodeType]"
    Write-Log -Message "InstallExperience: [$InstallExperience]"
    Write-Log -Message "LogoFile: [$LogoFile]"
}
if ( $AppType -ne "Edge" ) {
    if ( ( $AppType -eq "EXE" ) -or ( $AppType -eq "MSI" ) ) {
        Write-Log -Message "Using install/unistall commands for AppType: $AppType"
        Write-Log -Message "installCmdLine: [$installCmdLine]"
        Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
    }
    Write-Log -Message "RuleType: [$RuleType]"
    if ($RuleType -eq "FILE") {
        Write-Log -Message "Using detection for RuleType: $RuleType"
        Write-Log -Message "FilePath: [$FilePath]"
        Write-Log -Message "FileDetectionType: [$FileDetectionType]"
        Write-Log -Message "FileDetectionOperator: [$FileDetectionOperator]"
        Write-Log -Message "FileDetectionValue: [$FileDetectionValue]"
    }
    if ($RuleType -eq "REGISTRY") {
        Write-Log -Message "Using detection for RuleType: $RuleType"
        Write-Log -Message "RegistryKeyPath: [$RegistryKeyPath]"
        Write-Log -Message "RegistryValue: [$RegistryValue]"
        Write-Log -Message "RegistryDetectionType: [$RegistryDetectionType]"
        Write-Log -Message "RegistryDetectionOperator: [$RegistryDetectionOperator]"
        Write-Log -Message "RegistryDetectionValue: [$RegistryDetectionValue]"
    }
    if ($RuleType -eq "MSI") {
        Write-Log -Message "Using detection for RuleType: $RuleType"
        Write-Log -Message "MSIProductCode: [$MSIProductCode]"
        Write-Log -Message "MSIProductVersionOperator: [$MSIProductVersionOperator]"
        Write-Log -Message "MSIProductVersion: [$MSIProductVersion]"
    }
    Write-Log -Message "ReturnCodeType: [$ReturnCodeType]"
    Write-Log -Message "InstallExperience: [$InstallExperience]"
    Write-Log -Message "PackageName: [$PackageName]"
    Write-Log -Message "displayName: [$displayName]"
    Write-Log -Message "displayVersion: [$displayVersion]"
    Write-Log -Message "Description: [$Description]"
    Write-Log -Message "Publisher: [$Publisher]"
    Write-Log -Message "Category: [$Category]"
    Write-Log -Message "LogoFile: [$LogoFile]"
}

if (-not($RequiredAADGroupName -or $AvailableAADGroupName -or $UninstallAADGroupName)) {
    Write-Log -Message "EntraGroupName: [$EntraGroupName]"
}
Write-Log -Message "Path to IntuneWinAppUtil: [$IntuneWinAppUtil]"
Write-Log -Message "SourcePath: [$SourcePath]"

#region auth
if ($IntuneWinPackageOnly) {
    Write-Log -Message "IntuneWinPackageOnly param used, skipping authentication..."
}
else {
    if ($IntuneAdmin) {
        Write-Host "`nUsing IntuneAdmin: $IntuneAdmin" -ForegroundColor Green

        # Required scopes for Intune app management and Entra ID group operations
        $requiredScopes = @(
            "DeviceManagementApps.ReadWrite.All",    # For creating/updating Intune apps
            "Group.ReadWrite.All",                    # For creating Entra ID groups
            "GroupMember.ReadWrite.All",              # For managing group memberships
            "DeviceManagementRBAC.ReadWrite.All"      # For managing scope tags (roleScopeTags)
        )

        # Build Connect-MgGraph parameters
        # If -ClientID is also specified, use it as a custom app registration for delegated auth
        $connectParams = @{
            Scopes    = $requiredScopes
            NoWelcome = $true
        }
        if ($ClientID) {
            $connectParams['ClientId'] = $ClientID
            Write-Host "Using custom app registration (ClientID: $ClientID) for delegated authentication" -ForegroundColor Cyan
        }
        if ($TenantID) {
            $connectParams['TenantId'] = $TenantID
            Write-Host "Using Tenant ID: $TenantID" -ForegroundColor Cyan
        }

        # Check if already connected and if current scopes are sufficient
        $context = Get-MgContext
        if ($null -ne $context) {
            $currentScopes = $context.Scopes
            $missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
            # Also check if ClientId changed
            $clientIdChanged = $ClientID -and ($context.ClientId -ne $ClientID)
            if ($missingScopes.Count -gt 0 -or $clientIdChanged) {
                if ($clientIdChanged) {
                    Write-Host "Current session uses different app registration. Reconnecting with ClientID: $ClientID" -ForegroundColor Yellow
                }
                else {
                    Write-Host "Current session is missing required scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
                }
                Write-Host "Disconnecting and reconnecting with required scopes..." -ForegroundColor Yellow
                Disconnect-MgGraph | Out-Null
                Invoke-MgGraphConnect -ConnectParams $connectParams
            }
            else {
                Write-Host "Already connected with required scopes" -ForegroundColor Green
            }
        }
        else {
            Invoke-MgGraphConnect -ConnectParams $connectParams
        }

        # Verify connection succeeded
        $postContext = Get-MgContext
        if ($null -eq $postContext) {
            Write-Log -Message "Connect-MgGraph completed but no context found - authentication did not succeed" -LogLevel 3
            Write-Host "Authentication did not succeed. Please check your credentials and try again." -ForegroundColor Red
            Invoke-Cleanup -ForceDisconnect
            throw "Authentication failed. No MgContext available."
        }
        Write-Host "Successfully authenticated to Microsoft Graph" -ForegroundColor Green
        Write-Log -Message "Authenticated to Graph. ClientId: $($postContext.ClientId), AuthType: $($postContext.AuthType), Scopes: $($postContext.Scopes -join ', ')"
        # Store connection params for 401 re-auth in Invoke-GraphRequestWithRetry
        $script:MgGraphConnectParams = $connectParams
    }
    elseif ($CertName) {
        Write-Host "Using certname: $CertName"
        if ($CertName -match "CN=") {
            Write-Host "Matches" -ForegroundColor Green
        }
        else {
            $CertName = $CertName -replace $CertName, "CN=$CertName"
            Write-Host "Modified Cert Name: $CertName" -ForegroundColor Yellow
        }

        $myCert = Get-ChildItem -Path "cert:\CurrentUser\My" | Where-Object Subject -EQ $CertName
        if ($myCert) {
            Write-Host "Found cert, using it to authenticate to Graph..." -ForegroundColor Yellow
            Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $myCert.Thumbprint -ErrorAction Stop ## Or -CertificateThumbprint instead of -CertificateName
        }
        else {
            Invoke-Cleanup -ForceDisconnect
            throw "Error - cert not found: $CertName"
        }
        #$null = Select-MgProfile -Name "beta" | Out-Null
    }
    elseif ($ClientSecret) {
        #Region Auth
        Write-Host "Authenticating with Client Secret..." -ForegroundColor Cyan
        $body = @{
            Grant_Type    = "client_credentials"
            Scope         = "https://graph.microsoft.com/.default"
            Client_Id     = $ClientID
            Client_Secret = $ClientSecret
        }

        $tokenParams = @{
            Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
            Method = 'POST'
            Body   = $body
        }
        Add-IntuneWinProxyParameter -Parameters $tokenParams

        $proxyHelp = @(
            "The machine is routing outbound traffic through a proxy that requires authentication."
            "Re-run with one of the following:"
            "  -ProxyUri 'http://your-proxy:8080' -ProxyUseDefaultCredentials    (Windows-integrated proxy auth)"
            "  -ProxyUri 'http://your-proxy:8080' -ProxyCredential (Get-Credential)   (explicit proxy account)"
            "Or set the proxy once for the session with:  `$env:INTUNEWIN_PROXY_URI = 'http://your-proxy:8080'"
            "Diagnose with:  .\Upload-IntuneWin.ps1 -TestProxyConnectivity -ProxyUri 'http://your-proxy:8080'"
        ) -join [Environment]::NewLine

        $connection = $null
        try {
            $connection = Invoke-RestMethod @tokenParams -ErrorAction Stop
        }
        catch {
            $statusCode = $null
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { $statusCode = $null }

            if ($statusCode -eq 407) {
                Write-Log -Message "Token request rejected with HTTP 407 Proxy Authentication Required" -LogLevel 2

                # A system proxy needing Windows-integrated auth is the common cause; retry once with the caller's credentials
                if (-not (Test-IntuneWinProxyEnabled) -and (Enable-SystemProxyDefaultCredential)) {
                    Write-Host "Proxy returned HTTP 407 - retrying with your Windows credentials..." -ForegroundColor Yellow
                    try {
                        $connection = Invoke-RestMethod @tokenParams -ErrorAction Stop
                        Write-Log -Message "Token acquired after attaching default proxy credentials"
                    }
                    catch {
                        Invoke-Cleanup -ForceDisconnect
                        throw "Proxy authentication failed (HTTP 407) even with your Windows credentials.$([Environment]::NewLine)$proxyHelp"
                    }
                }
                else {
                    Invoke-Cleanup -ForceDisconnect
                    throw "Proxy authentication required (HTTP 407) when requesting a token from Entra ID.$([Environment]::NewLine)$proxyHelp"
                }
            }
            else {
                Invoke-Cleanup -ForceDisconnect
                $detail = if ($statusCode) { "HTTP $statusCode - $($_.Exception.Message)" } else { $_.Exception.Message }
                throw "Failed to acquire an access token from Entra ID: $detail"
            }
        }

        $token = $connection.access_token
        if ([string]::IsNullOrWhiteSpace($token)) {
            Invoke-Cleanup -ForceDisconnect
            throw "The Entra ID token endpoint returned no access_token. Verify -TenantID, -ClientID and -ClientSecret are correct and the secret has not expired."
        }

        # Creating header for Authorization token
        $global:authToken = @{
            'Content-Type'  = 'application/json'
            'Authorization' = "Bearer " + $connection.access_token
            'ExpiresOn'     = $connection.expires_in
        }

        #$global:authToken = Connect-MgGraph -AccessToken $authToken
        #Connect-MgGraph -AccessToken $token

        $targetParameter = (Get-Command Connect-MgGraph).Parameters['AccessToken']

        if ($targetParameter.ParameterType -eq [securestring]) {
            Connect-MgGraph -AccessToken ($token | ConvertTo-SecureString -AsPlainText -Force) -NoWelcome -ErrorAction Stop
        }
        else {
            Connect-MgGraph -AccessToken $token -NoWelcome -ErrorAction Stop
        }

        Write-Host "Successfully authenticated to Microsoft Graph" -ForegroundColor Green
        Write-Host "Tenant ID: $TenantID" -ForegroundColor Cyan
        Write-Host "Client ID: $ClientID" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "If you encounter 'Forbidden' errors, verify the App Registration has these API permissions:" -ForegroundColor Yellow
        Write-Host "  - DeviceManagementApps.ReadWrite.All (Application)" -ForegroundColor Yellow
        Write-Host "  - Group.ReadWrite.All (Application)" -ForegroundColor Yellow
        Write-Host "  - Ensure Admin Consent has been granted" -ForegroundColor Yellow
        Write-Host ""

        #$null = Select-MgProfile -Name "beta" | Out-Null
        #endRegion Auth
    }
    else {
        Invoke-Cleanup -ForceDisconnect
        throw "Please specify either a valid certificate name or client secret for authentication"
    }

    # After authentication, update description with user info stamp
    $dayDateTime = (Get-Date -UFormat "%A %d-%m-%Y %R")
    $userInfo = Get-AuthenticatedUserInfo
    if (-not [string]::IsNullOrWhiteSpace($userInfo)) {
        $script:Description = $script:BaseDescription + "`nObject creation: $dayDateTime`nBy: $userInfo"
        Write-Log -Message "Updated description with user stamp: $userInfo"
    }
    else {
        # Using app registration - just add date/time without user info
        $script:Description = $script:BaseDescription + "`nObject creation: $dayDateTime"
        Write-Log -Message "Updated description with date stamp (no user info - app registration auth)"
    }
    Write-Log -Message "Final description: $($script:Description)"
}
#endregion auth

if (-not($AssignGroupsOnly)) {
    if (Test-Path -Path "$packagePath\IntuneWin") {
        Write-Log -Message "Removing folder: $packagePath\IntuneWin"
        Move-Item -Path "$packagePath\IntuneWin" -Destination "$env:Temp" -Force
        if (Test-Path -Path "$env:Temp\IntuneWin") {
            Remove-Item -Path "$env:Temp\IntuneWin" -Recurse -Force
        }
    }
}

if ( $AppType -ne "Edge" -and (-not($AssignGroupsOnly))) {
    # Determine which source folder to use
    # If OrigSource exists, copy it to Source via robocopy (mirrors DelegatedImport behavior)
    # This ensures a clean, reproducible Source folder from the golden OrigSource copy.
    $EffectiveSourcePath = $SourcePath
    if (Test-Path $OrigSourcePath) {
        Write-Log -Message "OrigSource folder found at: [$OrigSourcePath]"
        Write-Host "Copying OrigSource -> Source via robocopy..." -ForegroundColor Cyan
        if (Test-Path $SourcePath) {
            Remove-Item -Path $SourcePath -Recurse -Force -ErrorAction Stop
        }
        New-Item -ItemType Directory -Path $SourcePath -Force | Out-Null
        & robocopy "$OrigSourcePath" "$SourcePath" /MIR /MT:4 /NJH /NJS /NP | Out-Null
        Write-Log -Message "OrigSource copied to Source successfully"
        $EffectiveSourcePath = $SourcePath
    }
    elseif (!(Test-Path $SourcePath)) {
        Write-Log -Message "Error - Neither Source nor OrigSource folder found" -LogLevel 3
        Write-Host "Error: Neither Source nor OrigSource folder found at:" -ForegroundColor Red
        Write-Host "  Source: $SourcePath" -ForegroundColor Red
        Write-Host "  OrigSource: $OrigSourcePath" -ForegroundColor Red
        exit
    }

    # Version detection for EXE and MSI files
    if (($AppType -eq "EXE") -or ($AppType -eq "MSI")) {
        Write-Log -Message "Checking installer version for $AppType package..."

        # Determine which config file is being used
        $jsonConfigPath = "$packagePath\Config.json"
        $xmlConfigPath = "$packagePath\Config.xml"
        $activeConfigPath = if (Test-Path $jsonConfigPath) { $jsonConfigPath } else { $xmlConfigPath }

        Invoke-VersionCheck -SourcePath $EffectiveSourcePath -PackageName $PackageName -AppType $AppType -ConfigFilePath $activeConfigPath -ConfigVersion $script:displayVersion
    }

    # Validate EXE file exists in Source folder (EXE type only)
    if ($AppType -eq "EXE") {
        Write-Log -Message "Validating EXE file in installCmdLine..."

        # Determine which config file is being used (reuse if already set)
        if (-not $activeConfigPath) {
            $jsonConfigPath = "$packagePath\Config.json"
            $xmlConfigPath = "$packagePath\Config.xml"
            $activeConfigPath = if (Test-Path $jsonConfigPath) { $jsonConfigPath } else { $xmlConfigPath }
        }

        if (-not [string]::IsNullOrWhiteSpace($script:installCmdLine)) {
            Invoke-ExeValidation -SourcePath $EffectiveSourcePath -InstallCmdLine $script:installCmdLine -ConfigFilePath $activeConfigPath -PackageName $script:PackageName
        }
        else {
            Write-Log -Message "Warning: installCmdLine is empty for EXE type package" -LogLevel 2
        }
    }

    Write-Log -Message "Call Invoke-IntuneWinAppUtil function..."
    Invoke-IntuneWinAppUtil -AppType $AppType -IntuneWinAppPath $IntuneWinAppUtil -PackageSourcePath $EffectiveSourcePath -IntuneAppPackage "$PackageName"
    Write-Log -Message "Return code from IntuneWin: $script:exitCode"

    if ( $script:exitCode -eq "-1" ) {
        Write-Log -Message "Error - from IntuneWin, exiting."
        exit
    }

    if ($IntuneWinPackageOnly) {
        Write-Log -Message "IntuneWinPackageOnly param used, exiting. Package path located at: `n$packagePath\IntuneWin"
        return 0
    }
}

Write-Log -Message "Call Build-IntuneAppPackage function..."
Build-IntuneAppPackage -AppType $AppType -RuleType $RuleType -ReturnCodeType $ReturnCodeType -InstallExperience $InstallExperience -Logo $LogoFile -EntraGroupName $EntraGroupName
Write-Log -Message "Return code from Build-IntuneAppPackage: $script:exitCode"

if ( $script:exitCode -eq "-1" ) {
    Write-Log -Message "Error - from Build-IntuneAppPackage, exiting."
    exit
}

if (-not($SkipPackageRemoval -or $AssignGroupsOnly)) {
    if (Test-Path -Path "$packagePath\IntuneWin") {
        Write-Log -Message "Removing folder: $packagePath\IntuneWin"
        Move-Item -Path "$packagePath\IntuneWin" -Destination "$env:Temp" -Force
        if (Test-Path -Path "$env:Temp\IntuneWin") {
            Remove-Item -Path "$env:Temp\IntuneWin" -Recurse -Force
        }
    }
}

# Display completion summary with app name
if ($script:displayName) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    if ($script:exitCode -eq 0) {
        Write-Host "UPLOAD COMPLETE" -ForegroundColor Green
    }
    else {
        Write-Host "UPLOAD COMPLETED WITH WARNINGS" -ForegroundColor Yellow
    }
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Application: $($script:displayName)" -ForegroundColor White
    Write-Host "Exit Code: $($script:exitCode)" -ForegroundColor $(if ($script:exitCode -eq 0) { 'Green' } else { 'Yellow' })
    Write-Host "========================================`n" -ForegroundColor Cyan
}

Write-Log "$ScriptName completed. Application: $($script:displayName)" -WriteEventLog

# Handle Graph disconnection based on authentication method and -DisconnectGraph switch
if ($IntuneAdmin) {
    # When using -IntuneAdmin, only disconnect if explicitly requested with -DisconnectGraph
    if ($DisconnectGraph) {
        Write-Log -Message "Disconnecting from Microsoft Graph as requested..."
        Invoke-Cleanup -ForceDisconnect
    }
    else {
        Write-Log -Message "Preserving Microsoft Graph connection for subsequent runs. Use -DisconnectGraph to explicitly disconnect."
    }
}
elseif (-not $IntuneWinPackageOnly) {
    # For other auth methods (ClientSecret, CertName), always disconnect
    Invoke-Cleanup -ForceDisconnect
}
return $script:exitCode

##########################################################################################################
##########################################################################################################
#endregion Main Script work section

