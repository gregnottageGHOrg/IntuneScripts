#Requires -Module Microsoft.Graph.Authentication
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

.PARAMETER UserName
    Specifies an Azure/Intune admin user name for legacy AzureAD module authentication.
    This parameter is used with the older authentication method.

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
    Specifies an Entra ID group name for required assignment targeting.
    If the group doesn't exist, it will be created.
    Alias: RequiredEntraGroupName

.PARAMETER AvailableAADGroupName
    Specifies an Entra ID group name for available assignment targeting.
    If the group doesn't exist, it will be created.
    Alias: AvailableEntraGroupName

.PARAMETER UninstallAADGroupName
    Specifies an Entra ID group name for uninstall assignment targeting.
    If the group doesn't exist, it will be created.
    Alias: UninstallEntraGroupName

.PARAMETER NewTagPath
    Switch parameter that changes the tagfile path to %PROGRAMDATA%\IntuneManagementExtension\Logs.
    This ensures logs are captured during an Intune diagnostic log capture.

.PARAMETER ScopeTagName
    Specifies the Intune scope tag name to apply to the uploaded application.
    This parameter takes precedence over the ScopeTag attribute in Config.xml.
    If the scope tag doesn't exist in the tenant, it will be created automatically.
    The scope tag replaces any existing scope tags on the application (including the Default scope tag).

.PARAMETER ReplaceExistingContent
    Switch parameter that replaces only the IntuneWin content of an existing application.
    The application must already exist in Intune. All other configuration (assignments, detection rules,
    requirements, scope tags, etc.) will be preserved. Only the package content is updated.
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
    Version        : 1.9
    Prerequisite   : Microsoft.Graph.Authentication module
                     IntuneWinAppUtil.exe (Microsoft Win32 Content Prep Tool) - automatically downloaded if not present

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
    - category: App category (e.g., Business)
    - logoFile: Path to logo file (PNG/JPG)
    - scopetag: Name of the Intune scope tag (optional, overridden by -ScopeTagName parameter)
    - entraGroupName: Entra ID group name for assignments (preferred)
    - aadGroupName: Entra ID group name for assignments (legacy, still supported)
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
    - minimumSupportedOS: v10_1903, v10_21H2, v11_23H2, etc.
    - customReturnCodes: Custom return code handling (array or comma-separated code:type)
    - dependencies: Apps this app depends on (array or comma-separated names)
    - dependencyType: autoInstall or detect
    - supersedence: Apps this app supersedes (array or comma-separated names)
    - supersedenceType: update or replace
    - detectionScriptFile: Path to PowerShell detection script
    - detectionScriptEnforceSignatureCheck: Require signed detection script
    - detectionScriptRunAs32Bit: Run detection script as 32-bit

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

    [Parameter(Position = 2, ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $True,
        HelpMessage = 'Please specify an Azure/Intune admin user name'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $UserName,

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

    [Parameter(HelpMessage = 'Applies an Entra ID group with required assignment targeting'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("RequiredEntraGroupName")]
    [string] $RequiredAADGroupName,

    [Parameter(HelpMessage = 'Applies an Entra ID group with available assignment targeting'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("AvailableEntraGroupName")]
    [string] $AvailableAADGroupName,

    [Parameter(HelpMessage = 'Applies an Entra ID group with uninstall assignment targeting'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("UninstallEntraGroupName")]
    [string] $UninstallAADGroupName,

    [Parameter(HelpMessage = 'Changes the tagfile path to %PROGRAMDATA%\IntuneManagementExtension\Logs - this is so that the logs are captured during an Intune diagnostic log capture'
    )]
    [switch] $NewTagPath,

    [Parameter(HelpMessage = 'Specifies the Intune scope tag name to apply to the uploaded application. Takes precedence over ScopeTag in Config.xml. If the scope tag does not exist, it will be created.'
    )]
    [string] $ScopeTagName,

    [Parameter(HelpMessage = 'Replaces only the IntuneWin content of an existing application while keeping all other configuration intact. The app must already exist in Intune.'
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
    [string[]] $AppNameToDelete
)
$script:exitCode = 0
$script:contentReplaced = $false
$script:noExistingAssignments = $false
$script:replaceAssignmentsMode = $false

$BuildVer = "1.9"
$ProgramFiles = $env:ProgramFiles
$ScriptName = $myInvocation.MyCommand.Name
$ScriptName = $ScriptName.Substring(0, $ScriptName.Length - 4)
$LogName = $ScriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
$logPath = "$($env:LocalAppData)\Microsoft\IntuneApps\$ScriptName"
$logFile = "$logPath\$LogName.log"
Add-Type -AssemblyName Microsoft.VisualBasic
$script:EventLogName = "Application"
$script:EventLogSource = "EventSystem"
if ($packagePath) {
    $packagePath = $packagePath.Trim()
}

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
####################################################
#Build Functions
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
    [CmdletBinding()]
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
            elseif ($statusCode -ge 500 -and $statusCode -lt 600) {
                # Server error - retry with exponential backoff
                $isRetryable = $true
                Write-Log -Message "Server error ($statusCode). Retrying in $delay seconds..." -LogLevel 2
            }
            elseif ($_.Exception.Message -match 'network|timeout|connection') {
                # Network error - retry
                $isRetryable = $true
                Write-Log -Message "Network error. Retrying in $delay seconds..." -LogLevel 2
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
        [string]$RequiredAADGroupName,

        [Parameter(Mandatory = $false)]
        [string]$AvailableAADGroupName,

        [Parameter(Mandatory = $false)]
        [string]$UninstallAADGroupName
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

    # Validate group name uniqueness
    $groupNames = @($RequiredAADGroupName, $AvailableAADGroupName, $UninstallAADGroupName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $uniqueGroups = $groupNames | Select-Object -Unique
    if ($groupNames.Count -ne $uniqueGroups.Count) {
        [void]$errors.Add("Group names must be unique. RequiredAADGroupName, AvailableAADGroupName, and UninstallAADGroupName cannot be the same.")
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

                $response = Invoke-RestMethod -Uri $githubApiUrl -Headers $headers -Method Get -ErrorAction Stop

                if ($response -and $response.Count -gt 0) {
                    $githubCommitDate = [DateTime]::Parse($response[0].commit.committer.date).ToUniversalTime()
                    Write-Host "  GitHub last commit date: $($githubCommitDate.ToString('yyyy-MM-dd HH:mm:ss')) UTC" -ForegroundColor Cyan

                    # Compare dates - if GitHub version is newer (commit date is after local file date)
                    if ($githubCommitDate -gt $localLastWriteTime.AddMinutes(5)) {
                        Write-Host "A newer version is available on GitHub. Downloading update..." -ForegroundColor Yellow

                        # Download the new version
                        $tempPath = Join-Path $env:TEMP "IntuneWinAppUtil_new.exe"
                        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath -UseBasicParsing

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
            Invoke-WebRequest -Uri $downloadUrl -OutFile $ToolPath -UseBasicParsing

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

function Get-AuthToken {

    <#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )

    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

    $tenant = $userUpn.Host

    Write-Host "Checking for AzureAD module..."

    #$AadModule = Get-Module -Name "AzureAD" -ListAvailable
    $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    <#
    if ($null -eq $AadModule) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }
#>

    if ($null -eq $AadModule) {
        Write-Host
        Write-Host "AzureADPreview Powershell module not installed..." -f Red
        Write-Host "Attempting module install now (requires Admin rights!)" -f Red
        Install-Module -Name AzureADPreview -AllowClobber -Force -Scope CurrentUser
        Write-Host
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if ($AadModule.count -gt 1) {

        $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]

        $aadModule = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }

        # Checking if there are multiple versions of the same module found

        if ($AadModule.count -gt 1) {

            $aadModule = $AadModule | Select-Object -Unique

        }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    $resourceAppIdURI = "https://graph.microsoft.com"

    $authority = "https://login.microsoftonline.com/$Tenant"

    try {

        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result

        # If the accesstoken is valid then create the authentication header

        if ($authResult.AccessToken) {

            # Creating header for Authorization token

            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }

            return $authHeader

        }

        else {

            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            $script:exitCode = 1
            return $null

        }

    }

    catch {

        Write-Host $_.Exception.Message -f Red
        Write-Host $_.Exception.ItemName -f Red
        Write-Host
        $script:exitCode = 1
        return $null

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
            if ($userName) {
                $result = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
            }
            else {
                $result = Invoke-MgGraphRequest -Method Get -Uri $uri
            }

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

            if ($userName) {
                $categoryJson = $categoryBody | ConvertTo-Json -Depth 10
                $headers = Copy-Object $authToken
                $headers["content-length"] = $categoryJson.Length
                $headers["content-type"] = "application/json"
                $null = Invoke-RestMethod -Uri $categoryUri -Headers $headers -Method Post -Body $categoryJson
            }
            else {
                $null = Invoke-MgGraphRequest -Uri $categoryUri -Method Post -Body $categoryBody
            }

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
The ID of the application that is depended upon (the dependency)
.PARAMETER DependencyType
The type of dependency: 'detect' or 'autoInstall'. Default is 'autoInstall'.
.EXAMPLE
Set-IntuneAppDependency -ApplicationId "12345" -DependencyAppId "67890" -DependencyType "autoInstall"
.NOTES
NAME: Set-IntuneAppDependency
#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
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

        $graphApiVersion = "beta"
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps/$ApplicationId/relationships"

        try {
            $dependencyBody = @{
                "@odata.type"    = "#microsoft.graph.mobileAppDependency"
                "targetId"       = $DependencyAppId
                "dependencyType" = $DependencyType
            }

            if ($userName) {
                $dependencyJson = $dependencyBody | ConvertTo-Json -Depth 10
                $headers = Copy-Object $authToken
                $headers["content-length"] = $dependencyJson.Length
                $headers["content-type"] = "application/json"
                $null = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $dependencyJson
            }
            else {
                $null = Invoke-MgGraphRequest -Uri $uri -Method Post -Body $dependencyBody
            }

            Write-Log -Message "Dependency added successfully"
            Write-Host "Dependency on app '$DependencyAppId' added successfully" -ForegroundColor Green
            return $true
        }
        catch {
            if ($_.Exception.Message -match "already exists") {
                Write-Log -Message "Dependency on app '$DependencyAppId' already exists"
                Write-Host "Dependency already exists" -ForegroundColor Green
                return $true
            }
            Write-Log -Message "Error adding dependency: $_" -LogLevel 2
            Write-Host "Warning: Failed to add dependency - $_" -ForegroundColor Yellow
            return $false
        }
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
The ID of the application being superseded (the older app)
.PARAMETER SupersedenceType
The type of supersedence: 'update' or 'replace'. Default is 'update'.
.EXAMPLE
Set-IntuneAppSupersedence -ApplicationId "12345" -SupersededAppId "67890" -SupersedenceType "update"
.NOTES
NAME: Set-IntuneAppSupersedence
#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
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

        $graphApiVersion = "beta"
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps/$ApplicationId/relationships"

        try {
            $supersedenceBody = @{
                "@odata.type"      = "#microsoft.graph.mobileAppSupersedence"
                "targetId"         = $SupersededAppId
                "supersedenceType" = $SupersedenceType
            }

            if ($userName) {
                $supersedenceJson = $supersedenceBody | ConvertTo-Json -Depth 10
                $headers = Copy-Object $authToken
                $headers["content-length"] = $supersedenceJson.Length
                $headers["content-type"] = "application/json"
                $null = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $supersedenceJson
            }
            else {
                $null = Invoke-MgGraphRequest -Uri $uri -Method Post -Body $supersedenceBody
            }

            Write-Log -Message "Supersedence added successfully"
            Write-Host "Supersedence of app '$SupersededAppId' added successfully" -ForegroundColor Green
            return $true
        }
        catch {
            if ($_.Exception.Message -match "already exists") {
                Write-Log -Message "Supersedence of app '$SupersededAppId' already exists"
                Write-Host "Supersedence already exists" -ForegroundColor Green
                return $true
            }
            Write-Log -Message "Error adding supersedence: $_" -LogLevel 2
            Write-Host "Warning: Failed to add supersedence - $_" -ForegroundColor Yellow
            return $false
        }
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
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps?`$filter=displayName eq '$DisplayName'"

        try {
            if ($userName) {
                $response = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
            }
            else {
                $response = Invoke-MgGraphRequest -Uri $uri -Method Get
            }

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

            if ($userName) {
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
            }
            else {
                Invoke-MgGraphRequest -Uri $uri -Method Delete
            }

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
Creates a minimum operating system object for Win32 app requirements
.DESCRIPTION
This function creates a windowsMinimumOperatingSystem object based on the specified Windows version.
.PARAMETER MinimumOS
The minimum Windows version: v10_1607, v10_1703, v10_1709, v10_1803, v10_1809, v10_1903, v10_1909, v10_2004, v10_2H20, v10_21H1
.EXAMPLE
$minOS = Get-MinimumOperatingSystemObject -MinimumOS "v10_1903"
.NOTES
NAME: Get-MinimumOperatingSystemObject
#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('v10_1507', 'v10_1511', 'v10_1607', 'v10_1703', 'v10_1709', 'v10_1803', 'v10_1809', 'v10_1903', 'v10_1909', 'v10_2004', 'v10_2H20', 'v10_21H1', 'v10_21H2', 'v10_22H2', 'v11_21H2', 'v11_22H2', 'v11_23H2', 'v11_24H2')]
        [string]$MinimumOS
    )

    # Create object with the selected version set to true
    $minOSObject = @{
        "@odata.type" = "#microsoft.graph.windowsMinimumOperatingSystem"
    }

    # Set the specified version to true
    $minOSObject[$MinimumOS] = $true

    return $minOSObject
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

    $stream = New-Object IO.MemoryStream;
    $formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter;
    $formatter.Serialize($stream, $object);
    $stream.Position = 0;
    $formatter.Deserialize($stream);
}

####################################################

function Write-AuthHeaders($authToken) {

    foreach ($header in $authToken.GetEnumerator()) {
        if ($header.Name.ToLower() -eq "authorization") {
            continue;
        }

        Write-Host -ForegroundColor Gray "$($header.Name): $($header.Value)";
    }
}

####################################################

function Invoke-GetRequest($collectionPath) {

    Write-Host "Running Invoke-GetRequest: $collectionPath" -ForegroundColor Green
    Write-Host "Running Invoke-GetRequest baseURL: $script:baseUrl" -ForegroundColor Green
    Write-Host


    $uri = "$script:baseUrl$collectionPath";
    $request = "GET $uri";

    if ($userName) {
        if ($logRequestUris) { Write-Host $request; }
        if ($logHeaders) { Write-AuthHeaders $authToken; }
    }

    try {
        if ($userName) {
            Test-AuthToken -User $Username
            $response = Invoke-RestMethod $uri -Method Get -Headers $authToken;
        }
        else {
            #Write-Host "Get URI: $uri" -ForegroundColor Magenta
            $response = Invoke-MgGraphRequest $uri -Method Get
        }
        Write-Host
        Write-Host "Response returned:" -ForegroundColor Green
        #$response
        Write-Host
        Write-Host "Response: $($response | Out-String)" -ForegroundColor Yellow
        Write-Host
        return $response
    }
    catch {
        throw
    }
}

####################################################

function Invoke-PatchRequest($collectionPath, $body) {

    Invoke-IntuneGraphRequest "PATCH" $collectionPath $body;

}

####################################################

function Invoke-PostRequest($collectionPath, $body) {

    Invoke-IntuneGraphRequest "POST" $collectionPath $body;

}

####################################################

function Invoke-IntuneGraphRequest($verb, $collectionPath, $body) {

    $uri = "$script:baseUrl$collectionPath";
    $request = "$verb $uri";

    <#
    If ($authToken) {
        Write-Host "authToken: $authToken"
    }
    Else { Throw "No authToken" }
    #$authToken | Format-List *

    $clonedHeaders = Copy-Object $authToken;
    #$clonedHeaders | Format-List *
    $clonedHeaders["content-length"] = $body.Length;
    Write-Host "After clonedHeaders length" -ForegroundColor Yellow
    $clonedHeaders["content-type"] = "application/json";

    if ($logRequestUris) { Write-Host $request; }
    if ($logHeaders) { Write-AuthHeaders $clonedHeaders; }
    if ($logContent) { Write-Host -ForegroundColor Gray $body; }

    Exit
    #>

    if ($userName) {
        if ($authToken) {
            Write-Host "authToken expires on:" -ForegroundColor Green
            $authToken.ExpiresOn.datetime

            # Setting DateTime to Universal time to work in all timezones
            $DateTime = (Get-Date).ToUniversalTime()
            Write-Host "$DateTime" -ForegroundColor Magenta

            # If the authToken exists checking when it expires
            $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
            Write-Host "$TokenExpires" -ForegroundColor Magenta
        }
        else { throw "No authToken" }

        $clonedHeaders = Copy-Object $authToken;
        #Write-Host "clonedHeaders: $clonedHeaders" -ForegroundColor Green
        #$clonedHeaders | Format-List *

        $clonedHeaders["content-length"] = $body.Length;
        $clonedHeaders["content-type"] = "application/json";

        Write-Host $request
        Write-AuthHeaders $clonedHeaders
        Write-Host -ForegroundColor Gray $body`n
    }
    try {
        if ($userName) {
            Test-AuthToken -User $Username
            $response = Invoke-RestMethod $uri -Method $verb -Headers $clonedHeaders -Body $body -UseBasicParsing;
        }
        else {
            #$response = Invoke-MgGraphRequest $uri -Method $verb -Body $body -Headers $clonedHeaders
            $response = Invoke-MgGraphRequest $uri -Method $verb -Body $body
        }
        $response;
    }
    catch {
        Write-Host -ForegroundColor Red $request;
        Write-Host -ForegroundColor Red $_.Exception.Message;
        throw;
    }
}

####################################################

function Send-AzureStorageChunk($sasUri, $id, $body) {

    $uri = "$sasUri&comp=block&blockid=$id";
    $request = "PUT $uri";

    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
    };

    if ($logRequestUris) { Write-Host $request; }
    if ($logHeaders) { Write-AuthHeaders $headers; }

    try {
        # Upload binary data directly without text encoding conversion
        $response = Invoke-WebRequest $uri -Method Put -Headers $headers -Body $body -UseBasicParsing;
    }
    catch {
        Write-Host -ForegroundColor Red $request;
        Write-Host -ForegroundColor Red $_.Exception.Message;
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

        $response = Invoke-WebRequest -Uri $uri -Method Put -Headers $headers -Body $xmlBytes -ContentType "application/xml; charset=utf-8" -UseBasicParsing

        Write-Host -ForegroundColor Green "Azure Storage Response: StatusCode=$($response.StatusCode) StatusDescription=$($response.StatusDescription)"
        return $response
    }
    catch {
        Write-Host -ForegroundColor Red $request;
        Write-Host -ForegroundColor Red "Error Message: $($_.Exception.Message)";

        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $reader.BaseStream.Position = 0
                $responseBody = $reader.ReadToEnd()
                Write-Host -ForegroundColor Red "Response Body: $responseBody"
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

        $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb;

        # Start the timer for SAS URI renewal.
        $sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()

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

            $null = Send-AzureStorageChunk $sasUri $id $bytes

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

        if ($null -eq $reader) { $reader.Dispose(); }

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
    $attempts = 600;
    $waitTimeInSeconds = 10;

    $successState = "$($stage)Success"
    $pendingState = "$($stage)Pending"

    $file = $null
    while ($attempts -gt 0) {
        $file = Invoke-GetRequest $fileUri;

        Write-Host
        Write-Host "File: $($file | Out-String)" -ForegroundColor Yellow
        Write-Host

        if ($file.uploadState -eq $successState) {
            break;
        }
        elseif ($file.uploadState -ne $pendingState) {
            Write-Host -ForegroundColor Red $_.Exception.Message;
            throw "File upload state is not successful: $($file.uploadState)";
        }

        Start-Sleep $waitTimeInSeconds;
        $attempts--;
    }

    if ($null -eq $file -or $file.uploadState -ne $successState) {
        throw "File request did not complete in the allotted time.";
    }

    $file;
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
            $body.minimumSupportedOperatingSystem = Get-MinimumOperatingSystemObject -MinimumOS $minimumSupportedOS
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
            $body.uninstallCommandLine = "msiexec /x `"$MsiProductCode`""
        }
        else {
            $body.uninstallCommandLine = "msiexec /x `"$MsiProductCode`" $msiUninstallCommandLine"
        }
        $body.allowAvailableUninstall = $true
        if (-not [string]::IsNullOrWhiteSpace($logo)) {
            $body.largeIcon = @{"type" = "image/png"; "value" = $logo }
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
            $body.minimumSupportedOperatingSystem = Get-MinimumOperatingSystemObject -MinimumOS $minimumSupportedOS
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
        $body.allowAvailableUninstall = $true
        if (-not [string]::IsNullOrWhiteSpace($logo)) {
            $body.largeIcon = @{"type" = "image/png"; "value" = $logo }
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
        $DR.enforceSignatureCheck = $false;
        $DR.runAs32Bit = $false;
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

        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)

    }

    $zip.Dispose()

    [xml]$IntuneWinXML = Get-Content "$Directory\$filename"

    return $IntuneWinXML

    if ($removeitem -eq "true") { Remove-Item "$Directory\$filename" }

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

        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)

    }

    $zip.Dispose()

    return "$Directory\$folder\$filename"

    if ($removeitem -eq "true") { Remove-Item "$Directory\$filename" }

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
        [hashtable] $minimumSupportedOS = $null,

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

        # Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Host
        Write-Host "Creating Content Version in the service for the application..." -ForegroundColor Yellow
        $appId = $mobileApp.id;
        $contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions";
        $contentVersion = Invoke-PostRequest $contentVersionUri "{}";

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

        #$sasUri = $file.azureStorageUri;
        Send-FileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri;

        # Wait a few seconds for Azure Storage to fully commit and replicate
        Write-Host "Waiting 5 seconds for Azure Storage to finalize..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5

        # Need to Add removal of IntuneWin file
        #$IntuneWinFolder = [System.IO.Path]::GetDirectoryName("$IntuneWinFile")
        Remove-Item "$IntuneWinFile" -Force

        # Commit the file.
        Write-Host
        Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
        Write-Host "File Encryption Info being sent:" -ForegroundColor Cyan
        Write-Host ($fileEncryptionInfo | ConvertTo-Json -Depth 10) -ForegroundColor Gray
        $commitFileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit";
        Invoke-PostRequest $commitFileUri ($fileEncryptionInfo | ConvertTo-Json);

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

        # Create a new content version for the existing app
        Write-Host
        Write-Host "Creating new Content Version for the existing application..." -ForegroundColor Yellow
        $contentVersionUri = "mobileApps/$AppId/$LOBType/contentVersions"
        $contentVersion = Invoke-PostRequest $contentVersionUri "{}"

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

        # Clean up the extracted IntuneWin file
        Remove-Item "$IntuneWinFile" -Force

        # Commit the file
        Write-Host
        Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
        Write-Host "File Encryption Info being sent:" -ForegroundColor Cyan
        Write-Host ($fileEncryptionInfo | ConvertTo-Json -Depth 10) -ForegroundColor Gray
        $commitFileUri = "mobileApps/$AppId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit"
        Invoke-PostRequest $commitFileUri ($fileEncryptionInfo | ConvertTo-Json)

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
            <#
            If (Test-Null($Username)) {
                $script:Username = [string]$XMLEntity.Username
            }
            #>
            $script:baseUrl = [string]$XMLEntity.baseUrl
            $script:logRequestUris = [string]$XMLEntity.logRequestUris
            $script:logHeaders = [string]$XMLEntity.logHeaders
            $script:logContent = [string]$XMLEntity.logContent
            $script:azureStorageUploadChunkSizeInMb = [string]$XMLEntity.azureStorageUploadChunkSizeInMb
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
                if (($FileDetectionType -ne "exists") -or ($FileDetectionType -ne "doesNotExist")) {
                    $script:FileDetectionOperator = [string]$XMLEntity.FileDetectionOperator
                    $script:FileDetectionValue = [string]$XMLEntity.FileDetectionValue
                }
            }

            if ($RuleType -eq "REGISTRY") {
                Write-Log -Message "Reading detection for RuleType: $RuleType"
                $script:RegistryKeyPath = [string]$XMLEntity.RegistryKeyPath
                $script:RegistryValue = [string]$XMLEntity.RegistryValue
                $script:RegistryDetectionType = [string]$XMLEntity.RegistryDetectionType
                if (($RegistryDetectionType -ne "exists") -or ($RegistryDetectionType -ne "doesNotExist")) {
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
            $script:Category = [string]$XMLEntity.Category
            $script:LogoFile = [string]$XMLEntity.LogoFile
            # Support both EntraGroupName (preferred) and AADGroupName (legacy)
            $script:EntraGroupName = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.EntraGroupName)) { [string]$XMLEntity.EntraGroupName } else { [string]$XMLEntity.AADGroupName }

            # Read optional ScopeTag from Config.xml
            $script:ConfigScopeTag = [string]$XMLEntity.ScopeTag
            if (-not [string]::IsNullOrWhiteSpace($script:ConfigScopeTag)) {
                Write-Log -Message "Found ScopeTag in Config.xml: $($script:ConfigScopeTag)"
            }

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

            # Dependencies (comma-separated list of app display names)
            $script:Dependencies = [string]$XMLEntity.Dependencies
            $script:DependencyType = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.DependencyType)) { [string]$XMLEntity.DependencyType } else { "autoInstall" }

            # Supersedence (comma-separated list of app display names)
            $script:Supersedence = [string]$XMLEntity.Supersedence
            $script:SupersedenceType = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.SupersedenceType)) { [string]$XMLEntity.SupersedenceType } else { "update" }

            # PowerShell Script Detection settings
            $script:DetectionScriptFile = [string]$XMLEntity.DetectionScriptFile
            $script:DetectionScriptEnforceSignatureCheck = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.DetectionScriptEnforceSignatureCheck)) { [bool]::Parse([string]$XMLEntity.DetectionScriptEnforceSignatureCheck) } else { $false }
            $script:DetectionScriptRunAs32Bit = if (-not [string]::IsNullOrWhiteSpace([string]$XMLEntity.DetectionScriptRunAs32Bit)) { [bool]::Parse([string]$XMLEntity.DetectionScriptRunAs32Bit) } else { $false }

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
            $script:JSON_Content = Get-Content $JSONFile -Raw | ConvertFrom-Json
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
        $script:azureStorageUploadChunkSizeInMb = "6l"
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
            if (($FileDetectionType -ne "exists") -or ($FileDetectionType -ne "doesNotExist")) {
                $script:FileDetectionOperator = if ($JSON_Content.fileDetectionOperator) { [string]$JSON_Content.fileDetectionOperator } else { [string]$JSON_Content.FileDetectionOperator }
                $script:FileDetectionValue = if ($JSON_Content.fileDetectionValue) { [string]$JSON_Content.fileDetectionValue } else { [string]$JSON_Content.FileDetectionValue }
            }
        }

        if ($RuleType -eq "REGISTRY") {
            Write-Log -Message "Reading detection for RuleType: $RuleType"
            $script:RegistryKeyPath = if ($JSON_Content.registryKeyPath) { [string]$JSON_Content.registryKeyPath } else { [string]$JSON_Content.RegistryKeyPath }
            $script:RegistryValue = if ($JSON_Content.registryValue) { [string]$JSON_Content.registryValue } else { [string]$JSON_Content.RegistryValue }
            $script:RegistryDetectionType = if ($JSON_Content.registryDetectionType) { [string]$JSON_Content.registryDetectionType } else { [string]$JSON_Content.RegistryDetectionType }
            if (($RegistryDetectionType -ne "exists") -or ($RegistryDetectionType -ne "doesNotExist")) {
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
        $script:Category = if ($JSON_Content.category) { [string]$JSON_Content.category } else { [string]$JSON_Content.Category }
        $script:LogoFile = if ($JSON_Content.logoFile) { [string]$JSON_Content.logoFile } else { [string]$JSON_Content.LogoFile }
        # Support both entraGroupName (preferred) and aadGroupName (legacy)
        $script:EntraGroupName = if ($JSON_Content.entraGroupName) { [string]$JSON_Content.entraGroupName } `
            elseif ($JSON_Content.EntraGroupName) { [string]$JSON_Content.EntraGroupName } `
            elseif ($JSON_Content.aadGroupName) { [string]$JSON_Content.aadGroupName } `
            else { [string]$JSON_Content.AADGroupName }

        # Read optional ScopeTag from Config.json (supports both scopetag and scopeTag)
        $script:ConfigScopeTag = if ($JSON_Content.scopetag) { [string]$JSON_Content.scopetag } `
            elseif ($JSON_Content.scopeTag) { [string]$JSON_Content.scopeTag } `
            elseif ($JSON_Content.ScopeTag) { [string]$JSON_Content.ScopeTag } `
            else { "" }
        if (-not [string]::IsNullOrWhiteSpace($script:ConfigScopeTag)) {
            Write-Log -Message "Found ScopeTag in Config.json: $($script:ConfigScopeTag)"
        }

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

        # Additional Requirement Rules (array of requirement rule objects)
        $script:RequirementRules = $JSON_Content.requirementRules

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

                # Load logo icon from config file if specified
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
                    Write-Log -Message "No logo file specified in config"
                }

            }

            # Process extended settings from config
            Write-Log -Message "Processing extended settings from config..."

            # Build minimum supported OS object from string
            $minOSObject = $null
            if (-not [string]::IsNullOrWhiteSpace($script:MinimumSupportedOS)) {
                Write-Log -Message "MinimumSupportedOS from config: $($script:MinimumSupportedOS)"
                $minOSObject = Get-MinimumOperatingSystemObject -OSVersionString $script:MinimumSupportedOS
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
                            if ($userName) {
                                # Using legacy auth token method
                                $clonedHeaders = Copy-Object $authToken
                                $clonedHeaders["content-length"] = $logoJson.Length
                                $clonedHeaders["content-type"] = "application/json"
                                $null = Invoke-RestMethod -Uri $logoUri -Method Patch -Headers $clonedHeaders -Body $logoJson -UseBasicParsing
                            }
                            else {
                                # Using Invoke-MgGraphRequest with pre-serialized JSON string and explicit content type
                                $null = Invoke-MgGraphRequest -Uri $logoUri -Method PATCH -Body $logoJson -ContentType "application/json"
                            }
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

                    # Call the content replacement function
                    Update-Win32LobContent -AppId $appID -SourceFile $script:SourceFile

                    Write-Log -Message "Content replacement completed for: $displayName"

                    # Ensure allowAvailableUninstall is set to true
                    Write-Log -Message "Ensuring allowAvailableUninstall is set to true..."
                    $uninstallBody = @{
                        "@odata.type"             = "#microsoft.graph.win32LobApp"
                        "allowAvailableUninstall" = $true
                    }
                    $appUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appID"
                    try {
                        if ($userName) {
                            # Using legacy auth token method
                            $uninstallJson = $uninstallBody | ConvertTo-Json -Depth 10
                            $clonedHeaders = Copy-Object $authToken
                            $clonedHeaders["content-length"] = $uninstallJson.Length
                            $clonedHeaders["content-type"] = "application/json"
                            $null = Invoke-RestMethod -Uri $appUri -Method Patch -Headers $clonedHeaders -Body $uninstallJson -UseBasicParsing
                        }
                        else {
                            # Using Invoke-MgGraphRequest with hashtable
                            $null = Invoke-MgGraphRequest -Uri $appUri -Method PATCH -Body $uninstallBody
                        }
                        Write-Log -Message "allowAvailableUninstall set to true successfully"
                        Write-Host "Allow available uninstall: Enabled" -ForegroundColor Green
                    }
                    catch {
                        Write-Log -Message "Warning: Failed to set allowAvailableUninstall - $_" -LogLevel 2
                        Write-Host "Warning: Failed to set allowAvailableUninstall - $_" -ForegroundColor Yellow
                    }

                    # Re-apply settings from config file (description, displayVersion, publisher)
                    Write-Log -Message "Re-applying settings from config file..."
                    Write-Host "Updating application properties from config..." -ForegroundColor Cyan

                    # Build minimum supported OS object from string for ReplaceExistingContent
                    $minOSObjectForReplace = $null
                    if (-not [string]::IsNullOrWhiteSpace($script:MinimumSupportedOS)) {
                        $minOSObjectForReplace = Get-MinimumOperatingSystemObject -OSVersionString $script:MinimumSupportedOS
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
                    if ($null -ne $minOSObjectForReplace) {
                        $settingsBody["minimumSupportedOperatingSystem"] = $minOSObjectForReplace
                    }

                    try {
                        # Convert to JSON explicitly with proper depth to ensure correct serialization (especially for largeIcon)
                        $settingsJson = $settingsBody | ConvertTo-Json -Depth 10 -Compress
                        if ($userName) {
                            $clonedHeaders = Copy-Object $authToken
                            $clonedHeaders["content-length"] = $settingsJson.Length
                            $clonedHeaders["content-type"] = "application/json"
                            $null = Invoke-RestMethod -Uri $appUri -Method Patch -Headers $clonedHeaders -Body $settingsJson -UseBasicParsing
                        }
                        else {
                            $null = Invoke-MgGraphRequest -Uri $appUri -Method PATCH -Body $settingsJson -ContentType "application/json"
                        }
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

                    # Apply category from config file
                    if (-not [string]::IsNullOrWhiteSpace($script:Category)) {
                        Write-Log -Message "Applying category from config: $($script:Category)"
                        $categoryResult = Set-IntuneAppCategory -ApplicationId $appID -CategoryName $script:Category
                    }

                    # Skip the normal upload process and group assignment when just replacing content
                    # Jump to scope tag handling if specified
                    $script:contentReplaced = $true
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
                    exit
                }
            }
            else {
                if ($ReplaceExistingContent) {
                    Write-Log -Message "Error: -ReplaceExistingContent specified but application not found: $displayName" -LogLevel 3
                    Write-Host
                    Write-Host "Error: Cannot replace content - application '$displayName' not found in Intune." -ForegroundColor Red
                    Write-Host "The application must already exist to use -ReplaceExistingContent." -ForegroundColor Yellow
                    Write-Host
                    exit
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
                    minimumSupportedOS        = $minOSObject
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
                    minimumSupportedOS        = $minOSObject
                    requirementRules          = $additionalRequirementRules
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
                    minimumSupportedOS        = $minOSObject
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
            if ($script:Dependencies) {
                Write-Log -Message "Processing dependencies..."
                Write-Host "Processing dependencies..." -ForegroundColor Cyan

                $dependencyList = @()
                if ($script:Dependencies -is [string]) {
                    # Parse comma-separated list from XML
                    $dependencyList = $script:Dependencies -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                }
                elseif ($script:Dependencies -is [array]) {
                    # Array from JSON
                    $dependencyList = $script:Dependencies
                }

                foreach ($depAppName in $dependencyList) {
                    if (-not [string]::IsNullOrWhiteSpace($depAppName)) {
                        Write-Log -Message "Adding dependency: $depAppName"
                        $result = Set-IntuneAppDependency -SourceAppId $appID -TargetAppDisplayName $depAppName -DependencyType $script:DependencyType
                        if ($result) {
                            Write-Host "  Dependency added: $depAppName ($($script:DependencyType))" -ForegroundColor Green
                        }
                        else {
                            Write-Host "  Failed to add dependency: $depAppName" -ForegroundColor Yellow
                        }
                    }
                }
            }

            # Process Supersedence
            if ($script:Supersedence) {
                Write-Log -Message "Processing supersedence..."
                Write-Host "Processing supersedence..." -ForegroundColor Cyan

                $supersedenceList = @()
                if ($script:Supersedence -is [string]) {
                    # Parse comma-separated list from XML
                    $supersedenceList = $script:Supersedence -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                }
                elseif ($script:Supersedence -is [array]) {
                    # Array from JSON
                    $supersedenceList = $script:Supersedence
                }

                foreach ($supersededAppName in $supersedenceList) {
                    if (-not [string]::IsNullOrWhiteSpace($supersededAppName)) {
                        Write-Log -Message "Adding supersedence: $supersededAppName"
                        $result = Set-IntuneAppSupersedence -SourceAppId $appID -TargetAppDisplayName $supersededAppName -SupersedenceType $script:SupersedenceType
                        if ($result) {
                            Write-Host "  Supersedence added: $supersededAppName ($($script:SupersedenceType))" -ForegroundColor Green
                        }
                        else {
                            Write-Host "  Failed to add supersedence: $supersededAppName" -ForegroundColor Yellow
                        }
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
                Write-Log -Message "Prepare Entra ID group for required assignment targeting: $RequiredAADGroupName"
                $script:groupsWereCreated = $false
                if ($userName) {
                    $script:exitCode = New-EntraGroup -groupName $RequiredAADGroupName
                }
                else {
                    $script:exitCode = New-EntraGroupMG -groupName $RequiredAADGroupName
                }

                if ($script:groupsWereCreated) {
                    Write-Host "Sleeping for $sleep seconds to allow Entra ID group creation..." -f Magenta
                    Start-Sleep $sleep
                    Write-Host
                }
                else {
                    Write-Host "Group already exists, skipping wait..." -f Green
                }

                #If ($script:exitCode -eq 0) {
                Write-Log -Message "Apply Entra ID group for required assignment targeting: $RequiredAADGroupName"

                Write-Log -Message "Find application ID"
                $appID = Get-ApplicationID -AppName $displayName

                Write-Log -Message "Reading group IDs"

                if ($userName) {
                    $installReqGroup = Get-GroupID -GroupName $RequiredAADGroupName
                }
                else {
                    $installReqGroup = Get-GroupIDMG -GroupName $RequiredAADGroupName
                }

                Write-Log -Message "Assigning groups to application..."
                $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installReqGroup -InstallIntent "required"
            }

            if ($AvailableAADGroupName) {
                Write-Log -Message "Prepare Entra ID group for available assignment targeting: $AvailableAADGroupName"
                $script:groupsWereCreated = $false
                if ($userName) {
                    $script:exitCode = New-EntraGroup -groupName $AvailableAADGroupName
                }
                else {
                    $script:exitCode = New-EntraGroupMG -groupName $AvailableAADGroupName
                }

                if ($script:groupsWereCreated) {
                    Write-Host "Sleeping for $sleep seconds to allow Entra ID group creation..." -f Magenta
                    Start-Sleep $sleep
                    Write-Host
                }
                else {
                    Write-Host "Group already exists, skipping wait..." -f Green
                }

                #If ($script:exitCode -eq 0) {
                Write-Log -Message "Apply Entra ID group for available assignment targeting: $AvailableAADGroupName"

                Write-Log -Message "Find application ID"
                $appID = Get-ApplicationID -AppName $displayName

                Write-Log -Message "Reading group IDs"

                if ($userName) {
                    $installAvailGroup = Get-GroupID -GroupName $AvailableAADGroupName
                }
                else {
                    $installAvailGroup = Get-GroupIDMG -GroupName $AvailableAADGroupName
                }

                Write-Log -Message "Assigning groups to application..."
                $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installAvailGroup -InstallIntent "available"
            }

            if ($UninstallAADGroupName) {
                Write-Log -Message "Prepare Entra ID group for uninstall assignment targeting: $UninstallAADGroupName"
                $script:groupsWereCreated = $false
                if ($userName) {
                    $script:exitCode = New-EntraGroup -groupName $UninstallAADGroupName
                }
                else {
                    $script:exitCode = New-EntraGroupMG -groupName $UninstallAADGroupName
                }

                if ($script:groupsWereCreated) {
                    Write-Host "Sleeping for $sleep seconds to allow Entra ID group creation..." -f Magenta
                    Start-Sleep $sleep
                    Write-Host
                }
                else {
                    Write-Host "Group already exists, skipping wait..." -f Green
                }

                #If ($script:exitCode -eq 0) {
                Write-Log -Message "Apply Entra ID group for uninstall assignment targeting: $UninstallAADGroupName"

                Write-Log -Message "Find application ID"
                $appID = Get-ApplicationID -AppName $displayName

                Write-Log -Message "Reading group IDs"

                if ($userName) {
                    $uninstallGroup = Get-GroupID -GroupName $UninstallAADGroupName
                }
                else {
                    $uninstallGroup = Get-GroupIDMG -GroupName $UninstallAADGroupName
                }

                Write-Log -Message "Assigning groups to application..."
                $null = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "uninstall"
            }


            if (-not($RequiredAADGroupName -or $AvailableAADGroupName -or $UninstallAADGroupName)) {
                Write-Log -Message "Create Entra ID groups for install/uninstall"
                $script:groupsWereCreated = $false
                if ($userName) {
                    $script:exitCode = New-EntraGroup -groupName $EntraGroupName
                }
                else {
                    $script:exitCode = New-EntraGroupMG -groupName $EntraGroupName
                }

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

                if ($userName) {
                    $installReqGroup = Get-GroupID -GroupName "$EntraGroupName-Required"
                }
                else {
                    $installReqGroup = Get-GroupIDMG -GroupName "$EntraGroupName-Required"
                }
                if ($userName) {
                    $installAvailGroup = Get-GroupID -GroupName "$EntraGroupName-Available"
                }
                else {
                    $installAvailGroup = Get-GroupIDMG -GroupName "$EntraGroupName-Available"
                }
                if ($userName) {
                    $uninstallGroup = Get-GroupID -GroupName "$EntraGroupName-UnInstall"
                }
                else {
                    $uninstallGroup = Get-GroupIDMG -GroupName "$EntraGroupName-UnInstall"
                }

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

        # Apply category to the application (for new uploads - not when content was replaced as that's handled separately)
        if ((-not($AssignGroupsOnly)) -and (-not($script:contentReplaced)) -and (-not [string]::IsNullOrWhiteSpace($script:Category))) {
            Write-Log -Message "Checking for category assignment..."
            if ($null -eq $appID) {
                Write-Log -Message "Getting application ID for category assignment..."
                $appID = Get-ApplicationID -AppName $displayName
            }
            if ($null -ne $appID) {
                $categoryResult = Set-IntuneAppCategory -ApplicationId $appID -CategoryName $script:Category
                if (-not $categoryResult) {
                    Write-Log -Message "Warning: Category assignment may have failed" -LogLevel 2
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
        $hasScopeTagSpecified = (-not [string]::IsNullOrWhiteSpace($ScopeTagName)) -or (-not [string]::IsNullOrWhiteSpace($script:ConfigScopeTag))
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
This function sets the scope tag on an Intune Win32 application
.DESCRIPTION
This function sets the scope tag on an Intune Win32 application. It replaces any existing
scope tags with the specified scope tag (including removing the Default scope tag).
.EXAMPLE
Set-IntuneAppScopeTag -ApplicationId "12345678-1234-1234-1234-123456789012" -ScopeTagId "1"
Sets the scope tag with ID 1 on the specified application.
.NOTES
NAME: Set-IntuneAppScopeTag
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
        [string]$ScopeTagId,

        [Parameter(Mandatory = $false)]
        [string]$ScopeTagName
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        Write-Log -Message "Setting scope tag on application ID: [$ApplicationId]"
        Write-Log -Message "Scope Tag ID: [$ScopeTagId]"

        $graphApiVersion = "beta"
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps/$ApplicationId"

        try {
            # The roleScopeTagIds property accepts an array of scope tag IDs as strings
            # Setting it to only our scope tag ID will replace all existing scope tags
            $body = @{
                '@odata.type'     = '#microsoft.graph.win32LobApp'
                'roleScopeTagIds' = @($ScopeTagId)
            }

            Write-Host "Applying scope tag '$ScopeTagName' (ID: $ScopeTagId) to application..." -ForegroundColor Cyan
            $null = Invoke-MgGraphRequest -Method Patch -Uri $uri -Body ($body | ConvertTo-Json -Depth 10)

            Write-Log -Message "Successfully applied scope tag to application"
            Write-Host "Successfully applied scope tag '$ScopeTagName' to application" -ForegroundColor Green

            return $true
        }
        catch {
            Write-Log -Message "Error setting scope tag on application: $($_.Exception.Message)" -LogLevel 3
            Write-Host "Error setting scope tag on application: $($_.Exception.Message)" -ForegroundColor Red

            # Check if it's a different app type (e.g., Edge)
            if ($_.Exception.Message -like "*does not match*" -or $_.Exception.Message -like "*invalid*") {
                Write-Host "Attempting to set scope tag without specifying app type..." -ForegroundColor Yellow
                try {
                    $body = @{
                        'roleScopeTagIds' = @($ScopeTagId)
                    }
                    $null = Invoke-MgGraphRequest -Method Patch -Uri $uri -Body ($body | ConvertTo-Json -Depth 10)
                    Write-Log -Message "Successfully applied scope tag to application (alternate method)"
                    Write-Host "Successfully applied scope tag '$ScopeTagName' to application" -ForegroundColor Green
                    return $true
                }
                catch {
                    Write-Log -Message "Error setting scope tag (alternate method): $($_.Exception.Message)" -LogLevel 3
                    Write-Host "Error setting scope tag (alternate method): $($_.Exception.Message)" -ForegroundColor Red
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
This function determines which scope tag to use (parameter vs config.xml), validates/creates
the scope tag, and applies it to the specified application.
.EXAMPLE
Invoke-ScopeTagAssignment -ApplicationId "12345678-1234-1234-1234-123456789012"
Applies the appropriate scope tag to the application based on parameter or config.xml.
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
        # Determine which scope tag to use
        $effectiveScopeTag = $null

        if (-not [string]::IsNullOrWhiteSpace($ScopeTagName)) {
            # Script parameter takes precedence
            $effectiveScopeTag = $ScopeTagName

            # Check if there's a different scope tag in config.xml and warn the user
            if (-not [string]::IsNullOrWhiteSpace($script:ConfigScopeTag) -and $script:ConfigScopeTag -ne $ScopeTagName) {
                Write-Host ""
                Write-Host "==========================================================================" -ForegroundColor Yellow
                Write-Host "NOTICE: Scope tag parameter precedence" -ForegroundColor Yellow
                Write-Host "==========================================================================" -ForegroundColor Yellow
                Write-Host "Config.xml defines scope tag: '$($script:ConfigScopeTag)'" -ForegroundColor Yellow
                Write-Host "Script parameter specifies:   '$ScopeTagName'" -ForegroundColor Yellow
                Write-Host "Using script parameter value: '$ScopeTagName' (parameter takes precedence)" -ForegroundColor Cyan
                Write-Host "==========================================================================" -ForegroundColor Yellow
                Write-Host ""
                Write-Log -Message "Scope tag from Config.xml ($($script:ConfigScopeTag)) is being overridden by script parameter ($ScopeTagName)"
            }
            else {
                Write-Host "Using scope tag from script parameter: '$ScopeTagName'" -ForegroundColor Cyan
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($script:ConfigScopeTag)) {
            # Use config.xml scope tag
            $effectiveScopeTag = $script:ConfigScopeTag
            Write-Host "Using scope tag from Config.xml: '$effectiveScopeTag'" -ForegroundColor Cyan
        }
        else {
            # No scope tag specified
            Write-Log -Message "No scope tag specified (neither parameter nor Config.xml). Skipping scope tag assignment."
            Write-Host "No scope tag specified. Application will retain default scope tag." -ForegroundColor Gray
            return $true
        }

        Write-Log -Message "Effective scope tag to apply: $effectiveScopeTag"

        try {
            # Get or create the scope tag
            $scopeTag = Get-IntuneScopeTag -ScopeTagName $effectiveScopeTag

            if ($null -eq $scopeTag -or [string]::IsNullOrWhiteSpace($scopeTag.id)) {
                Write-Log -Message "Failed to get or create scope tag: $effectiveScopeTag" -LogLevel 3
                Write-Host "Failed to get or create scope tag: $effectiveScopeTag" -ForegroundColor Red
                return $false
            }

            # Apply the scope tag to the application
            $result = Set-IntuneAppScopeTag -ApplicationId $ApplicationId -ScopeTagId $scopeTag.id -ScopeTagName $effectiveScopeTag

            if ($result) {
                Write-Host ""
                Write-Host "Scope tag '$effectiveScopeTag' successfully applied to application" -ForegroundColor Green
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
                    $groupBody = @{
                        'displayName'        = $group
                        'description'        = "Group for $group"
                        'mailNickname'       = ($($group).Replace(" ", "") + "-Group")
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

function New-EntraGroup {
    <#
.SYNOPSIS
This function creates the relevant install/uninstall Entra ID groups
.DESCRIPTION
This function creates the relevant install/uninstall Entra ID groups. Sets $script:groupsWereCreated
to indicate if any groups were newly created. Supports -WhatIf.
.EXAMPLE
New-EntraGroup -groupName "MyGroupName"
This function creates the relevant install/uninstall Entra ID groups
.NOTES
NAME: New-EntraGroup -groupName
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

        foreach ($group in $EntraGroups) {
            if (Get-AzureADGroup -SearchString $group) {
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
                try {
                    New-AzureADGroup -DisplayName $group -Description "Group for $group" -MailEnabled $false -SecurityEnabled $true -MailNickName ($($group).Replace(" ", "") + "-Group")
                    $script:groupsWereCreated = $true
                }
                catch {
                    Write-Log -Message "Error creating Entra ID group $group"
                    $script:exitCode = -1
                    exit
                }

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

function Get-GroupID {
    <#
.SYNOPSIS
This function is used to get an Entra ID group and return its object ID if found
        .DESCRIPTION
        The function is used to get an Entra ID group and return its object ID if found
.EXAMPLE
Get-GroupID -GroupName GroupNameHere
The function is used to get an Entra ID group and return its object ID if found
        .NOTES
        NAME: Get-GroupID
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
        $Group = Get-AzureADGroup -SearchString $GroupName

        if (Test-Null($Group)) {
            Write-Log -Message "Error - could not find group: $GroupName" -LogLevel 3
            $script:exitCode = -1
        }
        else {
            Write-Log -Message "Found group: `n$Group"
            $script:exitCode = 0
        }
    }

    end {
        if (!($script:exitCode -eq 0)) { return $script:exitCode }# Just return without doing anything else, error tripped
        $GroupID = $($Group).ObjectId
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
        #$filter = "DisplayName eq '"+$AppName+"'"
        #Write-Log -Message "Using filter: $filter"
        if ($userName) {
            $application = Get-IntuneApplication -Name $AppName
        }
        else {
            $application = Get-IntuneApplicationMG -DisplayName $AppName
        }

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

function Get-IntuneApplication() {

    <#
.SYNOPSIS
This function is used to get applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any applications added
.EXAMPLE
Get-IntuneApplication
Returns any applications configured in Intune
.NOTES
NAME: Get-IntuneApplication
#>

    [cmdletbinding()]

    param
    (
        $Name
    )

    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps"

    try {
        if ($userName) {
            if ($Name) {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") -and (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }

            }

            else {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }

            }
        }
        else {
            if ($Name) {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                (Invoke-MgGraphRequest -Uri "$uri" -Method GET).Value | Where-Object { ($_.'displayName').contains("$Name") -and (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }

                #$dcp = Invoke-MgGraphRequest -Uri "$uri" -Method GET

            }

            else {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                (Invoke-MgGraphRequest -Uri "$uri" -Method GET).Value | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }

            }
        }
    }

    catch {

        $ex = $_.Exception
        Write-Host "Request to $Uri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" -f Red
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
    Get-IntuneApplication
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

function Set-GroupMember {
    <#
.SYNOPSIS
This function is used to make an object a member of an Entra group
.DESCRIPTION
This function is used to make an object a member of an Entra group
.EXAMPLE
Set-GroupMember -AddToGroup GroupIDObject -MemberToAdd GroupIDObject
This function is used to make an object a member of an Entra group
.NOTES
NAME: Set-GroupMember
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$AddToGroup,

        [Parameter(Mandatory = $true)]
        [string]$MemberToAdd,

        [bool]$Skip = $false
    )

    begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    process {
        $MemberName = (Get-AzureADGroup -ObjectId $MemberToAdd).DisplayName
        $GroupName = (Get-AzureADGroup -ObjectId $AddToGroup).DisplayName
        Write-Log -Message "Adding $MemberName (member object: $MemberToAdd)"
        Write-Log -Message "To $GroupName (group object: $AddToGroup)"


        $ExistingGroupMembers = Get-AzureADGroupMember -ObjectId $AddToGroup
        #Write-Log -Message "Existing members: $ExistingGroupMembers"

        foreach ($member in $ExistingGroupMembers) {
            if ($($member).ObjectId -eq $MemberToAdd) {
                Write-Log -Message "Member: [$MemberToAdd] already exists, returning..."
                return $Skip = $true
            }
        }

        try {
            Write-Log -Message "Add member to group"
            Add-AzureADGroupMember -ObjectId $AddToGroup -RefObjectId $MemberToAdd | Out-Null
        }

        catch {
            Write-Log -Message "Error adding member to group" -LogLevel 3
        }

    }

    end {
        if ($Skip) { return }# Just return without doing anything else
        Write-Log -Message "Added member object: $MemberToAdd"
        Write-Log -Message "To group object: $AddToGroup"
        return
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

                $JSON += @"

    {
      "@odata.type": "#microsoft.graph.mobileAppAssignment",
      "target": {
        "@odata.type": "$existingODataType",
        "groupId": "$ExistingTargetGroupId"
      },
      "intent": "$ExistingInstallIntent"
"@

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

            if ($userName) {
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
            }
            else {
                Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
            }
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

            if ($userName) {
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
            }
            else {
                Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
            }
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
            if ($userName) {
                $response = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
            }
            else {
                $response = Invoke-MgGraphRequest -Uri $uri -Method Get
            }
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
            if ($userName) {
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
            }
            else {
                Invoke-MgGraphRequest -Uri $uri -Method Get
            }
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

        if ($userName) {
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
        }
        else {
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
        }

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

function Test-AuthToken() {


    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true,
            HelpMessage = 'Please specify your user principal name for Azure Authentication')]
        $User
    )

    # Checking if authToken exists before running authentication
    if ($global:authToken) {

        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if ($TokenExpires -le 0) {

            Write-Host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            Write-Host

            # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if ($null -eq $User -or $User -eq "") {

                $script:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                Write-Host

            }

            $global:authToken = Get-AuthToken -User $User
            $null = Remove-Module AzureAD -Force -ErrorAction SilentlyContinue | Out-Null
            Import-Module AzureADPreview -Force
            Connect-AzureAD -AccountId $Username

        }
    }

    # Authentication doesn't exist, calling Get-AuthToken function

    else {

        if ($null -eq $User -or $User -eq "") {

            $script:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

        }

        # Getting the authorization token
        $global:authToken = Get-AuthToken -User $User
        $null = Remove-Module AzureAD -Force -ErrorAction SilentlyContinue | Out-Null
        Import-Module AzureADPreview -Force
        Connect-AzureAD -AccountId $Username

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
Write-Host
Write-Host "Script log file path is [$logFile]" -f Cyan
Write-Host
Write-Log -Message "Starting $ScriptName version $BuildVer" -WriteEventLog

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

        $context = Get-MgContext
        if ($null -ne $context) {
            $currentScopes = $context.Scopes
            $missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
            if ($missingScopes.Count -gt 0) {
                Write-Host "Current session is missing required scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
                Write-Host "Disconnecting and reconnecting with required scopes..." -ForegroundColor Yellow
                Disconnect-MgGraph | Out-Null
                Connect-MgGraph -Scopes $requiredScopes -NoWelcome
            }
            else {
                Write-Host "Already connected with required scopes" -ForegroundColor Green
            }
        }
        else {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
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

        $connection = Invoke-RestMethod `
            -Uri https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token `
            -Method POST `
            -Body $body

        $token = $connection.access_token

        $global:authToken = @{
            'Content-Type'  = 'application/json'
            'Authorization' = "Bearer " + $connection.access_token
            'ExpiresOn'     = $connection.expires_in
        }

        $targetParameter = (Get-Command Connect-MgGraph).Parameters['AccessToken']
        if ($targetParameter.ParameterType -eq [securestring]) {
            Connect-MgGraph -AccessToken ($token | ConvertTo-SecureString -AsPlainText -Force) -NoWelcome
        }
        else {
            Connect-MgGraph -AccessToken $token -NoWelcome
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
            Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $myCert.Thumbprint -NoWelcome
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

#Validate targeting group names are different - Graph API fails to apply assignment if same group is used for multiple assignments!
if (-not(Test-Null($RequiredAADGroupName)) -and ($RequiredAADGroupName -eq $AvailableAADGroupName)) {
    Write-Log -Message "Error - RequiredAADGroupName must be different from AvailableAADGroupName!" -LogLevel 3
    return 1
}
if (-not(Test-Null($RequiredAADGroupName)) -and ($RequiredAADGroupName -eq $UninstallAADGroupName)) {
    Write-Log -Message "Error - RequiredAADGroupName must be different from UninstallAADGroupName!" -LogLevel 3
    return 1
}
if (-not(Test-Null($UninstallAADGroupName)) -and ($UninstallAADGroupName -eq $AvailableAADGroupName)) {
    Write-Log -Message "Error - UninstallAADGroupName must be different from AvailableAADGroupName!" -LogLevel 3
    return 1
}

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

if ($Username) {
    Write-Log -Message "Username: [$Username]"
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

<#
If (Test-Null($Username)) {
    Write-Log -Message "Username not found in XML file, prompt user to enter one..."
    $Username = Read-Host -Prompt "Please specify an Azure admin user name"
    Write-Log -Message "Admin user account: $Username"
}
#>

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
            "DeviceManagementConfiguration.Read.All"  # For reading scope tags
        )

        # Check if already connected and if current scopes are sufficient
        $context = Get-MgContext
        if ($null -ne $context) {
            $currentScopes = $context.Scopes
            $missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
            if ($missingScopes.Count -gt 0) {
                Write-Host "Current session is missing required scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
                Write-Host "Disconnecting and reconnecting with required scopes..." -ForegroundColor Yellow
                Disconnect-MgGraph | Out-Null
                Connect-MgGraph -Scopes $requiredScopes -NoWelcome
            }
            else {
                Write-Host "Already connected with required scopes" -ForegroundColor Green
            }
        }
        else {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        }
    }
    elseif ($userName) {
        Write-Log -Message "Authenticate to AzureAD..."
        Test-AuthToken -User $Username
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
            Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $myCert.Thumbprint ## Or -CertificateThumbprint instead of -CertificateName
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

        $connection = Invoke-RestMethod `
            -Uri https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token `
            -Method POST `
            -Body $body

        $token = $connection.access_token

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
            Connect-MgGraph -AccessToken ($token | ConvertTo-SecureString -AsPlainText -Force) -NoWelcome
        }
        else {
            Connect-MgGraph -AccessToken $token -NoWelcome
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
    # Determine which source folder to use - Source takes precedence, fall back to OrigSource
    $EffectiveSourcePath = $SourcePath
    if (!(Test-Path $SourcePath)) {
        if (Test-Path $OrigSourcePath) {
            Write-Log -Message "Source folder not found at: [$SourcePath]"
            Write-Log -Message "Using OrigSource folder instead: [$OrigSourcePath]"
            Write-Host "Source folder not found, using OrigSource folder instead..." -ForegroundColor Yellow
            $EffectiveSourcePath = $OrigSourcePath
        }
        else {
            Write-Log -Message "Error - Neither Source nor OrigSource folder found" -LogLevel 3
            Write-Host "Error: Neither Source nor OrigSource folder found at:" -ForegroundColor Red
            Write-Host "  Source: $SourcePath" -ForegroundColor Red
            Write-Host "  OrigSource: $OrigSourcePath" -ForegroundColor Red
            exit
        }
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
elseif (-not($Username)) {
    # For other auth methods (ClientSecret, CertName), always disconnect
    Invoke-Cleanup -ForceDisconnect
}
return $script:exitCode

##########################################################################################################
##########################################################################################################
#endregion Main Script work section

