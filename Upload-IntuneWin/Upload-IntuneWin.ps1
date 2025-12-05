#Requires -Module Microsoft.Graph.Authentication
#region Initialisation...
<#

.SYNOPSIS
    Creates and uploads Win32 application packages to Microsoft Intune.

.DESCRIPTION
    This script automates the creation and upload of Win32 application packages (.intunewin) to Microsoft Intune.
    It supports MSI, EXE, PS1, and Edge application types with configurable detection rules, return codes,
    and AAD group assignments.

    The script reads configuration from a Config.xml file in the package folder and can authenticate using
    interactive login, certificate-based authentication, or client secret.

    Key features:
    - Creates .intunewin packages using IntuneWinAppUtil.exe
    - Uploads packages to Intune via Microsoft Graph API
    - Creates and assigns AAD groups for Required, Available, and Uninstall targeting
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
    Specifies an AAD group name for required assignment targeting.
    If the group doesn't exist, it will be created.

.PARAMETER AvailableAADGroupName
    Specifies an AAD group name for available assignment targeting.
    If the group doesn't exist, it will be created.

.PARAMETER UninstallAADGroupName
    Specifies an AAD group name for uninstall assignment targeting.
    If the group doesn't exist, it will be created.

.PARAMETER NewTagPath
    Switch parameter that changes the tagfile path to %PROGRAMDATA%\IntuneManagementExtension\Logs.
    This ensures logs are captured during an Intune diagnostic log capture.

.PARAMETER ScopeTagName
    Specifies the Intune scope tag name to apply to the uploaded application.
    This parameter takes precedence over the ScopeTag attribute in Config.xml.
    If the scope tag doesn't exist in the tenant, it will be created automatically.
    The scope tag replaces any existing scope tags on the application (including the Default scope tag).

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

    Uploads a package and assigns specific AAD groups for required and available targeting.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -ScopeTagName "CloudPC-Apps"

    Uploads a package and applies the "CloudPC-Apps" scope tag. If the scope tag doesn't exist, it will be created.

.EXAMPLE
    .\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -SkipGroupAssignment -ScopeTagName "Production"

    Uploads a package without group assignments but applies the "Production" scope tag.

.NOTES
    File Name      : Upload-IntuneWin.ps1
    Prerequisite   : Microsoft.Graph.Authentication module
                     IntuneWinAppUtil.exe (Microsoft Win32 Content Prep Tool)

    The Config.xml file supports the following attributes in the IntuneWin_Settings section:
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
[CmdLetBinding()]
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

    [Parameter(Mandatory = $true, Position = 3, ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $True,
        HelpMessage = 'Please enter path to package folder, containing Config.xml file'
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

    [Parameter(HelpMessage = 'Applies an AAD group with required assignment targeting'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $RequiredAADGroupName,

    [Parameter(HelpMessage = 'Applies an AAD group with available assignment targeting'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $AvailableAADGroupName,

    [Parameter(HelpMessage = 'Applies an AAD group with uninstall assignment targeting'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $UninstallAADGroupName,

    [Parameter(HelpMessage = 'Changes the tagfile path to %PROGRAMDATA%\IntuneManagementExtension\Logs - this is so that the logs are captured during an Intune diagnostic log capture'
    )]
    [switch] $NewTagPath,

    [Parameter(HelpMessage = 'Specifies the Intune scope tag name to apply to the uploaded application. Takes precedence over ScopeTag in Config.xml. If the scope tag does not exist, it will be created.'
    )]
    [string] $ScopeTagName
)
$script:exitCode = 0

$BuildVer = "1.2"
$ProgramFiles = $env:ProgramFiles
$ScriptName = $myInvocation.MyCommand.Name
$ScriptName = $ScriptName.Substring(0, $ScriptName.Length - 4)
$LogName = $ScriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
$logPath = "$($env:LocalAppData)\Microsoft\IntuneApps\$ScriptName"
$logFile = "$logPath\$LogName.log"
Add-Type -AssemblyName Microsoft.VisualBasic
$script:EventLogName = "Application"
$script:EventLogSource = "EventSystem"
$packagePath = $packagePath.Trim()
$SourcePath = "$packagePath\Source"

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
            break

        }

    }

    catch {

        Write-Host $_.Exception.Message -f Red
        Write-Host $_.Exception.ItemName -f Red
        Write-Host
        break

    }

}

####################################################

function CloneObject($object) {

    $stream = New-Object IO.MemoryStream;
    $formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter;
    $formatter.Serialize($stream, $object);
    $stream.Position = 0;
    $formatter.Deserialize($stream);
}

####################################################

function WriteHeaders($authToken) {

    foreach ($header in $authToken.GetEnumerator()) {
        if ($header.Name.ToLower() -eq "authorization") {
            continue;
        }

        Write-Host -ForegroundColor Gray "$($header.Name): $($header.Value)";
    }
}

####################################################

function MakeGetRequest($collectionPath) {

    Write-Host "Running MakeGetRequest: $collectionPath" -ForegroundColor Green
    Write-Host "Running MakeGetRequest baseURL: $baseUrl" -ForegroundColor Green
    Write-Host


    $uri = "$baseUrl$collectionPath";
    $request = "GET $uri";

    if ($userName) {
        if ($logRequestUris) { Write-Host $request; }
        if ($logHeaders) { WriteHeaders $authToken; }
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

function MakePatchRequest($collectionPath, $body) {

    MakeRequest "PATCH" $collectionPath $body;

}

####################################################

function MakePostRequest($collectionPath, $body) {

    MakeRequest "POST" $collectionPath $body;

}

####################################################

function MakeRequest($verb, $collectionPath, $body) {

    Write-Host "Running MakeRequest" -ForegroundColor Green

    $uri = "$baseUrl$collectionPath";
    $request = "$verb $uri";

    <#
    If ($authToken) {
        Write-Host "authToken: $authToken"
    }
    Else { Throw "No authToken" }
    #$authToken | Format-List *

    $clonedHeaders = CloneObject $authToken;
    #$clonedHeaders | Format-List *
    $clonedHeaders["content-length"] = $body.Length;
    Write-Host "After clonedHeaders length" -ForegroundColor Yellow
    $clonedHeaders["content-type"] = "application/json";

    if ($logRequestUris) { Write-Host $request; }
    if ($logHeaders) { WriteHeaders $clonedHeaders; }
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

        $clonedHeaders = CloneObject $authToken;
        #Write-Host "clonedHeaders: $clonedHeaders" -ForegroundColor Green
        #$clonedHeaders | Format-List *

        $clonedHeaders["content-length"] = $body.Length;
        $clonedHeaders["content-type"] = "application/json";

        Write-Host $request
        WriteHeaders $clonedHeaders
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

function UploadAzureStorageChunk($sasUri, $id, $body) {

    $uri = "$sasUri&comp=block&blockid=$id";
    $request = "PUT $uri";

    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
    };

    if ($logRequestUris) { Write-Host $request; }
    if ($logHeaders) { WriteHeaders $headers; }

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

function FinalizeAzureStorageUpload($sasUri, $ids) {

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

function UploadFileToAzureStorage($sasUri, $filepath, $fileUri) {

    try {

        $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb;

        # Start the timer for SAS URI renewal.
        $sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()

        # Find the file size and open the file.
        $fileSize = (Get-Item $filepath).length;
        $chunks = [Math]::Ceiling($fileSize / $chunkSizeInBytes);
        $reader = New-Object System.IO.BinaryReader([System.IO.File]::Open($filepath, [System.IO.FileMode]::Open));
        $position = $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin);

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

            $uploadResponse = UploadAzureStorageChunk $sasUri $id $bytes;

            # Renew the SAS URI if 7 minutes have elapsed since the upload started or was renewed last.
            if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000) {

                $renewalResponse = RenewAzureStorageUpload $fileUri;
                $sasRenewalTimer.Restart();

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
    $uploadResponse = FinalizeAzureStorageUpload $sasUri $ids;
    Write-Host -ForegroundColor Green "Finalize completed successfully!"

}

####################################################

function RenewAzureStorageUpload($fileUri) {

    $renewalUri = "$fileUri/renewUpload";
    $actionBody = "";
    $rewnewUriResult = MakePostRequest $renewalUri $actionBody;

    $file = WaitForFileProcessing $fileUri "AzureStorageUriRenewal" $azureStorageRenewSasUriBackOffTimeInSeconds;

}

####################################################

function WaitForFileProcessing($fileUri, $stage) {

    Write-Host "WaitForFileProcessing: $fileUri" -ForegroundColor Cyan
    $attempts = 600;
    $waitTimeInSeconds = 10;

    $successState = "$($stage)Success";
    $pendingState = "$($stage)Pending";
    $failedState = "$($stage)Failed";
    $timedOutState = "$($stage)TimedOut";

    $file = $null;
    while ($attempts -gt 0) {
        $file = MakeGetRequest $fileUri;

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

function GetWin32AppBody() {

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

        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        #[parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
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
        [string] $channel

    )

    if ($MSI) {

        $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" };
        $body.applicableArchitectures = "x64,x86";
        $body.description = $description;
        $body.developer = "";
        $body.displayName = $displayName;
        $body.displayVersion = $displayVersion;
        $body.fileName = $filename;
        if ( ! ( Test-Null ( $msiInstallCommandLine ) ) ) {
            $body.installCommandLine = "msiexec /i `"$SetupFileName`" $msiInstallCommandLine"
        }
        else {
            $body.installCommandLine = "msiexec /i `"$SetupFileName`""
        }
        $body.installExperience = @{"runAsAccount" = "$installExperience" };
        $body.informationUrl = $null;
        $body.isFeatured = $false;
        $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true };
        $body.msiInformation = @{
            "packageType"    = "$MsiPackageType";
            "productCode"    = "$MsiProductCode";
            "productName"    = "$MsiProductName";
            "productVersion" = "$MsiProductVersion";
            "publisher"      = "$MsiPublisher";
            "requiresReboot" = "$MsiRequiresReboot";
            "upgradeCode"    = "$MsiUpgradeCode"
        };
        $body.notes = "";
        $body.owner = "";
        $body.privacyInformationUrl = $null;
        $body.publisher = $publisher;
        $body.runAs32bit = $false;
        $body.setupFilePath = $SetupFileName;
        if ( ! ( Test-Null ( $msiUninstallCommandLine ) ) ) {
            $body.uninstallCommandLine = "msiexec /x `"$MsiProductCode`""
        }
        else {
            $body.uninstallCommandLine = "msiexec /x `"$MsiProductCode`" $msiUninstallCommandLine"
        }
        $body.largeIcon = @{"type" = "image/png"; "value" = $logo }

    }

    elseif ($EXE) {
        #"deviceRestartBehavior": "basedOnReturnCode" = Determine behavior based on return codes
        #"deviceRestartBehavior": "suppress" = No specific action
        #"deviceRestartBehavior": "allow" = App install may force a device restart
        #"deviceRestartBehavior": "force" = Intune will force a mandatory device restart

        $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" };
        $body.description = $description;
        $body.developer = "";
        $body.displayName = $displayName;
        $body.displayVersion = $displayVersion;
        $body.fileName = $filename;
        $body.installCommandLine = "$installCommandLine"
        $body.installExperience = @{"runAsAccount" = "$installExperience"; "deviceRestartBehavior" = "suppress" };
        $body.informationUrl = $null;
        $body.isFeatured = $false;
        $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true };
        $body.msiInformation = $null;
        $body.notes = "";
        $body.owner = "";
        $body.privacyInformationUrl = $null;
        $body.publisher = $publisher;
        $body.runAs32bit = $false;
        $body.setupFilePath = $SetupFileName;
        $body.uninstallCommandLine = "$uninstallCommandLine";
        $body.largeIcon = @{"type" = "image/png"; "value" = $logo }

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

function GetAppFileBody($name, $size, $sizeEncrypted, $manifest) {

    $body = @{ "@odata.type" = "#microsoft.graph.mobileAppContentFile" };
    $body.name = $name;
    $body.size = $size;
    $body.sizeEncrypted = $sizeEncrypted;
    $body.manifest = $manifest;
    $body.isDependency = $false;

    $body;
}

####################################################

function GetAppCommitBody($contentVersionId, $LobType) {

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
            throw

        }

    }

    catch {

        Write-Host -ForegroundColor Red $_.Exception.Message;
        Write-Host
        break

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
            break

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

function Upload-Win32Lob() {

    <#
.SYNOPSIS
This function is used to upload a Win32 Application to the Intune Service
.DESCRIPTION
This function is used to upload a Win32 Application to the Intune Service
.EXAMPLE
Upload-Win32Lob "C:\Packages\package.intunewin" -publisher "Microsoft" -description "Package"
This example uses all parameters required to add an intunewin File into the Intune Service
.NOTES
NAME: Upload-Win32LOB
#>

    [cmdletbinding()]

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

        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 7)]
        [parameter(Mandatory = $true, ParameterSetName = "EXE", Position = 7)]
        [parameter(Mandatory = $true, ParameterSetName = "PS1", Position = 7)]
        #[parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNullOrEmpty()]
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
        [string] $channel
    )

    try	{

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
                $mobileAppBody = GetWin32AppBody `
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
                    -msiUninstallCommandLine $msiUninstallCommandLine
            }
            else {
                $mobileAppBody = GetWin32AppBody `
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
                    -logo $logo
            }
        }

        if ($EXE) {
            $mobileAppBody = GetWin32AppBody -EXE -displayName "$DisplayName" -displayVersion "$DisplayVersion" -publisher "$publisher" `
                -description $description -category $Category -filename $FileName -SetupFileName "$SetupFileName" `
                -installExperience $installExperience -logo $logo `
                -installCommandLine $installCommandLine -uninstallCommandLine $uninstallCommandLine
        }
        elseif ($PS1) {
            $mobileAppBody = GetWin32AppBody -EXE -displayName "$DisplayName" -displayVersion "$DisplayVersion" -publisher "$publisher" `
                -description $description -category $Category -filename $FileName -SetupFileName "$SetupFileName" `
                -installExperience $installExperience -logo $logo `
                -installCommandLine $ps1InstallCommandLine -uninstallCommandLine $ps1UninstallCommandLine
        }
        elseif ($Edge) {
            Write-Host
            Write-Host "Creating Edge ODATA construct" -ForegroundColor Yellow

            #$Publisher = 'Microsoft'
            #$Description = 'Microsoft Edge is the browser for business with modern and legacy web compatibility, new privacy features such as Tracking prevention, and built-in productivity tools such as enterprise-grade PDF support and access to Office and corporate search right from a new tab.'
            #$displayName = 'Microsoft Edge Stable1'
            #$channel = 'stable'

            $mobileAppBody = GetWin32AppBody -Edge -displayName "$DisplayName" -publisher "$publisher" `
                -description $description -channel $channel

            Write-Host
            Write-Host "Creating application in Intune..." -ForegroundColor Yellow
            $mobileApp = MakePostRequest "mobileApps" ($mobileAppBody | ConvertTo-Json)

            return
        }


        if ($detectionRules.'@odata.type' -contains "#microsoft.graph.win32LobAppPowerShellScriptDetection" -and @($detectionRules).'@odata.type'.Count -gt 1) {

            Write-Host
            Write-Warning "A Detection Rule can either be 'Manually configure detection rules' or 'Use a custom detection script'"
            Write-Warning "It can't include both..."
            Write-Host
            break

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
            break

        }

        Write-Host
        Write-Host "Creating application in Intune..." -ForegroundColor Yellow
        $mobileApp = MakePostRequest "mobileApps" ($mobileAppBody | ConvertTo-Json);

        # Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Host
        Write-Host "Creating Content Version in the service for the application..." -ForegroundColor Yellow
        $appId = $mobileApp.id;
        $contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions";
        $contentVersion = MakePostRequest $contentVersionUri "{}";

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
        $fileBody = GetAppFileBody "$FileName" $Size $EncrySize $null;
        $filesUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files";
        $file = MakePostRequest $filesUri ($fileBody | ConvertTo-Json);

        # Wait for the service to process the new file request.
        Write-Host
        Write-Host "Waiting for the file entry URI to be created..." -ForegroundColor Yellow
        $fileId = $file.id;
        $fileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId";
        $file = WaitForFileProcessing $fileUri "azureStorageUriRequest";

        # Upload the content to Azure Storage.
        Write-Host
        Write-Host "Uploading file to Azure Storage..." -f Yellow

        #$sasUri = $file.azureStorageUri;
        UploadFileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri;

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
        MakePostRequest $commitFileUri ($fileEncryptionInfo | ConvertTo-Json);

        # Wait for the service to process the commit file request.
        Write-Host
        Write-Host "Waiting for the service to process the commit file request..." -ForegroundColor Yellow
        $file = WaitForFileProcessing $fileUri "CommitFile";

        # Commit the app.
        Write-Host
        Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
        $commitAppUri = "mobileApps/$appId";
        $commitAppBody = GetAppCommitBody $contentVersionId $LOBType;
        MakePatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json);

        Write-Host "Sleeping for $sleep seconds to allow package upload completion..." -f Magenta
        Start-Sleep $sleep
        Write-Host

    }

    catch {
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
        $dayDateTime = (Get-Date -UFormat "%A %d-%m-%Y %R")
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
            if ($script:AADGroupName.Length -gt 50) {
                Write-Log -Message "Error - AAD group name longer than 50 chars. Shorten then retry."
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
                $script:Description = [string]$XMLEntity.Description + "`nObject creation: $dayDateTime"
                $script:Publisher = [string]$XMLEntity.Publisher
                $script:Channel = [string]$XMLEntity.Channel
                $script:AADGroupName = [string]$XMLEntity.AADGroupName
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
            $script:Description = [string]$XMLEntity.Description + "`nObject creation: $dayDateTime"
            $script:Publisher = [string]$XMLEntity.Publisher
            $script:Category = [string]$XMLEntity.Category
            $script:LogoFile = [string]$XMLEntity.LogoFile
            $script:AADGroupName = [string]$XMLEntity.AADGroupName

            # Read optional ScopeTag from Config.xml
            $script:ConfigScopeTag = [string]$XMLEntity.ScopeTag
            if (-not [string]::IsNullOrWhiteSpace($script:ConfigScopeTag)) {
                Write-Log -Message "Found ScopeTag in Config.xml: $($script:ConfigScopeTag)"
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
        [string]$AADGroupName
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
            Write-Log -Message "AADGroupName: [$AADGroupName]"

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

                $Icon = New-IntuneWin32AppIcon -FilePath "$packagePath\$LogoFile"

            }

            #If ($AppType -eq "Edge") {
            #    $displayName = 'Microsoft Edge Stable1'
            #}
            Write-Log -Message "Find application ID"
            $appID = Get-ApplicationID -AppName $displayName

            #Check if package already exists
            if ( ! ( Test-Null ( $appID ) ) ) {
                Write-Log -Message "Detected existing package in Intune: $displayName"
                Write-Log -Message "Manual upload of the new IntuneWin package required."
                Write-Log -Message "Upload content: "
                Write-Host
                Write-Host "$script:SourceFile" -ForegroundColor Cyan
                Write-Host
                Write-Host
                exit
            }
            else {
                Write-Log -Message "Existing package not found"
            }

            # Win32 Application Upload
            if ($AppType -eq "MSI") {
                Write-Log -Message "Preparing MSI package"

                if ( ( ! ( Test-Null( $installCmdLine) ) ) -and ( ! ( Test-Null( $uninstallCmdLine ) ) ) ) {
                    Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                        -returnCodes $ReturnCodes -displayName $displayName -msiInstallCommandLine $installCmdLine -msiUninstallCommandLine $uninstallCmdLine -installExperience $installExperience -logo $Icon -Category $Category
                }
                elseif ( ( ! ( Test-Null( $installCmdLine ) ) ) -and ( Test-Null( $uninstallCmdLine ) ) ) {
                    Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                        -returnCodes $ReturnCodes -displayName $displayName -msiInstallCommandLine $installCmdLine -installExperience $installExperience -logo $Icon -Category $Category
                }
                elseif ( ( Test-Null( $installCmdLine ) ) -and ( ! ( Test-Null( $uninstallCmdLine ) ) ) ) {
                    Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                        -returnCodes $ReturnCodes -displayName $displayName -msiUninstallCommandLine $uninstallCmdLine -installExperience $installExperience -logo $Icon -Category $Category
                }
                elseif ( ( Test-Null( $installCmdLine ) ) -and ( Test-Null( $uninstallCmdLine ) ) ) {
                    Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                        -returnCodes $ReturnCodes -displayName $displayName -installExperience $installExperience -logo $Icon -Category $Category
                }
            }
            elseif ($AppType -eq "EXE") {
                Write-Log -Message "Preparing EXE package"
                Upload-Win32Lob -EXE -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -installCommandLine $installCmdLine -uninstallCommandLine $uninstallCmdLine -installExperience $installExperience -logo $Icon -Category $Category
            }
            elseif ($AppType -eq "PS1") {
                Write-Log -Message "Preparing PS1 package"
                Upload-Win32Lob -PS1 -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -ps1InstallCommandLine $InstallCmdLine -ps1UninstallCommandLine $UninstallCmdLine -installExperience $installExperience -logo $Icon -Category $Category
            }
            elseif ($AppType -eq "Edge") {
                Write-Log -Message "Preparing Edge package"
                #$Publisher = 'Microsoft'
                #$Description = 'Microsoft Edge is the browser for business with modern and legacy web compatibility, new privacy features such as Tracking prevention, and built-in productivity tools such as enterprise-grade PDF support and access to Office and corporate search right from a new tab.'
                #$displayName = 'Microsoft Edge Stable1'
                #$channel = 'stable'

                Upload-Win32Lob -Edge -publisher "$Publisher" -description "$Description" `
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

        if (-not($SkipGroupAssignment)) {

            if ($RequiredAADGroupName) {
                Write-Log -Message "Prepare AAD group for required assignment targeting: $RequiredAADGroupName"
                $script:groupsWereCreated = $false
                if ($userName) {
                    $script:exitCode = New-AADGroup -groupName $RequiredAADGroupName
                }
                else {
                    $script:exitCode = New-AADGroupMG -groupName $RequiredAADGroupName
                }

                if ($script:groupsWereCreated) {
                    Write-Host "Sleeping for $sleep seconds to allow AAD group creation..." -f Magenta
                    Start-Sleep $sleep
                    Write-Host
                }
                else {
                    Write-Host "Group already exists, skipping wait..." -f Green
                }

                #If ($script:exitCode -eq 0) {
                Write-Log -Message "Apply AAD group for required assignment targeting: $RequiredAADGroupName"

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
                $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installReqGroup -InstallIntent "required"
            }

            if ($AvailableAADGroupName) {
                Write-Log -Message "Prepare AAD group for available assignment targeting: $AvailableAADGroupName"
                $script:groupsWereCreated = $false
                if ($userName) {
                    $script:exitCode = New-AADGroup -groupName $AvailableAADGroupName
                }
                else {
                    $script:exitCode = New-AADGroupMG -groupName $AvailableAADGroupName
                }

                if ($script:groupsWereCreated) {
                    Write-Host "Sleeping for $sleep seconds to allow AAD group creation..." -f Magenta
                    Start-Sleep $sleep
                    Write-Host
                }
                else {
                    Write-Host "Group already exists, skipping wait..." -f Green
                }

                #If ($script:exitCode -eq 0) {
                Write-Log -Message "Apply AAD group for required assignment targeting: $AvailableAADGroupName"

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
                $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installAvailGroup -InstallIntent "available"
            }

            if ($UninstallAADGroupName) {
                Write-Log -Message "Prepare AAD group for uninstall assignment targeting: $UninstallAADGroupName"
                $script:groupsWereCreated = $false
                if ($userName) {
                    $script:exitCode = New-AADGroup -groupName $UninstallAADGroupName
                }
                else {
                    $script:exitCode = New-AADGroupMG -groupName $UninstallAADGroupName
                }

                if ($script:groupsWereCreated) {
                    Write-Host "Sleeping for $sleep seconds to allow AAD group creation..." -f Magenta
                    Start-Sleep $sleep
                    Write-Host
                }
                else {
                    Write-Host "Group already exists, skipping wait..." -f Green
                }

                #If ($script:exitCode -eq 0) {
                Write-Log -Message "Apply AAD group for required assignment targeting: $UninstallAADGroupName"

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
                $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "uninstall"
            }


            if (-not($RequiredAADGroupName -or $AvailableAADGroupName -or $UninstallAADGroupName)) {
                Write-Log -Message "Create AAD groups for install/uninstall"
                $script:groupsWereCreated = $false
                if ($userName) {
                    $script:exitCode = New-AADGroup -groupName $AADGroupName
                }
                else {
                    $script:exitCode = New-AADGroupMG -groupName $AADGroupName
                }

                if ($script:groupsWereCreated) {
                    Write-Host "Sleeping for $sleep seconds to allow AAD group creation..." -f Magenta
                    Start-Sleep $sleep
                    Write-Host
                }
                else {
                    Write-Host "All groups already exist, skipping wait..." -f Green
                }

                #If ($script:exitCode -eq 0) {
                Write-Log -Message "Assigning AAD groups for install/uninstall"

                Write-Log -Message "Find application ID"
                $appID = Get-ApplicationID -AppName $displayName

                Write-Log -Message "Reading group IDs"

                if ($userName) {
                    $installReqGroup = Get-GroupID -GroupName "$AADGroupName-Required"
                }
                else {
                    $installReqGroup = Get-GroupIDMG -GroupName "$AADGroupName-Required"
                }
                if ($userName) {
                    $installAvailGroup = Get-GroupID -GroupName "$AADGroupName-Available"
                }
                else {
                    $installAvailGroup = Get-GroupIDMG -GroupName "$AADGroupName-Available"
                }
                if ($userName) {
                    $uninstallGroup = Get-GroupID -GroupName "$AADGroupName-UnInstall"
                }
                else {
                    $uninstallGroup = Get-GroupIDMG -GroupName "$AADGroupName-UnInstall"
                }

                Write-Log -Message "Assigning groups to application..."
                $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installReqGroup -InstallIntent "required"
                $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installAvailGroup -InstallIntent "available"
                $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "uninstall"
                $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "required" -exclude
                $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "available" -exclude
            }

            #}
        }
        else {
            Write-Log -Message "Skipping assignment groups"
        }

        # Apply scope tag to the application (after group assignments are complete)
        if (-not($AssignGroupsOnly)) {
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

function New-AADGroupMG {
    <#
.SYNOPSIS
This function creates the relevant install/uninstall AAD groups
.DESCRIPTION
This function creates the relevant install/uninstall AAD groups. Returns a hashtable with
'ExitCode' and 'GroupsCreated' properties to indicate if any groups were newly created.
.EXAMPLE
$result = New-AADGroupMG -groupName "MyGroupName"
This function creates the relevant install/uninstall AAD groups
.NOTES
NAME: New-AADGroupMG -groupName
#>

    [cmdletbinding()]

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

        $AADGroups = $groupName
        if (-not($RequiredAADGroupName -or $AvailableAADGroupName -or $UninstallAADGroupName)) {
            $AADGroups = @("$groupName-Required", "$groupName-Available", "$groupName-Uninstall")
        }

        $graphApiVersion = "v1.0"
        foreach ($group in $AADGroups) {
            # Check if group exists using REST API
            $uri = "https://graph.microsoft.com/$graphApiVersion/groups?`$filter=displayName eq '$group'"
            try {
                $existingGroup = Invoke-MgGraphRequest -Method Get -Uri $uri
                if ($existingGroup.value.Count -gt 0) {
                    Write-Log -Message "AAD group $group already exists!"
                }
                else {
                    Write-Log -Message "Creating AAD group $group"
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
                    Write-Log -Message "Successfully created AAD group $group"
                    $script:groupsWereCreated = $true
                }
            }
            catch {
                Write-Log -Message "Error with AAD group $group : $($_.Exception.Message)"
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

function New-AADGroup {
    <#
.SYNOPSIS
This function creates the relevant install/uninstall AAD groups
.DESCRIPTION
This function creates the relevant install/uninstall AAD groups. Sets $script:groupsWereCreated
to indicate if any groups were newly created.
.EXAMPLE
New-AADGroup -groupName "MyGroupName"
This function creates the relevant install/uninstall AAD groups
.NOTES
NAME: New-AADGroup -groupName
#>

    [cmdletbinding()]

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

        $AADGroups = $groupName
        if (-not($RequiredAADGroupName -or $AvailableAADGroupName -or $UninstallAADGroupName)) {
            $AADGroups = @("$groupName-Required", "$groupName-Available", "$groupName-Uninstall")
        }

        foreach ($group in $AADGroups) {
            if (Get-AzureADGroup -SearchString $group) {
                Write-Log -Message "AAD group $group already exists!"
            }
            else {
                Write-Log -Message "Creating AAD group $group"
                try {
                    New-AzureADGroup -DisplayName $group -Description "Group for $group" -MailEnabled $false -SecurityEnabled $true -MailNickName ($($group).Replace(" ", "") + "-Group")
                    $script:groupsWereCreated = $true
                }
                catch {
                    Write-Log -Message "Error creating AAD group $group"
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
This function is used to get an AAD group and return it's object ID if found
        .DESCRIPTION
        The function is used to get an AAD group and return it's object ID if found
.EXAMPLE
Get-GroupID -GroupName GroupNameHere
The function is used to get an AAD group and return it's object ID if found
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
This function is used to get an AAD group and return it's object ID if found
        .DESCRIPTION
        The function is used to get an AAD group and return it's object ID if found
.EXAMPLE
Get-GroupID -GroupName GroupNameHere
The function is used to get an AAD group and return it's object ID if found
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
        break

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
This function is used to make an object a member of an AAD group
.DESCRIPTION
This function is used to make an object a member of an AAD group
.EXAMPLE
Set-GroupMember -AddToGroup GroupIDObject -MemberToAdd GroupIDObject
This function is used to make an object a member of an AAD group
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
The function connects to the Graph API Interface and adds a application assignment
.EXAMPLE
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignment
#>

    [cmdletbinding()]

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

            Write-Log -Message "No Application Id specified, specify a valid Application Id"
            break

        }

        if (!$TargetGroupId) {

            Write-Log -Message "No Target Group Id specified, specify a valid Target Group Id"
            break

        }


        if (!$InstallIntent) {

            Write-Log -Message "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment"
            break

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

            #   Write-Log -Message "'$AADGroup' is already targetted to this application, can't add an AAD Group already assigned..."

            #}

            #else {

            if ( ! ( $exclude ) ) {
                # Creating header of JSON File
                Write-Log -Message "Creating header of JSON File for include"
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
        "notifications": "hideAll",
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
      "intent": "$InstallIntent",
      "settings": {
        "@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
        "notifications": "hideAll",
        "installTimeSettings": {
          "useLocalTime": false,
          "deadlineDateTime": null
        },
        "deliveryOptimizationPriority": "foreground"
      }
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

            if ( ! ( $exclude ) ) {
                # Creating header of JSON File
                Write-Log -Message "Creating header of JSON File for include with no additional assignments"
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
          "notifications": "hideAll",
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
        "intent": "$InstallIntent",
        "settings": {
          "@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
          "notifications": "hideAll",
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

    Write-Host "Sleeping for $sleep seconds to allow AAD group assignment..." -f Magenta
    Start-Sleep $sleep
    Write-Host
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
            break

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
        break

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
    [CmdletBinding(SupportsShouldProcess = $true)]
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
    $null = Disconnect-MgGraph | Out-Null
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

#Check package path is valid
if ( ! ( Test-Path $packagePath ) ) {
    Write-Log -Message "Error - path not valid: $packagePath"
    break
}

#Validate targeting group names are different - Graph API fails to apply assignment if same group is used for multiple assignments!
if (-not(Test-Null($RequiredAADGroupName)) -and ($RequiredAADGroupName -eq $AvailableAADGroupName)) {
    Write-Log -Message "Error - RequiredAADGroupName must be different from AvailableAADGroupName!"
    break
}
if (-not(Test-Null($RequiredAADGroupName)) -and ($RequiredAADGroupName -eq $UninstallAADGroupName)) {
    Write-Log -Message "Error - RequiredAADGroupName must be different from UninstallAADGroupName!"
    break
}
if (-not(Test-Null($UninstallAADGroupName)) -and ($UninstallAADGroupName -eq $AvailableAADGroupName)) {
    Write-Log -Message "Error - UninstallAADGroupName must be different from AvailableAADGroupName!"
    break
}

#Read XML File
Write-Log -Message "Reading XML file: [$packagePath\Config.xml]"
Get-XMLConfig -XMLFile "$packagePath\Config.xml"
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
    Write-Log -Message "AADGroupName: [$AADGroupName]"
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

        #$global:authToken = Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All", "Group.ReadWrite.All" | Out-Null
        #$global:authToken = Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All", "Group.ReadWrite.All"
        Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All", "Group.ReadWrite.All"
        #$null = Select-MgProfile -Name "beta" | Out-Null
    }
    elseif ($userName) {
        Write-Log -Message "Authenticate to AzureAD..."
        Test-AuthToken -User $Username

        $aryUserFromUPN = $userName.Split("@")
        $userFromUPN = $aryUserFromUPN[0]
        Write-Log -Message "Username without UPN address: $userFromUPN"

        $Description = $Description + "`nBy: $userFromUPN"
        Write-Log -Message "Updated description stamp to: $Description"
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
            Invoke-Cleanup
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
        Invoke-Cleanup
        throw "Please specify either a valid certificate name or client secret for authentication"
    }
}
#endregion auth

if (-not($AssignGroupsOnly)) {
    if (Test-Path -Path "$packagePath\IntuneWin") {
        Write-Log -Message "Removing folder: $packagePath\IntuneWin"
        Move-Item -Path "$packagePath\IntuneWin" -Destination "$env:Temp" -Force
        Remove-Item -Path "$env:Temp\IntuneWin" -Recurse -Force
    }
}

if ( $AppType -ne "Edge" -and (-not($AssignGroupsOnly))) {
    Write-Log -Message "Call Invoke-IntuneWinAppUtil function..."
    Invoke-IntuneWinAppUtil -AppType $AppType -IntuneWinAppPath $IntuneWinAppUtil -PackageSourcePath $SourcePath -IntuneAppPackage "$PackageName"
    Write-Log -Message "Return code from IntuneWin: $script:exitCode"

    if ( $script:exitCode -eq "-1" ) {
        Write-Log -Message "Error - from IntuneWin, exiting."
        exit
    }

    if ($IntuneWinPackageOnly) {
        Write-Log -Message "IntuneWinPackageOnly param used, exiting. Package path located at: `n$packagePath\IntuneWin"
        break
    }
}

Write-Log -Message "Call Build-IntuneAppPackage function..."
Build-IntuneAppPackage -AppType $AppType -RuleType $RuleType -ReturnCodeType $ReturnCodeType -InstallExperience $InstallExperience -Logo $LogoFile -AADGroupName $AADGroupName
Write-Log -Message "Return code from Build-IntuneAppPackage: $script:exitCode"

if ( $script:exitCode -eq "-1" ) {
    Write-Log -Message "Error - from Build-IntuneAppPackage, exiting."
    exit
}

if (-not($SkipPackageRemoval -or $AssignGroupsOnly)) {
    if (Test-Path -Path "$packagePath\IntuneWin") {
        Write-Log -Message "Removing folder: $packagePath\IntuneWin"
        Move-Item -Path "$packagePath\IntuneWin" -Destination "$env:Temp" -Force
        Remove-Item -Path "$env:Temp\IntuneWin" -Recurse -Force
    }
}

Write-Log "$ScriptName completed." -WriteEventLog
if (-not($Username)) {
    Invoke-Cleanup
}
return $script:exitCode

##########################################################################################################
##########################################################################################################
#endregion Main Script work section