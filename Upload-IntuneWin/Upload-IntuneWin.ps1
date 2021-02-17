#region Initialisation...
<#

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
    [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $True,
        HelpMessage = 'Please specify an Azure/Intune admin user name'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $userName, 
    [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $True,
        HelpMessage = 'Please enter path to package folder, containing Config.xml file'
    )]
    [Alias("PackageName")]
    [string[]] $packagePath,

    [Parameter(Position = 3,
        HelpMessage = 'Please enter folder path containing IntuneWinAppUtil.exe'
    )]
    [string] $intuneWinAppUtilPath,

    [Parameter()]
    [switch] $intuneWinPackageOnly,

    [Parameter()]
    [switch] $createGroupsOnly,

    [Parameter()]
    [switch] $skipGroupCreation
)
$script:exitCode = 0

$BuildVer = "1.1"
$ProgramFiles = $env:ProgramFiles
$ScriptName = $myInvocation.MyCommand.Name
$ScriptName = $ScriptName.Substring(0, $ScriptName.Length - 4)
$LogName = $ScriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
$logPath = "$($env:LocalAppData)\Microsoft\Temp\IntuneApps\$ScriptName"
$logFile = "$logPath\$LogName.log"
Add-Type -AssemblyName Microsoft.VisualBasic
$script:EventLogName = "Application"
$script:EventLogSource = "EventSystem"
$packagePath = $packagePath.Trim()
$SourcePath = "$packagePath\Source"

If (!($intuneWinAppUtilPath)) {
    $IntuneWinAppUtil = "$PSScriptRoot\IntuneWinAppUtil.exe"
}
Else {
    $intuneWinAppUtilPath = $intuneWinAppUtilPath.Trim('"')
    #Strip trailing \
    $lastChar = $intuneWinAppUtilPath.Substring($intuneWinAppUtilPath.Length - 1)
    Write-Host "lastChar: $lastChar"
    If ($lastChar -eq "\") { $script:intuneWinAppUtilPath = $intuneWinAppUtilPath.Substring(0, $intuneWinAppUtilPath.Length - 1) }
    Write-Host "script:intuneWinAppUtilPath: $script:intuneWinAppUtilPath"
    $IntuneWinAppUtil = "$intuneWinAppUtilPath\IntuneWinAppUtil.exe"
}

####################################################
####################################################
#Build Functions
####################################################

Function Start-Log {
    param (
        [string]$FilePath,

        [Parameter(HelpMessage = 'Deletes existing file if used with the -DeleteExistingFile switch')]
        [switch]$DeleteExistingFile
    )
		
    #Create Event Log source if it's not already found...
    If (!([system.diagnostics.eventlog]::SourceExists($EventLogSource))) { New-EventLog -LogName $EventLogName -Source $EventLogSource }

    Try {
        If (!(Test-Path $FilePath)) {
            ## Create the log file
            New-Item $FilePath -Type File -Force | Out-Null
        }
            
        If ($DeleteExistingFile) {
            Remove-Item $FilePath -Force
        }
			
        ## Set the global variable to be used as the FilePath for all subsequent Write-Log
        ## calls in this session
        $script:ScriptLogFilePath = $FilePath
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}

####################################################

Function Write-Log {
    #Write-Log -Message 'warning' -LogLevel 2
    #Write-Log -Message 'Error' -LogLevel 3
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
			
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1,

        [Parameter(HelpMessage = 'Outputs message to Event Log,when used with -WriteEventLog')]
        [switch]$WriteEventLog
    )
    Write-Host
    Write-Host $Message
    Write-Host
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat
    Add-Content -Value $Line -Path $ScriptLogFilePath
    If ($WriteEventLog) { Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message $Message  -Id 100 -Category 0 -EntryType Information }
}

####################################################

Function Set-IntuneTag {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .EXAMPLE
    .PARAMETER
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
#>
    Param ([string]$TagFilePath = "$($env:ProgramData)\Microsoft\IntuneApps\$ScriptName\")
              
    Begin {
        Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
    }

    Process {
        # Create a tag file just so Intune knows this was installed
        Write-Log "Tag file path is $TagFilePath"
        If (-not (Test-Path $TagFilePath)) {

            Try {
                New-Item -Path $TagFilePath -ItemType "directory" -Force | out-null 
            }

            Catch {
                Write-Log -Message "Error creating Intune Tag file: [$TagFile]" -LogLevel 3
            }
                    
        }
        $script:TagFile = "$($TagFilePath)\$ScriptName.tag"

        Try {
            Set-Content -Path $TagFile -Value "Installed" | out-null
        }

        Catch {
            Write-Log -Message "Error writing to Intune Tag file: [$TagFile]" -LogLevel 3
        }

    }

    End {
        Write-Log -Message "Created Intune Tag file: [$TagFile]"
        Return
    }

}

####################################################

Function New-RegKey {
    param($key)
  
    $key = $key -replace ':', ''
    $parts = $key -split '\\'
  
    $tempkey = ''
    $parts | ForEach-Object {
        $tempkey += ($_ + "\")
        if ( (Test-Path "Registry::$tempkey") -eq $false) {
            New-Item "Registry::$tempkey" | Out-Null
        }
    }
}

####################################################

function IsNull($objectToCheck) {
    if ($objectToCheck -eq $null) {
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

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

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
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Attempting module install now (requires Admin rights!)" -f Red
        Install-Module -Name AzureAD -AllowClobber -Force -Scope CurrentUser
        write-host
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if ($AadModule.count -gt 1) {

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

        # Checking if there are multiple versions of the same module found

        if ($AadModule.count -gt 1) {

            $aadModule = $AadModule | select -Unique

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

        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
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

    $uri = "$baseUrl$collectionPath";
    $request = "GET $uri";
	
    if ($logRequestUris) { Write-Host $request; }
    if ($logHeaders) { WriteHeaders $authToken; }

    try {
        Test-AuthToken -User $Username
        $response = Invoke-RestMethod $uri -Method Get -Headers $authToken;
        $response;
    }
    catch {
        Write-Host -ForegroundColor Red $request;
        Write-Host -ForegroundColor Red $_.Exception.Message;
        throw;
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

    $uri = "$baseUrl$collectionPath";
    $request = "$verb $uri";
	
    $clonedHeaders = CloneObject $authToken;
    $clonedHeaders["content-length"] = $body.Length;
    $clonedHeaders["content-type"] = "application/json";

    if ($logRequestUris) { Write-Host $request; }
    if ($logHeaders) { WriteHeaders $clonedHeaders; }
    if ($logContent) { Write-Host -ForegroundColor Gray $body; }

    try {
        Test-AuthToken -User $Username
        $response = Invoke-RestMethod $uri -Method $verb -Headers $clonedHeaders -Body $body -UseBasicParsing;
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

    $iso = [System.Text.Encoding]::GetEncoding("iso-8859-1");
    $encodedBody = $iso.GetString($body);
    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
    };

    if ($logRequestUris) { Write-Host $request; }
    if ($logHeaders) { WriteHeaders $headers; }

    try {
        $response = Invoke-WebRequest $uri -Method Put -Headers $headers -Body $encodedBody -UseBasicParsing;
    }
    catch {
        Write-Host -ForegroundColor Red $request;
        Write-Host -ForegroundColor Red $_.Exception.Message;
        throw;
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
        Invoke-RestMethod $uri -Method Put -Body $xml;
    }
    catch {
        Write-Host -ForegroundColor Red $request;
        Write-Host -ForegroundColor Red $_.Exception.Message;
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

            Write-Progress -Activity "Uploading File to Azure Storage" -status "Uploading chunk $currentChunk of $chunks" `
                -percentComplete ($currentChunk / $chunks * 100)

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

        if ($reader -ne $null) { $reader.Dispose(); }
	
    }
	
    # Finalize the upload.
    $uploadResponse = FinalizeAzureStorageUpload $sasUri $ids;

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

    $attempts = 600;
    $waitTimeInSeconds = 10;

    $successState = "$($stage)Success";
    $pendingState = "$($stage)Pending";
    $failedState = "$($stage)Failed";
    $timedOutState = "$($stage)TimedOut";

    $file = $null;
    while ($attempts -gt 0) {
        $file = MakeGetRequest $fileUri;

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

    if ($file -eq $null -or $file.uploadState -ne $successState) {
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
        $body.fileName = $filename;
        If ( ! ( ISNull ( $msiInstallCommandLine ) ) ) {
            $body.installCommandLine = "msiexec /i `"$SetupFileName`" $msiInstallCommandLine"
        }
        Else {
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
        If ( ! ( IsNull ( $msiUninstallCommandLine ) ) ) {
            $body.uninstallCommandLine = "msiexec /x `"$MsiProductCode`""
        }
        Else {
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
    ElseIf ($Edge) {
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

Function Test-SourceFile() {

    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $SourceFile
    )

    try {

        if (!(test-path "$SourceFile")) {

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

Function New-DetectionRule() {

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
   
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateNotNullOrEmpty()]
        [String]$Path,
 
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateNotNullOrEmpty()]
        [string]$FileOrFolderName,

        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateSet("notConfigured", "exists", "modifiedDate", "createdDate", "version", "sizeInMB")]
        [string]$FileDetectionType,

        [parameter(Mandatory = $false, ParameterSetName = "File")]
        $FileDetectionValue = $null,

        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateSet("True", "False")]
        [string]$check32BitOn64System = "False",

        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateNotNullOrEmpty()]
        [String]$RegistryKeyPath,

        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateSet("notConfigured", "exists", "doesNotExist", "string", "integer", "version")]
        [string]$RegistryDetectionType,

        [parameter(Mandatory = $false, ParameterSetName = "Registry")]
        [ValidateNotNullOrEmpty()]
        [String]$RegistryValue,

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
        $DR.productVersionOperator = "notConfigured";
        $DR.productCode = "$MsiProductCode";
        $DR.productVersion = $null;

    }

    elseif ($File) {
    
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppFileSystemDetection" }
        $DR.check32BitOn64System = "$check32BitOn64System";
        $DR.detectionType = "$FileDetectionType";
        $DR.detectionValue = $FileDetectionValue;
        $DR.fileOrFolderName = "$FileOrFolderName";
        $DR.operator = "notConfigured";
        $DR.path = "$Path"

    }

    elseif ($Registry) {
    
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppRegistryDetection" }
        $DR.check32BitOn64System = "$check32BitRegOn64System";
        $DR.detectionType = "$RegistryDetectionType";
        $DR.detectionValue = "";
        $DR.keyPath = "$RegistryKeyPath";
        $DR.operator = "notConfigured";
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

Function Get-IntuneWinXML() {

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

    $zip.Entries | where { $_.Name -like "$filename" } | foreach {

        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)

    }

    $zip.Dispose()

    [xml]$IntuneWinXML = gc "$Directory\$filename"

    return $IntuneWinXML

    if ($removeitem -eq "true") { remove-item "$Directory\$filename" }

}

####################################################

Function Get-IntuneWinFile() {

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

    $zip.Entries | where { $_.Name -like "$filename" } | foreach {

        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)

    }

    $zip.Dispose()

    return "$Directory\$folder\$filename"

    if ($removeitem -eq "true") { remove-item "$Directory\$filename" }

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

        If ( $AppType -ne "Edge" ) {
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
        If ($MSI) {
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

            $MSIRule = New-DetectionRule -MSI -MSIproductCode $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode

            # Creating Array for detection Rule
            $detectionRules = @($MSIRule)

            If ( ! ($null -eq $msiInstallCommandLine ) ) {
                $mobileAppBody = GetWin32AppBody `
                    -MSI `
                    -displayName "$DisplayName" `
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
            Else {
                $mobileAppBody = GetWin32AppBody `
                    -MSI `
                    -displayName "$DisplayName" `
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
        ElseIf ($EXE) {
            $mobileAppBody = GetWin32AppBody -EXE -displayName "$DisplayName" -publisher "$publisher" `
                -description $description -category $Category -filename $FileName -SetupFileName "$SetupFileName" `
                -installExperience $installExperience -logo $logo `
                -installCommandLine $installCommandLine -uninstallCommandLine $uninstallCommandLine 
        }
        ElseIf ($PS1) {
            $mobileAppBody = GetWin32AppBody -EXE -displayName "$DisplayName" -publisher "$publisher" `
                -description $description -category $Category -filename $FileName -SetupFileName "$SetupFileName" `
                -installExperience $installExperience -logo $logo `
                -installCommandLine $ps1InstallCommandLine -uninstallCommandLine $ps1UninstallCommandLine
        }
        ElseIf ($Edge) {
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

            Return
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
        $file = WaitForFileProcessing $fileUri "AzureStorageUriRequest";

        # Upload the content to Azure Storage.
        Write-Host
        Write-Host "Uploading file to Azure Storage..." -f Yellow

        #$sasUri = $file.azureStorageUri;
        UploadFileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri;

        # Need to Add removal of IntuneWin file
        #$IntuneWinFolder = [System.IO.Path]::GetDirectoryName("$IntuneWinFile")
        Remove-Item "$IntuneWinFile" -Force

        # Commit the file.
        Write-Host
        Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
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

        Write-Host "";
        Write-Host -ForegroundColor Red "Aborting with exception: $($_.Exception.ToString())";
        Exit
	
    }
}

####################################################

Function Get-XMLConfig {
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

    Begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    Process {
        $dayDateTime = (Get-Date -UFormat "%A %d-%m-%Y %R")
        If (-Not(Test-Path $XMLFile)) {
            Write-Log -Message "Error - XML file not found: $XMLFile" -LogLevel 3
            Return $Skip = $true
        }
        Write-Log -Message "Reading XML file: $XMLFile"
        [xml]$script:XML_Content = Get-Content $XMLFile

        ForEach ($XMLEntity in $XML_Content.GetElementsByTagName("Azure_Settings")) {
            If (IsNull($Username)) {
                $script:Username = [string]$XMLEntity.Username
            }
            $script:baseUrl = [string]$XMLEntity.baseUrl
            $script:logRequestUris = [string]$XMLEntity.logRequestUris
            $script:logHeaders = [string]$XMLEntity.logHeaders
            $script:logContent = [string]$XMLEntity.logContent
            $script:azureStorageUploadChunkSizeInMb = [string]$XMLEntity.azureStorageUploadChunkSizeInMb
            $script:sleep = [int32]$XMLEntity.sleep
        }

        ForEach ($XMLEntity in $XML_Content.GetElementsByTagName("IntuneWin_Settings")) {
            If ($script:AADGroupName.Length -gt 50) {
                Write-Log -Message "Error - AAD group name longer than 50 chars. Shorten then retry."
                Exit
            }

            $script:AppType = [string]$XMLEntity.AppType
            If ( ( $AppType -eq "EXE" ) -or ( $AppType -eq "MSI" ) ) {
                Write-Log -Message "Reading commands for AppType: $AppType"
                $script:installCmdLine = [string]$XMLEntity.installCmdLine
                $script:uninstallCmdLine = [string]$XMLEntity.uninstallCmdLine
            }
            If ( $AppType -eq "Edge" ) {
                Write-Log -Message "Reading commands for AppType: $AppType"
                $script:displayName = [string]$XMLEntity.displayName
                $script:Description = [string]$XMLEntity.Description + "`nObject creation: $dayDateTime"
                $script:Publisher = [string]$XMLEntity.Publisher
                $script:Channel = [string]$XMLEntity.Channel
                $script:AADGroupName = [string]$XMLEntity.AADGroupName
                Return
            }
            $script:RuleType = [string]$XMLEntity.RuleType
            If ($RuleType -eq "FILE") {
                Write-Log -Message "Reading detection for RuleType: $RuleType"
                $script:FilePath = [string]$XMLEntity.FilePath
            }
            $script:ReturnCodeType = [string]$XMLEntity.ReturnCodeType
            $script:InstallExperience = [string]$XMLEntity.InstallExperience
            $script:PackageName = [string]$XMLEntity.PackageName
            $script:displayName = [string]$XMLEntity.displayName
            $script:Description = [string]$XMLEntity.Description + "`nObject creation: $dayDateTime"
            $script:Publisher = [string]$XMLEntity.Publisher
            $script:Category = [string]$XMLEntity.Category
            $script:LogoFile = [string]$XMLEntity.LogoFile
            $script:AADGroupName = [string]$XMLEntity.AADGroupName
                               
            #Strip .ps1 extension, if entered into XML file...
            $lastFourChars = $PackageName.Substring($PackageName.Length - 4)
            If ($lastFourChars -eq ".ps1") { $script:PackageName = $PackageName.Substring(0, $PackageName.Length - 4) }
        }

    }

    End {
        If ($Skip) { Return }# Just return without doing anything else
        Write-Log -Message "Returning..."
        Return
    }

}

####################################################

Function Invoke-IntuneWinAppUtil {
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

    Begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    Process {
        Write-Log -Message "AppType: [$AppType]"
        Write-Log -Message "Using IntuneWinAppUtil path: [$IntuneWinAppPath]"
        Write-Log -Message "Using Package Source path: [$PackageSourcePath]"
        Write-Log -Message "IntuneAppPackage: [$IntuneAppPackage]"
            
        If ($AppType -eq "PS1") {
            Write-Log -Message "Configuring Package Name to include .PS1 extension..."
            $IntuneAppPackage = "$IntuneAppPackage.ps1"
            Write-Log -Message "IntuneAppPackage re-written as: [$IntuneAppPackage]"
        }
        ElseIf ($AppType -eq "EXE") {
            Write-Log -Message "Configuring Package Name to include .EXE extension..."
            $IntuneAppPackage = "$IntuneAppPackage.exe"
            Write-Log -Message "IntuneAppPackage re-written as: [$IntuneAppPackage]"
        }
        ElseIf ($AppType -eq "MSI") {
            Write-Log -Message "Configuring Package Name to include .MSI extension..."
            $IntuneAppPackage = "$IntuneAppPackage.msi"
            Write-Log -Message "IntuneAppPackage re-written as: [$IntuneAppPackage]"
        }

        If (!(Test-Path $IntuneWinAppPath)) {
            Write-Log -Message "Error - $IntuneWinAppPath not found, exiting..." -LogLevel 3
            $script:exitCode = -1
            Return
        }
        If (!(Test-Path "$packagePath\IntuneWin")) {
            Write-Log -Message "Output path: [$packagePath\IntuneWin] not found, creating..."
            Try {
                New-Item -Path "$packagePath\IntuneWin" -ItemType Directory -Force | out-null
            }

            Catch {
                Write-Log -Message "Error creating output path: [$packagePath\IntuneWin]" -LogLevel 3
                $script:exitCode = -1
            }
                
        }
        Else {
            Write-Log -Message "Existing output path: [$packagePath\IntuneWin] found, re-creating..."
            Try {
                Remove-Item -Path "$packagePath\IntuneWin" -Recurse -Force | out-null
                New-Item -Path "$packagePath\IntuneWin" -ItemType Directory -Force | out-null
            }

            Catch {
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
        If (Test-Path $SourceFile) {
            Write-Log -Message "File created: [$SourceFile]"
        }
        Else {
            Write-Log -Message "Error - something went wrong creating IntuneWin package: [$SourceFile]" -LogLevel 3
            $script:exitCode = -1
        }
    }

    End {
        If (!($script:exitCode -eq 0)) { Return $script:exitCode }# Just return without doing anything else, error tripped
        Write-Log -Message "Returning..."
        Return $script:exitCode = 0
    }

}

####################################################

Function Build-IntuneAppPackage {
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

    Begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    Process {
        Write-Log -Message "AppType: [$AppType]"
        Write-Log -Message "RuleType: [$RuleType]"
        Write-Log -Message "ReturnCodeType: [$ReturnCodeType]"
        Write-Log -Message "InstallExperience: [$InstallExperience]"
        Write-Log -Message "LogoFile: [$LogoFile]"
        Write-Log -Message "AADGroupName: [$AADGroupName]"
            
        If ( $AppType -ne "Edge" ) {
            If ( ( $AppType -eq "PS1" ) -and ( $RuleType -eq "TAGFILE" ) ) {
                Write-Log -Message "Building variables for AppType: $AppType with RuleType: $RuleType"

                If ($installExperience -eq "User") {
                    $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install -userInstall"
                    $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall -userInstall"
                }
                Else {
                    $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install"
                    $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall"
                }
                                
                Write-Log -Message "installCmdLine: [$installCmdLine]"
                Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
            }
            ElseIf ( ( $AppType -eq "PS1" ) -and ( $RuleType -eq "REGTAG" ) ) {
                Write-Log -Message "Building variables for AppType: $AppType with RuleType: $RuleType"

                If ($installExperience -eq "User") {
                    $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install -userInstall -regTag"
                    $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall -userInstall -regTag"
                }
                Else {
                    $installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install -regTag"
                    $uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall -regTag"
                }
                                
                Write-Log -Message "installCmdLine: [$installCmdLine]"
                Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
            }
            ElseIf ($AppType -eq "EXE") {
                Write-Log -Message "Building variables for AppType: $AppType"
                #$installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install"
                #$uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall"
                Write-Log -Message "installCmdLine: [$installCmdLine]"
                Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
            }
            ElseIf ($AppType -eq "MSI") {
                Write-Log -Message "Building variables for AppType: $AppType"
                #$installCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -Install"
                #$uninstallCmdLine = "powershell.exe -windowstyle hidden -noprofile -executionpolicy bypass -file .\$PackageName.ps1 -UnInstall"
                Write-Log -Message "installCmdLine: [$installCmdLine]"
                Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
            }

            If ( ( $RuleType -eq "TAGFILE" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
                Write-Log -Message "Building variables for RuleType: $RuleType"
                If ($installExperience -eq "System") {
                    Write-Log -Message "Creating TagFile detection rule for System install"
                    $FileRule = New-DetectionRule -File -Path "%PROGRAMDATA%\Microsoft\IntuneApps\$PackageName" `
                        -FileOrFolderName "$PackageName.tag" -FileDetectionType exists -check32BitOn64System False
                }
                ElseIf ($installExperience -eq "User") {
                    Write-Log -Message "Creating TagFile detection rule for User install"
                    $FileRule = New-DetectionRule -File -Path "%LOCALAPPDATA%\Microsoft\IntuneApps\$PackageName" `
                        -FileOrFolderName "$PackageName.tag" -FileDetectionType exists -check32BitOn64System False
                }
                Write-Log -Message "FileRule: [$FileRule]"

                # Creating Array for detection Rule
                $DetectionRule = @($FileRule)
            }
            ElseIf ( ( $RuleType -eq "FILE" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
                Write-Log -Message "Building variables for RuleType: $RuleType"
                $fileDetectPath = split-path -parent $FilePath
                $fileDetectFile = split-path -leaf $FilePath
                Write-Log -Message "fileDetectPath: $fileDetectPath"
                Write-Log -Message "fileDetectFile: $fileDetectFile"

                $FileRule = New-DetectionRule -File -Path $fileDetectPath `
                    -FileOrFolderName $fileDetectFile -FileDetectionType exists -check32BitOn64System False
                Write-Log -Message "FileRule: [$FileRule]"

                # Creating Array for detection Rule
                $DetectionRule = @($FileRule)
            }
            ElseIf ( ( $RuleType -eq "REGTAG" ) -and ( ! ( $AppType -eq "MSI" ) ) ) {
                Write-Log -Message "Building variables for RuleType: $RuleType"
                If ($installExperience -eq "System") {
                    Write-Log -Message "Creating RegTag detection rule for System install"

                    $RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$PackageName" `
                        -RegistryDetectionType exists -check32BitRegOn64System True -RegistryValue "Installed"
                }
                ElseIf ($installExperience -eq "User") {
                    Write-Log -Message "Creating RegTag detection rule for User install"

                    $RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$PackageName" `
                        -RegistryDetectionType exists -check32BitRegOn64System True -RegistryValue "Installed"
                }
                Write-Log -Message "RegistryRule: [$RegistryRule]"

                # Creating Array for detection Rule
                $DetectionRule = @($RegistryRule)
            }
            Else {                           
                Write-Log -Message "Using MSI detection rule"
                $DetectionRule = "MSI"
            }

            If ($ReturnCodeType -eq "DEFAULT") {
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
        If ( ! ( IsNull ( $appID ) ) ) {
            Write-Log -Message "Detected existing package in Intune: $displayName"
            Write-Log -Message "Manual upload of the new IntuneWin package required."
            Write-Log -Message "Upload content: "
            Write-Host
            Write-Host "$script:SourceFile" -ForegroundColor Cyan
            Write-Host
            Write-Host
            Exit                
        }
        Else {
            Write-Log -Message "Existing package not found"
        }

        # Win32 Application Upload
        If ($AppType -eq "MSI") {
            Write-Log -Message "Preparing MSI package"

            If ( ( ! ( IsNull( $installCmdLine) ) ) -and ( ! ( IsNull( $uninstallCmdLine ) ) ) ) {
                Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -msiInstallCommandLine $installCmdLine -msiUninstallCommandLine $uninstallCmdLine -installExperience $installExperience -logo $Icon -Category $Category
            }
            ElseIf ( ( ! ( IsNull( $installCmdLine ) ) ) -and ( IsNull( $uninstallCmdLine ) ) ) {
                Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -msiInstallCommandLine $installCmdLine -installExperience $installExperience -logo $Icon -Category $Category
            }
            ElseIf ( ( IsNull( $installCmdLine ) ) -and ( ! ( IsNull( $uninstallCmdLine ) ) ) ) {
                Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -msiUninstallCommandLine $uninstallCmdLine -installExperience $installExperience -logo $Icon -Category $Category
            }
            ElseIf ( ( IsNull( $installCmdLine ) ) -and ( IsNull( $uninstallCmdLine ) ) ) {
                Upload-Win32Lob -MSI -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                    -returnCodes $ReturnCodes -displayName $displayName -installExperience $installExperience -logo $Icon -Category $Category
            }
        }
        ElseIf ($AppType -eq "EXE") {
            Write-Log -Message "Preparing EXE package"
            Upload-Win32Lob -EXE -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                -returnCodes $ReturnCodes -displayName $displayName -installCommandLine $installCmdLine -uninstallCommandLine $uninstallCmdLine -installExperience $installExperience -logo $Icon -Category $Category
        }
        ElseIf ($AppType -eq "PS1") {
            Write-Log -Message "Preparing PS1 package"
            Upload-Win32Lob -PS1 -SourceFile "$SourceFile" -publisher "$Publisher" -description "$Description" -detectionRules $DetectionRule `
                -returnCodes $ReturnCodes -displayName $displayName -ps1InstallCommandLine $InstallCmdLine -ps1UninstallCommandLine $UninstallCmdLine -installExperience $installExperience -logo $Icon -Category $Category
        }
        ElseIf ($AppType -eq "Edge") {
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
        #Exit
        Write-Log -Message "Create AAD groups for install/uninstall"
        $script:exitCode = New-AADGroup -groupName $AADGroupName

        Write-Host "Sleeping for $sleep seconds to allow AAD group creation..." -f Magenta
        Start-Sleep $sleep
        Write-Host
            
        #If ($script:exitCode -eq 0) {
        Write-Log -Message "Assigning AAD groups for install/uninstall"

        Write-Log -Message "Find application ID"
        $appID = Get-ApplicationID -AppName $displayName

        Write-Log -Message "Reading group IDs"
        $installReqGroup = Get-GroupID -GroupName "$AADGroupName-Required"
        $installAvailGroup = Get-GroupID -GroupName "$AADGroupName-Available"
        $uninstallGroup = Get-GroupID -GroupName "$AADGroupName-UnInstall"

        Write-Log -Message "Assigning groups to application..."
        $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installReqGroup -InstallIntent "required"
        $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $installAvailGroup -InstallIntent "available"
        $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "uninstall"
        $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "required" -exclude
        $Assign_Application = Add-ApplicationAssignment -ApplicationId $appID -TargetGroupId $uninstallGroup -InstallIntent "available" -exclude
               
        #}         
    }

    End {
        If (!($script:exitCode -eq 0)) { Return $script:exitCode }# Just return without doing anything else, error tripped
        Write-Log -Message "Returning..."
        Return $script:exitCode = 0
    }

}

####################################################

Function New-AADGroup {
    <#
.SYNOPSIS
This function creates the relevant install/uninstall AAD groups
.DESCRIPTION
This function creates the relevant install/uninstall AAD groups
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

    Begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    Process {
        Write-Log -Message "groupName: [$groupName]"

        Connect-AzureAD -AccountId $Username

        $AADGroups = @("$groupName-Required", "$groupName-Available", "$groupName-Uninstall")

        foreach ($group in $AADGroups) {
            If (Get-AzureADGroup -SearchString $group) {
                Write-Log -Message "AAD group $group already exists!"
            }
            Else {
                Write-Log -Message "Creating AAD group $group"
                try {
                    New-AzureADGroup -DisplayName $group -Description "Group for $group" -MailEnabled $false -SecurityEnabled $true -MailNickName ($($group).Replace(" ", "") + "-Group")
                }
                catch {
                    Write-Log -Message "Error creating AAD group $group"
                    $script:exitCode = -1
                    Exit
                }

            }
        }
    }

    End {
        If (!($script:exitCode -eq 0)) { Return $script:exitCode }# Just return without doing anything else, error tripped
        Write-Log -Message "Returning..."
        Return $script:exitCode = 0
    }

}

####################################################

Function Get-GroupID {
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

    Begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    Process {
        Write-Log -Message "Search for group name: $GroupName"
        $Group = Get-AzureADGroup -SearchString $GroupName

        If (IsNull($Group)) {
            Write-Log -Message "Error - could not find group: $GroupName" -LogLevel 3
            $script:exitCode = -1
        }
        Else {
            Write-Log -Message "Found group: `n$Group"
            $script:exitCode = 0
        }
    }

    End {
        If (!($script:exitCode -eq 0)) { Return $script:exitCode }# Just return without doing anything else, error tripped
        $GroupID = $($Group).ObjectId
        Write-Log -Message "Returning group ID: [$GroupID]"
        Return $GroupID
    }

}

####################################################

Function Get-ApplicationID {
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

    Begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    Process {
        Write-Log -Message "Search for application name: $AppName"
        #$filter = "DisplayName eq '"+$AppName+"'"
        #Write-Log -Message "Using filter: $filter"
        $application = Get-IntuneApplication -Name $AppName

        If (IsNull($application)) {
            Write-Log -Message "Error - could not find application: $application" -LogLevel 3
            #$script:exitCode = -1
        }
        Else {
            Write-Log -Message "Found application: $application"
            #$script:exitCode = 0
            
        }
        $appID = $($application).id
        Write-Log -Message "Returning application ID: [$appID]"
        Return $appID
    }
}

####################################################

Function Get-IntuneApplication() {

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

        if ($Name) {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") -and (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }

        }

        else {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }

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
        write-host
        break

    }

}

####################################################

Function Set-GroupMember {
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

    Begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }

    Process {
        $MemberName = (Get-AzureADGroup -ObjectId $MemberToAdd).DisplayName
        $GroupName = (Get-AzureADGroup -ObjectId $AddToGroup).DisplayName
        Write-Log -Message "Adding $MemberName (member object: $MemberToAdd)"
        Write-Log -Message "To $GroupName (group object: $AddToGroup)"


        $ExistingGroupMembers = Get-AzureADGroupMember -ObjectId $AddToGroup
        #Write-Log -Message "Existing members: $ExistingGroupMembers"

        foreach ($member in $ExistingGroupMembers) {
            If ($($member).ObjectId -eq $MemberToAdd) {
                Write-Log -Message "Member: [$MemberToAdd] already exists, returning..."
                Return $Skip = $true
            }
        }

        Try {
            Write-Log -Message "Add member to group"
            Add-AzureADGroupMember -ObjectId $AddToGroup -RefObjectId $MemberToAdd | out-null
        }

        Catch {
            Write-Log -Message "Error adding member to group" -LogLevel 3
        }

    }

    End {
        If ($Skip) { Return }# Just return without doing anything else
        Write-Log -Message "Added member object: $MemberToAdd"
        Write-Log -Message "To group object: $AddToGroup"
        Return
    }

}

####################################################

Function Add-ApplicationAssignment() {

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

            If ( ! ( $exclude ) ) {
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
      "intent": "$InstallIntent"
    },
"@
            }
            ElseIf ( $exclude ) {
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
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

            #}

        }#Try

        else {

            If ( ! ( $exclude ) ) {
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
        "intent": "$InstallIntent"
    }
    ]
}
"@
            }
            ElseIf ( $exclude ) {
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
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

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
        write-host
        break

    }

    Write-Host "Sleeping for $sleep seconds to allow AAD group assignment..." -f Magenta
    Start-Sleep $sleep
    Write-Host
}

####################################################

Function Get-ApplicationAssignment() {

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

            write-host "No Application Id specified, specify a valid Application Id" -f Red
            break

        }

        else {
        
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        
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
        write-host
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

Function Test-AuthToken() {


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

            write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            write-host

            # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if ($User -eq $null -or $User -eq "") {

                $script:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                Write-Host

            }

            $global:authToken = Get-AuthToken -User $User

        }
    }

    # Authentication doesn't exist, calling Get-AuthToken function

    else {

        if ($User -eq $null -or $User -eq "") {

            $script:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

        }

        # Getting the authorization token
        $global:authToken = Get-AuthToken -User $User

    }
}

####################################################

Start-Log -FilePath $logFile -DeleteExistingFile
Write-Host
Write-Host "Script log file path is [$logFile]" -f Cyan
Write-Host
Write-Log -Message "Starting $ScriptName version $BuildVer" -WriteEventLog

<#
####################################################
# Sample Win32 Application
####################################################

$SourceFile = "C:\packages\package.intunewin"

# Defining Intunewin32 detectionRules
$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

# Defining Intunewin32 detectionRules
$FileRule = New-DetectionRule -File -Path "C:\Program Files\Application" `
-FileOrFolderName "application.exe" -FileDetectionType exists -check32BitOn64System False

$RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\Program" `
-RegistryDetectionType exists -check32BitRegOn64System True

$MSIRule = New-DetectionRule -MSI -MSIproductCode $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode

# Creating Array for detection Rule
$DetectionRule = @($FileRule,$RegistryRule,$MSIRule)

$ReturnCodes = Get-DefaultReturnCodes

$ReturnCodes += New-ReturnCode -returnCode 302 -type softReboot
$ReturnCodes += New-ReturnCode -returnCode 145 -type hardReboot

# Win32 Application Upload
Upload-Win32Lob -SourceFile "$SourceFile" -publisher "Publisher" `
-description "Description" -detectionRules $DetectionRule -returnCodes $ReturnCodes `
-installCmdLine "powershell.exe .\install.ps1" `
-uninstallCmdLine "powershell.exe .\uninstall.ps1"

####################################################
#>
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

#Check package path is valid
If ( ! ( Test-Path $packagePath ) ) {
    Write-Log -Message "Error - path not valid: $packagePath"
    Exit
}

#Read XML File
Write-Log -Message "Reading XML file: [$packagePath\Config.xml]"
Get-XMLConfig -XMLFile "$packagePath\Config.xml"

Write-Log -Message "Username: [$Username]"
Write-Log -Message "baseUrl: [$baseUrl]"
Write-Log -Message "logRequestUris: [$logRequestUris]"
Write-Log -Message "logHeaders: [$logHeaders]"
Write-Log -Message "logContent: [$logContent]"
Write-Log -Message "sleep: [$sleep]"

Write-Log -Message "AppType: [$AppType]"
If ( $AppType -eq "Edge" ) {
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
If ( $AppType -ne "Edge" ) {
    If ( ( $AppType -eq "EXE" ) -or ( $AppType -eq "MSI" ) ) {
        Write-Log -Message "Using install/unistall commands for AppType: $AppType"
        Write-Log -Message "installCmdLine: [$installCmdLine]"
        Write-Log -Message "uninstallCmdLine: [$uninstallCmdLine]"
    }
    Write-Log -Message "RuleType: [$RuleType]"
    If ($RuleType -eq "FILE") {
        Write-Log -Message "Using detection for RuleType: $RuleType"
        Write-Log -Message "FilePath: [$FilePath]"
    }
    Write-Log -Message "ReturnCodeType: [$ReturnCodeType]"
    Write-Log -Message "InstallExperience: [$InstallExperience]"
    Write-Log -Message "PackageName: [$PackageName]"
    Write-Log -Message "displayName: [$displayName]"
    Write-Log -Message "Description: [$Description]"
    Write-Log -Message "Publisher: [$Publisher]"
    Write-Log -Message "Category: [$Category]"
    Write-Log -Message "LogoFile: [$LogoFile]"
}
Write-Log -Message "AADGroupName: [$AADGroupName]"

Write-Log -Message "Path to IntuneWinAppUtil: [$IntuneWinAppUtil]"
Write-Log -Message "SourcePath: [$SourcePath]"

If (IsNull($Username)) {
    Write-Log -Message "Username not found in XML file, prompt user to enter one..."
    $Username = Read-Host -Prompt "Please specify an Azure admin user name"
    Write-Log -Message "Admin user account: $Username"
}

Write-Log -Message "Authenticate to AzureAD..."
Test-AuthToken -User $Username

$aryUserFromUPN = $userName.Split("@")
$userFromUPN = $aryUserFromUPN[0]
Write-Log -Message "Username without UPN address: $userFromUPN"

$Description = $Description + "`nBy: $userFromUPN"
Write-Log -Message "Updated description stamp to: $Description"

If ( $AppType -ne "Edge" ) {
    Write-Log -Message "Call Invoke-IntuneWinAppUtil function..."
    Invoke-IntuneWinAppUtil -AppType $AppType -IntuneWinAppPath $IntuneWinAppUtil -PackageSourcePath $SourcePath -IntuneAppPackage "$PackageName"
    Write-Log -Message "Return code from IntuneWin: $script:exitCode"

    If ( $script:exitCode -eq "-1" ) {
        Write-Log -Message "Error - from IntuneWin, exiting."
        Exit
    }
}

Write-Log -Message "Call Build-IntuneAppPackage function..."
Build-IntuneAppPackage -AppType $AppType -RuleType $RuleType -ReturnCodeType $ReturnCodeType -InstallExperience $InstallExperience -Logo $LogoFile -AADGroupName $AADGroupName
Write-Log -Message "Return code from Build-IntuneAppPackage: $script:exitCode"

If ( $script:exitCode -eq "-1" ) {
    Write-Log -Message "Error - from Build-IntuneAppPackage, exiting."
    Exit
}


Write-Log -Message "Removing folder: $packagePath\IntuneWin"
Remove-Item -Path "$packagePath\IntuneWin" -Recurse -Force

Write-Log "$ScriptName completed." -WriteEventLog
Return $script:exitCode

##########################################################################################################
##########################################################################################################
#endregion Main Script work section