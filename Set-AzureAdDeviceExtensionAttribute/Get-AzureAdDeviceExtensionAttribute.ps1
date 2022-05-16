#Requires -Module AzureADPreview
#region Initialisation...
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
####################################################
####################################################
#Instantiate Vars
####################################################

[CmdLetBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $True,
        HelpMessage = 'Please specify an Azure/Intune admin user name'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $userName,

    [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $True,
        HelpMessage = 'Please specify a devicename (or list of devices)'
    )]
    [ValidateNotNullOrEmpty()]
    [string[]] $DeviceName = @()
)

$Global:exitCode = 0
$BuildVer = "1.0"
$ProgramFiles = $env:ProgramFiles
$ScriptName = $myInvocation.MyCommand.Name
$ScriptName = $ScriptName.Substring(0, $ScriptName.Length - 4)
$LogName = $ScriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
$logPath = "$($env:Temp)\$ScriptName"
$logFile = "$logPath\$LogName.log"
Add-Type -AssemblyName Microsoft.VisualBasic
$EventLogName = "Application"
$EventLogSource = $ScriptName

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
    $ErrorActionPreference = 'SilentlyContinue'
    If (!([system.diagnostics.eventlog]::SourceExists($EventLogSource))) { New-EventLog -LogName $EventLogName -Source $EventLogSource }
    $ErrorActionPreference = 'Continue'

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
        $global:ScriptLogFilePath = $FilePath
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
    #If ($WriteEventLog) { Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message $Message  -Id 100 -Category 0 -EntryType Information }
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
    
                $Global:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                Write-Host
    
            }
    
            $global:authToken = Get-AuthToken -User $User
    
        }
    }
    
    # Authentication doesn't exist, calling Get-AuthToken function
    
    else {
    
        if ($User -eq $null -or $User -eq "") {
    
            $Global:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host
    
        }
    
        # Getting the authorization token
        $global:authToken = Get-AuthToken -User $User
    
    }
    $NULL = Connect-AzureAD -AccountId $User
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
    
    $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
    
    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureADPreview' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }
    
    <#
    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Attempting module install now (requires Admin rights!)" -f Red
        Install-Module -Name AzureAD -AllowClobber -Scope CurrentUser -Force
        write-host
    }
    #>
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
    
    #$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    $authorityUri = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    
    try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
        $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($authorityUri, $false)
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
        $global:accessToken = $authContext.AcquireTokenAsync($resourceUri, $clientId, $redirectUri, $platformParameters).Result.AccessToken
    
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

function Get-AzureAdDeviceExtensionAttribute {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0)]
        [guid]$ObjectId
    )

    $graphApiVersion = "v1.0"
    $graphResource = "devices"
    
    if ($ObjectId) {
        $Uri = "https://graph.microsoft.com/$graphApiVersion/$graphResource/{0}" -f $ObjectId        
    }
    else {
        $Uri = "https://graph.microsoft.com/$graphApiVersion/$graphResource"
    }
    Write-Verbose $('{0} - Using {1} API URI' -f $(Get-Date -Format T), $Uri)

    #get results from API
    try {
        #$restData = Invoke-RestMethod -Headers @{Authorization = "$global:authToken" } -Uri $apiUri -Method Get
        #$restData = Invoke-RestMethod -Headers @{Authorization = "Bearer $global:authToken" } -Uri $apiUri -Method Get
        #$restData = Invoke-RestMethod -Headers @{Authorization = "Bearer $global:accessToken" } -Uri $apiUri -Method Get
        #$restData = Invoke-RestMethod -Headers @{Authorization = "Bearer $accessToken" } -Uri $apiUri -Method Get
        $restData = Invoke-RestMethod -Headers $authToken -Uri $Uri -Method Get

        if ($ObjectId) {
            $deviceData = $restData
            $deviceDataCount = 1
        }
        else {
            $deviceData = $restData.value
            $deviceDataCount = $deviceData.Count
        }
        Write-Verbose $('{0} - REST method returned {1} results.' -f $(Get-Date -Format T), $deviceDataCount)
    }
    catch {
        Write-Error $('Could not get device data from {0} - {1}' -f $apiUri, $Error[0].Exception)
    }

    $devicesOut = @()
    foreach ($d in $deviceData) {
        $deviceOut = [PSCustomObject]@{
            id                     = $d.id
            displayName            = $d.displayName
            operatingSystem        = $d.operatingSystem
            operatingSystemVersion = $d.operatingSystemVersion
            isCompliant            = $d.isCompliant
            isManaged              = $d.isManaged
            profileType            = $d.profileType
            extensionAttribute1    = $d.extensionAttributes.extensionAttribute1
            extensionAttribute2    = $d.extensionAttributes.extensionAttribute2
            extensionAttribute3    = $d.extensionAttributes.extensionAttribute3
            extensionAttribute4    = $d.extensionAttributes.extensionAttribute4
            extensionAttribute5    = $d.extensionAttributes.extensionAttribute5
            
        }
        $devicesOut += $deviceOut
    }

    return $devicesOut
}

####################################################

Function Get-DeviceID {
    <#
    .SYNOPSIS
    This function is used to get an AAD device and return it's object ID if found
    .DESCRIPTION
    The function is used to get an AAD device and return it's object ID if found
    .EXAMPLE
    Get-DeviceID -deviceName DeviceNameHere
    The function is used to get an AAD device and return it's object ID if found
    .NOTES
    NAME: Get-DeviceID
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true)]
        $DeviceName
    )
    
    Begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..."
    }
    
    Process {
        Write-Log -Message "Search for device name: $deviceName"
        $deviceID = Get-AzureADDevice -SearchString $deviceName
    
        If ($null -eq $deviceID) {
            Write-Log -Message "Error - could not find device: $deviceName" -LogLevel 3
        }
        Else {
            Write-Log -Message "Found device: $deviceName"
            Write-Verbose "Found device: `n$deviceID"
        }

        Return $deviceID
    }
}
    
####################################################

Clear-Host
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
Write-Log -Message "Authenticate to AzureAD..."
Test-AuthToken -User $Username

$tenant = Get-AzureADTenantDetail

$tenantName = $(($tenant.VerifiedDomains | Where-Object _Default).Name)
Write-Log -Message "Tennant Name: $tenantName"

foreach ($device in $DeviceName) {
    Write-Log -Message "Reading device ID"
    $objDevice = Get-DeviceID -DeviceName $device
    Write-Log -Message "Device ID: $($objDevice.DeviceId)"

    Write-Log -Message "Getting ObjectId attributes..."
    $deviceAttributes = Get-AzureAdDeviceExtensionAttribute -ObjectId $($objDevice.ObjectId)
    $deviceAttributes | Format-List
}

Write-Log -Message "Script end."
##########################################################################################################
##########################################################################################################
#endregion Main Script work section