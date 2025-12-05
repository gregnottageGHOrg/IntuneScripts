#region Initialisation...
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
#Script to code sign relevant files
####################################################
####################################################
#Instantiate Vars
####################################################
[CmdLetBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'Provide path to folder to code sign then upload to Intune. OrigSource should be a subfolder in this path!'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $PackagePath,

    [Parameter(HelpMessage = 'Provide full-path to the ACS Code-Signing script'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $ACSScriptFullPath = "C:\Intune\IntuneApps\CodeSigning\Invoke-CodeSigning.ps1",

    [Parameter(HelpMessage = 'Provide full-path to the Intune Upload script'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $UploadScriptFullPath = "C:\Intune\IntuneApps\Upload-IntuneWin.ps1",

    [Parameter(HelpMessage = 'Please enter folder path containing IntuneWinAppUtil.exe'
    )]
    [string] $IntuneWinAppUtilPath,

    [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $True,
        HelpMessage = 'Please specify Azure App Registration (Service Principle) Application (client) ID'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("AppID")]
    [string] $ClientID,

    [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $True,
        HelpMessage = 'Please specify Azure Tenant ID'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $TenantID,

    [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $True,
        HelpMessage = 'Please specify Azure App Registration (Service Principle) Client Secret'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("Secret")]
    [string] $ClientSecret,

    [Parameter(ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Provide Azure App Registration (Service Principle) Certificate name'
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
    [switch] $NewTagPath
)
#endregion Initialisation...
##########################################################################################################
##########################################################################################################
#region Main Script work section
##########################################################################################################
##########################################################################################################
#Main Script work section
##########################################################################################################
##########################################################################################################

Write-Host "`nUsing path: $PackagePath`n" -ForegroundColor Green

#region Prep Parameters
$hashtable = [hashtable] $PSBoundParameters
$hashtable.Remove('ACSScriptFullPath')
$hashtable.Remove('UploadScriptFullPath')
#endregion Prep Parameters

#region Validate Path
if ((Split-Path -Path $PackagePath -Leaf) -eq 'Source') {
    throw 'Error with supplied path, do not point to Source subfolder!'
}
if ((Split-Path -Path $PackagePath -Leaf) -eq 'OrigSource') {
    throw 'Error with supplied path, do not point to OrigSource subfolder!'
}
#endregion Validate Path

#region Prep Source folder
if (Test-Path -Path "$PackagePath\Source") {
    Write-Host "Existing path found: `"$PackagePath\Source`", removing... `n" -ForegroundColor Cyan

    try {
        Write-Host "Removing: `"$PackagePath\Source`"`n" -ForegroundColor Yellow
        Remove-Item -Path "$PackagePath\Source" -Recurse -Force -ErrorAction Stop
    }
    catch {
        throw
    }
}

try {
    Write-Host "Create folder: `"$PackagePath\Source`"`n" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path "$PackagePath\Source" -Force -ErrorAction Stop
}
catch {
    throw
}
#endregion Prep Source folder

#region Copy OrigSource to Source
if (Test-Path -Path "$PackagePath\OrigSource") {
    Write-Host "`nCopy Source content, ready to code-sign`n" -ForegroundColor Cyan
    Robocopy "$PackagePath\OrigSource" "$PackagePath\Source" /MIR /MT:4 #Mirror folder structure and use 4 threads for speed
}
else {
    throw "Path not found: `"$PackagePath\OrigSource`""
}
#endregion  Copy OrigSource to Source

#region Invoke Code-Sign
Write-Host "Call Code-Signing script: $ACSScriptFullPath`n" -ForegroundColor Cyan
& $ACSScriptFullPath -Path "$PackagePath\Source"
#endregion Invoke Code-Sign

#region Invoke Upload script
Write-Host "`nCall Upload script: $UploadScriptFullPath`n" -ForegroundColor Cyan
& $UploadScriptFullPath @hashtable
#endregion Invoke Upload script

#endregion Main Script work section
##########################################################################################################
##########################################################################################################