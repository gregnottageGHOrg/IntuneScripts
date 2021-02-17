<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
#Bulk upload script, reads specified subfolder names from IntunePackages.JSON file
[CmdLetBinding(SupportsShouldProcess = $true)]
Param(
    [Parameter(Mandatory = $true, Position = 1,
        HelpMessage = 'Please specify an Azure/Intune admin user name'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $userName,
    [parameter(Position = 2,
        HelpMessage = "Enter name of JSON answer file containing package names to be uploaded")]
    [string]$PackageJSON = 'IntunePackages.JSON',    
    [parameter(Position = 3,
        HelpMessage = "Enter a path to the folder containing the IntunePackages.JSON file")]
    [string]$PackageListFolder = $PSScriptRoot,
    [parameter(Position = 4,
        HelpMessage = "Enter a path to the IntuneWinAppUtil.exe file")]
    [string]$IntuneWinAppUtilPath = $PSScriptRoot
)
Clear-Host
Write-Host "Running process to bulk upload Intune packages..." -ForegroundColor Green
Write-Host "Folder containing the $PackageJSON file: $PackageListFolder" -ForegroundColor Green
Write-Host "Username: $userName" -ForegroundColor Green
Write-Host 
Write-Host "Importing packages:" -ForegroundColor Cyan

(Get-Content -Raw "$PackageListFolder\$PackageJSON" | ConvertFrom-Json) | ForEach-Object { 
    $passThruPackageName = "$PSScriptRoot\$($_.packageName)"
    $passThruFile = "$PSScriptRoot\Upload-IntuneWin.ps1"
    Write-Host
    Write-host "Path to upload script: $passThruFile"
    Write-host "Processing package: $passThruPackageName"
    Write-Host
    #Use & (i.e. Call) instead of Start-Process, as this keeps everything in the same PowerShell process without spawning another session and this is needed
    #to maintain the AAD auth token when the upload script runs
    & "$passThruFile" -UserName $userName -PackagePath $passThruPackageName
}

Write-Host "Process complete." -ForegroundColor Magenta
Write-Host