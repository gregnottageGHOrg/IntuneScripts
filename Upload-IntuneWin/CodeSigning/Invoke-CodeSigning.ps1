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
    [Parameter(HelpMessage = 'Provide path to folder to search for files and code sign them'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $Path
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
Write-Host "Using path: $Path" -ForegroundColor Green
$includeFilter = "*.exe", "*.dll,", "*.sys", "*.efi", "*.scr", "*.msi", "*.appx", "*.appxbundle", "*.msix", "*.msixbundle", "*.cat", "*.cab", "*.js", "*.vbs", "*.wsf", "*.ps1", "*.xap"
$files = Get-ChildItem -Path $path -File -Include $includeFilter -Recurse -Force

$signToolPath = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
$dlib = "$PSScriptRoot\microsoft.trusted.signing.client.1.0.52\bin\x64\Azure.CodeSigning.Dlib.dll"
$codeSignJson = "$PSScriptRoot\mazlcodesign.json"

#Test files exist: $signToolPath, $dlib and $codeSignJson
if (-not (Test-Path -Path $signToolPath)) {
    Write-Host "SignTool not found at: $signToolPath" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path -Path $dlib)) {
    Write-Host "Dlib file not found: $dlib" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path -Path $codeSignJson)) {
    Write-Host "Code sign JSON file not found: $codeSignJson" -ForegroundColor Red
    exit 1
}

Foreach ($file in $files) {
    Write-Host "`nCode sign file name: $($file.name)" -ForegroundColor Green

    & $signToolPath sign /v /debug /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 /dlib $dlib /dmdf $codeSignJson "$($file.FullName)"
}
#endregion Main Script work section