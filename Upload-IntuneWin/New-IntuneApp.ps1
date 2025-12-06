<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
#Script to create a new IntuneWin package
param(
    [parameter(Mandatory = $true, HelpMessage = "Enter a name for the new package")]
    $Name,
    [parameter(Mandatory = $false, HelpMessage = "Skip PSADT version check")]
    [switch]$SkipPSADTCheck
)

$script:BuildVer = "1.1"

####################################################
# Functions
####################################################

function Get-LocalPSADTVersion {
    <#
    .SYNOPSIS
    Gets the version of the locally installed PSAppDeployToolkit
    #>
    param(
        [string]$PSADTPath
    )

    $manifestPath = Join-Path $PSADTPath "PSAppDeployToolkit.psd1"

    if (Test-Path $manifestPath) {
        try {
            $manifestContent = Get-Content $manifestPath -Raw
            if ($manifestContent -match "ModuleVersion\s*=\s*['""]([^'""]+)['""]") {
                return [version]$matches[1]
            }
        }
        catch {
            Write-Warning "Failed to read local PSADT version: $($_.Exception.Message)"
        }
    }

    return $null
}

####################################################

function Get-GalleryPSADTVersion {
    <#
    .SYNOPSIS
    Gets the latest version of PSAppDeployToolkit from PowerShell Gallery
    #>

    try {
        Write-Host "Checking PowerShell Gallery for latest PSAppDeployToolkit version..." -ForegroundColor Cyan
        $galleryModule = Find-Module -Name PSAppDeployToolkit -Repository PSGallery -ErrorAction Stop
        return [version]$galleryModule.Version
    }
    catch {
        Write-Warning "Failed to check PowerShell Gallery: $($_.Exception.Message)"
        return $null
    }
}

####################################################

function Update-PSADTFromGallery {
    <#
    .SYNOPSIS
    Downloads and extracts the latest PSAppDeployToolkit from PowerShell Gallery
    #>
    param(
        [string]$DestinationPath,
        [version]$Version
    )

    $tempPath = Join-Path $env:TEMP "PSADT_Update_$(Get-Date -Format 'yyyyMMddHHmmss')"

    try {
        Write-Host "Downloading PSAppDeployToolkit v$Version from PowerShell Gallery..." -ForegroundColor Cyan

        # Create temp directory
        New-Item -Path $tempPath -ItemType Directory -Force | Out-Null

        # Save the module to temp location
        Save-Module -Name PSAppDeployToolkit -Path $tempPath -Repository PSGallery -Force -ErrorAction Stop

        # Find the downloaded module path
        $downloadedModulePath = Join-Path $tempPath "PSAppDeployToolkit\$Version"

        if (-not (Test-Path $downloadedModulePath)) {
            # Try without version subfolder (some versions of Save-Module behave differently)
            $downloadedModulePath = Join-Path $tempPath "PSAppDeployToolkit"
        }

        if (Test-Path $downloadedModulePath) {
            # Backup existing PSADT if it exists
            if (Test-Path $DestinationPath) {
                $backupPath = "$DestinationPath`_backup_$(Get-Date -Format 'yyyyMMddHHmmss')"
                Write-Host "Backing up existing PSADT to: $backupPath" -ForegroundColor Yellow
                Rename-Item -Path $DestinationPath -NewName (Split-Path $backupPath -Leaf) -Force
            }

            # Copy new version to destination
            Write-Host "Installing PSAppDeployToolkit v$Version to template..." -ForegroundColor Cyan
            Copy-Item -Path $downloadedModulePath -Destination $DestinationPath -Recurse -Force

            Write-Host "PSAppDeployToolkit updated successfully to v$Version" -ForegroundColor Green
            return $true
        }
        else {
            Write-Warning "Downloaded module not found at expected path"
            return $false
        }
    }
    catch {
        Write-Warning "Failed to update PSAppDeployToolkit: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Cleanup temp directory
        if (Test-Path $tempPath) {
            Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

####################################################

function Invoke-PSADTVersionCheck {
    <#
    .SYNOPSIS
    Checks PSADT version and prompts user to update if newer version available
    #>
    param(
        [string]$TemplatePath
    )

    $psadtPath = Join-Path $TemplatePath "OrigSource\PSAppDeployToolkit"

    # Get local version
    $localVersion = Get-LocalPSADTVersion -PSADTPath $psadtPath

    if ($null -eq $localVersion) {
        Write-Warning "Could not determine local PSAppDeployToolkit version"
        return
    }

    Write-Host "Local PSAppDeployToolkit version: " -NoNewline
    Write-Host "v$localVersion" -ForegroundColor Yellow

    # Get gallery version
    $galleryVersion = Get-GalleryPSADTVersion

    if ($null -eq $galleryVersion) {
        Write-Host "Skipping version check - could not reach PowerShell Gallery" -ForegroundColor Yellow
        return
    }

    Write-Host "Latest PSAppDeployToolkit version: " -NoNewline
    Write-Host "v$galleryVersion" -ForegroundColor Cyan

    # Compare versions
    if ($galleryVersion -gt $localVersion) {
        Write-Host ""
        Write-Host "A newer version of PSAppDeployToolkit is available!" -ForegroundColor Yellow
        Write-Host "Current: v$localVersion -> Available: v$galleryVersion" -ForegroundColor Yellow
        Write-Host ""

        # Prompt user with timeout
        $timeout = 30
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $userResponse = $null

        Write-Host "Do you want to update PSAppDeployToolkit before creating the package? (Y/N)" -ForegroundColor Cyan
        Write-Host "Auto-selecting 'N' (keep current version) in $timeout seconds..." -ForegroundColor Gray

        while ($stopwatch.Elapsed.TotalSeconds -lt $timeout) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq 'Y') {
                    $userResponse = 'Y'
                    Write-Host "Y" -ForegroundColor Green
                    break
                }
                elseif ($key.Key -eq 'N') {
                    $userResponse = 'N'
                    Write-Host "N" -ForegroundColor Yellow
                    break
                }
            }

            $remaining = [math]::Ceiling($timeout - $stopwatch.Elapsed.TotalSeconds)
            Write-Host "`r($remaining seconds remaining) " -NoNewline
            Start-Sleep -Milliseconds 500
        }

        $stopwatch.Stop()
        Write-Host ""

        if ($userResponse -eq 'Y') {
            $updateResult = Update-PSADTFromGallery -DestinationPath $psadtPath -Version $galleryVersion
            if ($updateResult) {
                Write-Host "Template will use PSAppDeployToolkit v$galleryVersion" -ForegroundColor Green
            }
            else {
                Write-Host "Update failed - continuing with existing version v$localVersion" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "Keeping current PSAppDeployToolkit version v$localVersion" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "PSAppDeployToolkit is up to date (v$localVersion)" -ForegroundColor Green
    }

    Write-Host ""
}

####################################################
# Main Script
####################################################

Set-Location -Path "$PSScriptRoot"
$NewPackageName = "$PSScriptRoot\$Name"
$sourcePath = "$PSScriptRoot\_Template\CopyMeAsStartingPointForNewPackages"

Write-Host ""
Write-Host "New-IntuneApp v$script:BuildVer" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""

# Check PSADT version before cloning (unless skipped)
if (-not $SkipPSADTCheck) {
    Invoke-PSADTVersionCheck -TemplatePath $sourcePath
}

Write-Host "Cloning template to: $NewPackageName" -ForegroundColor Cyan

try {
    Copy-Item -Path $sourcePath -Destination $NewPackageName -Recurse -Force -ErrorAction Stop
    #Rename-Item -Path "$NewPackageName\Source\Install-Template - only required if AppType is PS1.ps1" -NewName "$Name.ps1"
    Rename-Item -Path "$NewPackageName\OrigSource\Install-Template - only required if AppType is PS1.ps1" -NewName "$Name.ps1"
}
catch {
    Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
    exit
}

Write-Host ''
Write-Host '-----------------------------------------------------------------------' -ForegroundColor cyan
Write-Host ' New package folder created' -ForegroundColor Yellow
Write-Host
Write-Host ' Next Steps:-'
Write-Host
Write-Host ' 1. Copy the package content into ' -NoNewline
Write-Host $NewPackageName'\OrigSource' -ForegroundColor green
Write-Host ' 2. Copy the logo png file into ' -NoNewline
Write-Host $NewPackageName -ForegroundColor green
Write-Host ' 3. Run ' -NoNewline
Write-Host ".\Set-Config.ps1 -Name $Name" -ForegroundColor green
Write-Host '-----------------------------------------------------------------------' -ForegroundColor cyan
Write-Host ''