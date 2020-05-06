<#PSScriptInfo

.VERSION 1.0

.GUID 07e4ef9f-8341-4dc4-bc73-fc277eb6b4e6

.AUTHOR Greg Nottage

.COMPANYNAME Microsoft

.COPYRIGHT

.TAGS Out of Band OS Update

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
Version 1.0:  Original published version.

#>

<#
.SYNOPSIS
Installs the latest Windows 10 quality updates.
.DESCRIPTION
This script uses the PSWindowsUpdate module to install the latest cumulative update for Windows 10.
.EXAMPLE
.\UpdateOS.ps1
#>
# If we are running as a 32-bit process on a 64-bit system, re-launch as a 64-bit process
if (Test-Path "$($env:SystemRoot)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
    & "$($env:SystemRoot)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
    Exit $lastexitcode
}

# Start logging
Start-Transcript "$env:SystemRoot\Temp\Update-OS\Update-OS.log" -Append

# Main logic
$needReboot = $false
$schTaskName = "OutOfBandOSUpdates"

# Modify Scheduled Task to ensure it keeps running until we get the updates deployed
$schTaskTrigger = New-ScheduledTaskTrigger -AtLogOn
Set-ScheduledTask -TaskName $schTaskName -Trigger $schTaskTrigger

# This script is expected to run while connected to the internet
$isOnline = Invoke-WebRequest -UseBasicParsing -Uri "https://www.microsoft.com"
if (!$isOnline) {
    Write-Output "This device appear to NOT be Internet Connected."
    Write-Output "Wait 5 minutes then retry."
    Start-Sleep -Seconds 300
    #Start-Sleep -Seconds 15
}
# Exit if still not connected to the Internet
$isOnline = Invoke-WebRequest -UseBasicParsing -Uri "https://graph.microsoft.com"
if (!$isOnline) {
    Write-Output "This device is still not connected to the Internet, exit for now."
    Return
}

# Check for Module
if ($null -eq (Get-InstalledModule `
            -Name "PSWindowsUpdate" `
            -MinimumVersion 2.1.1.2 `
            -ErrorAction SilentlyContinue)) {

    # Install it...
    Install-PackageProvider -Name NuGet -Force
    Install-Module PSWindowsUpdate -Force
}

# Install all available updates, except SilverLight
Get-WindowsUpdate -Install -NotKBArticleID KB4481252 -IgnoreUserInput -AcceptAll -IgnoreReboot
$needReboot = (Get-WURebootStatus -Silent)

"Reboot required: $needReboot"

# Specify return code
if ($needReboot) {
    #Write-Host "Soft Reboot is needed."
    #Return 3010
    #Write-Host "Hard Reboot is needed."
    #Return 1641
    
    shutdown /r /f /t 180 /c "Emergency patch install requires device reboot. Save your work now."
    # Stop logging
    Stop-Transcript
}
else {
    # Set scheduled task back to event ID trigger start
    $schTaskTrigger = Import-Clixml "$PSScriptRoot\OutOfBandOSUpdatesRebootTaskTrigger.xml"
    Set-ScheduledTask -TaskName $schTaskName -Trigger $schTaskTrigger
    
    # Stop logging
    Stop-Transcript
    
    Return
}
