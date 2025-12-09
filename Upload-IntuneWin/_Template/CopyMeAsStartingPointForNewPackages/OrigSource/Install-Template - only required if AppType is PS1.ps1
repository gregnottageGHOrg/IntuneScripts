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
[CmdLetBinding()]
param(
    [Parameter()]
    [switch] $install,
    [switch] $unInstall,
    [switch] $userInstall,
    [string] $tagFile,
    [switch] $regTag
)
#$VerbosePreference = "Continue" #Enables Verbose Logging, can be enabled with -verbose on the cmdline too
$script:exitCode = 0
$script:BuildVer = "1.4"
$script:ProgramFiles = $env:ProgramFiles
$script:ParentFolder = $PSScriptRoot | Split-Path -Parent
$script:ScriptName = $myInvocation.MyCommand.Name
$script:ScriptName = $scriptName.Substring(0, $scriptName.Length - 4)
$script:LogName = $scriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
#$script:LogName = $scriptName + "_" + $(Get-Date).ToFileTimeUtc()
if ( $userInstall ) {
    $script:logPath = "$($env:LOCALAPPDATA)\Microsoft\IntuneApps\$scriptName"
}
else {
    #$script:logPath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName"
    $script:logPath = "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs"
}
$script:logFile = "$logPath\$LogName.log"
#Add-Type -AssemblyName Microsoft.VisualBasic
$script:EventLogName = "Application"
$script:EventLogSource = "EventSystem"
$script:transcriptLog = "$logPath\$LogName" + "_Transcript.log"
if ($VerbosePreference -eq 'Continue') { Start-Transcript -Path "$transcriptLog" -Append }
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
    if ([System.Diagnostics.EventLog]::Exists($script:EventLogName) -eq $false) {
        New-EventLog -LogName $EventLogName -Source $EventLogSource
    }
    if ([System.Diagnostics.EventLog]::SourceExists($script:EventLogSource ) -eq $false) {
        [System.Diagnostics.EventLog]::CreateEventSource($script:EventLogSource , $EventLogName)
    }
    #If (!([system.diagnostics.eventlog]::SourceExists($EventLogSource))) { New-EventLog -LogName $EventLogName -Source $EventLogSource }

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

function New-IntuneTag {
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
    param (
        [string]$TagFilePath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName\",
        [string]$tagName
    )

    begin {
        Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
    }

    process {
        # Create a tag file just so Intune knows this was installed
        Write-Log "Creating Intune Tag file path: [$TagFilePath]"

        if (-not (Test-Path $TagFilePath) ) {

            New-Item -Path $TagFilePath -ItemType "directory" -Force | Out-Null
        }

        # Check if tagName already has .tag at the end
        if ($tagName.Substring(($tagName.Length - 4), 4) -eq ".tag") {
            Write-Log -Message "Using passed in tagName: $tagName"
            $tagFileName = "$TagFilePath\$tagName"
        }
        else {
            Write-Log -Message "Using default of scriptname: $tagName and appending .tag"
            $tagFileName = "$TagFilePath\$tagName.tag"
        }

        Write-Log "Creating Intune Tag file: [$tagFileName]"

        Set-Content -Path $tagFileName -Value "Installed"

        Write-Log -Message "Created Intune Tag file: [$tagFileName]"

    }
}

####################################################

function Remove-IntuneTag {
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
    param (
        [string]$TagFilePath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName\",
        [string]$tagName
    )

    begin {
        Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
    }

    process {
        # Remove the tag file so Intune knows this was uninstalled
        # Check if tagName already has .tag at the end
        if ($tagName.Substring(($tagName.Length - 4), 4) -eq ".tag") {
            Write-Log -Message "Using passed in tagName: $tagName"
            $tagFileName = "$TagFilePath\$tagName"
        }
        else {
            Write-Log -Message "Using default of scriptname: $tagName and appending .tag"
            $tagFileName = "$TagFilePath\$tagName.tag"
        }

        Write-Log "Removing Intune Tag file: [$tagFileName]"

        if (Test-Path $tagFileName) {
            Remove-Item -Path $tagFileName -Force
        }

    }
}

####################################################

function New-IntuneRegTag {
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
    param (
        [string]$TagRegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\",
        [string]$tagName
    )

    begin {
        Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
    }

    process {
        # Create a registry tag just so Intune knows this was installed
        Write-Log "Creating Intune Tag file path: [$TagRegPath\$tagName]"

        #Get-ItemProperty -Path "HKLM:\SOFTWARE\$TagRegPath" -Name $tagName

        New-Item -Path "Registry::$TagRegPath" -Force

        $returnCode = New-ItemProperty -Path "Registry::$TagRegPath" -Name $tagName -PropertyType String -Value "Installed" -Force
        Write-Log -Message "Return code: $returnCode"
    }
}

####################################################

function Remove-IntuneRegTag {
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
    param (
        [string]$TagRegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\",
        [string]$tagName
    )

    begin {
        Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
    }

    process {
        # Remove registry tag just so Intune knows this was uninstalled
        Write-Log "Removing Intune Tag file path: [$TagRegPath\$tagName]"

        $returnCode = Remove-ItemProperty -Path "Registry::$TagRegPath" -Name $tagName -Force
        Write-Log -Message "Return code: $returnCode"
    }
}

####################################################

function Test-Null($objectToCheck) {
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

function Test-OOBE {
    $TypeDef = @"

using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Api
{
 public class Kernel32
 {
   [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
   public static extern int OOBEComplete(ref int bIsOOBEComplete);
 }
}
"@

    Add-Type -TypeDefinition $TypeDef -Language CSharp

    $IsOOBEComplete = $false
    $hr = [Api.Kernel32]::OOBEComplete([ref] $IsOOBEComplete)

    #$IsOOBEComplete
    if ($IsOOBEComplete -eq '1') {
        return $true
    }
    else {
        return $false
    }
}

####################################################

Start-Log -FilePath $logFile -DeleteExistingFile
Write-Host
Write-Host "Script log file path is [$logFile]" -ForegroundColor Cyan
Write-Host
Write-Log -Message "Starting $ScriptName version $BuildVer"
Write-Log -Message "Running from location: $PSScriptRoot"
Write-Log -Message "Script log file path is [$logFile]"
Write-Log -Message "Running in 64-bit mode: $([System.Environment]::Is64BitProcess)"
#endregion Initialisation...
##########################################################################################################
##########################################################################################################

#region Main Script work section
##########################################################################################################
##########################################################################################################
#Main Script work section
##########################################################################################################
##########################################################################################################

#region PSAppDeployToolkit Loading
# Support both PSADT v4.x module import and legacy dot-source methods
# Preserve our CMTrace-compatible Write-Log function before loading toolkit
$savedWriteLog = ${function:Write-Log}
$psadtLoaded = $false

# Method 1: Try PSADT v4.x module import (module manifest at script root)
$modulePath = "$PSScriptRoot\PSAppDeployToolkit.psd1"
if (Test-Path $modulePath -PathType Leaf) {
    Write-Log -Message "Found PSAppDeployToolkit module at [$modulePath] - attempting module import"
    try {
        Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
        Import-Module -Name $modulePath -Force -ErrorAction Stop
        $psadtLoaded = $true
        Write-Log -Message "Successfully imported PSAppDeployToolkit module v4.x"
    }
    catch {
        Write-Log -Message "Failed to import PSAppDeployToolkit module: $($_.Exception.Message)" -Severity 2
    }
}

# Method 2: Try legacy dot-source from same folder
if (-not $psadtLoaded) {
    $toolkitPath = "$PSScriptRoot\Invoke-AppDeployToolkit.ps1"
    if (Test-Path $toolkitPath -PathType Leaf) {
        Write-Log -Message "Found AppDeployToolkit at [$toolkitPath] - attempting dot-source"
        try {
            . $toolkitPath
            $psadtLoaded = $true
            Write-Log -Message "Successfully dot-sourced AppDeployToolkit"
        }
        catch {
            Write-Log -Message "Failed to dot-source AppDeployToolkit: $($_.Exception.Message)" -Severity 2
        }
    }
}

# Method 3: Try PSADT v4.x Frontend folder structure
if (-not $psadtLoaded) {
    $frontendPath = "$PSScriptRoot\Frontend\v4\Invoke-AppDeployToolkit.ps1"
    if (Test-Path $frontendPath -PathType Leaf) {
        Write-Log -Message "Found AppDeployToolkit at [$frontendPath] - attempting dot-source"
        try {
            . $frontendPath
            $psadtLoaded = $true
            Write-Log -Message "Successfully dot-sourced AppDeployToolkit from Frontend\v4"
        }
        catch {
            Write-Log -Message "Failed to dot-source AppDeployToolkit from Frontend: $($_.Exception.Message)" -Severity 2
        }
    }
}

# Restore our CMTrace-compatible Write-Log function (toolkit may have overwritten it)
if ($savedWriteLog) {
    ${function:Write-Log} = $savedWriteLog
    if ($psadtLoaded) {
        Write-Log -Message "Restored custom CMTrace-compatible Write-Log function"
    }
}

if (-not $psadtLoaded) {
    Write-Log -Message "PSAppDeployToolkit not found - continuing without toolkit functions" -Severity 2
}
#endregion PSAppDeployToolkit Loading

if ($([System.Environment]::Is64BitProcess)) {
    Write-Log -Message "Running in 64-bit mode, so use normal ProgramFiles path"
    $programFiles = "$($env:ProgramFiles)"
    Write-Log -Message "Running in 64-bit mode, so use normal systemroot path"
    $systemRoot = "$($env:SystemRoot)\System32"
}
else {
    Write-Log -Message "Running in 32-bit mode, adjust to ProgramW6432 path"
    $programFiles = "$($env:ProgramW6432)"
    Write-Log -Message "Running in 32-bit mode, adjust to sysnative path"
    $systemRoot = "$($env:SystemRoot)\sysnative"
}

if ($Install) {
    Write-Log -Message "Performing Install steps..."

    #Your code goes here

    <#
    If ($OOBEComplete -eq $false) {
        Write-Log -Message "Running during OOBE"
        Write-Log -Message "Will force reboot!" -WriteHost Cyan
        $rebootNow = $true
    }
    #>

    #Handle Intune detection method
    if (! ($userInstall) ) {
        Write-Log -Message "Creating detection rule for System install"

        if ( $regTag ) {
            Write-Log -Message "Using RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
            New-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
        }
        else {
            Write-Log -Message "Using FileTag"

            if ( ! ( Test-Null ( $tagFile ) ) ) {
                Write-Log -Message "Using tagFile name: $tagFile"
                New-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
            }
            else {
                Write-Log -Message "Using default tagFile name: $scriptName"
                New-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
            }
        }
    }
    elseif ( $userInstall ) {
        Write-Log -Message "Creating detection rule for User install"

        if ( $regTag ) {
            Write-Log -Message "Using RegTag: HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
            New-IntuneRegTag -TagRegPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
        }
        else {
            Write-Log -Message "Using FileTag: "

            if ( ! ( Test-Null ( $tagFile ) ) ) {
                Write-Log -Message "Using tagFile name: $tagFile"
                New-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
            }
            else {
                Write-Log -Message "Using default tagFile name: $scriptName"
                New-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
            }
        }
    }
}
elseif ( $UnInstall ) {
    Write-Log -Message "Performing Uninstall steps..."

    #Your code goes here

    #Handle Intune detection method
    if (! ($userInstall) ) {
        Write-Log -Message "Removing detection for System install"

        if ( $regTag ) {
            Write-Log -Message "Removing RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
            Remove-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
        }
        else {
            Write-Log -Message "Removing FileTag"

            if ( ! ( Test-Null ( $tagFile ) ) ) {
                Write-Log -Message "Removing tagFile name: $tagFile"
                Remove-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
            }
            else {
                Write-Log -Message "Removing default tagFile name: $scriptName"
                Remove-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
            }
        }
    }
    elseif ( $userInstall ) {
        Write-Log -Message "Removing detection for User install"

        if ( $regTag ) {
            Write-Log -Message "Removing RegTag: HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
            Remove-IntuneRegTag -TagRegPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
        }
        else {
            Write-Log -Message "Removing FileTag: "

            if ( ! ( Test-Null ( $tagFile ) ) ) {
                Write-Log -Message "Removing tagFile name: $tagFile"
                Remove-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
            }
            else {
                Write-Log -Message "Removing default tagFile name: $scriptName"
                Remove-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
            }
        }
    }
}


#Final
if ($rebootNow -eq $true) {
    Write-Log -Message "Rebooting..." -WriteHost Yellow
    Write-Log "$ScriptName completed." -WriteEventLog
    if ($VerbosePreference -eq 'Continue') { $null = Stop-Transcript }
    [Environment]::Exit(1641)# Hard Reboot - i.e. reboot now!
}
else {
    Write-Log "$ScriptName completed." -WriteEventLog
    if ($VerbosePreference -eq 'Continue') { $null = Stop-Transcript }
    exit $exitCode
}
##########################################################################################################
##########################################################################################################
#endregion Main Script work section
