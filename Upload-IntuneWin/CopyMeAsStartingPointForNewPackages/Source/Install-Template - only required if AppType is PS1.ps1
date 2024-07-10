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
$script:BuildVer = "1.3"
$script:ProgramFiles = $env:ProgramFiles
$script:ParentFolder = $PSScriptRoot | Split-Path -Parent
$script:ScriptName = $myInvocation.MyCommand.Name
$script:ScriptName = $scriptName.Substring(0, $scriptName.Length - 4)
$script:LogName = $scriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
#$script:LogName = $scriptName + "_" + $(Get-Date).ToFileTimeUtc()
If ( $userInstall ) {
    $script:logPath = "$($env:LOCALAPPDATA)\Microsoft\IntuneApps\$scriptName"
}
Else {
    #$script:logPath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName"
    $script:logPath = "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs"
}
$script:logFile = "$logPath\$LogName.log"
#Add-Type -AssemblyName Microsoft.VisualBasic
$script:EventLogName = "Application"
$script:EventLogSource = "EventSystem"
$script:transcriptLog = "$logPath\$LogName" + "_Transcript.log"
If ($VerbosePreference -eq 'Continue') { Start-Transcript -Path "$transcriptLog" -Append }
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
    if ([System.Diagnostics.EventLog]::Exists($script:EventLogName) -eq $false) {
        New-EventLog -LogName $EventLogName -Source $EventLogSource
    }
    if ([System.Diagnostics.EventLog]::SourceExists($script:EventLogSource ) -eq $false) {
        [System.Diagnostics.EventLog]::CreateEventSource($script:EventLogSource , $EventLogName)
    }
    #If (!([system.diagnostics.eventlog]::SourceExists($EventLogSource))) { New-EventLog -LogName $EventLogName -Source $EventLogSource }

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

    If ($WriteEventLog) { Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message $Message  -Id 100 -Category 0 -EntryType Information }
}

####################################################

Function New-IntuneTag {
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
    Param (
        [string]$TagFilePath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName\",
        [string]$tagName
    )

    Begin {
        Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
    }

    Process {
        # Create a tag file just so Intune knows this was installed
        Write-Log "Creating Intune Tag file path: [$TagFilePath]"

        If (-not (Test-Path $TagFilePath) ) {

            New-Item -Path $TagFilePath -ItemType "directory" -Force | out-null
        }

        # Check if tagName already has .tag at the end
        If ($tagName.Substring(($tagName.Length - 4), 4) -eq ".tag") {
            Write-Log -Message "Using passed in tagName: $tagName"
            $tagFileName = "$TagFilePath\$tagName"
        }
        Else {
            Write-Log -Message "Using default of scriptname: $tagName and appending .tag"
            $tagFileName = "$TagFilePath\$tagName.tag"
        }

        Write-Log "Creating Intune Tag file: [$tagFileName]"

        Set-Content -Path $tagFileName -Value "Installed"

        Write-Log -Message "Created Intune Tag file: [$tagFileName]"

    }
}

####################################################

Function Remove-IntuneTag {
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
    Param (
        [string]$TagFilePath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName\",
        [string]$tagName
    )

    Begin {
        Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
    }

    Process {
        # Remove the tag file so Intune knows this was uninstalled
        # Check if tagName already has .tag at the end
        If ($tagName.Substring(($tagName.Length - 4), 4) -eq ".tag") {
            Write-Log -Message "Using passed in tagName: $tagName"
            $tagFileName = "$TagFilePath\$tagName"
        }
        Else {
            Write-Log -Message "Using default of scriptname: $tagName and appending .tag"
            $tagFileName = "$TagFilePath\$tagName.tag"
        }

        Write-Log "Removing Intune Tag file: [$tagFileName]"

        If (Test-Path $tagFileName) {
            Remove-Item -Path $tagFileName -Force
        }

    }
}

####################################################

Function New-IntuneRegTag {
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
    Param (
        [string]$TagRegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\",
        [string]$tagName
    )

    Begin {
        Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
    }

    Process {
        # Create a registry tag just so Intune knows this was installed
        Write-Log "Creating Intune Tag file path: [$TagRegPath\$tagName]"

        #Get-ItemProperty -Path "HKLM:\SOFTWARE\$TagRegPath" -Name $tagName

        New-Item -Path "Registry::$TagRegPath" -Force

        $returnCode = New-ItemProperty -Path "Registry::$TagRegPath" -Name $tagName -PropertyType String -Value "Installed" -Force
        Write-Log -Message "Return code: $returnCode"
    }
}

####################################################

Function Remove-IntuneRegTag {
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
    Param (
        [string]$TagRegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\",
        [string]$tagName
    )

    Begin {
        Write-Log -Message "Starting $($MyInvocation.InvocationName) function..."
    }

    Process {
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
If ($([System.Environment]::Is64BitProcess)) {
    Write-Log -Message "Running in 64-bit mode, so use normal ProgramFiles path"
    $programFiles = "$($env:ProgramFiles)"
    Write-Log -Message "Running in 64-bit mode, so use normal systemroot path"
    $systemRoot = "$($env:SystemRoot)\System32"
}
Else {
    Write-Log -Message "Running in 32-bit mode, adjust to ProgramW6432 path"
    $programFiles = "$($env:ProgramW6432)"
    Write-Log -Message "Running in 32-bit mode, adjust to sysnative path"
    $systemRoot = "$($env:SystemRoot)\sysnative"
}

If ($Install) {
    Write-Log -Message "Performing Install steps..."

    #Your code goes here

    #Handle Intune detection method
    If (! ($userInstall) ) {
        Write-Log -Message "Creating detection rule for System install"

        If ( $regTag ) {
            Write-Log -Message "Using RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
            New-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
        }
        Else {
            Write-Log -Message "Using FileTag"

            If ( ! ( Test-Null ( $tagFile ) ) ) {
                Write-Log -Message "Using tagFile name: $tagFile"
                New-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
            }
            Else {
                Write-Log -Message "Using default tagFile name: $scriptName"
                New-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
            }
        }
    }
    ElseIf ( $userInstall ) {
        Write-Log -Message "Creating detection rule for User install"

        If ( $regTag ) {
            Write-Log -Message "Using RegTag: HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
            New-IntuneRegTag -TagRegPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
        }
        Else {
            Write-Log -Message "Using FileTag: "

            If ( ! ( Test-Null ( $tagFile ) ) ) {
                Write-Log -Message "Using tagFile name: $tagFile"
                New-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
            }
            Else {
                Write-Log -Message "Using default tagFile name: $scriptName"
                New-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
            }
        }
    }
}
ElseIf ( $UnInstall ) {
    Write-Log -Message "Performing Uninstall steps..."

    #Your code goes here

    #Handle Intune detection method
    If (! ($userInstall) ) {
        Write-Log -Message "Removing detection for System install"

        If ( $regTag ) {
            Write-Log -Message "Removing RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
            Remove-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
        }
        Else {
            Write-Log -Message "Removing FileTag"

            If ( ! ( Test-Null ( $tagFile ) ) ) {
                Write-Log -Message "Removing tagFile name: $tagFile"
                Remove-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
            }
            Else {
                Write-Log -Message "Removing default tagFile name: $scriptName"
                Remove-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
            }
        }
    }
    ElseIf ( $userInstall ) {
        Write-Log -Message "Removing detection for User install"

        If ( $regTag ) {
            Write-Log -Message "Removing RegTag: HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
            Remove-IntuneRegTag -TagRegPath "HKEY_CURRENT_USER\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
        }
        Else {
            Write-Log -Message "Removing FileTag: "

            If ( ! ( Test-Null ( $tagFile ) ) ) {
                Write-Log -Message "Removing tagFile name: $tagFile"
                Remove-IntuneTag -TagFilePath "$logPath" -tagName $tagFile
            }
            Else {
                Write-Log -Message "Removing default tagFile name: $scriptName"
                Remove-IntuneTag -TagFilePath "$logPath" -tagName $scriptName
            }
        }
    }
}


Write-Log "$ScriptName completed." -WriteEventLog
If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
exit $exitCode

##########################################################################################################
##########################################################################################################
#endregion Main Script work section
