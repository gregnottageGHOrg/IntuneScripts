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

#Restart as 64-bit
if (![System.Environment]::Is64BitProcess) {
    $additionalArgs = ''
    foreach ($Param in $PSBoundParameters.GetEnumerator()) {
        if (-not $MyInvocation.MyCommand.Parameters[$Param.key].SwitchParameter) {
            $additionalArgs += "-$($Param.Key) $($Param.Value) "
        }
        else {
            $additionalArgs += "-$($Param.Key) "
        }
    }

    # start new PowerShell as x64 bit process, wait for it and gather exit code and standard error output
    $sysNativePowerShell = "$($PSHOME.ToLower().Replace("syswow64", "sysnative"))\powershell.exe"

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $sysNativePowerShell
    $pinfo.Arguments = "-ex bypass -file `"$PSCommandPath`" $additionalArgs"
    $pinfo.RedirectStandardError = $true
    #$pinfo.RedirectStandardOutput = $true
    $pinfo.CreateNoWindow = $true
    
    #$pinfo.RedirectStandardError = $false
    #$pinfo.RedirectStandardOutput = $false
    #$pinfo.CreateNoWindow = $false
    
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null

    #$exitCode = $p.ExitCode

    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($stderr) { Write-Error -Message $stderr }
}
Else {

    $script:BuildVer = "1.1"
    $script:ProgramFiles = $env:ProgramFiles
    $script:ParentFolder = $PSScriptRoot | Split-Path -Parent
    $script:ScriptName = $myInvocation.MyCommand.Name
    $script:ScriptName = $scriptName.Substring(0, $scriptName.Length - 4)
    $script:LogName = $scriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
    If ( $userInstall ) {
        $script:logPath = "$($env:LOCALAPPDATA)\Microsoft\IntuneApps\$scriptName"
    }
    Else { 
        $script:logPath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName" 
    }
    $script:logFile = "$logPath\$LogName.log"
    Add-Type -AssemblyName Microsoft.VisualBasic
    $script:EventLogName = "Application"
    $script:EventLogSource = "EventSystem"
    If ($VerbosePreference -eq 'Continue') { Start-Transcript -Path "$logPath\Transcript.log" -Append -IncludeInvocationHeader }
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

    Start-Log -FilePath $logFile -DeleteExistingFile
    Write-Host
    Write-Host "Script log file path is [$logFile]" -ForegroundColor Cyan
    Write-Host
    Write-Log -Message "Starting $ScriptName version $BuildVer" -WriteEventLog
    Write-Log -Message "Running from location: $PSScriptRoot" -WriteEventLog
    Write-Log -Message "Script log file path is [$logFile]" -WriteEventLog
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
    $mcsPath = "$env:ProgramFiles\MCS"
    $targetPath = "$mcsPath\Set-Windows10LanguagePack"
    $scheduledTask = 'Set-Windows10LanguagePack'

    If ($Install) {
        Write-Log -Message "Performing Install steps..."

        #region create folder
        Write-Log -Message "Creating folder: $targetPath" -WriteEventLog
        Try {
            New-Item -Path $targetPath -ItemType "directory" -Force -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw 
        }
        #endregion create folder

        #region copy files
        Write-Log -Message "Copying package content to: $targetPath" -WriteEventLog
        Try {
            Copy-Item -Path "$PSScriptRoot\*" -Exclude "$ScriptFullName", "New-LanguageOutput.ps1", "Set-Windows10LanguagePack.xml" -Destination $targetPath -Recurse -Force -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw 
        }
        #endregion copy files

        #region create scheduled task
        Write-Log -Message "Register scheduled task" -WriteEventLog
        Try {
            Register-ScheduledTask -Xml (get-content "$PSScriptRoot\Set-Windows10LanguagePack.xml" | out-string) -TaskName $scheduledTask -Force -ErrorAction Stop
        }        
        Catch [Exception] {
            Write-Log -Message "Error occurred: $($_.Exception.message)"
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw
        }
        #endregion create scheduled task

        #region create shortcut
        Write-Log -Message "Create Start Menu shortcut: $env:ProgramData\Microsoft\Windows\Start Menu\Programs\Set-Windows10LanguagePack" -WriteEventLog
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Set-Windows10LanguagePack.lnk")
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = '-ExecutionPolicy Bypass -WindowStyle Hidden -file "' + $targetPath + '\Invoke-SetWindows10LanguagePack.ps1"'
        $Shortcut.Save()
        #Start-ScheduledTask -TaskName 'Set-Windows10LanguagePack'
        #endregion create shortcut

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

        #region remove scheduled task
        Write-Log -Message "Stopping scheduled task: $scheduledTask" -WriteEventLog
        Try {
            Disable-ScheduledTask -TaskName $scheduledTask -InformationAction SilentlyContinue -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw 
        }

        Write-Log -Message "Removing scheduled task: $scheduledTask" -WriteEventLog
        Try {
            Unregister-ScheduledTask -TaskName $scheduledTask -Confirm:$false -InformationAction SilentlyContinue -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw 
        }
        #endregion remove scheduled task

        #region remove shortcut
        Write-Log -Message "Removing file: $env:ProgramData\Microsoft\Windows\Start Menu\Programs\Set-Windows10LanguagePack.lnk" -WriteEventLog
        Try {
            Remove-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Set-Windows10LanguagePack.lnk" -Force -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw 
        }
        #endregion remove shortcut 

        #region remove target folder
        Write-Log -Message "Removing folder: $targetPath" -WriteEventLog
        Try {
            Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "Error occurred: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw 
        }
        #endregion remove target folder              

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

    ##########################################################################################################
    ##########################################################################################################
    #endregion Main Script work section
}