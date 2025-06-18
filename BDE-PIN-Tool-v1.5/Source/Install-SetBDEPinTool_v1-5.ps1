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

    $exitCode = $p.ExitCode

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
    #Add-Type -AssemblyName Microsoft.VisualBasic
    $script:EventLogName = "Application"
    $script:EventLogSource = "EventSystem"
    If ($VerbosePreference -eq 'Continue') { Start-Transcript -Path "$logPath\Transcript.log" -Append }
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

            If (-Not(Test-Path $XMLFile)) {
                Write-Log -Message "Error - XML file not found: $XMLFile" -LogLevel 3
                Return $Skip = $true
            }
            Write-Log -Message "Reading XML file: $XMLFile"
            [xml]$script:XML_Content = Get-Content $XMLFile

            ForEach ($XMLEntity in $XML_Content.GetElementsByTagName("Azure_Settings")) {
                $script:baseUrl = [string]$XMLEntity.baseUrl
                $script:logRequestUris = [string]$XMLEntity.logRequestUris
                $script:logHeaders = [string]$XMLEntity.logHeaders
                $script:logContent = [string]$XMLEntity.logContent
                $script:azureStorageUploadChunkSizeInMb = [int32]$XMLEntity.azureStorageUploadChunkSizeInMb
                $script:sleep = [int32]$XMLEntity.sleep
            }

            ForEach ($XMLEntity in $XML_Content.GetElementsByTagName("IntuneWin_Settings")) {
                $script:PackageName = [string]$XMLEntity.PackageName
                $script:displayName = [string]$XMLEntity.displayName
                $script:Description = [string]$XMLEntity.Description
                $script:Publisher = [string]$XMLEntity.Publisher
            }

        }

        End {
            If ($Skip) { Return }# Just return without doing anything else
            Write-Log -Message "Returning..."
            Return
        }

    }

    ####################################################

    Function Show-PWPromptForm {
        <#
.SYNOPSIS
This function shows a password prompt form
.DESCRIPTION
This function shows a password prompt form
.EXAMPLE
Show-PWPromptForm -promptMsg "Enter your network password"
This function shows a password prompt form
.NOTES
NAME: Show-PWPromptForm
#>

        [cmdletbinding()]

        param
        (
            [Parameter(Mandatory = $true)]
            [string]$promptTitle,

            [Parameter(Mandatory = $true)]
            [string]$promptMsg
        )

        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {

            <# Build Form #>
            Write-Log -Message "Preparing form."

            # Bring in the Windows Forms Library
            Add-Type -assembly System.Windows.Forms

            # Generate the form
            $Form = New-Object System.Windows.Forms.Form

            # Window Font
            $Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)

            # Font styles are: Regular, Bold, Italic, Underline, Strikeout
            $Form.Font = $Font

            # Window Basics
            $Form.Text = $promptTitle
            $Form.Width = 350
            $Form.Height = 300
            $Form.AutoSize = $true
            $Form.MinimizeBox = $False
            $Form.MaximizeBox = $False
            $Form.ControlBox = $True
            $Form.WindowState = "Normal"
            # Maximized, Minimized, Normal
            $Form.SizeGripStyle = "Hide"
            # Auto, Hide, Show
            $Form.ShowInTaskbar = $False
            $Form.Opacity = 1.0
            # 1.0 is fully opaque; 0.0 is invisible
            $Form.StartPosition = "CenterScreen"
            $Form.TopMost = $True
            # CenterScreen, Manual, WindowsDefaultLocation, WindowsDefaultBounds, CenterParent

            <# Header Text #>

            # Create the label
            $lbl_HeaderText = New-Object System.Windows.Forms.Label

            # Create Instruction String
            $lbl_InstructionString = $promptMsg

            # Label Basics
            $lbl_HeaderText.Text = $lbl_InstructionString
            $lbl_HeaderText.Location = New-Object System.Drawing.Point(10, 10)
            $lbl_HeaderText.AutoSize = $true

            # Add to form
            $Form.Controls.Add($lbl_HeaderText)

            # Create the label
            $lbl_TxbHeader1 = New-Object System.Windows.Forms.Label

            # Label Basics
            $lbl_TxbHeader1.Text = "Enter Password"
            $lbl_TxbHeader1.Location = New-Object System.Drawing.Point(20, 70)
            $lbl_TxbHeader1.AutoSize = $true

            # Add to form
            $Form.Controls.Add($lbl_TxbHeader1)

            # Create the label
            $lbl_TxbHeader2 = New-Object System.Windows.Forms.Label

            # Label Basics
            $lbl_TxbHeader2.Text = "Repeat Password"
            $lbl_TxbHeader2.Location = New-Object System.Drawing.Point(20, 130)
            $lbl_TxbHeader2.AutoSize = $true

            # Add to form
            $Form.Controls.Add($lbl_TxbHeader2)

            # Create the label
            $lbl_FeedbackMsg = New-Object System.Windows.Forms.Label

            # Label Basics
            $lbl_FeedbackMsg.Text = "Passwords Do Not Match"
            $lbl_FeedbackMsg.ForeColor = "Red"
            $lbl_FeedbackMsg.Location = New-Object System.Drawing.Point(20, 230)
            $lbl_FeedbackMsg.AutoSize = $true
            $lbl_FeedbackMsg.Visible = $false

            # Add to form
            $Form.Controls.Add($lbl_FeedbackMsg)

            <# Text Boxes #>

            # Create Pw Box 1
            $txb_PwEnter1 = New-Object System.Windows.Forms.MaskedTextBox

            # Set Params
            $txb_PwEnter1.Width = 200
            $txb_PwEnter1.Height = 50
            $txb_PwEnter1.Location = New-Object System.Drawing.Point(20, 95)
            $txb_PwEnter1.PasswordChar = '*'

            # Add to Form
            $Form.Controls.Add($txb_PwEnter1)

            # Create Pw Box 2
            $txb_PwEnter2 = New-Object System.Windows.Forms.MaskedTextBox

            # Set Params
            $txb_PwEnter2.Width = 200
            $txb_PwEnter2.Height = 50
            $txb_PwEnter2.Location = New-Object System.Drawing.Point(20, 155)
            $txb_PwEnter2.PasswordChar = '*'

            # Add to Form
            $Form.Controls.Add($txb_PwEnter2)

            <# Buttons #>

            # Create a button
            $btn_InstallPrinters = New-Object System.Windows.Forms.Button

            # Button basics
            $btn_InstallPrinters.Location = New-Object System.Drawing.Size(20, 200)
            $btn_InstallPrinters.Size = New-Object System.Drawing.Size(150, 25)
            $btn_InstallPrinters.Text = "Install Printers"
            #$btn_InstallPrinters.DialogResult = [System.Windows.Forms.DialogResult]::OK

            $Form.AcceptButton = $btn_InstallPrinters

            # Set Function Handler
            $btn_InstallPrinters.Add_Click( {

                    # Set Error Conditions
                    $InputErrorPresent = $false
                    $InputErrorMessage = "Unspecified Input Error"

                    # Check if the PWs Match
                    if ($txb_PwEnter1.Text -ne $txb_PwEnter2.Text) {
                        # Set Error Conditions
                        $InputErrorPresent = $true
                        $InputErrorMessage = "Entered Passwords do not match"

                        Write-Log -Message "User entered mismatched Passwords"
                    }

                    # Check if 1st PW box empty
                    if ( IsNull ( $txb_PwEnter1.Text ) ) {
                        # Set Error Conditions
                        $InputErrorPresent = $true
                        $InputErrorMessage = "Enter your password"

                        Write-Log -Message "1st PW box empty"
                    }

                    # Check if the error flag has been set
                    if ($InputErrorPresent) {
                        # Set and show error
                        $lbl_FeedbackMsg.Text = $InputErrorMessage
                        $lbl_FeedbackMsg.Visible = $true

                        Write-Log -Message "Button clicked, but error message shown"

                        Return

                    }
                    else {
                        # Clear Error Message
                        $lbl_FeedbackMsg.Visible = $false

                        Write-Log -Message "Passwords entered correctly"

                    }

                    Write-Log -Message "Returning with password string"
                    $Script:pw = $txb_PwEnter1.Text

                    # Now Close the form
                    $Form.Close()

                    Return

                })

            # Add to Form
            $Form.Controls.Add($btn_InstallPrinters)

            <# Show the Form #>
            Write-Log -Message "Form onscreen"
            #Set-Content -Path "C:\Windows\Temp\PPForm.tag" -Value "Running..."
            $Form.ShowDialog()

        }
    }

    ####################################################

    Function Is-VM {
        <#
.SYNOPSIS
This function checks WMI to determine if the device is a VM
.DESCRIPTION
This function checks WMI to determine if the device is a VM
.EXAMPLE
Is-VM
This function checks WMI to determine if the device is a VM
.NOTES
NAME: Is-VM
#>

        [CmdletBinding()]
        Param ()

        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {
            Write-Log -Message "Checking WMI class: Win32_ComputerSystem for string: *virtual*"
            Try {
                $ComputerSystemInfo = Get-CIMInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                #$ComputerSystemInfo
                if ($ComputerSystemInfo.Model -like "*virtual*") {
                    Write-Log -Message "Virtual string detected"
                    $True
                }
                else {
                    Write-Log -Message "Virtual string not found"
                    $False
                }
            }
            Catch [Exception] {
                Write-Log -Message "Error occurred: $($_.Exception.message)"
                Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            }
        }

        End {
            Write-Log -Message "Ending: $($MyInvocation.Mycommand)"
        }
    }

    ####################################################

    Function Install-Hotfix {
        <#
.SYNOPSIS
This function installs the specified Hotfix
.DESCRIPTION
This function installs the specified Hotfix
.EXAMPLE
Install-Hotfix -HotFixID KBxxxxxx.msu
This function installs the specified Hotfix
.NOTES
NAME: Install-Hotfix
#>

        [CmdletBinding()]
        Param (

            [Parameter(Mandatory = $true)]
            [string]$HotFixID

        )

        Begin {
            Write-Log -Message "$($MyInvocation.InvocationName) function..."
        }

        Process {
            If (get-hotfix | Where-Object { $_.HotFixID -match $HotFixID }) {
                Write-Log -Message "Hotfix: $HotFixID already installed, returning."
                Return "Installed"
            }
            Write-Log -Message "Running Hotfix install for: wusa.exe ""$PSScriptRoot\$HotFixID"" /quiet /norestart /log:""$logPath\wusa.evtx"""
            Try {
                Start-Process -FilePath "wusa.exe" -ArgumentList """$PSScriptRoot\$HotFixID"" /quiet /norestart /log:""$logPath\wusa.evtx""" -WorkingDirectory "$PSScriptRoot" -Wait -WindowStyle Hidden -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Error occurred deploying Hotfix: $($_.Exception.message)"
                Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
                Return "Failed"
            }

            <#
        If (get-hotfix | Where-Object {$_.HotFixID -match $HotFixID}) {
            Write-Log -Message "Hotfix: $HotFixID successfully installed."
            Return "Installed"
        }
        Else {
            Write-Log -Message "Error - something went wrong installing Hotfix: $HotFixID"
            Return "Failed"
        }
        #>
        }

        End {
            Write-Log -Message "Ending: $($MyInvocation.Mycommand)"
        }
    }

    ####################################################

    function Get-ActiveUser {
        <#
    .SYNOPSIS
        Retrive list of active users on windows machine

    .DESCRIPTION
        Uses WMI, CIM or Query.exe

        This module was created with a powershell.org blogpost in mind
        http://powershell.org/wp/2015/08/28/list-users-logged-on-to-your-machines/
        Created by Jonas Sommer Nielsen

    .PARAMETER ComputerName / CN / IP / Hostname
        Optional: Specifies a remote computer to target

    .PARAMETER Method
        Optional: Specifies the method to retrieve logged on users. Query, CIM, WMI

    .PARAMETER Credential
        Optional: Specifies alternative credentials to use for the WMI connection

    .EXAMPLE
        Get-ActiveUser
        Retrieves all users currently logged into the local machine

    .EXAMPLE
        Get-ActiveUser -ComputerName TestComputer -Method CIM
        Retrieves all users currently logged into the remote machine "TestComputer" using CIM

    .EXAMPLE
        Get-ActiveUser -ComputerName TestComputer -Method WMI -Credential (Get-Credential)
        Retrieves all users currently logged into the remote machine "TestComputer" using WMI.
        This will prompt for credentials to authenticate the connection.

    .ExternalHelp
        https://github.com/mrhvid/Get-ActiveUser

    .NOTES
        Author: Jonas Sommer Nielsen
        Revised: Ian Mott
    #>

        [CmdletBinding(DefaultParameterSetName = 'Standard Parameters',
            SupportsShouldProcess = $false,
            PositionalBinding = $false,
            HelpUri = 'https://github.com/mrhvid/Get-ActiveUser',
            ConfirmImpact = 'Medium')]
        [Alias()]
        [OutputType([string[]])]
        Param
        (
            # Computer name, IP, Hostname
            [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
                HelpMessage = "Default set to localhost",
                Position = 0)]
            [Alias("CN", "IP", "Hostname")]
            [String]
            $ComputerName = $ENV:COMPUTERNAME,

            # Choose method, WMI, CIM or Query
            [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
                HelpMessage = "Default set to WMI",
                Position = 1)]
            [ValidateSet('WMI', 'CIM', 'Query')]
            [String]
            $Method = "WMI",

            # Specify Credentials for the remote WMI/CIM queries
            [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
                HelpMessage = "This is only required for WMI connections. Try the Query or CIM method?",
                Position = 2)]
            [pscredential]
            $Credential
        )

        Begin {
            Write-Verbose -Message "VERBOSE: Starting Begin"

            $Params = @{}

            if ($ComputerName -notin ($ENV:COMPUTERNAME, "localhost", "127.0.0.1")) {
                if ($Method -in ("WMI", "CIM")) {
                    $Params.Add("ComputerName", $ComputerName)

                    if ($Credential -and $Method -eq "WMI") {
                        $Params.Add("Credential", $Credential)
                    }
                }

                if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {
                    Write-Verbose -Message "VERBOSE: Confirmed $ComputerName is reachable by ping"

                    if (Test-WSMan @Params -ErrorAction SilentlyContinue -ErrorVariable error_WSMan) {
                        Write-Verbose -Message "VERBOSE: Successfully connected with WSMan"
                    }
                    else {
                        Write-Error -Message "ERROR: Failed to connect with WSMan. ErrorMessage: $error_WSMan" -RecommendedAction Stop
                    }

                }
                else {
                    Write-Error -Message "ERROR: Could not reach $ComputerName by ping. Confirm the computer is reachable." -RecommendedAction Stop
                }

            }
            else {
                Write-Verbose -Message "VERBOSE: ComputerName not set to a remote machine. No need to check for connectivity."
            }

            Write-Verbose -Message "VERBOSE: Ending Begin"
        }
        Process {
            Write-Verbose -Message "VERBOSE: Starting Process"

            Write-Verbose "$Method selected as method"

            switch ($Method) {
                'WMI' {
                    Write-Verbose "Contacting $ComputerName via WMI"

                    $WMI = (Get-WmiObject Win32_LoggedOnUser @Params).Antecedent

                    $ActiveUsers = @()
                    foreach ($User in $WMI) {
                        $StartOfUsername = $User.LastIndexOf('=') + 2
                        $EndOfUsername = $User.Length - $User.LastIndexOf('=') - 3
                        $ActiveUsers += $User.Substring($StartOfUsername, $EndOfUsername)
                    }
                    $ActiveUsers = $ActiveUsers | Select-Object -Unique

                }
                'CIM' {
                    Write-Verbose "Contacting $ComputerName via CIM"
                    $ActiveUsers = (Get-CimInstance Win32_LoggedOnUser @Params).antecedent.name | Select-Object -Unique

                }
                'Query' {
                    Write-Verbose "Contacting $ComputerName via Query"
                    $Template = @'
USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>{USER*:jonas}                 console             1  Active    1+00:27  24-08-2015 22:22
{USER*:test}                                      2  Disc      1+00:27  25-08-2015 08:26
>{USER*:mrhvid}                rdp-tcp#2           2  Active          .  9/1/2015 8:54 PM
'@

                    $Query = query.exe user /server $ComputerName
                    $ActiveUsers = $Query | ConvertFrom-String -TemplateContent $Template | Select-Object -ExpandProperty User
                }

            }

            Write-Verbose -Message "VERBOSE: Ending process"
        }
        End {
            Write-Verbose -Message "VERBOSE: Starting End"

            # Create nice output format
            $UsersComputersToOutput = @()
            foreach ($User in $ActiveUsers) {
                $UsersComputersToOutput += New-Object psobject -Property @{ComputerName = $ComputerName; UserName = $User }
            }

            Write-Verbose -Message "VERBOSE: Ending End"

            # output data
            #$UsersComputersToOutput
            Return $UsersComputersToOutput
        }
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
    #region IntuneCodeSample
    # === variant 1: use try/catch with ErrorAction stop -> use write-error to signal Intune failed execution
    # example:
    # try
    # {
    #     Set-ItemProperty ... -ErrorAction Stop
    # }
    # catch
    # {
    #     Write-Error -Message "Could not write regsitry value" -Category OperationStopped
    #     $exitCode = -1
    # }

    # === variant 2: ErrorVariable and check error variable -> use write-error to signal Intune failed execution
    # example:
    # Start-Process ... -ErrorVariable err -ErrorAction SilentlyContinue
    # if ($err)
    # {
    #     Write-Error -Message "Could not write regsitry value" -Category OperationStopped
    #     $exitCode = -1
    # }
    #endregion IntuneCodeSample

    #endregion Initialisation...
    ##########################################################################################################
    ##########################################################################################################

    #region Main Script work section
    ##########################################################################################################
    ##########################################################################################################
    #Main Script work section
    ##########################################################################################################
    ##########################################################################################################

    If ($Install) {
        Write-Log -Message "Performing Install steps..."

        $EventLogName = "Bitlocker Setup"
        $EventLogSource = "PS-Bitlocker-SetupScript"

        $ProgramFilesPathTail = "\MCS\BitlockerScripts"

        $ForceScriptRootPath = "C:\Program Files"
        $RegistrySavePath = "\Software\MCS\SetBitlocker"
        #$RegistryFveLocation = "HKLM:\Software\Policies\Microsoft\FVE"
        #$RegistryConnectedStbyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"

        $SchTaskNamePrompt = "BLTOOL-USRPROMPT"
        $SchTaskNameBckgW = "BLTOOL-BCKGWTCH"
        $SchTaskNameStatusMessage = "StatusMessage"
        $SchTaskNameBDEPINReset = "BDE-PIN_Reset"

        $initialInstall = $True

        <#
    #Enable Max Performance Power Overlay
    Write-Log -Message "Enabling Max Performance Power Overlay"
    $command = "powercfg.exe /overlaysetactive overlay_scheme_max"
    $workDir = "$env:SystemRoot\System32"
    Try {
        Start-Process -FilePath $command -WorkingDirectory $workDir -Wait -WindowStyle Hidden -ErrorAction Stop
    }
    Catch {
        Write-Log -Message "Error occurred trying to enable Max Performance Power Overlay: $($_.Exception.message)"
    }

    # Enable Scheduled Tasks All History option
    $logName = 'Microsoft-Windows-TaskScheduler/Operational'
    $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
    $log.IsEnabled = $true
    $log.SaveChanges()
#>

        <# Setup Event Logging #>
        New-Eventlog -LogName $EventLogName -Source $EventLogSource -ErrorAction SilentlyContinue

        $eventSources = @("PS-Bitlocker-SetupScript", "PS-Bitlocker-BackgroundWatcher", "PS-Bitlocker-UserPrompt" )
        foreach ($source in $eventSources) {
            if ([System.Diagnostics.EventLog]::SourceExists($source) -eq $false) {
                [System.Diagnostics.EventLog]::CreateEventSource($source, $EventLogName)
            }
        }

        <# Announce Our Presence #>
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Bitlocker Tool Setup Script Started"  -Id 100 -Category 0 -EntryType Information

        # Check for existing tag files, to determine if previous deployment occurred.
        If (Test-Path -Path "C:\ProgramData\Microsoft\BDE-PIN\BDE-PIN.ps1.tag") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Existing tag file found: C:\ProgramData\Microsoft\BDE-PIN\BDE-PIN.ps1.tag"  -Id 100 -Category 0 -EntryType Information
            $initialInstall = $False
        }
        ElseIf (Test-Path -Path "C:\ProgramData\Microsoft\IntuneApps\Install-SetBDEPinTool\Install-SetBDEPinTool.tag") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Existing tag file found: C:\ProgramData\Microsoft\IntuneApps\Install-SetBDEPinTool\Install-SetBDEPinTool.tag"  -Id 100 -Category 0 -EntryType Information
            $initialInstall = $False
        }
        ElseIf (Test-Path -Path "C:\ProgramData\Microsoft\IntuneApps\Setup-BitlockerPinTool\Setup-BitlockerPinTool.tag") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Existing tag file found: C:\ProgramData\Microsoft\IntuneApps\Setup-BitlockerPinTool\Setup-BitlockerPinTool.tag"  -Id 100 -Category 0 -EntryType Information
            $initialInstall = $False
        }
        ElseIf (Test-Path -Path "C:\ProgramData\Microsoft\IntuneApps\Install-SetBDEPinTool_v1-5\Install-SetBDEPinTool_v1-5.tag") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Existing tag file found: C:\ProgramData\Microsoft\IntuneApps\Install-SetBDEPinTool_v1-5\Install-SetBDEPinTool_v1-5.tag"  -Id 100 -Category 0 -EntryType Information
            $initialInstall = $False
        }

        <# Figure Out Where This Script Is #>
        $InvocationPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Script is running at $InvocationPath"  -Id 100 -Category 0 -EntryType Information

        <# Check required scripts are with us #>
        if ( !(Test-Path "$InvocationPath\BackgroundWatcher-ImplementUserPin.ps1") -or !(Test-Path "$InvocationPath\UserInteract-EnterBitlockerPin.ps1")) {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Required scripts are not alongside setup script in folder, exiting"  -Id 100 -Category 0 -EntryType Information
            break
        }

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Required script files are present"  -Id 100 -Category 0 -EntryType Information

        <# Figure Out Where To Put Scripts #>
        $OSArchitecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture

        # Create Source Path
        If ($OSArchitecture -like '64*') { $ScriptRootLocation = "$env:ProgramFiles$ProgramFilesPathTail" } else { $ScriptRootLocation = "${env:ProgramFiles(x86)}$ProgramFilesPathTail" }
        if ($ForceScriptRootPath) { $ScriptRootLocation = "$ForceScriptRootPath$ProgramFilesPathTail" }

        # Does the path exist ?
        if (!(Test-Path $ScriptRootLocation)) {
            New-Item -ItemType Directory -Path $ScriptRootLocation -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created path: $ScriptRootLocation"  -Id 100 -Category 0 -EntryType Information
        }
        Else {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Detected existing path: $ScriptRootLocation - cleaning up first"  -Id 100 -Category 0 -EntryType Information

            Remove-Item -Path $ScriptRootLocation -Recurse -Force
            New-Item -ItemType Directory -Path $ScriptRootLocation -Force

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created path: $ScriptRootLocation"  -Id 100 -Category 0 -EntryType Information
        }

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Local root location will be $ScriptRootLocation"  -Id 100 -Category 0 -EntryType Information

        <# Copy Scripts #>
        if (Test-Path "$ScriptRootLocation\BackgroundWatcher-ImplementUserPin.ps1") { Remove-Item "$ScriptRootLocation\BackgroundWatcher-ImplementUserPin.ps1" -Force }
        if (Test-Path "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1") { Remove-Item "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1" -Force }
        Copy-Item -Path "$InvocationPath\BackgroundWatcher-ImplementUserPin.ps1" -Destination $ScriptRootLocation -Force
        Copy-Item -Path "$InvocationPath\UserInteract-EnterBitlockerPin.ps1" -Destination $ScriptRootLocation -Force
		Copy-Item -Path "$InvocationPath\StatusMessage.ps1" -Destination $ScriptRootLocation -Force
        Copy-Item -Path "$InvocationPath\AutoItX" -Destination "$ScriptRootLocation\AutoItX" -Recurse -Force

        Copy-Item -Path "$InvocationPath\Invoke-BDEPINReset.ps1" -Destination $ScriptRootLocation -Force
        Copy-Item -Path "$InvocationPath\ServiceUI.exe" -Destination $ScriptRootLocation -Force
        Copy-Item -Path "$InvocationPath\BDEPINReset.xml" -Destination $ScriptRootLocation -Force


        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Copied scripts to local root"  -Id 100 -Category 0 -EntryType Information

        <# Create Secure String Key #>
        $KeyFile = "$ScriptRootLocation\AES.key"
        $Key = New-Object Byte[] 16   # You can use 16, 24, or 32 for AES
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
        $Key | Out-File $KeyFile

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created shared AES key at $KeyFile"  -Id 100 -Category 0 -EntryType Information

        If ($initialInstall -eq $True) {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Initial install, so creating the user prompt scheduled task"  -Id 100 -Category 0 -EntryType Information

            <# Create User Prompting Scheduled Task #>
            Register-ScheduledTask -Xml (get-content "$PSScriptRoot\BLTOOL-USRPROMPT.xml" | out-string) -TaskName $SchTaskNamePrompt -Force

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created $SchTaskNamePrompt Scheduled Task"  -Id 100 -Category 0 -EntryType Information
        }
        Else {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Script ran previously, so creating the PIN reset scheduled task"  -Id 100 -Category 0 -EntryType Information

            If (Get-ScheduledTask | ? { $_.TaskName -eq $SchTaskNamePrompt }) {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Detected user prompt scheduled task, so removing it"  -Id 100 -Category 0 -EntryType Information

                <# Stop Scheduled Task #>
                #Disable-ScheduledTask -TaskName $SchTaskNameBckgW -InformationAction SilentlyContinue
                Disable-ScheduledTask -TaskName $SchTaskNamePrompt -InformationAction SilentlyContinue

                <# Remove Scheduled Task #>
                #Unregister-ScheduledTask -TaskName $SchTaskNameBckgW -Confirm:$false -InformationAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $SchTaskNamePrompt -Confirm:$false -InformationAction SilentlyContinue

                Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Scheduled Task: $SchTaskNamePrompt" -Id 100 -Category 0 -EntryType Information
            }

            # Create BDE-Pin Reset scheduled task
            Register-ScheduledTask -Xml (get-content "$PSScriptRoot\BDEPINReset.xml" | out-string) -TaskName $SchTaskNameBDEPINReset -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created $SchTaskNameBDEPINReset Scheduled Task"  -Id 100 -Category 0 -EntryType Information

            # Replace UserInteract-EnterBitlockerPin.ps1 with the one that calls the above scheduled task
            Rename-Item -Path "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1" -NewName "$ScriptRootLocation\UserInteract-EnterBitlockerPinInitial.ps1"
            Rename-Item -Path "$ScriptRootLocation\Invoke-BDEPINReset.ps1" -NewName "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1"
        }

        <# Create Background Watcher System Task To Ingest Pin #>
        Register-ScheduledTask -Xml (get-content "$PSScriptRoot\BLTOOL-BCKGWTCH.xml" | out-string) -TaskName $SchTaskNameBckgW -Force

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created $SchTaskNameBckgW Scheduled Task"  -Id 100 -Category 0 -EntryType Information

        <# Create Status Message Scheduled Task #>
        Register-ScheduledTask -Xml (get-content "$PSScriptRoot\StatusMessage.xml" | out-string) -TaskName $SchTaskNameStatusMessage -Force

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created $SchTaskNameStatusMessage Scheduled Task"  -Id 100 -Category 0 -EntryType Information

        <# Create Shortcut #>
        $WScriptShell = New-Object -ComObject WScript.Shell
        #$Shortcut = $WScriptShell.CreateShortcut("C:\Users\Public\Desktop\Set BitLocker PIN.lnk")
        $Shortcut = $WScriptShell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Manage BitLocker PIN.lnk")
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = '-ExecutionPolicy Bypass -WindowStyle Hidden -file "' + $ScriptRootLocation + '\UserInteract-EnterBitlockerPin.ps1"'
        $Shortcut.Save()

        <# End #>
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Setup Complete, Ready for the user"  -Id 100 -Category 0 -EntryType Information

        #Handle Intune detection method
        If (! ($userInstall) ) {
            Write-Log -Message "Creating detection rule for System install"

            If ( $regTag ) {
                Write-Log -Message "Using RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                New-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            Else {
                Write-Log -Message "Using FileTag"

                If ( ! ( IsNull ( $tagFile ) ) ) {
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

                If ( ! ( IsNull ( $tagFile ) ) ) {
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

        $EventLogName = "Bitlocker Setup"
        $EventLogSource = "PS-Bitlocker-SetupScript"

        $ProgramFilesPathTail = "\MCS\BitlockerScripts"
        $sourcePath = "$env:ProgramFiles$ProgramFilesPathTail"
        $ForceScriptRootPath = "C:\Program Files"
        $RegistrySavePath = "\Software\MCS\SetBitlocker"
        #$RegistryFveLocation = "HKLM:\Software\Policies\Microsoft\FVE"
        #$RegistryConnectedStbyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"

        $SchTaskNamePrompt = "BLTOOL-USRPROMPT"
        $SchTaskNameBckgW = "BLTOOL-BCKGWTCH"
        $SchTaskNameStatusMessage = "StatusMessage"
        $SchTaskNameBDEPINReset = "BDE-PIN_Reset"

        # Create Source Path
        If ($OSArchitecture -like '64*') { $ScriptRootLocation = "$env:ProgramFiles$ProgramFilesPathTail" } else { $ScriptRootLocation = "${env:ProgramFiles(x86)}$ProgramFilesPathTail" }
        if ($ForceScriptRootPath) { $ScriptRootLocation = "$ForceScriptRootPath$ProgramFilesPathTail" }

        #Find users and clean registry paths
        $users = Get-ActiveUser -Method Query
        ForEach ($user in $users.UserName) {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User detected: $user"  -Id 100 -Category 0 -EntryType Information

            <# Resolve User SID #>
            $WmiSid = (New-Object System.Security.Principal.NTAccount($WmiUsername)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            <# Build key location #>
            $UserKeyPath = ("HKU:\" + $WmiSid + $RegistrySavePath)

            <# Clean Up any registry values #>
            if (Test-Path $UserKeyPath) {
                Remove-Item -Path $UserKeyPath -Force
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Registry" -Id 100 -Category 0 -EntryType Information
            }

        }

        #Remove scheduled tasks
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Remove Scheduled Tasks" -Id 100 -Category 0 -EntryType Information
        <# Stop Scheduled Task #>
        Disable-ScheduledTask -TaskName $SchTaskNameBckgW -InformationAction SilentlyContinue
        Disable-ScheduledTask -TaskName $SchTaskNamePrompt -InformationAction SilentlyContinue
        Disable-ScheduledTask -TaskName $SchTaskNameStatusMessage -InformationAction SilentlyContinue
        Disable-ScheduledTask -TaskName $SchTaskNameBDEPINReset -InformationAction SilentlyContinue

        <# Remove Scheduled Task #>
        Unregister-ScheduledTask -TaskName $SchTaskNameBckgW -Confirm:$false -InformationAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $SchTaskNamePrompt -Confirm:$false -InformationAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $SchTaskNameStatusMessage -Confirm:$false -InformationAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $SchTaskNameBDEPINReset -Confirm:$false -InformationAction SilentlyContinue

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Scheduled Tasks" -Id 100 -Category 0 -EntryType Information

        #Remove shortcut files
        If (Test-Path -Path "C:\Users\Public\Desktop\Set BitLocker PIN.lnk") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removing Shortcut: C:\Users\Public\Desktop\Set BitLocker PIN.lnk" -Id 100 -Category 0 -EntryType Information
            Remove-Item -Path "C:\Users\Public\Desktop\Set BitLocker PIN.lnk" -Force
        }

        If (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Manage BitLocker PIN.lnk") {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removing Shortcut: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Manage BitLocker PIN.lnk" -Id 100 -Category 0 -EntryType Information
            Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Manage BitLocker PIN.lnk" -Force
        }

        #Remove scriptroot path
        <# Remove Key #>
        If (Test-Path -Path "$ScriptRootLocation\AES.key") {
            Remove-Item -Path "$ScriptRootLocation\AES.key" -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removed Key" -Id 100 -Category 0 -EntryType Information
        }

        <# Clearing Folder #>
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleanup source folder" -Id 100 -Category 0 -EntryType Information
        If (((get-item $sourcePath).parent.EnumerateDirectories() | Measure-Object).Count -gt 1) {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "More folders found in parent path, do not remove parent folder." -Id 100 -Category 0 -EntryType Information
            Remove-Item -Path $sourcePath -Recurse -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Deleted Self Folder only" -Id 100 -Category 0 -EntryType Information
        }
        Else {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Only script folder found in parent path, remove parent folder and child items" -Id 100 -Category 0 -EntryType Information
            Remove-Item -Path ($sourcePath.Substring(0, $sourcePath.LastIndexOf('\'))) -Recurse -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Deleted Self & Root Folder" -Id 100 -Category 0 -EntryType Information
        }

        $SystemKeyPath = ("HKU:\S-1-5-18\$RegistrySavePath")
        if (Test-Path $SystemKeyPath) {
            Remove-Item -Path $SystemKeyPath -Force
        }

        #Handle Intune detection method
        If (! ($userInstall) ) {
            Write-Log -Message "Removing detection for System install"

            If ( $regTag ) {
                Write-Log -Message "Removing RegTag: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps\$ScriptName"
                Remove-IntuneRegTag -TagRegPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneApps" -tagName $ScriptName
            }
            Else {
                Write-Log -Message "Removing FileTag"

                If ( ! ( IsNull ( $tagFile ) ) ) {
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

                If ( ! ( IsNull ( $tagFile ) ) ) {
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
}