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
    [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $True,
        HelpMessage = 'Please supply the web address to scrape M365 Language and culture codes from'
    )]
    [ValidateNotNullOrEmpty()]
    $URL = "https://docs.microsoft.com/en-us/deployoffice/overview-deploying-languages-microsoft-365-apps#languages-culture-codes-and-companion-proofing-languages",

    [Parameter()]
    [switch] $RunSetup
)
$script:buildVer = "1.0"
$script:scriptName = 'Install-M365AppsLanguages'
$script:logName = ($myInvocation.MyCommand.Name).Substring(0, ($myInvocation.MyCommand.Name).Length - 4) + "_" + (Get-Date -UFormat "%d-%m-%Y")
$script:logPath = "$($env:ProgramData)\Microsoft\IntuneApps\$scriptName"
$script:logFile = "$logPath\$LogName.log"
#Add-Type -AssemblyName Microsoft.VisualBasic
$script:eventLogName = "Application"
$script:eventLogSource = "EventSystem"
$script:transcriptLog = "$logPath\$LogName" + "_Transcript.log"
If ($VerbosePreference -eq 'Continue') { Start-Transcript -Path $transcriptLog -Append }
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

Function Get-WebRequestTable {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.HtmlWebResponseObject] $WebRequest,
          
        [Parameter(Mandatory = $true)]
        [int] $TableNumber
    )
        
    ## Extract the tables out of the web request
    $tables = @($WebRequest.ParsedHtml.getElementsByTagName("TABLE"))
    $table = $tables[$TableNumber]
    $titles = @()
    $rows = @($table.Rows)
        
    ## Go through all of the rows in the table
    foreach ($row in $rows) {
        $cells = @($row.Cells)
           
        ## If we've found a table header, remember its titles
        if ($cells[0].tagName -eq "TH") {
            $titles = @($cells | ForEach-Object { ("" + $_.InnerText).Trim() })
            continue
        }
        
        ## If we haven't found any table headers, make up names "P1", "P2", etc.
        if (-not $titles) {
            $titles = @(1..($cells.Count + 2) | ForEach-Object { "P$_" })
        }
        
        ## Now go through the cells in the the row. For each, try to find the
        ## title that represents that column and create a hashtable mapping those
        ## titles to content
        $resultObject = [Ordered] @{}
        for ($counter = 0; $counter -lt $cells.Count; $counter++) {
            $title = $titles[$counter]
            if (-not $title) { continue }  
        
            $resultObject[$title] = ("" + $cells[$counter].InnerText).Trim()
        }
        
        ## And finally cast that hashtable to a PSCustomObject
        [PSCustomObject] $resultObject
    }
}

####################################################

#region Utility Functions
function New-CheckBox {
    [CmdletBinding()]
    param (
        $ContextObject,
				
        $Parent,

        [int]$TotalCount
    )
			
    #$column = $Parent.Controls.Count % 2
    #$row = [math]::Truncate(($Parent.Controls.Count / 2))
    $columnCount = 4
    $sizePerColumnRaw = $TotalCount / $columnCount
    $sizePerColumn = [math]::Truncate($sizePerColumnRaw)
    if ($sizePerColumnRaw -gt $sizePerColumn) { $sizePerColumn++ }
    #$sizePerColumn = [math]::Round(($TotalCount / $columnCount), [System.MidpointRounding]::AwayFromZero)
    $column = [math]::Truncate(($Parent.Controls.Count / $sizePerColumn))
    #$column = $Parent.Controls.Count % $columnCount
    $row = $Parent.Controls.Count
    While ($row -ge $sizePerColumn) {
        $row = $row - $sizePerColumn
    }
    #$row = [math]::Truncate(($Parent.Controls.Count / $columnCount))
			
    $checkbox = [System.Windows.Forms.CheckBox]::new()
    $checkbox.Width = 280
    $checkbox.Height = 20
    $checkbox.AutoSize = $false
    $checkbox.Location = [System.Drawing.Point]::new((280 * $column + 15), (25 * $row + 15))
    #$checkbox.Text = $ContextObject.Name
    $checkbox.Text = $ContextObject
    $checkbox.Font = 'Microsoft Sans Serif,10'
    $null = $Parent.Controls.Add($checkbox)
    #$tooltip = [System.Windows.Forms.ToolTip]::new()
    #$tooltip.ToolTipTitle = $ContextObject.Name
    #$tooltipText = $ContextObject.Description
    #if ($ContextObject.Prerequisites.Count -gt 0) { $tooltipText += "`nPrerequisites: $($ContextObject.Prerequisites -join ', ')" }
    #if ($ContextObject.MutuallyExclusive.Count -gt 0) { $tooltipText += "`nMutually exclusive with: $($ContextObject.MutuallyExclusive -join ', ')" }
    #$tooltip.SetToolTip($checkbox, $tooltipText)
			
    #$checkbox.Add_CheckedChanged( { Update-Checkbox })
			
    $checkbox
}
		
function New-Form {
    [OutputType([System.Windows.Forms.Form])]
    [CmdletBinding()]
    param ()
			
    #Sets the starting position of the form at run time.
    $centerScreen = [System.Windows.Forms.FormStartPosition]::CenterScreen

    #width, height
    New-Object System.Windows.Forms.Form -Property @{
        #ClientSize    = '880,600'
        #ClientSize    = '880,1200'
        ClientSize    = '1160,500'
        Text          = "M365 Apps for Enterprise (Office)"
        TopMost       = $true
        AutoSize      = $false
        StartPosition = $centerScreen
    }
}
		
function New-GroupBox {
    [OutputType([System.Windows.Forms.Groupbox])]
    [CmdletBinding()]
    param (
        [string]
        $Text,
				
        [int]
        $Height,
				
        $Form
    )
			
    $newHeight = 10
    if ($Form.Controls.Count -gt 0) {
        $last = $Form.Controls | Sort-Object { $_.Location.Y } -Descending | Select-Object -First 1
        $newHeight = 10 + $last.Height + $last.Location.Y
    }
			
    $groupBox = New-Object System.Windows.Forms.Groupbox -Property @{
        Height   = $Height
        Width    = 1140
        Text     = $Text
        AutoSize = $false
        Location = (New-Object System.Drawing.Point(10, $newHeight))
    }
    $Form.Controls.Add($groupBox)
    $groupBox
}
#endregion Utility Functions

function Invoke-Form {
    <#
	.SYNOPSIS
		Builds a GUI to display M365 Apps for Enterprise (Office365) Languages
	
	.DESCRIPTION
		Creates a GUI containing checkboxes to allow the user to choose which
        M365 Apps for Enterprise (Office365) Languages to be installed
        The Office Setup.exe process is then called to dynamically install the
        languages by retrieving the content from CDN.
	#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    [CmdletBinding()]
    param (
        $groupedContexts
    )
	
    begin {
        #Ensure Script can process XAML files
        Add-Type -AssemblyName PresentationFramework
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
    		
        #region Form
        [System.Windows.Forms.Application]::EnableVisualStyles()
        $form = New-Form

        $groupedContexts
        $rows = [math]::Round(($groupedContexts.Count / 4), [System.MidpointRounding]::AwayFromZero)
        $group_Context = New-GroupBox -Text "Select the languages to install:" -Height ($rows * 25 + 15) -Form $form
        $contextCheckboxes = @{ }

        #region Checkboxes
        foreach ($groupedContext in $groupedContexts) {
            $contextCheckboxes[$groupedContext.Language] = New-CheckBox -ContextObject $groupedContext.Language -Parent $group_Context -TotalCount @($groupedContexts).Count
            foreach ($m365AppsInstalledLanguage in $m365AppsInstalledLanguages.ClientCulture) {
                If ($($groupedContext.'Culture (ll-CC)') -eq $m365AppsInstalledLanguage) {
                    Write-Log -Message "Culture already installed: $($groupedContext.'Culture (ll-CC)')"
                    $contextCheckboxes[$groupedContext.Language].Enabled = $false
                }
            }
        }
		
        #Update-Checkbox
        #endregion Checkboxes
		
        #region Buttons
        $button_Cancel = New-Object system.Windows.Forms.Button -Property @{
            Text     = 'Cancel'
            Width    = 60
            Height   = 30
            Anchor   = 'right,bottom'
            Location = (New-Object System.Drawing.Point(576, 460))
            Font     = 'Microsoft Sans Serif,10'
        }
        $form.Controls.Add($button_Cancel)
        $button_OK = New-Object system.Windows.Forms.Button -Property @{
            Text     = 'OK'
            Width    = 38
            Height   = 30
            Anchor   = 'right,bottom'
            Location = (New-Object System.Drawing.Point(528, 460))
            Font     = 'Microsoft Sans Serif,10'
        }
        $form.Controls.Add($button_OK)
        #endregion Buttons
		
        #region Other Stuff
        $okbox = [System.Windows.Forms.CheckBox]::new()
        $okbox.Visible = $false
        $form.Controls.Add($okbox)
		
        $button_OK.Add_Click( {
                $okbox.Checked = $true
                $this.Parent.Close()
            })
        $form.ShowIcon = $false
        $form.CancelButton = $button_Cancel
        $form.AcceptButton = $button_OK
		
        $last = $form.Controls | Where-Object { $_ -is [System.Windows.Forms.Groupbox] } | Sort-Object { $_.Location.Y } -Descending | Select-Object -First 1
        $newHeight = 90 + $last.Height + $last.Location.Y
        $form.Height = $newHeight
        Write-Host "Form height: $newHeight"
        #endregion Other Stuff
        #endregion Form
    }
    process {
        $null = $form.ShowDialog()
        if (-not $okbox.Checked) {
            Write-Log "User cancelled, create error flag file: $PSScriptRoot\Error.flg"
            Set-Content -Path "$PSScriptRoot\Error.flg" -Value "User Cancelled."
            throw "Interrupting: User cancelled operation"
        }
		
        $selectedLanguages = @(($contextCheckboxes.Values | Where-Object Checked).Text)
        Return $selectedLanguages      
    }
}

####################################################

function New-M365LanguageXML {
    param(
        [string[]]$XMLFile,
        [string[]]$cultures
    )
    Write-Log -Message "Creating XML: $XMLFile"

    $xmlWriter = New-Object System.XMl.XmlTextWriter($XMLFile, $Null)
    $xmlWriter.Formatting = 'Indented'
    $xmlWriter.Indentation = 1
    $XmlWriter.IndentChar = "`t"
    $xmlWriter.WriteStartDocument()
    $xmlWriter.WriteComment('M365 Languages')
    $xmlWriter.WriteStartElement('Configuration')
    
    $xmlWriter.WriteStartElement('Add')
    $xmlWriter.WriteAttributeString('Version', 'MatchInstalled')
    $xmlWriter.WriteStartElement('Product')
    $xmlWriter.WriteAttributeString('ID', 'LanguagePack')

    Foreach ($culture in $cultures) {
        Foreach ($language in $webTable) {
            If ($culture -eq $language.Language) {
                #Write-Log -Message "Language: $name | Culture: $($language.'Culture (ll-CC)')"
                $xmlWriter.WriteStartElement('Language')
                $xmlWriter.WriteAttributeString('ID', $($language.'Culture (ll-CC)'))
                #$xmlWriter.WriteAttributeString('ID', $($language.culture))
                $xmlWriter.WriteEndElement()
            }
        }
    }

    
    $xmlWriter.WriteEndElement()
    $xmlWriter.WriteEndElement()
 
    $xmlWriter.WriteStartElement('Display')
    $xmlWriter.WriteAttributeString('Level', 'None')
    $xmlWriter.WriteEndElement()
    
    $xmlWriter.WriteEndDocument()
    $xmlWriter.Flush()
    $xmlWriter.Close()
}

####################################################

function Invoke-Setup {
    Write-Log -Message "Running Office Update process..."

    #Clear existing computername*.log files in $env:SystemRoot\Temp
    #MIP-35319690177-20210907-1125c.log
    #Need to test with invoking 'Office Automatic Updates 2.0' scheduled task - didn't work, HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Updates Set to anything 1327*
    #Need to test what happens when no updates needed

    Write-Log -Message "Running: `"$env:CommonProgramFiles\microsoft shared\ClickToRun\OfficeC2RClient.exe`" /update user updatepromptuser=false forceappshutdown=true displaylevel=false"
    Try {
        Start-Process -FilePath "$env:CommonProgramFiles\microsoft shared\ClickToRun\OfficeC2RClient.exe" -ArgumentList "/update user updatepromptuser=false forceappshutdown=true displaylevel=false" -WorkingDirectory "$PSScriptRoot" -Wait -WindowStyle Hidden -ErrorAction Stop
        Write-Log -Message "Pause for 30 seconds"
        Start-Sleep -Seconds 30
        while ((get-process -Name "OfficeClickToRun").Count -gt 1) {
            Write-Log -Message "Office updating..."
            Start-Sleep -Seconds 30
            Write-Host
        }
        Write-Log -Message "Pause for another 30 seconds"
        Start-Sleep -Seconds 30
        #Write-Log -Message "Running: `"$env:SystemRoot\Notepad.exe`""
        #Start-Process -FilePath "$env:SystemRoot\Notepad.exe" -WorkingDirectory "$PSScriptRoot" -Wait -ErrorAction Stop
        #Pause until Application log has Event ID 11728 Information Product: Office 16 Click-to-Run Extensibility Component -- Configuration completed successfully.
        #Write-Log -Message "Running: `"$PSScriptRoot\setup.exe`" /configure `"$PSScriptRoot\M365Languages.xml`""
        #Start-Process -FilePath "$PSScriptRoot\setup.exe" -ArgumentList "/configure `"$PSScriptRoot\M365Languages.xml`"" -WorkingDirectory "$PSScriptRoot" -Wait -WindowStyle Hidden -ErrorAction Stop
    }
    Catch {
        #Write-Log -Message "Error occurred installing driver: $($_.Exception.message)" -WriteEventLog
        Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
        If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
        Throw
    }

}

####################################################

function Invoke-Application {
    <#
.SYNOPSIS
	This script performs the installation or uninstallation of an application(s).
	# LICENSE #
	PowerShell App Deployment Toolkit - Provides a set of functions to perform common application deployment tasks on Windows.
	Copyright (C) 2017 - Sean Lillis, Dan Cunningham, Muhammad Mashwani, Aman Motazedian.
	This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
	You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
.DESCRIPTION
	The script is provided as a template to perform an install or uninstall of an application(s).
	The script either performs an "Install" deployment type or an "Uninstall" deployment type.
	The install deployment type is broken down into 3 main sections/phases: Pre-Install, Install, and Post-Install.
	The script dot-sources the AppDeployToolkitMain.ps1 script which contains the logic and functions required to install or uninstall an application.
.PARAMETER DeploymentType
	The type of deployment to perform. Default is: Install.
.PARAMETER DeployMode
	Specifies whether the installation should be run in Interactive, Silent, or NonInteractive mode. Default is: Interactive. Options: Interactive = Shows dialogs, Silent = No dialogs, NonInteractive = Very silent, i.e. no blocking apps. NonInteractive mode is automatically set if it is detected that the process is not user interactive.
.PARAMETER AllowRebootPassThru
	Allows the 3010 return code (requires restart) to be passed back to the parent process (e.g. SCCM) if detected from an installation. If 3010 is passed back to SCCM, a reboot prompt will be triggered.
.PARAMETER TerminalServerMode
	Changes to "user install mode" and back to "user execute mode" for installing/uninstalling applications for Remote Destkop Session Hosts/Citrix servers.
.PARAMETER DisableLogging
	Disables logging to file for the script. Default is: $false.
.EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -DeployMode 'Silent'; Exit $LastExitCode }"
.EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -AllowRebootPassThru; Exit $LastExitCode }"
.EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -DeploymentType 'Uninstall'; Exit $LastExitCode }"
.EXAMPLE
    Deploy-Application.exe -DeploymentType "Install" -DeployMode "Silent"
.NOTES
	Toolkit Exit Code Ranges:
	60000 - 68999: Reserved for built-in exit codes in Deploy-Application.ps1, Deploy-Application.exe, and AppDeployToolkitMain.ps1
	69000 - 69999: Recommended for user customized exit codes in Deploy-Application.ps1
	70000 - 79999: Recommended for user customized exit codes in AppDeployToolkitExtensions.ps1
.LINK
	http://psappdeploytoolkit.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Install', 'Uninstall', 'Repair')]
        [string]$DeploymentType = 'Install',
        [Parameter(Mandatory = $false)]
        [ValidateSet('Interactive', 'Silent', 'NonInteractive')]
        [string]$DeployMode = 'Interactive',
        [Parameter(Mandatory = $false)]
        [switch]$AllowRebootPassThru = $false,
        [Parameter(Mandatory = $false)]
        [switch]$TerminalServerMode = $false,
        [Parameter(Mandatory = $false)]
        [switch]$DisableLogging = $false
    )

    Try {
        ## Set the script execution policy for this process
        Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' } Catch {}

        ##*===============================================
        ##* VARIABLE DECLARATION
        ##*===============================================
        ## Variables: Application
        [string]$appVendor = 'Microsoft'
        [string]$appName = 'Apps for Enterprise Language Packs'
        [string]$appVersion = '(Office365)'
        [string]$appArch = 'x64'
        [string]$appLang = 'EN'
        [string]$appRevision = '01'
        [string]$appScriptVersion = '1.0.0'
        [string]$appScriptDate = '09/09/2021'
        [string]$appScriptAuthor = 'Greg Nottage'
        ##*===============================================
        ## Variables: Install Titles (Only set here to override defaults set by the toolkit)
        [string]$installName = ''
        [string]$installTitle = ''

        ##* Do not modify section below
        #region DoNotModify

        ## Variables: Exit Code
        [int32]$mainExitCode = 0

        ## Variables: Script
        [string]$deployAppScriptFriendlyName = 'Deploy Application'
        [version]$deployAppScriptVersion = [version]'3.8.4'
        [string]$deployAppScriptDate = '26/01/2021'
        [hashtable]$deployAppScriptParameters = $psBoundParameters

        ## Variables: Environment
        #If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }
        #[string]$scriptDirectory = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent
        [string]$scriptDirectory = $PSScriptRoot

        ## Dot source the required App Deploy Toolkit Functions
        Try {
            [string]$moduleAppDeployToolkitMain = "$scriptDirectory\AppDeployToolkit\AppDeployToolkitMain.ps1"
            Write-Log -Message "moduleAppDeployToolkitMain: $moduleAppDeployToolkitMain"
            #If (-not (Test-Path -LiteralPath $moduleAppDeployToolkitMain -PathType 'Leaf')) { Throw "Module does not exist at the specified location [$moduleAppDeployToolkitMain]." }
            #. $moduleAppDeployToolkitMain
            If ($DisableLogging) { . $moduleAppDeployToolkitMain -DisableLogging } Else { . $moduleAppDeployToolkitMain }
        }
        Catch {
            If ($mainExitCode -eq 0) { [int32]$mainExitCode = 60008 }
            Write-Error -Message "Module [$moduleAppDeployToolkitMain] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
            ## Exit the script, returning the exit code to SCCM
            #If (Test-Path -LiteralPath 'variable:HostInvocation') { $script:ExitCode = $mainExitCode; Exit } Else { Exit $mainExitCode }
            Write-Log "Error occurred, create error flag file: $PSScriptRoot\Error.flg"
            Set-Content -Path "$PSScriptRoot\Error.flg" -Value "Module [$moduleAppDeployToolkitMain] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
            Throw "Error occurred: importing PSAppDeployToolkit module sources"
        }
        #endregion
        ##* Do not modify section above
        ##*===============================================
        ##* END VARIABLE DECLARATION
        ##*===============================================

        If ($deploymentType -ine 'Uninstall' -and $deploymentType -ine 'Repair') {
            ##*===============================================
            ##* PRE-INSTALLATION
            ##*===============================================
            [string]$installPhase = 'Pre-Installation'

            ## Show Welcome Message, close Internet Explorer if required, allow up to 3 deferrals, verify there is enough disk space to complete the install, and persist the prompt
            Show-InstallationWelcome -CloseApps 'winword=Microsoft Word,outlook=Microsoft Outlook,excel=Microsoft Excel,powerpnt=Microsoft Powerpoint,onenote=Microsoft OneNote,visio=Microsoft Visio,project=Microsoft Project,teams=Microsoft Teams' -CheckDiskSpace -CloseAppsCountdown 600 -PersistPrompt

            ## Show Progress Message (with the default message)
            Show-InstallationProgress

            ## Pre-Installation tasks
            Write-Log -Message "Running Office update check process, please wait..."
            Invoke-Setup

            ##*===============================================
            ##* INSTALLATION
            ##*===============================================
            [string]$installPhase = 'Installation'

            ## Handle Zero-Config MSI Installations
            If ($useDefaultMsi) {
                [hashtable]$ExecuteDefaultMSISplat = @{ Action = 'Install'; Path = $defaultMsiFile }; If ($defaultMstFile) { $ExecuteDefaultMSISplat.Add('Transform', $defaultMstFile) }
                Execute-MSI @ExecuteDefaultMSISplat; If ($defaultMspFiles) { $defaultMspFiles | ForEach-Object { Execute-MSI -Action 'Patch' -Path $_ } }
            }

            ## <Perform Installation tasks here>
            Execute-Process -Path "$dirFiles\setup.exe" -Parameters "/CONFIGURE M365Languages.xml"

            ##*===============================================
            ##* POST-INSTALLATION
            ##*===============================================
            [string]$installPhase = 'Post-Installation'

            ## <Perform Post-Installation tasks here>

            ## Display a message at the end of the install
            If (-not $useDefaultMsi) { Show-InstallationPrompt -Message 'Thanks for your patience, installation is now complete. You can now reopen your applications.' -ButtonRightText 'OK' -Icon Information -NoWait }
        }
        ElseIf ($deploymentType -ieq 'Uninstall') {
            ##*===============================================
            ##* PRE-UNINSTALLATION
            ##*===============================================
            [string]$installPhase = 'Pre-Uninstallation'

            ## Show Welcome Message, close Internet Explorer with a 60 second countdown before automatically closing
            Show-InstallationWelcome -CloseApps 'iexplore' -CloseAppsCountdown 60

            ## Show Progress Message (with the default message)
            Show-InstallationProgress

            ## <Perform Pre-Uninstallation tasks here>


            ##*===============================================
            ##* UNINSTALLATION
            ##*===============================================
            [string]$installPhase = 'Uninstallation'

            ## Handle Zero-Config MSI Uninstallations
            If ($useDefaultMsi) {
                [hashtable]$ExecuteDefaultMSISplat = @{ Action = 'Uninstall'; Path = $defaultMsiFile }; If ($defaultMstFile) { $ExecuteDefaultMSISplat.Add('Transform', $defaultMstFile) }
                Execute-MSI @ExecuteDefaultMSISplat
            }

            # <Perform Uninstallation tasks here>


            ##*===============================================
            ##* POST-UNINSTALLATION
            ##*===============================================
            [string]$installPhase = 'Post-Uninstallation'

            ## <Perform Post-Uninstallation tasks here>


        }
        ElseIf ($deploymentType -ieq 'Repair') {
            ##*===============================================
            ##* PRE-REPAIR
            ##*===============================================
            [string]$installPhase = 'Pre-Repair'

            ## Show Progress Message (with the default message)
            Show-InstallationProgress

            ## <Perform Pre-Repair tasks here>

            ##*===============================================
            ##* REPAIR
            ##*===============================================
            [string]$installPhase = 'Repair'

            ## Handle Zero-Config MSI Repairs
            If ($useDefaultMsi) {
                [hashtable]$ExecuteDefaultMSISplat = @{ Action = 'Repair'; Path = $defaultMsiFile; }; If ($defaultMstFile) { $ExecuteDefaultMSISplat.Add('Transform', $defaultMstFile) }
                Execute-MSI @ExecuteDefaultMSISplat
            }
            # <Perform Repair tasks here>

            ##*===============================================
            ##* POST-REPAIR
            ##*===============================================
            [string]$installPhase = 'Post-Repair'

            ## <Perform Post-Repair tasks here>


        }
        ##*===============================================
        ##* END SCRIPT BODY
        ##*===============================================

        ## Call the Exit-Script function to perform final cleanup operations
        #Exit-Script -ExitCode $mainExitCode
    }
    Catch {
        [int32]$mainExitCode = 60001
        [string]$mainErrorMessage = "$(Resolve-Error)"
        #Write-Log -Message $mainErrorMessage -Severity 3 -Source $deployAppScriptFriendlyName
        Write-Log -Message $mainErrorMessage
        Show-DialogBox -Text $mainErrorMessage -Icon 'Stop'
        Write-Log "Error occurred, create error flag file: $PSScriptRoot\Error.flg"
        Set-Content -Path "$PSScriptRoot\Error.flg" -Value $mainErrorMessage
        throw "Error occurred: $mainErrorMessage"
        #Exit-Script -ExitCode $mainExitCode
    }

}

####################################################

If ($PSBoundParameters.Debug) {
    Write-Host "Functions loaded, terminating due to debug mode."
    function Write-Log {}
    Return
}

Start-Log -FilePath $logFile -DeleteExistingFile
Write-Host
Write-Host "Script log file path is [$logFile]" -ForegroundColor Cyan
Write-Host
Write-Log -Message "Starting $ScriptName version $BuildVer" -WriteEventLog
Write-Log -Message "Running from location: $PSScriptRoot" -WriteEventLog
Write-Log -Message "Script log file path is [$logFile]" -WriteEventLog
Write-Log -Message "Running in 64-bit mode: $([System.Environment]::Is64BitProcess)"
Write-Log -Message "Transcript log file path: $transcriptLog"

#endregion Initialisation...
##########################################################################################################
##########################################################################################################


#Main script
Write-Log -Message "Starting Main script..."
#Read existing M365 Apps for Enterprise (Office365) installed languages
$registryPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
Write-Log -Message "Read registry value: $registryPath"
Try {
    $m365AppsInstalledLanguages = Get-ItemProperty -Path $registryPath -Name 'ClientCulture' -ErrorAction Stop
    $m365AppsInstalledLanguages.ClientCulture
}
Catch {
    Write-Log -Message "Error occurred: $($_.Exception.message)"
    Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
    Write-Log "Error occurred reading registry, create error flag file: $PSScriptRoot\Error.flg"
    Set-Content -Path "$PSScriptRoot\Error.flg" -Value "Error occurred reading registry."
    Throw "Error occurred: reading registry"
}

<#
#region AngleParse
#Install-Module -Name AngleParse -Force
#Import-Module -Name AngleParse
Import-Module -Name "$PSScriptRoot\Modules\AngleParse" -Force
$webTable = Invoke-WebRequest -Uri $URL -UseBasicParsing | Select-HtmlContent "table tbody tr", @{
    language                   = "td:first-of-type"
    culture                    = "td:nth-of-type(2)"
    companionProofingLanguages = "td:nth-of-type(3)"
}
#endregion AngleParse
#>

<#
#Export to JSON
Write-Log -Message "Scrape web page: $URL"
$uri = Invoke-WebRequest -Uri $URL
$webTable = Get-WebRequestTable -WebRequest $uri -TableNumber 0
$outputFile = "$PSScriptRoot\Languages.JSON"
$webTable | ConvertTo-Json | Out-File -FilePath $outputFile -Force
#>

#<#
#Read JSON that was created using IWR + Get-WebRequestTable above
$outputFile = "$PSScriptRoot\Languages.JSON"
$webTable = Get-Content $outputFile | ConvertFrom-Json
#>

$selectedLanguages = Invoke-Form -groupedContexts $webTable

Write-Log -Message "Build XML file: $PSScriptRoot\Files\M365Languages.xml with cultures: $selectedLanguages"
New-M365LanguageXML -XMLFile "$PSScriptRoot\Files\M365Languages.xml" -cultures $selectedLanguages

If ($RunSetup) {
    Write-Log -Message "Running Office setup process, please wait..."
    Try {
        #Use PowerShell App Deployment Toolkit to handle Office updates & language pack install
        Invoke-Application -DeploymentType 'Install' -DeployMode 'Interactive'
    }
    Catch {
        Write-Log -Message "Error occurred: $($_.Exception.message)"
        Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
        Write-Log "Error occurred running Invoke-Application function, create error flag file: $PSScriptRoot\Error.flg"
        Set-Content -Path "$PSScriptRoot\Error.flg" -Value "Error occurred running Invoke-Application function."
        Throw "Error occurred: running Invoke-Application function"
    }

    #Backup Office Log files
    $logfileDate = get-date -Format "yyyyMMdd"
    Write-Log -Message "Backup Office log files"
    Try {
        Copy-Item -Path "$env:SystemRoot\Temp\$env:computername-$logfileDate-*.log" -Destination $logPath -ErrorAction Stop
    }
    Catch {
        Write-Log -Message "Error occurred: $($_.Exception.message)"
        Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
        Write-Log "Error occurred reading registry, create error flag file: $PSScriptRoot\Error.flg"
        Set-Content -Path "$PSScriptRoot\Error.flg" -Value "Error occurred reading registry."
        Throw "Error occurred: reading registry"
    }
}

#Remove-Module -Name AngleParse -Force
#Uninstall-Module -Name AngleParse -AllVersions -Force

Write-Log -Message "Script end."
Stop-Transcript