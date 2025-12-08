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
$script:BuildVer = "1.6"
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

            New-Item -Path $TagFilePath -ItemType "directory" -Force | Out-Null
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

Function Get-InstalledSoftware {
    param (
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide computer name(s) to evaluate'
        )]
        [ValidateNotNullOrEmpty()]
        [string[]] $ComputerNames
    )

    Begin {
        Write-Log -Message "$($MyInvocation.InvocationName) function..." -WriteEventLog -WriteHost Green
        Write-Log -Message "Processing Computernames: $($ComputerNames)" -WriteEventLog -WriteHost Magenta
    }

    Process {
        $array = @()

        foreach ($ComputerName in $ComputerNames) {
            Write-Log -Message "Computername: $($ComputerName)" -WriteEventLog -WriteHost Green

            #Define the variable to hold the location of Currently Installed Programs
            $UninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"

            #Create an instance of the Registry Object and open the HKLM base key
            $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)

            #Drill down into the Uninstall key using the OpenSubKey Method
            $regkey = $reg.OpenSubKey($UninstallKey)

            #Retrieve an array of string that contain all the subkey names
            $subkeys = $regkey.GetSubKeyNames()

            #Open each Subkey and use GetValue Method to return the required values for each
            foreach ($key in $subkeys) {

                $thisKey = $UninstallKey + "\\" + $key
                $thisSubKey = $reg.OpenSubKey($thisKey)
                $obj = New-Object PSObject
                $obj | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $ComputerName
                $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))
                $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"))
                $obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($thisSubKey.GetValue("InstallLocation"))
                $obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($thisSubKey.GetValue("Publisher"))

                $array += $obj
            }
        }

        Return $array
    }
}

####################################################

Function Start-Command {
    Param([Parameter (Mandatory = $true)]
        [string]$Command,
        [Parameter (Mandatory = $true)]
        [string]$Arguments)

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $Command
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.CreateNoWindow = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $Arguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    [pscustomobject]@{
        stdout   = $p.StandardOutput.ReadToEnd()
        stderr   = $p.StandardError.ReadToEnd()
        ExitCode = $p.ExitCode
    }
}

####################################################

Function Get-DotNetSource {
    param (
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide path to search'
        )]
        [ValidateNotNullOrEmpty()]
        [string[]] $Path
    )
    #$dotNetFile = "windowsdesktop-runtime-8.0.8-win-x86.exe"
    #Runtime exe in same folder as script must be named like: windowsdesktop-runtime-8.0.xx-win-x86.exe - where xx is a version number shown in digits - like: windowsdesktop-runtime-8.0.8-win-x86.exe
    #If the file in the script folder is not named the same (apart from changes to the version number) - the detection logic in the Install section of this script will fail!!!
    Write-Log -Message "Searching path $Path for DotNet8 Desktop runtime executable file..."
    $ErrorActionPreference = 'Stop'
    Try {
        $dotNetFile = Get-ChildItem -Path $Path -Include "*.exe"
        Write-Log -Message "dotNetFile: $($dotNetFile | format-list * | Out-String)"
        Return $dotNetFile
    }
    Catch {
        If ($VerbosePreference -eq 'Continue') { $null = Stop-Transcript }
        Throw
    }
}

####################################################

Function Get-InstallSource {
    param (
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide path to search'
        )]
        [ValidateNotNullOrEmpty()]
        [string[]] $Path
    )

    Write-Log -Message "Searching path $Path for executable file..."

    Try {
        $file = Get-ChildItem -Path $Path -Include "*.exe" -ErrorAction Stop

        Return $file
    }
    Catch {
        If ($VerbosePreference -eq 'Continue') { $null = Stop-Transcript }
        Throw
    }
}

####################################################

Function Invoke-DotNetInstall {
    param (
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide app name to search for'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $AppName,

        [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide app version to search for'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $AppVersion
    )

    Write-Log -Message "Using app name: $($AppName) with app version: $($AppVersion)"

    $installDotNet = $false
    Write-Log -Message "Using .NET install path: $($dotNetFile.FullName)"
    If ($dotNetFile.FullName -like "*x86*") {
        $dotNetPath = "$programFiles\dotnet\dotnet.exe"
        Write-Log -Message "x86 install path: $dotNetPath"
    }
    Else {
        $dotNetPath = "$programFiles\dotnet\dotnet.exe"
        Write-Log -Message "x64 install path: $dotNetPath"
    }

    If (Test-Path $dotNetPath) {
        Write-Log -Message "DOTNET already installed, check version" -WriteHost Yellow

        $output = Start-Command -Command $dotNetPath -Arguments "--list-runtimes"
        $inputString = ($($output.stdout)).trim() | Out-String
        Write-Log -Message "Validate version number"

        $dotNet8Ver = Select-String -InputObject $inputString -Pattern '(?<=Microsoft\.WindowsDesktop\.App )\d+\.\d+\.\d+' -AllMatches | ForEach-Object { $_.Matches.Value }

        If ($dotNet8Ver) {
            Foreach ($version in ($dotNet8Ver | Sort-Object -Unique)) {
                [version]$version
                Write-Log -Message "Detected installed DotNet8 version: $version" -WriteHost Green

                [version]$newDotNet8Ver = Select-String -InputObject $($dotNetFile.Name) -Pattern '(?<=windowsdesktop-runtime-)\d+\.\d+\.\d+' -AllMatches | ForEach-Object { $_.Matches.Value }
                Write-Log -Message "NewDotNet8 version: $newDotNet8Ver" -WriteHost Green
                If ($newDotNet8Ver -gt $version) {
                    Write-Log -Message "DotNet needs upgrading" -WriteHost Magenta
                    $installDotNet = $true
                }
                Else {
                    Write-Log -Message "DotNet already at this version or later" -WriteHost Green
                    $installDotNet = $false
                }
            }
        }
    }
    Else {
        Write-Log -Message "Unable to determine DotNet8 version, will install anyway"
        $installDotNet = $true
    }

    If ($installDotNet) {
        Write-Log -Message "Installing $($dotNetFile.Name)" -WriteHost Cyan

        Write-Log -Message "Running `"$($dotNetFile.FullName)`" /install /quiet /norestart"
        $result = Start-Command -Command "`"$($dotNetFile.FullName)`"" -Arguments "/install /quiet /norestart"
        Write-Log -Message "Command result: $($result.ExitCode)"

        Test-AppInstall -AppName $AppName -AppVersion $AppVersion
    }
}

####################################################

Function Test-AppInstall {
    param (
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide app name to search for'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $AppName,

        [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide app version to search for'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $AppVersion     
    )

    Write-Log -Message "Checking for: $($AppName) with version: $($AppVersion)"

    $appInstall = Get-ProgramUninstallString -Filter $AppName | Where-Object { $_.version -like $AppVersion } | Select-Object -First 1
    If (-Not($appInstall)) {
        Write-Log -Message "Error - app $($AppName) with version: $($AppVersion) not detected!" -WriteHost Red
        If (-Not($($AppName) -like "*WebView2*")) { Throw "Error - app $($AppName) with version: $($AppVersion) not detected!" }
    }
    Else {
        Write-Log -Message "App detected as: $($appInstall | Format-List * | Out-String)"
    }
}


####################################################

Function Get-InstalledApps {
    Write-Log -Message "Determine installed applications for device: $($env:ComputerName)..." -WriteEventLog -WriteHost Yellow

    $apps = Get-ProgramUninstallString
    #$logOfApps = $apps | Format-List * | Out-String
    #Write-Log -Message "Installed app details: `n$($logOfApps)" -WriteEventLog -WriteHost Yellow
    Write-Log -Message "Installed app details: `n$($apps | Format-List * | Out-String)" -WriteEventLog -WriteHost Yellow
    Return $apps
}

####################################################

Function Remove-App {
    param (
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide app name to search for'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $AppName,

        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide app version to search for'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $AppVersion
    )

    Write-Log -Message "Search for appname: $AppName with version like: $AppVersion"

    $dotNet6x86 = Get-ProgramUninstallString -Filter $AppName | Where-Object { $_.version -like $AppVersion } | Select-Object -First 1

    If ($dotNet6x86) {
        Write-Log -Message ".NET 6 app details: $($dotNet6x86 | Format-List * | Out-String)"
        $null = $($dotNet6x86.QuietUninstallString) -match '^(.*?"[^"]*")\s(.*)$'
        if ($matches) {
            Write-Log -Message "Uninstall using command: $($matches[1]) with args: $($matches[2]) /norestart" -WriteHost Yellow
        }
        Else {
            Write-Log -Message "Error- uninstall string not correctly matched"
            If ($VerbosePreference -eq 'Continue') { $null = Stop-Transcript }
            Throw "Uninstall string not correctly matched"
        }

        $result = Start-Command -Command $($matches[1]) -Arguments "$($matches[2]) /norestart"
        Write-Log -Message "Uninstall command result: $($result.ExitCode)"
    }
    Else {
        Write-Log -Message "App not found."
    }
}

####################################################

Function Get-ProgramUninstallString {
    [CmdletBinding(
        DefaultParameterSetName = "ByName"
    )]
    [OutputType(
        [PSCustomObject]
    )]

    param (
        [Parameter(
            ParameterSetName = "ByName",
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias(
            "DisplayName"
        )]
        [String[]]
        $Name,

        [Parameter(
            ParameterSetName = "ByFilter"
        )]
        [String]
        $Filter = "*",

        [Parameter()]
        [Switch]
        $ShowNulls
    )

    begin {
        try {
            if (Test-Path -Path "HKLM:\SOFTWARE\WOW6432Node") {
                $programs = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction Stop
            }
            $programs += Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction Stop
            $programs += Get-ItemProperty -Path "Registry::\HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
            #$programs | Out-GridView
        }
        catch {
            Write-Error $_
            break
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq "ByName") {
            foreach ($nameValue in $Name) {
                $programs = $programs.Where({
                        $_.DisplayName -eq $nameValue
                    })
            }
        }
        else {
            $programs = $programs.Where({
                    $_.DisplayName -like "*$Filter*"
                })
        }

        if ($null -ne $programs) {
            if (-not ($ShowNulls.IsPresent)) {
                $programs = $programs.Where({
                        -not [String]::IsNullOrEmpty(
                            $_.UninstallString
                        )
                    })
            }

            $output = $programs.ForEach({
                    [PSCustomObject]@{
                        Name                 = $_.DisplayName
                        Version              = $_.DisplayVersion
                        Guid                 = $_.PSChildName
                        UninstallString      = $_.UninstallString
                        QuietUninstallString = $_.QuietUninstallString
                    }
                })

            #$output | Out-GridView
            #Write-Output -InputObject $output
            Return $output
        }
    }
}

####################################################

function Get-MSIFileInformation {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo[]]$FilePath
    )

    # https://learn.microsoft.com/en-us/windows/win32/msi/installer-opendatabase
    $msiOpenDatabaseModeReadOnly = 0

    $productLanguageHashTable = @{
        '1025' = 'Arabic'
        '1026' = 'Bulgarian'
        '1027' = 'Catalan'
        '1028' = 'Chinese - Traditional'
        '1029' = 'Czech'
        '1030' = 'Danish'
        '1031' = 'German'
        '1032' = 'Greek'
        '1033' = 'English'
        '1034' = 'Spanish'
        '1035' = 'Finnish'
        '1036' = 'French'
        '1037' = 'Hebrew'
        '1038' = 'Hungarian'
        '1040' = 'Italian'
        '1041' = 'Japanese'
        '1042' = 'Korean'
        '1043' = 'Dutch'
        '1044' = 'Norwegian'
        '1045' = 'Polish'
        '1046' = 'Brazilian'
        '1048' = 'Romanian'
        '1049' = 'Russian'
        '1050' = 'Croatian'
        '1051' = 'Slovak'
        '1053' = 'Swedish'
        '1054' = 'Thai'
        '1055' = 'Turkish'
        '1058' = 'Ukrainian'
        '1060' = 'Slovenian'
        '1061' = 'Estonian'
        '1062' = 'Latvian'
        '1063' = 'Lithuanian'
        '1081' = 'Hindi'
        '1087' = 'Kazakh'
        '2052' = 'Chinese - Simplified'
        '2070' = 'Portuguese'
        '2074' = 'Serbian'
    }

    $summaryInfoHashTable = @{
        1  = 'Codepage'
        2  = 'Title'
        3  = 'Subject'
        4  = 'Author'
        5  = 'Keywords'
        6  = 'Comment'
        7  = 'Template'
        8  = 'LastAuthor'
        9  = 'RevisionNumber'
        10 = 'EditTime'
        11 = 'LastPrinted'
        12 = 'CreationDate'
        13 = 'LastSaved'
        14 = 'PageCount'
        15 = 'WordCount'
        16 = 'CharacterCount'
        18 = 'ApplicationName'
        19 = 'Security'
    }

    $properties = @('ProductVersion', 'ProductCode', 'ProductName', 'Manufacturer', 'ProductLanguage', 'UpgradeCode')

    try {
        $file = Get-ChildItem $FilePath -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to get file $FilePath $($_.Exception.Message)"
        return
    }

    $object = [PSCustomObject][ordered]@{
        FileName     = $file.Name
        FilePath     = $file.FullName
        'Length(MB)' = $file.Length / 1MB
    }

    # Read property from MSI database
    $windowsInstallerObject = New-Object -ComObject WindowsInstaller.Installer

    # open read only
    $msiDatabase = $windowsInstallerObject.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $windowsInstallerObject, @($file.FullName, $msiOpenDatabaseModeReadOnly))

    foreach ($property in $properties) {
        $view = $null
        $query = "SELECT Value FROM Property WHERE Property = '$($property)'"
        $view = $msiDatabase.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $msiDatabase, ($query))
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)

        try {
            $value = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
        }
        catch {
            Write-Verbose "Unable to get '$property' $($_.Exception.Message)"
            $value = ''
        }

        if ($property -eq 'ProductLanguage') {
            $value = "$value ($($productLanguageHashTable[$value]))"
        }

        $object | Add-Member -MemberType NoteProperty -Name $property -Value $value
    }

    $summaryInfo = $msiDatabase.GetType().InvokeMember('SummaryInformation', 'GetProperty', $null, $msiDatabase, $null)
    $summaryInfoPropertiesCount = $summaryInfo.GetType().InvokeMember('PropertyCount', 'GetProperty', $null, $summaryInfo, $null)

    (1..$summaryInfoPropertiesCount) | ForEach-Object {
        $value = $SummaryInfo.GetType().InvokeMember("Property", "GetProperty", $Null, $SummaryInfo, $_)

        if ($null -eq $value) {
            Return
            $object | Add-Member -MemberType NoteProperty -Name $summaryInfoHashTable[$_] -Value '' -ErrorAction 'SilentlyContinue'
        }
        else {
            $object | Add-Member -MemberType NoteProperty -Name $summaryInfoHashTable[$_] -Value $value -ErrorAction 'SilentlyContinue'
        }
    }

    #$msiDatabase.GetType().InvokeMember('Commit', 'InvokeMethod', $null, $msiDatabase, $null)
    $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)

    # Run garbage collection and release ComObject
    $null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($windowsInstallerObject)
    [System.GC]::Collect()

    return $object
}

####################################################

Function Invoke-WebView2Install {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo[]]$Path,

        [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide app name to search for'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $AppName,

        [Parameter(Mandatory = $true, Position = 3, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide app version to search for'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $AppVersion
    )
    Write-Log -Message "Using path: $($Path.FullName)"
    Write-Log -Message "Using app name: $($AppName) with app version: $($AppVersion)"
    #$webView2InstallEXEVer = [Version]"128.0.2739.67"
    $installWebView2 = $false

    $null = $($Path.Name) -match "_([\d.]+)\.exe$"
    If ($matches) {
        [version]$webView2InstallEXEVer = $($matches[1])
    }
    Else {
        Write-Log -Message "Unable to determine package version" -WriteHost Yellow
        If ($VerbosePreference -eq 'Continue') { $null = Stop-Transcript }
        Throw "Unable to determine package version"
    }

    Write-Log -Message "WebView2 installer version: $webView2InstallEXEVer" -WriteHost Magenta
    #$webView2AppDetails = Get-ProgramUninstallString -Filter "Microsoft Edge WebView2 Runtime" | Select-Object -First 1
    $webView2AppDetails = Get-ProgramUninstallString -Filter $AppName | Select-Object -First 1

    If ($webView2AppDetails) {
        #Check Version
        [Version]$currentWebView2Version = $($webView2AppDetails.Version)
        If (-Not($currentWebView2Version)) {
            Write-Log -Message "WebView2 version not detected, install package version" -WriteHost Yellow
            $installWebView2 = $true
        }
        Else {
            Write-Log -Message "Currently installed version of WebView2: $currentWebView2Version" -WriteHost Cyan
            If ($currentWebView2Version -lt $webView2InstallEXEVer) {
                Write-Log -Message "WebView2 upgrade required!" -WriteHost Yellow
                $installWebView2 = $true
            }
            Else {
                Write-Log -Message "No WebView2 upgrade required." -WriteHost Green
            }
        }
    }
    Else {
        Write-Log -Message "WebView2 not detected, will install" -WriteHost Yellow
        $installWebView2 = $true
    }

    If ($installWebView2 -eq $true) {
        Write-Log -Message "Installing WebView2" -WriteHost Cyan

        #Write-Log -Message "Running `"$($Path.FullName)`" /silent /install /norestart" #Don't think /norestart is valid for WebView2
        #$result = Start-Command -Command "`"$($Path.FullName)`"" -Arguments "/silent /install /norestart" #Don't think /norestart is valid for WebView2

        Write-Log -Message "Running `"$($Path.FullName)`" /silent /install"
        $result = Start-Command -Command "`"$($Path.FullName)`"" -Arguments "/silent /install"
        Write-Log -Message "Command result: $($result.ExitCode)"
        
        Test-AppInstall -AppName $AppName -AppVersion $AppVersion
    }
}

####################################################

Function Invoke-VCRuntimeInstall {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo[]]$Path,

        [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide app name to search for'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $AppName,

        [Parameter(Mandatory = $true, Position = 3, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $True,
            HelpMessage = 'Please provide app version to search for'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $AppVersion
    )

    Write-Log -Message "Using path: $($Path.FullName)"
    Write-Log -Message "Using app name: $($AppName) with app version: $($AppVersion)"
    $installVCRuntime = $false

    [version]$vcRuntimeInstallEXEVer = $Path.VersionInfo.FileVersion
    Write-Log -Message "VCRuntime Install version info:$($vcRuntimeInstallEXEVer | Format-List * | Out-String)"

    If (-Not($vcRuntimeInstallEXEVer)) {
        Write-Log -Message "Unable to determine package version" -WriteHost Yellow
        If ($VerbosePreference -eq 'Continue') { $null = Stop-Transcript }
        Throw "Unable to determine package version"
    }

    Write-Log -Message "VCRuntime installer version: $vcRuntimeInstallEXEVer" -WriteHost Magenta
    #$vcRuntimeAppDetails = Get-ProgramUninstallString -Filter "Microsoft Visual C++ 2022 $AppArch Additional Runtime - 14.*"
    #$vcRuntimeAppDetails = Get-ProgramUninstallString -Filter "Microsoft Visual C++ 2015-202* Redistributable ($($AppArch.ToLower())) - 14.*"
    #$vcRuntimeAppDetails = Get-ProgramUninstallString -Filter $AppName
    $vcRuntimeAppDetails = Get-ProgramUninstallString -Filter $AppName | Where-Object { $_.version -like $AppVersion } | Select-Object -First 1

    If ($vcRuntimeAppDetails) {
        $vcRuntimeAppDetails
        #Check Version
        $currentVCRuntimeVersion = [Version]$vcRuntimeAppDetails.Version
        If (-Not($currentVCRuntimeVersion)) {
            Write-Log -Message "VCRuntime version not detected, install package version" -WriteHost Yellow
            $installVCRuntime = $true
        }
        Else {
            Write-Log -Message "Currently installed version of VCRuntime: $currentVCRuntimeVersion" -WriteHost Cyan
            #If ($currentVCRuntimeVersion -lt $vcRuntimeInstallEXEVer) {
            If ([Version]::new($currentVCRuntimeVersion.Major, $currentVCRuntimeVersion.Minor, $currentVCRuntimeVersion.Build) -lt [Version]::new($vcRuntimeInstallEXEVer.Major, $vcRuntimeInstallEXEVer.Minor, $vcRuntimeInstallEXEVer.Build)) {
                Write-Log -Message "VCRuntime upgrade required!" -WriteHost Yellow
                $installVCRuntime = $true
            }
            Else {
                Write-Log -Message "No VCRuntime upgrade required." -WriteHost Green
            }
        }
    }
    Else {
        Write-Log -Message "VCRuntime not detected, will install" -WriteHost Yellow
        $installVCRuntime = $true
    }

    If ($installVCRuntime -eq $true) {
        Write-Log -Message "Installing VCRuntime" -WriteHost Cyan

        $vcRuntimeLog = $($script:logPath + "\VCRuntime-$AppArch" + $(Get-Date -Format 'yyyyMMdd-HHmmssff') + ".log")
        Write-Log -Message "Running `"$($Path.FullName)`" /install /quiet /norestart /log `"$vcRuntimeLog`""
        $result = Start-Command -Command "`"$($Path.FullName)`"" -Arguments "/install /quiet /norestart /log `"$vcRuntimeLog`""
        Write-Log -Message "Command result: $($result.ExitCode)"

        Test-AppInstall -AppName $AppName -AppVersion $AppVersion
    }
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

    $appsInitial = Get-InstalledApps

    #.NET 8 x64
    $dotNetFile = Get-DotNetSource -Path "$PSScriptRoot\DotNet8_x64\*"
    Invoke-DotNetInstall -AppName "Microsoft Windows Desktop Runtime - 8.0.* (x64)" -AppVersion '8.0.*'
    $apps2 = Get-ProgramUninstallString
    Compare-Object -ReferenceObject $appsInitial -DifferenceObject $apps2

    #Remove .NET 6 x86
    Remove-App -AppName 'Microsoft Windows Desktop Runtime - 6.0.* (x86)' -AppVersion '6.0.*'
    $apps3 = Get-ProgramUninstallString
    Compare-Object -ReferenceObject $appsInitial -DifferenceObject $apps3

    #Remove .NET 6 x64
    Remove-App -AppName 'Microsoft Windows Desktop Runtime - 6.0.* (x64)' -AppVersion '6.0.*'
    $apps3 = Get-ProgramUninstallString
    Compare-Object -ReferenceObject $appsInitial -DifferenceObject $apps3

    $appsFinal = Get-InstalledApps

    <#
    #Need an OOBE check - and if so, exitcode should force a reboot
    $OOBEComplete = Test-OOBE
    Write-Log -Message "OOBE is complete: $OOBEComplete"

    If ($OOBEComplete -eq $false) {
        Write-Log -Message "Running during OOBE"
        Write-Log -Message "Will force reboot!" -WriteHost Cyan
        $rebootNow = $true
    }
    Else {
        Write-Log -Message "Not running during OOBE, so no reboot enforced." -WriteHost Green
    }
    #>

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

#Final
If ($rebootNow -eq $true) {
    Write-Log -Message "Rebooting..." -WriteHost Yellow
    Write-Log "$ScriptName completed." -WriteEventLog
    If ($VerbosePreference -eq 'Continue') { $null = Stop-Transcript }
    [Environment]::Exit(1641)# Hard Reboot - i.e. reboot now!
}
Else {
    Write-Log "$ScriptName completed." -WriteEventLog
    If ($VerbosePreference -eq 'Continue') { $null = Stop-Transcript }
}

##########################################################################################################
##########################################################################################################
#endregion Main Script work section
