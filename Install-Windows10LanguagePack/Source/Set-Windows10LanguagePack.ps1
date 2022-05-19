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
$VerbosePreference = "Continue" #Enables Verbose Logging, can be enabled with -verbose on the cmdline too
$script:BuildVer = "1.0"
$script:ProgramFiles = $env:ProgramFiles
$script:ParentFolder = $PSScriptRoot | Split-Path -Parent
$script:ScriptName = $myInvocation.MyCommand.Name
$script:ScriptName = $scriptName.Substring(0, $scriptName.Length - 4)
$script:LogName = $scriptName + "_" + (Get-Date -UFormat "%d-%m-%Y")
#C:\Windows\system32\config\systemprofile\AppData\Local
#$script:logPath = "$($env:LOCALAPPDATA)\Microsoft\IntuneApps\$scriptName"
$script:logPath = "$PSScriptRoot"
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

                #$Query = & $env:SystemRoot\System32\query.exe user /server $ComputerName
                $Query = Start-Command -Command "`"$env:SystemRoot\System32\query.exe`"" -Arguments "user /server $ComputerName"
                Write-Host "Command result: $Query"
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

        # output data
        $UsersComputersToOutput
    
        Write-Verbose -Message "VERBOSE: Ending End"
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

Function Set-Language {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Language,

        [switch]$SetDefaultLanguage
    )

    Write-Log -Message "Using language: $Language"
    Write-Log -Message "Set default language: $SetDefaultLanguage"

    #region configure OS language
    If ($setDefaultLanguage) {
        #Find loggged on user
        Write-Log -Message "Finding logged on user"
        #$users = Get-ActiveUser -Method Query
        $users = Get-ActiveUser -Method CIM
        $loggedOnUser = "$($users.username[0])"
        #$azureADUser = "AzureAD\$loggedOnUser"
        $regexMatchStringInQuotes = [regex]'(?<=\=")(.+?)(?=\",)'
        $userRaw = (Get-WmiObject -ComputerName $env:COMPUTERNAME -Class Win32_LoggedOnUser | Select-Object Antecedent).Antecedent[0]
        $domain = ([regex]::match($userRaw, $regexMatchStringInQuotes).Groups[1]).Value
        $azureADUser = "$domain\$loggedOnUser"
        Write-Log -Message "Logged on user: $loggedOnUser"
        Write-Log -Message "AzureAD user: $azureADUser"

        #Find profiles path
        Write-Log -Message "Determine user profile path" -WriteEventLog
        $profilesPath = Split-Path -Path (Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.LocalPath -notlike "*$env:SystemRoot*" } | Select-Object LocalPath -First 1).LocalPath -Parent
        Write-Log -Message "User profile path: $profilesPath" -WriteEventLog
        $loggedOnUserProfilePath = "$($profilesPath)\$loggedOnUser"

        Write-Log "Logged on user profile path: $loggedOnUserProfilePath" -WriteEventLog
    }
    
    $regexMatchNameInBrackets = [regex]"\((.*)\)"
    #$language = $selectedLanguage.Language
    $language = $selectedLanguage.RegionTag
    $applicationId = $selectedLanguage.StoreAppId
    $geoId = $selectedLanguage.GeoLocIDDec
    $inputLanguageID = [regex]::match($selectedLanguage.PrimaryInput, $regexMatchNameInBrackets).Groups[1]
    #$inputLanguageID = $selectedLanguage.PrimaryInput
    $secondInputLanguage = [regex]::match($selectedLanguage.SecondaryInput, $regexMatchNameInBrackets).Groups[1]
    #$secondInputLanguage = $selectedLanguage.SecondaryInput

    # the language we want as new default
    #$language = "de-DE"
    #$language = "ja-JP"

    #Start-Transcript -Path "$env:TEMP\LXP-SystemContext-Installer-$language.log" | Out-Null

    #region store
    # found in MS online Store:
    # https://www.microsoft.com/de-de/p/deutsch-local-experience-pack/9p6ct0slw589
    #$applicationId = "9p6ct0slw589" # german

    # https://businessstore.microsoft.com/en-us/store/details/-----/9N4S78P86PKX
    # $applicationId = "9N4S78P86PKX" # Arabic (Saudi)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9N1W692FV4S1
    # $applicationId = "9N1W692FV4S1" # Japanese

    # https://businessstore.microsoft.com/en-us/store/details/paket-pengalaman-lokal-bahasa-indonesia/9P4X3N4SDK8P
    # $applicationId = "9P4X3N4SDK8P" # Indonesian Bahasa

    # https://businessstore.microsoft.com/en-us/store/details/pakiet-lokalizacyjny--polski/9NC5HW94R0LD
    # $applicationId = "9NC5HW94R0LD" # Polish

    # https://businessstore.microsoft.com/en-us/store/details/local-experience-pack-para-portugus-portugal/9P7X8QJ7FL0X
    # $applicationId = "9P7X8QJ7FL0X" # Portugese Portugal

    # https://businessstore.microsoft.com/en-us/store/details/trke-yerel-deneyim-paketi/9NL1D3T5HG9R
    # $applicationId = "9NL1D3T5HG9R" # Turkish

    # https://businessstore.microsoft.com/en-us/store/details/ting-vit-gi-tri-nghim-cc-b/9P0W68X0XZPT
    # $applicationId = "9P0W68X0XZPT" # Vietnamese

    # https://businessstore.microsoft.com/en-us/store/details/lokalni-paket-za-hrvatski/9NW01VND4LTW
    # $applicationId = "9NW01VND4LTW" # Croation

    # https://businessstore.microsoft.com/en-us/store/details/---/9NB6ZFND5HCQ
    # $applicationId = "9NB6ZFND5HCQ" # Hebrew Israel

    # https://businessstore.microsoft.com/en-us/store/details/english-united-kingdom-local-experience-pack/9NT52VQ39BVN
    # $applicationId = "9NT52VQ39BVN" # English UK

    # https://businessstore.microsoft.com/en-us/store/details/english-united-states-local-experience-pack/9PDSCC711RVF
    # $applicationId = "9PDSCC711RVF" # English US

    # https://businessstore.microsoft.com/en-us/store/details/local-experience-pakket-voor-nederlands/9PF1C9NB5PRV
    # $applicationId = "9PF1C9NB5PRV" # Dutch

    # https://businessstore.microsoft.com/en-us/store/details/paquete-de-experiencia-local-en-espaol-espaa/9NWVGWLHPB1Z
    # $applicationId = "9NWVGWLHPB1Z" # Spanish Spain

    # https://businessstore.microsoft.com/en-us/store/details/----/9NMJCX77QKPX
    # $applicationId = "9NMJCX77QKPX" # Russian?

    # https://businessstore.microsoft.com/en-us/store/details/paquete-de-experiencia-local-en-espaol-mxico/9N8MCM1X3928
    # $applicationId = "" # Spanish Mexican

    # https://businessstore.microsoft.com/en-us/store/details/-----/9PPPMZRSGHR8
    # $applicationId = "" # Ukrainian

    # https://businessstore.microsoft.com/en-us/store/details/pacote-de-experincia-local-em-portugus-brasil/9P8LBDM4FW35
    # $applicationId = "" # Portugese Brazil

    # https://businessstore.microsoft.com/en-us/store/details/module-dexprience-locale-franais-france/9NHMG4BJKMDG
    # $applicationId = "" # French France

    # https://businessstore.microsoft.com/en-us/store/details/--/9PCJ4DHCQ1JQ
    # $applicationId = "" # Chinese Taiwan zh-TW

    # https://businessstore.microsoft.com/en-us/store/details/ltzebuergesch-local-experience-pack/9N0ST1WBZ9D9
    # $applicationId = "" # Luxembourg

    # https://businessstore.microsoft.com/en-us/store/details/ikinyarwanda---local-experience-pack/9NFW0M20H9WG
    # $applicationId = "" # Kinyarwanda

    # https://businessstore.microsoft.com/en-us/store/details/---/9NGS7DD4QS21
    # $applicationId = "" # Persian

    # https://businessstore.microsoft.com/en-us/store/details/pachet-de-experien-local-romn/9MWXGPJ5PJ3H
    # $applicationId = "" # Romanian

    # https://businessstore.microsoft.com/en-us/store/details/paquet-dexperincia-local-en-catal/9P6JMKJQZ9S7
    # $applicationId = "" # Catalan

    # https://businessstore.microsoft.com/en-us/store/details/lokalni-paket-za-hrvatski/9NW01VND4LTW
    # $applicationId = "" # Hungary hr-HR

    # https://businessstore.microsoft.com/en-us/store/details/sada-pro-mstn-prosted-v-etin/9P3WXZ1KTM7C
    # $applicationId = "" # Czech

    # https://businessstore.microsoft.com/en-us/store/details/------/9N586B13PBLD
    # $applicationId = "" # Greek

    # https://businessstore.microsoft.com/en-us/store/details/balk-pre-loklne-prostredie-v-slovenine/9N7LSNN099WB
    # $applicationId = "" # Slovakia

    # https://businessstore.microsoft.com/en-us/store/details/lietuvi-k-lokalizuotos-vartotojo-ssajos-paketas/9NWWD891H6HN
    # $applicationId = "" # Lithuanian

    # https://businessstore.microsoft.com/en-us/store/details/----/9MX54588434F
    # $applicationId = "" # Bulgarian

    # https://businessstore.microsoft.com/en-us/store/details/dansk-lokal-grnsefladepakke/9NDMT2VKSNL1
    # $applicationId = "" # Danish

    # https://businessstore.microsoft.com/en-us/store/details/slovenski-paket-lokalnih-izkuenj/9NV27L34J4ST
    # $applicationId = "" # Slovenian

    # https://businessstore.microsoft.com/en-us/store/details/eesti-keelde-lokaliseeritud-kasutajaliidese-pakett/9NFBHFMCR30L
    # $applicationId = "" # Estonian

    # https://businessstore.microsoft.com/en-us/store/details/---/9NDWFTFW12BQ
    # $applicationId = "" # Urdu

    # https://businessstore.microsoft.com/en-us/store/details/---/9PMQJJGF63FW
    # $applicationId = "" # Telugu

    # https://businessstore.microsoft.com/en-us/store/details/---/9PDZB1WT1B34
    # $applicationId = "" # Tamil

    # https://businessstore.microsoft.com/en-us/store/details/paketa-e-prvojs-lokale-n-shqip/9MWLRGNMDGK7
    # $applicationId = "" # Albanian

    # https://businessstore.microsoft.com/en-us/store/details/azrbaycan-dilind-lokal-tcrb-paketi/9P5TFKZHQ5K8
    # $applicationId = "" # Azerbaijani

    # https://businessstore.microsoft.com/en-us/store/details//9MSTWFRL0LR4
    # $applicationId = "" # Thai

    # https://businessstore.microsoft.com/en-us/store/details/norsk-bokml-lokal-grensesnittpakke/9N6J0M5DHCK0
    # $applicationId = "" # Norwegian (Bokmål)

    # https://businessstore.microsoft.com/en-us/store/details/ozbekcha-mahalliy-tajribalar-toplami/9P5P2T5P5L9S
    # $applicationId = "" # Uzbek

    # https://businessstore.microsoft.com/en-us/store/details/-------/9MXGN7V65C7B
    # $applicationId = "" # Serbian (Cyrillic, Bosnia and Herzegovina)

    # https://businessstore.microsoft.com/en-us/store/details/paket-za-lokalni-interfejs-za-srpski/9NBZ0SJDPPVT
    # $applicationId = "" # Serbian (Latin, Serbia)

    # https://businessstore.microsoft.com/en-us/store/details/-----/9NV90Q1X1ZR2
    # $applicationId = "" # Tatar

    # https://businessstore.microsoft.com/en-us/store/details/---/9NKM28TM6P67
    # $applicationId = "" # Armenian

    # https://businessstore.microsoft.com/en-us/store/details/paket-za-lokalni-interfejs-za-bosanski/9MVFKLJ10MFL
    # $applicationId = "" # Bosnian (Latin, Bosnia and Herzegovina)

    # https://businessstore.microsoft.com/en-us/store/details/---/9MWXCKHJVR1J
    # $applicationId = "" # Marathi

    # https://businessstore.microsoft.com/en-us/store/details/----/9MXPBGNNDW3L
    # $applicationId = "" # Belarusian

    # https://businessstore.microsoft.com/en-us/store/details/latvieu-lokl-interfeisa-pakotne/9N5CQDPH6SQT
    # $applicationId = "" # Latvian

    # https://businessstore.microsoft.com/en-us/store/details/kifurushi-cha-vijenzi-vya-ndani-cha-kiswahili/9NFF2M19DQ55
    # $applicationId = "" # Kiswahili

    # https://businessstore.microsoft.com/en-us/store/details/---/9NGL4R61W3PL
    # $applicationId = "" # Amharic

    # https://businessstore.microsoft.com/en-us/store/details/trkmen-dilinde-erli-tejribe-paketi/9NKHQ4GL6VLT
    # $applicationId = "" # Turkmen

    # https://businessstore.microsoft.com/en-us/store/details/pecyn-profiad-lleol-cymraeg/9NKJ9TBML4HB
    # $applicationId = "" # Welsh

    # https://businessstore.microsoft.com/en-us/store/details/---/9NKM28TM6P67
    # $applicationId = "" # Armenian

    # https://businessstore.microsoft.com/en-us/store/details/pek-pengalaman-bahasa-melayu/9NPXL8ZSDDQ7
    # $applicationId = "" # Malay

    # https://businessstore.microsoft.com/en-us/store/details/pakki-me-stafru-notendavimti-fyrir-slensku/9NTHJR7TQXX1
    # $applicationId = "" # Icelandic

    # https://businessstore.microsoft.com/en-us/store/details/---/9NTJLXMXX35J
    # $applicationId = "" # Assamese

    # https://businessstore.microsoft.com/en-us/store/details/---/9NVF9QSLGTL0
    # $applicationId = "" # Sinhala

    # https://businessstore.microsoft.com/en-us/store/details/pack-para-sa-lokal-na-karanasan-sa-filipino/9NWM2KGTDSSS
    # $applicationId = "" # Filipino

    # https://businessstore.microsoft.com/en-us/store/details/---/9NTJLXMXX35J
    # $applicationId = "" # Assamese

    # https://businessstore.microsoft.com/en-gb/store/details/paquete-de-experiencia-local-en-galego/9NXRNBRNJN9B
    # $applicationId = "" # Galician (Spain)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9NZC3GRX8LD3
    # $applicationId = "" # Hindi (India)

    # https://businessstore.microsoft.com/en-gb/store/details/----/9P1C18QL3D7H
    # $applicationId = "" # Kurdish (Iraq)

    # https://businessstore.microsoft.com/en-gb/store/details/------/9P1X6XB1K3RN
    # $applicationId = "" # Macedonian (Macedonia, FYRO)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9P2HMSWDJDQ1
    # $applicationId = "" # Gujarati (India)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9P3NGC6X5ZQC
    # $applicationId = "" # Dari (Afghanistan)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9P52C5D7VL5S
    # $applicationId = "" # Uyghur (China)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9P60JZL05WGH
    # $applicationId = "" # Georgian (Georgia)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9P7CHPLWDQVN
    # $applicationId = "" # Nepali (Nepal)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9P7D3JJGZM48
    # $applicationId = "" # Kyrgyz (Kyrgyzstan)

    # https://businessstore.microsoft.com/en-gb/store/details/afrikaans-plaaslike-ervaringpak/9PDW16B5HMXR
    # $applicationId = "" # Afrikaans (South Africa)

    # https://businessstore.microsoft.com/en-gb/store/details/paquet-dexperincia-local-de-valenci/9P9K3WMFSW90
    # $applicationId = "" # Valencian

    # https://businessstore.microsoft.com/en-gb/store/details/---/9PG1DHC4VTZW
    # $applicationId = "" # Mongolian (Mongolia)

    # https://businessstore.microsoft.com/en-gb/store/details/-/9PGKTS4JS531
    # $applicationId = "" # Khmer (Cambodia)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9PHV179R97LV
    # $applicationId = "" # Kazakh (Kazakhstan)

    # https://businessstore.microsoft.com/en-gb/store/details/norsk-nynorsk-lokal-grensesnittpakke/9PK7KM3Z06KH
    # $applicationId = "" # Norwegian (Nynorsk) (Norway)

    # https://businessstore.microsoft.com/en-gb/store/details/------/9PPD6CCK9K5H
    # $applicationId = "" # Serbian (Cyrillic) (Serbia )

    # https://businessstore.microsoft.com/en-gb/store/details/---/9MV3P55CMZ6P
    # $applicationId = "" # Konkani (India)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9MX15485N3RK
    # $applicationId = "" # Cherokee (Cherokee) (United States)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9MZHLBPPT2HC
    # $applicationId = "" # Tajik (Tajikistan)

    # https://businessstore.microsoft.com/en-gb/store/details/hausa-fakitin-warewa-ta-gida/9N1L95DBGRG3
    # $applicationId = "" # Hausa (Latin) (Nigeria)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9N8X352G5NZV
    # $applicationId = "" # Afghanistan

    # https://businessstore.microsoft.com/en-gb/store/details/---/9NB9JSCXW9X5
    # $applicationId = "" # Sindhi (Pakistan)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9NC6DB7N95F9
    # $applicationId = "" # Kannada (India)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9NC8C9RDNK2S
    # $applicationId = "" # Tigrinya (Ethiopia)

    # https://businessstore.microsoft.com/en-gb/store/details/setswana-sephuthelo-sa-maitemogelo-a-selegae/9NFSXM123DHT
    # $applicationId = "" # Setswana (South Africa)

    # https://businessstore.microsoft.com/en-gb/store/details/yorb-kjp-rr-agbgb/9NGM3VPPZS5V
    # $applicationId = "" # Yoruba (Nigeria)

    # https://businessstore.microsoft.com/en-gb/store/details/wolof-kmbu-jfandikoo-ci-gox/9NH3SW1CR90F
    # $applicationId = "" # Wolof (Senegal)

    # https://businessstore.microsoft.com/en-gb/store/details/runasimi-hunta-local-yachaykuna/9NHTX8NVQ04K
    # $applicationId = "" # Quechua (Peru)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9NJRL03WH6FM
    # $applicationId = "" # Punjabi (Pakistan)

    # https://businessstore.microsoft.com/en-gb/store/details/esperientzia-lokalaren-paketea-euskaraz/9NMCHQHZ37HZ
    # $applicationId = "" # Basque (Basque)

    # https://businessstore.microsoft.com/en-gb/store/details/isizulu-iphakethe-lokuhlangenwe-nakho-kwasendaweni/9NNRM7KT5NB0
    # $applicationId = "" # isiZulu (South Africa)

    # https://businessstore.microsoft.com/en-gb/store/details/sehlopha-sa-maitemogelo-a-gae-sa-sesotho-sa-leboa/9NS49QLX5CDV
    # $applicationId = "" # Sesotho sa Leboa (South Africa)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9NSNC0ZJX69B
    # $applicationId = "" # Punjabi (India)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9NTHCXCXSJDH
    # $applicationId = "" # Odia (India)

    # https://businessstore.microsoft.com/en-gb/store/details/iphekhi-yamava-asekuhlaleni-yesixhosa-sase/9NW3QWSLQD17
    # $applicationId = "" # isiXhosa (South Africa)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9NWDTV8FFV7L
    # $applicationId = "" # Malayalam (India)

    # https://businessstore.microsoft.com/en-gb/store/details/gaeilge-paca-eispiris-lognta/9P0L5Q848KXT
    # $applicationId = "" # Irish (Ireland)

    # https://businessstore.microsoft.com/en-gb/store/details/pacaid-rainneachd-ionadail-na-gidhlig/9P1DBPF36BF3
    # $applicationId = "" # Scottish Gaelic (United Kingdom)

    # https://businessstore.microsoft.com/en-gb/store/details/----/9P1M44L7W84T
    # $applicationId = "" # Bangla (India)

    # https://businessstore.microsoft.com/en-gb/store/details/pkai-wheako-paetata-reo-mori/9P2GDFB3JPSX
    # $applicationId = "" # Maori (New Zealand)

    # https://businessstore.microsoft.com/en-gb/store/details/kiche-ujutunaj-ajwaral-etamanem/9P2V6MNNQZ0B
    # $applicationId = "" # Afghanistan

    # https://businessstore.microsoft.com/en-gb/store/details/pakkett-tal-esperjenza-lokali-malti/9PDG96SQ6BN8
    # $applicationId = "" # Maltese (Malta)

    # https://businessstore.microsoft.com/en-gb/store/details/igbo---mkpokota-ahumahu-obodo/9PG4ZFJ48JSX
    # $applicationId = "" # Igbo (Nigeria)

    # https://businessstore.microsoft.com/en-gb/store/details/----/9PH7TKVXGGM8
    # $applicationId = "" # Bangla (Bangladesh)

    # https://businessstore.microsoft.com/en-gb/store/details/lokaliserat-grnssnittspaket-fr-svenska/9P0HSNX08177
    # $applicationId = "" # Swedish (Sweden)

    # https://businessstore.microsoft.com/en-gb/store/details/suomi-paikallinen-paketti/9MW3PQ7SD3QK
    # $applicationId = "" # Finnish (Finland)

    # https://businessstore.microsoft.com/en-gb/store/details/---/9N4TXPCVRNGF
    # $applicationId = "" # Korean

    # https://businessstore.microsoft.com/en-gb/store/details/italiano-pacchetto-di-esperienze-locali/9P8PQWNS6VJX
    # $applicationId = "" # Italian

    # https://businessstore.microsoft.com/en-gb/store/details/module-dexprience-locale-franais-canada/9MTP2VP0VL92
    # $applicationId = "" # French Canadian

    # https://businessstore.microsoft.com/en-gb/store/details//9NRMNT6GMZ70
    # $applicationId = "" # Chinese China

    # https://businessstore.microsoft.com/en-gb/store/details/pakiet-lokalizacyjny--polski/9NC5HW94R0LD
    # $applicationId = "" # Polish

    # 
    # $applicationId = "" # 


    # https://docs.microsoft.com/en-us/configmgr/protect/deploy-use/find-a-pfn-for-per-app-vpn

    # Find a PFN if the app is not installed on a computer
    # ====================================================
    # 1. Go to https://www.microsoft.com/store/apps
    # 2. Enter the name of the app in the search bar. In our example, search for OneNote.
    # 3. Click the link to the app. Note that the URL that you access has a series of letters at the end. In our example, 
    # the URL looks like this: https://www.microsoft.com/store/apps/onenote/9wzdncrfhvjl
    # 4. In a different tab, paste the following URL, https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/<app id>/applockerdata, 
    # replacing <app id> with the app id you obtained from https://www.microsoft.com/store/apps - that series of letters 
    # at the end of the URL in step 3. In our example, example of OneNote, you'd paste: 
    # https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/9wzdncrfhvjl/applockerdata.

    # found with special API here:
    # https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/9pdscc711rvf/applockerdata
    #$packageFamilyName = 'Microsoft.LanguageExperiencePacken-US_8wekyb3d8bbwe' # english

    # https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/9p6ct0slw589/applockerdata
    #$packageFamilyName = 'Microsoft.LanguageExperiencePackde-DE_8wekyb3d8bbwe' # german
    #endregion store

    # Andrew Cooper (@adotcoop) simplified it even more to automatically parse the packageFamilyName, thanks for this small tweak even less to configure then
    $webpage = Invoke-WebRequest -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$applicationId/applockerdata"
    $packageFamilyName = ($webpage | ConvertFrom-JSON).packageFamilyName

    # found in Business Store:
    # https://businessstore.microsoft.com/en-us/manage/inventory/apps/9P6CT0SLW589/0016/00000000000000000000000000000000;tab=users
    $skuId = 0016

    # found here:
    # https://docs.microsoft.com/en-us/windows/win32/intl/table-of-geographical-locations?redirectedfrom=MSDN
    #$geoId = 244 # United States
    #$geoId = 94  # Germany
    #$geoId = 122 # Japan

    # found here:
    # https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs
    #$inputLanguageID = "0409:00000409" # en-US
    #$inputLanguageID = "0407:00000407" # de-DE
    #$inputLanguageID = "0411:{03B5835F-F03C-411B-9CE2-AA23E1171E36}{A76C93D9-5523-4E90-AAFA-4DB112F9AC76}" # ja-JP

    Write-Log -Message "language: $language, skuId: $skuId, geoId: $geoId, applicationId = $applicationId"
    Write-Log -Message "keyboard: $inputLanguageID, second keyboard: $secondInputLanguage"
    #return
    If ($setDefaultLanguage) {
        # custom folder for temp scripts
        Write-Log -Message "...creating custom temp script folder"
        #$scriptFolderPath = "$env:SystemDrive\ProgramData\CustomTempScripts"
        $scriptFolderPath = "$env:ProgramFiles\MCS\Install-LanguageExperiencePack"
        New-Item -ItemType Directory -Force -Path $scriptFolderPath

        $languageXmlPath = $(Join-Path -Path $scriptFolderPath -ChildPath "MUI.xml")
        # language xml definition for intl.cpl call to switch the language 'welcome screen' and 'new user' defaults
        #<!-- UI Language Preferences -->
        #<gs:MUILanguagePreferences>
        #<gs:MUIFallback Value="$secondInputLanguage"/>
        $languageXml = @"
<gs:GlobalizationServices xmlns:gs="urn:longhornGlobalizationUnattend">

<!-- user list -->
<gs:UserList>
<gs:User UserID="Current" CopySettingsToDefaultUserAcct="true" CopySettingsToSystemAcct="true"/>
</gs:UserList>

<!-- GeoID -->
<gs:LocationPreferences>
<gs:GeoID Value="$geoId"/>
</gs:LocationPreferences>

<!-- UI Language Preferences -->
<gs:MUILanguagePreferences>
<gs:MUILanguage Value="$language"/>
</gs:MUILanguagePreferences>

<!-- system locale -->
<gs:SystemLocale Name="$language"/>

<!-- input preferences -->
<gs:InputPreferences>
<gs:InputLanguageID Action="add" ID="$inputLanguageID" Default="true"/>
<gs:InputLanguageID Action="add" ID="$secondInputLanguage"/>
</gs:InputPreferences>

<!-- user locale -->
<gs:UserLocale>
<gs:Locale Name="$language" SetAsCurrent="true" ResetAllSettings="false"/>
</gs:UserLocale>

</gs:GlobalizationServices>
"@

        Write-Log -Message "languageXml: `n$languageXml"

        $userConfigScriptPath = $(Join-Path -Path $scriptFolderPath -ChildPath "UserConfig.ps1")
        $userLogPath = "$loggedOnUserProfilePath\AppData\Local\Microsoft\IntuneApps\$scriptName"
        #Start-Transcript -Path "`$env:TEMP\LXP-UserSession-Config-`$language.log" | Out-Null
        # we could encode the complete script to prevent the escaping of $, but I found it easier to maintain
        # to not encode. I do not have to decode/encode all the time for modifications.
        $userConfigScript = @"
`$userLogPath = "$userLogPath"
`$language = "$language"

New-Item -Path "`$userLogPath" -ItemType "directory" -Force
Start-Transcript -Path "`$userLogPath\LXP-UserSession-Config-`$language.log" -IncludeInvocationHeader -Force | Out-Null

`$geoId = $geoId

"explicitly register the LXP in current user session (Add-AppxPackage -Register ...)"
`$appxLxpPath = (Get-AppxPackage | Where-Object Name -Like *LanguageExperiencePack`$language).InstallLocation
Add-AppxPackage -Register -Path "`$appxLxpPath\AppxManifest.xml" -DisableDevelopmentMode

"Set-WinUILanguageOverride = `$language"
Set-WinUILanguageOverride -Language `$language

"Set-WinUserLanguageList = `$language"
Set-WinUserLanguageList `$language -Force

"Set-WinSystemLocale = `$language"
Set-WinSystemLocale -SystemLocale `$language

"Set-Culture = `$language"
Set-Culture -CultureInfo `$language

"Set-WinHomeLocation = `$geoId"
Set-WinHomeLocation -GeoId `$geoId

Stop-Transcript -Verbose
"@

        Write-Log -Message "userConfigScript: `n$userConfigScript"

        $userConfigScriptHiddenStarterPath = $(Join-Path -Path $scriptFolderPath -ChildPath "UserConfigHiddenStarter.vbs")
        $userConfigScriptHiddenStarter = @"
sCmd = "powershell.exe -ex bypass -file ""$userConfigScriptPath"""
Set oShell = CreateObject("WScript.Shell")
oShell.Run sCmd,0,true
"@

        Write-Log -Message "userConfigScriptHiddenStarter : `n$userConfigScriptHiddenStarter "
    }
    # There is a known issue: It is possible for the language pack cleanup task to remove a language pack before the language pack can be used.
    # It can be prevented by not allowing to cleanup the language packs.
    # https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/language-packs-known-issue
    # IME app install runs by default in 32-bit so we write explicitly to 64-bit registry
    Write-Log -Message "...set reg key: BlockCleanupOfUnusedPreinstalledLangPacks = 1"
    #& REG add "HKLM\Software\Policies\Microsoft\Control Panel\International" /v BlockCleanupOfUnusedPreinstalledLangPacks /t REG_DWORD /d 1 /f /reg:64
    & REG add "HKLM\Software\Policies\Microsoft\Control Panel\International" /v BlockCleanupOfUnusedPreinstalledLangPacks /t REG_DWORD /d 1 /f

    # We trigger via MDM method (MDM/WMI Bridge) an install of the LXP via the Store... 
    # Imagine to navigate to the store and click the LXP to install, but this time fully programmatically :-). 
    # This way we do not have to maintain language cab files in our solution here! And the store install trigger 
    # does always download the latest correct version, even when used with newer Windows versions.

    # Here are the requirements for this scenario:

    # - The app is assigned to a user Azure Active Directory (AAD) identity in the Store for Business. 
    #   You can do this directly in the Store for Business or through a management server.
    # - The device requires connectivity to the Microsoft Store.
    # - Microsoft Store services must be enabled on the device. Note that the UI for the Microsoft Store can be disabled by the enterprise admin.
    # - The user must be signed in with their AAD identity.
    $namespaceName = "root\cimv2\mdm\dmmap"
    $session = New-CimSession

    # constructing the MDM instance and correct parameter for the 'StoreInstallMethod' function call
    $omaUri = "./Vendor/MSFT/EnterpriseModernAppManagement/AppInstallation"
    $newInstance = New-Object Microsoft.Management.Infrastructure.CimInstance "MDM_EnterpriseModernAppManagement_AppInstallation01_01", $namespaceName
    $property = [Microsoft.Management.Infrastructure.CimProperty]::Create("ParentID", $omaUri, "string", "Key")
    $newInstance.CimInstanceProperties.Add($property)
    $property = [Microsoft.Management.Infrastructure.CimProperty]::Create("InstanceID", $packageFamilyName, "String", "Key")
    $newInstance.CimInstanceProperties.Add($property)

    $flags = 0
    $paramValue = [Security.SecurityElement]::Escape($('<Application id="{0}" flags="{1}" skuid="{2}"/>' -f $applicationId, $flags, $skuId))
    $params = New-Object Microsoft.Management.Infrastructure.CimMethodParametersCollection
    $param = [Microsoft.Management.Infrastructure.CimMethodParameter]::Create("param", $paramValue, "String", "In")
    $params.Add($param)

    try {
        try {
            # we create the MDM instance and trigger the StoreInstallMethod to finally download the LXP
            $instance = $session.CreateInstance($namespaceName, $newInstance)
            $result = $session.InvokeMethod($namespaceName, $instance, "StoreInstallMethod", $params)
        }
        catch [Exception] {
            write-host $_ | out-string
            Write-Log -Message "Error occurred at block2: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw
        }

        if ($result.ReturnValue.Value -eq 0) {
            Write-Log -Message "...Language Experience Pack install process triggered via MDM/StoreInstall method"
            Write-Log -Message "...busy wait until language pack found, max 15 min."

            $counter = 0
            do {
                Start-Sleep 10
                $counter++

                # check for installed Language Experience Pack (LXP)
                $packageName = "Microsoft.LanguageExperiencePack$language"
                $status = $(Get-AppxPackage -AllUsers -Name $packageName).Status

            } while ($status -ne "Ok" -and $counter -ne 90) # 90x10s sleep => 900s => 15 min. max wait time!
            #} while ($status -ne "Ok" -and $counter -ne 6) # 9x10s sleep => 60s => 1 min. max wait time!

            Write-Log -Message "Counter: $counter"
            Write-Log -Message  "Status: $status"

            If ($status -ne "Ok" -and $counter -ge 90) {
                #If ($status -ne "Ok" -and $counter -ge 6) {
                Write-Log -Message "Error occurred with language pack install" -WriteEventLog
                [int32]$mainExitCode = 60001
                [string]$mainErrorMessage = "$(Resolve-Error)"

                Write-Log -Message $mainErrorMessage
                #Show-DialogBox -Text $mainErrorMessage -Icon 'Stop'
                #Write-Log "Error occurred, create error flag file: $PSScriptRoot\Error.flg"
                #Set-Content -Path "$PSScriptRoot\Error.flg" -Value $mainErrorMessage
                Exit-Script -ExitCode $mainExitCode

                If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
                Throw
            }

            # print some LXP package details for the log
            Get-AppxPackage -AllUsers -Name $packageName

            if ($status -eq "Ok") {
                Write-Log -Message "...found Microsoft.LanguageExperiencePack$language with Status=Ok"

                # to check for availability with "DISM.exe /Online /Get-Capabilities"

                # we use dism /online /add-cpability switch to trigger an online install and dism will reach out to 
                # Windows Update to get the latest correct source files
                Write-Log -Message "...trigger install for language FOD packages"
                Write-Log -Message "`tLanguage.Basic~~~$language~0.0.1.0"
                & DISM.exe /Online /Add-Capability /CapabilityName:Language.Basic~~~$language~0.0.1.0
                Write-Log -Message "`tLanguage.Handwriting~~~$language~0.0.1.0"
                & DISM.exe /Online /Add-Capability /CapabilityName:Language.Handwriting~~~$language~0.0.1.0
                Write-Log -Message "`tLanguage.OCR~~~$language~0.0.1.0"
                & DISM.exe /Online /Add-Capability /CapabilityName:Language.OCR~~~$language~0.0.1.0
                Write-Log -Message "`tLanguage.Speech~~~$language~0.0.1.0"
                & DISM.exe /Online /Add-Capability /CapabilityName:Language.Speech~~~$language~0.0.1.0
                Write-Log -Message "`tLanguage.TextToSpeech~~~$language~0.0.1.0"
                & DISM.exe /Online /Add-Capability /CapabilityName:Language.TextToSpeech~~~$language~0.0.1.0

                If ($setDefaultLanguage) {
                    # we have to switch the language for the current user session. The powershell cmdlets must be run in the current logged on user context.
                    # creating a temp scheduled task to run on-demand in the current user context does the trick here.
                    Write-Log -Message "...trigger language change for current user session via ScheduledTask = LXP-UserSession-Config-$language"
                    Out-File -FilePath $userConfigScriptPath -InputObject $userConfigScript -Encoding ascii
                    Out-File -FilePath $userConfigScriptHiddenStarterPath -InputObject $userConfigScriptHiddenStarter -Encoding ascii

                    # REMARK: usag of wscript as hidden starter may be blocked because of security restrictions like AppLocker, ASR, etc...
                    #         switch to PowerShell if this represents a problem in your environment.
                    $taskName = "LXP-UserSession-Config-$language"
                    $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$userConfigScriptHiddenStarterPath`""
                    $trigger = New-ScheduledTaskTrigger -AtLogOn

                    #$principal = New-ScheduledTaskPrincipal -UserId (Get-CimInstance –ClassName Win32_ComputerSystem | Select-Object -expand UserName)
                    $principal = New-ScheduledTaskPrincipal -UserId $azureADUser
                    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries
                    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
                    Register-ScheduledTask $taskName -InputObject $task
                    Start-ScheduledTask -TaskName $taskName

                    Start-Sleep -Seconds 30

                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false

                    # trigger 'LanguageComponentsInstaller\ReconcileLanguageResources' otherwise 'Windows Settings' need a long time to change finally
                    Write-Log -Message "...trigger ScheduledTask = LanguageComponentsInstaller\ReconcileLanguageResources"
                    Start-ScheduledTask -TaskName "\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources"

                    Start-Sleep 10

                    # change 'welcome screen' and 'new user' language defaults
                    Write-Log -Message "...trigger language change for welcome screen and new user defaults"
                    Out-File -FilePath $languageXmlPath -InputObject $languageXml -Encoding ascii

                    # check eventlog 'Microsoft-Windows-Internationl/Operational' for troubleshooting
                    & $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$languageXmlPath`""

                    # trigger store updates, there might be new app versions due to the language change
                    Write-Log -Message "...trigger MS Store updates for app updates"
                    Get-CimInstance -Namespace $namespaceName -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName "UpdateScanMethod"

                    Write-Log -Message "Calling BCDEdit to set boot menu language to: $language"
                    #& $env:SystemRoot\System32\bcdedit.exe "/set locale $language"
                    $result = Start-Command -Command "`"$env:SystemRoot\System32\bcdedit.exe`"" -Arguments "/set locale $language"
                    Write-Log -Message "Command result: $result"
                }
            }
        }
        else {
            Write-Log -Message "Error occurred at if1: $($_.Exception.message)" -WriteEventLog
            Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
            If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
            Throw
        }

        Write-Log -Message "...cleanup and finish"
        $session.DeleteInstance($namespaceName, $instance) | Out-Null
        Remove-CimSession -CimSession $session
        If ($setDefaultLanguage) {
            Remove-Item -Path $scriptFolderPath -Force -Recurse
        }
    }
    catch [Exception] {
        $session.DeleteInstance($namespaceName, $instance) | Out-Null
        Write-Log -Message "Error occurred at block1: $($_.Exception.message)" -WriteEventLog
        Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
        If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
        Throw
    }

    #endregion configure OS language
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
        [switch]$DisableLogging = $false,

        [string]$Language,

        [switch]$SetDefaultLanguage
    )

    Write-Log -Message "Using language: $Language"
    Write-Log -Message "Set default language: $SetDefaultLanguage"

    Try {
        ## Set the script execution policy for this process
        Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' } Catch {}

        ##*===============================================
        ##* VARIABLE DECLARATION
        ##*===============================================
        ## Variables: Application
        [string]$appVendor = 'Microsoft'
        [string]$appName = 'Windows 10'
        [string]$appVersion = 'OS Language'
        [string]$appArch = 'x64'
        [string]$appLang = 'EN'
        [string]$appRevision = '01'
        [string]$appScriptVersion = '1.0.0'
        [string]$appScriptDate = '18/10/2021'
        [string]$appScriptAuthor = 'Microsoft'
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
        [string]$deployAppScriptDate = '18/10/2021'
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
            Write-Log -Message "Error occurred: importing PSAppDeployToolkit module sources"
            #Write-Log "Error occurred, create error flag file: $PSScriptRoot\Error.flg"
            #Set-Content -Path "$PSScriptRoot\Error.flg" -Value "Module [$moduleAppDeployToolkitMain] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
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
            #Write-Log -Message "Running pre-installation tasks, please wait..."

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
            Write-Log -Message "Running installation tasks, please wait..."
            If ($SetDefaultLanguage) {
                Write-Log -Message "Set OS default language to: $selectedLanguage"
                Write-Log -Message "Calling Set-Language function with Set Default Language enabled..."
                Set-Language -Language $selectedLanguage -SetDefaultLanguage
            }
            else {
                Write-Log -Message "Not setting language as OS default"
                Write-Log -Message "Calling Set-Language function to install the language but not apply it..."
                Set-Language -Language $selectedLanguage
            } 

            ##*===============================================
            ##* POST-INSTALLATION
            ##*===============================================
            [string]$installPhase = 'Post-Installation'

            ## <Perform Post-Installation tasks here>

            ## Display a message at the end of the install
            If (-not $useDefaultMsi) { Show-InstallationPrompt -Message 'Thanks for your patience. Please restart your computer to complete installation.' -ButtonRightText 'OK' -Icon Information -NoWait }
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
        Exit-Script -ExitCode $mainExitCode
    }
    Catch {
        [int32]$mainExitCode = 60001
        [string]$mainErrorMessage = "$(Resolve-Error)"
        #Write-Log -Message $mainErrorMessage -Severity 3 -Source $deployAppScriptFriendlyName
        Write-Log -Message $mainErrorMessage
        Show-DialogBox -Text $mainErrorMessage -Icon 'Stop'
        #Write-Log "Error occurred, create error flag file: $PSScriptRoot\Error.flg"
        #Set-Content -Path "$PSScriptRoot\Error.flg" -Value $mainErrorMessage
        Exit-Script -ExitCode $mainExitCode
        throw "Error occurred: $mainErrorMessage"
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

#endregion Initialisation...
##########################################################################################################
##########################################################################################################

#region Main Script work section
##########################################################################################################
##########################################################################################################
#Main Script work section
##########################################################################################################
##########################################################################################################

Write-Log -Message "Running main script section..."
Write-Log -Message "Reading current OS Language"
$currentLanguage = Get-WinUserLanguageList
$currentLanguage[0].LocalizedName
Write-Log -Message "Current OS Language set to: $($currentLanguage[0].LocalizedName)"

#Show the GUI
Write-Log "Preparing Language selection GUI..."
#region GUI
$jsonFile = "$PSScriptRoot\LanguageObjects.json"
Write-Log -Message "Reading languages from file: $jsonFile"
$languageObjects = Get-Content "$PSScriptRoot\LanguageObjects.json" -Encoding UTF8 | ConvertFrom-Json

#Ensure Script can process XAML files
Write-Log -Message "Load PresentationFramework assemblies"
Add-Type -AssemblyName PresentationFramework

#Path to the XAML file?
$xamlFile = "$PSScriptRoot\MainWindow.xaml"
Write-Log -Message "Loading XAML file: $xamlFile"

#Create window
$inputXML = Get-Content $xamlFile -Raw
$inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
[XML]$XAML = $inputXML

#Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
try {
    Write-Log -Message "Build form"
    $window = [Windows.Markup.XamlReader]::Load( $reader )
}
catch {
    Write-Warning $_.Exception
    throw
}

#Create variables based on form control names.
#Variable will be named as 'var_<control name>'
Write-Log -Message "Create form object variables"
$xaml.SelectNodes("//*[@Name]") | ForEach-Object {
    If ($window.FindName($_.Name) -notlike '*System.Windows.Controls.Label*') {
        try {
            Set-Variable -Name "var_$($_.Name)" -Value $window.FindName($_.Name) -ErrorAction Stop
        }
        catch {
            throw
        }
    }
}
#Get-Variable var_*

<#
    Name                           Value
    ----                           -----
    var_buttonCancel               System.Windows.Controls.Button: Cancel
    var_buttonOK                   System.Windows.Controls.Button: OK
    var_checkboxYes                System.Windows.Controls.CheckBox Content:Yes IsChecked:False
    var_LanguageList               System.Windows.Controls.ComboBox Items.Count:0
#>

Write-Log -Message "Populate Language drop-down list box"
foreach ($language in $languageObjects) {
    $var_LanguageList.Items.Add("$($language.RegionName)") | Out-Null
    $var_LanguageList.Text = "$($language.RegionName)"
}
$var_LanguageList.Text = $currentLanguage[0].LocalizedName
Write-Host

Write-Log -Message "Prepare form objects"
$var_buttonOK.Add_Click( {
        Write-Log -Message "OK button"
        $window.close()

        If ($var_LanguageList.Text -eq $currentLanguage[0].LocalizedName) {
            Write-Host "Selected language already installed." -ForegroundColor Magenta
        }
        Else {
            Write-Host "$($var_LanguageList.Text)" -ForegroundColor Green

            #Set Language
            foreach ($language in $languageObjects) {
                If ($language.RegionName -eq $($var_LanguageList.Text)) {
                    #$selectedLanguage = $($language.RegionName)
                    $selectedLanguage = $language                  
                    Write-Log -Message "Setting OS Language to: $($selectedLanguage.RegionName)"
                    #Write-Host $language
                }
                #>
            }
            #$var_checkboxYes | Format-List *
            #Write-Host "checkbox: $var_checkboxYes"

            If (($var_checkboxYes).IsChecked -eq $true) {
                Write-Log -Message "Set OS default language to: $selectedLanguage"

                Write-Log -Message "Calling Invoke-Application function to install the language and set it as default..."
                Invoke-Application -DeploymentType 'Install' -DeployMode 'Interactive' -Language $selectedLanguage -SetDefaultLanguage
            }
            else {
                Write-Log -Message "Not setting language as OS default"
                Write-Log -Message "Calling Invoke-Application function to install the language, but not apply it..."
                Invoke-Application -DeploymentType 'Install' -DeployMode 'Interactive' -Language $selectedLanguage
            }            
        }
        Write-Host
        <#
        Add-Type -AssemblyName Microsoft.VisualBasic
        $result = [Microsoft.VisualBasic.Interaction]::MsgBox('Language pack installed.  Please reboot your device for the change to take effect.', 'OKOnly,SystemModal,Information', 'Reboot to complete!')
        $result
        #>
    })

$var_buttonCancel.Add_Click( {
        Write-Log -Message "Cancel button"
        $window.close()
        $cancelPressed = "true"
    })

Write-Log -Message "Show form onscreen"
$Null = $window.ShowDialog()
#endregion GUI

Write-Log "$ScriptName completed." -WriteEventLog
If ($VerbosePreference -eq 'Continue') { Stop-Transcript }
##########################################################################################################
##########################################################################################################
#endregion Main Script work section
