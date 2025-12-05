<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
#Script helper to build out the Config.xml for the Upload-IntuneWin script
param(
    [parameter(Mandatory = $true, HelpMessage = "Enter subfolder name of the package")]
    $Name
)

if ( $args.count -ne 0) {
    $list = $args[0]

    if (!($list -eq "--list")) {
        Write-Host
        Write-Host "Syntax : "
        Write-Host
        Write-Host "    Set-Config.ps1"
        Write-Host "    Set-Config.ps1 --list       list out the file metadata."
        Write-Host
        exit
    }
}

$package = "$PSScriptRoot\$Name"
$filename = "$PSScriptRoot\$Name\config.xml"
$version = ""
$publisher = ""
$logofile = ""
$exename = ""
$category = "Business"
$InstallOpts = ""
$UnInstallOpts = ""
$apptype = "exe"
$DetectRule = "TAGFILE"
$DetectFile = ""
$aadGroupPrefix = "MIP-WIN10-OBJECT-APP-"

# Search for file in OrigSource folder either, exe,msi or ps1 (returns only first match if multiple found)

$exename = ""
$exename = Get-ChildItem -Path $package'\OrigSource\*' -Include "*.exe" -Name | Select-Object -First 1
if ($exename.Length -eq 0) {
    $exename = Get-ChildItem -Path $package'\OrigSource\*' -Include '*.msi' -Name | Select-Object -First 1
}

if ($exename.Length -eq 0) {
    $exename = Get-ChildItem -Path $package'\OrigSource\*' -Include '*.ps1' -Name | Select-Object -First 1
}

$logofile = (Get-ChildItem -Path $package'\' -Include '*.png' -Name | Select-Object -First 1)
if ( $null -eq $logofile) { $logofile = "" } else { $logofile = $logofile.ToString() }

# Confirm filename found or get new name

Write-Host ""
Write-Host "Type a filename or Press ENTER to use " -ForegroundColor white -NoNewline
Write-Host "[$exename]" -ForegroundColor green -NoNewline

if (($result = Read-Host -Prompt " ") -ne '') { $exename = $result.tostring() }

# does OrigSource file exist
if (-not (Test-Path -Path $package'\OrigSource\'$exename -PathType Leaf)) {
    Write-Host
    Write-Host $package'\OrigSource\'$exename "not found, exiting." -ForegroundColor red
    Write-Host "" -ForegroundColor white
    exit
}

if ($exename -clike "*.ps1") {
    $appname = $exename -replace "(.exe|.msi|.ps1)", $NULL
    $apptype = "ps1"
    $version = "1.0"
    $publisher = "Microsoft"
    $description = ""
    $displayname = ""
    $DetectFile = "c:\Program Files\"
}
else {
    $appname = $exename -replace "(.exe|.msi|.ps1)", $NULL
    $DetectFile = "C:\Program Files\" + $appname + "\" + $exename

    # get file metatdata
    $exefilepath = Join-Path $package '\OrigSource\'


    $info = New-Object -ComObject Shell.Application
    $info_detailspace = $info.namespace($exefilepath)
    $file_details = $info_detailspace.items()

    <# Get object metadata specified by the index value
    0 = name
    1 = size
    2 = Type
    3 = Date modified
    4 = Date created
    5 = date accessed
    6 = Attributes
    7 = Offline Status
    8 = Availability
    9 = Perceived Type
    10 = Owner
    11 = kind
    20 = Authors
    21 = Title
    22 = Subject
    25 = Copyright
    34 = File description
    42 = Program Name
    165 - filename
    166 = File Version
    201 = Description
    217 = writers
    297 = product name
    298 = product version
    #>

    foreach ($file in $file_details) {
        if ($exename -eq ($info_detailspace.getDetailsof($file, 0))) {

            if ($list -eq '--list') {
                Write-Host
                Write-Host "0  : Name - '" $info_detailspace.getDetailsof($file, 0) "'"
                Write-Host "2  : Type - '" $info_detailspace.getDetailsof($file, 2) "'"
                Write-Host "9  :Perceived Type - '" $info_detailspace.getDetailsof($file, 9) "'"
                Write-Host "20 : Authors - '" $info_detailspace.getDetailsof($file, 20) "'"
                Write-Host "21 : Title - '" $info_detailspace.getDetailsof($file, 21) "'"
                Write-Host "22 : Subject - '" $info_detailspace.getDetailsof($file, 22) "'"
                Write-Host "25 : Copyright - '" $info_detailspace.getDetailsof($file, 25) "'"
                Write-Host "34 : File Description - '" $info_detailspace.getDetailsof($file, 34) "'"
                Write-Host "42 : Program Name - '" $info_detailspace.getDetailsof($file, 42) "'"
                Write-Host "165: Filename - '" $info_detailspace.getDetailsof($file, 165) "'"
                Write-Host "166: File Version - '" $info_detailspace.getDetailsof($file, 166) "'"
                Write-Host "201: Description - '" $info_detailspace.getDetailsof($file, 201) "'"
                Write-Host "217: Writers - '" $info_detailspace.getDetailsof($file, 217) "'"
                Write-Host "297: Product name  - '" $info_detailspace.getDetailsof($file, 297) "'"
                Write-Host "298: Product version - '" $info_detailspace.getDetailsof($file, 298) "'"
                Write-Host
            }

            if ($info_detailspace.getDetailsof($file, 2) -clike "Windows Installer*") {
                $publisher = $info_detailspace.getDetailsof($file, 20)
                $version = $info_detailspace.getDetailsof($file, 298)
                $description = $info_detailspace.getDetailsof($file, 42)
                $displayname = $info_detailspace.getDetailsof($file, 22)
                $apptype = "msi"
            }
            else {
                if ($info_detailspace.getDetailsof($file, 2) -clike "Application*") {
                    $publisher = $info_detailspace.getDetailsof($file, 25)
                    $version = $info_detailspace.getDetailsof($file, 298)
                    $description = $info_detailspace.getDetailsof($file, 34)
                    $displayname = $info_detailspace.getDetailsof($file, 297)
                    $apptype = "exe"
                }
            }
        }
    }

}
# Confirm values and prompt for changes

Write-Host "Product execution syntax is (exe/msi/ps1), Press ENTER to use " -ForegroundColor white -NoNewline
Write-Host "[$apptype]" -ForegroundColor green -NoNewline
if (($result = Read-Host -Prompt " ") -ne '') { $apptype = $result.tostring() }

Write-Host "Type a version or Press ENTER to use " -ForegroundColor white -NoNewline
Write-Host "[$version]" -ForegroundColor green -NoNewline
if (($result = Read-Host -Prompt " ") -ne '') { $version = $result.tostring() }

Write-Host "Type a displayname or Press ENTER to use " -ForegroundColor white -NoNewline
Write-Host "[$displayname]" -ForegroundColor green -NoNewline
if (($result = Read-Host -Prompt " ") -ne '') { $displayname = $result.tostring() }

Write-Host "Type a description or Press ENTER to use " -ForegroundColor white -NoNewline
Write-Host "[$description]" -ForegroundColor green -NoNewline
if (($result = Read-Host -Prompt " ") -ne '') { $description = $result.tostring() }

Write-Host "Type publisher name or Press ENTER to use " -ForegroundColor white -NoNewline
Write-Host "[$publisher]" -ForegroundColor green -NoNewline
if (($result = Read-Host -Prompt " ") -ne '') { $publisher = $result.tostring() }

Write-Host "Type a logo filename or Press ENTER to use " -ForegroundColor white -NoNewline
Write-Host "[$logofile]" -ForegroundColor green -NoNewline
if (($result = Read-Host -Prompt " ") -ne '') { $logofile = $result.tostring() }

Write-Host "Type the Intune category or Press ENTER to use " -ForegroundColor white -NoNewline
Write-Host "[$category]" -ForegroundColor green -NoNewline
if (($result = Read-Host -Prompt " ") -ne '') { $category = $result.tostring() }

# exe or msi style description info or use base package if nothing in metadata
if ($displayname -ne '') {
    $EntraGroupName = "$aadGroupPrefix$displayname v$version"
}
else {
    #$EntraGroupName = $aadGroupPrefix + $appname + ' v' + $version
    $EntraGroupName = "$aadGroupPrefix$displayname v$version"
}

Write-Host "Type the Entra Static Group Name or Press ENTER to use " -ForegroundColor white -NoNewline
Write-Host "[$EntraGroupName]" -ForegroundColor green -NoNewline
if (($result = Read-Host -Prompt " ") -ne '') { $EntraGroupName = $result.tostring() }

Write-Host "FILE or TAGFILE Detection Rule, Type TAGFILE or Press ENTER for " -ForegroundColor white -NoNewline
Write-Host "[$DetectRule]" -ForegroundColor green -NoNewline
if (($result = Read-Host -Prompt " ") -ne '') { $DetectRule = $result.tostring() }

if ($DetectRule -eq "FILE") {
    Write-Host "Type Detection Path for FILE or Press ENTER for " -ForegroundColor white -NoNewline
    Write-Host "[$DetectFile]" -ForegroundColor green -NoNewline
    if (($result = Read-Host -Prompt " ") -ne '') { $DetectFile = $result.tostring() }

}
else {
    $DetectFile = ""
}

if ($apptype -eq "ps1") {
    Write-Host "Type FULL Install command and options (e.g. -verbose)" -ForegroundColor white -NoNewline
    Write-Host "[]" -ForegroundColor green -NoNewline
    if (($result = Read-Host -Prompt " ") -ne '') { $InstallOpts = $result.tostring() }

    Write-Host "Type FULL Uninstall and options (e.g. -verbose)" -ForegroundColor white -NoNewline
    Write-Host "[]" -ForegroundColor green -NoNewline
    if (($result = Read-Host -Prompt " ") -ne '') { $UnInstallOpts = $result.tostring() }
}
else {
    Write-Host "Type any Install options (e.g. /quiet) or Press ENTER for " -ForegroundColor white -NoNewline
    Write-Host "[]" -ForegroundColor green -NoNewline
    if (($result = Read-Host -Prompt " ") -ne '') { $InstallOpts = $result.tostring() }

    Write-Host "Type any Uninstall options (e.g. /verysilent) or Press ENTER for " -ForegroundColor white -NoNewline
    Write-Host "[]" -ForegroundColor green -NoNewline
    if (($result = Read-Host -Prompt " ") -ne '') { $UnInstallOpts = $result.tostring() }
}
# open and edit the config.xml document

[XML]$XML = Get-Content $filename
$XML.CONFIG.IntuneWin_Settings.AppType = $apptype
$XML.CONFIG.IntuneWin_Settings.PackageName = $appname
$XML.CONFIG.IntuneWin_Settings.displayName = $displayname
$XML.CONFIG.IntuneWin_Settings.Description = $description
$XML.CONFIG.IntuneWin_Settings.Publisher = $publisher
$XML.CONFIG.IntuneWin_Settings.LogoFile = $logofile
$XML.CONFIG.IntuneWin_Settings.Category = $category
$XML.CONFIG.IntuneWin_Settings.AADGroupName = $EntraGroupName
$XML.CONFIG.IntuneWin_Settings.RuleType = $DetectRule
$XML.CONFIG.IntuneWin_Settings.FilePath = $DetectFile
$XML.CONFIG.IntuneWin_Settings.installCmdLine = $InstallOpts
$XML.CONFIG.IntuneWin_Settings.uninstallCmdLine = $UnInstallOpts
$XML.Save($filename)

Write-Host
Write-Host "----------------------------------------------------" -ForegroundColor cyan
Write-Host
Write-Host "  Finished, Config.xml file succesfully updated" -ForegroundColor yellow
Write-Host "  Recommended to review the file." -ForegroundColor yellow
Write-Host
Write-Host "  To continue and upload to Intune run " -ForegroundColor yellow -NoNewline
Write-Host "  .\Invoke-Upload.ps1 -Name $Name" -ForegroundColor green
Write-Host "  or" -ForegroundColor green
Write-Host "  .\Invoke-CodeSignAndUpload.ps1 -PackagePath `"$PSScriptRoot\$Name`" -ClientID `"xxxx`" -TenantID `"xxxx`" -ClientSecret `"xxxx`" -NewTagPath -RequiredAADGroupName `"EUD-Global-Devices`" -SkipPackageRemoval -IntuneWinPackageOnly" -ForegroundColor green
Write-Host
Write-Host "----------------------------------------------------" -ForegroundColor cyan
Write-Host
