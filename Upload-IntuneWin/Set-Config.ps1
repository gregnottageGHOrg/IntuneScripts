<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
#Script helper to build out the Config.xml for the Upload-IntuneWin script
Param(
    [parameter(Mandatory = $true, HelpMessage = "Enter subfolder name of the package")]
    $Name
)

if ( $args.count -ne 0) {
    $list = $args[0]

    if (!($list -eq "--list")) {
        write-host
        Write-host "Syntax : "
        write-host
        write-host "    Set-Config.ps1"
        write-host "    Set-Config.ps1 --list       list out the file metadata."
        write-host
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

# Search for file in source folder either, exe,msi or ps1

$exename = ""
$exename = Get-ChildItem -Path $package'\Source\*' -Include "*.exe" -name
if ($exename.Length -eq 0) {
    $exename = Get-ChildItem -Path $package'\Source\*' -Include '*.msi' -Name
} 

if ($exename.Length -eq 0) {
    $exename = Get-ChildItem -Path $package'\Source\*' -Include '*.ps1' -Name
}

$logofile = (Get-ChildItem -Path $package'\' -Include '*.png' -Name)
if ( $null -eq $logofile) { $logofile = "" } else { $logofile = $logofile.ToString() }

# Confirm filename found or get new name

Write-Host ""
write-Host "Type a filename or Press ENTER to use " -ForegroundColor white -NoNewline
write-Host "[$exename]" -ForegroundColor green -NoNewline

if (($result = Read-Host -prompt " ") -ne '') { $exename = $result.tostring() }

# does source file exist
if (-not (Test-Path -Path $package'\Source\'$exename -PathType Leaf)) {
    write-host
    write-host $package'\Source\'$exename "not found, exiting." -ForegroundColor red
    write-host "" -ForegroundColor white
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
    $exefilepath = join-path $package '\Source\'


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
                write-host 
                write-host "0  : Name - '" $info_detailspace.getDetailsof($file, 0) "'"
                write-host "2  : Type - '" $info_detailspace.getDetailsof($file, 2) "'"
                write-host "9  :Perceived Type - '" $info_detailspace.getDetailsof($file, 9) "'"
                write-host "20 : Authors - '" $info_detailspace.getDetailsof($file, 20) "'"
                write-host "21 : Title - '" $info_detailspace.getDetailsof($file, 21) "'"
                write-host "22 : Subject - '" $info_detailspace.getDetailsof($file, 22) "'"
                write-host "25 : Copyright - '" $info_detailspace.getDetailsof($file, 25) "'"
                write-host "34 : File Description - '" $info_detailspace.getDetailsof($file, 34) "'"
                write-host "42 : Program Name - '" $info_detailspace.getDetailsof($file, 42) "'"
                write-host "165: Filename - '" $info_detailspace.getDetailsof($file, 165) "'"
                write-host "166: File Version - '" $info_detailspace.getDetailsof($file, 166) "'"
                write-host "201: Description - '" $info_detailspace.getDetailsof($file, 201) "'"
                write-host "217: Writers - '" $info_detailspace.getDetailsof($file, 217) "'"
                write-host "297: Product name  - '" $info_detailspace.getDetailsof($file, 297) "'"
                write-host "298: Product version - '" $info_detailspace.getDetailsof($file, 298) "'"
                write-host
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

write-host "Product execution syntax is (exe/msi/ps1), Press ENTER to use " -ForegroundColor white -NoNewline
write-host "[$apptype]" -ForegroundColor green -NoNewline
if (($result = Read-Host -prompt " ") -ne '') { $apptype = $result.tostring() }

write-host "Type a version or Press ENTER to use " -ForegroundColor white -NoNewline
write-host "[$version]" -ForegroundColor green -NoNewline
if (($result = Read-Host -prompt " ") -ne '') { $version = $result.tostring() }

write-host "Type a displayname or Press ENTER to use " -ForegroundColor white -NoNewline
write-host "[$displayname]" -ForegroundColor green -NoNewline
if (($result = Read-Host -prompt " ") -ne '') { $displayname = $result.tostring() }

write-host "Type a description or Press ENTER to use " -ForegroundColor white -NoNewline
write-host "[$description]" -ForegroundColor green -NoNewline
if (($result = Read-Host -prompt " ") -ne '') { $description = $result.tostring() }

write-host "Type publisher name or Press ENTER to use " -ForegroundColor white -NoNewline
write-host "[$publisher]" -ForegroundColor green -NoNewline
if (($result = Read-Host -prompt " ") -ne '') { $publisher = $result.tostring() }

write-host "Type a logo filename or Press ENTER to use " -ForegroundColor white -NoNewline
write-host "[$logofile]" -ForegroundColor green -NoNewline
if (($result = Read-Host -prompt " ") -ne '') { $logofile = $result.tostring() }

write-host "Type the Intune category or Press ENTER to use " -ForegroundColor white -NoNewline
write-host "[$category]" -ForegroundColor green -NoNewline
if (($result = Read-Host -prompt " ") -ne '') { $category = $result.tostring() }

# exe or msi style description info or use base package if nothing in metadata
if ($displayname -ne '') {
    $AADGroupName = "$aadGroupPrefix$displayname v$version"
}
else {
    #$AADGroupName = $aadGroupPrefix + $appname + ' v' + $version
    $AADGroupName = "$aadGroupPrefix$displayname v$version"
}

write-host "Type the AAD Group Name or Press ENTER to use " -ForegroundColor white -NoNewline
write-host "[$AADGroupName]" -ForegroundColor green -NoNewline
if (($result = Read-Host -prompt " ") -ne '') { $AADGroupName = $result.tostring() }

write-host "FILE or TAGFILE Detection Rule, Type TAGFILE or Press ENTER for " -ForegroundColor white -NoNewline
write-host "[$DetectRule]" -ForegroundColor green -NoNewline
if (($result = Read-Host -prompt " ") -ne '') { $DetectRule = $result.tostring() }

if ($DetectRule -eq "FILE") {
    write-host "Type Detection Path for FILE or Press ENTER for " -ForegroundColor white -NoNewline
    write-host "[$DetectFile]" -ForegroundColor green -NoNewline
    if (($result = Read-Host -prompt " ") -ne '') { $DetectFile = $result.tostring() }

}
else {
    $DetectFile = ""
}

if ($apptype -eq "ps1") {
    write-host "Type FULL Install command and options (e.g. -verbose)" -ForegroundColor white -NoNewline
    write-host "[]" -ForegroundColor green -NoNewline
    if (($result = Read-Host -prompt " ") -ne '') { $InstallOpts = $result.tostring() }

    write-host "Type FULL UnInstall and options (e.g. -verbose)" -ForegroundColor white -NoNewline
    write-host "[]" -ForegroundColor green -NoNewline
    if (($result = Read-Host -prompt " ") -ne '') { $UnInstallOpts = $result.tostring() }
}
else {
    write-host "Type any Install options (e.g. /quiet) or Press ENTER for " -ForegroundColor white -NoNewline
    write-host "[]" -ForegroundColor green -NoNewline
    if (($result = Read-Host -prompt " ") -ne '') { $InstallOpts = $result.tostring() }

    write-host "Type any UnInstall options (e.g. /verysilent) or Press ENTER for " -ForegroundColor white -NoNewline
    write-host "[]" -ForegroundColor green -NoNewline
    if (($result = Read-Host -prompt " ") -ne '') { $UnInstallOpts = $result.tostring() }
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
$XML.CONFIG.IntuneWin_Settings.AADGroupName = $AADGroupName
$XML.CONFIG.IntuneWin_Settings.RuleType = $DetectRule
$XML.CONFIG.IntuneWin_Settings.FilePath = $DetectFile
$XML.CONFIG.IntuneWin_Settings.installCmdLine = $InstallOpts
$XML.CONFIG.IntuneWin_Settings.uninstallCmdLine = $UnInstallOpts
$XML.Save($filename)

write-host 
write-host "----------------------------------------------------" -foregroundcolor cyan
write-host 
write-host "  Finished, Config.xml file succesfully updated" -foregroundcolor yellow
write-host "  Recommended to review the file." -foregroundcolor yellow
write-host
write-host "  To continue and upload to Intune run " -foregroundcolor yellow -nonewline
write-host "  .\Invoke-Upload.ps1 -Name $Name" -foregroundcolor green
write-host
write-host "----------------------------------------------------" -foregroundcolor cyan
write-host 
