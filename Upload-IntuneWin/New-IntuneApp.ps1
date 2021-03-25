<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
#Script to create a new IntuneWin package
Param(
  [parameter(Mandatory = $true, HelpMessage = "Enter a name for the new package")]
  $Name
)

$NewPackageName = "$PSScriptRoot\$Name"
$sourcePath = "$PSScriptRoot\CopyMeAsStartingPointForNewPackages"

Write-Host "Cloning ..."

Try {
  Copy-Item -Path $sourcePath -Destination $NewPackageName -Recurse -Force -ErrorAction Stop
  Rename-Item -Path "$NewPackageName\Source\Install-Template - only required if AppType is PS1.ps1" -NewName "$Name.ps1"
}
Catch {
  Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
  Exit
}

write-host ''
write-host '-----------------------------------------------------------------------' -ForegroundColor cyan
write-host ' New package folder created' -ForegroundColor Yellow
write-host
write-host ' Next Steps:-'
write-host
Write-Host ' 1. Copy the package content into ' -nonewline
write-host $NewPackageName'\Source' -ForegroundColor green
Write-Host ' 2. Copy the logo png file into ' -nonewline
write-host $NewPackageName -ForegroundColor green
write-host " 3. Run .\Set-Config.ps1 -Name $Name"
write-host '-----------------------------------------------------------------------' -ForegroundColor cyan
write-host ''