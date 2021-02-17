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
}
Catch {
  Write-Warning "$($env:computername.ToUpper()) : $($_.Exception.message)"
  Exit
}

Try {
  Rename-Item -Path "$NewPackageName\Source\Install-Template - only required if AppType is PS1.ps1" -NewName "$Name.ps1" -Force -ErrorAction Stop
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