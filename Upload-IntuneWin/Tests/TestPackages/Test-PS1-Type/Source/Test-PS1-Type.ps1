# Test installation script
Write-Host "Installing Test-PS1-Type..."
New-Item -ItemType File -Path "$env:ProgramData\Test-PS1-Type\installed.tag" -Force | Out-Null
Write-Host "Installation complete."
exit 0
