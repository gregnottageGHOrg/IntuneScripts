#Make sure you've installed the PowerShell Graph SDK module from an admin PowerShell window first: Install-Module Microsoft.Graph -Scope AllUsers -Repository PSGallery -Force
#Replace the xxx values below with the correct ones for the IntuneManagement Entra App Registration in your tenant - need to create a client secret too (but be careful as those shouldn't be stored in clear-text)

Set-Location -Path "C:\CPCIntuneApps"

.\Upload-IntuneWin.ps1 -PackagePath "C:\CPCIntuneApps\CPC-Invoke-AVUpdate" -AppID "xxx" -TenantID "xxx" -Secret "xxx" -RequiredAADGroupName "EUD-CloudPC-Dynamic-Devices-UKHosted" -ScopeTagName "EUD-CloudPC" -NewTagPath -SkipPackageRemoval

.\Upload-IntuneWin.ps1 -PackagePath "C:\CPCIntuneApps\CPC-DeviceConfig" -AppID "xxx" -TenantID "xxx" -Secret "xxx" -RequiredAADGroupName "EUD-CloudPC-Dynamic-Devices-UKHosted" -ScopeTagName "EUD-CloudPC" -NewTagPath -SkipPackageRemoval

#For testing
.\Upload-IntuneWin.ps1 -PackagePath "C:\CPCIntuneApps\CPC-Invoke-CP" -AppID "xxx" -TenantID "xxx" -Secret "xxx" -AvailableAADGroupName "EUD-CloudPC-Users-AdminTesting" -ScopeTagName "EUD-CloudPC" -NewTagPath -SkipPackageRemoval