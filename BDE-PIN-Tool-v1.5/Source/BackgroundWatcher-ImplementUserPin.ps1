<# Variables #>
$EventLogName = "Bitlocker Setup"
$EventLogSource = "PS-Bitlocker-BackgroundWatcher"

$ProgramFilesPathTail = "\MCS\BitlockerScripts"
$ForceScriptRootPath = "C:\Program Files"

$RegistrySavePath = "\Software\MCS\SetBitlocker"
$RegistryKeyName = "UserSecureString"
$SkipKeyName = "SkipImplement"

$RegistryFveLocation = "HKLM:\Software\Policies\Microsoft\FVE"
$RegistryConnectedStbyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"

$SchTaskNamePrompt = "BLTOOL-USRPROMPT"
#$SchTaskNameBckgW = "BLTOOL-BCKGWTCH"
$SchTaskNameBDEPINReset = "BDE-PIN_Reset"

$ScriptRemoveFiles = $false
$ForceRemove = $false
#$ForceRestart=$true
#$ForceRestart=$false


<# Create Event Log #>
Try {
	New-Eventlog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
}
Catch {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Event log already exists."  -Id 100 -Category 0 -EntryType Information
}

<# Announce Our Presence #>
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Background Watcher Process is running!"  -Id 100 -Category 0 -EntryType Information


<# Figure Out Where the Script Root Is #>
$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

# Create Source Path
If ($OSArchitecture -like '64*') { $ScriptRootLocation = "$env:ProgramFiles$ProgramFilesPathTail" } else { $ScriptRootLocation = "${env:ProgramFiles(x86)}$ProgramFilesPathTail" }
if ($ForceScriptRootPath) { $ScriptRootLocation = "$ForceScriptRootPath$ProgramFilesPathTail" }

<# Get the Key #>
try {
	$AesKey = Get-Content "$ScriptRootLocation\AES.key" # <TODO>
}
catch {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Could not find encryption key, check install directory. Exiting") -Id 100 -Category 0 -EntryType Information
	exit
}

<#
#Check if the skip flag is present
$SkipImplementKeyValue = (Get-ItemProperty -Path $RegistrySavePath -Name $SkipKeyName).SkipImplement

if ($SkipImplementKeyValue -eq "1") {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Skip flag has been set outside of script. Exiting") -Id 100 -Category 0 -EntryType Information
	exit
}
#>

<# Check present state of FVE #>
$WmiSystemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive

$BitlockerSystemDrive = (Get-BitLockerVolume -MountPoint $WmiSystemDrive)

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Detected system drive $WmiSystemDrive is protected ? " + [bool]$BitlockerSystemDrive.ProtectionStatus )  -Id 100 -Category 0 -EntryType Information

$RegistryFveUseTpmPin = [int](Get-ItemProperty -Path $RegistryFveLocation -Name "UseTPMPIN").UseTpmPin

if ( ($RegistryFveUseTpmPin -eq 1) -or ($RegistryFveUseTpmPin -eq 2) ) { $RegistryPrebootPinRequired = $true } else { $RegistryPrebootPinRequired = $false }

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Registry settings require Pin? $RegistryPrebootPinRequired"  -Id 100 -Category 0 -EntryType Information

<#
if ( ([bool]$BitlockerSystemDrive.ProtectionStatus) -and ($BitlockerSystemDrive.KeyProtector | Select-Object -ExpandProperty KeyProtectorType).Contains("TpmPin")) {
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker is enabled, and has a preboot PIN configured. Exiting"  -Id 100 -Category 0 -EntryType Information
    exit
}
#>

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker requires configuration, continuing"  -Id 100 -Category 0 -EntryType Information

<# Validate the device type and state #>
$WmiWin32ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem

if ( ($WmiWin32ComputerSystem.PCSystemType -eq 2) -and ($WmiWin32ComputerSystem.PCSystemTypeEx -eq 8) ) {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Device reports it is a Slate/Tablet (PcSystemType 2 + PcSystemTypeEx 8)"  -Id 100 -Category 0 -EntryType Information

	New-ItemProperty -Path $RegistryFveLocation -Name OSEnablePrebootInputProtectorsOnSlates -PropertyType DWORD -Value 1 -Force

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Set OSEnablePrebootInputProtectorsOnSlates to 1"  -Id 100 -Category 0 -EntryType Information
}

#$RegistryCsEnabled = [bool](Get-ItemProperty -Path $RegistryConnectedStbyLocation -Name "CsEnabled").CsEnabled

<# Figure Out Who Is Logged On #>
$WmiUsername = (Get-WmiObject -Class Win32_ComputerSystem).Username

<# If there is no logged on user, stop. Could be RDP User #>
if ($null -eq $WmiUsername) {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("No logged on user found, are you using RDP? Exiting") -Id 100 -Category 0 -EntryType Information
	exit
}

<# Resolve User SID #>
$WmiSid = (New-Object System.Security.Principal.NTAccount($WmiUsername)).Translate([System.Security.Principal.SecurityIdentifier]).Value

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Discovered logged on user:  $WmiUsername ($WmiSid)") -Id 100 -Category 0 -EntryType Information

<# Hook up to the HKEY Users Hive #>
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

<# Build key location #>
$UserKeyPath = ("HKU:\" + $WmiSid + $RegistrySavePath)
$SystemKeyPath = ("HKU:\S-1-5-18\$RegistrySavePath")


<# Check if the registry location exists #>
if (Test-Path $UserKeyPath) {

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User PIN Present in registry, processing" -Id 100 -Category 0 -EntryType Information
	<# Get the value set in registry #>
	$SecureString = (Get-ItemProperty -Path $UserKeyPath -Name $RegistryKeyName).UserSecureString | ConvertTo-SecureString -Key $AesKey

}
ElseIf (Test-Path $SystemKeyPath) {

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "System PIN present in registry, processing" -Id 100 -Category 0 -EntryType Information
	<# Get the value set in registry #>
	$SecureString = (Get-ItemProperty -Path $SystemKeyPath -Name $RegistryKeyName).UserSecureString | ConvertTo-SecureString -Key $AesKey

	#region Remove existing PIN protector and replace with TPMOnly
	Foreach ($protector in $BitlockerSystemDrive.KeyProtector) {
		If ($protector.KeyProtectorType -eq "TpmPin") {
			Write-Host "ProtectorType: $($protector.KeyProtectorType)"
			Write-Host "ID: $($protector.KeyProtectorId)"

			Remove-BitlockerKeyProtector -MountPoint $WmiSystemDrive -KeyProtectorId $protector.KeyProtectorId
			Add-BitLockerProtector -MountPoint $WmiSystemDrive -TpmProtector
		}
	}
	#endregion Remove PIN protector and replace with TPMOnly

}
ElseIf (!(Test-Path $UserKeyPath)) {

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User PIN not present in registry, exiting" -Id 100 -Category 0 -EntryType Information

	# Nothing has been set, exit
	exit

}


Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Preparing to configure BitLocker" -Id 100 -Category 0 -EntryType Information

if ( !([bool]$BitlockerSystemDrive.ProtectionStatus) ) {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker is not enabled for the target drive, enabling it with TpmAndPin" -Id 100 -Category 0 -EntryType Information

	try {
		Enable-BitLocker -MountPoint $WmiSystemDrive -EncryptionMethod XtsAes128 -UsedSpaceOnly -TpmAndPinProtector -Pin $SecureString -ErrorAction Stop -SkipHardwareTest -WarningAction SilentlyContinue
	}
	catch {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Crticial Failure Enabling BitLocker: " + $Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
		$NotComplete = $true
	}

}
else {

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Bitlocker is enabled, Adding Bitlocker Key Protector to Drive" -Id 100 -Category 0 -EntryType Information
	try {
		Add-BitLockerKeyProtector -MountPoint $WmiSystemDrive -Pin $SecureString -TpmAndPinProtector -ErrorAction Stop -WarningAction SilentlyContinue
	}
	catch {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Crticial Failure Adding Key Protector: " + $Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
		$NotComplete = $true
	}
}

<# Check for recovery keys on the drive, create if not present, and backup all found #>

$RecoveryPasswords = Get-BitLockerVolume -MountPoint $WmiSystemDrive | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'

if (!$RecoveryPasswords) {
	try {
		Add-BitLockerKeyProtector -MountPoint $WmiSystemDrive -RecoveryPasswordProtector -ErrorAction Stop -WarningAction SilentlyContinue
		$RecoveryPasswords = Get-BitLockerVolume -MountPoint C: | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'
	}
	catch {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Crticial Failure Creating RecoveryPassword: " + $Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
		$NotComplete = $true
	}
}
# In case there are multiple recovery passwords, lets copy them all just to make it sure.
foreach ($RecoveryPassword in $RecoveryPasswords) {
	try {
		BackupToAAD-BitLockerKeyProtector -MountPoint $WmiSystemDrive -KeyProtectorId $RecoveryPassword.KeyProtectorId -ErrorAction Stop -WarningAction SilentlyContinue
	}
	catch {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Critical Failure Uploading Key Protector:" + $Error[0].ToString()) -Id 100 -Category 0 -EntryType Error
		$NotComplete = $true
	}
}


$BitlockerSystemDrive = (Get-BitLockerVolume -MountPoint $WmiSystemDrive)
if ( !($BitlockerSystemDrive.KeyProtector | Select-Object -ExpandProperty KeyProtectorType).Contains("TpmPin")) {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Something went wrong enabling the PIN. Exiting"  -Id 100 -Category 0 -EntryType Information
	exit
}


########################################################################################################################################################## DO BITLOCKER TO IT

<# If not complete flag, don't let tidyup run and keep ticking background worker #>
if ($NotComplete -and !($ForceRemove)) {
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Configuration did not complete, Scheduled Tasks Disabled, Script Stopped. Artefacts have not been cleared" -Id 100 -Category 0 -EntryType Error
	exit
}

If (Get-ScheduledTask | ? { $_.TaskName -eq $SchTaskNamePrompt }) {

	<# Stop Scheduled Task #>
	#Disable-ScheduledTask -TaskName $SchTaskNameBckgW -InformationAction SilentlyContinue
	Disable-ScheduledTask -TaskName $SchTaskNamePrompt -InformationAction SilentlyContinue

	<# Remove Scheduled Task #>
	#Unregister-ScheduledTask -TaskName $SchTaskNameBckgW -Confirm:$false -InformationAction SilentlyContinue
	Unregister-ScheduledTask -TaskName $SchTaskNamePrompt -Confirm:$false -InformationAction SilentlyContinue
	$errormsgs = $error | out-string
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Errors detected: `n$errormsgs" -Id 100 -Category 0 -EntryType Information

	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Scheduled Task" -Id 100 -Category 0 -EntryType Information
}

<# Clean Up after initial run #>
if (Test-Path $UserKeyPath) {
	Remove-Item -Path $UserKeyPath -Force
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleaned Registry" -Id 100 -Category 0 -EntryType Information

	# Create BDE-Pin Reset scheduled task
	Register-ScheduledTask -Xml (get-content "$PSScriptRoot\BDEPINReset.xml" | out-string) -TaskName $SchTaskNameBDEPINReset -Force
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created $SchTaskNameBDEPINReset Scheduled Task"  -Id 100 -Category 0 -EntryType Information

	# Replace UserInteract-EnterBitlockerPin.ps1 with the one that calls the above scheduled task
	Rename-Item -Path "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1" -NewName "$ScriptRootLocation\UserInteract-EnterBitlockerPinInitial.ps1"
	Rename-Item -Path "$ScriptRootLocation\Invoke-BDEPINReset.ps1" -NewName "$ScriptRootLocation\UserInteract-EnterBitlockerPin.ps1"

	if ($ScriptRemoveFiles -or $ForceRemove) {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removing shortcut files" -Id 100 -Category 0 -EntryType Information
		<# Remove Shortcuts from User Desktop #>
		$UserDirectories = Get-ChildItem -Path "C:\Users"

		foreach ($User in $UserDirectories) {
			$shortcut = $User.FullName + "\Desktop\Set BitLocker Pin.lnk"
			Remove-Item -Path $shortcut -Force
			Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removed $shortcut" -Id 100 -Category 0 -EntryType Information
		}

		<# Remove Key #>
		Remove-Item -Path "$ScriptRootLocation\AES.key" -Force
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removed Key" -Id 100 -Category 0 -EntryType Information

		<# Clearing Folder #>
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Cleanup source folder" -Id 100 -Category 0 -EntryType Information
		If (((get-item $PSScriptRoot ).parent.EnumerateDirectories() | Measure-Object).Count -gt 1) {
			Write-Host "More folders found in parent path, do not remove parent folder."

			Remove-Item -Path $PSScriptRoot -Recurse
			Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Deleted Self Folder only" -Id 100 -Category 0 -EntryType Information
		}
		Else {
			Write-Host "Only script folder found in parent path, remove parent folder and child items"

			#$ScriptRootLocation.Substring(0, $ScriptRootLocation.LastIndexOf('\'))
			Remove-Item -Path ($ScriptRootLocation.Substring(0, $ScriptRootLocation.LastIndexOf('\'))) -Recurse
			Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Deleted Self & Root Folder" -Id 100 -Category 0 -EntryType Information
		}

	}

	#region Check for Windows Updates
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Run check for Windows Updates." -Id 100 -Category 0 -EntryType Information
	$command = 'usoclient.exe'
	$workDir = "$env:SystemRoot\system32"
	$ArgumentList = 'startinteractivescan'

	Try {
		Start-Process -FilePath $command -ArgumentList $ArgumentList -WorkingDirectory $workDir -Wait -WindowStyle Hidden -ErrorAction Stop
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Initiated check for Windows Updates." -Id 100 -Category 0 -EntryType Information
	}
	Catch {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Error running command: $($_.Exception.message)" -Id 100 -Category 0 -EntryType Information
		Write-Warning "Error: $($_.Exception.message)"
		#Exit
	}
	Finally {
		Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Finished initiating check for Windows Updates." -Id 100 -Category 0 -EntryType Information
	}
	#endregion Check for Windows Updates

	#Force Intune Device Sync
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Force Intune Device Sync" -Id 100 -Category 0 -EntryType Information
	Get-ScheduledTask | ? { $_.TaskName -eq 'PushLaunch' } | Start-ScheduledTask

	#Pause for 10 seconds
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Pause for 10 seconds" -Id 100 -Category 0 -EntryType Information
	Start-Sleep -Seconds 10

	#Cycle IME Service
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Restart Microsoft Intune Management Extension Service" -Id 100 -Category 0 -EntryType Information
	Get-Service -Name "Microsoft Intune Management Extension" | Restart-Service
}

<# Clean Up after PIN reset #>
if (Test-Path $SystemKeyPath) {
	Remove-Item -Path $SystemKeyPath -Force
}

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker Pin Process completed, recommended to reboot at next available opportunity." -Id 100 -Category 0 -EntryType Information
Start-ScheduledTask -TaskName "StatusMessage"
# not removing this now, as it will be required when a PIN reset is used
#Unregister-ScheduledTask -TaskName "StatusMessage" -Confirm:$false -InformationAction SilentlyContinue

<#
#<# Call A Restart # >
if($ForceRestart) {
    shutdown /t 90 /r /c "Your computer will restart shortly to finish configuring BitLocker. Please save your work."
}
#>