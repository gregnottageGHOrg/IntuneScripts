#Start-ScheduledTask -TaskName "BDE-PIN_Reset"
$EventLogName = "Bitlocker Setup"
$EventLogSource = "PS-Bitlocker-UserPrompt"

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Setting Registry Value & Closing Form" -Id 151 -Category 0 -EntryType Information