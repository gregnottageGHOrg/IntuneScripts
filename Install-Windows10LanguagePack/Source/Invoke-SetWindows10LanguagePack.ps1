Write-Host "Invoke Set-Windows10LanguagePack Scheduled Task"
$EventLogName = "Application"
$EventLogSource = "EventSystem"
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Invoke Set-Windows10LanguagePack Scheduled Task" -Id 156 -Category 0 -EntryType Information