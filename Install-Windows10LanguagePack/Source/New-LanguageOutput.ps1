#AngleParse
Import-Module -Name "$PSScriptRoot\Modules\AngleParse" -Force

$URL = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/available-language-packs-for-windows#language-packs"
$languagePacks = Invoke-WebRequest -Uri $URL -UseBasicParsing | Select-HtmlContent "table:first-of-type tbody tr", @{
    '00Language/region'            = "td:first-of-type"
    '01Language/region tag'        = "td:nth-of-type(2)"
    '02Language/region ID'         = "td:nth-of-type(3)"
    '03Language/region decimal ID' = "td:nth-of-type(4)"
}

#$languagePacks | Out-GridView

#Export to JSON
$outputFile = "$PSScriptRoot\LanguagePacks.JSON"
$languagePacks | ConvertTo-Json | Out-File -FilePath $outputFile -Force