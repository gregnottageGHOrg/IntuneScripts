<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
#Script to initiate the Upload-IntuneWin script process
Param(
    [Parameter(Position = 1,
        HelpMessage = 'Please specify an Azure/Intune admin user name'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $UserName,

    [parameter(Mandatory = $true, Position = 2,
        HelpMessage = "Enter path to the package")]
    $PackagePath
)

    ####################################################

    Function Invoke-FileDownload {
        #[CmdLetBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
                ValueFromPipeline = $True,
                HelpMessage = 'Please provide web-path for file to download'
            )]
            [ValidateNotNullOrEmpty()]
            [string] $Download,

            [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true,
                ValueFromPipeline = $True,
                HelpMessage = 'Please provide output file path'
            )]
            [ValidateNotNullOrEmpty()]
            [string] $OutFile,

            [Parameter(Mandatory = $true, Position = 3, ValueFromPipelineByPropertyName = $true,
                ValueFromPipeline = $True,
                HelpMessage = 'Please provide eTagFile output path'
            )]
            [ValidateNotNullOrEmpty()]
            [string] $ETagFile
        )

        Begin {
            Write-Host "$($MyInvocation.InvocationName) function... `n" -ForegroundColor Green
            Write-Host "Processing download: $Download" -ForegroundColor Magenta
            Write-Host "Using output file: $OutFile" -ForegroundColor Magenta
            Write-Host "Using eTag file: $ETagFile `n" -ForegroundColor Magenta
        }

        Process {
            $webContent = Invoke-WebRequest -method "Head" $Download -UseBasicParsing
            # Get the current eTag of the file on the web:
            $eTag = ($webContent | Select-Object Headers -ExpandProperty Headers)["ETag"]
            # Get the current size of the file on the web:
            $contentLength = ($webContent | Select-Object Headers -ExpandProperty Headers)["Content-Length"]

            If (-Not(Test-Path -Path $OutFile)) {
                Write-Host "Local file not found, so downloading file: $OutFile `n" -ForegroundColor Yellow
                Try {
                    Invoke-WebRequest $Download -UseBasicParsing -OutFile $OutFile -ErrorAction Stop
                }
                Catch {
                    Write-Host "Error processing download: $($Download)`n" -ForegroundColor Yellow
                    $errormsgs = $error | out-string
                    Write-Host "Errors:`n $errormsgs`n" -ForegroundColor Yellow
                    Throw "Error processing download: $($Download)"
                }

                Start-Sleep -Seconds 2
                Unblock-File -Path $OutFile
                If ($eTag) { $eTag | Out-File -FilePath $ETagFile -Force }
            }
            ElseIf ($(Get-Item -Path $OutFile).Length -ne $contentLength) {
                Write-Host "Local file size different, so downloading file: $OutFile `n" -ForegroundColor Yellow
                Try {
                    Invoke-WebRequest $Download -UseBasicParsing -OutFile $OutFile -ErrorAction Stop
                }
                Catch {
                    Write-Host "Error processing download: $($Download)`n" -ForegroundColor Yellow
                    $errormsgs = $error | out-string
                    Write-Host "Errors:`n $errormsgs`n" -ForegroundColor Yellow
                    Throw "Error processing download: $($Download)"
                }

                Start-Sleep -Seconds 2
                Unblock-File -Path $OutFile
                If ($eTag) { $eTag | Out-File -FilePath $ETagFile -Force }
            }
            ElseIf (-Not(Test-Path -Path $ETagFile)) {
                Write-Host "eTag file not found, so downloading file: $OutFile `n" -ForegroundColor Yellow
                Try {
                    Invoke-WebRequest $Download -UseBasicParsing -OutFile $OutFile -ErrorAction Stop
                }
                Catch {
                    Write-Host "Error processing download: $($Download)`n" -ForegroundColor Yellow
                    $errormsgs = $error | out-string
                    Write-Host "Errors:`n $errormsgs`n" -ForegroundColor Yellow
                    Throw "Error processing download: $($Download)"
                }

                Start-Sleep -Seconds 2
                Unblock-File -Path $OutFile

                Try {
                    $eTag = (Invoke-WebRequest -method "Head" $Download -ErrorAction Stop | Select-Object Headers -ExpandProperty Headers)["ETag"]
                }
                Catch {
                    Write-Host "Error processing eTag`n" -ForegroundColor Yellow
                    $errormsgs = $error | out-string
                    Write-Host "Errors:`n $errormsgs`n" -ForegroundColor Yellow
                    Throw "Error processing eTag"
                }

                If ($eTag) { $eTag | Out-File -FilePath $ETagFile -Force }
            }
            Else {
                Write-Host "eTag of file on the web is: $eTag `n" -ForegroundColor Magenta

                $existingETag = Get-Content -Path $ETagFile
                Write-Host "Existing eTag from local file is: $existingETag `n" -ForegroundColor Magenta

                # The If-None-Match header is what does the magic - downloads updated file if web eTag value doesn't match local eTagFile value
                Try {
                    Invoke-WebRequest -method "get" $Download -Headers @{"If-None-Match" = $existingETag } -outfile $OutFile
                }
                Catch [System.Net.WebException] {
                    Write-Host "File on web matches local file `n" -ForegroundColor Green
                }
                Catch {
                    Exit 1
                }
            }
        }
    }

    ####################################################

#Powershell -ExecutionPolicy Bypass -file "$PSScriptRoot\Upload-IntuneWin - Copy.ps1" -userName $userName -packagePath "$PSScriptRoot\$Name" -intuneWinAppUtilPath $PSScriptRoot
#& "$PSScriptRoot\Upload-IntuneWin.ps1" -AppID "9" -TenantID "" -Secret "" -PackagePath "$PSScriptRoot\$Name" -IntuneWinAppUtilPath $PSScriptRoot
#& "$PSScriptRoot\Upload-IntuneWin.ps1" -AppID "" -TenantID "" -Secret "" -PackagePath "$PackagePath" -IntuneWinAppUtilPath $PSScriptRoot
$downloadURL = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe"
$intuneWinFile = "$PSScriptRoot\IntuneWinAppUtil.exe"
If (-Not(Test-Path -Path $intuneWinFile)) {
    Write-Host "Local file not found: $($intuneWinFile), downloading... `n" -ForegroundColor Yellow
    $downloadFile = Split-Path -Path $($intuneWinFile) -Leaf
    $eTagFile = ("$PSScriptRoot\etag_$($downloadFile)").replace(".", "") + ".tag"
    Invoke-FileDownload -Download $downloadURL -OutFile $($intuneWinFile) -ETagFile $($eTagFile)
}

#& "$PSScriptRoot\Upload-IntuneWin.ps1" -AppID "xxx" -TenantID "xxx" -Secret "xxx" -PackagePath "$PSScriptRoot\$Name" -IntuneWinAppUtilPath $PSScriptRoot
& "$PSScriptRoot\Upload-IntuneWin.ps1" -userName $userName -PackagePath "$PackagePath" -IntuneWinAppUtilPath $PSScriptRoot