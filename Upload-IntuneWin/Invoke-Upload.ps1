<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
#Script to initiate the Upload-IntuneWin script process
Param(
    [parameter(Mandatory = $true, HelpMessage = "Enter a name for the new package")]
    $Name
)

Powershell -ExecutionPolicy Bypass -file "$PSScriptRoot\Upload-IntuneWin.ps1" -packagePath "$PSScriptRoot\$Name" -intuneWinAppUtilPath $PSScriptRoot