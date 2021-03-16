<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
#Script to initiate the Upload-IntuneWin script process
Param(
    [Parameter(Mandatory = $true, Position = 1,
        HelpMessage = 'Please specify an Azure/Intune admin user name'
    )]
    [ValidateNotNullOrEmpty()]
    [string] $userName,
    
    [parameter(Mandatory = $true, Position = 2,
        HelpMessage = "Enter a name for the new package")]
    $Name
)

Powershell -ExecutionPolicy Bypass -file "$PSScriptRoot\Upload-IntuneWin.ps1" -userName $userName -packagePath "$PSScriptRoot\$Name" -intuneWinAppUtilPath $PSScriptRoot