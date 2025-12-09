#Requires -Modules Pester
<#
.SYNOPSIS
    Integration tests for Upload-IntuneWin.ps1 that require Intune connection

.DESCRIPTION
    These tests create actual packages and upload them to Intune, then cleanup.
    Requires authentication to Microsoft Graph with DeviceManagementApps.ReadWrite.All permission.

.NOTES
    IMPORTANT: These tests will create and delete apps in your Intune tenant.
    Run only in a test/dev environment.

.EXAMPLE
    # First authenticate
    Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All","Group.ReadWrite.All"

    # Then run integration tests
    Invoke-Pester -Path ".\Tests\Integration.Tests.ps1" -Output Detailed
#>

BeforeAll {
    $script:TestRoot = $PSScriptRoot
    $script:ProjectRoot = Split-Path -Parent $TestRoot
    $script:MainScript = Join-Path $ProjectRoot "Upload-IntuneWin.ps1"
    $script:TestPackagesRoot = Join-Path $TestRoot "IntegrationTestPackages"

    # Timestamp for unique test names
    $script:TestTimestamp = Get-Date -Format "yyyyMMddHHmmss"

    # Track created apps for cleanup
    $script:CreatedApps = [System.Collections.ArrayList]::new()

    # Helper function to create PS1 test package
    function New-PS1TestPackage {
        param(
            [string]$PackageName,
            [string]$RuleType = "TAGFILE",
            [hashtable]$ExtendedSettings = @{}
        )

        $packagePath = Join-Path $script:TestPackagesRoot $PackageName
        $sourcePath = Join-Path $packagePath "Source"

        New-Item -ItemType Directory -Path $sourcePath -Force | Out-Null

        # Create installation script
        $installScript = @"
# Test installation script for $PackageName
Write-Host "Installing $PackageName..."
`$tagPath = "`$env:ProgramData\IntuneTags\$PackageName"
New-Item -ItemType Directory -Path (Split-Path `$tagPath -Parent) -Force | Out-Null
Set-Content -Path `$tagPath -Value "Installed: `$(Get-Date)" -Force
Write-Host "Installation complete."
exit 0
"@
        $installScript | Out-File -FilePath (Join-Path $sourcePath "$PackageName.ps1") -Encoding UTF8

        # Build config
        $config = @{
            baseUrl           = "https://graph.microsoft.com"
            logRequestUris    = $false
            logHeaders        = $false
            logContent        = $false
            sleep             = 30
            AppType           = "PS1"
            RuleType          = $RuleType
            ReturnCodeType    = "default"
            InstallExperience = "system"
            PackageName       = $PackageName
            displayName       = "IntegTest - $PackageName"
            displayVersion    = "1.0.0"
            Description       = "Integration test package created at $(Get-Date)"
            Publisher         = "Test Framework"
        }

        # Add extended settings
        foreach ($key in $ExtendedSettings.Keys) {
            $config[$key] = $ExtendedSettings[$key]
        }

        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $packagePath "Config.json") -Encoding UTF8

        return $packagePath
    }

    # Helper function to create EXE test package
    function New-EXETestPackage {
        param(
            [string]$PackageName,
            [string]$RuleType = "FILE",
            [hashtable]$DetectionSettings = @{},
            [hashtable]$ExtendedSettings = @{}
        )

        $packagePath = Join-Path $script:TestPackagesRoot $PackageName
        $sourcePath = Join-Path $packagePath "Source"

        New-Item -ItemType Directory -Path $sourcePath -Force | Out-Null

        # Create a batch file as a simple "installer" for testing
        $batchContent = @"
@echo off
echo Installing $PackageName...
mkdir "%ProgramData%\IntuneTags" 2>nul
echo Installed: %DATE% %TIME% > "%ProgramData%\IntuneTags\$PackageName.tag"
echo Installation complete.
exit /b 0
"@
        $batchContent | Out-File -FilePath (Join-Path $sourcePath "setup.bat") -Encoding ASCII

        # Build config
        $config = @{
            baseUrl           = "https://graph.microsoft.com"
            logRequestUris    = $false
            logHeaders        = $false
            logContent        = $false
            sleep             = 30
            AppType           = "EXE"
            RuleType          = $RuleType
            ReturnCodeType    = "default"
            InstallExperience = "system"
            PackageName       = $PackageName
            displayName       = "IntegTest - $PackageName"
            displayVersion    = "1.0.0"
            Description       = "Integration test EXE package"
            Publisher         = "Test Framework"
            installCmdLine    = "cmd.exe /c setup.bat"
            uninstallCmdLine  = "cmd.exe /c del `"%ProgramData%\IntuneTags\$PackageName.tag`""
        }

        # Add detection settings
        if ($RuleType -eq "FILE") {
            $config.FilePath = if ($DetectionSettings.FilePath) { $DetectionSettings.FilePath } else { "C:\ProgramData\IntuneTags\$PackageName.tag" }
            $config.FileDetectionType = if ($DetectionSettings.FileDetectionType) { $DetectionSettings.FileDetectionType } else { "exists" }
            if ($DetectionSettings.FileDetectionOperator) {
                $config.FileDetectionOperator = $DetectionSettings.FileDetectionOperator
            }
            if ($DetectionSettings.FileDetectionValue) {
                $config.FileDetectionValue = $DetectionSettings.FileDetectionValue
            }
        }
        elseif ($RuleType -eq "REGISTRY") {
            $config.RegistryKeyPath = if ($DetectionSettings.RegistryKeyPath) { $DetectionSettings.RegistryKeyPath } else { "HKLM\SOFTWARE\$PackageName" }
            $config.RegistryValue = if ($DetectionSettings.RegistryValue) { $DetectionSettings.RegistryValue } else { "Installed" }
            $config.RegistryDetectionType = if ($DetectionSettings.RegistryDetectionType) { $DetectionSettings.RegistryDetectionType } else { "exists" }
        }

        # Add extended settings
        foreach ($key in $ExtendedSettings.Keys) {
            $config[$key] = $ExtendedSettings[$key]
        }

        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $packagePath "Config.json") -Encoding UTF8

        return $packagePath
    }

    # Check for Graph connection
    $script:IsAuthenticated = $null -ne (Get-MgContext -ErrorAction SilentlyContinue)

    if (-not $script:IsAuthenticated) {
        Write-Warning "=========================================="
        Write-Warning "NOT AUTHENTICATED TO MICROSOFT GRAPH"
        Write-Warning "Integration tests will be skipped."
        Write-Warning ""
        Write-Warning "To run integration tests, first run:"
        Write-Warning "Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All','Group.ReadWrite.All'"
        Write-Warning "=========================================="
    }
}

AfterAll {
    # Cleanup test packages directory
    if (Test-Path $script:TestPackagesRoot) {
        Remove-Item -Path $script:TestPackagesRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "INTEGRATION TESTS COMPLETE" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    if ($script:CreatedApps.Count -gt 0) {
        Write-Host "`nApps created during testing:" -ForegroundColor Yellow
        $script:CreatedApps | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    }
}

Describe "PS1 App Type Integration Tests" -Tag "Integration", "PS1" -Skip:(-not $script:IsAuthenticated) {

    Context "Basic PS1 Package with TAGFILE Detection" {

        BeforeAll {
            $script:PS1BasicApp = "PS1-Basic-$($script:TestTimestamp)"
            $script:PS1BasicPath = New-PS1TestPackage -PackageName $script:PS1BasicApp -RuleType "TAGFILE"
        }

        It "Should create IntuneWin package without uploading" {
            $result = & $script:MainScript -PackagePath $script:PS1BasicPath -IntuneWinPackageOnly 2>&1
            $intuneWinPath = Join-Path $script:PS1BasicPath "IntuneWin"
            Test-Path $intuneWinPath | Should -BeTrue
        }

        It "Should upload app to Intune using WhatIf" {
            $result = & $script:MainScript -PackagePath $script:PS1BasicPath -IntuneAdmin -WhatIf -SkipGroupAssignment 2>&1
            # WhatIf should not create the app
            $result -join "`n" | Should -Match "WhatIf|What if"
        }

        It "Should upload app to Intune successfully" {
            $result = & $script:MainScript -PackagePath $script:PS1BasicPath -IntuneAdmin -SkipGroupAssignment 2>&1
            $script:CreatedApps.Add("IntegTest - $($script:PS1BasicApp)") | Out-Null
            $LASTEXITCODE | Should -Be 0
        }

        It "Should delete the app from Intune" {
            Start-Sleep -Seconds 5  # Allow propagation
            $result = & $script:MainScript -DeleteApp -AppNameToDelete "IntegTest - $($script:PS1BasicApp)" -IntuneAdmin 2>&1
            $result -join "`n" | Should -Match "Successfully Deleted|Deleted"
            $script:CreatedApps.Remove("IntegTest - $($script:PS1BasicApp)")
        }

        AfterAll {
            if (Test-Path $script:PS1BasicPath) {
                Remove-Item -Path $script:PS1BasicPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context "PS1 Package with Extended Settings" {

        BeforeAll {
            $script:PS1ExtendedApp = "PS1-Extended-$($script:TestTimestamp)"
            $script:PS1ExtendedPath = New-PS1TestPackage -PackageName $script:PS1ExtendedApp -RuleType "TAGFILE" -ExtendedSettings @{
                IsFeatured     = $true
                Developer      = "Integration Test Developer"
                Owner          = "Test Owner"
                Notes          = "Extended settings integration test"
                InformationUrl = "https://example.com/info"
            }
        }

        It "Should upload app with extended settings" {
            $result = & $script:MainScript -PackagePath $script:PS1ExtendedPath -IntuneAdmin -SkipGroupAssignment 2>&1
            $script:CreatedApps.Add("IntegTest - $($script:PS1ExtendedApp)") | Out-Null
            $LASTEXITCODE | Should -Be 0
        }

        It "Should cleanup extended settings app" {
            Start-Sleep -Seconds 5
            $result = & $script:MainScript -DeleteApp -AppNameToDelete "IntegTest - $($script:PS1ExtendedApp)" -IntuneAdmin 2>&1
            $script:CreatedApps.Remove("IntegTest - $($script:PS1ExtendedApp)")
        }

        AfterAll {
            if (Test-Path $script:PS1ExtendedPath) {
                Remove-Item -Path $script:PS1ExtendedPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe "EXE App Type Integration Tests" -Tag "Integration", "EXE" -Skip:(-not $script:IsAuthenticated) {

    Context "EXE Package with FILE Detection" {

        BeforeAll {
            $script:EXEFileApp = "EXE-File-$($script:TestTimestamp)"
            $script:EXEFilePath = New-EXETestPackage -PackageName $script:EXEFileApp -RuleType "FILE" -DetectionSettings @{
                FileDetectionType = "exists"
            }
        }

        It "Should create IntuneWin package for EXE" {
            $result = & $script:MainScript -PackagePath $script:EXEFilePath -IntuneWinPackageOnly 2>&1
            $intuneWinPath = Join-Path $script:EXEFilePath "IntuneWin"
            Test-Path $intuneWinPath | Should -BeTrue
        }

        It "Should upload EXE app to Intune" {
            $result = & $script:MainScript -PackagePath $script:EXEFilePath -IntuneAdmin -SkipGroupAssignment 2>&1
            $script:CreatedApps.Add("IntegTest - $($script:EXEFileApp)") | Out-Null
            $LASTEXITCODE | Should -Be 0
        }

        It "Should delete EXE app from Intune" {
            Start-Sleep -Seconds 5
            $result = & $script:MainScript -DeleteApp -AppNameToDelete "IntegTest - $($script:EXEFileApp)" -IntuneAdmin 2>&1
            $script:CreatedApps.Remove("IntegTest - $($script:EXEFileApp)")
        }

        AfterAll {
            if (Test-Path $script:EXEFilePath) {
                Remove-Item -Path $script:EXEFilePath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context "EXE Package with REGISTRY Detection" {

        BeforeAll {
            $script:EXERegApp = "EXE-Reg-$($script:TestTimestamp)"
            $script:EXERegPath = New-EXETestPackage -PackageName $script:EXERegApp -RuleType "REGISTRY" -DetectionSettings @{
                RegistryKeyPath       = "HKLM\SOFTWARE\$($script:EXERegApp)"
                RegistryDetectionType = "exists"
            }
        }

        It "Should upload EXE app with registry detection" {
            $result = & $script:MainScript -PackagePath $script:EXERegPath -IntuneAdmin -SkipGroupAssignment 2>&1
            $script:CreatedApps.Add("IntegTest - $($script:EXERegApp)") | Out-Null
            $LASTEXITCODE | Should -Be 0
        }

        It "Should delete registry detection app" {
            Start-Sleep -Seconds 5
            $result = & $script:MainScript -DeleteApp -AppNameToDelete "IntegTest - $($script:EXERegApp)" -IntuneAdmin 2>&1
            $script:CreatedApps.Remove("IntegTest - $($script:EXERegApp)")
        }

        AfterAll {
            if (Test-Path $script:EXERegPath) {
                Remove-Item -Path $script:EXERegPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe "ReplaceExistingContent Integration Tests" -Tag "Integration", "Replace" -Skip:(-not $script:IsAuthenticated) {

    Context "Update Existing App Content" {

        BeforeAll {
            $script:ReplaceApp = "Replace-Test-$($script:TestTimestamp)"
            $script:ReplacePath = New-PS1TestPackage -PackageName $script:ReplaceApp -ExtendedSettings @{
                displayVersion = "1.0.0"
            }
        }

        It "Should create initial app" {
            $result = & $script:MainScript -PackagePath $script:ReplacePath -IntuneAdmin -SkipGroupAssignment 2>&1
            $script:CreatedApps.Add("IntegTest - $($script:ReplaceApp)") | Out-Null
            $LASTEXITCODE | Should -Be 0
        }

        It "Should update app content with ReplaceExistingContent" {
            # Update version in config
            $configPath = Join-Path $script:ReplacePath "Config.json"
            $config = Get-Content $configPath | ConvertFrom-Json
            $config.displayVersion = "2.0.0"
            $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8 -Force

            Start-Sleep -Seconds 5
            $result = & $script:MainScript -PackagePath $script:ReplacePath -IntuneAdmin -ReplaceExistingContent -SkipGroupAssignment 2>&1
            $LASTEXITCODE | Should -Be 0
        }

        It "Should cleanup replace test app" {
            Start-Sleep -Seconds 5
            $result = & $script:MainScript -DeleteApp -AppNameToDelete "IntegTest - $($script:ReplaceApp)" -IntuneAdmin 2>&1
            $script:CreatedApps.Remove("IntegTest - $($script:ReplaceApp)")
        }

        AfterAll {
            if (Test-Path $script:ReplacePath) {
                Remove-Item -Path $script:ReplacePath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe "XML Config Format Integration Tests" -Tag "Integration", "XML" -Skip:(-not $script:IsAuthenticated) {

    Context "PS1 Package with XML Config" {

        BeforeAll {
            $script:XMLApp = "XML-Config-$($script:TestTimestamp)"
            $packagePath = Join-Path $script:TestPackagesRoot $script:XMLApp
            $sourcePath = Join-Path $packagePath "Source"

            New-Item -ItemType Directory -Path $sourcePath -Force | Out-Null

            # Create installation script
            $installScript = @"
Write-Host "Installing $($script:XMLApp)..."
exit 0
"@
            $installScript | Out-File -FilePath (Join-Path $sourcePath "$($script:XMLApp).ps1") -Encoding UTF8

            # Create XML config
            $xmlContent = @"
<?xml version="1.0" encoding="utf-8" ?>
<CONFIG>
    <Azure_Settings>
        <baseUrl>https://graph.microsoft.com</baseUrl>
        <logRequestUris>False</logRequestUris>
        <logHeaders>False</logHeaders>
        <logContent>False</logContent>
        <sleep>30</sleep>
    </Azure_Settings>
    <IntuneWin_Settings>
        <AppType>PS1</AppType>
        <RuleType>TAGFILE</RuleType>
        <ReturnCodeType>default</ReturnCodeType>
        <InstallExperience>system</InstallExperience>
        <PackageName>$($script:XMLApp)</PackageName>
        <displayName>IntegTest - $($script:XMLApp)</displayName>
        <displayVersion>1.0.0</displayVersion>
        <Description>XML config integration test</Description>
        <Publisher>Test Framework</Publisher>
    </IntuneWin_Settings>
</CONFIG>
"@
            $xmlContent | Out-File -FilePath (Join-Path $packagePath "Config.xml") -Encoding UTF8
            $script:XMLPath = $packagePath
        }

        It "Should upload app using XML config" {
            $result = & $script:MainScript -PackagePath $script:XMLPath -IntuneAdmin -SkipGroupAssignment 2>&1
            $script:CreatedApps.Add("IntegTest - $($script:XMLApp)") | Out-Null
            $LASTEXITCODE | Should -Be 0
        }

        It "Should cleanup XML config app" {
            Start-Sleep -Seconds 5
            $result = & $script:MainScript -DeleteApp -AppNameToDelete "IntegTest - $($script:XMLApp)" -IntuneAdmin 2>&1
            $script:CreatedApps.Remove("IntegTest - $($script:XMLApp)")
        }

        AfterAll {
            if (Test-Path $script:XMLPath) {
                Remove-Item -Path $script:XMLPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe "Bulk Cleanup" -Tag "Cleanup" -Skip:(-not $script:IsAuthenticated) {

    It "Should cleanup any remaining test apps" {
        foreach ($appName in $script:CreatedApps) {
            Write-Host "Cleaning up: $appName" -ForegroundColor Yellow
            try {
                & $script:MainScript -DeleteApp -AppNameToDelete $appName -IntuneAdmin 2>&1 | Out-Null
            }
            catch {
                Write-Warning "Failed to delete: $appName - $_"
            }
        }
        $script:CreatedApps.Clear()
        $true | Should -BeTrue
    }
}
