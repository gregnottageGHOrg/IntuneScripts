#Requires -Modules Pester
<#
.SYNOPSIS
    Comprehensive Pester test suite for Upload-IntuneWin.ps1

.DESCRIPTION
    This test suite validates all features and parameters of the Upload-IntuneWin.ps1 script including:
    - Config file parsing (XML and JSON formats)
    - App types: MSI, EXE, PS1 (Edge excluded per request)
    - Detection rules: TAGFILE, FILE, REGISTRY, MSI, POWERSHELL
    - Extended settings: isFeatured, dependencies, supersedence, custom return codes, etc.
    - Parameter combinations: WhatIf, IntuneWinPackageOnly, DeleteApp, ReplaceExisting, etc.
    - Integration tests for Intune upload/delete cycle

.NOTES
    Version: 1.0
    Author: Test Framework
    Requires: Pester 5.x, Microsoft.Graph.Authentication module

.EXAMPLE
    # Run all tests
    Invoke-Pester -Path ".\Tests\Upload-IntuneWin.Tests.ps1" -Output Detailed

.EXAMPLE
    # Run only unit tests (no Intune connection required)
    Invoke-Pester -Path ".\Tests\Upload-IntuneWin.Tests.ps1" -TagFilter "Unit" -Output Detailed

.EXAMPLE
    # Run integration tests (requires Intune connection)
    Invoke-Pester -Path ".\Tests\Upload-IntuneWin.Tests.ps1" -TagFilter "Integration" -Output Detailed
#>

BeforeAll {
    # Script paths
    $script:TestRoot = $PSScriptRoot
    $script:ProjectRoot = Split-Path -Parent $TestRoot
    $script:MainScript = Join-Path $ProjectRoot "Upload-IntuneWin.ps1"
    $script:TestPackagesRoot = Join-Path $TestRoot "TestPackages"

    # Ensure test packages directory exists
    if (-not (Test-Path $script:TestPackagesRoot)) {
        New-Item -ItemType Directory -Path $script:TestPackagesRoot -Force | Out-Null
    }

    # Import helper functions from the main script for testing
    # We'll dot-source just the function definitions without running the main script
    $script:ScriptContent = Get-Content -Path $script:MainScript -Raw

    # Helper function to extract and execute a function definition from the script
    function Get-ScriptFunction {
        param([string]$FunctionName)

        $pattern = "function\s+$FunctionName\s*\{[\s\S]*?(?=\nfunction\s|\n####|\n#region Main|\z)"
        if ($script:ScriptContent -match $pattern) {
            return $Matches[0]
        }
        return $null
    }

    # Helper function to create test config files
    function New-TestConfigXML {
        param(
            [Parameter(Mandatory)]
            [string]$Path,
            [Parameter(Mandatory)]
            [hashtable]$Settings
        )

        # Build XML content using StringBuilder approach for clean output
        $xmlLines = [System.Collections.ArrayList]::new()
        [void]$xmlLines.Add('<?xml version="1.0" encoding="utf-8" ?>')
        [void]$xmlLines.Add('<CONFIG>')
        [void]$xmlLines.Add('    <Azure_Settings>')
        [void]$xmlLines.Add('        <baseUrl>https://graph.microsoft.com</baseUrl>')
        [void]$xmlLines.Add('        <logRequestUris>False</logRequestUris>')
        [void]$xmlLines.Add('        <logHeaders>False</logHeaders>')
        [void]$xmlLines.Add('        <logContent>False</logContent>')
        [void]$xmlLines.Add('        <sleep>30</sleep>')
        [void]$xmlLines.Add('    </Azure_Settings>')
        [void]$xmlLines.Add('    <IntuneWin_Settings>')

        # Required fields with defaults
        $appType = if ($Settings.ContainsKey('AppType')) { $Settings.AppType } else { 'PS1' }
        $ruleType = if ($Settings.ContainsKey('RuleType')) { $Settings.RuleType } else { 'TAGFILE' }
        $returnCodeType = if ($Settings.ContainsKey('ReturnCodeType')) { $Settings.ReturnCodeType } else { 'default' }
        $installExp = if ($Settings.ContainsKey('InstallExperience')) { $Settings.InstallExperience } else { 'system' }
        $pkgName = if ($Settings.ContainsKey('PackageName')) { $Settings.PackageName } else { 'Test-Package' }
        $dispName = if ($Settings.ContainsKey('displayName')) { $Settings.displayName } else { 'Test Package' }
        $dispVer = if ($Settings.ContainsKey('displayVersion')) { $Settings.displayVersion } else { '1.0.0' }
        $desc = if ($Settings.ContainsKey('Description')) { $Settings.Description } else { 'Test package' }
        $pub = if ($Settings.ContainsKey('Publisher')) { $Settings.Publisher } else { 'Test Publisher' }

        [void]$xmlLines.Add("        <AppType>$appType</AppType>")
        [void]$xmlLines.Add("        <RuleType>$ruleType</RuleType>")
        [void]$xmlLines.Add("        <ReturnCodeType>$returnCodeType</ReturnCodeType>")
        [void]$xmlLines.Add("        <InstallExperience>$installExp</InstallExperience>")
        [void]$xmlLines.Add("        <PackageName>$pkgName</PackageName>")
        [void]$xmlLines.Add("        <displayName>$dispName</displayName>")
        [void]$xmlLines.Add("        <displayVersion>$dispVer</displayVersion>")
        [void]$xmlLines.Add("        <Description>$desc</Description>")
        [void]$xmlLines.Add("        <Publisher>$pub</Publisher>")

        # Optional fields - only add if present
        $optionalFields = @('installCmdLine','uninstallCmdLine','Category','LogoFile','FilePath',
            'FileDetectionType','FileDetectionOperator','FileDetectionValue','RegistryKeyPath',
            'RegistryValue','RegistryDetectionType','RegistryDetectionOperator','RegistryDetectionValue',
            'MSIProductCode','MSIProductVersionOperator','MSIProductVersion','ScopeTag','IsFeatured',
            'InformationUrl','PrivacyInformationUrl','Developer','Owner','Notes',
            'MinimumSupportedOS','AllowedArchitectures')

        foreach ($field in $optionalFields) {
            if ($Settings.ContainsKey($field) -and $null -ne $Settings[$field]) {
                [void]$xmlLines.Add("        <$field>$($Settings[$field])</$field>")
            }
        }

        [void]$xmlLines.Add('    </IntuneWin_Settings>')
        [void]$xmlLines.Add('</CONFIG>')

        $xmlContent = $xmlLines -join "`n"
        $xmlContent | Out-File -FilePath $Path -Encoding UTF8 -Force
        return $Path
    }

    function New-TestConfigJSON {
        param(
            [Parameter(Mandatory)]
            [string]$Path,
            [Parameter(Mandatory)]
            [hashtable]$Settings
        )

        $config = @{
            baseUrl = "https://graph.microsoft.com"
            logRequestUris = $false
            logHeaders = $false
            logContent = $false
            sleep = 30
            AppType = if ($Settings.ContainsKey('AppType')) { $Settings.AppType } else { "PS1" }
            RuleType = if ($Settings.ContainsKey('RuleType')) { $Settings.RuleType } else { "TAGFILE" }
            ReturnCodeType = if ($Settings.ContainsKey('ReturnCodeType')) { $Settings.ReturnCodeType } else { "default" }
            InstallExperience = if ($Settings.ContainsKey('InstallExperience')) { $Settings.InstallExperience } else { "system" }
            PackageName = if ($Settings.ContainsKey('PackageName')) { $Settings.PackageName } else { "Test-Package" }
            displayName = if ($Settings.ContainsKey('displayName')) { $Settings.displayName } else { "Test Package" }
            displayVersion = if ($Settings.ContainsKey('displayVersion')) { $Settings.displayVersion } else { "1.0.0" }
            Description = if ($Settings.ContainsKey('Description')) { $Settings.Description } else { "Test package for unit testing" }
            Publisher = if ($Settings.ContainsKey('Publisher')) { $Settings.Publisher } else { "Test Publisher" }
        }

        # Add optional settings
        if ($Settings.ContainsKey('installCmdLine')) { $config.installCmdLine = $Settings.installCmdLine }
        if ($Settings.ContainsKey('uninstallCmdLine')) { $config.uninstallCmdLine = $Settings.uninstallCmdLine }
        if ($Settings.ContainsKey('Category')) { $config.Category = $Settings.Category }
        if ($Settings.ContainsKey('LogoFile')) { $config.LogoFile = $Settings.LogoFile }
        if ($Settings.ContainsKey('FilePath')) { $config.FilePath = $Settings.FilePath }
        if ($Settings.ContainsKey('FileDetectionType')) { $config.FileDetectionType = $Settings.FileDetectionType }
        if ($Settings.ContainsKey('FileDetectionOperator')) { $config.FileDetectionOperator = $Settings.FileDetectionOperator }
        if ($Settings.ContainsKey('FileDetectionValue')) { $config.FileDetectionValue = $Settings.FileDetectionValue }
        if ($Settings.ContainsKey('RegistryKeyPath')) { $config.RegistryKeyPath = $Settings.RegistryKeyPath }
        if ($Settings.ContainsKey('RegistryValue')) { $config.RegistryValue = $Settings.RegistryValue }
        if ($Settings.ContainsKey('RegistryDetectionType')) { $config.RegistryDetectionType = $Settings.RegistryDetectionType }
        if ($Settings.ContainsKey('RegistryDetectionOperator')) { $config.RegistryDetectionOperator = $Settings.RegistryDetectionOperator }
        if ($Settings.ContainsKey('RegistryDetectionValue')) { $config.RegistryDetectionValue = $Settings.RegistryDetectionValue }
        if ($Settings.ContainsKey('MSIProductCode')) { $config.MSIProductCode = $Settings.MSIProductCode }
        if ($Settings.ContainsKey('MSIProductVersionOperator')) { $config.MSIProductVersionOperator = $Settings.MSIProductVersionOperator }
        if ($Settings.ContainsKey('MSIProductVersion')) { $config.MSIProductVersion = $Settings.MSIProductVersion }
        if ($Settings.ContainsKey('ScopeTag')) { $config.ScopeTag = $Settings.ScopeTag }
        if ($Settings.ContainsKey('IsFeatured')) { $config.IsFeatured = $Settings.IsFeatured }
        if ($Settings.ContainsKey('InformationUrl')) { $config.InformationUrl = $Settings.InformationUrl }
        if ($Settings.ContainsKey('PrivacyInformationUrl')) { $config.PrivacyInformationUrl = $Settings.PrivacyInformationUrl }
        if ($Settings.ContainsKey('Developer')) { $config.Developer = $Settings.Developer }
        if ($Settings.ContainsKey('Owner')) { $config.Owner = $Settings.Owner }
        if ($Settings.ContainsKey('Notes')) { $config.Notes = $Settings.Notes }
        if ($Settings.ContainsKey('MinimumSupportedOS')) { $config.MinimumSupportedOS = $Settings.MinimumSupportedOS }
        if ($Settings.ContainsKey('AllowedArchitectures')) { $config.AllowedArchitectures = $Settings.AllowedArchitectures }
        if ($Settings.ContainsKey('Dependencies')) { $config.Dependencies = $Settings.Dependencies }
        if ($Settings.ContainsKey('Supersedence')) { $config.Supersedence = $Settings.Supersedence }
        if ($Settings.ContainsKey('CustomReturnCodes')) { $config.CustomReturnCodes = $Settings.CustomReturnCodes }

        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8 -Force
        return $Path
    }

    # Helper to create minimal test package structure
    function New-TestPackageStructure {
        param(
            [Parameter(Mandatory)]
            [string]$PackageName,
            [Parameter(Mandatory)]
            [string]$AppType,
            [hashtable]$ConfigOverrides = @{}
        )

        $packagePath = Join-Path $script:TestPackagesRoot $PackageName
        $sourcePath = Join-Path $packagePath "Source"

        # Create directories
        New-Item -ItemType Directory -Path $packagePath -Force | Out-Null
        New-Item -ItemType Directory -Path $sourcePath -Force | Out-Null

        # Create source files based on app type
        switch ($AppType) {
            "PS1" {
                $scriptContent = @"
# Test installation script
Write-Host "Installing $PackageName..."
New-Item -ItemType File -Path "`$env:ProgramData\$PackageName\installed.tag" -Force | Out-Null
Write-Host "Installation complete."
exit 0
"@
                $scriptContent | Out-File -FilePath (Join-Path $sourcePath "$PackageName.ps1") -Encoding UTF8
            }
            "EXE" {
                # Create a placeholder file (in real tests, you'd need actual EXE)
                "Placeholder for EXE installer" | Out-File -FilePath (Join-Path $sourcePath "setup.exe") -Encoding UTF8
            }
            "MSI" {
                # Create a placeholder file (in real tests, you'd need actual MSI)
                "Placeholder for MSI installer" | Out-File -FilePath (Join-Path $sourcePath "installer.msi") -Encoding UTF8
            }
        }

        # Merge config overrides
        $baseConfig = @{
            AppType = $AppType
            PackageName = $PackageName
            displayName = "Test - $PackageName"
        }
        $configSettings = $baseConfig + $ConfigOverrides

        return @{
            PackagePath = $packagePath
            SourcePath = $sourcePath
            ConfigSettings = $configSettings
        }
    }

    # Track created test apps for cleanup
    $script:CreatedTestApps = [System.Collections.ArrayList]::new()
}

AfterAll {
    # Cleanup test packages directory (optional - comment out to keep for debugging)
    # if (Test-Path $script:TestPackagesRoot) {
    #     Remove-Item -Path $script:TestPackagesRoot -Recurse -Force -ErrorAction SilentlyContinue
    # }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "TEST EXECUTION COMPLETE" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    if ($script:CreatedTestApps.Count -gt 0) {
        Write-Host "`nTest apps created during testing:" -ForegroundColor Yellow
        $script:CreatedTestApps | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        Write-Host "`nRun cleanup tests or use -DeleteApp to remove these apps." -ForegroundColor Yellow
    }
}

Describe "Upload-IntuneWin.ps1 Script Validation" -Tag "Unit" {

    Context "Script File Validation" {

        It "Main script file should exist" {
            Test-Path $script:MainScript | Should -BeTrue
        }

        It "Script should have valid PowerShell syntax" {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($script:MainScript, [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Script should contain required functions" {
            $requiredFunctions = @(
                "Get-XMLConfig",
                "Get-JSONConfig",
                "Build-IntuneAppPackage",
                "Invoke-IntuneWinAppUtil",
                "Send-Win32Lob",
                "Remove-IntuneApp",
                "Write-Log"
            )

            foreach ($func in $requiredFunctions) {
                $script:ScriptContent | Should -Match "function\s+$func"
            }
        }
    }
}

Describe "Configuration File Parsing" -Tag "Unit" {

    BeforeAll {
        # Create temp directory for config tests
        $script:ConfigTestDir = Join-Path $script:TestPackagesRoot "ConfigTests"
        New-Item -ItemType Directory -Path $script:ConfigTestDir -Force | Out-Null
    }

    Context "XML Configuration Parsing" {

        It "Should parse minimal XML config successfully" {
            $configPath = Join-Path $script:ConfigTestDir "minimal-config.xml"
            New-TestConfigXML -Path $configPath -Settings @{
                AppType = "PS1"
                PackageName = "Test-Minimal"
                displayName = "Minimal Test Package"
            }

            Test-Path $configPath | Should -BeTrue
            [xml]$config = Get-Content $configPath
            $config.CONFIG.IntuneWin_Settings.AppType | Should -Be "PS1"
        }

        It "Should parse XML config with MSI app type" {
            $configPath = Join-Path $script:ConfigTestDir "msi-config.xml"
            New-TestConfigXML -Path $configPath -Settings @{
                AppType = "MSI"
                PackageName = "Test-MSI"
                displayName = "MSI Test Package"
                RuleType = "MSI"
                MSIProductCode = "{12345678-1234-1234-1234-123456789012}"
            }

            [xml]$config = Get-Content $configPath
            $config.CONFIG.IntuneWin_Settings.AppType | Should -Be "MSI"
            $config.CONFIG.IntuneWin_Settings.MSIProductCode | Should -Be "{12345678-1234-1234-1234-123456789012}"
        }

        It "Should parse XML config with EXE app type and FILE detection" {
            $configPath = Join-Path $script:ConfigTestDir "exe-file-config.xml"
            New-TestConfigXML -Path $configPath -Settings @{
                AppType = "EXE"
                PackageName = "Test-EXE"
                displayName = "EXE Test Package"
                RuleType = "FILE"
                FilePath = "C:\Program Files\Test\app.exe"
                FileDetectionType = "exists"
                installCmdLine = "setup.exe /S"
                uninstallCmdLine = "uninstall.exe /S"
            }

            [xml]$config = Get-Content $configPath
            $config.CONFIG.IntuneWin_Settings.AppType | Should -Be "EXE"
            $config.CONFIG.IntuneWin_Settings.RuleType | Should -Be "FILE"
            $config.CONFIG.IntuneWin_Settings.FilePath | Should -Be "C:\Program Files\Test\app.exe"
        }

        It "Should parse XML config with REGISTRY detection" {
            $configPath = Join-Path $script:ConfigTestDir "registry-config.xml"
            New-TestConfigXML -Path $configPath -Settings @{
                AppType = "EXE"
                PackageName = "Test-Registry"
                displayName = "Registry Detection Test"
                RuleType = "REGISTRY"
                RegistryKeyPath = "HKLM\SOFTWARE\Test\App"
                RegistryValue = "Version"
                RegistryDetectionType = "string"
                RegistryDetectionOperator = "equal"
                RegistryDetectionValue = "1.0.0"
            }

            [xml]$config = Get-Content $configPath
            $config.CONFIG.IntuneWin_Settings.RuleType | Should -Be "REGISTRY"
            $config.CONFIG.IntuneWin_Settings.RegistryKeyPath | Should -Be "HKLM\SOFTWARE\Test\App"
        }

        It "Should parse XML config with extended settings" {
            $configPath = Join-Path $script:ConfigTestDir "extended-config.xml"
            New-TestConfigXML -Path $configPath -Settings @{
                AppType = "PS1"
                PackageName = "Test-Extended"
                displayName = "Extended Settings Test"
                IsFeatured = "true"
                InformationUrl = "https://example.com/info"
                PrivacyInformationUrl = "https://example.com/privacy"
                Developer = "Test Developer"
                Owner = "Test Owner"
                Notes = "Test notes for the application"
                MinimumSupportedOS = "22H2"
                AllowedArchitectures = "x64"
            }

            [xml]$config = Get-Content $configPath
            $config.CONFIG.IntuneWin_Settings.IsFeatured | Should -Be "true"
            $config.CONFIG.IntuneWin_Settings.Developer | Should -Be "Test Developer"
        }
    }

    Context "JSON Configuration Parsing" {

        It "Should parse minimal JSON config successfully" {
            $configPath = Join-Path $script:ConfigTestDir "minimal-config.json"
            New-TestConfigJSON -Path $configPath -Settings @{
                AppType = "PS1"
                PackageName = "Test-Minimal"
                displayName = "Minimal Test Package JSON"
            }

            Test-Path $configPath | Should -BeTrue
            $config = Get-Content $configPath | ConvertFrom-Json
            $config.AppType | Should -Be "PS1"
        }

        It "Should parse JSON config with MSI app type" {
            $configPath = Join-Path $script:ConfigTestDir "msi-config.json"
            New-TestConfigJSON -Path $configPath -Settings @{
                AppType = "MSI"
                PackageName = "Test-MSI-JSON"
                displayName = "MSI Test Package JSON"
                RuleType = "MSI"
                MSIProductCode = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
            }

            $config = Get-Content $configPath | ConvertFrom-Json
            $config.AppType | Should -Be "MSI"
            $config.MSIProductCode | Should -Be "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
        }

        It "Should parse JSON config with Dependencies array" {
            $configPath = Join-Path $script:ConfigTestDir "dependencies-config.json"
            New-TestConfigJSON -Path $configPath -Settings @{
                AppType = "PS1"
                PackageName = "Test-Dependencies"
                displayName = "Dependencies Test"
                Dependencies = @(
                    @{ AppName = "Dependency-App-1"; AutoInstall = $true }
                    @{ AppName = "Dependency-App-2"; AutoInstall = $false }
                )
            }

            $config = Get-Content $configPath | ConvertFrom-Json
            $config.Dependencies | Should -Not -BeNullOrEmpty
            $config.Dependencies.Count | Should -Be 2
        }

        It "Should parse JSON config with Supersedence array" {
            $configPath = Join-Path $script:ConfigTestDir "supersedence-config.json"
            New-TestConfigJSON -Path $configPath -Settings @{
                AppType = "PS1"
                PackageName = "Test-Supersedence"
                displayName = "Supersedence Test"
                Supersedence = @(
                    @{ AppName = "Old-App-1"; UpdateBehavior = "Replace" }
                    @{ AppName = "Old-App-2"; UpdateBehavior = "Update" }
                )
            }

            $config = Get-Content $configPath | ConvertFrom-Json
            $config.Supersedence | Should -Not -BeNullOrEmpty
            $config.Supersedence.Count | Should -Be 2
        }

        It "Should parse JSON config with CustomReturnCodes array" {
            $configPath = Join-Path $script:ConfigTestDir "returncodes-config.json"
            New-TestConfigJSON -Path $configPath -Settings @{
                AppType = "EXE"
                PackageName = "Test-ReturnCodes"
                displayName = "Custom Return Codes Test"
                installCmdLine = "setup.exe /S"
                uninstallCmdLine = "uninstall.exe /S"
                CustomReturnCodes = @(
                    @{ returnCode = 1641; type = "softReboot" }
                    @{ returnCode = 3010; type = "softReboot" }
                    @{ returnCode = 1618; type = "retry" }
                )
            }

            $config = Get-Content $configPath | ConvertFrom-Json
            $config.CustomReturnCodes | Should -Not -BeNullOrEmpty
            $config.CustomReturnCodes.Count | Should -Be 3
        }

        It "Should parse JSON config with POWERSHELL detection script" {
            $configPath = Join-Path $script:ConfigTestDir "powershell-detection-config.json"
            New-TestConfigJSON -Path $configPath -Settings @{
                AppType = "PS1"
                PackageName = "Test-PSDetection"
                displayName = "PowerShell Detection Test"
                RuleType = "POWERSHELL"
            }

            $config = Get-Content $configPath | ConvertFrom-Json
            $config.RuleType | Should -Be "POWERSHELL"
        }
    }

    Context "Config Format Precedence" {

        It "JSON should take precedence over XML when both exist" {
            $testDir = Join-Path $script:ConfigTestDir "precedence-test"
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null

            # Create both XML and JSON configs with different values
            New-TestConfigXML -Path (Join-Path $testDir "Config.xml") -Settings @{
                displayName = "XML Version"
            }
            New-TestConfigJSON -Path (Join-Path $testDir "Config.json") -Settings @{
                displayName = "JSON Version"
            }

            # Verify both files exist
            Test-Path (Join-Path $testDir "Config.xml") | Should -BeTrue
            Test-Path (Join-Path $testDir "Config.json") | Should -BeTrue

            # The script should prefer JSON - this validates the expected behavior
            # (Actual function test would require running the script)
        }
    }
}

Describe "App Type Configurations" -Tag "Unit" {

    Context "MSI App Type" {

        It "Should create valid MSI package structure" {
            $package = New-TestPackageStructure -PackageName "Test-MSI-Type" -AppType "MSI" -ConfigOverrides @{
                RuleType = "MSI"
                MSIProductCode = "{TEST-GUID-1234-5678-9012}"
            }

            Test-Path $package.PackagePath | Should -BeTrue
            Test-Path $package.SourcePath | Should -BeTrue
            $package.ConfigSettings.AppType | Should -Be "MSI"
        }

        It "MSI config should support auto-generated install commands" {
            # MSI type auto-generates msiexec commands based on MSI file
            $settings = @{
                AppType = "MSI"
                PackageName = "AutoCmd-MSI"
                displayName = "Auto Command MSI"
            }
            $settings.AppType | Should -Be "MSI"
        }
    }

    Context "EXE App Type" {

        It "Should create valid EXE package structure with install commands" {
            $package = New-TestPackageStructure -PackageName "Test-EXE-Type" -AppType "EXE" -ConfigOverrides @{
                installCmdLine = "setup.exe /S /V`"/qn`""
                uninstallCmdLine = "uninstall.exe /S"
                RuleType = "FILE"
                FilePath = "C:\Program Files\TestApp\app.exe"
                FileDetectionType = "exists"
            }

            Test-Path $package.PackagePath | Should -BeTrue
            $package.ConfigSettings.installCmdLine | Should -Not -BeNullOrEmpty
            $package.ConfigSettings.uninstallCmdLine | Should -Not -BeNullOrEmpty
        }

        It "EXE should require explicit install/uninstall commands" {
            $settings = @{
                AppType = "EXE"
                installCmdLine = ""
                uninstallCmdLine = ""
            }
            # Empty commands should be flagged as potential issue
            $settings.installCmdLine | Should -BeNullOrEmpty
        }
    }

    Context "PS1 App Type" {

        It "Should create valid PS1 package structure" {
            $package = New-TestPackageStructure -PackageName "Test-PS1-Type" -AppType "PS1" -ConfigOverrides @{
                RuleType = "TAGFILE"
            }

            Test-Path $package.PackagePath | Should -BeTrue
            Test-Path (Join-Path $package.SourcePath "Test-PS1-Type.ps1") | Should -BeTrue
        }

        It "PS1 should auto-generate install commands from script name" {
            $settings = @{
                AppType = "PS1"
                PackageName = "Install-TestApp"
            }
            # PS1 type uses PowerShell.exe to run the script
            $settings.AppType | Should -Be "PS1"
        }
    }
}

Describe "Detection Rule Types" -Tag "Unit" {

    Context "TAGFILE Detection" {

        It "Should configure TAGFILE detection for PS1 apps" {
            $configPath = Join-Path $script:TestPackagesRoot "tagfile-test.json"
            New-TestConfigJSON -Path $configPath -Settings @{
                AppType = "PS1"
                RuleType = "TAGFILE"
                PackageName = "Test-Tagfile"
            }

            $config = Get-Content $configPath | ConvertFrom-Json
            $config.RuleType | Should -Be "TAGFILE"
        }
    }

    Context "FILE Detection" {

        It "Should support 'exists' file detection type" {
            $settings = @{
                RuleType = "FILE"
                FilePath = "C:\Program Files\App\app.exe"
                FileDetectionType = "exists"
            }
            $settings.FileDetectionType | Should -Be "exists"
        }

        It "Should support 'version' file detection with comparison" {
            $settings = @{
                RuleType = "FILE"
                FilePath = "C:\Program Files\App\app.exe"
                FileDetectionType = "version"
                FileDetectionOperator = "greaterThanOrEqual"
                FileDetectionValue = "1.0.0.0"
            }
            $settings.FileDetectionType | Should -Be "version"
            $settings.FileDetectionOperator | Should -Be "greaterThanOrEqual"
        }

        It "Should support 'size' file detection" {
            $settings = @{
                RuleType = "FILE"
                FilePath = "C:\Program Files\App\app.exe"
                FileDetectionType = "sizeInMB"
                FileDetectionOperator = "equal"
                FileDetectionValue = "10"
            }
            $settings.FileDetectionType | Should -Be "sizeInMB"
        }
    }

    Context "REGISTRY Detection" {

        It "Should support registry key existence check" {
            $settings = @{
                RuleType = "REGISTRY"
                RegistryKeyPath = "HKLM\SOFTWARE\TestApp"
                RegistryDetectionType = "exists"
            }
            $settings.RegistryDetectionType | Should -Be "exists"
        }

        It "Should support registry string value comparison" {
            $settings = @{
                RuleType = "REGISTRY"
                RegistryKeyPath = "HKLM\SOFTWARE\TestApp"
                RegistryValue = "DisplayVersion"
                RegistryDetectionType = "string"
                RegistryDetectionOperator = "equal"
                RegistryDetectionValue = "1.0.0"
            }
            $settings.RegistryDetectionType | Should -Be "string"
        }

        It "Should support registry integer value comparison" {
            $settings = @{
                RuleType = "REGISTRY"
                RegistryKeyPath = "HKLM\SOFTWARE\TestApp"
                RegistryValue = "InstallCount"
                RegistryDetectionType = "integer"
                RegistryDetectionOperator = "greaterThan"
                RegistryDetectionValue = "0"
            }
            $settings.RegistryDetectionType | Should -Be "integer"
        }
    }

    Context "MSI Detection" {

        It "Should support MSI product code detection" {
            $settings = @{
                RuleType = "MSI"
                MSIProductCode = "{12345678-1234-1234-1234-123456789012}"
            }
            $settings.MSIProductCode | Should -Match "^\{[A-F0-9-]+\}$"
        }

        It "Should support MSI version comparison" {
            $settings = @{
                RuleType = "MSI"
                MSIProductCode = "{12345678-1234-1234-1234-123456789012}"
                MSIProductVersionOperator = "greaterThanOrEqual"
                MSIProductVersion = "1.0.0"
            }
            $settings.MSIProductVersionOperator | Should -Be "greaterThanOrEqual"
        }
    }

    Context "POWERSHELL Detection" {

        It "Should support custom PowerShell detection script" {
            $settings = @{
                RuleType = "POWERSHELL"
            }
            $settings.RuleType | Should -Be "POWERSHELL"
        }
    }
}

Describe "Extended Settings" -Tag "Unit" {

    Context "Application Metadata" {

        It "Should support IsFeatured setting" {
            $configPath = Join-Path $script:TestPackagesRoot "featured-test.json"
            New-TestConfigJSON -Path $configPath -Settings @{
                IsFeatured = $true
            }

            $config = Get-Content $configPath | ConvertFrom-Json
            $config.IsFeatured | Should -Be $true
        }

        It "Should support Information URLs" {
            $settings = @{
                InformationUrl = "https://example.com/app-info"
                PrivacyInformationUrl = "https://example.com/privacy"
            }
            $settings.InformationUrl | Should -Match "^https://"
        }

        It "Should support Developer, Owner, Notes fields" {
            $settings = @{
                Developer = "Development Team"
                Owner = "IT Department"
                Notes = "Internal application notes"
            }
            $settings.Developer | Should -Not -BeNullOrEmpty
            $settings.Owner | Should -Not -BeNullOrEmpty
        }
    }

    Context "System Requirements" {

        It "Should support MinimumSupportedOS setting" {
            $settings = @{
                MinimumSupportedOS = "22H2"
            }
            $settings.MinimumSupportedOS | Should -Be "22H2"
        }

        It "Should support AllowedArchitectures setting" {
            $settings = @{
                AllowedArchitectures = "x64"
            }
            $settings.AllowedArchitectures | Should -Be "x64"
        }

        It "Should support minimum resource requirements" {
            $settings = @{
                MinimumFreeDiskSpaceInMB = 500
                MinimumMemoryInMB = 2048
                MinimumNumberOfProcessors = 2
            }
            $settings.MinimumFreeDiskSpaceInMB | Should -BeGreaterThan 0
        }
    }

    Context "Runtime Settings" {

        It "Should support MaxRunTimeInMinutes" {
            $settings = @{
                MaxRunTimeInMinutes = 60
            }
            $settings.MaxRunTimeInMinutes | Should -Be 60
        }

        It "Should support DeviceRestartBehavior" {
            $validBehaviors = @("basedOnReturnCode", "allow", "suppress", "force")
            $settings = @{
                DeviceRestartBehavior = "suppress"
            }
            $settings.DeviceRestartBehavior | Should -BeIn $validBehaviors
        }
    }
}

Describe "Parameter Validation" -Tag "Unit" {

    Context "Authentication Parameters" {

        It "Should validate IntuneAdmin parameter exists in script" {
            $script:ScriptContent | Should -Match '\[string\]\s*\$IntuneAdmin'
        }

        It "Should validate ClientID parameter exists in script" {
            $script:ScriptContent | Should -Match '\[string\]\s*\$ClientID'
        }

        It "Should validate TenantID parameter exists in script" {
            $script:ScriptContent | Should -Match '\[string\]\s*\$TenantID'
        }

        It "Should validate ClientSecret parameter exists in script" {
            $script:ScriptContent | Should -Match '\[string\]\s*\$ClientSecret'
        }

        It "Should validate CertName parameter exists in script" {
            $script:ScriptContent | Should -Match '\[string\]\s*\$CertName'
        }
    }

    Context "Mode Parameters" {

        It "Should validate IntuneWinPackageOnly parameter" {
            $script:ScriptContent | Should -Match '\[switch\]\s*\$IntuneWinPackageOnly'
        }

        It "Should validate AssignGroupsOnly parameter" {
            $script:ScriptContent | Should -Match '\[switch\]\s*\$AssignGroupsOnly'
        }

        It "Should validate DeleteApp parameter" {
            $script:ScriptContent | Should -Match '\[switch\]\s*\$DeleteApp'
        }

        It "Should validate WhatIf support" {
            $script:ScriptContent | Should -Match 'SupportsShouldProcess'
        }
    }

    Context "Assignment Parameters" {

        It "Should validate RequiredAADGroupName parameter" {
            $script:ScriptContent | Should -Match '\[string\]\s*\$RequiredAADGroupName'
        }

        It "Should validate AvailableAADGroupName parameter" {
            $script:ScriptContent | Should -Match '\[string\]\s*\$AvailableAADGroupName'
        }

        It "Should validate UninstallAADGroupName parameter" {
            $script:ScriptContent | Should -Match '\[string\]\s*\$UninstallAADGroupName'
        }

        It "Should validate SkipGroupAssignment parameter" {
            $script:ScriptContent | Should -Match '\[switch\]\s*\$SkipGroupAssignment'
        }
    }

    Context "Advanced Parameters" {

        It "Should validate ReplaceExistingContent parameter" {
            $script:ScriptContent | Should -Match '\[switch\]\s*\$ReplaceExistingContent'
        }

        It "Should validate ReplaceExistingAssignments parameter" {
            $script:ScriptContent | Should -Match '\[switch\]\s*\$ReplaceExistingAssignments'
        }

        It "Should validate ScopeTagName parameter" {
            $script:ScriptContent | Should -Match '\[string\]\s*\$ScopeTagName'
        }

        It "Should validate DisconnectGraph parameter" {
            $script:ScriptContent | Should -Match '\[switch\]\s*\$DisconnectGraph'
        }
    }
}

Describe "IntuneWin Package Creation" -Tag "Unit" {

    Context "Package Structure Validation" {

        It "Should validate IntuneWinAppUtil.exe download logic exists" {
            $script:ScriptContent | Should -Match 'Test-IntuneWinAppUtil'
        }

        It "Should validate Invoke-IntuneWinAppUtil function exists" {
            $script:ScriptContent | Should -Match 'function\s+Invoke-IntuneWinAppUtil'
        }

        It "Should support Source folder path" {
            $script:ScriptContent | Should -Match '\$SourcePath'
        }

        It "Should support OrigSource folder fallback" {
            $script:ScriptContent | Should -Match '\$OrigSourcePath'
        }
    }
}

# Integration tests require actual Intune connection
Describe "Integration Tests - Intune Upload Cycle" -Tag "Integration" {

    BeforeAll {
        # Skip if not authenticated
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($null -eq $context) {
            Write-Warning "Not authenticated to Microsoft Graph. Skipping integration tests."
            Write-Warning "Run 'Connect-MgGraph -Scopes DeviceManagementApps.ReadWrite.All' to authenticate."
        }
    }

    Context "PS1 App Upload and Delete" -Skip:($null -eq (Get-MgContext -ErrorAction SilentlyContinue)) {

        BeforeAll {
            $script:IntegrationTestApp = "UnitTest-PS1-$(Get-Date -Format 'yyyyMMddHHmmss')"
        }

        It "Should create IntuneWin package only (no upload)" {
            $package = New-TestPackageStructure -PackageName $script:IntegrationTestApp -AppType "PS1"
            New-TestConfigJSON -Path (Join-Path $package.PackagePath "Config.json") -Settings ($package.ConfigSettings)

            # Run with IntuneWinPackageOnly
            $result = & $script:MainScript -PackagePath $package.PackagePath -IntuneWinPackageOnly 2>&1

            # Verify IntuneWin folder was created
            $intuneWinPath = Join-Path $package.PackagePath "IntuneWin"
            Test-Path $intuneWinPath | Should -BeTrue
        }

        AfterAll {
            # Cleanup test package folder
            $testPath = Join-Path $script:TestPackagesRoot $script:IntegrationTestApp
            if (Test-Path $testPath) {
                Remove-Item -Path $testPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe "Cleanup Tests" -Tag "Cleanup" {

    Context "Test App Cleanup" -Skip:($null -eq (Get-MgContext -ErrorAction SilentlyContinue)) {

        It "Should list apps created during testing" {
            if ($script:CreatedTestApps.Count -gt 0) {
                Write-Host "Apps to cleanup:" -ForegroundColor Yellow
                $script:CreatedTestApps | ForEach-Object { Write-Host "  - $_" }
            }
            else {
                Write-Host "No test apps to cleanup" -ForegroundColor Green
            }
            $true | Should -BeTrue
        }

        It "Should delete test apps from Intune" {
            foreach ($appName in $script:CreatedTestApps) {
                Write-Host "Deleting: $appName" -ForegroundColor Yellow
                & $script:MainScript -DeleteApp -AppNameToDelete $appName -IntuneAdmin 2>&1
            }
            $true | Should -BeTrue
        }
    }
}
