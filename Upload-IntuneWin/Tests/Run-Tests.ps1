<#
.SYNOPSIS
    Test runner for Upload-IntuneWin.ps1 test suite

.DESCRIPTION
    This script provides a convenient way to run the Pester test suite for Upload-IntuneWin.ps1.
    It supports running different test categories (Unit, Integration, Cleanup) and generates reports.

.PARAMETER TestType
    The type of tests to run:
    - All: Run all tests (requires Intune authentication)
    - Unit: Run only unit tests (no Intune connection required)
    - Integration: Run only integration tests (requires Intune connection)
    - Cleanup: Run cleanup tests to remove any leftover test apps

.PARAMETER OutputFormat
    The format for test output:
    - Detailed: Full output with all test details
    - Normal: Standard output
    - Minimal: Minimal output, only failures

.PARAMETER GenerateReport
    If specified, generates an HTML report of test results

.PARAMETER AuthenticateFirst
    If specified, prompts for Graph authentication before running tests

.EXAMPLE
    .\Run-Tests.ps1 -TestType Unit
    Runs only unit tests (no Intune connection required)

.EXAMPLE
    .\Run-Tests.ps1 -TestType All -AuthenticateFirst
    Authenticates to Graph and runs all tests

.EXAMPLE
    .\Run-Tests.ps1 -TestType Integration -GenerateReport
    Runs integration tests and generates HTML report

.EXAMPLE
    .\Run-Tests.ps1 -TestType Cleanup
    Runs cleanup tests to remove test apps from Intune
#>

[CmdletBinding()]
param(
    [ValidateSet("All", "Unit", "Integration", "Cleanup")]
    [string]$TestType = "Unit",

    [ValidateSet("Detailed", "Normal", "Minimal")]
    [string]$OutputFormat = "Detailed",

    [switch]$GenerateReport,

    [switch]$AuthenticateFirst
)

$ErrorActionPreference = "Stop"

# Script paths
$TestRoot = $PSScriptRoot
$ProjectRoot = Split-Path -Parent $TestRoot
$ReportsDir = Join-Path $TestRoot "Reports"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Upload-IntuneWin.ps1 Test Runner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verify Pester is installed
$pesterModule = Get-Module -ListAvailable Pester | Where-Object { $_.Version -ge [version]"5.0.0" } | Select-Object -First 1
if (-not $pesterModule) {
    Write-Host "Error: Pester 5.x or later is required but not found." -ForegroundColor Red
    Write-Host "Install with: Install-Module Pester -Force -SkipPublisherCheck" -ForegroundColor Yellow
    exit 1
}

Write-Host "Using Pester version: $($pesterModule.Version)" -ForegroundColor Green
Import-Module Pester -MinimumVersion 5.0.0 -Force

# Authenticate if requested
if ($AuthenticateFirst) {
    Write-Host ""
    Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow

    $requiredScopes = @(
        "DeviceManagementApps.ReadWrite.All",
        "Group.ReadWrite.All"
    )

    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($null -eq $context) {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
            Write-Host "Successfully authenticated to Microsoft Graph" -ForegroundColor Green
        }
        else {
            Write-Host "Already authenticated to Microsoft Graph" -ForegroundColor Green
            Write-Host "User: $($context.Account)" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "Error authenticating to Microsoft Graph: $_" -ForegroundColor Red
        if ($TestType -ne "Unit") {
            Write-Host "Cannot run $TestType tests without authentication." -ForegroundColor Red
            exit 1
        }
    }
}

# Determine which tests to run
$testFiles = @()
$tagFilter = @()

switch ($TestType) {
    "All" {
        $testFiles = @(
            (Join-Path $TestRoot "Upload-IntuneWin.Tests.ps1"),
            (Join-Path $TestRoot "Integration.Tests.ps1")
        )
    }
    "Unit" {
        $testFiles = @((Join-Path $TestRoot "Upload-IntuneWin.Tests.ps1"))
        $tagFilter = @("Unit")
    }
    "Integration" {
        $testFiles = @((Join-Path $TestRoot "Integration.Tests.ps1"))
        $tagFilter = @("Integration")
    }
    "Cleanup" {
        $testFiles = @(
            (Join-Path $TestRoot "Upload-IntuneWin.Tests.ps1"),
            (Join-Path $TestRoot "Integration.Tests.ps1")
        )
        $tagFilter = @("Cleanup")
    }
}

# Verify test files exist
foreach ($file in $testFiles) {
    if (-not (Test-Path $file)) {
        Write-Host "Error: Test file not found: $file" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Test Configuration:" -ForegroundColor Cyan
Write-Host "  Test Type: $TestType" -ForegroundColor White
Write-Host "  Output Format: $OutputFormat" -ForegroundColor White
Write-Host "  Test Files: $($testFiles.Count)" -ForegroundColor White
if ($tagFilter.Count -gt 0) {
    Write-Host "  Tag Filter: $($tagFilter -join ', ')" -ForegroundColor White
}
Write-Host ""

# Configure Pester
$pesterConfig = New-PesterConfiguration
$pesterConfig.Run.Path = $testFiles
$pesterConfig.Output.Verbosity = $OutputFormat

if ($tagFilter.Count -gt 0) {
    $pesterConfig.Filter.Tag = $tagFilter
}

# Configure report generation
if ($GenerateReport) {
    if (-not (Test-Path $ReportsDir)) {
        New-Item -ItemType Directory -Path $ReportsDir -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ReportsDir "TestReport_${TestType}_${timestamp}.xml"

    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputPath = $reportPath
    $pesterConfig.TestResult.OutputFormat = "NUnitXml"

    Write-Host "Report will be saved to: $reportPath" -ForegroundColor Yellow
    Write-Host ""
}

# Run tests
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Running Tests..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$pesterConfig.Run.PassThru = $true
$result = Invoke-Pester -Configuration $pesterConfig

# Display summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TEST SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($null -eq $result) {
    Write-Host "  Warning: Could not retrieve detailed test results" -ForegroundColor Yellow
    exit 0
}

Write-Host "  Total Tests:  $($result.TotalCount)" -ForegroundColor White
Write-Host "  Passed:       $($result.PassedCount)" -ForegroundColor Green
Write-Host "  Failed:       $($result.FailedCount)" -ForegroundColor $(if ($result.FailedCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Skipped:      $($result.SkippedCount)" -ForegroundColor Yellow
Write-Host "  Duration:     $($result.Duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor White
Write-Host ""

if ($GenerateReport -and (Test-Path $reportPath)) {
    Write-Host "Test report saved to: $reportPath" -ForegroundColor Green
}

# Return appropriate exit code
if ($result.FailedCount -gt 0) {
    Write-Host "TESTS FAILED" -ForegroundColor Red
    exit 1
}
else {
    Write-Host "ALL TESTS PASSED" -ForegroundColor Green
    exit 0
}
