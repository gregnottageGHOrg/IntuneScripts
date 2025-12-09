# Upload-IntuneWin.ps1 Test Suite Documentation

## Overview

This test suite provides comprehensive validation of the `Upload-IntuneWin.ps1` script across all its features and parameters. The tests are organized using **Pester 5.x**, the PowerShell testing framework.

## Test Categories

### 1. Unit Tests (`-Tag "Unit"`)
Tests that validate script structure, configuration parsing, and parameter definitions **without requiring an Intune connection**. These are safe to run at any time.

**Covered Areas:**
- Script syntax validation
- Required function existence
- XML configuration parsing (all app types, detection rules, extended settings)
- JSON configuration parsing (all app types, detection rules, extended settings)
- Config format precedence (JSON over XML)
- Parameter validation

### 2. Integration Tests (`-Tag "Integration"`)
Tests that **require an active connection to Microsoft Intune**. These tests create actual packages, upload them to Intune, and then delete them.

> ⚠️ **WARNING**: Integration tests will create and delete apps in your Intune tenant. Run only in a test/development environment.

**Covered Areas:**
- PS1 app type with TAGFILE detection
- PS1 app type with extended settings
- EXE app type with FILE detection
- EXE app type with REGISTRY detection
- XML config file format
- ReplaceExistingContent functionality
- WhatIf behavior

### 3. Cleanup Tests (`-Tag "Cleanup"`)
Tests specifically designed to remove any test applications that were created during testing.

## Prerequisites

### Required Modules
```powershell
# Pester 5.x or later
Install-Module Pester -Force -SkipPublisherCheck

# Microsoft.Graph.Authentication (for integration tests)
Install-Module Microsoft.Graph.Authentication -Force
```

### Required Permissions (for Integration Tests)
When running integration tests, you need to authenticate with the following Microsoft Graph permissions:
- `DeviceManagementApps.ReadWrite.All` - Create/update/delete Intune apps
- `Group.ReadWrite.All` - Create assignment groups (optional)

## Running the Tests

### Quick Start

```powershell
# Navigate to the project root
cd c:\Upload-IntuneWin

# Run unit tests only (no authentication required)
.\Tests\Run-Tests.ps1 -TestType Unit

# Run all tests with authentication
.\Tests\Run-Tests.ps1 -TestType All -AuthenticateFirst

# Run integration tests only
.\Tests\Run-Tests.ps1 -TestType Integration -AuthenticateFirst

# Run cleanup to remove test apps
.\Tests\Run-Tests.ps1 -TestType Cleanup -AuthenticateFirst
```

### Using Invoke-Pester Directly

```powershell
# Run all tests with detailed output
Invoke-Pester -Path ".\Tests\Upload-IntuneWin.Tests.ps1" -Output Detailed

# Run only unit tests
Invoke-Pester -Path ".\Tests\Upload-IntuneWin.Tests.ps1" -TagFilter "Unit" -Output Detailed

# Run only integration tests
Invoke-Pester -Path ".\Tests\Integration.Tests.ps1" -TagFilter "Integration" -Output Detailed

# Run tests for specific app type
Invoke-Pester -Path ".\Tests\Integration.Tests.ps1" -TagFilter "PS1" -Output Detailed
Invoke-Pester -Path ".\Tests\Integration.Tests.ps1" -TagFilter "EXE" -Output Detailed
```

### Generating Reports

```powershell
# Generate NUnit XML report
.\Tests\Run-Tests.ps1 -TestType All -GenerateReport

# Reports are saved to: .\Tests\Reports\
```

## Test File Structure

```
Tests/
├── Run-Tests.ps1                    # Test runner script
├── Upload-IntuneWin.Tests.ps1       # Main unit tests
├── Integration.Tests.ps1            # Integration tests
├── TestPackages/                    # Created during tests (auto-cleaned)
├── Reports/                         # Test reports (when -GenerateReport used)
└── README.md                        # This documentation
```

## Test Coverage Matrix

### App Types Tested

| App Type | Config Format | Detection Rules | Status                 |
| -------- | ------------- | --------------- | ---------------------- |
| PS1      | JSON          | TAGFILE         | ✅ Tested               |
| PS1      | XML           | TAGFILE         | ✅ Tested               |
| PS1      | JSON          | POWERSHELL      | ✅ Config Validated     |
| EXE      | JSON          | FILE            | ✅ Tested               |
| EXE      | JSON          | REGISTRY        | ✅ Tested               |
| EXE      | XML           | FILE            | ✅ Config Validated     |
| MSI      | JSON          | MSI             | ✅ Config Validated     |
| MSI      | XML           | MSI             | ✅ Config Validated     |
| Edge     | -             | -               | ❌ Excluded per request |

### Detection Rules Tested

| Rule Type  | Sub-Types                        | Status             |
| ---------- | -------------------------------- | ------------------ |
| TAGFILE    | -                                | ✅ Tested           |
| FILE       | exists, version, sizeInMB        | ✅ Tested           |
| REGISTRY   | exists, string, integer          | ✅ Tested           |
| MSI        | product code, version comparison | ✅ Config Validated |
| POWERSHELL | custom script                    | ✅ Config Validated |

### Parameters Tested

| Parameter                         | Test Type          | Status |
| --------------------------------- | ------------------ | ------ |
| -PackagePath                      | Unit + Integration | ✅      |
| -IntuneAdmin                      | Integration        | ✅      |
| -IntuneWinPackageOnly             | Integration        | ✅      |
| -SkipGroupAssignment              | Integration        | ✅      |
| -DeleteApp                        | Integration        | ✅      |
| -AppNameToDelete                  | Integration        | ✅      |
| -ReplaceExistingContent           | Integration        | ✅      |
| -WhatIf                           | Integration        | ✅      |
| -ClientID/-TenantID/-ClientSecret | Unit (validated)   | ✅      |
| -CertName                         | Unit (validated)   | ✅      |
| -RequiredAADGroupName             | Unit (validated)   | ✅      |
| -AvailableAADGroupName            | Unit (validated)   | ✅      |
| -UninstallAADGroupName            | Unit (validated)   | ✅      |
| -ScopeTagName                     | Unit (validated)   | ✅      |
| -ReplaceExistingAssignments       | Unit (validated)   | ✅      |
| -DisconnectGraph                  | Unit (validated)   | ✅      |

### Extended Settings Tested

| Setting                   | Status |
| ------------------------- | ------ |
| IsFeatured                | ✅      |
| InformationUrl            | ✅      |
| PrivacyInformationUrl     | ✅      |
| Developer                 | ✅      |
| Owner                     | ✅      |
| Notes                     | ✅      |
| MinimumSupportedOS        | ✅      |
| AllowedArchitectures      | ✅      |
| MinimumFreeDiskSpaceInMB  | ✅      |
| MinimumMemoryInMB         | ✅      |
| MinimumNumberOfProcessors | ✅      |
| MaxRunTimeInMinutes       | ✅      |
| DeviceRestartBehavior     | ✅      |
| Dependencies              | ✅      |
| Supersedence              | ✅      |
| CustomReturnCodes         | ✅      |

## Troubleshooting

### Common Issues

#### "Not authenticated to Microsoft Graph"
```powershell
# Authenticate before running integration tests
Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All","Group.ReadWrite.All"
```

#### "Pester not found or version too old"
```powershell
# Install latest Pester
Install-Module Pester -Force -SkipPublisherCheck
Import-Module Pester -MinimumVersion 5.0.0
```

#### "Tests fail with permission errors"
Ensure your account/app registration has:
- `DeviceManagementApps.ReadWrite.All` permission
- Admin consent granted

#### "Test apps not being cleaned up"
```powershell
# Run cleanup tests manually
.\Tests\Run-Tests.ps1 -TestType Cleanup -AuthenticateFirst

# Or delete apps manually
& .\Upload-IntuneWin.ps1 -DeleteApp -AppNameToDelete "IntegTest - *" -IntuneAdmin
```

### Viewing Detailed Logs
The main script creates detailed logs in `C:\Windows\Logs\Software\`. Check these logs if tests fail unexpectedly:
```powershell
Get-Content "C:\Windows\Logs\Software\Upload-IntuneWin*.log" | Select-Object -Last 100
```

## Adding New Tests

### Adding Unit Tests

Add new tests to `Upload-IntuneWin.Tests.ps1`:

```powershell
Describe "My New Feature Tests" -Tag "Unit" {

    Context "Feature Behavior" {

        It "Should do something specific" {
            # Arrange
            $expected = "expected value"

            # Act
            $actual = "expected value"

            # Assert
            $actual | Should -Be $expected
        }
    }
}
```

### Adding Integration Tests

Add new tests to `Integration.Tests.ps1`:

```powershell
Describe "My Integration Test" -Tag "Integration" -Skip:(-not $script:IsAuthenticated) {

    BeforeAll {
        $script:TestApp = "MyTest-$($script:TestTimestamp)"
        # Create test package
    }

    It "Should upload successfully" {
        $result = & $script:MainScript -PackagePath $path -IntuneAdmin -SkipGroupAssignment
        $script:CreatedApps.Add("IntegTest - $($script:TestApp)") | Out-Null
        $LASTEXITCODE | Should -Be 0
    }

    AfterAll {
        # Cleanup
    }
}
```

## Continuous Integration

For CI/CD pipelines, use the following approach:

```yaml
# Example Azure DevOps pipeline snippet
- task: PowerShell@2
  displayName: 'Run Unit Tests'
  inputs:
    targetType: 'inline'
    script: |
      Install-Module Pester -Force -SkipPublisherCheck
      cd $(Build.SourcesDirectory)
      .\Tests\Run-Tests.ps1 -TestType Unit -GenerateReport
    failOnStderr: true

- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'NUnit'
    testResultsFiles: '**/TestReport_*.xml'
    searchFolder: '$(Build.SourcesDirectory)/Tests/Reports'
```

## Version History

| Version | Date | Changes                     |
| ------- | ---- | --------------------------- |
| 1.0     | 2025 | Initial test suite creation |

## Contributing

When making changes to `Upload-IntuneWin.ps1`:
1. Run unit tests before committing: `.\Tests\Run-Tests.ps1 -TestType Unit`
2. Run integration tests for significant changes: `.\Tests\Run-Tests.ps1 -TestType Integration -AuthenticateFirst`
3. Add new tests for new features
4. Ensure all tests pass before submitting changes
