# Upload-IntuneWin.ps1

<!-- TIP: In VS Code, press Ctrl+Shift+V to open the Markdown preview and render this document properly. -->

A comprehensive PowerShell script for creating and uploading Win32 application packages (.intunewin) to Microsoft Intune.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [What the Script Does](#what-the-script-does)
- [Parameters](#parameters)
- [Authentication Methods](#authentication-methods)
- [Package Folder Structure](#package-folder-structure)
- [Config.xml Configuration](#configxml-configuration)
- [Usage Examples](#usage-examples)
- [Supported Application Types](#supported-application-types)
- [Detection Rules](#detection-rules)
- [Group Assignments](#group-assignments)
- [Scope Tags](#scope-tags)
- [Troubleshooting](#troubleshooting)

---

## Overview

`Upload-IntuneWin.ps1` automates the complete workflow of packaging and deploying Win32 applications to Microsoft Intune. It handles everything from creating `.intunewin` packages using the Microsoft Win32 Content Prep Tool to uploading them via Microsoft Graph API and configuring group assignments.

### Key Features

- ✅ Create `.intunewin` packages using IntuneWinAppUtil.exe
- ✅ Upload packages to Intune via Microsoft Graph API
- ✅ Support for MSI, EXE, PS1, and Edge application types
- ✅ Configurable detection rules (File, Registry, MSI, PowerShell script)
- ✅ Create and assign AAD groups for Required, Available, and Uninstall targeting
- ✅ Apply custom Intune scope tags for RBAC management
- ✅ Multiple authentication methods (Interactive, Certificate, Client Secret)
- ✅ Automatic return code configuration
- ✅ Detailed logging for troubleshooting

---

## Prerequisites

Before running the script, ensure you have:

1. **PowerShell 5.1 or later**
2. **Microsoft Graph PowerShell SDK module**:
   - `Microsoft.Graph.Authentication`
3. **Microsoft Win32 Content Prep Tool**:
   - `IntuneWinAppUtil.exe` (in the script directory or specified path)
4. **Required Permissions**:
   - Intune Administrator role or equivalent permissions
   - Application permissions for Microsoft Graph API
5. **Package folder** containing:
   - `Config.xml` configuration file
   - `Source` subfolder with application files

### Install Required Modules

```powershell
# Install Microsoft Graph Authentication module
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
```

### Download Win32 Content Prep Tool

Download `IntuneWinAppUtil.exe` from:
- [Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool)

---

## What the Script Does

### Complete Upload Workflow

1. **Validate Prerequisites** - Checks for IntuneWinAppUtil.exe and required modules
2. **Read Config.xml** - Parses package configuration settings
3. **Create IntuneWin Package** - Runs IntuneWinAppUtil.exe to create the encrypted package
4. **Authenticate to Graph** - Connects using specified authentication method
5. **Upload to Intune** - Creates the Win32 app and uploads the package content
6. **Configure Detection Rules** - Sets up application detection methods
7. **Apply Return Codes** - Configures installation return code handling
8. **Create AAD Groups** - Creates targeting groups if they don't exist
9. **Assign Groups** - Links groups to the application with appropriate intent
10. **Apply Scope Tags** - Assigns RBAC scope tags if specified
11. **Cleanup** - Removes temporary files (unless skipped)

---

## Parameters

### Authentication Parameters

| Parameter       | Type   | Required | Description                                        |
| --------------- | ------ | -------- | -------------------------------------------------- |
| `-IntuneAdmin`  | String | No       | Admin UPN for interactive authentication           |
| `-UserName`     | String | No       | Admin UPN for legacy AzureAD module authentication |
| `-ClientID`     | String | No       | App Registration Application (client) ID           |
| `-TenantID`     | String | No       | Azure Tenant ID                                    |
| `-ClientSecret` | String | No       | App Registration Client Secret                     |
| `-CertName`     | String | No       | Certificate name for cert-based authentication     |

### Package Parameters

| Parameter               | Type     | Required | Description                                  |
| ----------------------- | -------- | -------- | -------------------------------------------- |
| `-PackagePath`          | String[] | **Yes**  | Path to package folder containing Config.xml |
| `-IntuneWinAppUtilPath` | String   | No       | Path to IntuneWinAppUtil.exe folder          |

### Mode Switches

| Switch                  | Description                                |
| ----------------------- | ------------------------------------------ |
| `-IntuneWinPackageOnly` | Create .intunewin file only, don't upload  |
| `-AssignGroupsOnly`     | Only assign groups to existing app         |
| `-SkipGroupAssignment`  | Upload without assigning groups            |
| `-SkipPackageRemoval`   | Keep .intunewin file after upload          |
| `-NewTagPath`           | Use alternate tagfile path for diagnostics |

### Assignment Parameters

| Parameter                | Type   | Description                         |
| ------------------------ | ------ | ----------------------------------- |
| `-RequiredAADGroupName`  | String | Group name for required assignment  |
| `-AvailableAADGroupName` | String | Group name for available assignment |
| `-UninstallAADGroupName` | String | Group name for uninstall assignment |
| `-ScopeTagName`          | String | Intune scope tag to apply           |

---

## Authentication Methods

### Method 1: Interactive Authentication (Recommended for Testing)

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com"
```

### Method 2: Client Secret Authentication (For Automation)

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -ClientSecret "YourSecretValue"
```

### Method 3: Certificate Authentication (Most Secure)

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -CertName "MyCertificateName"
```

---

## Package Folder Structure

Each application package requires the following folder structure:

```text
MyApp/
├── Config.xml              # Required: Package configuration
├── Source/                 # Required: Application source files
│   ├── Setup.exe           # The installer file
│   ├── install.ps1         # Optional: Install script
│   └── [other files]       # Any additional required files
├── IntuneWin/              # Created by script: Output folder
│   └── MyApp.intunewin     # Generated package file
└── Logo.png                # Optional: Application icon
```

---

## Config.xml Configuration

The `Config.xml` file controls all aspects of the package. Here's a sample structure:

```xml
<?xml version="1.0" encoding="utf-8"?>
<IntuneWin_Settings>
    <AppType>EXE</AppType>
    <AppName>My Application</AppName>
    <AppVersion>1.0.0</AppVersion>
    <AppPublisher>Contoso</AppPublisher>
    <AppDescription>Application description here</AppDescription>
    <SetupFile>Setup.exe</SetupFile>
    <InstallCMD>Setup.exe /quiet</InstallCMD>
    <UninstallCMD>Setup.exe /uninstall /quiet</UninstallCMD>
    <InstallExperience>System</InstallExperience>
    <RuleType>FILE</RuleType>
    <FilePath>C:\Program Files\MyApp</FilePath>
    <FileName>MyApp.exe</FileName>
    <FileVersion>1.0.0</FileVersion>
    <ScopeTag>CloudPC-Apps</ScopeTag>
    <Category>Productivity</Category>
</IntuneWin_Settings>
```

### Config.xml Attributes

| Attribute           | Values                       | Description                      |
| ------------------- | ---------------------------- | -------------------------------- |
| `AppType`           | MSI, EXE, PS1, Edge          | Type of application              |
| `RuleType`          | TAGFILE, FILE, REGISTRY, MSI | Detection rule type              |
| `InstallExperience` | System, User                 | Installation context             |
| `ScopeTag`          | String                       | Intune scope tag name (optional) |

---

## Usage Examples

### Basic Package Upload

#### Upload with Interactive Authentication

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com"
```

#### Upload with Service Principal

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -ClientSecret "YourClientSecret"
```

### Package Creation Only

#### Create Package Without Uploading

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -IntuneWinPackageOnly
```

#### Create Package and Keep After Upload

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -SkipPackageRemoval
```

### Group Assignments

#### Upload with Required Group Assignment

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -RequiredAADGroupName "App-MyApp-Required"
```

#### Upload with Multiple Group Assignments

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -RequiredAADGroupName "App-MyApp-Required" `
    -AvailableAADGroupName "App-MyApp-Available" `
    -UninstallAADGroupName "App-MyApp-Uninstall"
```

#### Upload Without Group Assignments

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -SkipGroupAssignment
```

#### Update Groups Only (Existing App)

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -AssignGroupsOnly `
    -RequiredAADGroupName "App-MyApp-Required"
```

### Scope Tags

#### Upload with Scope Tag

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -ScopeTagName "CloudPC-Apps"
```

#### Upload with Scope Tag and No Groups

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -SkipGroupAssignment `
    -ScopeTagName "Production"
```

### Multiple Packages

#### Upload Multiple Packages (Pipeline)

```powershell
@("C:\Packages\App1", "C:\Packages\App2", "C:\Packages\App3") | ForEach-Object {
    .\Upload-IntuneWin.ps1 -PackagePath $_ `
        -ClientID "12345678-1234-1234-1234-123456789012" `
        -TenantID "87654321-4321-4321-4321-210987654321" `
        -ClientSecret "YourClientSecret"
}
```

### Custom IntuneWinAppUtil Path

#### Specify Custom Tool Location

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -IntuneWinAppUtilPath "C:\Tools\Win32ContentPrepTool"
```

### Diagnostics Mode

#### Use New Tag Path for Log Capture

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -NewTagPath
```

### Complete Production Example

```powershell
.\Upload-IntuneWin.ps1 `
    -PackagePath "C:\Packages\Office365" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -ClientSecret $env:INTUNE_SECRET `
    -RequiredAADGroupName "All-CloudPC-Devices" `
    -AvailableAADGroupName "Office-SelfService" `
    -ScopeTagName "EUD-CloudPC" `
    -SkipPackageRemoval
```

---

## Supported Application Types

### MSI Applications

- Automatic detection rule using MSI product code
- Install/Uninstall commands auto-generated from MSI
- Product version comparison support

### EXE Applications

- Custom install and uninstall command lines
- File, Registry, or PowerShell script detection
- Full control over detection logic

### PS1 (PowerShell Script) Applications

- PowerShell script-based installation
- Script detection support
- Runs in system or user context

### Edge Browser

- Microsoft Edge browser deployment
- Channel selection (Stable, Beta, Dev, Canary)
- Simplified deployment without .intunewin

---

## Detection Rules

### Available Detection Types

| Rule Type  | Description                                 | Use Case                  |
| ---------- | ------------------------------------------- | ------------------------- |
| `TAGFILE`  | Checks for a specific tag file              | Simple presence detection |
| `FILE`     | Checks for file existence, version, or size | Application files         |
| `REGISTRY` | Checks registry key or value                | Registry-based apps       |
| `MSI`      | Uses MSI product code                       | MSI installers            |

### Detection Rule Examples

**File Detection:**
```xml
<RuleType>FILE</RuleType>
<FilePath>C:\Program Files\MyApp</FilePath>
<FileName>MyApp.exe</FileName>
<FileVersion>1.0.0</FileVersion>
```

**Registry Detection:**
```xml
<RuleType>REGISTRY</RuleType>
<RegistryKeyPath>HKLM\SOFTWARE\MyApp</RegistryKeyPath>
<RegistryValue>Version</RegistryValue>
```

---

## Group Assignments

### Assignment Intent Types

| Intent        | Description                                         |
| ------------- | --------------------------------------------------- |
| **Required**  | App is automatically installed on assigned devices  |
| **Available** | App appears in Company Portal for user installation |
| **Uninstall** | App is automatically removed from assigned devices  |

### Group Creation

If specified groups don't exist, the script will create them automatically as security groups in Entra ID.

---

## Scope Tags

### How Scope Tags Work

- Scope tags control which administrators can see and manage the application
- The `-ScopeTagName` parameter overrides any `ScopeTag` setting in Config.xml
- If the scope tag doesn't exist, it will be created automatically
- The scope tag replaces all existing tags (including Default)

### Scope Tag Best Practices

1. Use consistent naming conventions (e.g., `CloudPC-Apps`, `Production-Apps`)
2. Align scope tags with RBAC role assignments
3. Document scope tag assignments for governance

---

## Troubleshooting

### Common Issues

#### IntuneWinAppUtil.exe Not Found

Ensure the tool is in the script directory or specify the path:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneWinAppUtilPath "C:\Tools"
```

#### Authentication Failures

Verify your credentials and permissions:

```powershell
# Test Graph connection
Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All"
Get-MgContext
```

#### Package Upload Fails

Check the log file at:
```text
%LocalAppData%\Microsoft\IntuneApps\Upload-IntuneWin\Upload-IntuneWin_[date].log
```

#### Group Assignment Errors

Ensure you have permissions to create and manage groups:
- `Group.ReadWrite.All` permission required

### Log File Location

Logs are written to:
```text
%LocalAppData%\Microsoft\IntuneApps\Upload-IntuneWin\Upload-IntuneWin_DD-MM-YYYY.log
```

### Getting Help

Display the built-in help:

```powershell
Get-Help .\Upload-IntuneWin.ps1 -Full
```

List all examples:

```powershell
Get-Help .\Upload-IntuneWin.ps1 -Examples
```

---

## Related Resources

- [Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool)
- [Win32 app management in Intune](https://learn.microsoft.com/mem/intune/apps/apps-win32-app-management)
- [Microsoft Graph API - Intune Apps](https://learn.microsoft.com/graph/api/resources/intune-apps-mobileapp)

---

**Script Version**: 1.2
**Last Updated**: December 5, 2025
**Author**: Microsoft Cloud PC Deployment Team
