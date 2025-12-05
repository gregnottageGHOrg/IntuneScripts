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
- [Configuration Files](#configuration-files)
  - [Config.json Format](#configjson-format)
  - [Config.xml Format](#configxml-format)
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

- ✅ **Dual configuration format support** - Config.json (preferred) or Config.xml
- ✅ Create `.intunewin` packages using IntuneWinAppUtil.exe
- ✅ Upload packages to Intune via Microsoft Graph API
- ✅ Support for MSI, EXE, PS1, and Edge application types
- ✅ Configurable detection rules (File, Registry, MSI, PowerShell script)
- ✅ Create and assign Entra ID groups for Required, Available, and Uninstall targeting
- ✅ **"Allow available uninstall" automatically enabled** on all apps for user self-service removal
- ✅ Apply custom Intune scope tags for RBAC management
- ✅ Multiple authentication methods (Interactive, Certificate, Client Secret)
- ✅ Automatic return code configuration
- ✅ **ESP/Core app designation support** (via Config.json)
- ✅ **Automatic logo detection and addition** when updating existing apps
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
   - `Config.json` or `Config.xml` configuration file (JSON takes precedence)
   - `Source` subfolder with application files

### Install Required Modules

```powershell
# Install Microsoft Graph Authentication module
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
```

### Download Win32 Content Prep Tool

Download `IntuneWinAppUtil.exe` from the link below:

- [Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool)

---

## What the Script Does

### Complete Upload Workflow

1. **Validate Prerequisites** - Checks for IntuneWinAppUtil.exe and required modules
2. **Read Configuration** - Parses Config.json (preferred) or Config.xml settings
3. **Create IntuneWin Package** - Runs IntuneWinAppUtil.exe to create the encrypted package
4. **Authenticate to Graph** - Connects using specified authentication method
5. **Upload to Intune** - Creates the Win32 app and uploads the package content
6. **Configure Detection Rules** - Sets up application detection methods
7. **Apply Return Codes** - Configures installation return code handling
8. **Create Entra ID Groups** - Creates targeting groups if they don't exist
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

| Parameter               | Type     | Required | Description                                                 |
| ----------------------- | -------- | -------- | ----------------------------------------------------------- |
| `-PackagePath`          | String[] | **Yes**  | Path to package folder containing Config.json or Config.xml |
| `-IntuneWinAppUtilPath` | String   | No       | Path to IntuneWinAppUtil.exe folder                         |

### Mode Switches

| Switch                        | Description                                                                       |
| ----------------------------- | --------------------------------------------------------------------------------- |
| `-IntuneWinPackageOnly`       | Create .intunewin file only, don't upload                                         |
| `-AssignGroupsOnly`           | Only assign groups to existing app                                                |
| `-SkipGroupAssignment`        | Upload without assigning groups                                                   |
| `-SkipPackageRemoval`         | Keep .intunewin file after upload                                                 |
| `-NewTagPath`                 | Use alternate tagfile path for diagnostics                                        |
| `-ReplaceExistingContent`     | Replace IntuneWin content of existing app; applies assignments only if none exist |
| `-ReplaceExistingAssignments` | Clear and replace all assignments on existing app                                 |

### Assignment Parameters

| Parameter                                             | Type   | Description                                  |
| ----------------------------------------------------- | ------ | -------------------------------------------- |
| `-RequiredAADGroupName` / `-RequiredEntraGroupName`   | String | Entra ID group name for required assignment  |
| `-AvailableAADGroupName` / `-AvailableEntraGroupName` | String | Entra ID group name for available assignment |
| `-UninstallAADGroupName` / `-UninstallEntraGroupName` | String | Entra ID group name for uninstall assignment |
| `-ScopeTagName`                                       | String | Intune scope tag to apply                    |

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
├── Config.json             # Preferred: JSON configuration (takes precedence)
├── Config.xml              # Alternative: XML configuration
├── Source/                 # Required: Application source files (or OrigSource/)
│   ├── Setup.exe           # The installer file
│   ├── install.ps1         # Optional: Install script
│   └── [other files]       # Any additional required files
├── OrigSource/             # Alternative: Used if Source/ doesn't exist
│   └── [source files]      # Same structure as Source/
├── IntuneWin/              # Created by script: Output folder
│   └── MyApp.intunewin     # Generated package file
└── Logo.png                # Optional: Application icon
```

> **Note:** If both `Config.json` and `Config.xml` exist in the package folder, `Config.json` takes precedence.

> **Note:** If the `Source/` folder does not exist but `OrigSource/` exists, the script will automatically use `OrigSource/` as the source for creating the .intunewin package. This is useful when you want to preserve original source files separately.

---

## Configuration Files

The script supports two configuration file formats. **Config.json is the preferred format** and takes precedence if both files exist in the package folder.

### Config.json Format

The modern JSON format provides a cleaner syntax and supports additional properties for ESP/Core app designation.

#### Sample Config.json

```json
{
  "$schema": "./../pawintuneapp.schema.json",
  "appType": "PS1",
  "ruleType": "TAGFILE",
  "returnCodeType": "DEFAULT",
  "installExperience": "System",
  "packageName": "Install-MyApp",
  "displayVersion": "1.0.0",
  "displayName": "My Application",
  "description": "Application description here",
  "publisher": "Contoso",
  "category": "Business",
  "logoFile": "Logo.png",
  "entraGroupName": "App-MyApp-Required",
  "scopetag": "CloudPC-Apps",
  "coreApp": false,
  "espApp": true
}
```

#### Config.json Properties

| Property            | Values                               | Description                                     |
| ------------------- | ------------------------------------ | ----------------------------------------------- |
| `appType`           | `MSI`, `EXE`, `PS1`, `Edge`          | Type of application                             |
| `ruleType`          | `TAGFILE`, `FILE`, `REGISTRY`, `MSI` | Detection rule type                             |
| `returnCodeType`    | `DEFAULT`                            | Return code configuration                       |
| `installExperience` | `System`, `User`                     | Installation context                            |
| `packageName`       | String                               | Setup file name (without extension)             |
| `displayName`       | String                               | Display name shown in Intune                    |
| `displayVersion`    | String                               | Version string to display                       |
| `description`       | String                               | Application description                         |
| `publisher`         | String                               | Publisher name                                  |
| `category`          | String                               | App category (e.g., `Business`, `Productivity`) |
| `logoFile`          | String                               | Path to logo file (PNG/JPG)                     |
| `entraGroupName`    | String                               | Entra ID group name for assignments (preferred) |
| `aadGroupName`      | String                               | AAD group name (legacy, still supported)        |
| `scopetag`          | String                               | Intune scope tag name (optional)                |
| `coreApp`           | Boolean                              | Mark as core app (optional)                     |
| `espApp`            | Boolean                              | Include in ESP (optional)                       |

#### Additional Config.json Properties for Detection

For **FILE** detection:

```json
{
  "ruleType": "FILE",
  "filePath": "C:\\Program Files\\MyApp",
  "fileDetectionType": "exists",
  "fileDetectionOperator": "notConfigured",
  "fileDetectionValue": ""
}
```

For **REGISTRY** detection:

```json
{
  "ruleType": "REGISTRY",
  "registryKeyPath": "HKLM\\SOFTWARE\\MyApp",
  "registryValue": "Version",
  "registryDetectionType": "string",
  "registryDetectionOperator": "equal",
  "registryDetectionValue": "1.0.0"
}
```

For **EXE/MSI** app types with custom commands:

```json
{
  "appType": "EXE",
  "installCmdLine": "Setup.exe /quiet",
  "uninstallCmdLine": "Setup.exe /uninstall /quiet"
}
```

---

### Config.xml Format

The traditional XML format is still fully supported for backward compatibility.

#### Sample Config.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<CONFIG>
    <Azure_Settings>
        <baseUrl>https://graph.microsoft.com/beta/deviceAppManagement/</baseUrl>
        <logRequestUris>$true</logRequestUris>
        <logHeaders>$false</logHeaders>
        <logContent>$true</logContent>
        <azureStorageUploadChunkSizeInMb>6l</azureStorageUploadChunkSizeInMb>
        <sleep>5</sleep>
    </Azure_Settings>
    <IntuneWin_Settings>
        <AppType>EXE</AppType>
        <installCmdLine>Setup.exe /quiet</installCmdLine>
        <uninstallCmdLine>Setup.exe /uninstall /quiet</uninstallCmdLine>
        <RuleType>FILE</RuleType>
        <FilePath>C:\Program Files\MyApp</FilePath>
        <ReturnCodeType>DEFAULT</ReturnCodeType>
        <InstallExperience>System</InstallExperience>
        <PackageName>MyApp</PackageName>
        <displayName>My Application</displayName>
        <displayVersion>1.0.0</displayVersion>
        <Description>Application description here</Description>
        <Publisher>Contoso</Publisher>
        <Category>Productivity</Category>
        <LogoFile>Logo.png</LogoFile>
        <EntraGroupName>App-MyApp-Required</EntraGroupName>
        <ScopeTag>CloudPC-Apps</ScopeTag>
    </IntuneWin_Settings>
</CONFIG>
```

#### Config.xml Attributes

| Attribute           | Values                               | Description                                     |
| ------------------- | ------------------------------------ | ----------------------------------------------- |
| `AppType`           | `MSI`, `EXE`, `PS1`, `Edge`          | Type of application                             |
| `RuleType`          | `TAGFILE`, `FILE`, `REGISTRY`, `MSI` | Detection rule type                             |
| `InstallExperience` | `System`, `User`                     | Installation context                            |
| `ScopeTag`          | String                               | Intune scope tag name (optional)                |
| `PackageName`       | String                               | Setup file name (without extension)             |
| `displayName`       | String                               | Display name shown in Intune                    |
| `displayVersion`    | String                               | Version string to display                       |
| `Description`       | String                               | Application description                         |
| `Publisher`         | String                               | Publisher name                                  |
| `Category`          | String                               | App category                                    |
| `LogoFile`          | String                               | Path to logo file                               |
| `EntraGroupName`    | String                               | Entra ID group name for assignments (preferred) |
| `AADGroupName`      | String                               | AAD group name (legacy, still supported)        |

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

> **Note:** Both `-RequiredAADGroupName` and `-RequiredEntraGroupName` work identically. The Entra aliases are preferred for new scripts.

#### Upload with Required Group Assignment

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -RequiredEntraGroupName "App-MyApp-Required"
```

#### Upload with Multiple Group Assignments

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -RequiredEntraGroupName "App-MyApp-Required" `
    -AvailableEntraGroupName "App-MyApp-Available" `
    -UninstallEntraGroupName "App-MyApp-Uninstall"
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
    -RequiredEntraGroupName "App-MyApp-Required"
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

### Replace Existing Application Content

#### Update Package Content Only

When an application already exists in Intune and you need to update just the installer package while keeping all existing configuration (assignments, detection rules, requirements, scope tags, etc.):

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -ReplaceExistingContent
```

> **Note:** The application must already exist in Intune with a matching `displayName` from the Config.xml or Config.json. All existing configuration is preserved - only the IntuneWin package content is updated.

#### Automatic Logo Addition

When using `-ReplaceExistingContent`, the script automatically detects if:

1. The existing app in Intune has no logo configured
2. A logo file is specified in the Config.json or Config.xml (via `logoFile` or `LogoFile`)
3. The logo file exists in the package folder

If all conditions are met, the logo will be automatically added to the existing application. The script:

1. Loads the logo file from the package folder and encodes it to Base64
2. Makes a separate Graph API call to fetch the `largeIcon` property (which is not returned by default)
3. Uses a PATCH request to update the app with the logo

**Supported image formats:**

- PNG files (`.png`) - recommended
- JPEG files (`.jpg`, `.jpeg`)

The script logs detailed information about logo detection:

```text
Checking logo status...
Logo not loaded yet, checking for logo file at: C:\Packages\MyApp\Logo.png
Logo file found, loading...
Logo icon loaded successfully (Base64 length: 12345)
Fetching existing application largeIcon property...
Fetching largeIcon from: https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/{id}/?$select=largeIcon
Existing app has icon: False
Config defines icon: True
Adding logo to existing application...
Using image type: image/png
Logo PATCH URI: https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{id}
Logo added successfully
```

If the existing app already has a logo, it will be preserved:

```text
Existing app already has a logo - preserving existing logo
Existing icon type: image/png
Existing icon value length: 12345
```

#### Replace Content and Add Assignments (If None Exist)

When replacing content, if the existing application has **no assignments**, you can provide assignment groups and they will be applied:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -ClientSecret "YourClientSecret" `
    -AvailableEntraGroupName "App-MyApp-Available" `
    -ScopeTagName "Production" `
    -ReplaceExistingContent
```

> **Note:** If the existing application already has assignments, they are preserved and the provided group parameters are ignored. This ensures existing deployment configurations are not accidentally overwritten.

### Replace Existing Assignments

#### Replace Assignments Only (No Content Change)

When you need to completely replace the assignments on an existing application without changing the package content:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -ReplaceExistingAssignments `
    -AvailableEntraGroupName "App-MyApp-Available"
```

This will:

1. Clear all existing assignments from the application
2. Apply the new assignment(s) specified

#### Replace Both Content and Assignments

Combine `-ReplaceExistingContent` with `-ReplaceExistingAssignments` to update both:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -ClientSecret "YourClientSecret" `
    -ReplaceExistingContent `
    -ReplaceExistingAssignments `
    -RequiredEntraGroupName "App-MyApp-Required" `
    -AvailableEntraGroupName "App-MyApp-Available"
```

> **Note:** `-ReplaceExistingAssignments` requires at least one assignment group parameter (`-RequiredAADGroupName`, `-AvailableAADGroupName`, or `-UninstallAADGroupName`).

### Complete Production Example

```powershell
.\Upload-IntuneWin.ps1 `
    -PackagePath "C:\Packages\Office365" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -ClientSecret $env:INTUNE_SECRET `
    -RequiredEntraGroupName "All-CloudPC-Devices" `
    -AvailableEntraGroupName "Office-SelfService" `
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

#### File Detection

```xml
<RuleType>FILE</RuleType>
<FilePath>C:\Program Files\MyApp</FilePath>
<FileName>MyApp.exe</FileName>
<FileVersion>1.0.0</FileVersion>
```

#### Registry Detection

```xml
<RuleType>REGISTRY</RuleType>
<RegistryKeyPath>HKLM\SOFTWARE\MyApp</RegistryKeyPath>
<RegistryValue>Version</RegistryValue>
```

---

## Group Assignment Details

### Assignment Intent Types

| Intent        | Description                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------------ |
| **Required**  | App is automatically installed on assigned devices                                               |
| **Available** | App appears in Company Portal for user installation. Users can also uninstall the app themselves |
| **Uninstall** | App is automatically removed from assigned devices                                               |

### Available Uninstall Feature

The script automatically enables the "Allow available uninstall" option (`allowAvailableUninstall: true`) on all Win32 applications at the app level. This allows users to:

- Install the app from the Company Portal (when assigned as Available)
- Uninstall the app from the Company Portal when they no longer need it

This provides users with self-service control over optional applications without requiring administrator intervention.

> **Note:** This is a property on the Win32 app itself, not on individual assignments. The setting enables uninstall capability for any "Available" assignments the app receives.

### Group Creation

If specified groups don't exist, the script will create them automatically as security groups in Entra ID.

---

## Scope Tag Configuration

### How Scope Tags Work

- Scope tags control which administrators can see and manage the application
- The `-ScopeTagName` parameter overrides any `ScopeTag` or `scopetag` setting in config files
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

#### Logo Not Being Added When Using -ReplaceExistingContent

If the logo isn't being added when updating an existing application, check the log file for these diagnostic messages:

1. **Logo file not specified in config:**

   ```text
   No logo file specified in config
   ```

   Solution: Add `logoFile` (Config.json) or `LogoFile` (Config.xml) to your configuration.

2. **Logo file not found:**

   ```text
   Warning: Logo file specified in config but not found at: C:\Packages\MyApp\Logo.png
   ```

   Solution: Ensure the logo file exists at the specified path in your package folder.

3. **Logo file failed to encode:**

   ```text
   Warning: Logo file found but failed to encode to Base64
   ```

   Solution: Verify the logo file is a valid PNG, JPG, or JPEG image.

4. **Failed to fetch existing logo status:**

   ```text
   Error fetching largeIcon: <error message>
   ```

   Solution: This may indicate a permission or network issue. Ensure you have `DeviceManagementApps.ReadWrite.All` permissions.

5. **Logo PATCH request failed:**

   ```text
   Warning: Failed to add logo - <error message>
   ```

   Solution: Check the full error message in the log. Common causes include:
   - Invalid image format (must be PNG or JPEG)
   - Image file too large
   - Network/API timeout

6. **Existing app already has a logo:**

   ```text
   Existing app already has a logo - preserving existing logo
   Existing icon type: image/png
   Existing icon value length: 12345
   ```

   This is expected behavior - existing logos are preserved to prevent accidental overwrites.

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

**Script Version**: 1.4
**Last Updated**: December 5, 2025
**Author**: Greg Nottage
