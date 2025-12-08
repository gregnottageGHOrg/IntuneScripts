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
- [Automatic Tool Download and Update (v1.7)](#automatic-tool-download-and-update-v17)
- [EXE File Validation (v1.7)](#exe-file-validation-v17)
- [Automatic Version Detection (v1.6)](#automatic-version-detection-v16)
- [Extended Settings (v1.5)](#extended-settings-v15)
- [Assignment Behavior (v1.7)](#assignment-behavior-v17)
- [Graph Connection Management (v1.7)](#graph-connection-management-v17)
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
- ✅ **Automatic version detection** for EXE and MSI installers (v1.6)
- ✅ **Auto-download and update of IntuneWinAppUtil.exe** from GitHub (v1.7)
- ✅ **EXE file validation** with fuzzy matching to detect mismatched installer filenames (v1.7)
- ✅ **Foreground delivery optimization** for faster app downloads on all assignment types (v1.7)
- ✅ **Smart notification settings** - hidden for Required/Available, shown for Uninstall (v1.7)
- ✅ **DisconnectGraph switch** for preserving Graph connections across multiple runs (v1.7)
- ✅ Detailed logging for troubleshooting

---

## Prerequisites

Before running the script, ensure you have:

1. **PowerShell 5.1 or later**
2. **Microsoft Graph PowerShell SDK module**:
   - `Microsoft.Graph.Authentication`
3. **Microsoft Win32 Content Prep Tool**:
   - `IntuneWinAppUtil.exe` (in the script directory or specified path)
   - **Note:** The script will automatically download the tool if not present, or update it if a newer version is available on GitHub
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

### Win32 Content Prep Tool (Auto-Download)

The script **automatically downloads and updates** `IntuneWinAppUtil.exe` from GitHub:

- If the tool is not present, it will be downloaded automatically
- If the tool exists, the script checks GitHub for updates and downloads a newer version if available
- No manual download is required

For manual download, visit: [Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool)

---

## What the Script Does

### Complete Upload Workflow

1. **Validate Prerequisites** - Checks for IntuneWinAppUtil.exe (auto-downloads or updates from GitHub if needed) and required modules
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

| Switch                        | Description                                                                                                        |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `-IntuneWinPackageOnly`       | Create .intunewin file only, don't upload                                                                          |
| `-AssignGroupsOnly`           | Only assign groups to existing app                                                                                 |
| `-SkipGroupAssignment`        | Upload without assigning groups                                                                                    |
| `-SkipPackageRemoval`         | Keep .intunewin file after upload                                                                                  |
| `-NewTagPath`                 | Use alternate tagfile path for diagnostics                                                                         |
| `-ReplaceExistingContent`     | Replace IntuneWin content of existing app; applies assignments only if none exist                                  |
| `-ReplaceExistingAssignments` | Clear and replace all assignments on existing app                                                                  |
| `-DisconnectGraph`            | Explicitly disconnect from Microsoft Graph after completion (connection is preserved by default with -IntuneAdmin) |

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

## Automatic Tool Download and Update (v1.7)

Version 1.7 introduces automatic download and update functionality for `IntuneWinAppUtil.exe`. The script automatically manages the Microsoft Win32 Content Prep Tool, eliminating the need for manual downloads.

### How It Works

1. **Tool Check**: When the script runs, it checks if `IntuneWinAppUtil.exe` exists at the expected location
2. **Auto-Download**: If the tool is not found, it is automatically downloaded from GitHub
3. **Version Check**: If the tool exists, the script queries the GitHub API to check for updates
4. **Auto-Update**: If a newer version is available on GitHub, it is automatically downloaded and replaces the old version
5. **User Notification**: The script provides clear feedback about the tool status:
   - Current local version
   - Whether an update is available
   - Download progress and success/failure status

### Example Output

**When tool needs to be downloaded:**

```text
Validating IntuneWinAppUtil.exe...
IntuneWinAppUtil.exe not found at: C:\Scripts\IntuneWinAppUtil.exe
Downloading from GitHub...
IntuneWinAppUtil.exe downloaded successfully!
  Version: 1.8.6.0
```

**When tool is up to date:**

```text
Validating IntuneWinAppUtil.exe...
IntuneWinAppUtil.exe found at: C:\Scripts\IntuneWinAppUtil.exe
  Local version: 1.8.6.0
  Local file date: 2024-11-15 10:30:00 UTC
Checking GitHub for updates...
  GitHub last commit date: 2024-11-15 09:00:00 UTC
Local version is up to date. No update required.
```

**When update is available:**

```text
Validating IntuneWinAppUtil.exe...
IntuneWinAppUtil.exe found at: C:\Scripts\IntuneWinAppUtil.exe
  Local version: 1.8.5.0
  Local file date: 2024-10-01 08:00:00 UTC
Checking GitHub for updates...
  GitHub last commit date: 2024-11-15 09:00:00 UTC
A newer version is available on GitHub. Downloading update...
  Downloaded version: 1.8.6.0
IntuneWinAppUtil.exe has been updated successfully!
```

> **Note:** The script uses the GitHub API to check for updates. If the API is unavailable (e.g., due to rate limiting or network issues), the script will continue with the existing local version.

---

## EXE File Validation (v1.7)

Version 1.7 introduces automatic validation of EXE installer file references. The script verifies that the EXE file specified in `installCmdLine` actually exists in the Source folder, helping catch common configuration errors before upload.

### Validation Process

1. **File Check**: Extracts the EXE filename from `installCmdLine` and checks if it exists in the Source folder
2. **Fuzzy Matching**: If not found, searches for the closest matching EXE file using Levenshtein distance algorithm
3. **User Prompt**: Offers to update the config file with the correct filename
4. **Config Update**: Automatically updates `installCmdLine` and `PackageName` if user accepts

### Example Output

**When EXE file is not found:**

```text
Validating EXE file reference...
EXE file not found: Setup-1.0.exe
Searching for similar files in Source folder...
Found potential match: Setup-2.0.exe (similarity: 85%)
Use Setup-2.0.exe instead? (Y/N) - Auto-selecting in 30 seconds...
Y
Updating config file with corrected filename...
Updated installCmdLine: Setup-2.0.exe /SILENT
Updated PackageName: Setup-2.0
```

**When EXE file exists:**

```text
Validating EXE file reference...
EXE file found: Setup.exe
```

> **Note:** EXE validation only applies to EXE package types. MSI, PS1, and Edge apps are not affected.

---

## Automatic Version Detection (v1.6)

Version 1.6 introduces automatic version detection for EXE and MSI installers. The script detects the version from the installer file and compares it to the `displayVersion` in your config file.

### How It Works

1. **EXE files**: Uses `FileVersionInfo.GetVersionInfo()` to read `FileVersion` or `ProductVersion`
2. **MSI files**: Uses Windows Installer COM object to query `ProductVersion` from the database
3. **Version comparison**: Compares detected version with `displayVersion` in Config.xml/Config.json
4. **User prompt**: If versions differ, prompts user to accept the detected version (Y/N)
5. **30-second timeout**: Auto-selects based on context:
   - If config has a version → keeps config version
   - If config version is empty → uses detected version
6. **Config update**: Automatically updates the config file when user accepts or config is empty

### Example Output

```text
Checking installer version for EXE package...
Detected version [2.1.0.456] from installer file
Config displayVersion is [2.0.0]
Versions are different. Use detected version [2.1.0.456]? (Y/N) - Auto-selecting in 30 seconds...
(25 seconds remaining) Y
User accepted detected version. Updating config file...
Successfully updated config file with version: 2.1.0.456
```

> **Note:** Version detection only applies to EXE and MSI package types. PS1 and Edge apps are not affected.

---

## Extended Settings (v1.5)

Version 1.5 introduces comprehensive extended settings that provide full control over Win32 app configuration via the Microsoft Graph API. All extended settings are **optional** - if not specified, sensible defaults are used.

### Extended Settings Overview

| Category                | Settings                                                                                                                                           |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **App Information**     | `isFeatured`, `informationUrl`, `privacyInformationUrl`, `developer`, `owner`, `notes`                                                             |
| **Install Experience**  | `maxRunTimeInMinutes`, `deviceRestartBehavior`                                                                                                     |
| **System Requirements** | `minimumFreeDiskSpaceInMB`, `minimumMemoryInMB`, `minimumNumberOfProcessors`, `minimumCpuSpeedInMHz`, `allowedArchitectures`, `minimumSupportedOS` |
| **Return Codes**        | `customReturnCodes`                                                                                                                                |
| **Dependencies**        | `dependencies`, `dependencyType`                                                                                                                   |
| **Supersedence**        | `supersedence`, `supersedenceType`                                                                                                                 |
| **Script Detection**    | `detectionScriptFile`, `detectionScriptEnforceSignatureCheck`, `detectionScriptRunAs32Bit`                                                         |

### App Information Settings

| Setting                 | Type    | Default | Description                                       |
| ----------------------- | ------- | ------- | ------------------------------------------------- |
| `isFeatured`            | Boolean | `false` | Show this app as a featured app in Company Portal |
| `informationUrl`        | String  | (empty) | URL for more information about the app            |
| `privacyInformationUrl` | String  | (empty) | URL for privacy information                       |
| `developer`             | String  | (empty) | Developer name                                    |
| `owner`                 | String  | (empty) | Owner name                                        |
| `notes`                 | String  | (empty) | Additional notes about the app                    |

### Install Experience Settings

| Setting                 | Type    | Default    | Values                                            | Description                                 |
| ----------------------- | ------- | ---------- | ------------------------------------------------- | ------------------------------------------- |
| `maxRunTimeInMinutes`   | Integer | `60`       | 1-1440                                            | Maximum time the install is allowed to run  |
| `deviceRestartBehavior` | String  | `suppress` | `basedOnReturnCode`, `allow`, `suppress`, `force` | How to handle device restarts after install |

**Restart Behavior Values:**

- `basedOnReturnCode` - Restart based on the return code from the installer
- `allow` - Allow restart if requested by the installer
- `suppress` - Suppress restart requests from the installer (default)
- `force` - Force a restart after installation

### System Requirements Settings

| Setting                     | Type    | Default          | Description                                        |
| --------------------------- | ------- | ---------------- | -------------------------------------------------- |
| `minimumFreeDiskSpaceInMB`  | Integer | 0 (not enforced) | Minimum free disk space required in MB             |
| `minimumMemoryInMB`         | Integer | 0 (not enforced) | Minimum physical memory required in MB             |
| `minimumNumberOfProcessors` | Integer | 0 (not enforced) | Minimum number of logical processors required      |
| `minimumCpuSpeedInMHz`      | Integer | 0 (not enforced) | Minimum CPU speed required in MHz                  |
| `allowedArchitectures`      | String  | (empty)          | Comma-separated list: `x64`, `x86`, `arm`, `arm64` |
| `minimumSupportedOS`        | String  | (empty)          | Minimum Windows version (see table below)          |

**Supported OS Version Values:**

| Value      | Windows Version        |
| ---------- | ---------------------- |
| `v10_1903` | Windows 10 1903 (19H1) |
| `v10_1909` | Windows 10 1909 (19H2) |
| `v10_2004` | Windows 10 2004 (20H1) |
| `v10_20H2` | Windows 10 20H2        |
| `v10_21H1` | Windows 10 21H1        |
| `v10_21H2` | Windows 10 21H2        |
| `v10_22H2` | Windows 10 22H2        |
| `v11_21H2` | Windows 11 21H2        |
| `v11_22H2` | Windows 11 22H2        |
| `v11_23H2` | Windows 11 23H2        |
| `v11_24H2` | Windows 11 24H2        |

### Custom Return Codes

Custom return codes allow you to define how specific exit codes from the installer should be handled.

**Config.xml Format:**

```xml
<!-- Comma-separated code:type pairs -->
<CustomReturnCodes>3010:softReboot,1641:hardReboot,1618:retry</CustomReturnCodes>
```

**Config.json Format:**

```json
{
  "customReturnCodes": [
    { "returnCode": 3010, "type": "softReboot" },
    { "returnCode": 1641, "type": "hardReboot" },
    { "returnCode": 1618, "type": "retry" }
  ]
}
```

**Return Code Types:**

| Type         | Description                            |
| ------------ | -------------------------------------- |
| `failed`     | Installation failed                    |
| `success`    | Installation succeeded                 |
| `softReboot` | Soft reboot required (can be deferred) |
| `hardReboot` | Hard reboot required (immediate)       |
| `retry`      | Retry the installation                 |

### Dependencies

Dependencies allow you to specify other Win32 apps that must be installed before this app.

**Config.xml Format:**

```xml
<!-- Comma-separated list of app display names -->
<Dependencies>Microsoft Visual C++ Redistributable,Microsoft .NET Runtime 8.0</Dependencies>
<DependencyType>autoInstall</DependencyType>
```

**Config.json Format:**

```json
{
  "dependencies": [
    "Microsoft Visual C++ Redistributable",
    "Microsoft .NET Runtime 8.0"
  ],
  "dependencyType": "autoInstall"
}
```

**Dependency Types:**

| Type          | Description                                                   |
| ------------- | ------------------------------------------------------------- |
| `autoInstall` | Automatically install the dependency if not present (default) |
| `detect`      | Only check if the dependency is installed, don't auto-install |

> **Note:** Dependencies are processed after the app is created/uploaded. The target apps must already exist in Intune with matching display names.

### Supersedence

Supersedence allows you to specify apps that this app should replace (upgrade or uninstall-then-replace).

**Config.xml Format:**

```xml
<!-- Comma-separated list of app display names to supersede -->
<Supersedence>Old App v1.0,Old App v2.0</Supersedence>
<SupersedenceType>update</SupersedenceType>
```

**Config.json Format:**

```json
{
  "supersedence": [
    "Old App v1.0",
    "Old App v2.0"
  ],
  "supersedenceType": "update"
}
```

**Supersedence Types:**

| Type      | Description                                                         |
| --------- | ------------------------------------------------------------------- |
| `update`  | Upgrade the old app to this app (keeps detection, upgrades content) |
| `replace` | Uninstall the old app first, then install this app                  |

> **Note:** Supersedence relationships are processed after the app is created/uploaded. The superseded apps must already exist in Intune.

### PowerShell Script Detection

As an alternative to TAGFILE, FILE, or REGISTRY detection, you can use a custom PowerShell script for detection.

**Config.xml Format:**

```xml
<DetectionScriptFile>Detection\Detect-MyApp.ps1</DetectionScriptFile>
<DetectionScriptEnforceSignatureCheck>false</DetectionScriptEnforceSignatureCheck>
<DetectionScriptRunAs32Bit>false</DetectionScriptRunAs32Bit>
```

**Config.json Format:**

```json
{
  "detectionScriptFile": "Detection/Detect-MyApp.ps1",
  "detectionScriptEnforceSignatureCheck": false,
  "detectionScriptRunAs32Bit": false
}
```

| Setting                                | Type    | Default | Description                                         |
| -------------------------------------- | ------- | ------- | --------------------------------------------------- |
| `detectionScriptFile`                  | String  | (empty) | Path to detection script relative to package folder |
| `detectionScriptEnforceSignatureCheck` | Boolean | `false` | Require the script to be signed                     |
| `detectionScriptRunAs32Bit`            | Boolean | `false` | Run the script as a 32-bit process                  |

**Detection Script Requirements:**

- The script must exit with code 0 for "detected" (app installed)
- Any non-zero exit code means "not detected" (app not installed)
- Write output to STDOUT for logging purposes

**Example Detection Script:**

```powershell
# Detect-MyApp.ps1
$appPath = "C:\Program Files\MyApp\MyApp.exe"
if (Test-Path $appPath) {
    Write-Output "MyApp detected at $appPath"
    exit 0
} else {
    Write-Output "MyApp not found"
    exit 1
}
```

### Complete Config.json Example with Extended Settings

```json
{
  "$schema": "./../pawintuneapp.schema.json",
  "appType": "EXE",
  "ruleType": "FILE",
  "filePath": "C:\\Program Files\\MyApp",
  "returnCodeType": "DEFAULT",
  "installExperience": "System",
  "packageName": "Setup",
  "displayVersion": "2.0.0",
  "displayName": "My Application v2.0",
  "description": "Enterprise application for productivity",
  "publisher": "Contoso",
  "category": "Business",
  "logoFile": "Logo.png",
  "entraGroupName": "App-MyApp-Required",
  "scopetag": "CloudPC-Apps",
  "installCmdLine": "Setup.exe /quiet",
  "uninstallCmdLine": "Setup.exe /uninstall /quiet",

  "isFeatured": true,
  "informationUrl": "https://contoso.com/myapp",
  "privacyInformationUrl": "https://contoso.com/privacy",
  "developer": "Contoso Development Team",
  "owner": "IT Department",
  "notes": "Approved for production deployment",

  "maxRunTimeInMinutes": 120,
  "deviceRestartBehavior": "suppress",

  "minimumFreeDiskSpaceInMB": 500,
  "minimumMemoryInMB": 4096,
  "minimumNumberOfProcessors": 2,
  "minimumCpuSpeedInMHz": 1000,
  "allowedArchitectures": "x64",
  "minimumSupportedOS": "v10_21H2",

  "customReturnCodes": [
    { "returnCode": 3010, "type": "softReboot" },
    { "returnCode": 1641, "type": "hardReboot" }
  ],

  "dependencies": [
    "Microsoft Visual C++ Redistributable",
    "Microsoft .NET Runtime 8.0"
  ],
  "dependencyType": "autoInstall",

  "supersedence": [
    "My Application v1.0"
  ],
  "supersedenceType": "update"
}
```

### Complete Config.xml Example with Extended Settings

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
        <PackageName>Setup</PackageName>
        <displayName>My Application v2.0</displayName>
        <displayVersion>2.0.0</displayVersion>
        <Description>Enterprise application for productivity</Description>
        <Publisher>Contoso</Publisher>
        <Category>Business</Category>
        <LogoFile>Logo.png</LogoFile>
        <EntraGroupName>App-MyApp-Required</EntraGroupName>
        <ScopeTag>CloudPC-Apps</ScopeTag>

        <!-- Extended Settings -->
        <IsFeatured>true</IsFeatured>
        <InformationUrl>https://contoso.com/myapp</InformationUrl>
        <PrivacyInformationUrl>https://contoso.com/privacy</PrivacyInformationUrl>
        <Developer>Contoso Development Team</Developer>
        <Owner>IT Department</Owner>
        <Notes>Approved for production deployment</Notes>

        <MaxRunTimeInMinutes>120</MaxRunTimeInMinutes>
        <DeviceRestartBehavior>suppress</DeviceRestartBehavior>

        <MinimumFreeDiskSpaceInMB>500</MinimumFreeDiskSpaceInMB>
        <MinimumMemoryInMB>4096</MinimumMemoryInMB>
        <MinimumNumberOfProcessors>2</MinimumNumberOfProcessors>
        <MinimumCpuSpeedInMHz>1000</MinimumCpuSpeedInMHz>
        <AllowedArchitectures>x64</AllowedArchitectures>
        <MinimumSupportedOS>v10_21H2</MinimumSupportedOS>

        <CustomReturnCodes>3010:softReboot,1641:hardReboot</CustomReturnCodes>

        <Dependencies>Microsoft Visual C++ Redistributable,Microsoft .NET Runtime 8.0</Dependencies>
        <DependencyType>autoInstall</DependencyType>

        <Supersedence>My Application v1.0</Supersedence>
        <SupersedenceType>update</SupersedenceType>
    </IntuneWin_Settings>
</CONFIG>
```

---

## Assignment Behavior (v1.7)

Version 1.7 introduces enhanced assignment behavior settings to optimize the app deployment experience.

### Delivery Optimization Priority

All assignment types (Required, Available, and Uninstall) now use **foreground** delivery optimization priority. This setting prioritizes the app download, resulting in faster delivery to devices.

| Priority Setting | Description                                         |
| ---------------- | --------------------------------------------------- |
| `foreground`     | Prioritized download for faster app delivery (v1.7) |
| `notConfigured`  | Default Windows delivery optimization behavior      |

### User Notification Settings

The script now applies intelligent notification settings based on the assignment intent:

| Assignment Intent | Notifications | Behavior                                             |
| ----------------- | ------------- | ---------------------------------------------------- |
| **Required**      | Hidden        | Silent installation without user prompts             |
| **Available**     | Hidden        | App appears in Company Portal without install toasts |
| **Uninstall**     | Shown         | User notified when app is being removed              |

This configuration provides a streamlined experience:

- **Required apps** install silently without interrupting users
- **Available apps** are discoverable in Company Portal without unwanted notifications
- **Uninstall actions** notify users so they understand why an app is being removed

### Assignment Settings Summary

The following settings are applied automatically to all Win32 app assignments:

```json
{
  "settings": {
    "@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
    "notifications": "hideAll",
    "deliveryOptimizationPriority": "foreground",
    "installTimeSettings": {
      "useLocalTime": false,
      "deadlineDateTime": null
    }
  }
}
```

> **Note:** For Uninstall assignments, `notifications` is set to `showAll` instead of `hideAll`.

> **Note:** Exclusion group assignments do not include the `settings` property as it is not supported by the Microsoft Graph API.

---

## Graph Connection Management (v1.7)

Version 1.7 introduces improved Microsoft Graph connection management to support batch processing of multiple packages.

### Connection Behavior by Authentication Method

| Authentication Method | Default Behavior                      | Override                             |
| --------------------- | ------------------------------------- | ------------------------------------ |
| `-IntuneAdmin`        | Connection **preserved** after script | Add `-DisconnectGraph` to disconnect |
| `-ClientSecret`       | Connection **always disconnected**    | N/A                                  |
| `-CertName`           | Connection **always disconnected**    | N/A                                  |

### Benefits of Preserved Connections

When using `-IntuneAdmin`, the Graph connection is preserved by default, enabling:

- **Batch processing**: Upload multiple packages without re-authentication
- **Faster execution**: No authentication delay between packages
- **Pipeline support**: Pass multiple paths to `-PackagePath`

### Connection Management Examples

**Run multiple packages with single authentication:**

```powershell
# First package - authenticates once
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\App1" -IntuneAdmin "admin@contoso.com"

# Second package - reuses existing connection (no auth prompt)
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\App2" -IntuneAdmin "admin@contoso.com"

# Last package - disconnect when done
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\App3" -IntuneAdmin "admin@contoso.com" -DisconnectGraph
```

**Explicitly disconnect after each run:**

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -DisconnectGraph
```

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

**Script Version**: 1.7
**Last Updated**: December 2025
**Author**: Greg Nottage
