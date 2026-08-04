# Upload-IntuneWin.ps1

<!-- TIP: In VS Code, press Ctrl+Shift+V to open the Markdown preview and render this document properly. -->

A comprehensive PowerShell script for creating and uploading Win32 application packages (.intunewin) to Microsoft Intune.

> **New to this?** Start with the [Quick Start guide](Upload-IntuneWin_QuickStart.html) — it walks through packaging and uploading your first app without needing any of the detail below.

**Related guides:** [Quick Start](Upload-IntuneWin_QuickStart.html) · [Export-IntunePolicy](Export-IntunePolicy_ReadMe.html) · [Change log](Upload-IntuneWin_ChangeLog.html)

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
- [Caller-Supplied Authentication (v1.97)](#caller-supplied-authentication-v197)
- [Secure Client Secret Sources (v1.97)](#secure-client-secret-sources-v197)
- [Multi-Tenant Configuration File (v1.97)](#multi-tenant-configuration-file-v197)
- [PowerShell Script Installer Type (v1.96)](#powershell-script-installer-type-v196)
- [Dependency and Supersedence Fixes (v1.94)](#dependency-and-supersedence-fixes-v194)
- [DelegatedImport Parity Enhancements (v1.93)](#delegatedimport-parity-enhancements-v193)
- [Corporate Proxy Support (v1.93)](#corporate-proxy-support-v193)
- [Upload Resilience and Feature Parity (v1.92)](#upload-resilience-and-feature-parity-v192)
- [App Deletion (v1.92)](#app-deletion-v192)
- [Config File Upload Parameters (v1.91)](#config-file-upload-parameters-v191)
- [Script Optimizations (v1.9)](#script-optimizations-v19)
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
- ✅ **Configurable "Allow available uninstall"** — enabled by default, can be disabled per-app via `allowAvailableUninstall` config property
- ✅ Apply custom Intune scope tags for RBAC management (supports multiple, comma-separated)
- ✅ Multiple authentication methods (Interactive, Certificate, Client Secret)
- ✅ **Custom app registration with delegated auth** — pass `-ClientID` with `-IntuneAdmin` to route interactive sign-in through your own app registration
- ✅ **Multiple app categories** — `category` config property accepts a comma-separated list (e.g., `"Communication,Productivity"`)
- ✅ Automatic return code configuration
- ✅ **ESP/Core app designation support** (via Config.json)
- ✅ **Automatic logo detection and addition** when updating existing apps
- ✅ **Automatic version detection** for EXE and MSI installers (v1.6)
- ✅ **Auto-download and update of IntuneWinAppUtil.exe** from GitHub (v1.7)
- ✅ **EXE file validation** with fuzzy matching to detect mismatched installer filenames (v1.7)
- ✅ **Foreground delivery optimization** for faster app downloads on all assignment types (v1.7)
- ✅ **Smart notification settings** - hidden for Required/Available, shown for Uninstall (v1.7)
- ✅ **DisconnectGraph switch** for preserving Graph connections across multiple runs (v1.7)
- ✅ **Automatic retry logic** for Graph API calls with exponential backoff (v1.9)
- ✅ **Enhanced configuration validation** with centralized error checking (v1.9)
- ✅ **WhatIf support** to preview operations before execution (v1.9)
- ✅ **Improved error handling** with proper control flow management (v1.9)
- ✅ **Config file support for upload parameters** — assignment groups, content replacement, and package removal settings can be specified in Config.json or Config.xml (v1.91)
- ✅ **NewTagPath enabled by default** — tagfile detection uses the diagnostics-compatible path without requiring the switch (v1.91)
- ✅ **App deletion via `-DeleteApp`/`-AppNameToDelete`** — delete one or many Intune apps from a config file, command line, or pipeline (v1.92)
- ✅ **Upload resilience** — SAS readiness probing, per-chunk retry with automatic SAS renewal, file-commit retry loop, and full upload-attempt retry with fresh content versions (v1.92)
- ✅ **Smart logo handling** — auto-scans the package folder for `PNG`/`JPG`/`JPEG` files, sets correct MIME type, and persists the logo via a dedicated PATCH after content commit (v1.92)
- ✅ **HTTP 412 Precondition Failed now retryable** to handle content version conflicts (v1.92)
- ✅ **Automatic 401 token refresh** — Graph requests transparently re-authenticate and retry when the token expires (v1.93)
- ✅ **Expanded transient-error detection** — retries on `forcibly closed`, `ResponseEnded`, `response ended prematurely`, `request was canceled`, and similar network failures (v1.93)
- ✅ **Stuck app delete/recreate** — detects apps stuck in `notPublished` state via `Wait-AppPublishingState` and recreates them on retry (v1.93)
- ✅ **Escalating upload retry backoff** — 30 s × attempt number between full upload retries (v1.93)
- ✅ **OrigSource → Source robocopy** — when `OrigSource\` exists, the script mirrors it into `Source\` with `robocopy /MIR /MT:4` for a clean, reproducible build (v1.93)
- ✅ **Corporate proxy support** — opt-in routing of every outbound HTTP/S call (MSAL, Graph SDK, Azure Storage SAS upload, GitHub tool download) through a corporate proxy via `-ProxyUri` / `$env:INTUNEWIN_PROXY_URI`, with explicit credential, Windows-integrated, and bypass-list modes; built-in auto-fallback skips the proxy when direct connectivity already works (v1.93)
- ✅ **`-TestProxyConnectivity` diagnostic switch** — runs a direct-vs-proxy connectivity report against Graph and Entra ID and exits with `0 = PASS`, `1 = FAIL`, `2 = init error` (v1.93)
- ✅ **Bundled-module precedence** — a signed `Microsoft.Graph.Authentication` copy shipped in the script's `Modules\` folder is prepended to `PSModulePath` and used in preference to any installed copy, so the script runs with zero module installation; the prepend is fail-closed and requires a trusted-publisher Authenticode signature (v1.93)
- ✅ **App dependencies and supersedence now actually apply** — relationships declared in `Config.xml`/`Config.json` are created via the supported `updateRelationships` Graph action; previously every attempt failed silently (v1.94)
- ✅ **Relationship merge on write** — existing relationships are read back and re-posted, so adding a dependency no longer wipes supersedence and vice versa (v1.94)
- ✅ **App names or IDs accepted** — dependency and supersedence targets can be given as a display name or an application GUID; names are resolved automatically and unresolvable names are skipped with a warning instead of failing the upload (v1.94)
- ✅ **Per-app dependency and supersedence types** — each referenced app can carry its own `autoInstall`/`detect` or `update`/`replace` type, via repeated element pairs or an inline `Name:Type` suffix, instead of one type governing the whole list (v1.95)
- ✅ **Proxy `407` handling** — an authenticating proxy no longer leaves the run with a null token while reporting success; the script retries once with your Windows credentials and otherwise stops with actionable proxy guidance (v1.95)
- ✅ **PowerShell script installer type** — install and/or uninstall can run from a `.ps1` instead of a command line, matching the portal's `Installer type: PowerShell script`, with per-script signature-check and 32-bit options; any combination of script and command line is supported (v1.96)
- ✅ Detailed logging for troubleshooting

---

## Prerequisites

Before running the script, ensure you have:

1. **PowerShell 5.1 or later**
2. **Microsoft Graph PowerShell SDK module**:
   - `Microsoft.Graph.Authentication`
   - **Note:** This module ships bundled inside the script's `Modules\` folder, so it does **not** need to be installed separately on the target machine (see [Microsoft.Graph.Authentication Module Resolution](#microsoftgraphauthentication-module-resolution) below)
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

> **Note:** Installation is **optional**. The script ships a signed copy of `Microsoft.Graph.Authentication` in its `Modules\` subfolder and prefers it automatically — see the next section. Installing the module is only needed if you remove the bundled copy or the bundled copy fails signature validation.

### Microsoft.Graph.Authentication Module Resolution

The script resolves the `Microsoft.Graph.Authentication` module in the following order, so it can run with **no prior module installation** while still preferring a trusted bundled copy:

1. **Bundled copy (preferred)** — at startup the script looks for `<ScriptRoot>\Modules\Microsoft.Graph.Authentication`. If found, the `<ScriptRoot>\Modules` folder is **prepended to `$env:PSModulePath`** so the bundled module takes precedence over any machine- or user-installed copy. This is the same precedence model used by `Invoke-DelegatedImport.ps1`.
2. **Installed copy** — if no bundled copy exists (or it fails the signature check below), the script falls back to a system- or user-installed `Microsoft.Graph.Authentication` discovered via the normal `Get-Module -ListAvailable`.
3. **Script-root copies (legacy fallback)** — if the module is still not available, the script then probes `<ScriptRoot>\Microsoft.Graph.Authentication` and finally `<ScriptRoot>\Modules\Microsoft.Graph.Authentication` and imports the first one found. If none of these resolve, the script exits with guidance to run `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`.

#### Fail-Closed Signature Enforcement

Because `Microsoft.Graph.Authentication` handles authentication tokens, the bundled-module prepend is **fail-closed** — a counterfeit module dropped into `Modules\` could exfiltrate Graph tokens, so the prepend only happens when **every** `*.psm1` under the bundled folder is Authenticode-signed by a trusted publisher:

- Every `*.psm1` must have signature status `Valid`.
- The signing certificate subject must match one of the trusted publishers (default: `CN=Microsoft Corporation`, `CN=Microsoft Code Signing`, `CN=Microsoft 3rd Party Application Component`, `CN=GitHub`).
- If any file is unsigned, has an invalid signature, or is signed by an untrusted publisher, the prepend is **skipped** with a warning and the script falls back to the installed copy.

Override the trusted-publisher allow-list with the `$env:INTUNEWIN_TRUSTED_PUBLISHERS` environment variable (semicolon-separated subject substrings).

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

| Parameter             | Type             | Required | Description                                                        |
| --------------------- | ---------------- | -------- | ------------------------------------------------------------------ |
| `-IntuneAdmin`        | String           | No       | Admin UPN for interactive authentication                           |
| `-ClientID`           | String           | No       | App Registration Application (client) ID                           |
| `-TenantID`           | String           | No       | Azure Tenant ID                                                    |
| `-ClientSecret`       | String           | No       | App Registration Client Secret                                     |
| `-CertName`           | String           | No       | Certificate name for cert-based authentication                     |
| `-AccessToken`        | `[SecureString]` | No       | Pre-acquired Graph token. Aliases: `Token`, `GraphToken` *(v1.97)* |
| `-TokenRefreshScript` | `[ScriptBlock]`  | No       | Invoked on HTTP 401 to obtain a fresh token *(v1.97)*              |

### Secure Secret Source Parameters (v1.97)

Supply the client secret without putting it on the command line. See [Secure Client Secret Sources (v1.97)](#secure-client-secret-sources-v197).

| Parameter                  | Type   | Description                                                                             |
| -------------------------- | ------ | --------------------------------------------------------------------------------------- |
| `-ClientSecretFile`        | String | Path to a DPAPI-protected secret file created by `-ProtectSecret`                       |
| `-ProtectSecret`           | Switch | Alternate path: prompt for a secret, DPAPI-encrypt it to `-ClientSecretFile`, exit      |
| `-KeyVaultName`            | String | Key Vault name to retrieve the secret from. Requires `-KeyVaultSecretName`              |
| `-KeyVaultSecretName`      | String | Name of the Key Vault secret holding the client secret                                  |
| `-KeyVaultAuth`            | String | `ManagedIdentity` (default) or `Certificate` — how the vault itself is authenticated    |
| `-ManagedIdentityClientId` | String | Client ID of a user-assigned managed identity. Omit to use the system-assigned identity |

### Multi-Tenant Configuration Parameters (v1.97)

Hold each environment's settings in one file instead of passing them every time. See [Multi-Tenant Configuration File (v1.97)](#multi-tenant-configuration-file-v197).

| Parameter           | Type   | Description                                                                                                  |
| ------------------- | ------ | ------------------------------------------------------------------------------------------------------------ |
| `-TenantConfigFile` | String | Path to an SPN configuration file with one `<spn>` entry per environment. Aliases: `SpnFile`, `TenantConfig` |
| `-EnvironmentName`  | String | Which environment to select, matched on `<tenantname>`. Aliases: `TenantName`, `Environment`                 |

### Proxy Parameters (v1.93)

All proxy parameters are **opt-in**. When neither `-ProxyUri` nor `$env:INTUNEWIN_PROXY_URI` is set the script runs without any proxy plumbing — existing usage is unaffected. See [Corporate Proxy Support (v1.93)](#corporate-proxy-support-v193) for details.

| Parameter                     | Type           | Description                                                                                                                                                                                   |
| ----------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-ProxyUri`                   | `[uri]`        | Absolute URI of the outbound HTTP/HTTPS proxy (e.g., `http://proxy.contoso.com:443`). Falls back to `$env:INTUNEWIN_PROXY_URI`. Aliases: `Proxy`, `HttpsProxy`.                                    |
| `-ProxyCredential`            | `PSCredential` | Credential used to authenticate against the proxy server. If `-ProxyUri` is supplied but no credential is, the script prompts once via `Get-Credential` and reuses the result.                |
| `-ProxyUseDefaultCredentials` | Switch         | Use Windows-integrated authentication (Kerberos / NTLM) for the proxy instead of explicit credentials — skips the credential prompt. Falls back to `$env:INTUNEWIN_PROXY_USE_DEFAULT_CREDENTIALS`. |
| `-ProxyBypassList`            | `String[]`     | Wildcard hostname patterns to bypass the proxy for (e.g., `*.contoso.com`). Falls back to `$env:INTUNEWIN_PROXY_BYPASS` (semicolon-separated).                                                     |
| `-NoProxyBypassLocal`         | Switch         | Disable the default behaviour of bypassing the proxy for local-name addresses. Falls back to `$env:INTUNEWIN_PROXY_BYPASS_ON_LOCAL=false`.                                                         |

### Package Parameters

| Parameter               | Type     | Required | Description                                                                                                             |
| ----------------------- | -------- | -------- | ----------------------------------------------------------------------------------------------------------------------- |
| `-PackagePath`          | String[] | Yes¹     | Path to package folder containing Config.json or Config.xml. Optional when used with `-DeleteApp` + `-AppNameToDelete`. |
| `-IntuneWinAppUtilPath` | String   | No       | Path to IntuneWinAppUtil.exe folder                                                                                     |

¹ `-PackagePath` becomes optional when deleting apps by display name via `-DeleteApp -AppNameToDelete`.

### Mode Switches

| Switch                        | Description                                                                                                                                                                                                                                                            |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-IntuneWinPackageOnly`       | Create .intunewin file only, don't upload                                                                                                                                                                                                                              |
| `-AssignGroupsOnly`           | Only assign groups to existing app                                                                                                                                                                                                                                     |
| `-SkipGroupAssignment`        | Upload without assigning groups                                                                                                                                                                                                                                        |
| `-SkipPackageRemoval`         | Keep .intunewin file after upload (can also be set in config file)                                                                                                                                                                                                     |
| `-NewTagPath`                 | Enabled by default (v1.91). Uses diagnostics-compatible tagfile path. Can be set to `false` in config file                                                                                                                                                             |
| `-ReplaceExistingContent`     | Replace IntuneWin content of existing app; applies assignments only if none exist                                                                                                                                                                                      |
| `-ReplaceExistingAssignments` | Clear and replace all assignments on existing app                                                                                                                                                                                                                      |
| `-DisconnectGraph`            | Explicitly disconnect from Microsoft Graph after completion (connection is preserved by default with -IntuneAdmin)                                                                                                                                                     |
| `-DeleteApp`                  | Delete an app from Intune instead of uploading. Reads `displayName` from the config file unless `-AppNameToDelete` is supplied (v1.92)                                                                                                                                 |
| `-TestProxyConnectivity`      | Diagnostic mode (v1.93). Runs a direct-vs-proxy connectivity report against `graph.microsoft.com:443` and `login.microsoftonline.com:443`, prints the result, and exits with `0` (PASS), `1` (FAIL), or `2` (init error). Does not upload, modify, or delete anything. |
| `-WhatIf`                     | Preview operations (upload, update, delete, group create/assign) without making any changes                                                                                                                                                                            |
| `-Confirm`                    | Prompt for confirmation before any operation that modifies Intune                                                                                                                                                                                                      |

### Delete Parameters (v1.92)

| Parameter          | Type     | Description                                                                                                                                  |
| ------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `-AppNameToDelete` | String[] | Display name(s) of app(s) to delete. Supports pipeline input. When supplied, `-PackagePath` becomes optional. Aliases: `DisplayName`, `Name` |

### Assignment Parameters

| Parameter                                             | Type     | Description                                                                 |
| ----------------------------------------------------- | -------- | --------------------------------------------------------------------------- |
| `-RequiredAADGroupName` / `-RequiredEntraGroupName`   | String[] | Entra ID group(s) for required assignment (can also be set in config file)  |
| `-AvailableAADGroupName` / `-AvailableEntraGroupName` | String[] | Entra ID group(s) for available assignment (can also be set in config file) |
| `-UninstallAADGroupName` / `-UninstallEntraGroupName` | String[] | Entra ID group(s) for uninstall assignment (can also be set in config file) |
| `-ScopeTagName`                                       | String[] | Intune scope tag(s) to apply                                                |

---

## Authentication Methods

### Method 1: Interactive Authentication (Recommended for Testing)

Uses the default Microsoft Graph PowerShell app registration in your tenant.

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com"
```

### Method 2: Interactive Authentication via Custom App Registration (v1.93)

Routes the interactive sign-in through your own Entra ID app registration by combining `-IntuneAdmin` with `-ClientID` (and optionally `-TenantID`). Useful when the default Microsoft Graph PowerShell app is blocked or when you need a specific consent / branding experience.

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -ClientID  "12345678-1234-1234-1234-123456789012" `
    -TenantID  "87654321-4321-4321-4321-210987654321"
```

The connection parameters used at sign-in are cached internally so the script can transparently re-authenticate if the access token expires mid-upload (see [DelegatedImport Parity Enhancements (v1.93)](#delegatedimport-parity-enhancements-v193)).

### Method 3: Client Secret Authentication (For Automation)

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -ClientSecret "YourSecretValue"
```

### Method 4: Certificate Authentication (Most Secure)

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

> **Note:** If the `Source/` folder does not exist but `OrigSource/` exists, the script will automatically use `OrigSource/` as the source for creating the .intunewin package. From **v1.93**, when `OrigSource/` is present the script mirrors it into `Source/` using `robocopy /MIR /MT:4 /NJH /NJS /NP`, so each run starts from a clean, reproducible copy of the original payload.

> **Note:** A logo image is auto-detected from the package folder root. If `logoFile` is not set in the config, the script picks the first `*.png`, `*.jpg`, or `*.jpeg` it finds and uploads it with the correct MIME type (`image/png` or `image/jpeg`).

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

| Property                  | Values                                | Description                                                                                                                                            |
| ------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `appType`                 | `MSI`, `EXE`, `PS1`, `Edge`           | Type of application                                                                                                                                    |
| `ruleType`                | `TAGFILE`, `FILE`, `REGISTRY`, `MSI`  | Detection rule type                                                                                                                                    |
| `returnCodeType`          | `DEFAULT`                             | Return code configuration                                                                                                                              |
| `installExperience`       | `System`, `User`                      | Installation context                                                                                                                                   |
| `packageName`             | String                                | Setup file name (without extension)                                                                                                                    |
| `displayName`             | String                                | Display name shown in Intune                                                                                                                           |
| `displayVersion`          | String                                | Version string to display                                                                                                                              |
| `description`             | String                                | Application description                                                                                                                                |
| `publisher`               | String                                | Publisher name                                                                                                                                         |
| `category`                | String (comma-separated for multiple) | App category (e.g., `Business`, or `"Communication,Productivity"`). All listed categories are assigned to the app (loop over `Set-IntuneAppCategory`). |
| `logoFile`                | String                                | Path to logo file (PNG/JPG/JPEG). Auto-detected from the package folder root if omitted.                                                               |
| `allowAvailableUninstall` | Boolean / `yes` / `no`                | Enables user-initiated uninstall from Company Portal (default: `true`)                                                                                 |
| `channel`                 | String (Edge only)                    | Edge channel: `stable`, `beta`, `dev`, or `canary`                                                                                                     |
| `msiInstallCommandLine`   | String                                | Optional install command-line override for MSI apps                                                                                                    |
| `msiUninstallCommandLine` | String                                | Optional uninstall command-line override for MSI apps                                                                                                  |
| `entraGroupName`          | String                                | Entra ID group name for assignments (preferred)                                                                                                        |
| `aadGroupName`            | String                                | AAD group name (legacy, still supported)                                                                                                               |
| `scopetag`                | String                                | Intune scope tag name (optional)                                                                                                                       |
| `coreApp`                 | Boolean                               | Mark as core app (optional)                                                                                                                            |
| `espApp`                  | Boolean                               | Include in ESP (optional)                                                                                                                              |
| `newTagPath`              | Boolean                               | Use diagnostics-compatible tagfile path (default: `true` if not specified)                                                                             |
| `requiredEntraGroupName`  | String or Array                       | Entra ID group(s) for required assignment (also accepts `requiredAADGroupName`)                                                                        |
| `availableEntraGroupName` | String or Array                       | Entra ID group(s) for available assignment (also accepts `availableAADGroupName`)                                                                      |
| `uninstallEntraGroupName` | String or Array                       | Entra ID group(s) for uninstall assignment (also accepts `uninstallAADGroupName`)                                                                      |
| `replaceExistingContent`  | Boolean                               | Replace IntuneWin content of existing app (optional)                                                                                                   |
| `skipPackageRemoval`      | Boolean                               | Keep .intunewin file after upload (optional)                                                                                                           |

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

| Attribute                 | Values                               | Description                                                                       |
| ------------------------- | ------------------------------------ | --------------------------------------------------------------------------------- |
| `AppType`                 | `MSI`, `EXE`, `PS1`, `Edge`          | Type of application                                                               |
| `RuleType`                | `TAGFILE`, `FILE`, `REGISTRY`, `MSI` | Detection rule type                                                               |
| `InstallExperience`       | `System`, `User`                     | Installation context                                                              |
| `ScopeTag`                | String                               | Intune scope tag name (optional)                                                  |
| `PackageName`             | String                               | Setup file name (without extension)                                               |
| `displayName`             | String                               | Display name shown in Intune                                                      |
| `displayVersion`          | String                               | Version string to display                                                         |
| `Description`             | String                               | Application description                                                           |
| `Publisher`               | String                               | Publisher name                                                                    |
| `Category`                | String                               | App category                                                                      |
| `LogoFile`                | String                               | Path to logo file                                                                 |
| `EntraGroupName`          | String                               | Entra ID group name for assignments (preferred)                                   |
| `AADGroupName`            | String                               | AAD group name (legacy, still supported)                                          |
| `NewTagPath`              | `true` / `false` / `yes` / `no`      | Use diagnostics-compatible tagfile path (default: `true` if not specified)        |
| `RequiredEntraGroupName`  | String (comma-separated)             | Entra ID group(s) for required assignment (also accepts `RequiredAADGroupName`)   |
| `AvailableEntraGroupName` | String (comma-separated)             | Entra ID group(s) for available assignment (also accepts `AvailableAADGroupName`) |
| `UninstallEntraGroupName` | String (comma-separated)             | Entra ID group(s) for uninstall assignment (also accepts `UninstallAADGroupName`) |
| `ReplaceExistingContent`  | `true` / `false` / `yes` / `no`      | Replace IntuneWin content of existing app (optional)                              |
| `SkipPackageRemoval`      | `true` / `false` / `yes` / `no`      | Keep .intunewin file after upload (optional)                                      |

---

## Caller-Supplied Authentication (v1.97)

The script can run against a Microsoft Graph token that something else acquired. Authentication, proxy negotiation and secret retrieval then live outside this script entirely, which makes it callable from an orchestrating script, a build pipeline, or any host that already holds a token — a managed identity, a certificate flow, or a secret store.

| Parameter             | Type             | Purpose                                     |
| --------------------- | ---------------- | ------------------------------------------- |
| `-AccessToken`        | `[SecureString]` | Pre-acquired Graph access token             |
| `-TokenRefreshScript` | `[ScriptBlock]`  | Invoked on HTTP 401 to obtain a fresh token |

`-AccessToken` takes precedence over `-IntuneAdmin`, `-CertName` and `-ClientSecret`, and works for both uploads and `-DeleteApp`.

### Why pass a token instead of a secret

`-ClientSecret` is a plain string, so it appears in the process list and in shell history. Acquiring the token in the calling script and passing `-AccessToken` keeps the secret out of this script's invocation entirely.

```powershell
$token = $myToken | ConvertTo-SecureString -AsPlainText -Force
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -AccessToken $token
```

### Surviving token expiry

Win32 uploads can outlast a token. Supply `-TokenRefreshScript` and a 401 will invoke the scriptblock, re-seed the session with the returned token, and retry the request — so a large package is not lost part-way through:

```powershell
$getToken = {
    $body = @{
        grant_type    = 'client_credentials'
        scope         = 'https://graph.microsoft.com/.default'
        client_id     = $env:APP_CLIENT_ID
        client_secret = $env:APP_CLIENT_SECRET
    }
    (Invoke-RestMethod -Method POST -Body $body `
        -Uri "https://login.microsoftonline.com/$env:APP_TENANT_ID/oauth2/v2.0/token").access_token
}

$token = & $getToken | ConvertTo-SecureString -AsPlainText -Force

.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -AccessToken $token `
    -TokenRefreshScript $getToken
```

The scriptblock may return a `String` or a `SecureString`. If it returns nothing, or throws, the failure is logged and the run ends rather than retrying indefinitely.

### Behaviour without a refresh script

Where `-AccessToken` is supplied on its own, an expired token ends the run with an actionable message. It deliberately never falls back to an interactive sign-in prompt — an unattended run cannot hang waiting for input.

| Supplied                                       | On token expiry                                          |
| ---------------------------------------------- | -------------------------------------------------------- |
| `-AccessToken` + `-TokenRefreshScript`         | Token renewed automatically, request retried             |
| `-AccessToken` only                            | Run ends with guidance to re-run or add a refresh script |
| `-IntuneAdmin` / `-ClientSecret` / `-CertName` | Existing re-authentication behaviour, unchanged          |

---

## Secure Client Secret Sources (v1.97)

Three ways to supply a client secret without putting it on the command line, where it would otherwise be visible in the process list and shell history. All are self-contained — no `Az` or `SecretManagement` modules are required, so the script stays a single file with one bundled dependency.

Precedence, highest first:

| Source               | Parameters                             | Secret stored on the machine? |
| -------------------- | -------------------------------------- | ----------------------------- |
| Azure Key Vault      | `-KeyVaultName`, `-KeyVaultSecretName` | No                            |
| DPAPI-protected file | `-ClientSecretFile`                    | Yes, encrypted                |
| Literal string       | `-ClientSecret`                        | No, but exposed on the CLI    |

### DPAPI-protected file

Create the file once, as the identity that will run the uploads:

```powershell
.\Upload-IntuneWin.ps1 -ProtectSecret -ClientSecretFile "C:\Secure\app-secret.dpapi"
```

You are prompted for the secret, so it never reaches the command line. Then use it:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -ClientSecretFile "C:\Secure\app-secret.dpapi"
```

> **Important:** DPAPI binds the ciphertext to **the current user on the current machine**. A file you create interactively will **not** decrypt under a build agent's service account, or on another host. That is the security property, but it is also the most common cause of failure — create the file as the identity that runs the script. On shared build agents, prefer Key Vault.

If decryption fails the script says so explicitly, naming the account and machine it is running as.

### Azure Key Vault

Nothing secret is stored on the machine at all. The vault is read over REST at `https://<vault>.vault.azure.net/secrets/<name>?api-version=7.4`.

**Managed identity (default)** — for Azure VMs, Scale Sets, App Service, Functions and Container Apps:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -KeyVaultName "my-vault" -KeyVaultSecretName "intune-app-secret"
```

Both managed identity endpoints are supported automatically — `IDENTITY_ENDPOINT` where present (App Service, Functions, Container Apps), otherwise IMDS at `169.254.169.254`. The IMDS call deliberately bypasses any configured proxy, because routing a link-local address through a corporate proxy always fails.

For a host carrying several user-assigned identities, name the one to use:

```powershell
    -ManagedIdentityClientId "11111111-2222-3333-4444-555555555555"
```

**Certificate** — for hosts outside Azure, where no managed identity exists:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -KeyVaultName "my-vault" -KeyVaultSecretName "intune-app-secret" `
    -KeyVaultAuth Certificate -CertName "IntuneAutomation"
```

The certificate signs an RS256 JWT client assertion, so no secret is needed in order to fetch the secret. The certificate is looked up in `CurrentUser\My` then `LocalMachine\My`, must have a private key, and is rejected if expired.

### Required vault permissions

The identity reading the vault needs **Key Vault Secrets User** (RBAC) or a **Get** access policy on secrets. An HTTP 403 is reported with that guidance inline, and a 404 names the missing secret.

### Proxy behaviour

Every outbound call in the credential paths honours the proxy configuration, with two deliberate exceptions:

| Call                                 | Proxy treatment                          |
| ------------------------------------ | ---------------------------------------- |
| Key Vault secret retrieval           | Routed through the configured proxy      |
| Certificate token exchange           | Routed through the configured proxy      |
| Graph connection from `-AccessToken` | Inherits the proxy set at initialisation |
| IMDS (`169.254.169.254`)             | **Bypasses** the proxy                   |
| `IDENTITY_ENDPOINT` (loopback)       | **Bypasses** the proxy                   |

The managed identity endpoints are link-local and loopback addresses — routing them through a corporate proxy always fails. They are also added to the proxy bypass list automatically, so they stay reachable even when a proxy is configured globally.

### PowerShell version support

Everything runs on **Windows PowerShell 5.1** and **PowerShell 7**. Two paths branch to use a better PowerShell 7 facility, falling back cleanly on 5.1:

| Operation                    | PowerShell 7                            | Windows PowerShell 5.1                |
| ---------------------------- | --------------------------------------- | ------------------------------------- |
| `SecureString` → plain text  | `ConvertFrom-SecureString -AsPlainText` | Marshals the value                    |
| Bypassing the proxy for IMDS | `Invoke-RestMethod -NoProxy`            | `HttpWebRequest` with `Proxy = $null` |

Both paths are verified on each version, including RSA JWT signing for certificate authentication, which produces a validating signature identically on both.

### Constrained Language Mode

The credential functions avoid restricted .NET APIs wherever it costs nothing — file access uses cmdlets rather than `System.IO.File`, and secret handling uses the PowerShell 7 native conversion. Three things remain restricted:

- the two PowerShell 5.1 fallbacks in the table above
- `-KeyVaultAuth Certificate`, because RSA signing needs cryptography APIs that CLM blocks

> **Be aware:** the script *as a whole* cannot run under Constrained Language Mode regardless of the above. Building `.intunewin` packages requires file, path and compression APIs that CLM does not permit, and those calls predate this work. Reducing the credential surface lowers exposure — it does not make the script CLM-ready.

---

## Multi-Tenant Configuration File (v1.97)

Where apps are pushed to several tenants — Dev, Test and Production, or separate customer tenants — each environment's IDs and secret source can live in one file rather than being retyped on every run.

The file holds one `<spn>` element per environment, identified by `<tenantname>`:

```xml
<root>
  <spn>
    <tenantname>Production</tenantname>
    <tenantid>11111111-1111-1111-1111-111111111111</tenantid>
    <clientid>aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa</clientid>
    <keyvaultname>prod-vault</keyvaultname>
    <keyvaultsecretname>intune-app-secret</keyvaultsecretname>
    <keyvaultauth>ManagedIdentity</keyvaultauth>
    <scopetag>Production</scopetag>
  </spn>
  <spn>
    <tenantname>Test</tenantname>
    <tenantid>22222222-2222-2222-2222-222222222222</tenantid>
    <clientid>bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb</clientid>
    <clientsecretfile>C:\Secure\test-secret.dpapi</clientsecretfile>
  </spn>
  <spn>
    <tenantname>Dev</tenantname>
    <tenantid>33333333-3333-3333-3333-333333333333</tenantid>
    <clientid>cccccccc-cccc-cccc-cccc-cccccccccccc</clientid>
    <certname>DevAutomation</certname>
  </spn>
</root>
```

Select an environment by name:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -TenantConfigFile ".\tenants.xml" -EnvironmentName "Production"
```

Each environment can use a **different** secret source — the example above has Production on Key Vault, Test on a DPAPI file and Dev on a certificate.

### Recognised elements

| Element                              | Purpose                                                        |
| ------------------------------------ | -------------------------------------------------------------- |
| `tenantname`                         | Lookup key for `-EnvironmentName` *(required)*                 |
| `tenantid`, `clientid`               | Entra ID identifiers *(required)*                              |
| `certname`                           | Certificate subject for certificate authentication             |
| `clientsecretfile`                   | Path to a DPAPI-protected secret file                          |
| `keyvaultname`, `keyvaultsecretname` | Key Vault retrieval                                            |
| `keyvaultauth`                       | `ManagedIdentity` (default) or `Certificate`                   |
| `managedidentityclientid`            | User-assigned managed identity                                 |
| `proxyserver`                        | Outbound proxy URI (informational — pass `-ProxyUri` to apply) |
| `scopetag`                           | Default Intune scope tag                                       |
| `encrpytedsecret`                    | Legacy obfuscated secret — see the warning below               |

### Behaviour

- **Explicit parameters always win.** Anything passed on the command line overrides the file, so a single environment can be varied without editing it.
- `-EnvironmentName` may be **omitted** when the file holds exactly one entry.
- Omitting it with several entries is an error that **lists the available names**, as is naming one that does not exist.
- A missing file or malformed XML is reported explicitly rather than failing later during authentication.

### Legacy `encrpytedsecret` values

Older SPN files stored the secret in an `<encrpytedsecret>` element, encrypted with an AES key derived from the `clientid` — **which sits in plain text in the same file**. Anyone holding the file can recover the secret offline, so this is obfuscation, not encryption.

Such files are still read so existing setups keep working, but a warning is printed every run. To migrate:

```powershell
.\Upload-IntuneWin.ps1 -ProtectSecret -ClientSecretFile "C:\Secure\prod-secret.dpapi"
```

Then replace `<encrpytedsecret>` with `<clientsecretfile>`, or move the secret to Key Vault. Rotate the secret afterwards — the old value should be treated as compromised.

---

## PowerShell Script Installer Type (v1.96)

Intune's Win32 app **Program** tab now offers `Installer type: PowerShell script` and
`Uninstaller type: PowerShell script` alongside the traditional command line. The script supports
both, and they are configured independently — so **all four combinations** work exactly as they do
in the portal.

| Install      | Uninstall    | Configuration                  |
| ------------ | ------------ | ------------------------------ |
| Command line | Command line | Default — nothing new required |
| **Script**   | Command line | Set `InstallScriptFile` only   |
| Command line | **Script**   | Set `UninstallScriptFile` only |
| **Script**   | **Script**   | Set both                       |

### Configuration

**Config.xml:**

```xml
<!-- Paths are relative to the package folder, or absolute -->
<InstallScriptFile>Scripts\Install.ps1</InstallScriptFile>
<InstallScriptRunAs32Bit>false</InstallScriptRunAs32Bit>
<InstallScriptEnforceSignatureCheck>false</InstallScriptEnforceSignatureCheck>

<UninstallScriptFile>Scripts\Uninstall.ps1</UninstallScriptFile>
<UninstallScriptRunAs32Bit>false</UninstallScriptRunAs32Bit>
<UninstallScriptEnforceSignatureCheck>false</UninstallScriptEnforceSignatureCheck>
```

**Config.json:**

```json
{
  "installScriptFile": "Scripts\\Install.ps1",
  "installScriptRunAs32Bit": false,
  "installScriptEnforceSignatureCheck": false,

  "uninstallScriptFile": "Scripts\\Uninstall.ps1",
  "uninstallScriptRunAs32Bit": false,
  "uninstallScriptEnforceSignatureCheck": false
}
```

| Setting                                     | Default  | Description                                                                                           |
| ------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------- |
| `InstallScriptFile` / `UninstallScriptFile` | *(none)* | Path to the `.ps1`. Absolute, or relative to the package folder. Omit to keep using the command line. |
| `*ScriptRunAs32Bit`                         | `false`  | `true` runs the script in a 32-bit PowerShell host; `false` runs 64-bit.                              |
| `*ScriptEnforceSignatureCheck`              | `false`  | `true` requires the script to be signed before it will run.                                           |

### Behaviour

- **The command line is ignored where a script is set.** Graph documents the script reference as
  *"when null, the install command line is used instead"* — so setting a script takes precedence.
  Graph still requires both command lines to be present, so if you configure a script without a
  matching `installCmdLine` / `uninstallCmdLine` the script generates a placeholder for you.
- **Scripts belong to the content version, not the app.** They are uploaded after the `.intunewin`
  content is committed, and are automatically re-applied whenever content is replaced — so a
  content update will not silently drop your scripts.
- **Size limit:** Intune caps script content at **100 KB**. Oversized scripts are rejected locally,
  before upload, with the raw and encoded sizes reported.
- **`-WhatIf`** previews the script uploads without creating anything.

### How It Works

Each script is created against the app's committed content version:

```http
POST /beta/deviceAppManagement/mobileApps/{appId}/contentVersions/{contentVersionId}/scripts

{
  "@odata.type": "#microsoft.graph.win32LobAppInstallPowerShellScript",
  "displayName": "Install.ps1",
  "content": "<base64>",
  "enforceSignatureCheck": false,
  "runAs32Bit": false
}
```

The returned script ID is then activated on the app:

```http
PATCH /beta/deviceAppManagement/mobileApps/{appId}

{
  "activeInstallScript": {
    "@odata.type": "microsoft.graph.mobileAppScriptReference",
    "targetId": "<script id>"
  },
  "@odata.type": "#microsoft.graph.win32LobApp"
}
```

> **Note:** This feature is only available in the Microsoft Graph **beta** endpoint, which the
> script already uses. It requires `DeviceManagementApps.ReadWrite.All`, which is already in the
> script's requested scopes — no permission changes are needed.

---

## Dependency and Supersedence Fixes (v1.94)

App dependencies and supersedence have been configurable since v1.5 (see [Dependencies](#dependencies) and [Supersedence](#supersedence)), but the relationships were **never actually created in Intune**. Version 1.94 fixes the underlying Graph calls. No configuration changes are required — existing `Config.xml` / `Config.json` files now work as documented.

### What Was Broken

| Defect                       | Symptom                                                                                                                                                                     |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Parameter mismatch           | `Set-IntuneAppDependency` / `Set-IntuneAppSupersedence` were called with parameter names the functions did not declare, so every call failed with a parameter-binding error |
| App name passed as an app ID | The config supplies display names, but the Graph payload requires an application GUID                                                                                       |
| Unsupported endpoint         | `POST /deviceAppManagement/mobileApps/{id}/relationships` is not supported for Win32 apps                                                                                   |
| `@odata.type` ordering       | The request body was an unordered hashtable, so the type annotation could be serialised after `targetId`, which Graph rejects                                               |

The last defect produced this error, which is now resolved:

```text
HTTP 400 Bad Request
{"error":{"code":"ModelValidationFailure","message":"The annotation 'odata.type' was found.
 This annotation is either not recognized or not expected at the current position."}}
```

### The Supported Graph Call

Relationships are now written with the `updateRelationships` action — the same call the Intune portal makes — with `@odata.type` as the first property of each relationship object:

```http
POST https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{appId}/updateRelationships
Content-Type: application/json

{
  "relationships": [
    {
      "@odata.type": "#microsoft.graph.mobileAppDependency",
      "targetId": "<dependency app id>",
      "dependencyType": "autoInstall"
    },
    {
      "@odata.type": "#microsoft.graph.mobileAppSupersedence",
      "targetId": "<superseded app id>",
      "supersedenceType": "update"
    }
  ]
}
```

### Relationships Are Merged, Not Overwritten

`updateRelationships` **replaces the entire child relationship set** on the app. The script therefore reads the existing relationships first, keeps them, and posts the complete set with the new relationship merged in. Practical effects:

- Adding a dependency no longer removes existing supersedence entries (and vice versa)
- Re-running the script is idempotent — re-declaring an existing relationship updates its type rather than duplicating it
- Relationships where the app is the **target** rather than the source (`targetType = parent`) are left alone, because they belong to the other app

### Names or IDs

Dependency and supersedence targets may be given as either a display name or an application GUID. Names are resolved via a `displayName` lookup before the relationship is written; embedded apostrophes are escaped correctly, so names such as `Bob's App` work. If a target cannot be found, the script logs a warning and skips that relationship — the app upload itself still succeeds.

### Other Fixes

- An app can no longer be given a dependency or supersedence on **itself**
- `-WhatIf` is genuinely read-only for relationship changes: no `updateRelationships` call is issued, and the script no longer reports a relationship as added during a preview run

---

## DelegatedImport Parity Enhancements (v1.93)

Version 1.93 brings the upload pipeline to feature parity with the long-running DelegatedImport tooling. It hardens every Graph and Azure Storage exchange against transient cloud failures so long-running uploads can survive token expiration, network blips, and stuck app states without operator intervention.

### Automatic 401 Token Refresh

`Invoke-GraphRequestWithRetry` now traps `HTTP 401 Unauthorized` responses, disconnects the current Graph session, re-authenticates using the connection parameters cached at sign-in (`$script:MgGraphConnectParams`), and retries the original request. Long-running uploads that outlive the access token continue without prompting the user.

### Expanded Transient Network Error Detection

The retry filter now matches a much wider set of HttpClient / SDK failure signatures, in addition to the existing `network`, `timeout`, and `connection` triggers:

- `forcibly closed`
- `Error while copying content to a stream`
- `ResponseEnded`
- `response ended prematurely`
- `ended prematurely`
- `request was canceled`
- `send the request`

Any match is treated as retryable with exponential backoff.

### Per-Chunk Transient HTTP 5xx Handling

`Send-FileToAzureStorage` retries each Azure Storage block upload up to **5 times** when it receives an `HTTP 500`, `502`, `503`, or `504`. The backoff between attempts is exponential (`10s × 2^(attempt-1)` → 10 s, 20 s, 40 s, 80 s, 160 s), giving Azure Storage a chance to recover from short-lived availability issues before the upload aborts.

### `Wait-AppPublishingState` Helper and Stuck App Recovery

After a failed upload attempt the script polls the app's `publishingState` via `Wait-AppPublishingState` (default 6 attempts × 10 s wait). If the app is stuck in `notPublished`, `Send-Win32Lob` deletes the stale `mobileApp` record, waits 5 seconds, recreates it, and retries the upload with a fresh app object. This automatically recovers from the long-standing "stuck app" failure mode where a partial commit prevents new content versions from being added.

### Escalating Upload Retry Backoff

When a full upload attempt fails, the delay before the next attempt now scales with the attempt number: `30 s × attempt` (30 s, 60 s, 90 s for the standard 3 attempts), replacing the previous flat 10 s wait. This gives Azure Storage and Intune service-side state more time to settle between retries.

### `OrigSource → Source` Robocopy Mirror

When a package folder contains both `OrigSource\` (the immutable golden copy) and `Source\` (the build staging folder), the script now mirrors `OrigSource\` into `Source\` at the start of every run:

```text
robocopy "<package>\OrigSource" "<package>\Source" /MIR /MT:4 /NJH /NJS /NP
```

`/MIR` removes any files in `Source\` that no longer exist in `OrigSource\` (no drift) and `/MT:4` parallelises the copy across 4 threads. The previous behaviour — silently using `OrigSource\` only when `Source\` was missing — is preserved as a fallback when no `Source\` folder exists.

---

## Corporate Proxy Support (v1.93)

The script now embeds the proxy module so a single set of switches (or env vars) routes **every** outbound HTTP/S call through a corporate proxy. The same configuration covers MSAL.NET token acquisition, the Microsoft.Graph SDK's `HttpClient`, the Azure Storage block-blob SAS upload path, the GitHub `IntuneWinAppUtil.exe` download, and any in-script `Invoke-WebRequest` / `Invoke-RestMethod` calls.

Proxy support is **fully opt-in**. When neither `-ProxyUri` nor `$env:INTUNEWIN_PROXY_URI` is set the script runs without any proxy plumbing and behaviour is unchanged from earlier versions.

### When To Use It

- Workstations or build agents that must reach `graph.microsoft.com` and `login.microsoftonline.com` via a corporate forward proxy.
- Environments where direct egress is firewalled and a single intercepting proxy holds the TLS-inspection certificate trust.
- CI/CD pipelines (Azure DevOps, GitHub Actions) that need the proxy applied without an interactive credential prompt.

### Activation Modes

| Mode                                     | How to enable                                                                                             | Credential source                                                                 |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **Explicit credential (prompt)**         | `-ProxyUri http://proxy.contoso.com:443`                                                                  | `Get-Credential` prompt — captured once and reused across MSAL / Graph / Storage. |
| **Explicit credential (silent)**         | `-ProxyUri … -ProxyCredential $cred`                                                                      | Pre-built `[PSCredential]` (build secret store, key vault, etc.).                 |
| **Windows-integrated (Kerberos / NTLM)** | `-ProxyUri … -ProxyUseDefaultCredentials` or `$env:INTUNEWIN_PROXY_USE_DEFAULT_CREDENTIALS=true`               | Caller's logon token — no prompt, no stored credential.                           |
| **Env-var only (zero CLI flags)**        | `setx INTUNEWIN_PROXY_URI http://proxy.contoso.com:443` (plus optionally `INTUNEWIN_PROXY_USE_DEFAULT_CREDENTIALS`) | Whichever credential mode the env vars resolve to.                                |

If `-ProxyUri` (or `$env:INTUNEWIN_PROXY_URI`) is supplied but no `-ProxyCredential` and no `-ProxyUseDefaultCredentials` are given, the script prompts **once** via `Get-Credential` and reuses the result for every downstream call. In a non-interactive host (Get-Credential unavailable) it gracefully falls back to Windows-integrated authentication and logs a warning.

### Auto-Fallback to Direct Connectivity

The main flow calls `Initialize-IntuneWinProxy -OnlyIfNeeded`, which **probes direct connectivity to Graph / Entra ID first** and only configures the proxy if the direct path fails. This means it is safe to permanently set `$env:INTUNEWIN_PROXY_URI` on a fleet of machines — those with direct egress will skip the proxy automatically and the log will read:

```text
Direct connectivity to Microsoft Graph / Entra ID OK - proxy not activated (auto-fallback).
```

### CI / Non-Interactive Detection

`Initialize-IntuneWinProxy` automatically detects CI hosts by inspecting `$env:TF_BUILD`, `$env:GITHUB_ACTIONS`, `$env:CI`, and `$env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI`. In a detected CI run, if a credential is required but neither `-ProxyCredential` nor `-ProxyUseDefaultCredentials` is supplied, the script throws a descriptive error instead of hanging at a credential prompt.

### What Gets Configured Under The Hood

- `System.Net.WebRequest.DefaultWebProxy` (covers MSAL.NET and most legacy .NET HTTP calls).
- `System.Net.Http.HttpClient.DefaultProxy` (PS 7+, covers the Microsoft.Graph SDK and modern `HttpClient` consumers).
- `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` environment variables for the current process (covers SDKs that read env vars rather than .NET defaults — including the Azure Storage block-blob upload path).
- Per-call splat fallback via `Add-IntuneWinProxyParameter` so `Invoke-WebRequest` / `Invoke-RestMethod` get `-Proxy` / `-ProxyCredential` / `-ProxyUseDefaultCredentials` injected when the .NET default proxy cannot be set (e.g., under PowerShell ConstrainedLanguage mode).

All previous proxy / env-var values are saved at activation and restored when the script ends.

### Bypass List

`-ProxyBypassList "*.contoso.com","*.local"` (or `$env:INTUNEWIN_PROXY_BYPASS="*.contoso.com;*.local"`) adds explicit hostname patterns that should skip the proxy. The proxy also bypasses local-name addresses by default; pass `-NoProxyBypassLocal` (or set `$env:INTUNEWIN_PROXY_BYPASS_ON_LOCAL=false`) to turn that off.

### Environment Variable Reference

| Env var                              | Maps to                          | Example                                 |
| ------------------------------------ | -------------------------------- | --------------------------------------- |
| `INTUNEWIN_PROXY_URI`                     | `-ProxyUri`                      | `http://proxy.contoso.com:443`          |
| `INTUNEWIN_PROXY_USE_DEFAULT_CREDENTIALS` | `-ProxyUseDefaultCredentials`    | `true` / `1` / `yes` / `on`             |
| `INTUNEWIN_PROXY_BYPASS`                  | `-ProxyBypassList`               | `*.contoso.com;*.local`                 |
| `INTUNEWIN_PROXY_BYPASS_ON_LOCAL`         | inverse of `-NoProxyBypassLocal` | `false` / `0` / `no` / `off` to disable |

### Diagnostic Mode — `-TestProxyConnectivity`

`-TestProxyConnectivity` is an alternate execution path. It does **not** upload, modify, or delete anything — it only runs a two-phase connectivity report and exits.

- **Phase 1 — Direct**: TCP-connect + HTTPS HEAD probe against `graph.microsoft.com:443` and `login.microsoftonline.com:443` with no proxy.
- **Phase 2 — Proxy** (only if `-ProxyUri` or `$env:INTUNEWIN_PROXY_URI` resolves): same endpoints with the proxy configuration applied.

The probe records per-endpoint TCP status, HTTPS status code, and round-trip durations. In proxy mode the raw TCP probe is reported as `SKIP` because HTTP `CONNECT` proxies cannot be traversed with a raw socket — the HTTPS probe is the meaningful test.

Exit codes:

| Code | Meaning                                                                |
| ---- | ---------------------------------------------------------------------- |
| `0`  | All probed endpoints reachable (direct, or via proxy if proxy was set) |
| `1`  | One or more endpoints unreachable                                      |
| `2`  | Initialisation error (invalid proxy URI, missing credential, etc.)     |

---

## Upload Resilience and Feature Parity (v1.92)

Version 1.92 focuses on making the Azure Storage upload pipeline robust against the most common cloud-side failure modes encountered in long-running, large-payload uploads.

### SAS Readiness Probing

Before chunked upload begins, `Send-FileToAzureStorage` issues a `GET ?comp=blocklist` against the supplied SAS URI to verify the token has propagated:

- **404 Not Found** → SAS is valid; the blob simply does not exist yet → proceed.
- **403 Forbidden** → SAS has not yet replicated → wait 10 s and probe again (up to 6 retries).
- Other responses → SAS treated as valid; upload proceeds.

This single change eliminates the most common class of upload failure where the first block PUT is rejected because the SAS token has not propagated to the target storage region.

### Per-Chunk Upload Retry with SAS Renewal

Each block upload is now retried **up to 5 times** (previously 3):

- `HTTP 403` → SAS token may have expired mid-upload → call `Update-AzureStorageUpload` to renew it, wait 5 s, retry.
- `HTTP 500 / 502 / 503 / 504` → exponential backoff (`10s × 2^attempt`), retry.

A background timer also proactively renews the SAS URI every ~7 minutes during long uploads to prevent expiry while chunks are still being written.

### File Commit Retry Loop

Calls to the `commit` endpoint sometimes fail with `HTTP 400` or "SAS request" errors when Azure Storage has not yet finalised the upload state. The commit is now retried **up to 6 times with a 15 s wait** between attempts, eliminating a common cause of "successful upload but failed commit" errors.

### Full Upload Attempt Retry with Fresh Content Versions

The entire upload is wrapped in a retry loop of **up to 3 attempts**, each one creating a brand new content version (`POST /contentVersions`) so it starts from a clean state. Combined with the stuck-app recovery introduced in v1.93, transient Azure-side failures rarely require manual restart.

### HTTP 412 Precondition Failed Is Now Retryable

`Invoke-GraphRequestWithRetry` treats `HTTP 412` as a retryable response (10 s delay, normal retry limit). 412s typically indicate a content-version optimistic-concurrency conflict that resolves on retry.

### Smart Logo Handling

| Capability              | Behaviour                                                                                                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Auto-detection**      | If `logoFile` is omitted from the config, the script scans the package folder root for the first `*.png` / `*.jpg` / `*.jpeg` file and uses it as the app icon.                |
| **MIME type detection** | Sets `image/jpeg` for `.jpg` / `.jpeg` files and `image/png` for `.png` files instead of hard-coding `image/png`.                                                              |
| **Persistence PATCH**   | After the content commit, the script issues a dedicated PATCH to set `largeIcon`, ensuring the logo survives content replacement on existing apps that previously had no icon. |

---

## App Deletion (v1.92)

The new `-DeleteApp` switch removes one or many Intune Win32 applications without any other side effects (no `.intunewin` build, no assignments, no scope-tag changes). It pairs with a new `-AppNameToDelete` parameter that accepts multiple names directly or via the pipeline.

### Parameter Reference

| Parameter          | Type     | Notes                                                                                                                                                   |
| ------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-DeleteApp`       | Switch   | Required to enter delete mode. Without it, `-AppNameToDelete` is ignored and the script behaves as an upload tool.                                      |
| `-AppNameToDelete` | String[] | One or more app display names to remove. Aliases: `DisplayName`, `Name`. Supports pipeline input.                                                       |
| `-PackagePath`     | String[] | Optional when `-AppNameToDelete` is supplied. When supplied alone, the `displayName` from the package's Config.json / Config.xml is used as the target. |
| `-WhatIf`          | Switch   | Preview which apps would be deleted without making changes (full `ShouldProcess` integration).                                                          |
| `-Confirm`         | Switch   | Prompt before each delete operation.                                                                                                                    |

### Behavior

- Each name is resolved to an app via `Get-IntuneAppByDisplayName` (filtered server-side on `displayName`).
- If the app does not exist, the operation returns `Status: NotFound` and continues with the next name (does not abort the batch).
- On failure, the operation returns `Status: Error` with the underlying Graph exception message.
- Each delete is wrapped in `ShouldProcess`, so `-WhatIf` previews and `-Confirm` prompts are honoured automatically.

### Examples

**Delete the app referenced by a package's config file:**

```powershell
.\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" `
    -PackagePath "C:\Packages\MyApp" -DeleteApp
```

**Delete a single named app (no package required):**

```powershell
.\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" `
    -DeleteApp -AppNameToDelete "Old LOB App"
```

**Delete several apps in one run:**

```powershell
.\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" `
    -DeleteApp -AppNameToDelete "Legacy App 1", "Legacy App 2", "Legacy App 3"
```

**Pipeline input:**

```powershell
"Old App A", "Old App B", "Old App C" |
    .\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" -DeleteApp
```

**Combine package + extra names:**

```powershell
.\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" `
    -PackagePath "C:\Packages\MyApp" `
    -DeleteApp -AppNameToDelete "Previous Version of MyApp"
```

**Preview without deleting:**

```powershell
.\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" `
    -DeleteApp -AppNameToDelete "ToBeRemoved" -WhatIf
```

---

## Config File Upload Parameters (v1.91)

Version 1.91 introduces the ability to specify upload parameters directly in Config.json or Config.xml files, reducing the number of command-line arguments needed.

### Parameter Precedence

When a parameter is specified in multiple places, the following precedence applies:

1. **Command-line** (highest priority) — always wins
2. **Config file** — used if not specified on the command line
3. **Default value** — used if not specified anywhere (only applies to `NewTagPath`, which defaults to `true`)

### NewTagPath Default Behavior

`-NewTagPath` is now **enabled by default**. The tagfile detection path uses `%PROGRAMDATA%\Microsoft\IntuneManagementExtension\Logs` so that tag files are captured during Intune diagnostic log collection. To revert to the legacy path (`%PROGRAMDATA%\Microsoft\IntuneApps\<PackageName>`), set `newTagPath` to `false` in your config file.

### Config.json Example with Upload Parameters

```json
{
  "appType": "PS1",
  "ruleType": "TAGFILE",
  "returnCodeType": "DEFAULT",
  "installExperience": "System",
  "packageName": "Install-MyApp",
  "displayName": "My Application",
  "description": "Application description",
  "publisher": "Contoso",
  "category": "Business",
  "entraGroupName": "App-MyApp-Install",
  "scopetag": "Production",

  "requiredEntraGroupName": ["Win-Devices-All", "CloudPC-Devices-All"],
  "availableEntraGroupName": "CloudPC-Users-All",
  "replaceExistingContent": true,
  "skipPackageRemoval": true,
  "newTagPath": true
}
```

### Config.xml Example with Upload Parameters

```xml
<IntuneWin_Settings>
    <!-- ... other settings ... -->
    <RequiredEntraGroupName>Win-Devices-All, CloudPC-Devices-All</RequiredEntraGroupName>
    <AvailableEntraGroupName>CloudPC-Users-All</AvailableEntraGroupName>
    <ReplaceExistingContent>true</ReplaceExistingContent>
    <SkipPackageRemoval>true</SkipPackageRemoval>
    <NewTagPath>true</NewTagPath>
</IntuneWin_Settings>
```

### Supported Upload Parameters in Config Files

| Parameter                 | Config.json Property                                | Config.xml Element                                      | Type                           |
| ------------------------- | --------------------------------------------------- | ------------------------------------------------------- | ------------------------------ |
| `-NewTagPath`             | `newTagPath`                                        | `<NewTagPath>`                                          | Boolean (default: `true`)      |
| `-RequiredAADGroupName`   | `requiredEntraGroupName` / `requiredAADGroupName`   | `<RequiredEntraGroupName>` / `<RequiredAADGroupName>`   | String/Array (comma-separated) |
| `-AvailableAADGroupName`  | `availableEntraGroupName` / `availableAADGroupName` | `<AvailableEntraGroupName>` / `<AvailableAADGroupName>` | String/Array (comma-separated) |
| `-UninstallAADGroupName`  | `uninstallEntraGroupName` / `uninstallAADGroupName` | `<UninstallEntraGroupName>` / `<UninstallAADGroupName>` | String/Array (comma-separated) |
| `-ReplaceExistingContent` | `replaceExistingContent`                            | `<ReplaceExistingContent>`                              | Boolean                        |
| `-SkipPackageRemoval`     | `skipPackageRemoval`                                | `<SkipPackageRemoval>`                                  | Boolean                        |

---

## Script Optimizations (v1.9)

Version 1.9 introduces significant internal optimizations to improve reliability, error handling, and maintainability.

### Automatic Graph API Retry Logic

The script now includes built-in retry logic for Microsoft Graph API calls via the `Invoke-GraphRequestWithRetry` helper function:

- **Throttling handling** - Automatically detects HTTP 429 responses and waits the appropriate time before retrying
- **Server error recovery** - Retries on 5xx server errors with exponential backoff
- **Network resilience** - Handles transient network issues gracefully
- **Configurable retries** - Default of 3 retry attempts with 2-second initial delay

### Enhanced Configuration Validation

The `Test-ConfigurationValidity` function provides centralized validation before processing:

- **AppType validation** - Ensures valid application types (MSI, EXE, PS1, Edge)
- **Path validation** - Verifies package paths exist before processing
- **Group name uniqueness** - Prevents duplicate group names across Required, Available, and Uninstall
- **Config file detection** - Checks for Config.json or Config.xml presence

### WhatIf Support

The script now fully supports the `-WhatIf` parameter to preview operations:

```powershell
# Preview what would happen without making changes
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com" -WhatIf
```

WhatIf mode shows:

- Applications that would be uploaded, updated, or deleted
- Entra ID groups that would be created
- Assignments that would be applied or cleared

### Improved Error Handling

Version 1.9 includes comprehensive error handling improvements:

- **Proper control flow** - Replaced improper `break` statements with appropriate `return` or `throw` statements
- **Consistent error patterns** - Standardized error handling across all functions
- **Better error messages** - More descriptive error information for troubleshooting
- **Graceful failure handling** - Script continues or exits appropriately based on error severity

---

## Automatic Tool Download and Update (v1.7)

Version 1.7 introduces automatic download and update functionality for `IntuneWinAppUtil.exe`. The script automatically manages the Microsoft Win32 Content Prep Tool, eliminating the need for manual downloads.

### Tool Download Process

1. **Tool Check**: When the script runs, it checks if `IntuneWinAppUtil.exe` exists at the expected location
2. **Auto-Download**: If the tool is not found, it is automatically downloaded from GitHub
3. **Version Check**: If the tool exists, the script queries the GitHub API to check for updates
4. **Auto-Update**: If a newer version is available on GitHub, it is automatically downloaded and replaces the old version
5. **User Notification**: The script provides clear feedback about the tool status:
   - Current local version
   - Whether an update is available
   - Download progress and success/failure status

### Tool Download Examples

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

### EXE Validation Examples

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

### Version Detection Process

1. **EXE files**: Uses `FileVersionInfo.GetVersionInfo()` to read `FileVersion` or `ProductVersion`
2. **MSI files**: Uses Windows Installer COM object to query `ProductVersion` from the database
3. **Version comparison**: Compares detected version with `displayVersion` in Config.xml/Config.json
4. **User prompt**: If versions differ, prompts user to accept the detected version (Y/N)
5. **30-second timeout**: Auto-selects based on context:
   - If config has a version → keeps config version
   - If config version is empty → uses detected version
6. **Config update**: Automatically updates the config file when user accepts or config is empty

### Version Detection Example

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

The script accepts either the short key (e.g., `v10_21H2`) **or** the full display name (e.g., `Windows 10 21H2`). Older releases (up to and including `v10_21H1`) use Graph's `minimumSupportedOperatingSystem` boolean property; releases `v10_21H2` and newer (all Windows 11 builds) use the newer `minimumSupportedWindowsRelease` string property automatically.

| Short Value | Full Display Name      | Graph Property Used                         |
| ----------- | ---------------------- | ------------------------------------------- |
| `v10_1507`  | Windows 10 1507        | `minimumSupportedOperatingSystem` (boolean) |
| `v10_1607`  | Windows 10 1607        | `minimumSupportedOperatingSystem` (boolean) |
| `v10_1703`  | Windows 10 1703        | `minimumSupportedOperatingSystem` (boolean) |
| `v10_1709`  | Windows 10 1709        | `minimumSupportedOperatingSystem` (boolean) |
| `v10_1803`  | Windows 10 1803        | `minimumSupportedOperatingSystem` (boolean) |
| `v10_1809`  | Windows 10 1809        | `minimumSupportedOperatingSystem` (boolean) |
| `v10_1903`  | Windows 10 1903 (19H1) | `minimumSupportedOperatingSystem` (boolean) |
| `v10_1909`  | Windows 10 1909 (19H2) | `minimumSupportedOperatingSystem` (boolean) |
| `v10_2004`  | Windows 10 2004 (20H1) | `minimumSupportedOperatingSystem` (boolean) |
| `v10_20H2`  | Windows 10 20H2        | `minimumSupportedOperatingSystem` (boolean) |
| `v10_21H1`  | Windows 10 21H1        | `minimumSupportedOperatingSystem` (boolean) |
| `v10_21H2`  | Windows 10 21H2        | `minimumSupportedWindowsRelease` (string)   |
| `v10_22H2`  | Windows 10 22H2        | `minimumSupportedWindowsRelease` (string)   |
| `v11_21H2`  | Windows 11 21H2        | `minimumSupportedWindowsRelease` (string)   |
| `v11_22H2`  | Windows 11 22H2        | `minimumSupportedWindowsRelease` (string)   |
| `v11_23H2`  | Windows 11 23H2        | `minimumSupportedWindowsRelease` (string)   |
| `v11_24H2`  | Windows 11 24H2        | `minimumSupportedWindowsRelease` (string)   |
| `v11_25H2`  | Windows 11 25H2        | `minimumSupportedWindowsRelease` (string)   |
| `v11_26H2`  | Windows 11 26H2        | `minimumSupportedWindowsRelease` (string)   |

> **Fallback behavior:** If a supplied value is not yet known to the Graph schema (for example a future Windows release the SDK has not learned about), the script logs a warning and falls back to **`v10_21H1`** so the upload still succeeds. Update the value once the newer release is recognised.

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

#### Different Types for Different Apps (v1.95)

The single `<DependencyType>` above applies to every app in the list. To give each app its own
type, use **either** of the following — both can be mixed with the shared-type form above.

**Option 1 — repeat the element pair.** Each `<Dependencies>` is matched with the
`<DependencyType>` in the same position:

```xml
<Dependencies>Application 1.0</Dependencies>
<DependencyType>autoInstall</DependencyType>
<Dependencies>Application 2.0</Dependencies>
<DependencyType>detect</DependencyType>
```

**Option 2 — inline `Name:Type`.** Uses the same convention as `CustomReturnCodes`, and is usually
the tidier option for longer lists:

```xml
<Dependencies>Application 1.0:autoInstall,Application 2.0:detect</Dependencies>
```

An inline type always wins over `<DependencyType>`, so you can set the common case once and
override only the exceptions:

```xml
<!-- Everything auto-installs except Application 3.0, which is only detected -->
<Dependencies>Application 1.0,Application 2.0,Application 3.0:detect</Dependencies>
<DependencyType>autoInstall</DependencyType>
```

**Config.json** supports the inline form too, plus an array of objects:

```json
{
  "dependencies": [
    { "name": "Application 1.0", "type": "autoInstall" },
    { "name": "Application 2.0", "type": "detect" }
  ]
}
```

> **Note:** Dependencies are processed after the app is created/uploaded. The target apps must already exist in Intune with matching display names.
>
> An app display name that itself contains a colon is safe — the text after the final colon is only
> treated as a type when it is exactly `autoInstall` or `detect`.
>
> Relationship creation was broken before v1.94 — see [Dependency and Supersedence Fixes (v1.94)](#dependency-and-supersedence-fixes-v194).

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

#### Different Types for Different Apps (v1.95)

Supersedence supports exactly the same per-app syntax as dependencies — repeat the element pair,
or use inline `Name:Type`:

```xml
<!-- Repeated pairs, matched by position -->
<Supersedence>Old App 1.0</Supersedence>
<SupersedenceType>update</SupersedenceType>
<Supersedence>Old App 2.0</Supersedence>
<SupersedenceType>replace</SupersedenceType>

<!-- Or inline, equivalent to the above -->
<Supersedence>Old App 1.0:update,Old App 2.0:replace</Supersedence>
```

```json
{
  "supersedence": [
    { "name": "Old App 1.0", "type": "update" },
    { "name": "Old App 2.0", "type": "replace" }
  ]
}
```

> **Note:** Supersedence relationships are processed after the app is created/uploaded. The superseded apps must already exist in Intune.
>
> Relationship creation was broken before v1.94 — see [Dependency and Supersedence Fixes (v1.94)](#dependency-and-supersedence-fixes-v194).

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

### Corporate Proxy

#### Upload Through a Corporate Proxy (Interactive Credential Prompt)

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -IntuneAdmin "admin@contoso.com" `
    -ProxyUri "http://proxy.contoso.com:443"
```

The script prompts once for the proxy credential and reuses it for MSAL, Graph SDK, Azure Storage upload, and the GitHub `IntuneWinAppUtil.exe` download.

#### Service-Principal Upload Through Proxy with Windows-Integrated Auth

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -ClientSecret "YourClientSecret" `
    -ProxyUri "http://proxy.contoso.com:443" `
    -ProxyUseDefaultCredentials
```

#### Env-Var-Only Proxy Configuration (No CLI Flags)

```powershell
[Environment]::SetEnvironmentVariable("INTUNEWIN_PROXY_URI", "http://proxy.contoso.com:443", "User")
[Environment]::SetEnvironmentVariable("INTUNEWIN_PROXY_USE_DEFAULT_CREDENTIALS", "true", "User")

.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -IntuneAdmin "admin@contoso.com"
```

Because `Initialize-IntuneWinProxy -OnlyIfNeeded` probes the direct path first, the proxy is only activated when direct Graph / Entra ID connectivity actually fails — safe to set globally on a mixed fleet.

#### Proxy Connectivity Diagnostic

```powershell
.\Upload-IntuneWin.ps1 -TestProxyConnectivity -ProxyUri "http://proxy.contoso.com:443"
```

Runs the direct-vs-proxy connectivity report against Graph and Entra ID. Exit code `0` = PASS, `1` = FAIL, `2` = init error. No upload or modification occurs.

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

### App Deletion Examples (v1.92)

#### Delete a Single App by Name

```powershell
.\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" `
    -DeleteApp -AppNameToDelete "Old LOB App"
```

#### Delete Multiple Apps in One Call

```powershell
.\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" `
    -DeleteApp -AppNameToDelete "Legacy App 1", "Legacy App 2", "Legacy App 3"
```

#### Delete via Pipeline Input

```powershell
"Old App A", "Old App B", "Old App C" |
    .\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" -DeleteApp
```

#### Delete the App Referenced by a Package's Config

```powershell
.\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" `
    -PackagePath "C:\Packages\MyApp" -DeleteApp
```

#### Preview Without Deleting (`-WhatIf`)

```powershell
.\Upload-IntuneWin.ps1 -IntuneAdmin "admin@contoso.com" `
    -DeleteApp -AppNameToDelete "ToBeRemoved" -WhatIf
```

### Complete Production Example

```powershell
.\Upload-IntuneWin.ps1 `
    -PackagePath "C:\Packages\Office365" `
    -ClientID "12345678-1234-1234-1234-123456789012" `
    -TenantID "87654321-4321-4321-4321-210987654321" `
    -ClientSecret $env:INTUNE_SECRET `
    -RequiredEntraGroupName "All-CloudPC-Devices" `
    -AvailableEntraGroupName "Office-SelfService" `
    -ScopeTagName "CloudPC-Apps" `
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

The "Allow available uninstall" option (`allowAvailableUninstall`) is set on every Win32 application at the app level. This allows users to:

- Install the app from the Company Portal (when assigned as Available)
- Uninstall the app from the Company Portal when they no longer need it

Providing users with self-service control over optional applications without requiring administrator intervention.

From **v1.92** the value is **configurable per app** via the `allowAvailableUninstall` property in `Config.json` / `Config.xml`:

| Value (case-insensitive)   | Result                |
| -------------------------- | --------------------- |
| `true`, `"true"`, `"yes"`  | Enabled               |
| `false`, `"false"`, `"no"` | Disabled              |
| Property omitted           | **Enabled (default)** |

Example (`Config.json`):

```json
{
  "displayName": "Internal Line-of-Business App",
  "allowAvailableUninstall": false
}
```

> **Note:** This is a property on the Win32 app itself, not on individual assignments. The setting enables uninstall capability for any "Available" assignments the app receives.

### Group Creation

If specified groups don't exist, the script will create them automatically as security groups in Entra ID.

---

## Scope Tag Configuration

### How Scope Tags Work

- Scope tags control which administrators can see and manage the application
- The `-ScopeTagName` parameter overrides any `ScopeTag` or `scopetag` setting in config files
- **Multiple scope tags are supported**: pass an array to `-ScopeTagName` or use a comma-separated string in the config file (e.g., `"scopeTag": "CloudPC-Apps, Production-Apps"`)
- If a scope tag doesn't exist in the tenant, it will be created automatically
- The supplied scope tag set replaces all existing tags on the app (including `Default`)

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

#### `(407) Proxy Authentication Required`

```text
Invoke-RestMethod : The remote server returned an error: (407) Proxy Authentication Required.
```

The machine is routing outbound traffic through a proxy that demands credentials, and the token
request to Entra ID never reaches Microsoft. From v1.95 the script detects this, retries once using
your Windows credentials, and — if that still fails — stops with guidance rather than continuing
with no token.

Run with an explicit proxy:

```powershell
# Windows-integrated (NTLM/Negotiate) proxy authentication
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ProxyUri 'http://your-proxy:8080' -ProxyUseDefaultCredentials

# Explicit proxy account
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -ProxyUri 'http://your-proxy:8080' -ProxyCredential (Get-Credential)
```

Or set it once for the session so every run picks it up:

```powershell
$env:INTUNEWIN_PROXY_URI = 'http://your-proxy:8080'
```

Confirm the proxy path before running a real upload — this reports direct vs proxied connectivity to
Graph and Entra ID and exits `0 = PASS`, `1 = FAIL`, `2 = init error`:

```powershell
.\Upload-IntuneWin.ps1 -TestProxyConnectivity -ProxyUri 'http://your-proxy:8080'
```

> **Before v1.95** this error was non-terminating: the run carried on with an empty token, threw two
> further binding errors, and still printed `Successfully authenticated to Microsoft Graph`. If you
> see that combination, you are on an older build — upgrade rather than chasing the binding errors,
> which are only symptoms.

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

**Script Version**: 1.93
**Last Updated**: March 2026
**Author**: Greg Nottage
