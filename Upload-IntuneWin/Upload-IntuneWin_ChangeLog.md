# Upload-IntuneWin.ps1 Change Log

<!-- TIP: In VS Code, press Ctrl+Shift+V to open the Markdown preview and render this document properly. -->

For detailed information about features and usage, refer to [Upload-IntuneWin_ReadMe.md](Upload-IntuneWin_ReadMe.md).

---

## Version 1.9 (December 2025)

### Graph API Retry Logic

- Added `Invoke-GraphRequestWithRetry` helper function for resilient API calls
- Automatic handling of HTTP 429 throttling responses with Retry-After header support
- Exponential backoff retry logic for server errors (5xx status codes)
- Network error detection and automatic retry for transient failures
- Configurable maximum retries (default: 3) and initial delay (default: 2 seconds)

### Configuration Validation

- Added `Test-ConfigurationValidity` helper function for centralized validation
- Validates AppType against allowed values (MSI, EXE, PS1, Edge)
- Validates package path existence before processing
- Checks for duplicate group names across Required, Available, and Uninstall assignments
- Verifies Config.json or Config.xml presence in package folder

### WhatIf Support

- Full `-WhatIf` parameter support for previewing operations
- Shows what applications would be uploaded, updated, or deleted
- Shows what Entra ID groups would be created
- Shows what assignments would be applied or cleared

### Error Handling Improvements

- Replaced improper `break` statements with appropriate `return` or `throw` throughout the script
- Standardized error handling patterns across all functions
- Improved error messages for better troubleshooting
- Proper control flow management in nested loops and switch statements

### Internal Optimizations

- Centralized Graph API request handling for consistency
- Reduced code duplication in error handling paths
- Better separation of concerns in helper functions

---

## Version 1.7 (December 2025)

### Automatic Tool Download and Update

- Added `Test-IntuneWinAppUtil` function to validate and update IntuneWinAppUtil.exe
- Automatic download from GitHub if IntuneWinAppUtil.exe is not present
- Automatic version checking and update if a newer version is available on GitHub
- Uses GitHub API to compare local file date with last commit date
- Provides clear user feedback about tool status, version, and updates

### EXE File Validation

- Added `Invoke-ExeValidation` function to validate installer file references
- Checks if the EXE file specified in `installCmdLine` exists in the Source folder
- Uses Levenshtein distance algorithm for fuzzy matching when file not found
- Added `Get-LevenshteinDistance` function for string similarity calculation
- Offers to update Config.xml/Config.json with corrected filename
- Added `Update-ConfigInstallCmdLine` function to update config files with corrected EXE names
- 30-second timeout with intelligent defaults

### Assignment Enhancements

- **Foreground delivery optimization**: All assignment types (Required, Available, Uninstall) now use foreground download priority for faster app delivery
- **Smart notification settings**: User notifications are now hidden by default for Required and Available assignments, but shown for Uninstall assignments
- Fixed exclusion assignment issue: Removed unsupported `settings` property from exclusion assignments (Graph API doesn't support settings for exclusion targets)

### Graph Connection Management

- Added `-DisconnectGraph` switch parameter to explicitly disconnect from Microsoft Graph
- When using `-IntuneAdmin`, Graph connection is now preserved by default for running multiple scripts
- Allows batch processing of multiple packages without re-authentication
- Connection is always disconnected for `ClientSecret` and `CertName` authentication methods

### Internal Improvements

- Renamed AAD variables and functions to Entra ID naming convention:
  - `New-AADGroup` → `New-EntraGroup`
  - `New-AADGroupMG` → `New-EntraGroupMG`
  - Internal variable naming updated for consistency
- Maintained backward compatibility with existing `-RequiredAADGroupName`, `-AvailableAADGroupName`, `-UninstallAADGroupName` parameters

---

## Version 1.6 (December 2025)

### Automatic Version Detection

- Added `Get-InstallerVersion` function to detect version from EXE files using FileVersionInfo
- Added `Get-InstallerVersion` function to detect version from MSI files using Windows Installer COM object
- Added `Update-ConfigFileVersion` function to update displayVersion in Config.xml or Config.json
- Added `Invoke-VersionCheck` function to compare detected version with config version
- Version prompt times out after 30 seconds with intelligent defaults
- Automatically updates config file when user accepts detected version or config version is empty

---

## Version 1.5 (July 2025)

### Extended Settings Support

- Added `isFeatured` setting to show app as featured in Company Portal
- Added `informationUrl` and `privacyInformationUrl` for app metadata
- Added `developer`, `owner`, and `notes` fields for app information
- Added `maxRunTimeInMinutes` to configure maximum install time (default 60)
- Added `deviceRestartBehavior` setting: `basedOnReturnCode`, `allow`, `suppress`, `force`

### System Requirements

- Added `minimumFreeDiskSpaceInMB` for disk space requirements
- Added `minimumMemoryInMB` for memory requirements
- Added `minimumNumberOfProcessors` for CPU count requirements
- Added `minimumCpuSpeedInMHz` for CPU speed requirements
- Added `allowedArchitectures` setting: x64, x86, arm, arm64 (comma-separated)
- Added `minimumSupportedOS` for Windows version requirements

### Dependencies & Supersedence

- Added `dependencies` setting to specify apps this app depends on
- Added `dependencyType` setting: `autoInstall` or `detect`
- Added `supersedence` setting to specify apps this app supersedes
- Added `supersedenceType` setting: `update` or `replace`
- Added `Set-IntuneAppDependency` function for creating dependency relationships
- Added `Set-IntuneAppSupersedence` function for creating supersedence relationships
- Added `Get-IntuneAppByDisplayName` function for resolving app names to IDs

### Return Codes

- Added `customReturnCodes` setting for custom return code handling
- Added `New-CustomReturnCode` function for creating return code objects
- Support for array or comma-separated `code:type` format

### Script Detection

- Added `detectionScriptFile` for PowerShell script-based detection
- Added `detectionScriptEnforceSignatureCheck` for signature validation
- Added `detectionScriptRunAs32Bit` for 32-bit script execution

### New Helper Functions

- Added `Get-MinimumOperatingSystemObject` for OS version requirements
- Added `New-RequirementRule` for file, registry, and script requirements
- Added `Get-JSONConfig` function for reading Config.json files

### Core Improvements

- Updated `GetWin32AppBody` function with extended settings support
- Updated `Upload-Win32Lob` function with extended parameters
- Updated `Build-IntuneAppPackage` to pass extended settings
- Enhanced `ReplaceExistingContent` section with extended PATCH calls

---

## Version 1.4 (June 2025)

### Content Replacement

- Added `-ReplaceExistingContent` switch to update IntuneWin content of existing apps
- Added `-ReplaceExistingAssignments` switch to clear and replace all assignments
- Added `Update-Win32LobContent` function for content-only updates
- Preserves all app configuration (assignments, detection rules, requirements) during content updates

### Authentication Improvements

- Added `Get-AuthenticatedUserInfo` function to retrieve user display name and UPN
- Enhanced description field to include uploader information for audit trail

### App Categories

- Added `Get-IntuneAppCategory` function to retrieve categories by name
- Added `Set-IntuneAppCategory` function to assign categories to apps
- Automatic category assignment during app creation

---

## Version 1.3 (May 2025)

### Scope Tags

- Added `-ScopeTagName` parameter for applying Intune scope tags
- Automatic scope tag creation if tag doesn't exist
- ScopeTag attribute support in Config.xml and Config.json

### Source Folder Flexibility

- Added support for `OrigSource/` folder as fallback when `Source/` doesn't exist
- Allows preservation of original source files separately from working copies

### Entra ID Naming

- Added `-RequiredEntraGroupName`, `-AvailableEntraGroupName`, `-UninstallEntraGroupName` aliases
- Added `entraGroupName` config property (preferred over `aadGroupName`)
- Maintained backward compatibility with AAD naming

---

## Version 1.2 (April 2025)

### Initial Features

- Core script functionality for creating and uploading Win32 app packages
- Support for MSI, EXE, PS1, and Edge application types
- Detection rules: TAGFILE, FILE, REGISTRY, MSI
- Interactive, certificate, and client secret authentication
- Entra ID group creation and assignment
- Required, Available, and Uninstall targeting
- "Allow available uninstall" enabled by default
- ESP/Core app designation via Config.json
- Automatic logo detection and addition
- Config.json and Config.xml support (JSON takes precedence)
- Detailed logging to local log file

---

## Migration Notes

### Upgrading from v1.2 to v1.5+

1. **No breaking changes** - All existing Config.xml and Config.json files remain compatible
2. **New settings are optional** - Extended settings only apply if specified
3. **Dependencies/Supersedence** - Referenced apps must exist in Intune before upload
4. **Custom return codes** - Use format `"3010:softReboot,1641:hardReboot"` or JSON array

### Upgrading from v1.5 to v1.6

1. **Version detection is automatic** - No config changes required
2. **Prompts for EXE/MSI only** - PS1 and Edge apps are not affected
3. **Config file updates** - If user accepts detected version, config file is modified automatically

### Upgrading from v1.6 to v1.7

1. **IntuneWinAppUtil.exe auto-download** - Tool is now automatically downloaded and updated from GitHub
2. **EXE validation is automatic** - Validates installer file exists in Source folder for EXE packages
3. **Graph connection preserved** - When using `-IntuneAdmin`, add `-DisconnectGraph` if you want to disconnect after each run
4. **Assignment behavior changes**:
   - Notifications now hidden for Required/Available assignments (previously always hidden)
   - Notifications shown for Uninstall assignments (new behavior)
   - Delivery optimization set to foreground for all assignment types
5. **No breaking changes** - All existing config files and parameters remain compatible

### Upgrading from v1.7 to v1.9

1. **No breaking changes** - All existing config files and parameters remain compatible
2. **Automatic retry logic** - Graph API calls now automatically retry on transient failures
3. **WhatIf support** - Use `-WhatIf` to preview operations before execution
4. **Improved reliability** - Better error handling throughout the script
5. **No action required** - All optimizations are internal improvements
