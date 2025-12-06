# Upload-IntuneWin.ps1 Change Log

<!-- TIP: In VS Code, press Ctrl+Shift+V to open the Markdown preview and render this document properly. -->

For detailed information about features and usage, refer to [Upload-IntuneWin_ReadMe.md](Upload-IntuneWin_ReadMe.md).

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
