# Upload-IntuneWin.ps1 Change Log

<!-- TIP: In VS Code, press Ctrl+Shift+V to open the Markdown preview and render this document properly. -->

For detailed information about features and usage, refer to [Upload-IntuneWin_ReadMe.md](Upload-IntuneWin_ReadMe.md).

**Related guides:** [Quick Start](Upload-IntuneWin_QuickStart.html) · [Upload-IntuneWin](Upload-IntuneWin_ReadMe.html) · [Export-IntunePolicy](Export-IntunePolicy_ReadMe.html)

---

## Version 1.97 (August 2026)

### Caller-Supplied Authentication

The script can now run against a Graph token that something else acquired, so authentication, proxy negotiation and secret retrieval can live outside this script entirely. This makes it callable from an orchestrating script, a pipeline, or any host that already holds a token — a managed identity, a certificate flow, or a secret store.

| Parameter             | Type             | Purpose                                                         |
| --------------------- | ---------------- | --------------------------------------------------------------- |
| `-AccessToken`        | `[SecureString]` | Pre-acquired Graph access token. Aliases: `Token`, `GraphToken` |
| `-TokenRefreshScript` | `[ScriptBlock]`  | Invoked on HTTP 401 to obtain a fresh token                     |

`-AccessToken` takes precedence over `-IntuneAdmin`, `-CertName` and `-ClientSecret`, and is honoured by both the upload and the `-DeleteApp` paths.

Passing a token instead of `-ClientSecret` also keeps the secret off the command line, where it would otherwise be visible in the process list and shell history.

#### Surviving token expiry

Win32 uploads can outlast a token. Where `-TokenRefreshScript` is supplied, a 401 triggers the scriptblock, the returned token re-seeds the session, and the request retries — so a large package is not lost to expiry part-way through:

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
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" -AccessToken $token -TokenRefreshScript $getToken
```

The scriptblock may return either a `String` or a `SecureString`. If it returns nothing, or throws, the failure is logged and the run ends rather than retrying indefinitely.

Where `-AccessToken` is supplied **without** `-TokenRefreshScript`, an expired token ends the run with an actionable message. It deliberately never falls back to an interactive sign-in prompt, so an unattended run cannot hang waiting for input.

### Sanitised examples

Example group names, scope tags and proxy hostnames throughout the script and documentation were replaced with generic equivalents, so nothing in the published solution reflects any particular environment's naming.

### Secure Client Secret Sources

Three ways to supply the client secret without exposing it on the command line, where it would otherwise be visible in the process list and shell history. All are self-contained — no `Az` or `SecretManagement` modules — so the script remains a single file with one bundled dependency.

Precedence, highest first:

| Source               | Parameters                             | Secret on the machine?     |
| -------------------- | -------------------------------------- | -------------------------- |
| Azure Key Vault      | `-KeyVaultName`, `-KeyVaultSecretName` | No                         |
| DPAPI-protected file | `-ClientSecretFile`                    | Yes, encrypted             |
| Literal string       | `-ClientSecret`                        | No, but exposed on the CLI |

#### DPAPI-protected file

`-ProtectSecret` prompts for the secret, encrypts it with Windows DPAPI and writes it to `-ClientSecretFile`:

```powershell
.\Upload-IntuneWin.ps1 -ProtectSecret -ClientSecretFile "C:\Secure\app-secret.dpapi"
```

DPAPI binds the ciphertext to the **current user on the current machine**, so a file created interactively will not decrypt under a build agent's service account or on another host. Create it as the identity that runs the upload; on shared agents prefer Key Vault. A decryption failure reports the account and machine it is running as, rather than a generic error.

#### Azure Key Vault

Read over REST at `https://<vault>.vault.azure.net/secrets/<name>?api-version=7.4`, with `-KeyVaultAuth` selecting how the vault itself is authenticated:

- **`ManagedIdentity`** (default) — uses `IDENTITY_ENDPOINT` where present (App Service, Functions, Container Apps), otherwise IMDS at `169.254.169.254`. `-ManagedIdentityClientId` selects a user-assigned identity. The IMDS call deliberately bypasses any configured proxy, since routing a link-local address through a corporate proxy always fails.
- **`Certificate`** — signs an RS256 JWT client assertion (RFC 7523) with `-CertName`, for hosts outside Azure with no managed identity. No secret is needed in order to fetch the secret. The certificate is located in `CurrentUser\My` then `LocalMachine\My`, must have a private key, and is rejected if expired.

HTTP 403 from the vault is reported with the required permission named (`Key Vault Secrets User`), and 404 names the missing secret.

### Multi-Tenant Configuration File

Where apps are pushed to several tenants, each environment's IDs and secret source can now live in one file rather than being retyped on every run. The file holds one `<spn>` element per environment, identified by `<tenantname>`:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath "C:\Packages\MyApp" `
    -TenantConfigFile ".\tenants.xml" -EnvironmentName "Production"
```

| Parameter           | Aliases                     | Purpose                        |
| ------------------- | --------------------------- | ------------------------------ |
| `-TenantConfigFile` | `SpnFile`, `TenantConfig`   | Path to the configuration file |
| `-EnvironmentName`  | `TenantName`, `Environment` | Which `<spn>` entry to use     |

Each environment may use a **different** secret source — one on Key Vault, another on a DPAPI file, another on a certificate. Recognised elements are `tenantname`, `tenantid`, `clientid`, `certname`, `clientsecretfile`, `keyvaultname`, `keyvaultsecretname`, `keyvaultauth`, `managedidentityclientid`, `proxyserver` and `scopetag`.

Behaviour:

- **Explicit parameters always win** — anything passed on the command line overrides the file
- `-EnvironmentName` may be omitted when the file holds exactly one entry
- Omitting it with several entries errors and **lists the available names**, as does naming one that does not exist
- A missing file or malformed XML is reported immediately rather than failing later during authentication

#### Legacy `encrpytedsecret` values

Older SPN files encrypted the secret with an AES key derived from the `clientid` stored in plain text in the same file, so anyone holding the file can recover the secret offline. These files are still read for backwards compatibility, but every run prints a warning and points at `-ProtectSecret` for migration. Rotate any secret that has been stored this way.

### Documentation

A [Quick Start guide](Upload-IntuneWin_QuickStart.html) was added for people packaging their first app — it covers copying the template, editing `Config.xml`, and running the upload, with worked examples for MSI, EXE and PowerShell script apps.

`Export-IntunePolicy.ps1` ships alongside the upload script, with [its own guide](Export-IntunePolicy_ReadMe.html). It snapshots Intune configuration and assignments to JSON, and shares this script's authentication, proxy and secret handling — so one tenant configuration file drives both.

All four guides are self-contained HTML with a sidebar table of contents and cross-guide navigation, and are also provided as Markdown.

---

## Version 1.96 (August 2026)

### PowerShell Script Installer Type

Adds support for Intune's new Win32 app **Program** tab options `Installer type: PowerShell script` and `Uninstaller type: PowerShell script`, using the Graph beta `win32LobAppInstallPowerShellScript` / `win32LobAppUninstallPowerShellScript` resources.

Install and uninstall are configured independently, so every combination the portal offers is supported:

| Install      | Uninstall    | Configuration              |
| ------------ | ------------ | -------------------------- |
| Command line | Command line | Default — unchanged        |
| Script       | Command line | `InstallScriptFile` only   |
| Command line | Script       | `UninstallScriptFile` only |
| Script       | Script       | Both                       |

New configuration keys (`Config.xml`, with camelCase equivalents in `Config.json`):

| Key                                                                           | Default  | Description                                                      |
| ----------------------------------------------------------------------------- | -------- | ---------------------------------------------------------------- |
| `InstallScriptFile` / `UninstallScriptFile`                                   | *(none)* | Path to the `.ps1` — absolute, or relative to the package folder |
| `InstallScriptRunAs32Bit` / `UninstallScriptRunAs32Bit`                       | `false`  | Run the script in a 32-bit PowerShell host                       |
| `InstallScriptEnforceSignatureCheck` / `UninstallScriptEnforceSignatureCheck` | `false`  | Require the script to be signed                                  |

Implementation details:

- Scripts are uploaded to the app's **committed content version** (`POST .../contentVersions/{id}/scripts`) and then activated by pointing the app's `activeInstallScript` / `activeUninstallScript` at the returned script ID
- Because scripts belong to the content version rather than the app, they are **automatically re-applied whenever content is replaced** — a content update no longer silently drops them
- Where a script is configured, Intune ignores the matching command line. Graph still requires both command lines to be populated, so a placeholder is generated when only a script is supplied
- Script content is capped at **100 KB** by the service; oversized scripts are rejected locally before upload, reporting both the raw and base64 sizes
- `commitFailed` responses and upload failures raise an error rather than leaving the app half-configured
- `-WhatIf` previews the uploads without creating anything
- The `scripts` endpoint is attempted with the `microsoft.graph.win32LobApp` cast first (consistent with every other content-version call) and falls back to the documented uncast path, so it works whichever form the service accepts

---

## Version 1.95 (July 2026)

### Per-App Dependency and Supersedence Types

A single `<DependencyType>` previously governed the whole `<Dependencies>` list, so every app in a package shared one type. Repeating the element pair to get different types did not work — PowerShell's XML adapter returns repeated elements as an array, and the script cast that array to a single string, silently joining the app names with a space and producing lookups for apps that do not exist.

Each referenced app can now carry its own type. Three styles are supported and can be mixed:

- **Repeated element pairs**, matched by position — the form most people reach for first:

  ```xml
  <Dependencies>Application 1.0</Dependencies>
  <DependencyType>autoInstall</DependencyType>
  <Dependencies>Application 2.0</Dependencies>
  <DependencyType>detect</DependencyType>
  ```

- **Inline `Name:Type`**, using the same convention as `CustomReturnCodes`:

  ```xml
  <Dependencies>Application 1.0:autoInstall,Application 2.0:detect</Dependencies>
  ```

- **Shared type** — the original behaviour, unchanged, so existing configs keep working

An inline type always overrides the element type, so the common case can be set once with only the exceptions called out:

```xml
<Dependencies>Application 1.0,Application 2.0,Application 3.0:detect</Dependencies>
<DependencyType>autoInstall</DependencyType>
```

`<Supersedence>` / `<SupersedenceType>` accept exactly the same styles for `update` and `replace`. `Config.json` additionally accepts an array of objects — `[{ "name": "...", "type": "..." }]`.

Supporting details:

- A trailing `:suffix` is only treated as a type when it is genuinely one of the valid types, so app display names containing a colon are unaffected
- Types are normalised to their canonical casing before being sent to Graph, which rejects a mis-cased `dependencyType` / `supersedenceType`
- An invalid type logs a warning and falls back to the default (`autoInstall` / `update`) rather than failing the upload
- When the number of type elements does not match the number of list elements, types are applied by position and the mismatch is reported

### Proxy Authentication (HTTP 407) Handling

- **Failed token requests are now fatal.** The client-credentials token call was not error-handled, so a proxy returning `407 Proxy Authentication Required` left `$token` null, produced two further parameter-binding errors, and the script still printed `Successfully authenticated to Microsoft Graph` before continuing. The request is now wrapped, the returned token is validated, and any failure throws immediately
- **Automatic retry with Windows credentials.** On a `407` where no explicit `-ProxyUri` was supplied, the script attaches the caller's credentials to the system default proxy and retries once — this resolves the common NTLM/Negotiate corporate proxy without any parameter changes
- **Actionable guidance on failure.** If the retry does not succeed, the error names the exact switches to use (`-ProxyUri` with `-ProxyUseDefaultCredentials` or `-ProxyCredential`), the `$env:DMAC_PROXY_URI` alternative, and the `-TestProxyConnectivity` diagnostic
- Distinct token-endpoint failures are reported with their HTTP status instead of surfacing as downstream null-binding errors

---

## Version 1.94 (July 2026)

### Application Dependency and Supersedence Fixes

Dependencies and supersedence declared via `<Dependencies>` / `<Supersedence>` in `Config.xml` (or `dependencies` / `supersedence` in `Config.json`) were never applied to the uploaded app. Four separate defects were involved:

- **Parameter mismatch**: `Set-IntuneAppDependency` and `Set-IntuneAppSupersedence` were being called with `-SourceAppId` / `-TargetAppDisplayName`, but the functions declared `-ApplicationId` / `-DependencyAppId` / `-SupersededAppId`, so every call failed with a parameter-binding error. The call sites now use the canonical names, and the old names are retained as parameter **aliases** so either spelling binds correctly
- **Application name passed where an ID was required**: config supplies display names, but the Graph relationship payload needs an application ID. New `Resolve-IntuneAppReference` helper accepts either form — a GUID passes straight through, anything else is resolved via `Get-IntuneAppByDisplayName`, and an unresolvable name logs a warning and skips the relationship without posting
- **Unsupported Graph endpoint**: `POST /deviceAppManagement/mobileApps/{id}/relationships` is not supported for Win32 apps. Replaced with the `updateRelationships` action that the Intune portal itself uses
- **`@odata.type` annotation ordering**: the request body was built with an unordered hashtable, so `ConvertTo-Json` could emit `targetId` before `@odata.type`. Graph requires the annotation to be the **first** property of each relationship object and otherwise returns `HTTP 400 ModelValidationFailure` — *"The annotation 'odata.type' was found. This annotation is either not recognized or not expected at the current position."* The payload is now built with ordered dictionaries

### Relationship Merge Semantics

- **`updateRelationships` replaces the entire child relationship set**, so posting a single relationship silently discarded all the others. New `Set-IntuneAppRelationship` function reads the existing relationships, keeps only `targetType = 'child'` entries (`parent` entries are owned by the other app and must not be echoed back), merges in the requested relationship, and posts the complete set — adding a dependency no longer wipes supersedence, and vice versa

### Additional Hardening

- **Self-reference guard**: an application can no longer be given a dependency or supersedence on itself
- **OData single-quote escaping**: `Get-IntuneAppByDisplayName` now doubles embedded single quotes in the `$filter` string literal, so app names such as `Bob's App` produce a valid query instead of a malformed one
- **`-WhatIf` is now genuinely read-only** for relationship operations — no `updateRelationships` POST is issued, and the script no longer reports a dependency as "added successfully" during a preview run

---

## Version 1.93 (March 2026)

### DelegatedImport Feature Parity

- **Automatic 401 token refresh**: `Invoke-GraphRequestWithRetry` now traps `HTTP 401 Unauthorized`, disconnects the current Graph session, re-authenticates using the cached `$script:MgGraphConnectParams`, and retries the original request — long-running uploads survive access-token expiry without operator intervention
- **Expanded transient network error detection**: Retry filter now also matches `forcibly closed`, `Error while copying content to a stream`, `ResponseEnded`, `response ended prematurely`, `ended prematurely`, `request was canceled`, and `send the request` in addition to the existing `network` / `timeout` / `connection` triggers
- **Per-chunk HTTP 5xx backoff in Azure Storage upload**: `Send-FileToAzureStorage` retries each block PUT up to 5 times on `500` / `502` / `503` / `504` with exponential backoff (`10s × 2^(attempt-1)`)
- **`Wait-AppPublishingState` helper**: Polls an app's `publishingState` after upload (default 6 attempts × 10 s)
- **Stuck-app recovery**: If `Wait-AppPublishingState` confirms an app is stuck in `notPublished` after a failed upload, `Send-Win32Lob` deletes the stale `mobileApp` record, waits 5 seconds, recreates it, and retries the upload with a fresh app object
- **Escalating upload-attempt backoff**: Delay between full upload attempts is now `30 s × attempt` (30 s → 60 s → 90 s) instead of a flat 10 s
- **OrigSource → Source robocopy mirror**: When a package folder contains both `OrigSource\` and `Source\`, the script mirrors `OrigSource\` into `Source\` at the start of every run via `robocopy /MIR /MT:4 /NJH /NJS /NP` — eliminates drift while preserving the immutable golden copy

### Interactive Authentication via Custom App Registration

- **New parameter set** for interactive sign-in against a custom Entra ID app registration: supply `-IntuneAdmin` plus `-ClientID` (and optionally `-TenantID`) without `-ClientSecret` to use device-code / interactive auth with a tenant-specific app registration instead of the built-in Microsoft Graph PowerShell first-party app

### Corporate Proxy Support

- **Embedded DMAC proxy module** (no external dependency): seven internal helpers — `Test-DmacProxyEnabled`, `Get-DmacProxyConfiguration`, `Add-DmacProxyParameter`, `Set-DmacProxyConfiguration`, `Test-DmacGraphConnectivity`, `Initialize-DmacProxy`, `Invoke-DmacProxyTest` — drive a single proxy configuration across every outbound HTTP/S call (MSAL.NET, Microsoft.Graph SDK `HttpClient`, Azure Storage block-blob SAS upload, GitHub `IntuneWinAppUtil.exe` download, and in-script `Invoke-WebRequest` / `Invoke-RestMethod` calls)
- **Six new opt-in parameters**: `-ProxyUri` (aliases `Proxy` / `HttpsProxy`), `-ProxyCredential`, `-ProxyUseDefaultCredentials`, `-ProxyBypassList`, `-NoProxyBypassLocal`, and `-TestProxyConnectivity` (alternate diagnostic execution path)
- **Environment-variable fallbacks**: `$env:DMAC_PROXY_URI`, `$env:DMAC_PROXY_USE_DEFAULT_CREDENTIALS`, `$env:DMAC_PROXY_BYPASS` (semicolon-separated wildcards), `$env:DMAC_PROXY_BYPASS_ON_LOCAL` — allows zero-CLI-flag activation
- **Auto-fallback to direct**: main flow calls `Initialize-DmacProxy -OnlyIfNeeded`, which probes direct Graph / Entra ID connectivity first and only configures the proxy if direct fails — safe to set `$env:DMAC_PROXY_URI` globally on a mixed-egress fleet
- **Single-prompt credential reuse**: when `-ProxyUri` is set without a credential the script prompts once via `Get-Credential` and reuses the captured `[PSCredential]` for every downstream call; on a non-interactive host it gracefully falls back to Windows-integrated auth and logs a warning
- **CI / non-interactive detection**: auto-detects `$env:TF_BUILD`, `$env:GITHUB_ACTIONS`, `$env:CI`, and `$env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI` and throws a descriptive error rather than hanging on a credential prompt when a credential is required in a CI run
- **ConstrainedLanguage (CLM) fallback**: `Add-DmacProxyParameter` splats `-Proxy` / `-ProxyCredential` / `-ProxyUseDefaultCredentials` onto per-call `Invoke-WebRequest` / `Invoke-RestMethod` invocations when the .NET default proxy cannot be set under CLM
- **Configured layers**: `System.Net.WebRequest.DefaultWebProxy`, `System.Net.Http.HttpClient.DefaultProxy` (PS 7+), and `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` process env vars; all prior values are saved at activation and restored when the script ends
- **`-TestProxyConnectivity` diagnostic**: alternate execution path that runs a two-phase (direct, then proxy if configured) connectivity report against `graph.microsoft.com:443` and `login.microsoftonline.com:443`, prints a coloured per-endpoint table, and exits `0 = PASS`, `1 = FAIL`, `2 = init error`. TCP probe is reported as `SKIP` in proxy mode (raw TCP cannot traverse an HTTP `CONNECT` proxy)

### Documentation Fixes

- **Multiple categories now correctly documented**: the README previously claimed "Only the first category is currently sent to Graph" — corrected to reflect actual behaviour (the script loops over every comma-separated category and calls `Set-IntuneAppCategory` for each). No code change, doc-only correction

### Bundled Microsoft.Graph.Authentication Module Precedence

- **Bundled module takes precedence**: at startup the script looks for `<ScriptRoot>\Modules\Microsoft.Graph.Authentication` and, when present, prepends `<ScriptRoot>\Modules` to `$env:PSModulePath` so the bundled copy wins over any machine- or user-installed copy — the script now runs with **zero module installation** (mirrors the precedence model in `Invoke-DelegatedImport.ps1`)
- **Fail-closed Authenticode enforcement**: the prepend only happens when every `*.psm1` under the bundled folder has a `Valid` signature from a trusted publisher (default `CN=Microsoft Corporation`, `CN=Microsoft Code Signing`, `CN=Microsoft 3rd Party Application Component`, `CN=GitHub`). Any unsigned, invalid, or untrusted-publisher file skips the prepend (with a warning) and falls back to the installed copy — preventing a counterfeit module dropped into `Modules\` from exfiltrating Graph tokens
- **Configurable trust list**: override the trusted-publisher allow-list via `$env:DMAC_TRUSTED_PUBLISHERS` (semicolon-separated subject substrings)
- **Layered fallback**: if no bundled copy is trusted/available, the script falls back to an installed module, then to `<ScriptRoot>\Microsoft.Graph.Authentication`, then to `<ScriptRoot>\Modules\Microsoft.Graph.Authentication`, and finally exits with `Install-Module` guidance if none resolve

---

## Version 1.92 (March 2026)

### Upload Resilience

- **SAS readiness probing**: Before chunked upload begins, `Send-FileToAzureStorage` issues a `GET ?comp=blocklist` against the SAS URI to confirm token propagation. `403` triggers a 10 s wait and re-probe (up to 6 retries); `404` is treated as "blob does not exist yet — proceed"
- **Per-chunk upload retry × 5 with SAS renewal**: Each block PUT is retried up to 5 times. `HTTP 403` calls `Update-AzureStorageUpload` to renew the SAS token (also proactively renewed every ~7 minutes during long uploads). `HTTP 500 / 502 / 503 / 504` uses exponential backoff
- **File commit retry × 6**: Calls to the `commit` endpoint are retried up to 6 times with a 15 s wait when Azure Storage returns `HTTP 400` or "SAS request" errors
- **Full upload-attempt retry × 3 with fresh content versions**: Each attempt creates a brand-new `contentVersion` so it starts from a clean state
- **HTTP 412 Precondition Failed is now retryable**: `Invoke-GraphRequestWithRetry` treats `412` as a normal retry case (typically a content-version optimistic-concurrency conflict that resolves on retry)

### Smart Logo Handling

- **Auto-detection**: When `logoFile` is omitted from the config, the script picks the first `*.png` / `*.jpg` / `*.jpeg` file from the package folder root
- **MIME type detection**: Sets `image/jpeg` for `.jpg` / `.jpeg` and `image/png` for `.png` instead of hard-coding `image/png`
- **Persistence PATCH**: After content commit, a dedicated PATCH writes `largeIcon` so the logo survives content-replacement on existing apps that had no icon

### App Deletion

- **New `-DeleteApp` switch**: Removes one or more Win32 applications without building an `.intunewin`, applying assignments, or touching scope tags
- **New `-AppNameToDelete` parameter** (`String[]`, aliases `DisplayName` / `Name`): Accepts one or many app display names, including via pipeline input — `"App1","App2" | .\Upload-IntuneWin.ps1 -IntuneAdmin "…" -DeleteApp`
- **Combine with `-PackagePath`**: When `-PackagePath` is supplied alone, the `displayName` from the package's config file is used; when supplied together with `-AppNameToDelete`, the union is deleted
- **Full `ShouldProcess` integration**: `-WhatIf` previews the deletes; `-Confirm` prompts per app
- **Returns structured result per app**: `{ Status = Deleted | NotFound | Error; Message; AppId }` — failures do not abort the batch

### Configurable User Uninstall

- **New `allowAvailableUninstall` config property** (Config.json / Config.xml): Controls whether the Company Portal "Uninstall" button is exposed to users for available assignments. Accepts `true` / `false` / `yes` / `no` (defaults to `true`)

### Multi-Value Category and Scope Tag Parsing

- `category` and `scopetag` now accept comma-separated strings or JSON arrays in the config file (per existing schema conventions for assignment groups)

---

## Version 1.91 (March 2026)

### Config File Support for Upload Parameters

- **Assignment groups in config files**: `-RequiredAADGroupName` / `-RequiredEntraGroupName`, `-AvailableAADGroupName` / `-AvailableEntraGroupName`, and `-UninstallAADGroupName` / `-UninstallEntraGroupName` can now be specified in Config.json or Config.xml
  - Config.json supports both string (comma-separated) and array formats
  - Config.xml supports comma-separated values
  - Both formats support `EntraGroupName` (preferred) and `AADGroupName` (legacy) naming
- **Upload switches in config files**: `-ReplaceExistingContent`, `-SkipPackageRemoval`, and `-NewTagPath` can now be specified in Config.json or Config.xml
  - Accepts `true`/`false` or `yes`/`no` values (Config.json also accepts native booleans)
- **Precedence**: Command-line parameters always take precedence over config file values, which take precedence over defaults

### NewTagPath Enabled by Default

- `-NewTagPath` is now **enabled by default** — the tagfile detection path always uses `%PROGRAMDATA%\Microsoft\IntuneManagementExtension\Logs` unless explicitly overridden in the config file
- The `-NewTagPath` switch can still be specified on the command line for backward compatibility (no breaking change)
- Config files can set `newTagPath` to `false` to revert to the legacy path if needed

### Validation Improvements

- Targeting group overlap validation now runs **after** config file loading, so config-sourced group names are also validated against command-line group names

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

### Upgrading from v1.9 to v1.91

1. **NewTagPath now defaults to enabled** - The tagfile detection path now defaults to `%PROGRAMDATA%\Microsoft\IntuneManagementExtension\Logs` without needing to specify `-NewTagPath` on the command line. If you relied on the legacy path (`%PROGRAMDATA%\Microsoft\IntuneApps\<PackageName>`), set `newTagPath` to `false` in your config file.
2. **Config file upload parameters** - You can now move `-RequiredAADGroupName`, `-AvailableAADGroupName`, `-UninstallAADGroupName`, `-ReplaceExistingContent`, `-SkipPackageRemoval`, and `-NewTagPath` from the command line into Config.json or Config.xml for simpler automation scripts.
3. **No breaking changes** - All existing command-line usage remains fully compatible. Command-line parameters always take precedence over config file values.

### Upgrading from v1.91 to v1.92

1. **No breaking changes** - All existing config files and command-line parameters remain fully compatible.
2. **Upload resilience is automatic** - SAS readiness probing, per-chunk retry × 5, file-commit retry × 6, and full upload-attempt retry × 3 require no configuration. Long-running uploads previously prone to transient Azure Storage failures should now succeed without manual intervention.
3. **`allowAvailableUninstall` is opt-out** - Defaults to `true`, matching the previous behaviour. Set `allowAvailableUninstall` to `false` (or `no`) in Config.json / Config.xml to hide the Company Portal Uninstall button for available assignments of a specific app.
4. **New `-DeleteApp` mode** - Use `-DeleteApp` together with `-AppNameToDelete` (and/or `-PackagePath`) to remove apps without building or assigning anything. Always preview with `-WhatIf` first.
5. **Smart logo handling** - If you previously needed to set `logoFile` explicitly to a `.png` for the upload to succeed, you can now drop a `.png` / `.jpg` / `.jpeg` file in the package folder root and omit `logoFile`; the script auto-detects it and uses the correct MIME type.

### Upgrading from v1.92 to v1.93

1. **No breaking changes** - All existing config files and command-line parameters remain fully compatible.
2. **Long-running uploads survive token expiry** - The automatic 401 token refresh in `Invoke-GraphRequestWithRetry` removes the previous failure mode where uploads longer than the access-token lifetime aborted with a 401 partway through.
3. **Stuck apps now self-heal** - If an upload attempt fails and the app is left in `notPublished`, the script automatically deletes the stale `mobileApp` record, waits 5 seconds, recreates it, and retries the upload. No manual cleanup required.
4. **Robocopy of `OrigSource\` → `Source\`** - If your package folder contains both `OrigSource\` (immutable golden copy) and `Source\` (build staging folder), the script now mirrors `OrigSource\` into `Source\` at the start of every run using `robocopy /MIR /MT:4 /NJH /NJS /NP`. Files that exist in `Source\` but not in `OrigSource\` will be removed. If you intentionally place build artefacts in `Source\` that are not present in `OrigSource\`, either remove `OrigSource\` from the package or move those artefacts into `OrigSource\`.
5. **Custom-app-registration interactive auth** - You can now run interactive sign-in against a custom Entra ID app registration by supplying `-IntuneAdmin` plus `-ClientID` (and optionally `-TenantID`) without `-ClientSecret`. The previous `-IntuneAdmin`-only flow (built-in Microsoft Graph PowerShell app) continues to work unchanged.
6. **Corporate proxy support is opt-in** - When neither `-ProxyUri` nor `$env:DMAC_PROXY_URI` is set, the proxy layer is completely inactive and existing behaviour is unchanged. To activate, supply `-ProxyUri "http://proxy.contoso.com:443"` (or set `$env:DMAC_PROXY_URI`) and choose a credential mode: `-ProxyCredential`, `-ProxyUseDefaultCredentials`, or leave both unset to be prompted once. Direct connectivity is probed first via `-OnlyIfNeeded`, so the proxy is auto-skipped on machines with direct egress — it is safe to set the env var globally on a mixed-egress fleet. Use `-TestProxyConnectivity` to validate the proxy configuration without running an upload.
7. **Documentation correction — categories** - The README previously stated "Only the first category is currently sent to Graph"; this was incorrect. The script has always iterated every comma-separated category in the config file and called `Set-IntuneAppCategory` for each one. README updated accordingly.
8. **Bundled Microsoft.Graph.Authentication module** - You no longer need to `Install-Module Microsoft.Graph.Authentication`. Ship the script with its `Modules\Microsoft.Graph.Authentication` subfolder and the script prepends `Modules\` to `$env:PSModulePath` automatically, preferring the bundled (signed) copy. The prepend is fail-closed: if the bundled `*.psm1` files are unsigned or signed by an untrusted publisher, the script skips the bundled copy and falls back to an installed module. Installing the module remains fully supported and is used as the fallback. Override the trusted-publisher list with `$env:DMAC_TRUSTED_PUBLISHERS` if you re-sign the bundled module with your own certificate.
