# Quick Start

<!-- TIP: In VS Code, press Ctrl+Shift+V to open the Markdown preview and render this document properly. -->

Package and upload your first Win32 app to Intune, start to finish.

New to this? Start here. By the end of this guide you will have taken a plain installer, wrapped it into an Intune package, and uploaded it — without needing to understand the whole tool.

Everything is driven by **one file you edit: `Config.xml`**. The script reads that file, builds the `.intunewin` package, and creates the app in Intune for you.

---

## Table of Contents

- [What you need first](#what-you-need-first)
- [The five-minute version](#the-five-minute-version)
- [Step 1: Copy the template](#step-1-copy-the-template)
- [Step 2: Drop your installer in](#step-2-drop-your-installer-in)
- [Step 3: Edit Config.xml](#step-3-edit-configxml)
- [Step 4: Run the script](#step-4-run-the-script)
- [Worked example: an EXE installer](#worked-example-an-exe-installer)
- [Worked example: an MSI installer](#worked-example-an-msi-installer)
- [Worked example: a PowerShell script app](#worked-example-a-powershell-script-app)
- [Choosing a detection rule](#choosing-a-detection-rule)
- [Assigning the app to groups](#assigning-the-app-to-groups)
- [Signing in](#signing-in)
- [Common mistakes](#common-mistakes)
- [What to read next](#what-to-read-next)

---

## What you need first

| You need | Notes |
| -------- | ----- |
| Windows with PowerShell 5.1 or PowerShell 7 | Both work. Nothing to install. |
| An installer file | An `.exe`, `.msi`, or a `.ps1` script |
| Permission to add apps in Intune | An account with the Intune Administrator role, or an app registration |

`IntuneWinAppUtil.exe` (Microsoft's packaging tool) is **downloaded automatically** the first time you run the script — you do not need to fetch it yourself.

---

## The five-minute version

If you just want the shape of it:

```powershell
# 1. Copy the template folder and rename it
Copy-Item ".\_Template\CopyMeAsStartingPointForNewPackages" ".\MyApp" -Recurse

# 2. Put your installer in .\MyApp\Source\

# 3. Edit .\MyApp\Config.xml  (four fields is usually enough)

# 4. Upload it
.\Upload-IntuneWin.ps1 -PackagePath ".\MyApp" -IntuneAdmin "admin@contoso.com"
```

That is the whole workflow. The rest of this guide explains each step properly.

---

## Step 1: Copy the template

The download includes a ready-made folder to copy:

```text
_Template\CopyMeAsStartingPointForNewPackages\
```

Copy it, and rename the copy to something meaningful — the folder name is yours to choose and does not have to match the app name:

```powershell
Copy-Item ".\_Template\CopyMeAsStartingPointForNewPackages" ".\7-Zip" -Recurse
```

You now have this:

```text
7-Zip\
├── Config.xml        <- the only file you must edit
├── MSLogo.png        <- optional icon shown in Company Portal
└── Source\           <- your installer goes in here
```

> **Why a `Source` folder?** Everything inside `Source` is compressed into the `.intunewin` package and delivered to the device. Anything outside it (like `Config.xml`) is used by the script but never shipped.

---

## Step 2: Drop your installer in

Put the installer — and anything it needs — into the `Source` folder:

```text
7-Zip\
├── Config.xml
└── Source\
    └── 7z2408-x64.msi
```

Multiple files are fine. If your installer needs a config file, a transform, or supporting binaries, put them all in `Source` together.

---

## Step 3: Edit Config.xml

Open `Config.xml`. It is heavily commented, and **most of it you can leave alone**. For a first app you normally only need these:

| Field | What to put | Example |
| ----- | ----------- | ------- |
| `AppType` | `MSI`, `EXE`, or `PS1` | `MSI` |
| `PackageName` | Your installer's filename **without the extension** | `7z2408-x64` |
| `displayName` | The name users and admins see in Intune | `7-Zip 24.08` |
| `displayVersion` | Version number | `24.08` |

For `EXE` apps you also need `installCmdLine` and `uninstallCmdLine`. For `MSI` these are generated for you.

Here is a minimal working `Config.xml` for an MSI:

```xml
<CONFIG>
    <Azure_Settings>
        <baseUrl>https://graph.microsoft.com/beta/deviceAppManagement/</baseUrl>
        <logRequestUris>$true</logRequestUris>
        <logHeaders>$false</logHeaders>
        <logContent>$true</logContent>
        <azureStorageUploadChunkSizeInMb>6</azureStorageUploadChunkSizeInMb>
        <sleep>5</sleep>
    </Azure_Settings>
    <IntuneWin_Settings>
        <AppType>MSI</AppType>
        <PackageName>7z2408-x64</PackageName>
        <displayName>7-Zip 24.08</displayName>
        <displayVersion>24.08</displayVersion>
        <Description>7-Zip file archiver</Description>
        <Publisher>Igor Pavlov</Publisher>
        <Category>Productivity</Category>
        <LogoFile>MSLogo.png</LogoFile>
        <InstallExperience>System</InstallExperience>
        <ReturnCodeType>DEFAULT</ReturnCodeType>
    </IntuneWin_Settings>
</CONFIG>
```

> **Leave `Azure_Settings` alone** unless you have a reason to change it, and never edit `ReturnCodeType`.

### Prefer JSON?

A `Config.json` works too, using the same names in camelCase. If both files exist, **`Config.json` wins**.

```json
{
  "appType": "MSI",
  "packageName": "7z2408-x64",
  "displayName": "7-Zip 24.08",
  "displayVersion": "24.08",
  "publisher": "Igor Pavlov"
}
```

---

## Step 4: Run the script

```powershell
.\Upload-IntuneWin.ps1 -PackagePath ".\7-Zip" -IntuneAdmin "admin@contoso.com"
```

The script will:

1. Download `IntuneWinAppUtil.exe` if it is missing
2. Compress `Source\` into a `.intunewin` package
3. Sign you in to Microsoft Graph
4. Create the app in Intune and upload the package
5. Apply the icon, detection rule and any group assignments
6. Delete the `.intunewin` file afterwards (keep it with `-SkipPackageRemoval`)

**Try it safely first.** Add `-WhatIf` to see exactly what would happen without changing anything in Intune:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath ".\7-Zip" -IntuneAdmin "admin@contoso.com" -WhatIf
```

---

## Worked example: an EXE installer

EXE apps need you to supply the install and uninstall command lines, because the script cannot infer them.

```text
NotepadPlusPlus\
├── Config.xml
└── Source\
    └── npp.8.6.9.Installer.x64.exe
```

```xml
<IntuneWin_Settings>
    <AppType>EXE</AppType>
    <PackageName>npp.8.6.9.Installer.x64</PackageName>
    <installCmdLine>npp.8.6.9.Installer.x64.exe /S</installCmdLine>
    <uninstallCmdLine>"C:\Program Files\Notepad++\uninstall.exe" /S</uninstallCmdLine>
    <displayName>Notepad++ 8.6.9</displayName>
    <displayVersion>8.6.9</displayVersion>
    <Publisher>Notepad++ Team</Publisher>
    <RuleType>FILE</RuleType>
    <FilePath>C:\Program Files\Notepad++\notepad++.exe</FilePath>
    <FileDetectionType>exists</FileDetectionType>
    <InstallExperience>System</InstallExperience>
    <ReturnCodeType>DEFAULT</ReturnCodeType>
</IntuneWin_Settings>
```

Note the silent-install switch (`/S` here). Every installer is different — check the vendor's documentation. Without it, the install will hang waiting for a click that nobody can make.

---

## Worked example: an MSI installer

MSI is the easiest case. The script reads the product code and version straight out of the MSI, and builds the detection rule for you.

```xml
<IntuneWin_Settings>
    <AppType>MSI</AppType>
    <PackageName>7z2408-x64</PackageName>
    <displayName>7-Zip 24.08</displayName>
    <Publisher>Igor Pavlov</Publisher>
    <InstallExperience>System</InstallExperience>
    <ReturnCodeType>DEFAULT</ReturnCodeType>
</IntuneWin_Settings>
```

You can leave `displayVersion` out — it is detected from the MSI and you will be asked to confirm it.

`RuleType` is ignored for MSI apps; MSI product-code detection is always used.

---

## Worked example: a PowerShell script app

Use `PS1` when there is no installer — you are running a script to make a change.

```text
Set-CorporateWallpaper\
├── Config.xml
└── Source\
    └── Set-CorporateWallpaper.ps1
```

```xml
<IntuneWin_Settings>
    <AppType>PS1</AppType>
    <PackageName>Set-CorporateWallpaper</PackageName>
    <displayName>Corporate Wallpaper</displayName>
    <displayVersion>1.0</displayVersion>
    <RuleType>TAGFILE</RuleType>
    <InstallExperience>System</InstallExperience>
    <ReturnCodeType>DEFAULT</ReturnCodeType>
</IntuneWin_Settings>
```

`TAGFILE` detection means the script writes a marker when it finishes, and Intune looks for that marker. It saves you inventing a detection rule for something that does not install a file.

---

## Choosing a detection rule

Intune needs a way to tell whether the app is already installed. Pick whichever is easiest to describe:

| `RuleType` | Use when | You must also set |
| ---------- | -------- | ----------------- |
| `MSI` | The app is an MSI | Nothing — automatic |
| `FILE` | Installation leaves a known file or folder | `FilePath`, `FileDetectionType` |
| `REGISTRY` | Installation leaves a known registry value | `RegistryKeyPath`, `RegistryValue`, `RegistryDetectionType` |
| `TAGFILE` | Nothing reliable to detect, typically a `PS1` app | Nothing |

`FileDetectionType` and `RegistryDetectionType` accept `exists` or `doesNotExist` on their own. For anything else — comparing a version, a size, a date — you must also supply the matching `...DetectionOperator` and `...DetectionValue`.

```xml
<!-- Detect a specific version or newer -->
<RuleType>FILE</RuleType>
<FilePath>C:\Program Files\Contoso\App\app.exe</FilePath>
<FileDetectionType>version</FileDetectionType>
<FileDetectionOperator>greaterThanOrEqual</FileDetectionOperator>
<FileDetectionValue>3.1.0.0</FileDetectionValue>
```

---

## Assigning the app to groups

Add the group names to `Config.xml` and the assignments are created for you:

```xml
<RequiredEntraGroupName>Win-Devices-All</RequiredEntraGroupName>
<AvailableEntraGroupName>App-Users-SelfService</AvailableEntraGroupName>
```

Separate multiple groups with commas. Or pass them on the command line, which overrides the file:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath ".\7-Zip" -IntuneAdmin "admin@contoso.com" `
    -RequiredAADGroupName "Win-Devices-All"
```

To upload without any assignment at all, use `-SkipGroupAssignment`.

| Intent | Meaning |
| ------ | ------- |
| Required | Installed automatically |
| Available | Appears in Company Portal for users to install themselves |
| Uninstall | Removed from targeted devices |

---

## Signing in

For a first run, signing in as yourself is simplest:

```powershell
.\Upload-IntuneWin.ps1 -PackagePath ".\7-Zip" -IntuneAdmin "admin@contoso.com"
```

The connection is kept between runs, so uploading several apps only prompts once.

For unattended or scheduled runs, use an app registration. The secret never has to appear on the command line:

```powershell
# Store the secret once, encrypted, on this machine
.\Upload-IntuneWin.ps1 -ProtectSecret -ClientSecretFile "C:\Secure\app.dpapi"

# Then use it
.\Upload-IntuneWin.ps1 -PackagePath ".\7-Zip" `
    -ClientID "<app-guid>" -TenantID "<tenant-guid>" `
    -ClientSecretFile "C:\Secure\app.dpapi"
```

Azure Key Vault and certificate authentication are also supported. See [Secure Client Secret Sources](Upload-IntuneWin_ReadMe.html#secure-client-secret-sources-v197).

Behind a corporate proxy, add `-ProxyUri` and test it first with `-TestProxyConnectivity`.

---

## Common mistakes

| Symptom | Cause | Fix |
| ------- | ----- | --- |
| Install hangs forever on the device | No silent switch in `installCmdLine` | Add the vendor's silent flag (`/S`, `/quiet`, `/silent`) |
| "PackageName not found" | `PackageName` includes the file extension | Remove `.exe` / `.msi` — use the name only |
| App uploads but never shows as installed | Detection rule does not match reality | Check the path or registry value exists on a test device after install |
| Nothing is uploaded | `-IntuneWinPackageOnly` was used | That switch builds the package without uploading |
| Config changes seem ignored | A `Config.json` exists alongside `Config.xml` | JSON wins — edit that one, or delete it |
| Sign-in prompt on a scheduled run | Interactive authentication | Use an app registration with `-ClientSecretFile` or `-KeyVaultName` |

Every run writes a log file next to the script. When something fails, the log usually names the reason directly.

---

## What to read next

| Guide | Covers |
| ----- | ------ |
| [Upload-IntuneWin documentation](Upload-IntuneWin_ReadMe.html) | Every parameter and configuration option in full |
| [Export-IntunePolicy documentation](Export-IntunePolicy_ReadMe.html) | Snapshotting existing Intune configuration to JSON |
| [Change log](Upload-IntuneWin_ChangeLog.html) | What changed in each release |

Useful things to explore once the basics work:

- **Dependencies and supersedence** — chain apps together, or replace an older package
- **PowerShell script installers** — use a script instead of a command line
- **Scope tags** — restrict visibility to a subset of administrators
- **`-ReplaceExistingContent`** — update the payload of an app that already exists
