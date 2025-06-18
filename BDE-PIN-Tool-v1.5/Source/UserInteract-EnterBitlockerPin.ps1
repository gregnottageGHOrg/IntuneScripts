Import-Module -Name "$PSScriptRoot\AutoItX\AutoItX"
While ($(Assert-AU3WinExists -Title "BitLocker" -Text "You are required") -ne 0) {
    Close-AU3Win -Title "BitLocker" -Text "You are required" -Force
}

<# Script Variables #>
$ValidationPinMinLength = 6 # Min Pin length

$EventLogName = "Bitlocker Setup"
$EventLogSource = "PS-Bitlocker-UserPrompt"

$RegistrySavePath = "HKCU:\Software\MCS\SetBitlocker"
$StringKeyName = "UserSecureString"
$SkipKeyName = "SkipImplement"

$RegistryFveLocation = "HKLM:\Software\Policies\Microsoft\FVE"

$ProgramFilesPathTail = "\MCS\BitlockerScripts"
$ForceScriptRootPath = "C:\Program Files"

$IgnoreUserNames = "defaultuser100000", "Administrator"


<# Announce Ourselves #>
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User Prompt Script Running!" -Id 100 -Category 0 -EntryType Information


Function FreqAnalysis( $numstr ) {
    $counts = @(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    #Write-Host "FreqAnalysis $numstr"

    for ( $i = 0; $i -lt $numstr.length; $i += 1) {
        $v1 = ([int] $numstr.substring($i, 1));

        $counts[$v1] += 1
    }

    $total = 0
    $average = $numstr.Length / $counts.Length

    for ( $i = 0; $i -lt $counts.length; $i += 1) {
        $dif = $counts[$i] - $average;
        $total += $dif * $dif
    }

    #Write-Host "Square $total"
    return $total
}

####################################################

Function IncSeq($numstr) {
    $max = 1
    $count = 1
    $last = [int] $numstr.substring(0, 1);

    for ( $i = 1; $i -lt $numstr.length; $i += 1) {
        $v1 = [int] $numstr.substring($i, 1);

        if ( ($v1 - $last) -ge -1 -and ($v1 - $last) -le 1 ) {
            $count ++
            if ( $count -gt $max ) {
                $max = $count;
            }
        }
        else {
            $count = 1
        }
        $last = $v1
    }

    return $max;
}

####################################################

Function RepeatedSeq( $numstr ) {
    $longest = $null;

    for ( $l = [int] ($numstr.length / 2); $l -gt 0; $l -= 1) {
        for ( $i = 0; $i -le $numstr.length - $l; $i += 1) {
            $v1 = $numstr.substring($i, $l);
            #            Write-Host "$l $v1 $numstr"

            for ( $j = $l; $j -le $numstr.length - $l; $j += 1) {
                if ( $i -ne $j ) {
                    $v2 = $numstr.substring($j, $l);
                    #                    Write-Host "$l $v1 $v2 $numstr"

                    if ( $v1 -eq $v2 ) {
                        #                        Write-Host "Found Longest Repeat $v1 in $numstr $i $j"
                        $longest = $v1
                        break;
                    }
                }
            }
            if ( $longest -ne $null ) {
                break;
            }
        }
        if ( $longest -ne $null ) {
            break;
        }
    }

    if ( $longest -eq $null ) {
        # Write-Host "No Longest String";
        return 0;
    }

    $count = 0
    for ( $i = 0; $i -le $numstr.length - $longest.length; $i += 1) {
        if ( $numstr.substring($i, $longest.length) -eq $longest ) {
            $count += 1
        }
    }

    #Write-Host "Longest String $longest $count";

    return $longest.length * $count;
}

####################################################

Function IsRandomEnough( $numstr ) {
    #     Write-Host "$numstr"

    $freq = FreqAnalysis( $numstr )

    #    Write-Host "$numstr $freq $longest"

    $longest = RepeatedSeq( $numstr )

    #    Write-Host "$numstr $freq $longest"

    $longestIncSeq = IncSeq( $numstr )

    #    Write-Host "$numstr $freq $longest $longestIncSeq"

    $OK = ""

    if ( $freq -gt 23 ) {
        $OK = "Frequency Analysis"
    }

    if ( $longest -gt 6 ) {
        if ( $OK.Length -gt 0 ) {
            $OK = $OK + " : "
        }
        $OK = $OK + "Repeated Strings"
    }

    if ( $longestIncSeq -gt 5 ) {
        if ( $OK.Length -gt 0 ) {
            $OK = $OK + " : "
        }
        $OK = $OK + "Repeating, Incrementing and Decrementing Sequences"
    }

    if ( $OK.Length -eq 0 ) {
        $OK = "OK"
    }
    $OK = $OK.Trim()

    Write-Host "$numstr $OK $freq $longest $longestIncSeq"

    return $OK
}

####################################################

<# Check if we are running as an ignored user #>
$WmiUsername = (Get-WmiObject -Class Win32_ComputerSystem).Username

foreach ($Username in $IgnoreUserNames) {
    if ($WmiUsername.Contains($Username)) {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Logged on user $Username is in the ignored users list, exiting") -Id 100 -Category 0 -EntryType Information
        Return
    }
}

<# Check the present Bitlocker state before running #>
$WmiSystemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive

$BitlockerSystemDrive = (Get-BitLockerVolume -MountPoint $WmiSystemDrive)

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Detected system drive $WmiSystemDrive is protected ? " + [bool]$BitlockerSystemDrive.ProtectionStatus )  -Id 100 -Category 0 -EntryType Information

$RegistryFveUseTpmPin = [int](Get-ItemProperty -Path $RegistryFveLocation -Name "UseTPMPIN").UseTpmPin

if ( ($RegistryFveUseTpmPin -eq 1) -or ($RegistryFveUseTpmPin -eq 2) ) { $RegistryPrebootPinRequired = $true } else { $RegistryPrebootPinRequired = $false }

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Registry settings require Pin? $RegistryPrebootPinRequired"  -Id 100 -Category 0 -EntryType Information

if (($BitlockerSystemDrive.ProtectionStatus -eq "On") -and ($BitlockerSystemDrive.KeyProtector.KeyProtectorType -Contains "TpmPin")) {
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker is enabled, and has a preboot PIN configured.  Prompt user."  -Id 100 -Category 0 -EntryType Information

    Add-Type -AssemblyName PresentationCore, PresentationFramework

    $msgBody = "Do you want to reset the BitLocker PIN?"
    $msgTitle = "Reset BitLocker PIN?"
    $msgButton = 'YesNo'
    $msgImage = 'Question'
    $Result = [System.Windows.MessageBox]::Show($msgBody, $msgTitle, $msgButton, $msgImage)
    #Write-Host "The user chose: $Result [" ($result).value__ "]"

    If (($result).value__ -eq '7') {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User selected not to reset the existing BitLocker PIN."  -Id 100 -Category 0 -EntryType Information
        # Check if the registry location exists
        if (!(Test-Path $RegistrySavePath)) {

            # Location Missing, Create It
            New-Item -Path $RegistrySavePath -Force

            # Create Value
            New-ItemProperty -Path $RegistrySavePath -Name $SkipKeyName -Value "1" -PropertyType String -Force

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created Skip Flag Registry Item" -Id 100 -Category 0 -EntryType Information

        }

        Return
    }
    Else {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User does want to reset the existing BitLocker PIN."  -Id 100 -Category 0 -EntryType Information

        # Remove skip Value
        Remove-ItemProperty -Path $RegistrySavePath -Name $SkipKeyName -Force

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Removed Skip Flag Registry Item" -Id 100 -Category 0 -EntryType Information
    }
}

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "BitLocker requires configuration, continuing"  -Id 100 -Category 0 -EntryType Information

<# Figure Out Where the Script Root Is #>
$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

# Create Source Path
If ($OSArchitecture -like '64*') { $ScriptRootLocation = "$env:ProgramFiles$ProgramFilesPathTail" } else { $ScriptRootLocation = "${env:ProgramFiles(x86)}$ProgramFilesPathTail" }
if ($ForceScriptRootPath) { $ScriptRootLocation = "$ForceScriptRootPath$ProgramFilesPathTail" }

# Does the path exist ?
if (!(Test-Path "$ScriptRootLocation\AES.key")) {
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message ("Could not find encryption key, check install directory. Exiting") -Id 100 -Category 0 -EntryType Information
    Return
}

<# Get the Key #>
$AesKey = Get-Content "$ScriptRootLocation\AES.key"

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Got AES Key" -Id 100 -Category 0 -EntryType Information

<# Check FVE in Registry #>

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Checking FVE Setttings In Registry" -Id 100 -Category 0 -EntryType Information

if ( Get-ItemProperty -Path $RegistryFveLocation -Name "MinimumPIN" -ErrorAction SilentlyContinue ) {
    $ValidationPinMinLength = [int](Get-ItemProperty -Path $RegistryFveLocation -Name "MinimumPIN").MinimumPin
}
else {
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Could not get MinimumPin from reg, defaulting to $ValidationPinMinLength" -Id 100 -Category 0 -EntryType Information
}

if ( Get-ItemProperty -Path $RegistryFveLocation -Name "UseEnhancedPin" -ErrorAction SilentlyContinue ) {

    if ((Get-ItemProperty -Path $RegistryFveLocation -Name "UseEnhancedPin").UseEnhancedPin -ne 0) {
        $ValidationEnhancedPinAllowed = $true
    }
    else {
        $ValidationEnhancedPinAllowed = $false
    }

}
else {
    $ValidationEnhancedPinAllowed = $false
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Could not get UseEnhancedPin from reg, defaulting to disallowed" -Id 100 -Category 0 -EntryType Information

}

<# Event Log #>
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "FVE Checks Done, Got MinPin $ValidationPinMinLength and Enhanced is $ValidationEnhancedPinAllowed" -Id 100 -Category 0 -EntryType Information

#Region Form
<# Build Form #>

# Bring in the Windows Forms Library
Add-Type -assembly System.Windows.Forms

# Generate the form
$Form = New-Object System.Windows.Forms.Form

# Window Font
$Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)

# Font styles are: Regular, Bold, Italic, Underline, Strikeout
$Form.Font = $Font

# Window Basics
$Form.Text = 'BitLocker - Set up a PIN'
$Form.Width = 600
$Form.Height = 500
$Form.AutoSize = $true
#$Form.AutoSize = $False
$Form.MinimizeBox = $False
$Form.MaximizeBox = $False
$Form.ControlBox = $True
$Form.WindowState = "Normal"
# Maximized, Minimized, Normal
$Form.SizeGripStyle = "Hide"
# Auto, Hide, Show
$Form.ShowInTaskbar = $False
$Form.Opacity = 1.0
# 1.0 is fully opaque; 0.0 is invisible
$Form.StartPosition = "CenterScreen"
$Form.TopMost = $True
# CenterScreen, Manual, WindowsDefaultLocation, WindowsDefaultBounds, CenterParent


<# Header Text #>

# Create the label
$lbl_HeaderText = New-Object System.Windows.Forms.Label

# Create Instruction String
$lbl_InstructionString = "You are required to set a pre-boot PIN for BitLocker.`nIt must be a minimum of $ValidationPinMinLength characters.`n"
if ($ValidationEnhancedPinAllowed) { $lbl_InstructionString += "It may contain any character `n" } else { $lbl_InstructionString += "It can only contain numbers.`n" }

# Label Basics
$lbl_HeaderText.Text = $lbl_InstructionString
$lbl_HeaderText.Location = New-Object System.Drawing.Point(10, 5)
$lbl_HeaderText.AutoSize = $true

# Add to form
$Form.Controls.Add($lbl_HeaderText)

# Create the label
$lbl_TxbHeader1 = New-Object System.Windows.Forms.Label

# Label Basics
$lbl_TxbHeader1.Text = "New PIN"
$lbl_TxbHeader1.Location = New-Object System.Drawing.Point(20, 110)
$lbl_TxbHeader1.AutoSize = $true

# Add to form
$Form.Controls.Add($lbl_TxbHeader1)

# Create the label
$lbl_TxbHeader2 = New-Object System.Windows.Forms.Label

# Label Basics
$lbl_TxbHeader2.Text = "Confirm PIN"
$lbl_TxbHeader2.Location = New-Object System.Drawing.Point(20, 220)
$lbl_TxbHeader2.AutoSize = $true

# Add to form
$Form.Controls.Add($lbl_TxbHeader2)

# Create the label
$lbl_FeedbackMsg = New-Object System.Windows.Forms.Label

# Label Basics
$lbl_FeedbackMsg.Text = "The provided PINs do not match"
$lbl_FeedbackMsg.ForeColor = "Red"
$lbl_FeedbackMsg.Location = New-Object System.Drawing.Point(20, 320)
$lbl_FeedbackMsg.AutoSize = $true
$lbl_FeedbackMsg.Visible = $false

# Add to form
$Form.Controls.Add($lbl_FeedbackMsg)

<# Text Boxes #>

# Create Pin Box 1
$txb_PinEnter1 = New-Object System.Windows.Forms.MaskedTextBox

# Set Params
$txb_PinEnter1.Width = 200
$txb_PinEnter1.Height = 50
$txb_PinEnter1.Location = New-Object System.Drawing.Point(20, 150)
$txb_PinEnter1.PasswordChar = '*'

# Add to Form
$Form.Controls.Add($txb_PinEnter1)

# Create Pin Box 2
$txb_PinEnter2 = New-Object System.Windows.Forms.MaskedTextBox

# Set Params
$txb_PinEnter2.Width = 200
$txb_PinEnter2.Height = 50
$txb_PinEnter2.Location = New-Object System.Drawing.Point(20, 260)
$txb_PinEnter2.PasswordChar = '*'

# Add to Form
$Form.Controls.Add($txb_PinEnter2)

<# Buttons #>

# Create a button
$btn_SavePin = New-Object System.Windows.Forms.Button

# Button basics
$btn_SavePin.Location = New-Object System.Drawing.Size(20, 380)
$btn_SavePin.Size = New-Object System.Drawing.Size(120, 30)
$btn_SavePin.Text = "Set PIN"

# Check for ENTER and ESC presses
$Form.KeyPreview = $True
$Form.Add_KeyDown({ if ($_.KeyCode -eq "Enter") {
            # if enter, perform click
            $btn_SavePin.PerformClick()
        }
    })
$Form.Add_KeyDown({ if ($_.KeyCode -eq "Escape") {
            # if escape, exit
            $Form.Close()
        }
    })

# Set Function Handler
$btn_SavePin.Add_Click({

        # Set Error Conditions
        $InputErrorPresent = $false
        $InputErrorMessage = "Unspecified input error."

        # Check if the PINS Match
        if ($txb_PinEnter1.Text -ne $txb_PinEnter2.Text) {
            # Set Error Conditions
            $InputErrorPresent = $true
            $InputErrorMessage = "Entered PINs do not match."

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User entered mismatched PINs" -Id 100 -Category 0 -EntryType Information
        }

        # Check if Min Length
        if (($txb_PinEnter1.Text.Length -lt $ValidationPinMinLength) -or ($txb_PinEnter2.Text.Length -lt $ValidationPinMinLength)) {
            # Set Error Conditions
            $InputErrorPresent = $true
            $InputErrorMessage = "PIN does not meet minimum length."

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User entered a short PIN" -Id 100 -Category 0 -EntryType Information
        }

        # Check if the PIN is numeric
        if (!($txb_PinEnter1.Text -match '^[0-9]+$')) {
            # Set Error Conditions
            $InputErrorPresent = $true
            $InputErrorMessage = "PIN must contain numbers only."

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User entered a non numeric PIN" -Id 100 -Category 0 -EntryType Information
        }

        If ((IsRandomEnough $txb_PinEnter1.Text) -ne "OK") {
            # Set Error Conditions
            $InputErrorPresent = $true
            $InputErrorMessage = "PIN does not meet complexity requirements."

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User entered a PIN that does not meet complexity requirements." -Id 100 -Category 0 -EntryType Information
        }

        # Check if the error flag has been set
        if ($InputErrorPresent) {
            # Set and show error
            $lbl_FeedbackMsg.Text = $InputErrorMessage
            $lbl_FeedbackMsg.Visible = $true

            #Return
            return

        }
        else {
            # Clear Error Message
            $lbl_FeedbackMsg.Visible = $false

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "User managed to enter a valid PIN" -Id 100 -Category 0 -EntryType Information

        }

        # PIN has been validated, convert to PT secure string
        $PinSecureString = $txb_PinEnter1.Text | ConvertTo-SecureString -AsPlainText  -Force | ConvertFrom-SecureString -Key $AesKey

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Converted PIN to SecureString" -Id 100 -Category 0 -EntryType Information

        # Check if the registry location exists
        if (!(Test-Path $RegistrySavePath)) {

            # Location Missing, Create It
            New-Item -Path $RegistrySavePath -Force

            Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Created Registry Item" -Id 100 -Category 0 -EntryType Information

        }

        # Create Value
        New-ItemProperty -Path $RegistrySavePath -Name $StringKeyName -Value $PinSecureString -PropertyType String -Force

        Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Setting Registry Value & Closing Form" -Id 150 -Category 0 -EntryType Information


        # Now Close the form
        $Form.Close()
    })

# Add to Form
$Form.Controls.Add($btn_SavePin)
#EndRegion Form

<# Show the Form #>
#$Env:BitLockerFormIsDisplayed = $true
Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Form On Screen" -Id 100 -Category 0 -EntryType Information
#Set-Content -Path "C:\Windows\Temp\BLForm.tag" -Value "Running..."
$Form.ShowDialog()

Write-EventLog -LogName $EventLogName -Source $EventLogSource -Message "Finished, Exiting..." -Id 100 -Category 0 -EntryType Information
