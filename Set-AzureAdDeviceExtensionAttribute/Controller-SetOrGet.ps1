Set-Location -Path "$PSScriptRoot"

# To get extensionAttribute values for a single device
.\Get-AzureAdDeviceExtensionAttribute.ps1 -userName "upnhere" -DeviceName "devicenamehere"

# To get extensionAttribute values for devices in DeviceList.txt
.\Get-AzureAdDeviceExtensionAttribute.ps1 -userName "upnhere" -DeviceName (get-content .\DeviceList.txt)

# To set extensionAttribute values use the following for a single device
.\Set-AzureAdDeviceExtensionAttribute.ps1 -username "upnhere" -ExtensionAttributeNumber "extensionAttribute1" -AttributeValue "AttribHere" -DeviceName "devicenamehere"

# To set extensionAttribute values for multiple devices
.\Set-AzureAdDeviceExtensionAttribute.ps1 -username "upnhere" -ExtensionAttributeNumber "extensionAttribute1" -AttributeValue "AttribHere" -DeviceName (get-content .\DeviceList.txt)

# You can add values using the different extensionAttribute1-15 