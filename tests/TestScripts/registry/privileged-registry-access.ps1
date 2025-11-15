# Test script for PrivilegedRegistryAccess rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Accessing HKEY_LOCAL_MACHINE without need
Set-ItemProperty -Path "HKLM:\SOFTWARE\MyApp\Config" -Name "Setting" -Value "Value"

# ❌ VIOLATION: Modifying HKEY_CLASSES_ROOT
New-Item -Path "HKCR:\.customext" -Force
Set-ItemProperty -Path "HKCR:\.customext" -Name "(Default)" -Value "CustomFileType"

# ❌ VIOLATION: Accessing HKEY_USERS for other users
$userSID = "S-1-5-21-1234567890-1234567890-1234567890-1001"
Get-ItemProperty -Path "Registry::HKEY_USERS\$userSID\Software\Microsoft\Windows\CurrentVersion\Run"

# ❌ VIOLATION: Using New-PSDrive to access privileged registry paths
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
Get-ChildItem HKU:\

# ✅ SAFE: Accessing current user registry (should not be flagged)
$userSettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-ItemProperty -Path "HKCU:\Software\MyApp\UserPreferences" -Name "Option1" -Value "Enabled"
