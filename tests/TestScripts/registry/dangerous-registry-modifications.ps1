# Test script for DangerousRegistryMods rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Disabling Windows Defender
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1

# ❌ VIOLATION: Disabling UAC
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -PropertyType DWord -Force

# ❌ VIOLATION: Modifying startup registry keys
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MaliciousStartup" -Value "C:\Temp\malware.exe"

# ❌ VIOLATION: Disabling Windows Firewall
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "EnableFirewall" -Value 0

# ❌ VIOLATION: Modifying security policy registry
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0

# ✅ SAFE: Reading registry values (should not be flagged)
$winVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentVersion"
