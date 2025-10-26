# PowerShield Test Script: Credential Harvesting Detection
# This script contains intentional credential harvesting patterns for testing Rule 50
# MITRE ATT&CK: T1003 (OS Credential Dumping), T1555 (Credentials from Password Stores), T1552 (Unsecured Credentials)

# Test 1: Mimikatz keyword (Critical)
$mimikatzPath = "C:\Tools\mimikatz.exe"
$command = "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"

# Test 2: sekurlsa reference (Critical)
$cmd = "sekurlsa::logonpasswords"

# Test 3: Mimikatz golden ticket (Critical)
Invoke-Expression "kerberos::golden /user:admin /domain:example.com"

# Test 4: gentilkiwi reference (Critical)
$author = "gentilkiwi"
Write-Host "Tool by $author"

# Test 5: LSASS process dumping with Out-Minidump (Critical)
Get-Process lsass | Out-Minidump -DumpFilePath C:\Temp\lsass.dmp

# Test 6: procdump on lsass (Critical)
procdump.exe -ma lsass.exe lsass.dmp

# Test 7: rundll32 with MiniDumpWriteDump (Critical)
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full

# Test 8: Get-Process targeting lsass with export (Critical)
$lsass = Get-Process lsass
$lsass | Export-Clixml -Path C:\Temp\lsass.xml

# Test 9: Chrome Login Data access (High)
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
Copy-Item $chromePath "C:\Temp\stolen_passwords.db"

# Test 10: Firefox logins.json (High)
$firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
Get-ChildItem "$firefoxPath\*\logins.json"

# Test 11: Edge credentials (High)
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
if (Test-Path $edgePath) {
    Copy-Item $edgePath "C:\Temp\edge_creds.db"
}

# Test 12: Browser cookies theft (High)
$cookiesPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
Copy-Item $cookiesPath "C:\Temp\cookies.sqlite"

# Test 13: WiFi password extraction (High)
netsh wlan show profile name="NetworkName" key=clear

# Test 14: All WiFi profiles with keys (High)
netsh wlan export profile key=clear folder=C:\Temp

# Test 15: SAM registry hive dump (Critical)
reg save HKLM\SAM C:\Temp\sam.hive

# Test 16: SYSTEM hive dump (Critical)
reg save HKLM\SYSTEM C:\Temp\system.hive

# Test 17: SECURITY hive dump (Critical)
reg.exe save HKLM\SECURITY C:\Temp\security.hive

# Test 18: Multiple hive extraction (Critical)
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save

# Test 19: Credential Manager enumeration (High)
cmdkey /list

# Test 20: vaultcmd usage (High)
vaultcmd /listcreds:"Windows Credentials" /all

# Test 21: Windows Vault access (High)
$vaultPath = "$env:LOCALAPPDATA\Microsoft\Vault"
Get-ChildItem $vaultPath -Recurse

# Test 22: Credential Manager path (High)
$credPath = "$env:LOCALAPPDATA\Microsoft\Credentials"
Get-ChildItem $credPath

# Test 23: lsadump reference (Critical)
$dumpCmd = "lsadump::sam"

# Test 24: token elevation (Critical)
$elevate = "token::elevate"

# Test 25: LSASS reference in context (Critical)
$processName = "Local Security Authority Subsystem Service"
Write-Host "Accessing $processName"

Write-Host "Credential harvesting detection test complete"
