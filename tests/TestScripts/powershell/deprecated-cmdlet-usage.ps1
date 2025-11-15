# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for deprecated cmdlet usage violations
# These patterns represent legacy security improvements

# Violation 1: ConvertTo-SecureString with -AsPlainText
$password = "MyPassword123!"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force

# Violation 2: Using New-Object System.Net.WebClient
$webClient = New-Object System.Net.WebClient
$content = $webClient.DownloadString("https://example.com/data")

# Violation 3: New-Object for creating PSCredential
$username = "admin"
$password = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $password)

# Violation 4: Using WebClient to download files
$client = New-Object System.Net.WebClient
$client.DownloadFile("https://example.com/file.exe", "C:\temp\file.exe")

# Violation 5: Deprecated Invoke-WebRequest with -UseBasicParsing (pre-PowerShell 6)
Invoke-WebRequest -Uri "https://api.example.com" -UseBasicParsing

# Violation 6: Using New-Object for Stream operations
$stream = New-Object System.IO.StreamReader("C:\temp\file.txt")
$content = $stream.ReadToEnd()
$stream.Close()

# Violation 7: Deprecated Send-MailMessage cmdlet
Send-MailMessage -From "sender@example.com" -To "recipient@example.com" -Subject "Test" -SmtpServer "smtp.example.com"

# Violation 8: Using [Net.ServicePointManager]::SecurityProtocol with deprecated protocols
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3
$response = Invoke-WebRequest -Uri "https://example.com"

# Violation 9: Using deprecated TLS 1.0
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls

# Violation 10: New-Object for creating arrays
$array = New-Object System.Collections.ArrayList
$array.Add("item1")
$array.Add("item2")

# Violation 11: Using $env:TEMP or $env:TMP without validation
$tempFile = "$env:TEMP\sensitive-data.txt"
Set-Content -Path $tempFile -Value "Sensitive information"

# Violation 12: Deprecated [System.Web.Security.Membership]::GeneratePassword
Add-Type -AssemblyName System.Web
$generatedPassword = [System.Web.Security.Membership]::GeneratePassword(10, 2)

# Violation 13: Using ConvertFrom-SecureString without encryption key
$securePass = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$exportedPassword = ConvertFrom-SecureString $securePass
Set-Content -Path "C:\temp\exported-password.txt" -Value $exportedPassword

# Violation 14: Deprecated Out-Printer cmdlet (use Start-Process -Verb Print)
Get-Content "C:\temp\document.txt" | Out-Printer

# Violation 15: Using Read-Host for sensitive input without -AsSecureString
$userPassword = Read-Host "Enter your password"
$apiKey = Read-Host "Enter API key"

# Violation 16: New-WebServiceProxy (deprecated in favor of Invoke-RestMethod)
$proxy = New-WebServiceProxy -Uri "https://example.com/service.asmx?WSDL"
$result = $proxy.GetData()

# Violation 17: Using Export-Console (deprecated)
Export-Console -Path "C:\temp\console.psc1"

# Violation 18: Deprecated WMI cmdlets instead of CIM cmdlets
Get-WmiObject -Class Win32_Service
Set-WmiInstance -Class Win32_Service -Arguments @{Name="ServiceName"; StartMode="Automatic"}

# Violation 19: Using Invoke-Expression with user input
$command = Read-Host "Enter command"
Invoke-Expression $command

# Violation 20: Deprecated ConvertTo-Xml cmdlet attributes
$data = Get-Process | ConvertTo-Xml -As String

# Correct usage examples (should not trigger violations)
# Using Read-Host with -AsSecureString
$securePassword = Read-Host "Enter password" -AsSecureString

# Using modern Invoke-WebRequest (PowerShell 6+)
$response = Invoke-WebRequest -Uri "https://example.com"

# Using PSCredential constructor properly
$securePwd = Read-Host "Password" -AsSecureString
$credential = [PSCredential]::new("username", $securePwd)

# Using Invoke-RestMethod instead of WebClient
$data = Invoke-RestMethod -Uri "https://api.example.com/data" -Method Get

# Using proper TLS settings
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Using modern array syntax
$array = [System.Collections.Generic.List[string]]::new()
$array.Add("item1")
$array.Add("item2")

# Using Get-Content instead of Stream operations
$content = Get-Content -Path "C:\temp\file.txt" -Raw

# Using CIM cmdlets instead of WMI
Get-CimInstance -ClassName Win32_Service
Set-CimInstance -Query "SELECT * FROM Win32_Service WHERE Name='ServiceName'" -Property @{StartMode='Automatic'}

# Using proper temp directory with security
$tempPath = [System.IO.Path]::GetTempPath()
$secureTempFile = Join-Path $tempPath ([System.IO.Path]::GetRandomFileName())
Set-Content -Path $secureTempFile -Value "Data" -Force

# Using SecureString properly with encryption key
$key = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
$encryptedPassword = ConvertFrom-SecureString -SecureString $securePassword -Key $key

# Using proper mail sending (MailKit or Microsoft.Graph)
# Modern approach: Use Microsoft.Graph or MailKit libraries instead of Send-MailMessage
