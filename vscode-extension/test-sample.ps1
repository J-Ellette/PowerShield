# Sample PowerShell Script with Security Issues
# This file demonstrates the types of security violations PowerShield detects

# 1. Insecure Hash Algorithm (Critical)
$hash = [System.Security.Cryptography.MD5]::Create()
$data = [System.Text.Encoding]::UTF8.GetBytes("sensitive data")
$hashValue = $hash.ComputeHash($data)

# 2. Credential Exposure (Critical)
$username = "admin"
$password = ConvertTo-SecureString "MyPassword123!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $password)

# 3. Command Injection Risk (Critical)
$userInput = Read-Host "Enter command"
Invoke-Expression $userInput

# 4. Insecure HTTP Connection (High)
$response = Invoke-WebRequest -Uri "http://api.example.com/data" -Method GET

# 5. Certificate Validation Bypass (High)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# 6. Hardcoded Secret (High)
$apiKey = "sk-1234567890abcdef1234567890abcdef"
$connection = "Server=myserver;Database=mydb;User=sa;Password=P@ssw0rd123"

# 7. Execution Policy Bypass (Medium)
Set-ExecutionPolicy Bypass -Scope Process -Force

# 8. PowerShell Remoting without encryption (Medium)
$session = New-PSSession -ComputerName "server01" -UseSSL:$false

# EXPECTED DIAGNOSTICS:
# - Line 5: InsecureHashAlgorithms (Error) - MD5 usage detected
# - Line 11: CredentialExposure (Error) - Plaintext password in ConvertTo-SecureString
# - Line 16: CommandInjection (Error) - Unsafe Invoke-Expression usage
# - Line 19: InsecureHTTP (Warning) - HTTP instead of HTTPS
# - Line 22: CertificateValidation (Error) - Certificate validation bypass
# - Line 25: SecretExposure (Error) - Hardcoded API key pattern
# - Line 26: SecretExposure (Error) - Connection string with password
# - Line 29: ExecutionPolicyBypass (Warning) - Execution policy bypass
# - Line 32: UnsafePSRemoting (Warning) - PSRemoting without SSL

Write-Host "This script contains multiple security violations for testing purposes."
Write-Host "PowerShield will detect and highlight all of these issues in VS Code."
