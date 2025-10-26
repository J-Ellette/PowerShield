# Test script with multiple types of violations

# Insecure hash algorithm
$hash = Get-FileHash -Path "file.txt" -Algorithm MD5

# Credential exposure
$pass = ConvertTo-SecureString "Password123" -AsPlainText -Force

# Command injection
$cmd = Read-Host "Command"
Invoke-Expression $cmd

# Certificate bypass
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# More violations
$apiKey = "hardcoded-api-key-secret"
$sha1Hash = Get-FileHash -Path "data.bin" -Algorithm SHA1

Write-Host "This script intentionally contains multiple security violations for testing purposes"
