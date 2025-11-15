# Test script with credential exposure violations

# Violation 1: ConvertTo-SecureString with -AsPlainText
$password = ConvertTo-SecureString "MyPassword123!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("username", $password)

# Violation 2: Another plaintext password conversion
$dbPassword = ConvertTo-SecureString "DatabasePassword!" -AsPlainText -Force

# Violation 3: Hardcoded password in assignment
$apiKey = "my-secret-api-key-12345"
$apiPassword = "SuperSecretPassword123"

# Correct usage (should not trigger violation)
$securePassword = Read-Host "Enter password" -AsSecureString
$secureCred = Get-Credential -UserName "admin"
