# Test script for RegistryCredentials rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Storing plaintext password in registry
Set-ItemProperty -Path "HKCU:\Software\MyApp\Config" -Name "Password" -Value "SuperSecret123!"

# ❌ VIOLATION: Storing API key in registry
New-ItemProperty -Path "HKLM:\SOFTWARE\MyCompany\API" -Name "APIKey" -Value "sk-1234567890abcdef" -PropertyType String

# ❌ VIOLATION: Storing connection string with credentials
$connString = "Server=db.company.com;Database=prod;User Id=admin;Password=P@ssw0rd;"
Set-ItemProperty -Path "HKCU:\Software\App\Database" -Name "ConnectionString" -Value $connString

# ❌ VIOLATION: Storing OAuth token
New-Item -Path "HKCU:\Software\MyApp\Auth" -Force
Set-ItemProperty -Path "HKCU:\Software\MyApp\Auth" -Name "AccessToken" -Value "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# ❌ VIOLATION: Storing certificate password
Set-ItemProperty -Path "HKLM:\SOFTWARE\Certificates\Config" -Name "CertPassword" -Value "CertPass123"

# ✅ SAFE: Storing non-sensitive configuration (should not be flagged)
Set-ItemProperty -Path "HKCU:\Software\MyApp\Settings" -Name "Theme" -Value "Dark"
Set-ItemProperty -Path "HKCU:\Software\MyApp\Settings" -Name "Language" -Value "en-US"
