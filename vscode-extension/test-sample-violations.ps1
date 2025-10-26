# Sample PowerShell Script with Security Violations
# This file demonstrates various security issues that PowerShield can detect and fix

function Test-InsecureHash {
    <#
    .SYNOPSIS
    Example of insecure hash algorithm usage
    #>
    param(
        [string]$InputString
    )
    
    # VIOLATION: Using MD5 (insecure hash algorithm)
    $hash = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $hashBytes = $hash.ComputeHash($bytes)
    
    return [System.BitConverter]::ToString($hashBytes)
}

function Connect-WithPlainTextPassword {
    <#
    .SYNOPSIS
    Example of credential exposure
    #>
    
    # VIOLATION: Plain text password in code
    $username = "admin"
    $password = "MySecretPassword123!"
    
    # Insecure credential creation
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
    
    return $credential
}

function Invoke-UserCommand {
    <#
    .SYNOPSIS
    Example of command injection vulnerability
    #>
    param(
        [string]$UserInput
    )
    
    # VIOLATION: Using Invoke-Expression with user input
    # This allows arbitrary code execution
    Invoke-Expression $UserInput
}

function Get-WebContentInsecure {
    <#
    .SYNOPSIS
    Example of bypassing certificate validation
    #>
    param(
        [string]$Url
    )
    
    # VIOLATION: Bypassing SSL/TLS certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    
    $response = Invoke-WebRequest -Uri $Url
    
    return $response.Content
}

function Use-WeakEncryption {
    <#
    .SYNOPSIS
    Example of using deprecated cryptographic methods
    #>
    param(
        [string]$Data
    )
    
    # VIOLATION: Using SHA1 for hashing
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $hash = $sha1.ComputeHash($bytes)
    
    return [System.BitConverter]::ToString($hash)
}

# Main script execution with vulnerabilities
Write-Host "Running script with security violations..."

# Call vulnerable functions
$result1 = Test-InsecureHash -InputString "test data"
Write-Host "Hash: $result1"

$cred = Connect-WithPlainTextPassword
Write-Host "Credential: $($cred.UserName)"

# VIOLATION: Another plain text password example
$apiKey = "sk-1234567890abcdefghijklmnop"
Write-Host "API Key configured: $apiKey"

# More insecure practices
$connectionString = "Server=myServer;Database=myDB;User Id=sa;Password=Admin123!;"

Write-Host "Script complete (but very insecure!)"
