# Test script with insecure hash algorithm violations

# Violation 1: Using MD5 with Get-FileHash (cryptographically weak)
$md5Hash = Get-FileHash -Path "C:\temp\file.txt" -Algorithm MD5

# Violation 2: Using SHA1 with Get-FileHash (deprecated)
$sha1Hash = Get-FileHash -Path "C:\temp\another.txt" -Algorithm SHA1

# Violation 3: Using MD5 .NET class directly
$md5 = [System.Security.Cryptography.MD5]::Create()
$hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("test"))

# Violation 4: SHA1 crypto service provider
$sha1Provider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
$sha1HashBytes = $sha1Provider.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("data"))

# Violation 5: Using RIPEMD160 (also insecure)
$ripemd = [System.Security.Cryptography.RIPEMD160]::Create()
$ripemdHash = $ripemd.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("test"))

# Correct usage examples (should not trigger violations)
$secureHash = Get-FileHash -Path "C:\temp\file.txt" -Algorithm SHA256
$anotherSecureHash = Get-FileHash -Path "C:\temp\file.txt" -Algorithm SHA512
