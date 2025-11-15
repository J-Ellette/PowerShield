# Test script for PowerShell web request security detection

# Violation 1: Invoke-WebRequest with SkipCertificateCheck
$response = Invoke-WebRequest -Uri "https://example.com" -SkipCertificateCheck

# Violation 2: Invoke-RestMethod with SkipCertCheck
$data = Invoke-RestMethod -Uri "https://api.example.com" -SkipCertCheck

# Violation 3: Another pattern
Invoke-WebRequest -Uri "https://untrusted.com" -SkipCertificateCheck

# Correct usage (should not trigger violations)
$response = Invoke-WebRequest -Uri "https://trusted.com"
$data = Invoke-RestMethod -Uri "https://api.trusted.com"
