# Test script with suppression comments
# This demonstrates the suppression feature

Write-Host "Testing PowerShield suppression system"

# Example 1: POWERSHIELD-SUPPRESS-NEXT with justification
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy system requirement for MD5 compatibility
$hash1 = Get-FileHash -Path "test.txt" -Algorithm MD5

# Example 2: Inline suppression
$password = "test123" # POWERSHIELD-SUPPRESS: CredentialExposure - Test credential for unit tests

# Example 3: Suppression with expiry date
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Temporary until migration complete (2025-12-31)
$hash2 = Get-FileHash -Path "file.txt" -Algorithm SHA1

# Example 4: Block suppression
# POWERSHIELD-SUPPRESS-START: CommandInjection - Validated input only from trusted admin console
$commands = @(
    "Get-Process",
    "Get-Service"
)
foreach ($cmd in $commands) {
    Invoke-Expression $cmd
}
# POWERSHIELD-SUPPRESS-END

# Example 5: Expired suppression (should still trigger warning)
# POWERSHIELD-SUPPRESS-NEXT: CertificateValidation - Dev environment only (2024-01-01)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Example 6: Violation without suppression (should be detected)
$unsuppressedHash = Get-FileHash -Path "data.bin" -Algorithm MD5

Write-Host "Test script completed"
