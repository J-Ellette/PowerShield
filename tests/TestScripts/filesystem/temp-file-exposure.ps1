# Test script for TempFileExposure rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Creating temp file with sensitive data without cleanup
$tempFile = "C:\Windows\Temp\secret_data.txt"
"Password: Admin123!" | Out-File $tempFile

# ❌ VIOLATION: Using predictable temp file names
$logFile = "$env:TEMP\application_$(Get-Date -Format 'yyyyMMdd').log"
"Sensitive operation completed" | Add-Content $logFile

# ❌ VIOLATION: Creating temp file without secure permissions
$configTemp = Join-Path $env:TEMP "database_config.tmp"
@{Server="prod-db";Password="secret"} | ConvertTo-Json | Out-File $configTemp

# ❌ VIOLATION: Not cleaning up temp files with secrets
New-Item -Path "$env:TEMP\api_key.tmp" -ItemType File -Value "sk-1234567890abcdef"

# ✅ SAFE: Using proper temp file handling with cleanup (should not be flagged)
try {
    $secureTempFile = [System.IO.Path]::GetTempFileName()
    "Non-sensitive data" | Out-File $secureTempFile
    # Process file...
} finally {
    if (Test-Path $secureTempFile) {
        Remove-Item $secureTempFile -Force
    }
}
