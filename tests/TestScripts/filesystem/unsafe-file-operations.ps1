# Test script for UnsafeFileOperations rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Recursive deletion without confirmation
Remove-Item "C:\Data" -Recurse -Force

# ❌ VIOLATION: Deleting system files
Remove-Item "C:\Windows\System32\*.dll" -Force

# ❌ VIOLATION: Overwriting files without backup
$importantFile = "C:\Production\database.mdf"
"" | Out-File $importantFile -Force

# ❌ VIOLATION: Moving files to dangerous locations
Move-Item "C:\Temp\untrusted.exe" "C:\Windows\System32\" -Force

# ❌ VIOLATION: Copying with overwrite to sensitive location
Copy-Item ".\script.ps1" "C:\Windows\System32\WindowsPowerShell\v1.0\" -Force

# ✅ SAFE: Safe file operations with proper validation (should not be flagged)
$targetPath = "C:\UserData\Documents\backup.txt"
if (Test-Path $targetPath) {
    $confirm = Read-Host "File exists. Overwrite? (Y/N)"
    if ($confirm -eq "Y") {
        Copy-Item ".\data.txt" $targetPath
    }
}
