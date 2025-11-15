# Test script for PathTraversal rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Using ../ for directory traversal
$userInput = "../../etc/passwd"
Get-Content $userInput

# ❌ VIOLATION: Path traversal in file operations
$fileName = "..\..\..\Windows\System32\config\SAM"
Copy-Item $fileName "C:\Backup\"

# ❌ VIOLATION: Using absolute paths from user input without validation
$filePath = Read-Host "Enter file path"
Remove-Item $filePath -Force

# ❌ VIOLATION: Join-Path with unvalidated input
$basePath = "C:\Users\Public\Documents"
$userFile = "..\..\Administrator\Desktop\secrets.txt"
$fullPath = Join-Path $basePath $userFile
Get-Content $fullPath

# ✅ SAFE: Validating and constraining path (should not be flagged)
$allowedPath = "C:\AppData\UserFiles"
$requestedFile = "document.txt"
$safePath = Join-Path $allowedPath $requestedFile
if ($safePath.StartsWith($allowedPath)) {
    Get-Content $safePath
}
