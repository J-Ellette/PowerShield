# Test script for unsafe file inclusion detection

# Violation 1: Dot-sourcing from variable
$scriptPath = "C:\untrusted\script.ps1"
. $scriptPath

# Violation 2: Dot-sourcing with expression
. (Get-Item "C:\temp\script.ps1")

# Violation 3: Dot-sourcing with expandable string
$folder = "C:\scripts"
. "$folder\module.ps1"

# Correct usage (should not trigger violations)
. "C:\trusted\functions.ps1"
. .\LocalScript.ps1
