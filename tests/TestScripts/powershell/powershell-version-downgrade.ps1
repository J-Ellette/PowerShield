# Test script for PowerShell version downgrade detection

# Violation 1: PowerShell v2 in command string
$command = "powershell.exe -version 2 -command malicious"

# Violation 2: PowerShell v2 without .exe
$cmd = "powershell -version 2 -file script.ps1"

# Violation 3: Start-Process with v2
Start-Process powershell.exe -ArgumentList "-version 2 -command Get-Process"

# Correct usage (should not trigger violations)
$command = "pwsh -version 7 -command Get-Process"
