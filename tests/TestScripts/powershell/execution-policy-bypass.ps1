# Test script for execution policy bypass detection

# Violation 1: Set-ExecutionPolicy with Unrestricted
Set-ExecutionPolicy Unrestricted -Scope CurrentUser

# Violation 2: Set-ExecutionPolicy with Bypass
Set-ExecutionPolicy Bypass -Force

# Violation 3: Command line bypass in string
$command = "powershell.exe -ExecutionPolicy Bypass -File malicious.ps1"

# Violation 4: Another command line bypass pattern
$cmd = "powershell -ExecutionPolicy Unrestricted -Command { Get-Process }"

# Correct usage (should not trigger violations)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
