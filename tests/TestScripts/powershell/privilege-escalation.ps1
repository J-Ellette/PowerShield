# Test script for privilege escalation detection

# Violation 1: Start-Process with RunAs verb
Start-Process -FilePath "cmd.exe" -Verb RunAs

# Violation 2: Another RunAs pattern
Start-Process powershell.exe -Verb RunAs -ArgumentList "-File script.ps1"

# Correct usage (should not trigger violations)
Start-Process notepad.exe
Start-Process -FilePath "app.exe" -Verb Open
