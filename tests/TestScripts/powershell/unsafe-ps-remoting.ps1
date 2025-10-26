# Test script for unsafe PS remoting detection

# Violation 1: Enable-PSRemoting with Force
Enable-PSRemoting -Force

# Violation 2: Enter-PSSession without SSL
Enter-PSSession -ComputerName Server01 -UseSSL:$false

# Violation 3: New-PSSession without SSL
$session = New-PSSession -ComputerName Server02 -UseSSL:$false

# Correct usage (should not trigger violations)
Enable-PSRemoting -SkipNetworkProfileCheck
$secureSession = New-PSSession -ComputerName Server01 -UseSSL
