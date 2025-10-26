# Test script with command injection violations

# Violation 1: Invoke-Expression with variable
$userInput = Read-Host "Enter command"
Invoke-Expression $userInput

# Violation 2: Using iex alias with variable
$command = "Get-Process"
iex $command

# Violation 3: Dynamic command execution
$scriptBlock = "Get-Service -Name $serviceName"
Invoke-Expression $scriptBlock

# Correct usage (should not trigger violation)
Invoke-Expression "Get-Date"  # Static string (still not great practice, but doesn't contain variables)
& { Get-Process }  # Using script block operator instead
