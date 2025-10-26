# Test script for constrained mode compatibility detection

# Violation 1: Add-Type usage
Add-Type -TypeDefinition "public class MyClass { }"

# Violation 2: COM object creation
$excel = New-Object -ComObject Excel.Application

# Violation 3: Another COM object
$shell = New-Object -ComObject WScript.Shell

# Correct usage (these work in constrained mode)
$hashtable = @{}
$array = @()
$string = "test"
