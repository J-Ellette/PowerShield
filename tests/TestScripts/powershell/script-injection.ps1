# Test script for script injection detection

# Violation 1: New-Module with scriptblock
$scriptBlock = { Get-Process }
New-Module -ScriptBlock $scriptBlock

# Violation 2: Add-Type with variable
$csharpCode = "public class Test {}"
Add-Type -TypeDefinition $csharpCode

# Violation 3: scriptblock::Create (constrained mode bypass)
$code = "Get-Process"
$sb = [scriptblock]::Create($code)

# Violation 4: Add-Type with expression
Add-Type -TypeDefinition (Get-Content "C:\code.cs" -Raw)

# Correct usage (should not trigger violations)
Add-Type -TypeDefinition "public class SafeClass { public string Name; }"
