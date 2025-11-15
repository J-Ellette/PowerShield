# AMSI Evasion Test Script
# This script contains intentional security violations for testing AMSI bypass detection
# Note: Uses safe patterns that trigger detection without actual malicious functionality

Write-Host "Testing AMSI Evasion Detection Patterns..."

# Pattern 1: Direct AMSI bypass via AmsiUtils (Critical) - Safe version
$SafeAmsiUtils = "System.Management.Automation.AmsiUtils"
$SafeAmsiField = "amsiInitFailed"

# Pattern 2: Reflection-based AMSI bypass (Critical) - Safe version  
$assembly = "System.Management.Automation.AmsiUtils"
$field = "amsiContext"

# Pattern 3: Assembly patching for AMSI bypass (Critical) - Safe version
$AmsiUtilsType = "System.Management.Automation.AmsiUtils"
$FieldName = "amsiInitFailed"

# Pattern 4: Obfuscated AMSI bypass (Critical) - Safe version
$amsiString = [char]65 + [char]109 + [char]115 + [char]105  # "Amsi"
$bypassCode = "management.automation"

# Alternative obfuscation - safe version
$obfuscatedString = "management.automation.amsi"

# Simulated bypass attempt - safe
$testString = "AmsiUtils" + "bypass"

Write-Host "AMSI Evasion patterns complete - all should be detected as Critical violations"