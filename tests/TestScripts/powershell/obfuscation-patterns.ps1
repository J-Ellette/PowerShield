# PowerShield Test Script: PowerShell Obfuscation Detection
# This script contains intentional obfuscation patterns for testing Rule 47
# MITRE ATT&CK: T1027 (Obfuscated Files or Information), T1059.001 (PowerShell)

# Test 1: Base64 encoded command (Critical)
powershell.exe -EncodedCommand "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"

# Test 2: Base64 decoding (High)
$encoded = "SGVsbG8gV29ybGQ="
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))

# Test 3: Excessive string concatenation (High)
$cmd = "I" + "n" + "v" + "o" + "k" + "e" + "-" + "E" + "x" + "p" + "r" + "e" + "s" + "s" + "i" + "o" + "n"

# Test 4: Character code conversion (High)
$str = [char]73 + [char]69 + [char]88 + [char]32 + [char]40 + [char]78 + [char]101 + [char]119

# Test 5: Format string obfuscation (High)
$template = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}"
$parts = 'I','n','v','o','k','e','-','W','e','b','Request'
$command = $template -f $parts[0],$parts[1],$parts[2],$parts[3],$parts[4],$parts[5],$parts[6],$parts[7],$parts[8],$parts[9],$parts[10]

# Test 6: String reversal (High)
$reversed = "noisserpxE-ekovnI"
$actual = -join ($reversed.ToCharArray() | ForEach-Object { $_ })

# Test 7: Character array join (High)
$chars = [char[]]@(73, 69, 88)
$cmd = $chars -join ''

# Test 8: Multiple string replacements (Medium)
$obfuscated = "XnvXkXeYExpressXXn"
$clean = $obfuscated -replace 'X', '' -replace 'Y', '-' -replace 'n', 'io'

# Test 9: Combined obfuscation techniques (Critical)
$b64 = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
$decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64))
Invoke-Expression $decoded

# Test 10: -enc parameter (Critical)
powershell -enc "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEgAZQBsAGwAbwAiAA=="

# Test 11: Multiple char conversions in a loop (High)
$result = ""
66..90 | ForEach-Object {
    $result += [char]$_
}

# Test 12: Format operator with many placeholders (High)
$fmt = "The {0} {1} {2} {3} {4} {5} {6} jumped over"
$result = $fmt -f "quick","brown","fox","with","sharp","claws","and"

Write-Host "Obfuscation patterns test complete"
