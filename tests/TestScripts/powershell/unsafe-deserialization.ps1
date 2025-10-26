# Test script for unsafe deserialization detection

# Violation 1: Import-Clixml from variable
$untrustedPath = "C:\temp\data.xml"
$data = Import-Clixml -Path $untrustedPath

# Violation 2: Import-Clixml with subexpression
$obj = Import-Clixml -Path (Join-Path $env:TEMP "file.xml")

# Violation 3: ConvertFrom-Json with depth parameter
$json = '{"data": "value"}'
$object = ConvertFrom-Json -InputObject $json -Depth 100

# Correct usage (should not trigger violations)
$data = Import-Clixml -Path "C:\trusted\config.xml"
$obj = ConvertFrom-Json -InputObject '{"key": "value"}'
