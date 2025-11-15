# Test script for dangerous module import detection

# Violation 1: Import module from variable
$modulePath = "C:\temp\untrusted.psm1"
Import-Module $modulePath

# Violation 2: Import module with expression
Import-Module (Get-Item "C:\temp\module.psm1")

# Violation 3: Import module with expandable string
$folder = "C:\modules"
Import-Module "$folder\module.psm1"

# Correct usage (should not trigger violations)
Import-Module "C:\Program Files\PowerShell\Modules\TrustedModule"
Import-Module PSReadLine
