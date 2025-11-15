# Enhanced PowerShell 2.0 Detection Test Script
# This script contains intentional security violations for testing PS 2.0 detection

Write-Host "Testing Enhanced PowerShell 2.0 Detection Patterns..."

# Pattern 1: Direct PowerShell 2.0 invocation (High)
powershell.exe -version 2 -command "Write-Host 'PS 2.0 execution'"
powershell -v 2 -c "Get-Process"

# Pattern 2: PowerShell ISE usage (High) 
powershell_ise.exe -file "script.ps1"
powershell_ise -command "Get-Date"

# Pattern 3: .NET Framework 2.0 specific calls (High)
$framework = "v2.0.50727"
$automationAssembly = "System.Management.Automation, Version=2.0.0.0"
$dotNet2Reference = ".NET Framework 2.0"

# Pattern 4: WMI-based PowerShell execution (High)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -version 2"
Get-WmiObject -Class Win32_Process | Where-Object {$_.CommandLine -like "*powershell*"}

# Pattern 5: Legacy cmdlet usage specific to PS 2.0 (Medium)
$secureString = ConvertTo-SecureString "password" -AsPlainText -Force
$webClient = New-Object System.Net.WebClient
Add-PSSnapin Microsoft.PowerShell.Core

# Additional PS 2.0 indicators
$PSVersionTable.PSVersion -lt [Version]"3.0"
$host.Version.Major -eq 2

# Process invocation with version downgrade
Start-Process -FilePath "powershell.exe" -ArgumentList "-version", "2", "-command", "Get-Date"

# Registry check for PS 2.0 engine
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" -Name "PowerShellVersion"

# Legacy syntax patterns
$object = New-Object -TypeName System.Collections.ArrayList
$webclient = New-Object System.Net.WebClient

Write-Host "Enhanced PowerShell 2.0 Detection patterns complete - should detect High and Medium violations"