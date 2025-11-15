# ETW Evasion Test Script
# This script contains intentional security violations for testing ETW bypass detection

Write-Host "Testing ETW Evasion Detection Patterns..."

# Pattern 1: ScriptBlock logging bypass (Critical)
$PSModuleAutoLoadingPreference = 'None'
$EnableScriptBlockLogging = $false

# Pattern 2: ETW provider manipulation (Critical)
Set-EtwTraceProvider -Guid '{A0C1853B-5C40-4B15-8766-3CF1C58F985A}' -MatchAnyKeyword 0

Remove-EtwTraceSession -Name "PowerShell-Security"

Stop-EtwTraceSession -Name "Microsoft-Windows-PowerShell"

# Pattern 3: Registry modifications to disable logging (Critical)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0 -Force

# Pattern 4: Group Policy modifications (Critical)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "PowerShellExecutionPolicy" -Value "Bypass"

Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"

# Additional ETW evasion techniques
$LoggingSettings = @{
    "EnableScriptBlockLogging" = 0
    "EnableModuleLogging" = 0
    "PowerShellExecutionPolicy" = "Unrestricted"
}

# Registry path targeting
$PSLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

Write-Host "ETW Evasion patterns complete - all should be detected as Critical violations"