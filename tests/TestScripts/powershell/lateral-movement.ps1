# PowerShield Test Script: Lateral Movement Detection
# This script contains intentional lateral movement patterns for testing Rule 51
# MITRE ATT&CK: T1021 (Remote Services), T1570 (Lateral Tool Transfer), T1135 (Network Share Discovery)

# Test 1: Remote WMI execution (Critical)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c calc.exe" -ComputerName "target-server" -Credential $cred

# Test 2: Remote CIM execution (Critical)
$session = New-CimSession -ComputerName "remote-host"
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="powershell.exe"} -CimSession $session

# Test 3: WMI remote query (High)
Get-WmiObject -Class Win32_Service -ComputerName "target-pc" -Credential $cred

# Test 4: Get-CimInstance remote (High)
Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName "remote-server" -CimSession $session

# Test 5: wmic remote execution (Critical)
wmic /node:"target-host" process call create "cmd.exe /c malware.exe"

# Test 6: Remote scheduled task (Critical)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\evil.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "RemoteBackdoor" -Action $action -Trigger $trigger -ComputerName "target-server"

# Test 7: schtasks remote (Critical)
schtasks /create /tn "EvilTask" /tr "C:\backdoor.exe" /sc onlogon /s target-host /u admin /p password

# Test 8: SMB share enumeration (High)
net view \\target-server
net share \\remote-host

# Test 9: Get-SmbShare remote (High)
Get-SmbShare -CimSession $remoteSession

# Test 10: net use mapping (High)
net use \\target-server\C$ /user:domain\admin password

# Test 11: PSSession creation (Critical)
$session = New-PSSession -ComputerName "target-host" -Credential $cred
Invoke-Command -Session $session -ScriptBlock { whoami }

# Test 12: Enter-PSSession (High)
Enter-PSSession -ComputerName "remote-server" -Credential $cred

# Test 13: Invoke-Command remote (Critical)
Invoke-Command -ComputerName "target1","target2" -ScriptBlock { Get-Process } -Credential $cred

# Test 14: Pass-the-Hash pattern (Critical)
Invoke-Mimikatz -Command 'sekurlsa::pth /user:admin /domain:company.com /ntlm:hash'

# Test 15: Invoke-WMIExec (Critical)
Invoke-WMIExec -Target 192.168.1.10 -Username admin -Hash NTLMHASH -Command "cmd /c calc"

# Test 16: Invoke-SMBExec (Critical)
Invoke-SMBExec -Target target-host -Username admin -Hash hash -Command "powershell.exe"

# Test 17: Invoke-PSExec pattern (Critical)
Invoke-PSExec -ComputerName target-server -Command "cmd.exe"

# Test 18: Remote service creation (Critical)
New-Service -Name "EvilSvc" -BinaryPathName "C:\backdoor.exe" -ComputerName "remote-host"

# Test 19: sc.exe remote (Critical)
sc \\target-server create BackdoorService binpath= "C:\malware\evil.exe" start= auto

# Test 20: Remote registry access (High)
Get-ItemProperty -Path "\\remote-server\HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

# Test 21: reg query remote (High)
reg query \\target-host\HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# Test 22: reg add remote (High)
reg add \\remote-server\HKLM\Software\Backdoor /v Key /t REG_SZ /d Value

# Test 23: PsExec reference (Critical)
$tool = "psexec.exe \\target -u admin -p pass cmd.exe"

# Test 24: paexec usage (Critical)
$cmd = "paexec.exe \\remote-host cmd.exe"

# Test 25: remcom tool (Critical)
$remoteCmd = "remcom \\target-server cmd.exe"

# Test 26: CIM session with credential (Critical)
$cimSession = New-CimSession -ComputerName "target" -Credential $cred
Get-CimInstance -ClassName Win32_Process -CimSession $cimSession

# Test 27: Multiple computer names (High)
$computers = @("server1", "server2", "server3")
Invoke-Command -ComputerName $computers -ScriptBlock { hostname }

# Test 28: WMI namespace root\cimv2 remote (High)
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem -ComputerName target-host

Write-Host "Lateral movement detection test complete"
