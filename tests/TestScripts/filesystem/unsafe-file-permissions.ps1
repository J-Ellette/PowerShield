# Test script for UnsafeFilePermissions rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Setting overly permissive file permissions (Everyone Full Control)
$acl = Get-Acl "C:\SecretData\config.xml"
$permission = "Everyone", "FullControl", "Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl "C:\SecretData\config.xml" $acl

# ❌ VIOLATION: Granting modify access to Everyone
icacls "C:\Important\file.txt" /grant Everyone:M

# ❌ VIOLATION: Removing all security restrictions
icacls "C:\Config\settings.ini" /grant *S-1-1-0:F

# ❌ VIOLATION: Setting 777-equivalent permissions
$path = "C:\Data\sensitive.dat"
$acl = Get-Acl $path
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $path $acl

# ✅ SAFE: Setting appropriate permissions (should not be flagged)
$acl = Get-Acl "C:\Data\report.txt"
$permission = "DOMAIN\AdminGroup", "Read", "Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl "C:\Data\report.txt" $acl
