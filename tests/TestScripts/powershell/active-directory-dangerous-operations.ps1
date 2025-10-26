# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Active Directory dangerous operations violations
# These patterns represent enterprise identity security risks

# Violation 1: Unsafe LDAP filter with string concatenation (LDAP injection risk)
$username = $args[0]
$ldapFilter = "(&(objectClass=user)(sAMAccountName=$username))"
Get-ADUser -LDAPFilter $ldapFilter

# Violation 2: LDAP filter with user input concatenation
$searchTerm = Read-Host "Enter username"
$filter = "(|(cn=$searchTerm)(sAMAccountName=$searchTerm))"
Get-ADUser -LDAPFilter $filter -Properties *

# Violation 3: Bulk user deletion without confirmation
Get-ADUser -Filter {Department -eq "TempDept"} | Remove-ADUser -Confirm:$false

# Violation 4: Bulk password reset without security measures
$users = Get-ADUser -Filter * -SearchBase "OU=Users,DC=contoso,DC=com"
foreach ($user in $users) {
    Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Reset
}

# Violation 5: Adding user to privileged group without validation
$newUser = "JohnDoe"
Add-ADGroupMember -Identity "Domain Admins" -Members $newUser

# Violation 6: Bulk group membership modification
Get-ADUser -Filter * | Add-ADGroupMember -Identity "Enterprise Admins" -Members {$_}

# Violation 7: Creating user with weak password policy
New-ADUser -Name "TestUser" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -PasswordNeverExpires $true -Enabled $true

# Violation 8: Modifying security-sensitive AD attributes without validation
$dangerousAttributes = @{
    'userAccountControl' = 512
    'adminCount' = 1
}
Set-ADUser -Identity "someuser" -Replace $dangerousAttributes

# Violation 9: Unsafe AD search with wildcard
$searchPattern = "*admin*"
Get-ADUser -Filter "Name -like '$searchPattern'" -Properties *

# Violation 10: Granting excessive permissions on AD objects
$acl = Get-Acl "AD:\CN=AdminSDHolder,CN=System,DC=contoso,DC=com"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    "CONTOSO\RegularUser",
    "GenericAll",
    "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl "AD:\CN=AdminSDHolder,CN=System,DC=contoso,DC=com" $acl

# Violation 11: Enabling user account without proper validation
Get-ADUser -Filter {Enabled -eq $false} | Enable-ADAccount

# Violation 12: Bulk move of users to different OU
Get-ADUser -Filter * -SearchBase "OU=OldOU,DC=contoso,DC=com" | Move-ADObject -TargetPath "OU=NewOU,DC=contoso,DC=com"

# Violation 13: Removing account expiration for multiple users
Get-ADUser -Filter {AccountExpirationDate -like "*"} | Set-ADUser -AccountExpirationDate $null

# Violation 14: Granting DCSync rights (dangerous replication permissions)
$identity = "CONTOSO\RegularUser"
$domainDN = "DC=contoso,DC=com"
$acl = Get-Acl "AD:\$domainDN"
$sid = (Get-ADUser -Identity $identity).SID
$replicationGuid = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid,
    "ExtendedRight",
    "Allow",
    $replicationGuid
)
$acl.AddAccessRule($rule)
Set-Acl "AD:\$domainDN" $acl

# Violation 15: Modifying AD schema without proper testing
$schema = Get-ADObject -SearchBase "CN=Schema,CN=Configuration,DC=contoso,DC=com" -Filter {name -eq "User"}
Set-ADObject $schema -Replace @{lDAPDisplayName="modifiedUser"}

# Correct usage examples (should not trigger violations)
# Using parameterized LDAP filter
$safeUsername = "johndoe"
$escapedUsername = $safeUsername -replace '[*()\\\x00]', '\$0'
Get-ADUser -Filter "sAMAccountName -eq '$escapedUsername'"

# Using Identity parameter instead of filter
Get-ADUser -Identity "johndoe"

# Proper user deletion with confirmation
$userToDelete = Get-ADUser -Identity "testuser"
if ($userToDelete) {
    Remove-ADUser -Identity $userToDelete -Confirm:$true
}

# Adding user to group with validation
$groupName = "RegularUsers"
$userName = "newuser"
if ((Get-ADGroup -Identity $groupName).GroupCategory -ne "Security" -or 
    (Get-ADGroup -Identity $groupName).Name -notmatch "Admin|Enterprise|Domain") {
    Add-ADGroupMember -Identity $groupName -Members $userName
}

# Creating user with strong password requirements
$securePassword = Read-Host "Enter password" -AsSecureString
New-ADUser -Name "SecureUser" -AccountPassword $securePassword -ChangePasswordAtLogon $true -Enabled $true
