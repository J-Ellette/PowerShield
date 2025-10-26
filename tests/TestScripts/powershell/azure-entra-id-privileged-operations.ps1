# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure Entra ID (Azure AD) Privileged Operations violations
# Rule 38: AzureEntraIDPrivilegedOperations

# Violation 1: Adding member to Global Admin role
$objectId = "12345678-1234-1234-1234-123456789012"
Add-AzureADDirectoryRoleMember -RoleObjectId "GlobalAdministrator" -RefObjectId $objectId

# Violation 2: Adding member to Privileged Role Administrator
$roleId = Get-AzureADDirectoryRole -Filter "DisplayName eq 'Privileged Role Administrator'" | Select-Object -ExpandProperty ObjectId
Add-AzureADDirectoryRoleMember -RoleObjectId $roleId -RefObjectId $objectId

# Violation 3: Adding member to Company Administrator
Add-AzureADDirectoryRoleMember -RoleObjectId "CompanyAdministrator" -RefObjectId $objectId

# Violation 4: Adding member to User Administrator
Add-MgDirectoryRoleMember -DirectoryRoleId "UserAdministrator" -BodyParameter @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$objectId" }

# Violation 5: Adding member to Security Administrator
Add-AzureADDirectoryRoleMember -RoleObjectId "SecurityAdministrator" -RefObjectId $objectId

# Violation 6: Modifying privileged admin user
Set-AzureADUser -ObjectId "admin@contoso.com" -Department "IT Security"

# Violation 7: Modifying global admin account
Set-AzureADUser -ObjectId "globaladmin@contoso.com" -AccountEnabled $true

# Violation 8: Modifying privileged user with Graph API
Update-MgUser -UserId "privilegeduser@contoso.com" -CompanyName "Contoso"

# Violation 9: Modifying security admin
Set-AzureADUser -ObjectId "securityadmin@contoso.com" -PasswordPolicies "DisablePasswordExpiration"

# Violation 10: Creating application with excessive permissions
$appPermissions = @{
    ResourceAppId = "00000003-0000-0000-c000-000000000000"
    ResourceAccess = @(
        @{
            Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
            Type = "Scope"
        }
    )
}
New-AzureADApplication -DisplayName "PrivilegedApp" -RequiredResourceAccess $appPermissions

# Violation 11: Creating application with app roles
New-AzureADApplication -DisplayName "AppWithRoles" -AppRoles @(@{DisplayName="Admin"})

# Violation 12: Creating application with Microsoft Graph permissions
New-MgApplication -DisplayName "GraphApp" -RequiredResourceAccess @(@{ResourceAppId="00000003-0000-0000-c000-000000000000"})

# Violation 13: Bulk user deletion in a loop
$usersToDelete = Get-AzureADUser -Filter "Department eq 'Temp'"
foreach ($user in $usersToDelete) {
    Remove-AzureADUser -ObjectId $user.ObjectId
}

# Violation 14: Bulk user deletion with array
$userIds = @("user1@contoso.com", "user2@contoso.com", "user3@contoso.com")
foreach ($userId in $userIds) {
    Remove-MgUser -UserId $userId
}

# Violation 15: User deletion in pipeline
Get-AzureADUser -Filter "City eq 'Old'" | ForEach-Object {
    Remove-AzureADUser -ObjectId $_.ObjectId
}

# Violation 16: Modifying Azure AD policy
Set-AzureADPolicy -Id "12345678-1234-1234-1234-123456789012" -Definition @("PolicyDefinition")

# Violation 17: Setting conditional access policy
Set-AzureADPolicy -Id "PolicyId" -DisplayName "WeakPolicy" -Type "ConditionalAccessPolicy"

# Correct usage examples (should not trigger violations)
# Adding member to non-privileged role
Add-AzureADDirectoryRoleMember -RoleObjectId "DirectoryReaders" -RefObjectId $objectId

# Modifying regular user
Set-AzureADUser -ObjectId "user@contoso.com" -Department "Sales"

# Creating application without special permissions
New-AzureADApplication -DisplayName "StandardApp" -IdentifierUris "https://contoso.com/app"

# Single user deletion with confirmation
Remove-AzureADUser -ObjectId "olduser@contoso.com" -Confirm

# Reading policies (not modifying)
Get-AzureADPolicy -All $true
