# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure Subscription Management violations
# Rule 41: AzureSubscriptionManagement

# Violation 1: Switching to production subscription
Set-AzContext -SubscriptionId "12345678-1234-1234-1234-123456789012" -SubscriptionName "Production"

# Violation 2: Setting production context
Set-AzContext -Subscription "Prod-Subscription"

# Violation 3: Switching to production environment
Set-AzContext -SubscriptionName "Company-Production-001"

# Violation 4: Creating role definition with wildcard permissions
$role = @{
    Name = "CustomAdmin"
    Description = "Custom administrator role"
    Actions = @("*")
    AssignableScopes = @("/subscriptions/12345678-1234-1234-1234-123456789012")
}
New-AzRoleDefinition -Role $role

# Violation 5: Role with all Microsoft permissions
$broadRole = @{
    Name = "BroadAccessRole"
    Actions = @("Microsoft.*/read", "Microsoft.*/write")
    AssignableScopes = @("/")
}
New-AzRoleDefinition -Role $broadRole

# Violation 6: Role with wildcard resource access
New-AzRoleDefinition -Name "WildcardRole" -Description "Too broad" -Actions @("Microsoft.Compute/*", "Microsoft.Storage/*") -AssignableScopes "/"

# Violation 7: Bulk role assignment removal in loop
$assignments = Get-AzRoleAssignment -ResourceGroupName "Production-RG"
foreach ($assignment in $assignments) {
    Remove-AzRoleAssignment -ObjectId $assignment.ObjectId -RoleDefinitionName $assignment.RoleDefinitionName -Scope $assignment.Scope
}

# Violation 8: Removing role assignments in pipeline
Get-AzRoleAssignment -Scope "/subscriptions/sub-id" | ForEach-Object {
    Remove-AzRoleAssignment -ObjectId $_.ObjectId -RoleDefinitionId $_.RoleDefinitionId
}

# Violation 9: Bulk removal of contributor assignments
$contributors = Get-AzRoleAssignment -RoleDefinitionName "Contributor"
foreach ($user in $contributors) {
    Remove-AzRoleAssignment -ObjectId $user.ObjectId -RoleDefinitionName "Contributor" -Scope $user.Scope
}

# Violation 10: Modifying subscription settings
Set-AzSubscription -SubscriptionId "sub-id" -TenantId "tenant-id"

# Violation 11: Setting subscription quota
Set-AzSubscription -Name "Production" -MaxVMCount 1000

# Violation 12: Moving resource across subscriptions
Move-AzResource -ResourceId "/subscriptions/source-sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storage1" -DestinationSubscriptionId "dest-sub-id"

# Violation 13: Cross-subscription VM move
$vmId = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
Move-AzResource -ResourceId $vmId -DestinationSubscriptionId "sub2"

# Violation 14: Moving database cross-subscription
Move-AzResource -ResourceId "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Sql/servers/sql1/databases/db1" -DestinationSubscriptionId "sub2" -DestinationResourceGroupName "rg2"

# Violation 15: Batch cross-subscription resource move
$resources = @(
    "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storage1",
    "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
)
foreach ($resourceId in $resources) {
    Move-AzResource -ResourceId $resourceId -DestinationSubscriptionId "sub2"
}

# Correct usage examples (should not trigger violations)
# Switching to non-production subscription
Set-AzContext -SubscriptionName "Development"

# Setting test environment context
Set-AzContext -Subscription "Test-Sandbox"

# Creating role with specific permissions (no wildcards)
$specificRole = @{
    Name = "SpecificRole"
    Actions = @("Microsoft.Compute/virtualMachines/read", "Microsoft.Storage/storageAccounts/read")
    AssignableScopes = @("/subscriptions/sub-id/resourceGroups/rg")
}
New-AzRoleDefinition -Role $specificRole

# Single role assignment removal with confirmation
Remove-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName "Reader" -Scope $scope -Confirm

# Reading subscription information
Get-AzSubscription

# Moving resource within same subscription
Move-AzResource -ResourceId $resourceId -DestinationResourceGroupName "new-rg"

# Getting role assignments (not removing)
Get-AzRoleAssignment -ResourceGroupName "Production-RG"
