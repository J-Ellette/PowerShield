# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure Policy and Compliance violations
# Rule 45: AzurePolicyAndCompliance

# Violation 1: Removing policy assignment
Remove-AzPolicyAssignment -Name "RequireTags" -Scope "/subscriptions/sub-id"

# Violation 2: Removing compliance policy
Remove-AzPolicyAssignment -Id "/subscriptions/sub-id/providers/Microsoft.Authorization/policyAssignments/SecurityBaseline"

# Violation 3: Removing multiple policy assignments
$assignments = Get-AzPolicyAssignment -Scope "/subscriptions/sub-id"
foreach ($assignment in $assignments) {
    Remove-AzPolicyAssignment -Id $assignment.Id
}

# Violation 4: Setting policy to audit only (weakening from deny)
$policy = Get-AzPolicyDefinition -Name "AllowedLocations"
Set-AzPolicyDefinition -Name "AllowedLocations" -Policy $policy.Properties.PolicyRule -Mode "Audit"

# Violation 5: Disabling policy enforcement
Set-AzPolicyDefinition -Id $policyId -EnforcementMode "Disabled"

# Violation 6: Weakening deny policy
$policyRule = @{
    if = @{
        field = "location"
        notIn = @("eastus", "westus")
    }
    then = @{
        effect = "audit"  # Weakened from deny
    }
}
Set-AzPolicyDefinition -Name "LocationRestriction" -Policy $policyRule

# Violation 7: Policy definition with deny set to false
Set-AzPolicyDefinition -Name "RequireEncryption" -Deny:$false

# Violation 8: Creating policy exemption without description
New-AzPolicyExemption -Name "TempExemption" -PolicyAssignment $assignment -Scope "/subscriptions/sub-id/resourceGroups/rg1"

# Violation 9: Exemption without justification
New-AzPolicyExemption -Name "DevExemption" -PolicyAssignmentId $assignmentId -Scope $scope -ExemptionCategory "Waiver"

# Violation 10: Multiple exemptions without description
$policies = Get-AzPolicyAssignment
foreach ($policy in $policies) {
    New-AzPolicyExemption -Name "Exempt-$($policy.Name)" -PolicyAssignment $policy -Scope "/subscriptions/sub-id"
}

# Violation 11: Disabling security contact
Disable-AzSecurityContact -Name "default1"

# Violation 12: Removing security contacts
Get-AzSecurityContact | ForEach-Object { Disable-AzSecurityContact -Name $_.Name }

# Violation 13: Setting Security Center to Free tier
Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier "Free"

# Violation 14: Downgrading to free tier for SQL
Set-AzSecurityPricing -Name "SqlServers" -PricingTier "Free"

# Violation 15: Setting multiple resources to free tier
$resourceTypes = @("VirtualMachines", "StorageAccounts", "SqlServers", "AppServices")
foreach ($type in $resourceTypes) {
    Set-AzSecurityPricing -Name $type -PricingTier "Free"
}

# Correct usage examples (should not trigger violations)
# Creating policy assignment (not removing)
New-AzPolicyAssignment -Name "RequireTags" -PolicyDefinition $policyDef -Scope "/subscriptions/sub-id"

# Setting policy to deny (strong enforcement)
Set-AzPolicyDefinition -Name "LocationRestriction" -Policy $policyRule -Mode "All"

# Policy exemption WITH description
New-AzPolicyExemption -Name "ValidExemption" -PolicyAssignment $assignment -Scope $scope -Description "Approved by Security Team - Ticket #12345" -ExemptionCategory "Mitigated"

# Exemption with proper justification
New-AzPolicyExemption -Name "LegacySystem" -PolicyAssignmentId $assignmentId -Scope $scope -Description "Legacy system scheduled for migration Q2 2024" -ExpiresOn (Get-Date).AddMonths(6)

# Enabling/maintaining security contacts
Set-AzSecurityContact -Name "default1" -Email "security@company.com" -AlertsToAdmins On

# Setting Security Center to Standard tier
Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier "Standard"

# Upgrading to standard tier for production
Set-AzSecurityPricing -Name "SqlServers" -PricingTier "Standard"

# Reading policy assignments
Get-AzPolicyAssignment -Scope "/subscriptions/sub-id"

# Getting policy definitions
Get-AzPolicyDefinition -Name "RequireTags"

# Checking security pricing
Get-AzSecurityPricing
