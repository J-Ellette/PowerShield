# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure Logging Disabled violations
# Rule 40: AzureLoggingDisabled

# Violation 1: Disabling diagnostic settings
Set-AzDiagnosticSetting -ResourceId "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1" -Enabled $false

# Violation 2: Diagnostic setting with disabled categories
Set-AzDiagnosticSetting -ResourceId "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storage1" -Enabled:$false -WorkspaceId $workspaceId

# Violation 3: Disabling logging explicitly
Set-AzDiagnosticSetting -Name "DiagSetting" -ResourceId $resourceId -Enabled:$false

# Violation 4: Removing log profile
Remove-AzLogProfile -Name "default"

# Violation 5: Removing activity log profile
Remove-AzLogProfile -Name "production-logs"

# Violation 6: Removing all log profiles
Get-AzLogProfile | Remove-AzLogProfile

# Violation 7: Disabling security contact alerts to admins
Set-AzSecurityContact -Name "default1" -Email "security@contoso.com" -AlertsToAdmins Off

# Violation 8: Security contact with disabled notifications
Set-AzSecurityContact -Name "contact1" -Email "admin@company.com" -AlertNotifications $false

# Violation 9: Disabling alert notifications
Set-AzSecurityContact -Name "security-team" -Email "team@contoso.com" -AlertsToAdmins $false -AlertNotifications $false

# Violation 10: Disabling activity log alert
Disable-AzActivityLogAlert -Name "HighSeverityAlert" -ResourceGroupName "Monitoring-RG"

# Violation 11: Disabling critical security alert
Disable-AzActivityLogAlert -Name "UnauthorizedAccessAlert" -ResourceGroupName "Security-RG"

# Violation 12: Log profile with 30 days retention (less than 90)
Set-AzMonitorLogProfile -Name "short-retention" -RetentionInDays 30 -Locations "eastus" -Categories "Write","Delete","Action"

# Violation 13: Log profile with 60 days retention (less than 90)
Set-AzMonitorLogProfile -Name "medium-retention" -RetentionInDays 60 -StorageAccountId $storageId

# Violation 14: Log profile with 7 days retention
Set-AzMonitorLogProfile -Name "minimal-retention" -RetentionInDays 7 -Locations "westus"

# Violation 15: Log profile with 1 day retention
Set-AzMonitorLogProfile -Name "daily-logs" -RetentionInDays 1 -ServiceBusRuleId $ruleId

# Correct usage examples (should not trigger violations)
# Enabling diagnostic settings
Set-AzDiagnosticSetting -ResourceId $resourceId -Enabled $true -WorkspaceId $workspaceId

# Setting up log profile with adequate retention
Set-AzMonitorLogProfile -Name "compliant-logs" -RetentionInDays 365 -Locations "eastus","westus" -Categories "Write","Delete"

# 90 days retention (minimum acceptable)
Set-AzMonitorLogProfile -Name "minimum-compliant" -RetentionInDays 90 -StorageAccountId $storageId

# Enabling security contacts
Set-AzSecurityContact -Name "default1" -Email "security@contoso.com" -AlertsToAdmins On -AlertNotifications $true

# Enabling activity log alert
Enable-AzActivityLogAlert -Name "SecurityAlert" -ResourceGroupName "Monitoring-RG"

# Reading log profile (not modifying)
Get-AzLogProfile -Name "default"

# Getting diagnostic settings
Get-AzDiagnosticSetting -ResourceId $resourceId
