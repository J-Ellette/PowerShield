# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure DevOps Security Issues
# Rule 43: AzureDevOpsSecurityIssues

# Violation 1: Setting variable with password not marked as secret
Set-AzDevOpsVariable -Project "MyProject" -Name "DatabasePassword" -Value "MyP@ssw0rd123" -IsSecret $false

# Violation 2: API key variable not secured
Set-AzDevOpsVariable -Project "WebApp" -Name "APIKey" -Value "sk-1234567890abcdef"

# Violation 3: Token variable without secret flag
Set-AzDevOpsVariable -Project "Mobile" -Name "AuthToken" -Value "bearer_token_here" -IsSecret:$false

# Violation 4: Secret value in plaintext
Set-AzDevOpsVariable -Organization "MyOrg" -Project "API" -Name "ClientSecret" -Value "secret123" -IsSecret $false

# Violation 5: Credential variable exposed
Set-AzDevOpsVariable -Project "Backend" -Name "ServiceCredential" -Value "admin:password123"

# Violation 6: Creating pipeline with admin permissions
New-AzDevOpsPipeline -Project "Production" -Name "Deploy-Prod" -YamlPath "pipeline.yml" -Permission "Admin"

# Violation 7: Elevated pipeline creation
New-AzDevOpsPipeline -Organization "Company" -Project "Critical" -Name "Privileged-Deploy" -Permissions "Elevated"

# Violation 8: Pipeline with privileged access
New-AzDevOpsPipeline -Project "Infrastructure" -Name "IaC-Pipeline" -PermissionLevel "Privileged"

# Violation 9: Adding service connection
Add-AzDevOpsServiceConnection -Project "MyProject" -Name "AzureConnection" -Type "AzureRM" -Scope "Subscription"

# Violation 10: Broad service connection
Add-AzDevOpsServiceConnection -Organization "MyOrg" -Project "All" -Name "GlobalConnection" -AccessLevel "Full"

# Violation 11: Service connection with extensive permissions
Add-AzDevOpsServiceConnection -Project "Prod" -Name "ProdConnection" -Type "GitHub" -Scope "Organization"

# Violation 12: Disabling branch protection policy
Set-AzDevOpsRepositoryPolicy -Project "WebApp" -RepositoryId $repoId -PolicyType "RequireReviewer" -Enabled $false

# Violation 13: Disabling build validation
Set-AzDevOpsRepositoryPolicy -Project "API" -Repository "main-repo" -PolicyType "BuildValidation" -Enabled:$false

# Violation 14: Removing security checks
Set-AzDevOpsRepositoryPolicy -Organization "Company" -Project "Backend" -RepositoryId $repoId -PolicyType "MinimumReviewers" -Enabled:$false

# Violation 15: Granting all permissions
Grant-AzDevOpsPermission -Project "MyProject" -User "user@company.com" -Permission "Allow All"

# Violation 16: Administrator access grant
Grant-AzDevOpsPermission -Organization "MyOrg" -Project "Prod" -Group "Developers" -Role "Administrator"

# Violation 17: Full control permissions
Grant-AzDevOpsPermission -Project "Critical" -User "contractor@external.com" -AccessLevel "Full Control"

# Violation 18: Excessive scope permissions
Grant-AzDevOpsPermission -Organization "Company" -Scope "Organization" -User "temp@company.com" -Permission "Administrator"

# Correct usage examples (should not trigger violations)
# Variable properly marked as secret
Set-AzDevOpsVariable -Project "MyProject" -Name "DatabasePassword" -Value $securePassword -IsSecret $true

# Non-sensitive variable
Set-AzDevOpsVariable -Project "WebApp" -Name "ApplicationName" -Value "MyWebApp"

# Creating pipeline with standard permissions
New-AzDevOpsPipeline -Project "Development" -Name "Build-Dev" -YamlPath "pipeline.yml"

# Service connection with limited scope
Add-AzDevOpsServiceConnection -Project "MyProject" -Name "DevConnection" -Type "AzureRM" -Scope "ResourceGroup"

# Enabling repository policy
Set-AzDevOpsRepositoryPolicy -Project "WebApp" -RepositoryId $repoId -PolicyType "RequireReviewer" -Enabled $true

# Granting specific, limited permissions
Grant-AzDevOpsPermission -Project "MyProject" -User "user@company.com" -Permission "Read"

# Contributor access (not admin)
Grant-AzDevOpsPermission -Project "Dev" -Group "Developers" -Role "Contributor"

# Reading configuration (not modifying)
Get-AzDevOpsVariable -Project "MyProject" -Name "BuildConfiguration"
