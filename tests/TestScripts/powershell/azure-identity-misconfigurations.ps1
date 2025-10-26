# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These configurations are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure Identity Misconfigurations
# These patterns represent Azure identity and access management security risks

# Violation 1: Managed Identity credential exposure
$identity = Get-AzUserAssignedIdentity -ResourceGroupName "test-rg" -Name "test-identity"
$accessToken = $identity.AccessToken
Write-Host "Token: $accessToken"

# Violation 2: Service Principal certificate handling issues
$certPath = "C:\temp\service-principal-cert.pfx"
$certPassword = "PlaintextPassword123!"
$cert = Get-PfxCertificate -FilePath $certPath -Password (ConvertTo-SecureString $certPassword -AsPlainText -Force)

# Violation 3: Azure AD application secret exposure in logs
$appSecret = "MyApplicationSecret123!"
Write-Output "Connecting with secret: $appSecret"
$secureSecret = ConvertTo-SecureString $appSecret -AsPlainText -Force

# Violation 4: Hardcoded client credentials in connection
$clientId = "12345678-1234-1234-1234-123456789012"
$clientSecret = "SuperSecretClientSecret789!"
$tenantId = "87654321-4321-4321-4321-210987654321"
$credential = New-Object System.Management.Automation.PSCredential($clientId, (ConvertTo-SecureString $clientSecret -AsPlainText -Force))

# Violation 5: Unsafe token handling
$bearerToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6..."
$headers = @{
    "Authorization" = "Bearer $bearerToken"
    "Content-Type" = "application/json"
}
$apiResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers

# Violation 6: Azure AD B2C policy exposure
$b2cPolicy = "B2C_1_SignUpSignIn"
$b2cTenant = "contoso.onmicrosoft.com"
$redirectUri = "https://myapp.com/callback"
$clientSecretB2C = "B2CSecretValue123!"

# Violation 7: Graph API permissions escalation
$graphScope = "https://graph.microsoft.com/.default"
$appOnlyAuth = @{
    client_id = $clientId
    client_secret = $clientSecret
    scope = $graphScope
    grant_type = "client_credentials"
}

# Violation 8: Conditional Access policy bypass attempt
Set-AzureADPolicy -Id "ConditionalAccessPolicy123" -DisplayName "BypassPolicy" -Type "TokenIssuancePolicy"

# Violation 9: Privileged role assignment without justification
Add-AzureADDirectoryRoleMember -ObjectId "user-object-id" -RefObjectId "Global Administrator"

# Violation 10: Azure AD connect sync account exposure
$syncAccountUsername = "MSOL_abc123def456"
$syncAccountPassword = "SyncAccountPassword789!"
$syncCredential = New-Object System.Management.Automation.PSCredential($syncAccountUsername, (ConvertTo-SecureString $syncAccountPassword -AsPlainText -Force))

# Correct usage examples (should not trigger violations)

# Using certificate thumbprint (secure)
$certThumbprint = "A1B2C3D4E5F6789012345678901234567890ABCD"
Connect-AzAccount -ServicePrincipal -ApplicationId $clientId -TenantId $tenantId -CertificateThumbprint $certThumbprint

# Using managed identity (no credentials)
Connect-AzAccount -Identity

# Proper secret retrieval from Key Vault
$vault = "MySecureVault"
$secretName = "ApplicationSecret"
$secret = Get-AzKeyVaultSecret -VaultName $vault -Name $secretName

# Environment variable usage (better practice)
$envClientId = $env:AZURE_CLIENT_ID
$envTenantId = $env:AZURE_TENANT_ID

# Secure token validation
if ($bearerToken -and $bearerToken.Length -gt 0) {
    # Validate token before use
    $tokenValid = Test-AzureADToken -Token $bearerToken
}

# Proper RBAC assignment with least privilege
New-AzRoleAssignment -ObjectId "user-object-id" -RoleDefinitionName "Reader" -Scope "/subscriptions/subscription-id/resourceGroups/rg-name"