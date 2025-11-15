# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These credentials and patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure PowerShell credential leak violations
# These patterns represent security risks in Azure automation and scripts

# Violation 1: Connect-AzAccount with plaintext password
$username = "admin@contoso.com"
$password = "MyAzurePassword123!"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
Connect-AzAccount -Credential $credential

# Violation 2: Hardcoded Azure Service Principal credentials
$servicePrincipalId = "12345678-1234-1234-1234-123456789012"
$servicePrincipalKey = "MySecretServicePrincipalKey123!"
$tenantId = "87654321-4321-4321-4321-210987654321"
$secureKey = ConvertTo-SecureString $servicePrincipalKey -AsPlainText -Force
$spCredential = New-Object System.Management.Automation.PSCredential($servicePrincipalId, $secureKey)
Connect-AzAccount -ServicePrincipal -Credential $spCredential -Tenant $tenantId

# Violation 3: Azure Storage Account key in plaintext
$storageAccountName = "mystorageaccount"
$storageAccountKey = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=="
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey

# Violation 4: Connection string with embedded credentials
$connectionString = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/==;EndpointSuffix=core.windows.net"
$storageContext = New-AzStorageContext -ConnectionString $connectionString

# Violation 5: Azure SQL connection string with credentials
$sqlConnectionString = "Server=tcp:myserver.database.windows.net,1433;Database=mydb;User ID=sqladmin;Password=SqlP@ssw0rd123!;Encrypt=true;"
$sqlConnection = New-Object System.Data.SqlClient.SqlConnection($sqlConnectionString)

# Violation 6: Azure Key Vault access with plaintext app secret
$appId = "11111111-2222-3333-4444-555555555555"
$appSecret = "MyApplicationSecret123!"
$secureAppSecret = ConvertTo-SecureString $appSecret -AsPlainText -Force
$azureCredential = New-Object System.Management.Automation.PSCredential($appId, $secureAppSecret)

# Violation 7: Azure DevOps Personal Access Token in plaintext
$devOpsToken = "abcdefghijklmnopqrstuvwxyz0123456789"
$encodedToken = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$devOpsToken"))
$headers = @{Authorization = "Basic $encodedToken"}

# Violation 8: Azure Function key hardcoded
$functionKey = "FunctionKeyValue123456789abcdefghijklmnopqrstuvwxyz=="
$functionUrl = "https://myfunctionapp.azurewebsites.net/api/myfunction?code=$functionKey"
Invoke-RestMethod -Uri $functionUrl -Method Post

# Correct usage examples (should not trigger violations)
# Using Azure Managed Identity (no credentials needed)
Connect-AzAccount -Identity

# Using certificate-based authentication
$certThumbprint = "1234567890ABCDEF1234567890ABCDEF12345678"
Connect-AzAccount -ServicePrincipal -Tenant $tenantId -CertificateThumbprint $certThumbprint -ApplicationId $servicePrincipalId

# Using Azure Key Vault to retrieve secrets
$secret = Get-AzKeyVaultSecret -VaultName "MyKeyVault" -Name "MySecret"

# Using environment variables (better than hardcoding)
$envPassword = $env:AZURE_PASSWORD
if ($envPassword) {
    $secPass = ConvertTo-SecureString $envPassword -AsPlainText -Force
}
