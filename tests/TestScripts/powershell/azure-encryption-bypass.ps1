# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure Encryption Bypass violations
# Rule 44: AzureEncryptionBypass

# Violation 1: Disabling storage account encryption
Set-AzStorageAccount -ResourceGroupName "RG-Storage" -Name "mystorage" -EnableEncryptionService $false

# Violation 2: Storage account with no encryption
Set-AzStorageAccount -ResourceGroupName "RG-Prod" -AccountName "prodstorage" -EnableEncryptionService None

# Violation 3: Disabling infrastructure encryption
Set-AzStorageAccount -ResourceGroupName "RG" -Name "storage1" -RequireInfrastructureEncryption $false

# Violation 4: Storage with encryption disabled explicitly
Set-AzStorageAccount -ResourceGroupName "RG-Data" -Name "datastorage" -RequireInfrastructureEncryption:$false

# Violation 5: Creating disk without encryption
New-AzDisk -ResourceGroupName "RG-VM" -DiskName "datadisk1" -DiskSizeGB 128 -Location "eastus" -CreateOption Empty

# Violation 6: Managed disk without encryption set
New-AzDisk -ResourceGroupName "RG-Disks" -DiskName "disk2" -Location "westus" -SkuName Premium_LRS -DiskSizeGB 256 -CreateOption Empty

# Violation 7: Disk configuration without encryption
$diskConfig = New-AzDiskConfig -Location "eastus" -CreateOption Empty -DiskSizeGB 512
New-AzDisk -ResourceGroupName "RG" -DiskName "unencrypted-disk" -Disk $diskConfig

# Violation 8: Disabling Transparent Data Encryption
Set-AzSqlDatabase -ResourceGroupName "RG-SQL" -ServerName "sqlserver1" -DatabaseName "productiondb" -TransparentDataEncryption Disabled

# Violation 9: TDE disabled via state parameter
Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName "RG-Data" -ServerName "sql-prod" -DatabaseName "customerdb" -State Disabled

# Violation 10: Explicitly disabling TDE
Set-AzSqlDatabase -ResourceGroupName "RG" -ServerName "server1" -DatabaseName "db1" -State "Disabled"

# Violation 11: Creating VM without disk encryption
New-AzVirtualMachine -ResourceGroupName "RG-VMs" -Name "vm1" -Location "eastus" -VirtualNetworkName "vnet1" -SubnetName "subnet1" -SecurityGroupName "nsg1"

# Violation 12: VM config without encryption settings
$vmConfig = New-AzVMConfig -VMName "vm2" -VMSize "Standard_D2s_v3"
New-AzVirtualMachine -ResourceGroupName "RG" -Location "westus" -VM $vmConfig

# Violation 13: Production Key Vault without HSM
New-AzKeyVault -ResourceGroupName "RG-Production" -Name "prod-keyvault" -Location "eastus" -Sku Standard

# Violation 14: Setting production vault to standard SKU (no HSM)
Set-AzKeyVault -ResourceGroupName "RG-Prod" -Name "production-vault" -Sku Standard

# Violation 15: Production Key Vault without Premium tier
New-AzKeyVault -ResourceGroupName "RG" -Name "prod-vault-001" -Location "westus"

# Correct usage examples (should not trigger violations)
# Storage account with encryption enabled
Set-AzStorageAccount -ResourceGroupName "RG-Storage" -Name "securestorage" -EnableEncryptionService Blob,File -RequireInfrastructureEncryption $true

# Disk with encryption
$encryptedDiskConfig = New-AzDiskConfig -Location "eastus" -CreateOption Empty -DiskSizeGB 128 -DiskEncryptionSetId $desId -EncryptionType "EncryptionAtRestWithCustomerKey"
New-AzDisk -ResourceGroupName "RG" -DiskName "encrypted-disk" -Disk $encryptedDiskConfig

# Disk with encryption set
New-AzDisk -ResourceGroupName "RG-Secure" -DiskName "secure-disk" -Location "eastus" -DiskSizeGB 256 -DiskEncryptionSetId $encryptionSetId -CreateOption Empty

# Enabling TDE
Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName "RG-SQL" -ServerName "sqlserver1" -DatabaseName "productiondb" -State Enabled

# SQL database with TDE enabled
Set-AzSqlDatabase -ResourceGroupName "RG" -ServerName "server1" -DatabaseName "db1" -TransparentDataEncryption Enabled

# VM with encryption
$vmConfig = Set-AzVMOSDisk -VM $vmConfig -DiskEncryptionSetId $desId -CreateOption FromImage
New-AzVirtualMachine -ResourceGroupName "RG" -Location "eastus" -VM $vmConfig

# Production Key Vault with HSM (Premium SKU)
New-AzKeyVault -ResourceGroupName "RG-Production" -Name "prod-keyvault-hsm" -Location "eastus" -Sku Premium -EnableHsmProtection

# Setting vault to Premium for production
Set-AzKeyVault -ResourceGroupName "RG-Prod" -Name "production-vault" -Sku Premium

# Non-production vault (standard is acceptable)
New-AzKeyVault -ResourceGroupName "RG-Dev" -Name "dev-keyvault" -Location "eastus" -Sku Standard

# Reading configuration
Get-AzStorageAccount -ResourceGroupName "RG" -Name "storage1"
Get-AzDisk -ResourceGroupName "RG" -DiskName "disk1"
