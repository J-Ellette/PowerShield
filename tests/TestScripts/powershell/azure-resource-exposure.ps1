# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These configurations are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure Resource Exposure vulnerabilities
# These patterns represent unsafe Azure resource configurations

# Violation 1: Public blob container with Blob-level access
$storageAccount = Get-AzStorageAccount -ResourceGroupName "test-rg" -Name "teststorage"
$ctx = $storageAccount.Context
New-AzStorageContainer -Name "public-data" -Context $ctx -Permission Blob

# Violation 2: Public blob container with Container-level access
Set-AzStorageContainerAcl -Container "sensitive-data" -Permission Container -Context $ctx

# Violation 3: SQL Server firewall rule allowing all IPs
New-AzSqlServerFirewallRule -ResourceGroupName "test-rg" -ServerName "testserver" -FirewallRuleName "AllowAll" -StartIpAddress "0.0.0.0" -EndIpAddress "255.255.255.255"

# Violation 4: Another broad SQL firewall rule
New-AzSqlServerFirewallRule -ResourceGroupName "prod-rg" -ServerName "prodserver" -FirewallRuleName "OpenAccess" -StartIpAddress "0.0.0.0" -EndIpAddress "0.0.0.0"

# Violation 5: NSG rule allowing inbound from any source
$nsg = Get-AzNetworkSecurityGroup -ResourceGroupName "test-rg" -Name "test-nsg"
Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name "Allow-All-Inbound" -Description "Temporary rule" -Access Allow -Protocol Tcp -Direction Inbound -Priority 100 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80

# Violation 6: NSG rule with Internet source
Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name "Allow-Internet" -Access Allow -Protocol Tcp -Direction Inbound -Priority 110 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 443

# Violation 7: NSG rule with 0.0.0.0/0 CIDR
Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name "Allow-Any-CIDR" -Access Allow -Protocol Tcp -Direction Inbound -Priority 120 -SourceAddressPrefix "0.0.0.0/0" -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 22

# Violation 8: Public IP for production resource
New-AzPublicIpAddress -ResourceGroupName "prod-rg" -Name "prod-web-ip" -Location "East US" -AllocationMethod Static -Sku Standard

# Violation 9: Key Vault access policy with all permissions to secrets
Set-AzKeyVaultAccessPolicy -VaultName "test-keyvault" -ObjectId "12345678-1234-1234-1234-123456789012" -PermissionsToSecrets all

# Violation 10: Key Vault access policy with all permissions to keys
Set-AzKeyVaultAccessPolicy -VaultName "prod-vault" -ObjectId "87654321-4321-4321-4321-210987654321" -PermissionsToKeys "all"

# Violation 11: Key Vault with wildcard permissions
Set-AzKeyVaultAccessPolicy -VaultName "shared-vault" -ObjectId "11111111-2222-3333-4444-555555555555" -PermissionsToSecrets "*"

# Correct usage examples (should not trigger violations)

# Properly secured blob container with private access
New-AzStorageContainer -Name "private-data" -Context $ctx -Permission Off

# SQL firewall rule with specific IP range
New-AzSqlServerFirewallRule -ResourceGroupName "test-rg" -ServerName "testserver" -FirewallRuleName "OfficeAccess" -StartIpAddress "192.168.1.0" -EndIpAddress "192.168.1.255"

# NSG rule with specific source
Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name "Allow-Office" -Access Allow -Protocol Tcp -Direction Inbound -Priority 200 -SourceAddressPrefix "192.168.1.0/24" -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 443

# Public IP for development (should not trigger)
New-AzPublicIpAddress -ResourceGroupName "dev-rg" -Name "dev-test-ip" -Location "East US" -AllocationMethod Dynamic

# Key Vault with minimal permissions
Set-AzKeyVaultAccessPolicy -VaultName "secure-vault" -ObjectId "99999999-8888-7777-6666-555555555555" -PermissionsToSecrets @("Get", "List") -PermissionsToKeys @("Get")

# Using managed identity (no credentials needed)
$identity = Get-AzUserAssignedIdentity -ResourceGroupName "test-rg" -Name "test-identity"

# Private endpoint configuration
$privateEndpoint = New-AzPrivateEndpoint -ResourceGroupName "secure-rg" -Name "storage-pe" -Location "East US" -Subnet $subnet -PrivateLinkServiceConnection $plsConnection