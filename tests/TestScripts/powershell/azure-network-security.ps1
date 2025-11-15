# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These configurations are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure Network Security violations
# These patterns represent network security misconfigurations in Azure

# Violation 1: VNet with overly broad address space
$vnet = New-AzVirtualNetwork -ResourceGroupName "test-rg" -Location "East US" -Name "broad-vnet" -AddressPrefix "0.0.0.0/8"

# Violation 2: Subnet without Network Security Group
$subnet = Add-AzVirtualNetworkSubnetConfig -Name "unprotected-subnet" -VirtualNetwork $vnet -AddressPrefix "10.0.1.0/24"

# Violation 3: Application Gateway with weak SSL configuration
$appGw = New-AzApplicationGateway -Name "weak-appgw" -ResourceGroupName "test-rg" -Location "East US" -Sku Standard_Small -GatewayIPConfigurations $gatewayIP -SslPolicy $weakSslPolicy

# Violation 4: Load Balancer with public frontend and no access restrictions
$publicIp = New-AzPublicIpAddress -ResourceGroupName "test-rg" -Name "lb-public-ip" -Location "East US" -AllocationMethod Static
$frontendIP = New-AzLoadBalancerFrontendIpConfig -Name "PublicFrontEnd" -PublicIpAddress $publicIp
$lb = New-AzLoadBalancer -ResourceGroupName "test-rg" -Name "open-lb" -Location "East US" -FrontendIpConfiguration $frontendIP

# Violation 5: VNet peering without traffic restrictions
$peeringConfig = Add-AzVirtualNetworkPeering -Name "unrestricted-peering" -VirtualNetwork $vnet -RemoteVirtualNetworkId "/subscriptions/sub-id/resourceGroups/remote-rg/providers/Microsoft.Network/virtualNetworks/remote-vnet" -AllowForwardedTraffic -AllowGatewayTransit

# Violation 6: Express Route with unencrypted traffic
$erConnection = New-AzExpressRouteConnection -ResourceGroupName "test-rg" -ExpressRouteGatewayName "er-gateway" -Name "unencrypted-connection" -ExpressRouteCircuitId "/subscriptions/sub-id/resourceGroups/circuit-rg/providers/Microsoft.Network/expressRouteCircuits/my-circuit"

# Violation 7: VPN Gateway with weak authentication
$vpnGw = New-AzVirtualNetworkGateway -ResourceGroupName "test-rg" -Location "East US" -Name "weak-vpn" -IpConfigurations $vnetGatewayConfig -GatewayType Vpn -VpnType RouteBased -GatewaySku Basic

# Violation 8: Network Watcher flow logs disabled
$nsg = Get-AzNetworkSecurityGroup -ResourceGroupName "test-rg" -Name "test-nsg"
# No flow log configuration - this is a violation by omission

# Violation 9: DDoS protection not enabled on VNet
$vnetNoDDoS = New-AzVirtualNetwork -ResourceGroupName "test-rg" -Location "East US" -Name "unprotected-vnet" -AddressPrefix "192.168.0.0/16"

# Violation 10: Private endpoint without proper DNS configuration
$privateEndpoint = New-AzPrivateEndpoint -ResourceGroupName "test-rg" -Name "misconfigured-pe" -Location "East US" -Subnet $subnet -PrivateLinkServiceConnection $plsConnection

# Violation 11: Application Security Group with overly broad rules
$asg = New-AzApplicationSecurityGroup -ResourceGroupName "test-rg" -Name "broad-asg" -Location "East US"
$nsgRule = Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name "AllowASG" -Access Allow -Protocol "*" -Direction Inbound -Priority 100 -SourceApplicationSecurityGroup $asg -SourcePortRange "*" -DestinationAddressPrefix "*" -DestinationPortRange "*"

# Violation 12: Traffic Manager with HTTP endpoints
$tmProfile = New-AzTrafficManagerProfile -ResourceGroupName "test-rg" -Name "insecure-tm" -TrafficRoutingMethod Performance -RelativeDnsName "insecure-app" -Ttl 30 -MonitorProtocol HTTP -MonitorPort 80

# Correct usage examples (should not trigger violations)

# Properly sized VNet with appropriate address space
$secureVnet = New-AzVirtualNetwork -ResourceGroupName "secure-rg" -Location "East US" -Name "secure-vnet" -AddressPrefix "10.0.0.0/16"

# Subnet with NSG association
$secureSubnet = Add-AzVirtualNetworkSubnetConfig -Name "protected-subnet" -VirtualNetwork $secureVnet -AddressPrefix "10.0.1.0/24" -NetworkSecurityGroup $nsg

# Application Gateway with strong SSL
$strongSslPolicy = New-AzApplicationGatewaySslPolicy -PolicyType Predefined -PolicyName AppGwSslPolicy20220101S
$secureAppGw = New-AzApplicationGateway -Name "secure-appgw" -ResourceGroupName "secure-rg" -Location "East US" -Sku WAF_v2 -SslPolicy $strongSslPolicy

# Internal Load Balancer (not public)
$internalIP = New-AzLoadBalancerFrontendIpConfig -Name "InternalFrontEnd" -PrivateIpAddress "10.0.0.4" -SubnetId $secureSubnet.Id
$internalLb = New-AzLoadBalancer -ResourceGroupName "secure-rg" -Name "internal-lb" -Location "East US" -FrontendIpConfiguration $internalIP

# VPN Gateway with strong SKU and encryption
$strongVpnGw = New-AzVirtualNetworkGateway -ResourceGroupName "secure-rg" -Location "East US" -Name "strong-vpn" -IpConfigurations $vnetGatewayConfig -GatewayType Vpn -VpnType RouteBased -GatewaySku VpnGw2

# DDoS protection enabled
$ddosProtection = New-AzDdosProtectionPlan -ResourceGroupName "secure-rg" -Name "ddos-plan" -Location "East US"
$protectedVnet = New-AzVirtualNetwork -ResourceGroupName "secure-rg" -Location "East US" -Name "protected-vnet" -AddressPrefix "172.16.0.0/16" -DdosProtectionPlan $ddosProtection

# Traffic Manager with HTTPS monitoring
$secureTmProfile = New-AzTrafficManagerProfile -ResourceGroupName "secure-rg" -Name "secure-tm" -TrafficRoutingMethod Performance -RelativeDnsName "secure-app" -Ttl 30 -MonitorProtocol HTTPS -MonitorPort 443