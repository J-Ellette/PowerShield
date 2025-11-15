# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for Azure Compute Security Violations
# Rule 42: AzureComputeSecurityViolations

# Violation 1: VM with public IP and RDP open
New-AzVm -ResourceGroupName "RG-Test" -Name "vm-public-rdp" -Location "eastus" -PublicIpAddressName "public-ip-1" -OpenPorts 3389

# Violation 2: VM with public IP and SSH open
New-AzVM -ResourceGroupName "RG-Prod" -Name "vm-ssh" -PublicIpAddress "pip-vm" -OpenPorts 22 -Image UbuntuLTS

# Violation 3: VM with both RDP and SSH open
New-AzVm -ResourceGroupName "RG-Web" -Name "web-server" -PublicIpAddressName "web-public-ip" -OpenPorts @(22, 3389, 80, 443)

# Violation 4: Windows VM with public IP and open RDP
New-AzVM -ResourceGroupName "RG-Windows" -Name "win-vm-01" -PublicIpAddressName "win-pip" -OpenPorts @(3389) -Credential $cred

# Violation 5: Setting custom script VM extension
Set-AzVMExtension -ResourceGroupName "RG-VM" -VMName "vm1" -Name "CustomScript" -ExtensionType "CustomScript" -Publisher "Microsoft.Compute" -TypeHandlerVersion "1.10" -Settings $settings

# Violation 6: Linux custom script extension
Set-AzVMExtension -ResourceGroupName "RG-Linux" -VMName "linux-vm" -Name "LinuxCustomScript" -Publisher "Microsoft.Azure.Extensions" -ExtensionType "CustomScript" -TypeHandlerVersion "2.0"

# Violation 7: Custom script extension with download
Set-AzVMExtension -VMName "vm-test" -ResourceGroupName "RG" -ExtensionType "CustomScript" -Name "Script" -FileUri "https://example.com/script.ps1"

# Violation 8: Adding data disk without encryption
Add-AzVMDataDisk -VM $vm -Name "datadisk1" -DiskSizeInGB 128 -Lun 0 -CreateOption Empty

# Violation 9: Multiple data disks without encryption
Add-AzVMDataDisk -VM $vmConfig -Name "disk2" -DiskSizeInGB 256 -Lun 1 -Caching ReadWrite

# Violation 10: Premium disk without encryption
Add-AzVMDataDisk -VM $vm -Name "premium-disk" -DiskSizeInGB 512 -StorageAccountType Premium_LRS -Lun 2 -CreateOption Empty

# Violation 11: Setting Linux VM OS with password authentication enabled
Set-AzVMOperatingSystem -VM $vm -Linux -ComputerName "linux-host" -Credential $cred -DisablePasswordAuthentication $false

# Violation 12: Linux VM allowing password auth
$vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Linux -ComputerName "server01" -Credential $linuxCred -DisablePasswordAuthentication:$false

# Violation 13: Creating privileged container group
$container = New-AzContainerGroup -ResourceGroupName "RG-Containers" -Name "privileged-container" -Image "nginx:latest" -OsType Linux -Privileged

# Violation 14: Container with privileged flag in command
New-AzContainerGroup -ResourceGroupName "RG-App" -Name "app-container" -Image "myapp:latest" -Command @("--privileged", "run")

# Violation 15: Container group with privileged configuration
$containerDef = @{
    Name = "privContainer"
    Image = "ubuntu:latest"
    Command = @("/bin/bash", "-c", "docker run --privileged myimage")
}
New-AzContainerGroup -ResourceGroupName "RG" -Name "container-priv" -Container $containerDef -OsType Linux

# Correct usage examples (should not trigger violations)
# VM without public IP
New-AzVm -ResourceGroupName "RG-Private" -Name "private-vm" -Location "eastus"

# VM with Azure Bastion (no direct RDP/SSH)
New-AzVM -ResourceGroupName "RG-Secure" -Name "bastion-vm" -Location "westus" -Image Win2019Datacenter

# Data disk with encryption
$diskConfig = New-AzDiskConfig -Location "eastus" -CreateOption Empty -DiskSizeGB 128 -DiskEncryptionSetId $desId
Add-AzVMDataDisk -VM $vm -Name "encrypted-disk" -DiskEncryptionSetId $encryptionSetId -Lun 0

# Linux VM with SSH key only (password auth disabled)
Set-AzVMOperatingSystem -VM $vm -Linux -ComputerName "secure-linux" -Credential $cred -DisablePasswordAuthentication $true

# Standard container (not privileged)
New-AzContainerGroup -ResourceGroupName "RG-App" -Name "standard-container" -Image "nginx:latest" -OsType Linux -Port 80

# VM extension for monitoring (not custom script)
Set-AzVMExtension -ResourceGroupName "RG" -VMName "vm1" -Name "AzureMonitor" -ExtensionType "AzureMonitorWindowsAgent" -Publisher "Microsoft.Azure.Monitor"

# Reading VM configuration
Get-AzVM -ResourceGroupName "RG-Prod" -Name "vm1"
