# Test script for custom rules detection
# This script contains patterns that should be detected by community custom rules

# Test 1: Clear-Host usage (should be detected by ClearHostDetection)
Clear-Host
Write-Host "Script started"

# Test 2: Another Clear-Host variant using alias
cls

# Test 3: Write-Host usage (should be detected by WriteHostDetection)
Write-Host "Processing data..."
Write-Host "Status: Complete" -ForegroundColor Green

# Test 4: Hardcoded IP addresses (should be detected by HardcodedIPAddress)
$server = "192.168.1.100"
$apiEndpoint = "http://10.0.0.50/api/data"

# Test 5: More hardcoded IPs
Invoke-WebRequest -Uri "http://172.16.0.1/health"
$backupServer = "192.168.100.5"

# Some safe patterns that should NOT be detected
$hostname = "server.domain.com"
$port = 8080
Write-Output "This is safe output"
Write-Verbose "This is safe verbose output"
