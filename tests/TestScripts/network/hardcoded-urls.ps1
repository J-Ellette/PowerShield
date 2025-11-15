# Test script for HardcodedURLs rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Hardcoded production API endpoint
$productionApi = "https://api.production.company.com"

# ❌ VIOLATION: Hardcoded database connection string with URL
$connectionString = "Server=prod-db.company.com;Database=Production;Integrated Security=true"

# ❌ VIOLATION: Hardcoded internal service URL
Invoke-RestMethod -Uri "https://internal-api.company.local/v1/users"

# ❌ VIOLATION: Hardcoded IP address
$serverIp = "192.168.1.100"
$apiEndpoint = "http://$serverIp/api/data"

# ✅ SAFE: Using environment variable or configuration (should not be flagged)
$apiUrl = $env:API_ENDPOINT
if ($apiUrl) {
    Invoke-RestMethod -Uri $apiUrl
}
