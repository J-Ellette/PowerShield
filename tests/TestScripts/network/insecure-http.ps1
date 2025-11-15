# Test script for InsecureHTTP rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Using unencrypted HTTP
$response = Invoke-RestMethod -Uri "http://api.example.com/data"

# ❌ VIOLATION: Using HTTP in Invoke-WebRequest
$webData = Invoke-WebRequest -Uri "http://insecure.example.com/endpoint"

# ❌ VIOLATION: HTTP URL in variable
$apiUrl = "http://api.internal.company.com/users"
$result = Invoke-RestMethod -Uri $apiUrl

# ✅ SAFE: Using HTTPS (should not be flagged)
$secureResponse = Invoke-RestMethod -Uri "https://api.example.com/data"
