# Test script for LogInjection rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Logging user input directly without sanitization
$userInput = Read-Host "Enter your name"
Write-Host "User logged in: $userInput"
Add-Content -Path "C:\Logs\app.log" -Value "Login: $userInput"

# ❌ VIOLATION: Including unsanitized environment variables in logs
$userName = $env:USERNAME
Write-EventLog -LogName Application -Source "MyApp" -EventId 1000 -Message "User: $userName performed action"

# ❌ VIOLATION: Logging with newline injection risk
$comment = $args[0]
"User comment: $comment" | Out-File "C:\Logs\comments.log" -Append

# ❌ VIOLATION: Logging unsanitized exception messages
try {
    # Some operation
} catch {
    $errorMsg = $_.Exception.Message
    Add-Content "C:\Logs\errors.log" "ERROR: $errorMsg"
}

# ❌ VIOLATION: Including request parameters in logs
$requestData = @{
    User = Read-Host "Username"
    Action = Read-Host "Action"
}
Write-Host "Request: User=$($requestData.User), Action=$($requestData.Action)"

# ✅ SAFE: Sanitized logging (should not be flagged)
$input = Read-Host "Enter data"
$sanitized = $input -replace '[\r\n]', '' -replace '[^\w\s-]', ''
Add-Content -Path "C:\Logs\safe.log" -Value "Input: $sanitized"
