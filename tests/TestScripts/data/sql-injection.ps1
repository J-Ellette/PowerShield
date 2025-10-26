# Test script for SQLInjection rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Direct string concatenation in SQL query
$userId = Read-Host "Enter user ID"
$query = "SELECT * FROM Users WHERE UserId = $userId"
Invoke-Sqlcmd -Query $query

# ❌ VIOLATION: Building SQL with user input
$username = $args[0]
$sqlCommand = "DELETE FROM Accounts WHERE Username = '$username'"
Invoke-Sqlcmd -Query $sqlCommand -ServerInstance "localhost"

# ❌ VIOLATION: Unsafe dynamic SQL construction
$table = Read-Host "Table name"
$condition = Read-Host "WHERE condition"
$sql = "SELECT * FROM $table WHERE $condition"
Invoke-Sqlcmd -Query $sql

# ❌ VIOLATION: String interpolation in SQL with user data
$email = $env:USER_EMAIL
$updateSql = "UPDATE Users SET LastLogin = GETDATE() WHERE Email = '$email'"
Invoke-Sqlcmd -Query $updateSql

# ✅ SAFE: Using parameterized queries (should not be flagged)
$safeQuery = "SELECT * FROM Users WHERE UserId = @UserId"
$parameters = @{ UserId = $userId }
# Note: This is simplified - actual parameterized queries would use different cmdlets
Invoke-Sqlcmd -Query $safeQuery
