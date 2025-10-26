#!/usr/bin/env pwsh
# Test script with various secret types for PowerShield secret scanner testing
# NOTE: All secrets in this file are FAKE/EXAMPLE credentials for testing purposes only
# POWERSHIELD-SUPPRESS-FILE: All secrets are intentionally fake for testing

# AWS Credentials
$awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
$awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Azure Storage Connection String
$azureConnection = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=ABC123def456GHI789jkl012MNO345pqr678STU901vwx234YZA567bcd890EFG123hij456KLM789nop012QRS==;"

# GitHub Tokens
$githubPAT = "ghp_1234567890abcdefghijklmnopqrstuv"
$githubOAuth = "gho_1234567890abcdefghijklmnopqrstuv"
$githubFineGrained = "github_pat_11AAAA" + "AAA0Ab" + "cdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# API Keys
$apiKey = "x-api-key: [REDACTED]"
$bearerToken = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

# Private Keys (shortened for testing)
$pemKey = @"
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDExample1234567890
-----END RSA PRIVATE KEY-----
"@

# Database Connection Strings
$sqlServer = "Server=myserver.database.windows.net;Database=mydb;User Id=admin;Password=SecureP@ssw0rd123;"
$postgresql = "postgresql://username:MyP@ssw0rd@localhost:5432/dbname"
$mysql = "mysql://root:MySecretPass@localhost:3306/database"
$mongodb = "mongodb://admin:P@ssw0rd123@cluster.mongodb.net:27017/mydb"

# OAuth Tokens
$oauthClientSecret = "client_secret=1234567890abcdefghijklmnopqrstuvwxyz"
$refreshToken = "refresh_token=abc123.def456.ghi789.jkl012.mno345"

# Cryptocurrency Keys
$bitcoinKey = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss"
$ethereumKey = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# Slack Tokens
# POWERSHIELD-SUPPRESS-NEXT: SlackToken - Test data only
$slackToken = "[REDACTED]"
# POWERSHIELD-SUPPRESS-NEXT: SlackWebhook - Test data only
$slackWebhook = "[REDACTED]"

# Stripe Keys
# POWERSHIELD-SUPPRESS-NEXT: StripeAPIKey - Test data only
$stripeLiveKey = "[REDACTED]"
# POWERSHIELD-SUPPRESS-NEXT: StripeTestKey - Test data only
$stripeTestKey = "[REDACTED]"

# Twilio Credentials
# POWERSHIELD-SUPPRESS-NEXT: TwilioAccountSID - Test data only
$twilioSID = "[REDACTED]"
$twilioAuthToken = "twilio_auth_token=abcdef1234567890abcdef1234567890"

# Google Cloud
$googleAPIKey = "AIzaSyD1234567890abcdefghijklmnopqrstuv"

# JWT Token
$jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Note: These are example/fake credentials for testing purposes only
Write-Host "Test script with various secret patterns loaded"
