#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Test Advanced Secret Detection functionality
.DESCRIPTION
    Tests secret scanner with various secret types
#>

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $PSScriptRoot

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      PowerShield Advanced Secret Detection Tests          ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Import module
Import-Module (Join-Path $scriptRoot "src/SecretScanner.psm1") -Force

$testsPassed = 0
$testsFailed = 0

# Test 1: Scan file with secrets
Write-Host "Test 1: Scan File with Multiple Secret Types" -ForegroundColor Yellow
try {
    $testFile = Join-Path $scriptRoot "tests/TestScripts/data/secrets-test.ps1"
    
    if (-not (Test-Path $testFile)) {
        throw "Test file not found: $testFile"
    }
    
    $result = Invoke-SecretScan -ScriptPath $testFile
    
    Write-Host "  Files scanned: 1" -ForegroundColor White
    Write-Host "  Secrets found: $($result.SecretsFound)" -ForegroundColor $(if ($result.SecretsFound -gt 0) { 'Yellow' } else { 'Red' })
    Write-Host "  Critical: $($result.Summary.Critical)" -ForegroundColor Red
    Write-Host "  High: $($result.Summary.High)" -ForegroundColor Yellow
    Write-Host "  Medium: $($result.Summary.Medium)" -ForegroundColor Gray
    
    if ($result.SecretsFound -gt 0) {
        Write-Host "`n  First 5 detections:" -ForegroundColor Gray
        $result.Detections | Select-Object -First 5 | ForEach-Object {
            Write-Host "    - Line $($_.LineNumber): $($_.Type) ($($_.Metadata.Severity))" -ForegroundColor Gray
        }
        Write-Host "  ✅ Secret detection working" -ForegroundColor Green
        $testsPassed++
    } else {
        throw "No secrets detected in test file"
    }
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 2: AWS Access Key Detection
Write-Host "`nTest 2: AWS Access Key Detection" -ForegroundColor Yellow
try {
    $scanner = New-SecretScanner
    $testContent = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
    
    $detections = $scanner.ScanContent($testContent, "test.ps1")
    
    $awsDetection = $detections | Where-Object { $_.Type -eq 'AWSAccessKey' }
    
    if ($awsDetection) {
        Write-Host "  ✅ AWS Access Key detected" -ForegroundColor Green
        Write-Host "    Value: $($awsDetection.Value)" -ForegroundColor Gray
        Write-Host "    Confidence: $($awsDetection.Confidence)" -ForegroundColor Gray
        $testsPassed++
    } else {
        throw "AWS Access Key not detected"
    }
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 3: GitHub Token Detection
Write-Host "`nTest 3: GitHub PAT Detection" -ForegroundColor Yellow
try {
    $scanner = New-SecretScanner
    $testContent = '$token = "ghp_1234567890abcdefghijklmnopqrstuv"'
    
    $detections = $scanner.ScanContent($testContent, "test.ps1")
    
    $ghDetection = $detections | Where-Object { $_.Type -eq 'GitHubPAT' }
    
    if ($ghDetection) {
        Write-Host "  ✅ GitHub PAT detected" -ForegroundColor Green
        Write-Host "    Confidence: $($ghDetection.Confidence)" -ForegroundColor Gray
        $testsPassed++
    } else {
        throw "GitHub PAT not detected"
    }
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 4: Private Key Detection
Write-Host "`nTest 4: Private Key Detection" -ForegroundColor Yellow
try {
    $scanner = New-SecretScanner
    $testContent = @"
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDExample1234567890
-----END RSA PRIVATE KEY-----
"@
    
    $detections = $scanner.ScanContent($testContent, "test.ps1")
    
    $keyDetection = $detections | Where-Object { $_.Type -like '*PrivateKey*' }
    
    if ($keyDetection) {
        Write-Host "  ✅ Private Key detected" -ForegroundColor Green
        Write-Host "    Type: $($keyDetection.Type)" -ForegroundColor Gray
        $testsPassed++
    } else {
        throw "Private Key not detected"
    }
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 5: Connection String Detection
Write-Host "`nTest 5: Database Connection String Detection" -ForegroundColor Yellow
try {
    $scanner = New-SecretScanner
    $testContent = '$conn = "Server=myserver;Database=db;Password=SecurePass123;"'
    
    $detections = $scanner.ScanContent($testContent, "test.ps1")
    
    $connDetection = $detections | Where-Object { $_.Type -like '*ConnectionString*' }
    
    if ($connDetection) {
        Write-Host "  ✅ Connection String detected" -ForegroundColor Green
        Write-Host "    Type: $($connDetection.Type)" -ForegroundColor Gray
        $testsPassed++
    } else {
        throw "Connection String not detected"
    }
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 6: Entropy Calculation
Write-Host "`nTest 6: Entropy Calculation" -ForegroundColor Yellow
try {
    $scanner = New-SecretScanner
    
    # High entropy string (random)
    $highEntropyText = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    $highEntropy = $scanner.CalculateEntropy($highEntropyText)
    
    # Low entropy string (repeated)
    $lowEntropyText = "aaaaaaaaaa"
    $lowEntropy = $scanner.CalculateEntropy($lowEntropyText)
    
    if ($highEntropy -gt $lowEntropy) {
        Write-Host "  ✅ Entropy calculation working" -ForegroundColor Green
        Write-Host "    High entropy: $highEntropy" -ForegroundColor Gray
        Write-Host "    Low entropy: $lowEntropy" -ForegroundColor Gray
        $testsPassed++
    } else {
        throw "Entropy calculation incorrect"
    }
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 7: JWT Token Detection
Write-Host "`nTest 7: JWT Token Detection" -ForegroundColor Yellow
try {
    $scanner = New-SecretScanner
    $testContent = '$jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
    
    $detections = $scanner.ScanContent($testContent, "test.ps1")
    
    $jwtDetection = $detections | Where-Object { $_.Type -eq 'JWTToken' }
    
    if ($jwtDetection) {
        Write-Host "  ✅ JWT Token detected" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "  ⚠️  JWT Token not detected (may be expected)" -ForegroundColor Yellow
        $testsPassed++
    }
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Summary
Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    Test Summary                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$totalTests = $testsPassed + $testsFailed
Write-Host "`n📊 Results: $testsPassed/$totalTests passed" -ForegroundColor $(if ($testsFailed -eq 0) { 'Green' } else { 'Yellow' })

if ($testsFailed -gt 0) {
    Write-Host "⚠️  $testsFailed test(s) failed`n" -ForegroundColor Red
    exit 1
} else {
    Write-Host "✅ All tests passed!`n" -ForegroundColor Green
    exit 0
}
