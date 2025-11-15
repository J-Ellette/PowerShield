#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Integration test for VS Code Extension PowerShell integration
.DESCRIPTION
    Tests the PowerShieldEngine's ability to analyze PowerShell scripts
#>

Write-Host "=== PowerShield VS Code Extension Integration Test ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: Verify PowerShell modules exist
Write-Host "Test 1: Checking PowerShell modules..." -ForegroundColor Yellow
$analyzerPath = "$PSScriptRoot/../src/PowerShellSecurityAnalyzer.psm1"
$vscodePath = "$PSScriptRoot/../src/VSCodeIntegration.psm1"

if (-not (Test-Path $analyzerPath)) {
    Write-Host "❌ FAIL: PowerShellSecurityAnalyzer.psm1 not found at $analyzerPath" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $vscodePath)) {
    Write-Host "❌ FAIL: VSCodeIntegration.psm1 not found at $vscodePath" -ForegroundColor Red
    exit 1
}
Write-Host "✅ PASS: PowerShell modules found" -ForegroundColor Green
Write-Host ""

# Test 2: Import modules
Write-Host "Test 2: Importing PowerShell modules..." -ForegroundColor Yellow
try {
    Import-Module $analyzerPath -Force -ErrorAction Stop
    Import-Module $vscodePath -Force -ErrorAction Stop
    Write-Host "✅ PASS: Modules imported successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ FAIL: Failed to import modules: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 3: Create test script with security violation
Write-Host "Test 3: Creating test script with security violation..." -ForegroundColor Yellow
$testScript = @'
# Test script with MD5 usage (security violation)
$hash = [System.Security.Cryptography.MD5]::Create()
$bytes = [System.Text.Encoding]::UTF8.GetBytes("test")
$hashValue = $hash.ComputeHash($bytes)
Write-Host "Hash: $([BitConverter]::ToString($hashValue))"
'@

# POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Legitimate temporary file usage for test integration (2026-12-31)
$testFile = [System.IO.Path]::GetTempFileName() + ".ps1"
$testScript | Out-File -FilePath $testFile -Encoding utf8
Write-Host "✅ PASS: Test script created at $testFile" -ForegroundColor Green
Write-Host ""

# Test 4: Analyze test script
Write-Host "Test 4: Running security analysis..." -ForegroundColor Yellow
try {
    $analyzer = New-SecurityAnalyzer
    $result = Invoke-SecurityAnalysis -ScriptPath $testFile
    
    if ($result.Violations -and $result.Violations.Count -gt 0) {
        Write-Host "✅ PASS: Analysis detected $($result.Violations.Count) violation(s)" -ForegroundColor Green
        Write-Host "  First violation: $($result.Violations[0].Name)" -ForegroundColor Gray
    } else {
        Write-Host "⚠️  WARNING: No violations detected (expected at least 1)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ FAIL: Analysis failed: $_" -ForegroundColor Red
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    exit 1
}
Write-Host ""

# Test 5: Convert to VS Code diagnostics format
Write-Host "Test 5: Converting to VS Code diagnostics..." -ForegroundColor Yellow
try {
    $integration = New-VSCodeIntegration
    $diagnostics = $integration.ConvertToDiagnostics($result.Violations, $testFile)
    
    if ($diagnostics -and $diagnostics.Count -gt 0) {
        Write-Host "✅ PASS: Converted to $($diagnostics.Count) diagnostic(s)" -ForegroundColor Green
        Write-Host "  Diagnostic format: message=$($diagnostics[0].message)" -ForegroundColor Gray
        Write-Host "  Severity: $($diagnostics[0].severity)" -ForegroundColor Gray
    } else {
        Write-Host "❌ FAIL: No diagnostics generated" -ForegroundColor Red
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        exit 1
    }
} catch {
    Write-Host "❌ FAIL: Diagnostic conversion failed: $_" -ForegroundColor Red
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    exit 1
}
Write-Host ""

# Test 6: Export to JSON (format used by TypeScript extension)
Write-Host "Test 6: Exporting to JSON format..." -ForegroundColor Yellow
try {
    $json = $diagnostics | ConvertTo-Json -Depth 10 -Compress
    
    if ($json -and $json.Length -gt 0) {
        Write-Host "✅ PASS: JSON export successful" -ForegroundColor Green
        Write-Host "  JSON length: $($json.Length) characters" -ForegroundColor Gray
        
        # Verify it's valid JSON
        $parsed = $json | ConvertFrom-Json
        if ($parsed) {
            Write-Host "  ✅ JSON is valid and parseable" -ForegroundColor Gray
        }
    } else {
        Write-Host "❌ FAIL: JSON export empty" -ForegroundColor Red
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        exit 1
    }
} catch {
    Write-Host "❌ FAIL: JSON export failed: $_" -ForegroundColor Red
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    exit 1
}
Write-Host ""

# Cleanup
Remove-Item $testFile -Force -ErrorAction SilentlyContinue

# Summary
Write-Host "=== All Integration Tests Passed! ===" -ForegroundColor Green
Write-Host ""
Write-Host "The VS Code extension should be able to:" -ForegroundColor Cyan
Write-Host "  ✅ Load PowerShell analyzer modules" -ForegroundColor White
Write-Host "  ✅ Analyze PowerShell scripts for violations" -ForegroundColor White
Write-Host "  ✅ Convert violations to VS Code diagnostics" -ForegroundColor White
Write-Host "  ✅ Export results as JSON for TypeScript consumption" -ForegroundColor White
Write-Host ""
Write-Host "Next: Test the extension in VS Code!" -ForegroundColor Yellow
