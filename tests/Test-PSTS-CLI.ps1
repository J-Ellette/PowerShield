#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Test suite for PowerShield CLI (psts.ps1)
.DESCRIPTION
    Comprehensive tests for the PowerShield CLI wrapper
.NOTES
    Run this script to validate psts.ps1 functionality
#>

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $PSScriptRoot
$testResults = @{
    Passed = 0
    Failed = 0
    Tests = @()
}

# Color helpers
function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = ""
    )
    
    $result = @{
        Name = $TestName
        Passed = $Passed
        Message = $Message
    }
    $testResults.Tests += $result
    
    if ($Passed) {
        $testResults.Passed++
        Write-Host "  ✓ $TestName" -ForegroundColor Green
    } else {
        $testResults.Failed++
        Write-Host "  ✗ $TestName" -ForegroundColor Red
        if ($Message) {
            Write-Host "    $Message" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "PowerShield CLI Tests (psts.ps1)" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

#region Basic CLI Tests

Write-Host "`n[Basic CLI Tests]" -ForegroundColor White

# Test 1: CLI script exists
try {
    $cliPath = Join-Path $scriptRoot "psts.ps1"
    $exists = Test-Path $cliPath
    Write-TestResult "psts.ps1 exists" $exists "psts.ps1 not found at $cliPath"
} catch {
    Write-TestResult "psts.ps1 exists" $false $_.Exception.Message
}

# Test 2: Version command
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") version 2>&1 | Out-String
    $success = $output -match "PowerShield" -and $output -match "Version" -and $output -match "psts"
    Write-TestResult "version command works" ([bool]$success)
} catch {
    Write-TestResult "version command works" $false $_.Exception.Message
}

# Test 3: Help command
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") help 2>&1 | Out-String
    $success = $output -match "USAGE" -and $output -match "analyze" -and $output -match "baseline" -and $output -match "fix"
    Write-TestResult "help command works" ([bool]$success)
} catch {
    Write-TestResult "help command works" $false $_.Exception.Message
}

#endregion

#region Config Commands

Write-Host "`n[Config Commands]" -ForegroundColor White

# Test 4: Config validate
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") config validate 2>&1 | Out-String
    $success = $output -match "Configuration is valid"
    Write-TestResult "config validate works" ([bool]$success)
} catch {
    Write-TestResult "config validate works" $false $_.Exception.Message
}

# Test 5: Config show
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") config show 2>&1 | Out-String
    $success = $output -match '"version"' -or $output -match '"Version"'
    Write-TestResult "config show works" ([bool]$success)
} catch {
    Write-TestResult "config show works" $false $_.Exception.Message
}

# Test 6: Config init
try {
    $testDir = New-Item -ItemType Directory -Path (Join-Path ([System.IO.Path]::GetTempPath()) "psts-test-$(Get-Random)") -Force
    Push-Location $testDir.FullName
    
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") config init 2>&1 | Out-String
    $configCreated = Test-Path (Join-Path $testDir.FullName ".powershield.yml")
    
    Pop-Location
    Remove-Item $testDir -Recurse -Force
    
    Write-TestResult "config init creates file" $configCreated
} catch {
    Pop-Location
    Write-TestResult "config init creates file" $false $_.Exception.Message
}

#endregion

#region Analyze Commands

Write-Host "`n[Analyze Commands]" -ForegroundColor White

# Test 7: Analyze single file
try {
    $testFile = Get-ChildItem -Path (Join-Path $scriptRoot "tests/TestScripts/powershell") -Filter "insecure-hash.ps1" -Recurse | Select-Object -First 1
    if ($testFile) {
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") analyze $testFile.FullName 2>&1 | Out-String
        $success = $output -match "PowerShield Security Analysis Results"
        Write-TestResult "analyze single file works" ([bool]$success)
    } else {
        Write-TestResult "analyze single file works" $false "Test file not found"
    }
} catch {
    Write-TestResult "analyze single file works" $false $_.Exception.Message
}

# Test 8: Analyze with JSON output
try {
    $testFile = Get-ChildItem -Path (Join-Path $scriptRoot "tests/TestScripts/powershell") -Filter "insecure-hash.ps1" -Recurse | Select-Object -First 1
    $outputFile = Join-Path ([System.IO.Path]::GetTempPath()) "psts-test-output.json"
    
    if ($testFile) {
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") analyze $testFile.FullName --format json --output $outputFile 2>&1 | Out-String
        $success = (Test-Path $outputFile) -and (Get-Content $outputFile -Raw) -match '"TotalViolations"'
        
        if (Test-Path $outputFile) {
            Remove-Item $outputFile -Force
        }
        
        Write-TestResult "analyze with JSON output works" $success
    } else {
        Write-TestResult "analyze with JSON output works" $false "Test file not found"
    }
} catch {
    Write-TestResult "analyze with JSON output works" $false $_.Exception.Message
}

# Test 9: Analyze with SARIF output
try {
    $testFile = Get-ChildItem -Path (Join-Path $scriptRoot "tests/TestScripts/powershell") -Filter "insecure-hash.ps1" -Recurse | Select-Object -First 1
    $outputFile = Join-Path ([System.IO.Path]::GetTempPath()) "psts-test-output.sarif"
    
    if ($testFile) {
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") analyze $testFile.FullName --format sarif --output $outputFile 2>&1 | Out-String
        $success = (Test-Path $outputFile) -and (Get-Content $outputFile -Raw) -match '"version".*"2.1.0"'
        
        if (Test-Path $outputFile) {
            Remove-Item $outputFile -Force
        }
        
        Write-TestResult "analyze with SARIF output works" $success
    } else {
        Write-TestResult "analyze with SARIF output works" $false "Test file not found"
    }
} catch {
    Write-TestResult "analyze with SARIF output works" $false $_.Exception.Message
}

# Test 10: Analyze with markdown output
try {
    $testFile = Get-ChildItem -Path (Join-Path $scriptRoot "tests/TestScripts/powershell") -Filter "insecure-hash.ps1" -Recurse | Select-Object -First 1
    $outputFile = Join-Path ([System.IO.Path]::GetTempPath()) "psts-test-output.md"
    
    if ($testFile) {
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") analyze $testFile.FullName --format markdown --output $outputFile 2>&1 | Out-String
        $success = (Test-Path $outputFile) -and (Get-Content $outputFile -Raw) -match '#.*Security'
        
        if (Test-Path $outputFile) {
            Remove-Item $outputFile -Force
        }
        
        Write-TestResult "analyze with markdown output works" $success
    } else {
        Write-TestResult "analyze with markdown output works" $false "Test file not found"
    }
} catch {
    Write-TestResult "analyze with markdown output works" $false $_.Exception.Message
}

#endregion

#region Baseline Commands

Write-Host "`n[Baseline Commands]" -ForegroundColor White

# Test 11: Baseline create
try {
    $testDir = New-Item -ItemType Directory -Path (Join-Path ([System.IO.Path]::GetTempPath()) "psts-baseline-test-$(Get-Random)") -Force
    Push-Location $testDir.FullName
    
    $testFile = Get-ChildItem -Path (Join-Path $scriptRoot "tests/TestScripts/powershell") -Filter "insecure-hash.ps1" -Recurse | Select-Object -First 1
    
    if ($testFile) {
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") baseline create $testFile.FullName 2>&1 | Out-String
        $baselineCreated = Test-Path (Join-Path $testDir.FullName ".powershield-baseline.json")
        
        Pop-Location
        Remove-Item $testDir -Recurse -Force
        
        Write-TestResult "baseline create works" $baselineCreated
    } else {
        Pop-Location
        Remove-Item $testDir -Recurse -Force
        Write-TestResult "baseline create works" $false "Test file not found"
    }
} catch {
    Pop-Location
    Write-TestResult "baseline create works" $false $_.Exception.Message
}

# Test 12: Baseline compare
try {
    $testDir = New-Item -ItemType Directory -Path (Join-Path ([System.IO.Path]::GetTempPath()) "psts-baseline-test-$(Get-Random)") -Force
    Push-Location $testDir.FullName
    
    $testFile = Get-ChildItem -Path (Join-Path $scriptRoot "tests/TestScripts/powershell") -Filter "insecure-hash.ps1" -Recurse | Select-Object -First 1
    
    if ($testFile) {
        # Create baseline first
        $null = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") baseline create $testFile.FullName 2>&1
        
        # Compare
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") baseline compare $testFile.FullName 2>&1 | Out-String
        $success = $output -match "Baseline Comparison Results"
        
        Pop-Location
        Remove-Item $testDir -Recurse -Force
        
        Write-TestResult "baseline compare works" ([bool]$success)
    } else {
        Pop-Location
        Remove-Item $testDir -Recurse -Force
        Write-TestResult "baseline compare works" $false "Test file not found"
    }
} catch {
    Pop-Location
    Write-TestResult "baseline compare works" $false $_.Exception.Message
}

# Test 13: Baseline with custom output file
try {
    $testDir = New-Item -ItemType Directory -Path (Join-Path ([System.IO.Path]::GetTempPath()) "psts-baseline-test-$(Get-Random)") -Force
    Push-Location $testDir.FullName
    
    $testFile = Get-ChildItem -Path (Join-Path $scriptRoot "tests/TestScripts/powershell") -Filter "insecure-hash.ps1" -Recurse | Select-Object -First 1
    $customBaseline = "custom-baseline.json"
    
    if ($testFile) {
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") baseline create $testFile.FullName --output $customBaseline 2>&1 | Out-String
        $baselineCreated = Test-Path (Join-Path $testDir.FullName $customBaseline)
        
        Pop-Location
        Remove-Item $testDir -Recurse -Force
        
        Write-TestResult "baseline with custom output works" $baselineCreated
    } else {
        Pop-Location
        Remove-Item $testDir -Recurse -Force
        Write-TestResult "baseline with custom output works" $false "Test file not found"
    }
} catch {
    Pop-Location
    Write-TestResult "baseline with custom output works" $false $_.Exception.Message
}

#endregion

#region Fix Commands

Write-Host "`n[Fix Commands]" -ForegroundColor White

# Test 14: Fix preview
try {
    $testFile = Get-ChildItem -Path (Join-Path $scriptRoot "tests/TestScripts/powershell") -Filter "insecure-hash.ps1" -Recurse | Select-Object -First 1
    
    if ($testFile) {
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") fix preview $testFile.FullName 2>&1 | Out-String
        $success = $output -match "Fix Preview" -and $output -match "Fixable"
        Write-TestResult "fix preview works" ([bool]$success)
    } else {
        Write-TestResult "fix preview works" $false "Test file not found"
    }
} catch {
    Write-TestResult "fix preview works" $false $_.Exception.Message
}

# Test 15: Fix preview with confidence threshold
try {
    $testFile = Get-ChildItem -Path (Join-Path $scriptRoot "tests/TestScripts/powershell") -Filter "insecure-hash.ps1" -Recurse | Select-Object -First 1
    
    if ($testFile) {
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") fix preview $testFile.FullName --confidence 0.9 2>&1 | Out-String
        $success = $output -match "Confidence Threshold: 0.9"
        Write-TestResult "fix preview with confidence threshold works" ([bool]$success)
    } else {
        Write-TestResult "fix preview with confidence threshold works" $false "Test file not found"
    }
} catch {
    Write-TestResult "fix preview with confidence threshold works" $false $_.Exception.Message
}

# Test 16: Fix apply shows instructions
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") fix apply 2>&1 | Out-String
    $success = $output -match "confidence" -or $output -match "GitHub Actions"
    Write-TestResult "fix apply shows instructions" ([bool]$success)
} catch {
    Write-TestResult "fix apply shows instructions" $false $_.Exception.Message
}

#endregion

#region Error Handling

Write-Host "`n[Error Handling]" -ForegroundColor White

# Test 17: Invalid command
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") invalid-command 2>&1 | Out-String
    $success = $output -match "Unknown command" -or $output -match "does not belong to the set"
    Write-TestResult "invalid command shows error" ([bool]$success)
} catch {
    Write-TestResult "invalid command shows error" $false $_.Exception.Message
}

# Test 18: Missing subcommand for config
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") config 2>&1 | Out-String
    $success = $output -match "required"
    Write-TestResult "missing config subcommand shows error" ([bool]$success)
} catch {
    Write-TestResult "missing config subcommand shows error" $false $_.Exception.Message
}

# Test 19: Invalid path for analyze
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "psts.ps1") analyze /nonexistent/path 2>&1 | Out-String
    $success = $output -match "not found"
    Write-TestResult "invalid path shows error" ([bool]$success)
} catch {
    Write-TestResult "invalid path shows error" $false $_.Exception.Message
}

#endregion

#region Interactive Mode

Write-Host "`n[Interactive Mode]" -ForegroundColor White

# Test 20: Interactive mode starts
try {
    $output = & pwsh -NoProfile -Command "echo '7' | pwsh -NoProfile -File $(Join-Path $scriptRoot 'psts.ps1') interactive" 2>&1 | Out-String
    $success = $output -match "PowerShield Interactive Mode" -and $output -match "What would you like to do"
    Write-TestResult "interactive mode starts correctly" ([bool]$success)
} catch {
    Write-TestResult "interactive mode starts correctly" $false $_.Exception.Message
}

#endregion

#region Summary

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Test Results Summary" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

Write-Host "`nTotal Tests: $($testResults.Tests.Count)" -ForegroundColor White
Write-Host "Passed: $($testResults.Passed)" -ForegroundColor Green
Write-Host "Failed: $($testResults.Failed)" -ForegroundColor $(if ($testResults.Failed -eq 0) { 'Green' } else { 'Red' })

if ($testResults.Failed -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    foreach ($test in $testResults.Tests | Where-Object { -not $_.Passed }) {
        Write-Host "  • $($test.Name)" -ForegroundColor Red
        if ($test.Message) {
            Write-Host "    $($test.Message)" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

# Exit with appropriate code
exit $(if ($testResults.Failed -eq 0) { 0 } else { 1 })

#endregion
