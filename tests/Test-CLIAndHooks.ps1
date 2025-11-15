#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Test suite for PowerShield CLI and pre-commit hooks
.DESCRIPTION
    Validates CLI commands and pre-commit hook functionality
.NOTES
    Run this script to validate the installation
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
Write-Host "PowerShield CLI and Hook Tests" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

#region CLI Tests

Write-Host "`n[CLI Tests]" -ForegroundColor White

# Test 1: CLI exists
try {
    $cliPath = Join-Path $scriptRoot "powershield.ps1"
    $exists = Test-Path $cliPath
    Write-TestResult "CLI script exists" $exists "powershield.ps1 not found at $cliPath"
} catch {
    Write-TestResult "CLI script exists" $false $_.Exception.Message
}

# Test 2: Version command
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "powershield.ps1") version 2>&1 | Out-String
    $success = $output -match "PowerShield" -and $output -match "Version"
    Write-TestResult "Version command works" ([bool]$success)
} catch {
    Write-TestResult "Version command works" $false $_.Exception.Message
}

# Test 3: Help command
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "powershield.ps1") help 2>&1 | Out-String
    $success = $output -match "USAGE"
    Write-TestResult "Help command works" ([bool]$success)
} catch {
    Write-TestResult "Help command works" $false $_.Exception.Message
}

# Test 4: Config validate
try {
    $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "powershield.ps1") config validate 2>&1 | Out-String
    $success = $output -match "Configuration is valid"
    Write-TestResult "Config validate works" ([bool]$success)
} catch {
    Write-TestResult "Config validate works" $false $_.Exception.Message
}

# Test 5: Analyze command on test file
try {
    $testFile = Get-ChildItem -Path (Join-Path $scriptRoot "tests/TestScripts") -Filter "*.ps1" -Recurse | Select-Object -First 1
    if ($testFile) {
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "powershield.ps1") analyze $testFile.FullName 2>&1 | Out-String
        $success = $output -match "PowerShield Security Analysis Results"
        Write-TestResult "Analyze command works" ([bool]$success)
    } else {
        Write-TestResult "Analyze command works" $false "No test files found"
    }
} catch {
    Write-TestResult "Analyze command works" $false $_.Exception.Message
}

#endregion

#region Hook Tests

Write-Host "`n[Hook Tests]" -ForegroundColor White

# Test 6: Hook source exists
try {
    $hookSource = Join-Path $scriptRoot ".powershield/hooks/pre-commit"
    $exists = Test-Path $hookSource
    Write-TestResult "Hook source exists" $exists "pre-commit hook not found at $hookSource"
} catch {
    Write-TestResult "Hook source exists" $false $_.Exception.Message
}

# Test 7: Hook installation
try {
    # Check if we're in a git repo
    $gitDir = git -C $scriptRoot rev-parse --git-dir 2>&1
    if ($LASTEXITCODE -eq 0) {
        # Install hook
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "powershield.ps1") install-hooks -Force 2>&1 | Out-String
        
        # Check output for errors
        $hasError = $output -match "error|failed" -and $output -notmatch "Pre-commit hook installed successfully"
        
        # Check if installed
        $hookPath = Join-Path $scriptRoot ".git/hooks/pre-commit"
        $installed = Test-Path $hookPath
        
        Write-TestResult "Hook installation works" ($installed -and -not $hasError)
    } else {
        Write-TestResult "Hook installation works" $false "Not a git repository"
    }
} catch {
    Write-TestResult "Hook installation works" $false $_.Exception.Message
}

# Test 8: Hook uninstallation
try {
    $gitDir = git -C $scriptRoot rev-parse --git-dir 2>&1
    if ($LASTEXITCODE -eq 0) {
        # Uninstall hook
        $output = & pwsh -NoProfile -File (Join-Path $scriptRoot "powershield.ps1") uninstall-hooks 2>&1 | Out-String
        
        # Check output for errors
        $hasError = $output -match "error|failed" -and $output -notmatch "uninstalled successfully"
        
        # Check if removed
        $hookPath = Join-Path $scriptRoot ".git/hooks/pre-commit"
        $removed = -not (Test-Path $hookPath)
        
        Write-TestResult "Hook uninstallation works" ($removed -and -not $hasError)
    } else {
        Write-TestResult "Hook uninstallation works" $false "Not a git repository"
    }
} catch {
    Write-TestResult "Hook uninstallation works" $false $_.Exception.Message
}

#endregion

#region Configuration Tests

Write-Host "`n[Configuration Tests]" -ForegroundColor White

# Test 9: ConfigLoader module loads
try {
    Import-Module (Join-Path $scriptRoot "src/ConfigLoader.psm1") -Force -ErrorAction Stop
    Write-TestResult "ConfigLoader module loads" $true
} catch {
    Write-TestResult "ConfigLoader module loads" $false $_.Exception.Message
}

# Test 10: Configuration includes hooks section
try {
    $config = Import-PowerShieldConfiguration -WorkspacePath $scriptRoot
    $hasHooks = $null -ne $config.Hooks
    Write-TestResult "Configuration has hooks section" $hasHooks
    
    if ($hasHooks) {
        # Use property access instead of ContainsKey for more robust checking
        $hasEnabled = $null -ne $config.Hooks.enabled
        $hasBlockOn = $null -ne $config.Hooks.block_on
        $bothPresent = $hasEnabled -and $hasBlockOn
        
        # Also verify they have expected types
        $enabledIsBoolean = $config.Hooks.enabled -is [bool]
        $blockOnIsArray = $config.Hooks.block_on -is [array]
        $typesCorrect = $enabledIsBoolean -and $blockOnIsArray
        
        Write-TestResult "Hook config has required fields" ($bothPresent -and $typesCorrect)
    } else {
        Write-TestResult "Hook config has required fields" $false "Hooks section missing"
    }
} catch {
    Write-TestResult "Configuration has hooks section" $false $_.Exception.Message
    Write-TestResult "Hook config has required fields" $false $_.Exception.Message
}

#endregion

#region Documentation Tests

Write-Host "`n[Documentation Tests]" -ForegroundColor White

# Test 11: Hook guide exists
try {
    $guidePath = Join-Path $scriptRoot "docs/PRE_COMMIT_HOOK_GUIDE.md"
    $exists = Test-Path $guidePath
    Write-TestResult "Pre-commit hook guide exists" $exists
} catch {
    Write-TestResult "Pre-commit hook guide exists" $false $_.Exception.Message
}

# Test 12: README mentions hooks
try {
    $readmePath = Join-Path $scriptRoot "README.md"
    $content = Get-Content $readmePath -Raw
    $mentions = $content -match "pre-commit|hook"
    Write-TestResult "README mentions hooks" $mentions
} catch {
    Write-TestResult "README mentions hooks" $false $_.Exception.Message
}

# Test 13: Example config includes hooks
try {
    $examplePath = Join-Path $scriptRoot ".powershield.yml.example"
    $content = Get-Content $examplePath -Raw
    $hasHooks = $content -match "hooks:"
    Write-TestResult "Example config includes hooks" $hasHooks
} catch {
    Write-TestResult "Example config includes hooks" $false $_.Exception.Message
}

#endregion

#region Summary

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Test Results Summary" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

$total = $testResults.Passed + $testResults.Failed
Write-Host "`nTotal Tests: $total" -ForegroundColor White
Write-Host "Passed: $($testResults.Passed)" -ForegroundColor Green
Write-Host "Failed: $($testResults.Failed)" -ForegroundColor Red

$percentage = if ($total -gt 0) { [math]::Round(($testResults.Passed / $total) * 100, 1) } else { 0 }
Write-Host "Success Rate: $percentage%" -ForegroundColor $(if ($percentage -eq 100) { 'Green' } elseif ($percentage -ge 80) { 'Yellow' } else { 'Red' })

if ($testResults.Failed -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    foreach ($test in $testResults.Tests | Where-Object { -not $_.Passed }) {
        Write-Host "  - $($test.Name)" -ForegroundColor Red
        if ($test.Message) {
            Write-Host "    $($test.Message)" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan

# Exit with appropriate code
exit $(if ($testResults.Failed -gt 0) { 1 } else { 0 })

#endregion
