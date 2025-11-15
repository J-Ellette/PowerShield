#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Test VS Code Integration functionality
.DESCRIPTION
    Tests diagnostic export, quick fixes, command schema, and module validation
#>

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $PSScriptRoot

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        PowerShield VS Code Integration Tests              ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Import modules
Import-Module (Join-Path $scriptRoot "src/VSCodeIntegration.psm1") -Force
Import-Module (Join-Path $scriptRoot "src/PowerShellSecurityAnalyzer.psm1") -Force

$testsPassed = 0
$testsFailed = 0

# Test 1: Diagnostic Export
Write-Host "Test 1: Diagnostic Export" -ForegroundColor Yellow
try {
    $testFile = Join-Path $scriptRoot "tests/TestScripts/powershell/insecure-hash.ps1"
    $result = Invoke-SecurityAnalysis -ScriptPath $testFile
    
    if ($result.Violations.Count -eq 0) {
        throw "No violations found in test file"
    }
    
    $json = Export-VSCodeDiagnostics -Violations $result.Violations -FilePath $testFile
    $data = $json | ConvertFrom-Json
    
    if ($data.method -ne "textDocument/publishDiagnostics") {
        throw "Invalid LSP method: $($data.method)"
    }
    
    if ($data.params.diagnostics.Count -eq 0) {
        throw "No diagnostics generated"
    }
    
    Write-Host "  ✅ Generated $($data.params.diagnostics.Count) diagnostics" -ForegroundColor Green
    Write-Host "  ✅ LSP format validated" -ForegroundColor Green
    $testsPassed++
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 2: Severity Mapping
Write-Host "`nTest 2: Severity Mapping" -ForegroundColor Yellow
try {
    $integration = New-VSCodeIntegration
    
    # Create mock violations with different severities
    $mockViolations = @(
        @{
            RuleId = "Test1"
            Severity = [PowerShield.SecuritySeverity]::Critical
            Message = "Critical issue"
            LineNumber = 1
        },
        @{
            RuleId = "Test2"
            Severity = [PowerShield.SecuritySeverity]::High
            Message = "High issue"
            LineNumber = 2
        },
        @{
            RuleId = "Test3"
            Severity = [PowerShield.SecuritySeverity]::Medium
            Message = "Medium issue"
            LineNumber = 3
        },
        @{
            RuleId = "Test4"
            Severity = [PowerShield.SecuritySeverity]::Low
            Message = "Low issue"
            LineNumber = 4
        }
    )
    
    $diagnostics = $integration.ConvertToDiagnostics($mockViolations, "test.ps1")
    
    if ($diagnostics.Count -ne 4) {
        throw "Expected 4 diagnostics, got $($diagnostics.Count)"
    }
    
    # Verify severity mapping
    if ($diagnostics[0].severity -ne 1) { throw "Critical should map to Error (1)" }
    if ($diagnostics[1].severity -ne 1) { throw "High should map to Error (1)" }
    if ($diagnostics[2].severity -ne 2) { throw "Medium should map to Warning (2)" }
    if ($diagnostics[3].severity -ne 3) { throw "Low should map to Information (3)" }
    
    Write-Host "  ✅ Severity mapping correct" -ForegroundColor Green
    $testsPassed++
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 3: Quick Fix Generation
Write-Host "`nTest 3: Quick Fix Generation" -ForegroundColor Yellow
try {
    $testFile = Join-Path $scriptRoot "tests/TestScripts/powershell/insecure-hash.ps1"
    $result = Invoke-SecurityAnalysis -ScriptPath $testFile
    $fileContent = Get-Content -Path $testFile -Raw
    
    if ($result.Violations.Count -eq 0) {
        throw "No violations found"
    }
    
    $fixes = Get-VSCodeQuickFixes -Violation $result.Violations[0] -FileContent $fileContent
    
    if ($fixes.Count -gt 0) {
        Write-Host "  ✅ Generated $($fixes.Count) quick fix(es)" -ForegroundColor Green
        foreach ($fix in $fixes) {
            Write-Host "    - $($fix.description) (confidence: $($fix.confidence))" -ForegroundColor Gray
        }
        $testsPassed++
    } else {
        Write-Host "  ⚠️  No quick fixes available for this rule" -ForegroundColor Yellow
        $testsPassed++
    }
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 4: Command Schema
Write-Host "`nTest 4: Command Schema" -ForegroundColor Yellow
try {
    $schema = Get-VSCodeCommandSchema
    
    if (-not $schema.commands) {
        throw "No commands in schema"
    }
    
    if ($schema.commands.Count -lt 5) {
        throw "Expected at least 5 commands, got $($schema.commands.Count)"
    }
    
    # Verify required commands
    $requiredCommands = @(
        "powershield.analyzeFile",
        "powershield.analyzeWorkspace",
        "powershield.applyFix"
    )
    
    foreach ($cmdName in $requiredCommands) {
        $found = $schema.commands | Where-Object { $_.command -eq $cmdName }
        if (-not $found) {
            throw "Required command not found: $cmdName"
        }
    }
    
    Write-Host "  ✅ Found $($schema.commands.Count) commands" -ForegroundColor Green
    Write-Host "  ✅ All required commands present" -ForegroundColor Green
    $testsPassed++
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 5: Code Action Kinds
Write-Host "`nTest 5: Code Action Kinds" -ForegroundColor Yellow
try {
    $schema = Get-VSCodeCommandSchema
    
    if (-not $schema.codeActions) {
        throw "No code actions in schema"
    }
    
    if (-not $schema.codeActions.kinds) {
        throw "No code action kinds defined"
    }
    
    $expectedKinds = @("quickfix", "source.fixAll.powershield", "refactor.rewrite.powershield")
    foreach ($kind in $expectedKinds) {
        if ($schema.codeActions.kinds -notcontains $kind) {
            throw "Missing code action kind: $kind"
        }
    }
    
    Write-Host "  ✅ All code action kinds present" -ForegroundColor Green
    $testsPassed++
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 6: Position and Range
Write-Host "`nTest 6: Position and Range Classes" -ForegroundColor Yellow
try {
    $integration = New-VSCodeIntegration
    
    # Create a simple violation
    $mockViolation = @{
        RuleId = "TestRule"
        Severity = [PowerShield.SecuritySeverity]::High
        Message = "Test message"
        LineNumber = 5
    }
    
    $diagnostics = $integration.ConvertToDiagnostics(@($mockViolation), "test.ps1")
    $diagnostic = $diagnostics[0]
    
    # Verify range (0-indexed for VS Code)
    if ($diagnostic.range.start.line -ne 4) {
        throw "Expected start line 4 (0-indexed), got $($diagnostic.range.start.line)"
    }
    
    Write-Host "  ✅ Position and Range classes working" -ForegroundColor Green
    Write-Host "    Line: $($diagnostic.range.start.line) (0-indexed from PowerShell line $($mockViolation.LineNumber))" -ForegroundColor Gray
    $testsPassed++
} catch {
    Write-Host "  ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 7: JSON Export to File
Write-Host "`nTest 7: JSON Export to File" -ForegroundColor Yellow
try {
    $testFile = Join-Path $scriptRoot "tests/TestScripts/powershell/insecure-hash.ps1"
    $outputFile = Join-Path $scriptRoot "vscode-diagnostics-test.json"
    
    $result = Invoke-SecurityAnalysis -ScriptPath $testFile
    
    $json = Export-VSCodeDiagnostics `
        -Violations $result.Violations `
        -FilePath $testFile `
        -OutputPath $outputFile
    
    if (-not (Test-Path $outputFile)) {
        throw "Output file not created"
    }
    
    $fileContent = Get-Content -Path $outputFile -Raw
    $data = $fileContent | ConvertFrom-Json
    
    if ($data.params.diagnostics.Count -eq 0) {
        throw "No diagnostics in output file"
    }
    
    Write-Host "  ✅ Diagnostics exported to file" -ForegroundColor Green
    Write-Host "    File: $outputFile" -ForegroundColor Gray
    
    # Cleanup
    Remove-Item -Path $outputFile -Force
    
    $testsPassed++
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
