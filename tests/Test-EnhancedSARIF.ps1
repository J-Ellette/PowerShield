# Test script to validate enhanced SARIF output

Write-Host "Testing Enhanced SARIF Output..." -ForegroundColor Cyan

# Get cross-platform temp directory
$tempDir = [System.IO.Path]::GetTempPath()
$testJsonFile = Join-Path $tempDir "test-sarif-validation.json"
$testSarifFile = Join-Path $tempDir "test-sarif-validation.sarif"

# Import analyzer
Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force

# Test 1: Basic analysis with metadata
Write-Host "`n[Test 1] Analyzing test script..." -ForegroundColor Yellow
$result = Invoke-SecurityAnalysis -ScriptPath './tests/TestScripts/powershell/insecure-hash.ps1'

# Verify violations have metadata
$hasMetadata = $false
foreach ($violation in $result.Violations) {
    if ($violation.Metadata -and $violation.Metadata.Count -gt 0) {
        $hasMetadata = $true
        break
    }
}

if ($hasMetadata) {
    Write-Host "✓ Violations include metadata" -ForegroundColor Green
} else {
    Write-Host "✗ Violations missing metadata" -ForegroundColor Red
    exit 1
}

# Test 2: Export to SARIF and validate structure
Write-Host "`n[Test 2] Converting to SARIF..." -ForegroundColor Yellow

$exportData = @{
    metadata = @{
        version = '1.0.0'
        timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
        repository = 'PowerShield-Test'
    }
    summary = @{
        totalFiles = 1
        totalViolations = $result.Violations.Count
    }
    violations = $result.Violations
}

$exportData | ConvertTo-Json -Depth 10 | Out-File $testJsonFile

. ./scripts/Convert-ToSARIF.ps1
Convert-ToSARIF -InputFile $testJsonFile -OutputFile $testSarifFile

# Parse SARIF
$sarif = Get-Content $testSarifFile -Raw | ConvertFrom-Json

# Test 3: Validate SARIF structure
Write-Host "`n[Test 3] Validating SARIF structure..." -ForegroundColor Yellow

$tests = @(
    @{ Name = "Schema version"; Check = { $sarif.version -eq '2.1.0' } },
    @{ Name = "Has runs"; Check = { $sarif.runs.Count -gt 0 } },
    @{ Name = "Has tool driver"; Check = { $sarif.runs[0].tool.driver -ne $null } },
    @{ Name = "Has rules"; Check = { $sarif.runs[0].tool.driver.rules.Count -gt 0 } },
    @{ Name = "Has results"; Check = { $sarif.runs[0].results.Count -gt 0 } }
)

foreach ($test in $tests) {
    if (& $test.Check) {
        Write-Host "  ✓ $($test.Name)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($test.Name)" -ForegroundColor Red
        exit 1
    }
}

# Test 4: Validate enhanced metadata
Write-Host "`n[Test 4] Validating enhanced metadata..." -ForegroundColor Yellow

$rule = $sarif.runs[0].tool.driver.rules[0]

$metadataTests = @(
    @{ Name = "Rule has CWE"; Check = { $rule.properties.cwe -ne $null -and $rule.properties.cwe.Count -gt 0 } },
    @{ Name = "Rule has MITRE ATT&CK"; Check = { $rule.properties.mitreAttack -ne $null } },
    @{ Name = "Rule has OWASP"; Check = { $rule.properties.owasp -ne $null } },
    @{ Name = "Rule has help URI"; Check = { $rule.helpUri -ne $null -and $rule.helpUri -ne '' } }
)

foreach ($test in $metadataTests) {
    if (& $test.Check) {
        Write-Host "  ✓ $($test.Name)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($test.Name)" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n  CWE: $($rule.properties.cwe -join ', ')" -ForegroundColor Gray
Write-Host "  MITRE: $($rule.properties.mitreAttack)" -ForegroundColor Gray
Write-Host "  OWASP: $($rule.properties.owasp)" -ForegroundColor Gray
Write-Host "  Help: $($rule.helpUri)" -ForegroundColor Gray

# Test 5: Validate fix suggestions
Write-Host "`n[Test 5] Validating fix suggestions..." -ForegroundColor Yellow

$resultsWithFixes = $sarif.runs[0].results | Where-Object { $_.fixes -ne $null -and $_.fixes.Count -gt 0 }

if ($resultsWithFixes.Count -gt 0) {
    Write-Host "  ✓ Found $($resultsWithFixes.Count) results with fix suggestions" -ForegroundColor Green
    
    $sampleFix = $resultsWithFixes[0].fixes[0]
    if ($sampleFix.description -and $sampleFix.artifactChanges) {
        Write-Host "  ✓ Fix suggestions have proper structure" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Fix suggestions missing required fields" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "`n  Sample fix: $($sampleFix.description.text)" -ForegroundColor Gray
} else {
    Write-Host "  ✗ No fix suggestions found" -ForegroundColor Red
    exit 1
}

# Test 6: Validate SARIF JSON structure
Write-Host "`n[Test 6] Validating JSON structure..." -ForegroundColor Yellow

try {
    $sarifText = Get-Content $testSarifFile -Raw
    $null = ConvertFrom-Json $sarifText
    Write-Host "  ✓ Valid JSON" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Invalid JSON: $_" -ForegroundColor Red
    exit 1
}

# Test 7: Check for required SARIF fields per spec
Write-Host "`n[Test 7] Validating SARIF 2.1.0 required fields..." -ForegroundColor Yellow

$requiredFields = @(
    @{ Path = { $sarif.'$schema' }; Name = '$schema' },
    @{ Path = { $sarif.version }; Name = 'version' },
    @{ Path = { $sarif.runs[0].tool.driver.name }; Name = 'tool.driver.name' },
    @{ Path = { $sarif.runs[0].results[0].ruleId }; Name = 'results[0].ruleId' },
    @{ Path = { $sarif.runs[0].results[0].message }; Name = 'results[0].message' },
    @{ Path = { $sarif.runs[0].results[0].locations }; Name = 'results[0].locations' }
)

foreach ($field in $requiredFields) {
    $value = & $field.Path
    if ($value -ne $null) {
        Write-Host "  ✓ $($field.Name)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($field.Name) missing" -ForegroundColor Red
        exit 1
    }
}

# Summary
Write-Host "`n" + ("="*50) -ForegroundColor Cyan
Write-Host "All Enhanced SARIF Tests Passed! ✓" -ForegroundColor Green
Write-Host ("="*50) -ForegroundColor Cyan

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "  Rules with metadata: $($sarif.runs[0].tool.driver.rules.Count)"
Write-Host "  Results generated: $($sarif.runs[0].results.Count)"
Write-Host "  Results with fixes: $($resultsWithFixes.Count)"
Write-Host "  Schema version: $($sarif.version)"

# Cleanup
Remove-Item $testJsonFile -ErrorAction SilentlyContinue
Remove-Item $testSarifFile -ErrorAction SilentlyContinue

Write-Host "`nTest completed successfully!" -ForegroundColor Green
