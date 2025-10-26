# Pester Integration Guide

PowerShield integrates with Pester to provide automated security testing and fix validation capabilities.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Auto-Generated Security Tests](#auto-generated-security-tests)
- [Fix Validation Pipeline](#fix-validation-pipeline)
- [Custom Security Tests](#custom-security-tests)
- [CI/CD Integration](#cicd-integration)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

The Pester integration enables:

- **Automated fix validation** - Verify security fixes don't break functionality
- **Auto-generated security tests** - Create tests based on analysis results
- **Regression prevention** - Ensure fixed vulnerabilities don't reappear
- **Compliance validation** - Verify security policies are maintained

## Prerequisites

Pester 5.0 or later must be installed:

```powershell
# Install Pester
Install-Module -Name Pester -Force -SkipPublisherCheck -MinimumVersion 5.0

# Verify installation
Get-Module -Name Pester -ListAvailable
```

## Configuration

Add Pester integration to your `.powershield.yml`:

```yaml
integrations:
  pester:
    enabled: true
    security_tests: "./tests/Security.Tests.ps1"
    run_after_fixes: true
    validate_fixes: true
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable Pester integration |
| `security_tests` | `./tests/Security.Tests.ps1` | Path to security test file |
| `run_after_fixes` | `true` | Run tests after applying auto-fixes |
| `validate_fixes` | `true` | Generate validation tests for fixes |

## Auto-Generated Security Tests

PowerShield automatically generates Pester tests based on analysis results and applied fixes.

### Generating Tests

```powershell
# Import modules
Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
Import-Module ./src/PesterIntegration.psm1 -Force

# Run analysis
$result = Invoke-WorkspaceAnalysis -WorkspacePath "."

# Generate security tests
$pesterConfig = @{
    enabled = $true
    security_tests = './tests/Security.Tests.ps1'
}

$integration = New-PesterIntegration -Configuration $pesterConfig
New-SecurityTests -Integration $integration -AnalysisResult $result
```

### Generated Test Structure

The auto-generated tests include:

1. **Fix Validation Tests** - Verify each applied fix
2. **Rule-Specific Tests** - Check for specific vulnerability patterns
3. **File-Level Tests** - Validate files no longer contain violations

Example generated test:

```powershell
#Requires -Version 7.0
#Requires -Module Pester

Describe "PowerShield Security Validation" {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '../src/PowerShellSecurityAnalyzer.psm1'
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force
        }
    }
    
    Context "Security Fix Validation" {
        It "Should have fixed InsecureHashAlgorithms in src/Example.ps1 at line 42" {
            $content = Get-Content 'src/Example.ps1' -Raw
            $content | Should -Not -Match '(?i)(MD5|SHA1|RIPEMD160)'
        }
    }
    
    Context "Rule-Specific Security Checks" {
        It "Should not contain violations: InsecureHashAlgorithms" {
            $files = Get-ChildItem -Path . -Include *.ps1,*.psm1,*.psd1 -Recurse
            $violations = @()
            
            foreach ($file in $files) {
                $content = Get-Content $file.FullName -Raw
                if ($content -match '(?i)(MD5|SHA1|RIPEMD160)') {
                    $violations += $file.FullName
                }
            }
            
            $violations.Count | Should -Be 0 -Because "No insecure hash algorithms should be present"
        }
    }
    
    Context "File-Level Security Validation" {
        It "Should have no remaining violations in src/Example.ps1" {
            $result = Invoke-SecurityAnalysis -ScriptPath 'src/Example.ps1'
            if ($result -and $result.Violations) {
                $result.Violations.Count | Should -Be 0 -Because "All violations should be fixed"
            }
        }
    }
}
```

## Fix Validation Pipeline

The fix validation pipeline ensures security fixes don't break functionality:

### Pipeline Steps

1. **Run PowerShield analysis**
2. **Apply auto-fixes**
3. **Generate security validation tests**
4. **Run security tests**
5. **Run existing functional tests**
6. **Report validation results**

### Using the Validation Pipeline

```powershell
# Import modules
Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
Import-Module ./src/PesterIntegration.psm1 -Force

# Run analysis
$result = Invoke-WorkspaceAnalysis -WorkspacePath "."

# Simulate applied fixes (in reality, these come from auto-fix)
$appliedFixes = @(
    @{
        file = 'src/Example.ps1'
        rule_id = 'InsecureHashAlgorithms'
        line_number = 42
        original = 'MD5'
        fixed = 'SHA256'
    }
)

# Run fix validation pipeline
$pesterConfig = @{
    enabled = $true
    security_tests = './tests/Security.Tests.ps1'
    run_after_fixes = $true
    validate_fixes = $true
}

$testResult = Invoke-FixValidation -AnalysisResult $result -AppliedFixes $appliedFixes -PesterConfig $pesterConfig
```

### Validation Result

```powershell
@{
    Passed = 15
    Failed = 0
    Skipped = 2
    Total = 17
    Duration = [timespan]
    Success = $true
    ResultFile = './tests/SecurityTestResults.xml'
}
```

## Custom Security Tests

Create custom security tests for project-specific requirements.

### Creating a Template

```powershell
# Generate template
Import-Module ./src/PesterIntegration.psm1 -Force
New-SecurityTestTemplate -OutputPath './tests/Security.Tests.ps1'
```

### Custom Test Example

```powershell
#Requires -Version 7.0
#Requires -Module Pester

Describe "Custom Security Tests" {
    Context "Project-Specific Security Rules" {
        It "Should not contain sensitive configuration files" {
            $sensitiveFiles = Get-ChildItem -Path . -Include '.env','.env.local','*.key','*.pem' -Recurse
            $sensitiveFiles.Count | Should -Be 0 -Because "Sensitive files should not be committed"
        }
        
        It "Should not contain hardcoded API keys" {
            $files = Get-ChildItem -Path ./src -Include *.ps1,*.psm1 -Recurse
            $violations = @()
            
            foreach ($file in $files) {
                $content = Get-Content $file.FullName -Raw
                if ($content -match '(?i)(api[_-]?key|apikey)\s*=\s*[''"][^''"]{20,}') {
                    $violations += $file.FullName
                }
            }
            
            $violations.Count | Should -Be 0 -Because "No hardcoded API keys should be present"
        }
    }
    
    Context "PowerShell Best Practices" {
        It "Should use approved verbs for functions" {
            $files = Get-ChildItem -Path ./src -Include *.ps1,*.psm1 -Recurse
            $violations = @()
            
            foreach ($file in $files) {
                $content = Get-Content $file.FullName -Raw
                $functions = [regex]::Matches($content, '(?m)^function\s+(\w+)-')
                
                foreach ($match in $functions) {
                    $verb = $match.Groups[1].Value
                    if ($verb -notin (Get-Verb).Verb) {
                        $violations += "$($file.Name): $verb"
                    }
                }
            }
            
            $violations.Count | Should -Be 0 -Because "All functions should use approved PowerShell verbs"
        }
    }
    
    Context "Security Baseline" {
        It "Should pass PowerShield analysis with no critical violations" {
            Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
            $result = Invoke-WorkspaceAnalysis -WorkspacePath ./src
            
            $criticalCount = if ($result.Summary.Critical) { $result.Summary.Critical } else { 0 }
            $criticalCount | Should -Be 0 -Because "No critical violations should exist in src/"
        }
    }
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Tests

on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Pester
        shell: pwsh
        run: |
          Install-Module -Name Pester -Force -SkipPublisherCheck -MinimumVersion 5.0
      
      - name: Run PowerShield Analysis
        shell: pwsh
        run: |
          Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
          Import-Module ./src/PesterIntegration.psm1 -Force
          
          $result = Invoke-WorkspaceAnalysis -WorkspacePath "."
          
          # Generate and run security tests
          $pesterConfig = @{
              enabled = $true
              security_tests = './tests/Security.Tests.ps1'
          }
          
          $integration = New-PesterIntegration -Configuration $pesterConfig
          New-SecurityTests -Integration $integration -AnalysisResult $result
          Invoke-SecurityTests -Integration $integration
      
      - name: Upload Test Results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-test-results
          path: tests/SecurityTestResults.xml
```

### Azure DevOps

```yaml
steps:
  - task: PowerShell@2
    displayName: 'Run Security Tests'
    inputs:
      targetType: 'inline'
      script: |
        Install-Module -Name Pester -Force -SkipPublisherCheck -MinimumVersion 5.0
        Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
        Import-Module ./src/PesterIntegration.psm1 -Force
        
        $result = Invoke-WorkspaceAnalysis -WorkspacePath "."
        
        $pesterConfig = @{
            enabled = $true
            security_tests = './tests/Security.Tests.ps1'
        }
        
        $integration = New-PesterIntegration -Configuration $pesterConfig
        New-SecurityTests -Integration $integration -AnalysisResult $result
        $testResult = Invoke-SecurityTests -Integration $integration
        
        if (-not $testResult.Success) {
            Write-Error "Security tests failed"
            exit 1
        }

  - task: PublishTestResults@2
    displayName: 'Publish Security Test Results'
    condition: always()
    inputs:
      testResultsFormat: 'NUnit'
      testResultsFiles: 'tests/SecurityTestResults.xml'
      testRunTitle: 'PowerShield Security Tests'
```

## Examples

### Example 1: Basic Fix Validation

```powershell
# After applying auto-fixes
Import-Module ./src/PesterIntegration.psm1 -Force

$analysisResult = @{
    TotalViolations = 0
    FilesAnalyzed = 10
    Summary = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    Results = @()
}

$appliedFixes = @(
    @{
        file = 'src/script.ps1'
        rule_id = 'InsecureHashAlgorithms'
        line_number = 15
    }
)

$testResult = Invoke-FixValidation -AnalysisResult $analysisResult -AppliedFixes $appliedFixes

if ($testResult.Success) {
    Write-Host "✓ All security tests passed!" -ForegroundColor Green
} else {
    Write-Warning "Security tests failed: $($testResult.Failed) failures"
}
```

### Example 2: Custom Test Suite

```powershell
# Create custom test template
New-SecurityTestTemplate -OutputPath './tests/CustomSecurity.Tests.ps1'

# Edit the template to add project-specific tests
# Then run the tests

$config = New-PesterConfiguration
$config.Run.Path = './tests/CustomSecurity.Tests.ps1'
$config.Output.Verbosity = 'Detailed'

$result = Invoke-Pester -Configuration $config
```

### Example 3: Combining with Functional Tests

```powershell
# Run security tests first
Import-Module ./src/PesterIntegration.psm1 -Force

$securityConfig = @{
    enabled = $true
    security_tests = './tests/Security.Tests.ps1'
}

$integration = New-PesterIntegration -Configuration $securityConfig
$securityResult = Invoke-SecurityTests -Integration $integration

# Then run functional tests
$functionalConfig = New-PesterConfiguration
$functionalConfig.Run.Path = './tests/*.Tests.ps1'
$functionalConfig.Run.ExcludePath = './tests/Security.Tests.ps1'

$functionalResult = Invoke-Pester -Configuration $functionalConfig

# Report combined results
$totalPassed = $securityResult.Passed + $functionalResult.Passed
$totalFailed = $securityResult.Failed + $functionalResult.Failed

Write-Host "`nCombined Results:" -ForegroundColor Cyan
Write-Host "  Security Tests: $($securityResult.Passed)/$($securityResult.Total) passed"
Write-Host "  Functional Tests: $($functionalResult.Passed)/$($functionalResult.TotalCount) passed"
Write-Host "  Total: $totalPassed/$($totalPassed + $totalFailed) passed"
```

## Best Practices

1. **Run tests after every fix** to ensure fixes don't break functionality
2. **Commit generated tests** to track security validation over time
3. **Customize templates** for project-specific security requirements
4. **Integrate with CI/CD** to prevent regressions
5. **Review test failures** carefully - they may indicate legitimate issues
6. **Keep tests up-to-date** as security requirements evolve

## Troubleshooting

### Pester Not Found

**Issue**: `Pester module is not installed`

**Solution**:
```powershell
Install-Module -Name Pester -Force -SkipPublisherCheck -MinimumVersion 5.0
```

### Test Generation Fails

**Issue**: Security tests fail to generate

**Solutions**:
1. Verify analysis result is valid
2. Check that the output directory exists
3. Ensure write permissions for test file path
4. Review PowerShell error messages

### Tests Fail After Fixes

**Issue**: Security tests fail even after applying fixes

**Solutions**:
1. Re-run analysis to verify fixes were applied
2. Check that files were actually modified
3. Review specific test failures for clues
4. Manually verify the fix was correct

### Test File Already Exists

**Issue**: Cannot overwrite existing test file

**Solution**:
```powershell
# Backup existing tests
Move-Item './tests/Security.Tests.ps1' './tests/Security.Tests.ps1.bak' -Force

# Generate new tests
New-SecurityTests -Integration $integration -AnalysisResult $result

# Merge if needed
```

### CI/CD Test Failures

**Issue**: Tests pass locally but fail in CI/CD

**Solutions**:
1. Verify Pester version matches locally and in CI/CD
2. Check file paths are relative and portable
3. Ensure all dependencies are available
4. Review CI/CD logs for missing modules

## Advanced Usage

### Parallel Test Execution

```powershell
$config = New-PesterConfiguration
$config.Run.Path = './tests/Security.Tests.ps1'
$config.Run.Parallel = $true
$config.Run.PassThru = $true

$result = Invoke-Pester -Configuration $config
```

### Custom Test Result Format

```powershell
$config = New-PesterConfiguration
$config.Run.Path = './tests/Security.Tests.ps1'
$config.TestResult.Enabled = $true
$config.TestResult.OutputFormat = 'JUnitXml'  # or 'NUnitXml', 'NUnit3'
$config.TestResult.OutputPath = './test-results.xml'

Invoke-Pester -Configuration $config
```

### Filtering Tests by Tag

Add tags to custom tests:

```powershell
Describe "Custom Security Tests" -Tag "Security", "Critical" {
    It "Should not contain secrets" -Tag "Secrets" {
        # Test logic
    }
}

# Run only specific tags
$config = New-PesterConfiguration
$config.Filter.Tag = 'Critical', 'Secrets'
Invoke-Pester -Configuration $config
```

## Further Reading

- [Pester Documentation](https://pester.dev/)
- [PowerShield Auto-Fix Guide](./auto-fix.md)
- [PowerShield Configuration](./configuration.md)
- [CI/CD Integration Guide](../integrations/README.md)
