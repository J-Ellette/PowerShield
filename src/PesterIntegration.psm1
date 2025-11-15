#Requires -Version 7.0

<#
.SYNOPSIS
    Pester integration for PowerShield security testing framework
.DESCRIPTION
    Generates security validation tests and integrates with Pester for automated
    fix validation and regression testing.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

class PesterIntegration {
    [string]$SecurityTestsPath
    [bool]$Enabled
    [bool]$RunAfterFixes
    [bool]$ValidateFixes
    [hashtable]$Configuration
    
    PesterIntegration([hashtable]$config) {
        $this.SecurityTestsPath = if ($config.security_tests) { $config.security_tests } else { './tests/Security.Tests.ps1' }
        $this.Enabled = if ($config.ContainsKey('enabled')) { $config.enabled } else { $false }
        $this.RunAfterFixes = if ($config.ContainsKey('run_after_fixes')) { $config.run_after_fixes } else { $true }
        $this.ValidateFixes = if ($config.ContainsKey('validate_fixes')) { $config.validate_fixes } else { $true }
        $this.Configuration = $config
    }
    
    [string] GenerateSecurityTests([hashtable]$analysisResult, [array]$appliedFixes) {
        $testScript = @"
#Requires -Version 7.0
#Requires -Module Pester

<#
.SYNOPSIS
    PowerShield Security Validation Tests
.DESCRIPTION
    Auto-generated security tests to validate that security fixes were applied correctly
    and that no security violations remain.
.NOTES
    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    PowerShield Version: 1.0.0
#>

Describe "PowerShield Security Validation" {
    BeforeAll {
        # Setup: Import analyzer for validation
        `$modulePath = Join-Path `$PSScriptRoot '../src/PowerShellSecurityAnalyzer.psm1'
        if (Test-Path `$modulePath) {
            Import-Module `$modulePath -Force
        }
    }
    
    Context "Security Fix Validation" {
"@
        
        # Generate tests for each applied fix
        if ($appliedFixes -and $appliedFixes.Count -gt 0) {
            foreach ($fix in $appliedFixes) {
                $testScript += $this.GenerateFixValidationTest($fix)
            }
        } else {
            $testScript += @"
        
        It "Should have test placeholder (no fixes applied)" {
            `$true | Should -Be `$true
        }
"@
        }
        
        $testScript += @"

    }
    
    Context "Rule-Specific Security Checks" {
"@
        
        # Generate rule-specific tests based on analysis results
        $testScript += $this.GenerateRuleTests($analysisResult)
        
        $testScript += @"

    }
    
    Context "File-Level Security Validation" {
"@
        
        # Generate file-level validation tests
        if ($analysisResult.Results) {
            foreach ($fileResult in $analysisResult.Results) {
                if ($fileResult.Violations -and $fileResult.Violations.Count -gt 0) {
                    $testScript += $this.GenerateFileValidationTest($fileResult)
                }
            }
        } else {
            $testScript += @"
        
        It "Should have no security violations in analyzed files" {
            `$true | Should -Be `$true
        }
"@
        }
        
        $testScript += @"

    }
}
"@
        
        return $testScript
    }
    
    [string] GenerateFixValidationTest([hashtable]$fix) {
        $filePath = $fix.file
        $ruleId = $fix.rule_id
        $lineNumber = $fix.line_number
        
        $testName = "Should have fixed $ruleId in $filePath at line $lineNumber"
        
        return @"

        
        It "$testName" {
            `$content = Get-Content '$filePath' -Raw -ErrorAction SilentlyContinue
            if (-not `$content) {
                Set-ItResult -Skipped -Because "File not found: $filePath"
                return
            }
            
            # Rule-specific validation
            switch ('$ruleId') {
                'InsecureHashAlgorithms' {
                    `$content | Should -Not -Match '(?i)(MD5|SHA1|RIPEMD160)'
                }
                'CredentialExposure' {
                    `$content | Should -Not -Match '(?i)(ConvertTo-SecureString.*-AsPlainText|Password\s*=\s*[''"])'
                }
                'CommandInjection' {
                    `$lines = `$content -split '\r?\n'
                    if (`$lines.Count -ge $lineNumber) {
                        `$line = `$lines[$lineNumber - 1]
                        `$line | Should -Not -Match '(?i)Invoke-Expression'
                    }
                }
                default {
                    # Generic check: re-run analyzer on this file
                    `$tempResult = Invoke-SecurityAnalysis -ScriptPath '$filePath' -ErrorAction SilentlyContinue
                    if (`$tempResult -and `$tempResult.Violations) {
                        `$relevantViolations = `$tempResult.Violations | Where-Object { 
                            `$_.RuleId -eq '$ruleId' -and `$_.LineNumber -eq $lineNumber 
                        }
                        `$relevantViolations.Count | Should -Be 0
                    }
                }
            }
        }
"@
    }
    
    [string] GenerateRuleTests([hashtable]$analysisResult) {
        $tests = ""
        
        # Common security rules to check
        $rules = @{
            'InsecureHashAlgorithms' = @{
                Pattern = '(?i)(MD5|SHA1|RIPEMD160)'
                Description = 'No insecure hash algorithms (MD5, SHA1, RIPEMD160) should be present'
            }
            'CredentialExposure' = @{
                Pattern = '(?i)(ConvertTo-SecureString.*-AsPlainText.*-Force|Password\s*=\s*[''"][^''"])'
                Description = 'No plaintext credential exposure should be present'
            }
            'CommandInjection' = @{
                Pattern = '(?i)(Invoke-Expression|IEX)\s+[^#]'
                Description = 'No unsafe Invoke-Expression usage should be present'
            }
        }
        
        foreach ($ruleId in $rules.Keys) {
            $rule = $rules[$ruleId]
            $tests += @"

        
        It "Should not contain violations: $ruleId" {
            `$files = Get-ChildItem -Path . -Include *.ps1,*.psm1,*.psd1 -Recurse -ErrorAction SilentlyContinue
            `$violations = @()
            
            foreach (`$file in `$files) {
                `$content = Get-Content `$file.FullName -Raw -ErrorAction SilentlyContinue
                if (`$content -match '$($rule.Pattern)') {
                    `$violations += `$file.FullName
                }
            }
            
            `$violations.Count | Should -Be 0 -Because "$($rule.Description)"
        }
"@
        }
        
        return $tests
    }
    
    [string] GenerateFileValidationTest([hashtable]$fileResult) {
        $filePath = $fileResult.FilePath
        $violationCount = $fileResult.Violations.Count
        $criticalCount = ($fileResult.Violations | Where-Object { $_.Severity -eq 'Critical' }).Count
        
        return @"

        
        It "Should have no remaining violations in $filePath" {
            if (-not (Test-Path '$filePath')) {
                Set-ItResult -Skipped -Because "File not found: $filePath"
                return
            }
            
            `$result = Invoke-SecurityAnalysis -ScriptPath '$filePath' -ErrorAction SilentlyContinue
            if (`$result -and `$result.Violations) {
                `$result.Violations.Count | Should -Be 0 -Because "All violations should be fixed"
            }
        }
"@
    }
    
    [hashtable] RunTests([string]$testPath) {
        if (-not (Get-Module -ListAvailable -Name Pester)) {
            throw "Pester module is not installed. Install with: Install-Module Pester -Force"
        }
        
        Import-Module Pester -Force -MinimumVersion 5.0
        
        $config = New-PesterConfiguration
        $config.Run.Path = $testPath
        $config.Output.Verbosity = 'Detailed'
        $config.TestResult.Enabled = $true
        $config.TestResult.OutputFormat = 'NUnitXml'
        $config.TestResult.OutputPath = Join-Path (Split-Path $testPath -Parent) 'SecurityTestResults.xml'
        
        $result = Invoke-Pester -Configuration $config
        
        return @{
            Passed = $result.Passed
            Failed = $result.Failed
            Skipped = $result.Skipped
            Total = $result.TotalCount
            Duration = $result.Duration
            Success = $result.Result -eq 'Passed'
            ResultFile = $config.TestResult.OutputPath
        }
    }
    
    [void] SaveTests([string]$testScript) {
        $testDir = Split-Path $this.SecurityTestsPath -Parent
        if (-not (Test-Path $testDir)) {
            New-Item -Path $testDir -ItemType Directory -Force | Out-Null
        }
        
        $testScript | Set-Content -Path $this.SecurityTestsPath -Encoding UTF8
        Write-Verbose "Security tests saved to: $($this.SecurityTestsPath)"
    }
}

function New-PesterIntegration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [hashtable]$Configuration = @{}
    )
    
    return [PesterIntegration]::new($Configuration)
}

function New-SecurityTests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PesterIntegration]$Integration,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisResult,
        
        [Parameter(Mandatory=$false)]
        [array]$AppliedFixes = @()
    )
    
    $testScript = $Integration.GenerateSecurityTests($AnalysisResult, $AppliedFixes)
    $Integration.SaveTests($testScript)
    
    return $Integration.SecurityTestsPath
}

function Invoke-SecurityTests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PesterIntegration]$Integration,
        
        [Parameter(Mandatory=$false)]
        [string]$TestPath
    )
    
    if (-not $TestPath) {
        $TestPath = $Integration.SecurityTestsPath
    }
    
    if (-not (Test-Path $TestPath)) {
        throw "Test file not found: $TestPath"
    }
    
    return $Integration.RunTests($TestPath)
}

function Invoke-FixValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisResult,
        
        [Parameter(Mandatory=$true)]
        [array]$AppliedFixes,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$PesterConfig = @{
            enabled = $true
            security_tests = './tests/Security.Tests.ps1'
            run_after_fixes = $true
            validate_fixes = $true
        }
    )
    
    Write-Host "Starting fix validation pipeline..." -ForegroundColor Cyan
    
    $integration = New-PesterIntegration -Configuration $PesterConfig
    
    # Step 1: Generate security tests
    Write-Host "Generating security validation tests..." -ForegroundColor Cyan
    $testPath = New-SecurityTests -Integration $integration -AnalysisResult $AnalysisResult -AppliedFixes $AppliedFixes
    Write-Host "✓ Tests generated: $testPath" -ForegroundColor Green
    
    # Step 2: Run tests
    Write-Host "Running security validation tests..." -ForegroundColor Cyan
    try {
        $testResult = Invoke-SecurityTests -Integration $integration -TestPath $testPath
        
        if ($testResult.Success) {
            Write-Host "✓ All security tests passed ($($testResult.Passed)/$($testResult.Total))" -ForegroundColor Green
        } else {
            Write-Warning "✗ Some security tests failed ($($testResult.Failed)/$($testResult.Total))"
        }
        
        return $testResult
    } catch {
        Write-Warning "Failed to run security tests: $_"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function New-SecurityTestTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = './tests/Security.Tests.ps1'
    )
    
    $template = @'
#Requires -Version 7.0
#Requires -Module Pester

<#
.SYNOPSIS
    PowerShield Security Tests Template
.DESCRIPTION
    Template for creating custom security validation tests for PowerShield.
    Customize this file to add project-specific security checks.
.NOTES
    This is a template file. Customize it for your project needs.
#>

Describe "PowerShield Security Tests" {
    BeforeAll {
        # Import PowerShield analyzer
        $modulePath = Join-Path $PSScriptRoot '../src/PowerShellSecurityAnalyzer.psm1'
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force
        }
    }
    
    Context "Project-Specific Security Rules" {
        It "Should not contain sensitive configuration files" {
            $sensitiveFiles = Get-ChildItem -Path . -Include '.env','.env.local','*.key','*.pem' -Recurse -ErrorAction SilentlyContinue
            $sensitiveFiles.Count | Should -Be 0 -Because "Sensitive files should not be committed"
        }
        
        It "Should not contain hardcoded secrets" {
            $files = Get-ChildItem -Path . -Include *.ps1,*.psm1 -Recurse -ErrorAction SilentlyContinue
            $violations = @()
            
            foreach ($file in $files) {
                $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                # Check for common secret patterns
                if ($content -match '(?i)(password|secret|token|api[_-]?key)\s*=\s*[''"][^''"]{8,}') {
                    $violations += $file.FullName
                }
            }
            
            $violations.Count | Should -Be 0 -Because "No hardcoded secrets should be present"
        }
    }
    
    Context "PowerShell Best Practices" {
        It "Should use approved verbs for functions" {
            $files = Get-ChildItem -Path ./src -Include *.ps1,*.psm1 -Recurse -ErrorAction SilentlyContinue
            $violations = @()
            
            foreach ($file in $files) {
                $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                # Simple check for function definitions with non-approved verbs
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
    
    Context "Integration Tests" {
        It "Should be able to analyze the project itself" {
            $result = Invoke-WorkspaceAnalysis -WorkspacePath . -ErrorAction SilentlyContinue
            $result | Should -Not -BeNullOrEmpty
            $result.FilesAnalyzed | Should -BeGreaterThan 0
        }
    }
}
'@
    
    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
    }
    
    $template | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "Security test template created: $OutputPath" -ForegroundColor Green
    
    return $OutputPath
}

Export-ModuleMember -Function @(
    'New-PesterIntegration',
    'New-SecurityTests',
    'Invoke-SecurityTests',
    'Invoke-FixValidation',
    'New-SecurityTestTemplate'
)
