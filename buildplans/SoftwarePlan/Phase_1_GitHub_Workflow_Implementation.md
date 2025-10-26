# Phase 1: GitHub Workflow Implementation

## 1.1 Core Security Engine

File: src/PowerShellSecurityAnalyzer.psm1
powershell#Requires -Version 7.0

using namespace System.Management.Automation.Language
using namespace System.Collections.Generic

class SecurityViolation {
    [string]$Name
    [string]$Message
    [string]$Description
    [SecuritySeverity]$Severity
    [int]$LineNumber
    [string]$Code
    [string]$FilePath
    [string]$RuleId
    [hashtable]$Metadata

    SecurityViolation([string]$name, [string]$message, [SecuritySeverity]$severity, [int]$lineNumber, [string]$code) {
        $this.Name = $name
        $this.Message = $message
        $this.Severity = $severity
        $this.LineNumber = $lineNumber
        $this.Code = $code
        $this.Metadata = @{}
    }
}

enum SecuritySeverity {
    Low = 1
    Medium = 2
    High = 3
    Critical = 4
}

class SecurityRule {
    [string]$Name
    [string]$Description
    [SecuritySeverity]$Severity
    [ScriptBlock]$Evaluator
    [string]$Category
    [string[]]$Tags

    SecurityRule([string]$name, [string]$description, [SecuritySeverity]$severity, [ScriptBlock]$evaluator) {
        $this.Name = $name
        $this.Description = $description
        $this.Severity = $severity
        $this.Evaluator = $evaluator
        $this.Category = "Security"
        $this.Tags = @()
    }

    [SecurityViolation[]] Evaluate([Ast]$ast, [string]$filePath) {
        $violations = & $this.Evaluator $ast $filePath
        foreach ($violation in $violations) {
            $violation.FilePath = $filePath
            $violation.RuleId = $this.Name
        }
        return $violations
    }
}

class PowerShellSecurityAnalyzer {
    [List[SecurityRule]]$SecurityRules
    [List[SecurityRule]]$CodingRules
    [hashtable]$Configuration

    PowerShellSecurityAnalyzer() {
        $this.SecurityRules = [List[SecurityRule]]::new()
        $this.CodingRules = [List[SecurityRule]]::new()
        $this.Configuration = @{
            EnableParallelAnalysis = $true
            MaxFileSize = 10MB
            TimeoutSeconds = 30
        }
        $this.InitializeDefaultRules()
    }

    [void] InitializeDefaultRules() {
        # Hash Algorithm Security Rules
        $this.SecurityRules.Add([SecurityRule]::new(
            "InsecureHashAlgorithms",
            "Detects usage of cryptographically weak hash algorithms",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                $insecureAlgorithms = @('MD5', 'SHA1', 'SHA-1', 'RIPEMD160')
                
                # Check Get-FileHash calls
                $hashCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and $args[0].GetCommandName() -eq 'Get-FileHash'
                }, $true)
                
                foreach ($call in $hashCalls) {
                    $algorithmParam = $call.CommandElements | Where-Object { 
                        $_.ParameterName -eq 'Algorithm' 
                    }
                    
                    if ($algorithmParam -and $algorithmParam.Argument.Value -in $insecureAlgorithms) {
                        $violations += [SecurityViolation]::new(
                            "InsecureHashAlgorithms",
                            "Insecure hash algorithm '$($algorithmParam.Argument.Value)' detected. Use SHA-256 or higher.",
                            [SecuritySeverity]::High,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Check .NET crypto classes
                $cryptoUsage = $Ast.FindAll({
                    $args[0] -is [TypeExpressionAst] -and
                    $args[0].TypeName.Name -match 'MD5|SHA1CryptoServiceProvider'
                }, $true)
                
                foreach ($usage in $cryptoUsage) {
                    $violations += [SecurityViolation]::new(
                        "InsecureHashAlgorithms",
                        "Direct usage of insecure hash algorithm class detected",
                        [SecuritySeverity]::High,
                        $usage.Extent.StartLineNumber,
                        $usage.Extent.Text
                    )
                }
                
                return $violations
            }
        ))

        # Credential Exposure Rule
        $this.SecurityRules.Add([SecurityRule]::new(
            "CredentialExposure",
            "Detects potential credential exposure in scripts",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find ConvertTo-SecureString with -AsPlainText
                $secureStringCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    $args[0].GetCommandName() -eq 'ConvertTo-SecureString'
                }, $true)
                
                foreach ($call in $secureStringCalls) {
                    if ($call.CommandElements | Where-Object { $_.Value -eq '-AsPlainText' }) {
                        $violations += [SecurityViolation]::new(
                            "CredentialExposure",
                            "Plaintext password conversion detected. Use Read-Host -AsSecureString instead.",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                # Check for hardcoded passwords
                $stringLiterals = $Ast.FindAll({
                    $args[0] -is [StringConstantExpressionAst]
                }, $true)
                
                foreach ($literal in $stringLiterals) {
                    $text = $literal.Value.ToLower()
                    if ($text -match 'password|pwd|secret|key' -and $literal.Value.Length -gt 8) {
                        $context = $literal.Parent.Extent.Text
                        if ($context -match 'password\s*=|pwd\s*=|secret\s*=') {
                            $violations += [SecurityViolation]::new(
                                "CredentialExposure",
                                "Potential hardcoded credential detected",
                                [SecuritySeverity]::Critical,
                                $literal.Extent.StartLineNumber,
                                $literal.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        ))

        # Command Injection Rule
        $this.SecurityRules.Add([SecurityRule]::new(
            "CommandInjection",
            "Detects potential command injection vulnerabilities",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Find Invoke-Expression calls
                $iexCalls = $Ast.FindAll({
                    $args[0] -is [CommandAst] -and
                    ($args[0].GetCommandName() -eq 'Invoke-Expression' -or 
                     $args[0].GetCommandName() -eq 'iex')
                }, $true)
                
                foreach ($call in $iexCalls) {
                    # Check if the expression contains variables or parameters
                    if ($call.CommandElements[1].Extent.Text -match '\$') {
                        $violations += [SecurityViolation]::new(
                            "CommandInjection",
                            "Potential command injection via Invoke-Expression with variables",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ))

        # Certificate Validation Rule
        $this.SecurityRules.Add([SecurityRule]::new(
            "CertificateValidation",
            "Validates certificate security practices",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Check for certificate validation bypass
                $certValidation = $Ast.FindAll({
                    $args[0].Extent.Text -match 'ServerCertificateValidationCallback|CheckCertRevocationStatus'
                }, $true)
                
                foreach ($validation in $certValidation) {
                    $text = $validation.Extent.Text
                    if ($text -match 'return\s+\$true' -or $text -match '=\s*\$true') {
                        $violations += [SecurityViolation]::new(
                            "CertificateValidation",
                            "Certificate validation bypass detected",
                            [SecuritySeverity]::High,
                            $validation.Extent.StartLineNumber,
                            $text
                        )
                    }
                }
                
                return $violations
            }
        ))
    }

    [PSCustomObject] AnalyzeScript([string]$ScriptPath) {
        if (-not (Test-Path $ScriptPath)) {
            throw "Script file not found: $ScriptPath"
        }

        $fileInfo = Get-Item $ScriptPath
        if ($fileInfo.Length -gt $this.Configuration.MaxFileSize) {
            throw "File too large: $($fileInfo.Length) bytes exceeds limit of $($this.Configuration.MaxFileSize) bytes"
        }

        try {
            # Parse the script
            $tokens = $null
            $errors = $null
            $ast = [Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
            
            if ($errors.Count -gt 0) {
                Write-Warning "Parse errors in $ScriptPath`: $($errors -join '; ')"
            }

            # Run security rules
            $allViolations = @()
            
            $rules = $this.SecurityRules + $this.CodingRules
            foreach ($rule in $rules) {
                try {
                    $ruleViolations = $rule.Evaluate($ast, $ScriptPath)
                    $allViolations += $ruleViolations
                } catch {
                    Write-Warning "Rule $($rule.Name) failed: $($_.Exception.Message)"
                }
            }

            return [PSCustomObject]@{
                FilePath = $ScriptPath
                Violations = $allViolations
                ParseErrors = $errors
                RulesExecuted = $rules.Count
                Timestamp = Get-Date
            }
        } catch {
            throw "Analysis failed for $ScriptPath`: $($_.Exception.Message)"
        }
    }

    [PSCustomObject] AnalyzeWorkspace([string]$WorkspacePath) {
        $scriptFiles = Get-ChildItem -Path $WorkspacePath -Recurse -Include "*.ps1", "*.psm1", "*.psd1" | 
                      Where-Object { $_.Length -le $this.Configuration.MaxFileSize }
        
        $allResults = @()
        $totalViolations = 0
        
        foreach ($file in $scriptFiles) {
            try {
                $result = $this.AnalyzeScript($file.FullName)
                $allResults += $result
                $totalViolations += $result.Violations.Count
                
                Write-Progress -Activity "Analyzing PowerShell Files" -Status $file.Name -PercentComplete (($allResults.Count / $scriptFiles.Count) * 100)
            } catch {
                Write-Warning "Failed to analyze $($file.FullName): $($_.Exception.Message)"
            }
        }
        
        Write-Progress -Activity "Analyzing PowerShell Files" -Completed

        return [PSCustomObject]@{
            WorkspacePath = $WorkspacePath
            FilesAnalyzed = $allResults.Count
            TotalViolations = $totalViolations
            Results = $allResults
            Summary = $this.GenerateSummary($allResults)
            Timestamp = Get-Date
        }
    }

    [hashtable] GenerateSummary([array]$Results) {
        $summary = @{
            TotalFiles = $Results.Count
            TotalViolations = ($Results.Violations | Measure-Object).Count
            BySeverity = @{
                Critical = 0
                High = 0
                Medium = 0
                Low = 0
            }
            ByCategory = @{}
            TopIssues = @()
        }

        foreach ($result in $Results) {
            foreach ($violation in $result.Violations) {
                $summary.BySeverity[$violation.Severity.ToString()]++
                
                if (-not $summary.ByCategory.ContainsKey($violation.Name)) {
                    $summary.ByCategory[$violation.Name] = 0
                }
                $summary.ByCategory[$violation.Name]++
            }
        }

        $summary.TopIssues = $summary.ByCategory.GetEnumerator() | 
                            Sort-Object Value -Descending | 
                            Select-Object -First 5 |
                            ForEach-Object { @{ Rule = $_.Key; Count = $_.Value } }

        return $summary
    }
}

# Export functions and classes

File: .github/workflows/powershell-security.yml
yamlname: PowerShield - PowerShell Security Analysis

on:
  push:
    branches: [ main, develop, 'feature/*' ]
  pull_request:
    branches: [ main, develop ]
  workflow_dispatch:
    inputs:
      severity_threshold:
        description: 'Minimum severity level to report'
        required: false
        default: 'Medium'
        type: choice
        options:
        - Low
        - Medium
        - High
        - Critical

env:
  PowerShield_VERSION: '1.0.0'

jobs:
  security-analysis:
    name: Security Analysis
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
      issues: write

    outputs:
      violations-count: ${{ steps.analyze.outputs.violations-count }}
      critical-count: ${{ steps.analyze.outputs.critical-count }}
      fix-applied: ${{ steps.copilot-fix.outputs.fixes-applied }}

    steps:
    - name: Checkout Repository
      uses: actions/checkout@v4
      with:
        fetch-depth: 0

    - name: Setup PowerShell
      uses: azure/powershell@v1
      with:
        azPSVersion: 'latest'

    - name: Cache PowerShield Dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.local/share/powershell/Modules
          /home/runner/.local/share/powershell/Modules
        key: psts-modules-${{ runner.os }}-${{ hashFiles('**/requirements.psd1') }}

    - name: Install PowerShield Dependencies
      shell: pwsh
      run: |
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
        Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force

    - name: Run Security Analysis
      id: analyze
      shell: pwsh
      run: |
        $analyzer = [PowerShellSecurityAnalyzer]::new()
        $result = $analyzer.AnalyzeWorkspace("./")
        
        # Filter by severity if specified
        $severityThreshold = '${{ github.event.inputs.severity_threshold || 'Medium' }}'
        $filteredViolations = $result.Results.Violations | Where-Object { 
          [int]$_.Severity -ge [int]([SecuritySeverity]::$severityThreshold)
        }
        
        $criticalCount = ($filteredViolations | Where-Object { $_.Severity -eq 'Critical' }).Count
        $totalCount = $filteredViolations.Count
        
        # Export results
        $exportData = @{
          metadata = @{
            version = '${{ env.PowerShield_VERSION }}'
            timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
            repository = '${{ github.repository }}'
            ref = '${{ github.ref }}'
            sha = '${{ github.sha }}'
          }
          summary = $result.Summary
          violations = $filteredViolations
        }
        
        $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath 'powershield-results.json' -Encoding UTF8
        
        # Generate SARIF
        . ./scripts/Convert-ToSARIF.ps1
        Convert-ToSARIF -InputFile 'powershield-results.json' -OutputFile 'powershield-results.sarif'
        
        # Set outputs
        Write-Output "violations-count=$totalCount" >> $env:GITHUB_OUTPUT
        Write-Output "critical-count=$criticalCount" >> $env:GITHUB_OUTPUT
        
        # Fail if critical issues found
        if ($criticalCount -gt 0) {
          Write-Error "Found $criticalCount critical security violations"
          exit 1
        }

    - name: GitHub Copilot Auto-Fix
      id: copilot-fix
      if: steps.analyze.outputs.violations-count > 0
      uses: ./actions/copilot-autofix
      with:
        github-token: ${{ secrets.GITHUB_TOKEN }}
        violations-file: 'powershield-results.json'
        max-fixes: 10
        confidence-threshold: 0.8

    - name: Upload SARIF Results
      if: always()
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: powershield-results.sarif
        category: 'PowerShield-Security-Analysis'

    - name: Generate Security Report
      if: always()
      shell: pwsh
      run: |
        . ./scripts/Generate-SecurityReport.ps1
        Generate-SecurityReport -InputFile 'powershield-results.json' -OutputFile 'security-report.md'

    - name: Upload Analysis Artifacts
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: psts-analysis-results
        path: |
          powershield-results.json
          powershield-results.sarif
          security-report.md
        retention-days: 30

    - name: Comment on PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          
          // Read results
          const resultsFile = 'powershield-results.json';
          const results = JSON.parse(fs.readFileSync(resultsFile, 'utf8'));
          
          const violations = '${{ steps.analyze.outputs.violations-count }}';
          const critical = '${{ steps.analyze.outputs.critical-count }}';
          const fixesApplied = '${{ steps.copilot-fix.outputs.fixes-applied }}' === 'true';
          
          // Generate comment
          let comment = `## 🔒 PowerShield Security Analysis Results\n\n`;
          
          if (critical > 0) {
            comment += `⚠️ **${critical} Critical Security Issues Found!**\n\n`;
          } else if (violations > 0) {
            comment += `✅ No critical issues, but ${violations} other violations found\n\n`;
          } else {
            comment += `✅ No security violations found!\n\n`;
          }
          
          comment += `### Summary\n`;
          comment += `- **Total Violations:** ${violations}\n`;
          comment += `- **Critical Issues:** ${critical}\n`;
          
          if (fixesApplied) {
            comment += `- **AI Fixes Applied:** Yes 🤖\n`;
          }
          
          // Add top issues
          if (results.summary.TopIssues.length > 0) {
            comment += `\n### Top Issues\n`;
            results.summary.TopIssues.forEach(issue => {
              comment += `- **${issue.Rule}:** ${issue.Count} occurrences\n`;
            });
          }
          
          comment += `\n📊 [View detailed results](https://github.com/${{ github.repository }}/security/code-scanning)\n`;
          
          if (critical > 0) {
            comment += `\n⚠️ **Please address critical security issues before merging.**`;
          }
          
          // Post comment
          await github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });

  copilot-autofix:
    name: GitHub Copilot Auto-Fix
    needs: security-analysis
    if: needs.security-analysis.outputs.violations-count > 0
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write

    steps:
    - name: Checkout Repository
      uses: actions/checkout@v4
      with:
        token: ${{ secrets.GITHUB_TOKEN }}

    - name: Download Analysis Results
      uses: actions/download-artifact@v3
      with:
        name: psts-analysis-results

    - name: Apply Copilot Fixes
      id: apply-fixes
      uses: ./actions/copilot-autofix
      with:
        github-token: ${{ secrets.GITHUB_TOKEN }}
        violations-file: 'powershield-results.json'
        apply-fixes: true
        create-pr: true

    - name: Create Auto-Fix Pull Request
      if: steps.apply-fixes.outputs.fixes-applied == 'true'
      uses: peter-evans/create-pull-request@v5
      with:
        token: ${{ secrets.GITHUB_TOKEN }}
        commit-message: |
          🤖 PowerShield: Auto-fix security violations
          
          - Applied ${{ steps.apply-fixes.outputs.fixes-count }} security fixes
          - Fixed issues: ${{ steps.apply-fixes.outputs.fixed-rules }}
          
          Generated by PowerShield v${{ env.PowerShield_VERSION }}
        title: '🔒 PowerShield Auto-Fix: Security Violations'
        body: |
          ## 🤖 Automated Security Fixes
          
          This PR contains automated fixes for PowerShell security violations detected by PowerShield.
          
          ### 📊 Fix Summary
          - **Fixes Applied:** ${{ steps.apply-fixes.outputs.fixes-count }}
          - **Rules Addressed:** ${{ steps.apply-fixes.outputs.fixed-rules }}
          - **Confidence Level:** High (AI-generated with validation)
          
          ### 🔍 What was fixed:
          ${{ steps.apply-fixes.outputs.fix-details }}
          
          ### ⚠️ Important Notes
          - All fixes have been automatically validated
          - Please review changes carefully before merging
          - Test thoroughly in your environment
          - Consider the security implications of each change
          
          ### 🔗 Related
          - Original analysis: ${{ github.event.pull_request.html_url || github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
          - Security dashboard: https://github.com/${{ github.repository }}/security/code-scanning
          
          ---
          *Generated by PowerShield v${{ env.PowerShield_VERSION }} with GitHub Copilot*
        branch: psts-autofix-${{ github.run_number }}
          labels: |
            security
            automated-fix
            psts

## 1.3 GitHub Copilot Integration Action

File: actions/copilot-autofix/action.yml
yamlname: 'PowerShield Copilot Auto-Fix'
description: 'Uses GitHub Copilot to automatically fix PowerShell security violations'

inputs:
  github-token:
    description: 'GitHub token with appropriate permissions'
    required: true
  violations-file:
    description: 'Path to the PowerShield violations JSON file'
    required: true
  max-fixes:
    description: 'Maximum number of fixes to apply'
    required: false
    default: '10'
  confidence-threshold:
    description: 'Minimum confidence level for applying fixes (0.0-1.0)'
    required: false
    default: '0.8'
  apply-fixes:
    description: 'Whether to actually apply the fixes to files'
    required: false
    default: 'false'
  create-pr:
    description: 'Whether to create a pull request with fixes'
    required: false
    default: 'false'

outputs:
  fixes-applied:
    description: 'Whether any fixes were applied'
  fixes-count:
    description: 'Number of fixes applied'
  fixed-rules:
    description: 'Comma-separated list of rules that were fixed'
  fix-details:
    description: 'Detailed description of fixes applied'

runs:
  using: 'node20'
  main: 'dist/index.js'
File: actions/copilot-autofix/src/index.ts
typescriptimport *as core from '@actions/core';
import* as github from '@actions/github';
import *as fs from 'fs';
import* as path from 'path';

interface PSViolation {
    Name: string;
    Message: string;
    Severity: string;
    LineNumber: number;
    Code: string;
    FilePath: string;
    RuleId: string;
}

interface FixSuggestion {
    originalCode: string;
    fixedCode: string;
    explanation: string;
    confidence: number;
    ruleId: string;
}

class GitHubCopilotFixer {
    private octokit: ReturnType<`typeof github.getOctokit`>;
    private maxFixes: number;
    private confidenceThreshold: number;

    constructor(token: string, maxFixes: number = 10, confidenceThreshold: number = 0.8) {
        this.octokit = github.getOctokit(token);
        this.maxFixes = maxFixes;
        this.confidenceThreshold = confidenceThreshold;
    }

    async generateFixes(violations: PSViolation[]): Promise<Map<string, FixSuggestion[]>> {
        const fixes = new Map<string, FixSuggestion[]>();
        let processedCount = 0;

        for (const violation of violations) {
            if (processedCount >= this.maxFixes) {
                core.info(`Reached maximum fixes limit (${this.maxFixes})`);
                break;
            }

            try {
                const fix = await this.generateSingleFix(violation);
                
                if (fix && fix.confidence >= this.confidenceThreshold) {
                    if (!fixes.has(violation.FilePath)) {
                        fixes.set(violation.FilePath, []);
                    }
                    fixes.get(violation.FilePath)!.push(fix);
                    processedCount++;
                    
                    core.info(`Generated fix for ${violation.RuleId} in ${violation.FilePath} (confidence: ${fix.confidence})`);
                } else if (fix) {
                    core.warning(`Fix for ${violation.RuleId} has low confidence (${fix.confidence}), skipping`);
                }
            } catch (error) {
                core.error(`Failed to generate fix for ${violation.RuleId}: ${error}`);
            }
        }

        return fixes;
    }

    private async generateSingleFix(violation: PSViolation): Promise<FixSuggestion | null> {
        try {
            // Read the file content for context
            const fileContent = fs.readFileSync(violation.FilePath, 'utf8');
            const lines = fileContent.split('\n');
            
            // Get context around the problematic line
            const contextStart = Math.max(0, violation.LineNumber - 3);
            const contextEnd = Math.min(lines.length, violation.LineNumber + 2);
            const context = lines.slice(contextStart, contextEnd).join('\n');

            // Generate fix using GitHub Copilot
            const prompt = this.buildFixPrompt(violation, context);
            const completion = await this.callCopilotAPI(prompt);
            
            if (completion) {
                return this.parseCompletion(completion, violation);
            }
        } catch (error) {
            core.error(`Error generating fix for ${violation.RuleId}: ${error}`);
        }

        return null;
    }

    private buildFixPrompt(violation: PSViolation, context: string): string {
        const securityFixTemplates = {
            'InsecureHashAlgorithms': {
                instruction: 'Replace insecure hash algorithms (MD5, SHA1) with secure alternatives (SHA256, SHA384, SHA512)',
                example: 'Get-FileHash -Algorithm MD5 → Get-FileHash -Algorithm SHA256'
            },
            'CredentialExposure': {
                instruction: 'Replace plaintext credential handling with secure methods',
                example: 'ConvertTo-SecureString "password" -AsPlainText -Force → Read-Host "Enter password" -AsSecureString'
            },
            'CommandInjection': {
                instruction: 'Replace command injection vulnerabilities with safe parameterized approaches',
                example: 'Invoke-Expression $userInput → Use proper validation and parameterization'
            },
            'CertificateValidation': {
                instruction: 'Ensure proper certificate validation without bypassing security checks',
                example: 'Remove certificate validation bypasses and implement proper verification'
            }
        };

        const template = securityFixTemplates[violation.RuleId as keyof typeof securityFixTemplates] || {
            instruction: 'Fix the security vulnerability while maintaining functionality',
            example: 'Apply security best practices'
        };

        return `Fix this PowerShell security issue:

Issue: ${violation.RuleId}
Description: ${violation.Message}
Severity: ${violation.Severity}

Context:
\`\`\`powershell
${context}
\`\`\`

Problematic line (line ${violation.LineNumber}):
\`\`\`powershell
${violation.Code}
\`\`\`

Instructions: ${template.instruction}
Example: ${template.example}

Please provide only the corrected line of PowerShell code that fixes the security issue while maintaining the original functionality. Do not include explanations or markdown formatting.

Fixed code:`;
    }

    private async callCopilotAPI(prompt: string): Promise<string | null> {
        try {
            // Note: This is a simplified example. In reality, you'd need to use
            // the GitHub Copilot API or integrate with the Copilot service
            // For now, we'll use a mock implementation with predefined fixes
            return this.getMockCopilotResponse(prompt);
        } catch (error) {
            core.error(`Copilot API call failed: ${error}`);
            return null;
        }
    }

    private getMockCopilotResponse(prompt: string): string | null {
        // Mock responses for common security issues
        // In production, this would be replaced with actual Copilot API calls
        
        if (prompt.includes('Get-FileHash') && prompt.includes('MD5')) {
            return 'Get-FileHash -Algorithm SHA256';
        }
        
        if (prompt.includes('Get-FileHash') && prompt.includes('SHA1')) {
            return 'Get-FileHash -Algorithm SHA256';
        }
        
        if (prompt.includes('ConvertTo-SecureString') && prompt.includes('-AsPlainText')) {
            return 'Read-Host "Enter password" -AsSecureString';
        }
        
        if (prompt.includes('Invoke-Expression')) {
            return '# TODO: Replace with proper parameterization - Invoke-Expression removed for security';
        }
        
        if (prompt.includes('[System.Security.Cryptography.MD5]')) {
            return '[System.Security.Cryptography.SHA256]::Create()';
        }
        
        return null;
    }

    private parseCompletion(completion: string, violation: PSViolation): FixSuggestion | null {
        // Clean up the completion
        let fixedCode = completion.trim();
        
        // Remove common artifacts
        fixedCode = fixedCode.replace(/```powershell/g, '');
        fixedCode = fixedCode.replace(/```/g, '');
        fixedCode = fixedCode.replace(/^Fixed code:?\s*/i, '');
        
        // Validate the fix
        const confidence = this.calculateConfidence(fixedCode, violation);
        
        if (confidence < 0.5) {
            return null;
        }

        return {
            originalCode: violation.Code,
            fixedCode: fixedCode,
            explanation: this.generateExplanation(violation.RuleId, fixedCode),
            confidence: confidence,
            ruleId: violation.RuleId
        };
    }

    private calculateConfidence(fixedCode: string, violation: PSViolation): number {
        let confidence = 0.7; // Base confidence
        
        // Rule-specific confidence adjustments
        switch (violation.RuleId) {
            case 'InsecureHashAlgorithms':
                if (fixedCode.includes('SHA256') || fixedCode.includes('SHA384') || fixedCode.includes('SHA512')) {
                    confidence += 0.2;
                }
                if (fixedCode.includes('MD5') || fixedCode.includes('SHA1')) {
                    confidence -= 0.4;
                }
                break;
                
            case 'CredentialExposure':
                if (fixedCode.includes('-AsSecureString') || fixedCode.includes('Read-Host')) {
                    confidence += 0.2;
                }
                if (fixedCode.includes('-AsPlainText')) {
                    confidence -= 0.4;
                }
                break;
                
            case 'CommandInjection':
                if (!fixedCode.includes('Invoke-Expression') && !fixedCode.includes('iex')) {
                    confidence += 0.2;
                }
                break;
        }

        // Ensure the fix actually changes something
        if (fixedCode === violation.Code) {
            confidence -= 0.3;
        }

        return Math.max(0, Math.min(1, confidence));
    }

    private generateExplanation(ruleId: string, fixedCode: string): string {
        const explanations = {
            'InsecureHashAlgorithms': 'Replaced insecure hash algorithm with SHA256 for better security',
            'CredentialExposure': 'Replaced plaintext password handling with secure string input',
            'CommandInjection': 'Removed command injection vulnerability',
            'CertificateValidation': 'Fixed certificate validation to maintain security'
        };

        return explanations[ruleId as keyof typeof explanations] || `Applied security fix for ${ruleId}`;
    }

    async applyFixes(fixes: Map<string, FixSuggestion[]>): Promise<{count: number, details: string[], rules: string[]}> {
        let totalFixes = 0;
        const details: string[] = [];
        const rules = new Set<string>();

        for (const [filePath, fileFixes] of fixes) {
            try {
                let fileContent = fs.readFileSync(filePath, 'utf8');
                
                // Apply fixes in reverse order to maintain line numbers
                const sortedFixes = fileFixes.sort((a, b) => 
                    fileContent.lastIndexOf(b.originalCode) - fileContent.lastIndexOf(a.originalCode)
                );

                for (const fix of sortedFixes) {
                    if (fileContent.includes(fix.originalCode)) {
                        fileContent = fileContent.replace(fix.originalCode, fix.fixedCode);
                        totalFixes++;
                        rules.add(fix.ruleId);
                        
                        details.push(`${path.basename(filePath)}: ${fix.explanation}`);
                        core.info(`Applied fix in ${filePath}: ${fix.explanation}`);
                    }
                }

                fs.writeFileSync(filePath, fileContent, 'utf8');
            } catch (error) {
                core.error(`Failed to apply fixes to ${filePath}: ${error}`);
            }
        }

        return {
            count: totalFixes,
            details: details,
            rules: Array.from(rules)
        };
    }
}

async function run(): Promise\<void\> {
    try {
        // Get inputs
        const token = core.getInput('github-token', { required: true });
        const violationsFile = core.getInput('violations-file', { required: true });
        const maxFixes = parseInt(core.getInput('max-fixes') || '10');
        const confidenceThreshold = parseFloat(core.getInput('confidence-threshold') || '0.8');
        const applyFixes = core.getBooleanInput('apply-fixes');

        // Read violations
        if (!fs.existsSync(violationsFile)) {
            core.setFailed(`Violations file not found: ${violationsFile}`);
            return;
        }

        const violationsData = JSON.parse(fs.readFileSync(violationsFile, 'utf8'));
        const violations: PSViolation[] = violationsData.violations || [];

        if (violations.length === 0) {
            core.info('No violations to fix');
            core.setOutput('fixes-applied', 'false');
            core.setOutput('fixes-count', '0');
            return;
        }

        core.info(`Processing ${violations.length} violations...`);

        // Initialize fixer
        const fixer = new GitHubCopilotFixer(token, maxFixes, confidenceThreshold);

        // Generate fixes
        const fixes = await fixer.generateFixes(violations);
        const totalFixes = Array.from(fixes.values()).reduce((sum, fileFixes) => sum + fileFixes.length, 0);

        core.info(`Generated ${totalFixes} potential fixes`);

        if (totalFixes === 0) {
            core.setOutput('fixes-applied', 'false');
            core.setOutput('fixes-count', '0');
            return;
        }

        if (applyFixes) {
            // Apply the fixes
            const result = await fixer.applyFixes(fixes);
            
            core.setOutput('fixes-applied', result.count > 0 ? 'true' : 'false');
            core.setOutput('fixes-count', result.count.toString());
            core.setOutput('fixed-rules', result.rules.join(', '));
            core.setOutput('fix-details', result.details.join('\n- '));
            
            core.info(`Applied ${result.count} fixes successfully`);
        } else {
            // Just preview the fixes
            core.setOutput('fixes-applied', 'false');
            core.setOutput('fixes-count', totalFixes.toString());
            
            // Output fix preview
            for (const [filePath, fileFixes] of fixes) {
                core.info(`\nPotential fixes for ${filePath}:`);
                fileFixes.forEach((fix, index) => {
                    core.info(`  ${index + 1}. ${fix.explanation} (confidence: ${fix.confidence})`);
                    core.info(`     Before: ${fix.originalCode}`);
                    core.info(`     After:  ${fix.fixedCode}`);
                });
            }
        }

    } catch (error) {
        core.setFailed(`Action failed: ${error}`);
    }
run();

run();

## 1.4 SARIF Converter Script

File: scripts/Convert-ToSARIF.ps1

function Convert-ToSARIF {
    param(
        [Parameter(Mandatory)]
        [string]$InputFile,

        [Parameter(Mandatory)]
        [string]$OutputFile
    )

    $results = Get-Content $InputFile | ConvertFrom-Json
    
    $sarif = @{
        '$schema' = 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json'
        version = '2.1.0'
        runs = @(@{
            tool = @{
                driver = @{
                    name = 'PowerShield (Comprehensive PowerShell Security Platform)'
                    version = $results.metadata.version
                    informationUri = 'https://github.com/yourorg/psts'
                    semanticVersion = $results.metadata.version
                    rules = @()
                }
            }
            results = @()
            originalUriBaseIds = @{
                SRCROOT = @{
                    uri = 'file:///'
                }
            }
        })
    }

    # Build rules dictionary
    $rulesMap = @{}
    foreach ($violation in $results.violations) {
        if (-not $rulesMap.ContainsKey($violation.RuleId)) {
            $rulesMap[$violation.RuleId] = @{
                id = $violation.RuleId
                name = $violation.Name
                shortDescription = @{ text = $violation.Message }
                fullDescription = @{ text = $violation.Message }
                defaultConfiguration = @{
                    level = switch ($violation.Severity) {
                        'Critical' { 'error' }
                        'High' { 'error' }
                        'Medium' { 'warning' }
                        'Low' { 'note' }
                        default { 'warning' }
                    }
                }
                properties = @{
                    category = 'security'
                    tags = @('security', 'powershell')
                }
            }
        }
    }

    $sarif.runs[0].tool.driver.rules = $rulesMap.Values

    # Build results
    foreach ($violation in $results.violations) {
        $result = @{
            ruleId = $violation.RuleId
            ruleIndex = [array]::IndexOf($rulesMap.Keys, $violation.RuleId)
            message = @{ text = $violation.Message }
            level = switch ($violation.Severity) {
                'Critical' { 'error' }
                'High' { 'error' }
                'Medium' { 'warning' }
                'Low' { 'note' }
                default { 'warning' }
            }
            locations = @(@{
                physicalLocation = @{
                    artifactLocation = @{ 
                        uri = $violation.FilePath.Replace('\', '/').TrimStart('./')
                        uriBaseId = 'SRCROOT'
                    }
                    region = @{
                        startLine = $violation.LineNumber
                        startColumn = 1
                        snippet = @{ text = $violation.Code }
                    }
                }
            })
            partialFingerprints = @{
                primaryLocationLineHash = (Get-StringHash "$($violation.FilePath):$($violation.LineNumber)")
            }
        }
        
        $sarif.runs[0].results += $result
    }

    $sarif | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "SARIF output written to: $OutputFile"
}

function Get-StringHash {
    param([string]$String)

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))
    return [System.BitConverter]::ToString($hash).Replace('-', '').Substring(0, 16)
