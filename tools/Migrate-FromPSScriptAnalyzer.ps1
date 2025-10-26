#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    PSScriptAnalyzer to PowerShield migration utility
.DESCRIPTION
    Migrates PSScriptAnalyzer configurations, rules, and suppressions to PowerShield format.
    Provides side-by-side comparison and gap analysis.
.NOTES
    Version: 1.7.0
    Author: PowerShield Project
.EXAMPLE
    ./Migrate-FromPSScriptAnalyzer.ps1 -ConfigPath ./PSScriptAnalyzerSettings.psd1
.EXAMPLE
    ./Migrate-FromPSScriptAnalyzer.ps1 -RulesOnly -Output .powershield.yml
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "PSScriptAnalyzerSettings.psd1",
    
    [Parameter(Mandatory = $false)]
    [string]$Output = ".powershield.yml",
    
    [Parameter(Mandatory = $false)]
    [switch]$RulesOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport,
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = "migration-report.md",
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

# Color output helpers
function Write-MigrationInfo { param([string]$Message) Write-Host "ℹ $Message" -ForegroundColor Cyan }
function Write-MigrationSuccess { param([string]$Message) Write-Host "✓ $Message" -ForegroundColor Green }
function Write-MigrationWarning { param([string]$Message) Write-Host "⚠ $Message" -ForegroundColor Yellow }
function Write-MigrationError { param([string]$Message) Write-Host "✗ $Message" -ForegroundColor Red }

# PSScriptAnalyzer to PowerShield rule mapping
$script:RuleMapping = @{
    # Direct mappings
    "PSAvoidUsingConvertToSecureStringWithPlainText" = @{
        PowerShieldRule = "CredentialExposure"
        Confidence = "High"
        Notes = "Direct equivalent - detects plaintext credential handling"
    }
    "PSAvoidUsingInvokeExpression" = @{
        PowerShieldRule = "CommandInjection"
        Confidence = "High"
        Notes = "Direct equivalent - detects unsafe Invoke-Expression usage"
    }
    "PSUseDeclaredVarsMoreThanAssignments" = @{
        PowerShieldRule = $null
        Confidence = "N/A"
        Notes = "No direct equivalent - code quality rule, not security"
    }
    "PSAvoidUsingPlainTextForPassword" = @{
        PowerShieldRule = "CredentialExposure"
        Confidence = "High"
        Notes = "Direct equivalent - credential exposure detection"
    }
    "PSAvoidUsingUsernameAndPasswordParams" = @{
        PowerShieldRule = "CredentialExposure"
        Confidence = "Medium"
        Notes = "Partially covered by CredentialExposure rule"
    }
    "PSAvoidUsingComputerNameHardcoded" = @{
        PowerShieldRule = "HardcodedURLs"
        Confidence = "Medium"
        Notes = "Similar concept - hardcoded values detection"
    }
    "PSAvoidUsingBrokenHashAlgorithms" = @{
        PowerShieldRule = "InsecureHashAlgorithms"
        Confidence = "High"
        Notes = "Direct equivalent - detects MD5, SHA1, etc."
    }
    "PSUseShouldProcessForStateChangingFunctions" = @{
        PowerShieldRule = $null
        Confidence = "N/A"
        Notes = "No direct equivalent - PowerShell best practice, not security"
    }
    "PSAvoidGlobalVars" = @{
        PowerShieldRule = $null
        Confidence = "N/A"
        Notes = "No direct equivalent - code quality rule"
    }
}

# Additional PowerShield security features not in PSScriptAnalyzer
$script:PowerShieldExclusiveFeatures = @{
    "ExecutionPolicyBypass" = "Detects PowerShell execution policy bypasses"
    "PowerShellVersionDowngrade" = "Detects PowerShell v2 downgrade attacks"
    "UnsafePSRemoting" = "Detects insecure PowerShell remoting"
    "PrivilegeEscalation" = "Detects privilege escalation attempts"
    "ScriptInjection" = "Detects dynamic script generation vulnerabilities"
    "PowerShellObfuscationDetection" = "Detects obfuscation techniques"
    "DownloadCradleDetection" = "Detects download cradles"
    "PersistenceMechanismDetection" = "Detects persistence mechanisms"
    "CredentialHarvestingDetection" = "Detects credential harvesting"
    "LateralMovementDetection" = "Detects lateral movement techniques"
    "DataExfiltrationDetection" = "Detects data exfiltration attempts"
    "AMSIEvasion" = "Detects AMSI bypass attempts"
    "ETWEvasion" = "Detects ETW evasion techniques"
    "AzurePowerShellCredentialLeaks" = "Azure credential exposure"
    "AzureResourceExposure" = "Azure resource security"
}

<#
.SYNOPSIS
    Loads PSScriptAnalyzer configuration from PSD1 file
#>
function Read-PSScriptAnalyzerConfig {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-MigrationWarning "PSScriptAnalyzer config not found at: $Path"
        Write-MigrationInfo "Creating default PowerShield configuration..."
        return $null
    }
    
    try {
        Write-MigrationInfo "Reading PSScriptAnalyzer configuration from: $Path"
        $config = Import-PowerShellDataFile -Path $Path
        Write-MigrationSuccess "Successfully loaded PSScriptAnalyzer configuration"
        return $config
    }
    catch {
        Write-MigrationError "Failed to read PSScriptAnalyzer config: $_"
        return $null
    }
}

<#
.SYNOPSIS
    Converts PSScriptAnalyzer configuration to PowerShield format
#>
function Convert-ToPowerShieldConfig {
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$PSScriptAnalyzerConfig,
        
        [Parameter(Mandatory = $false)]
        [switch]$RulesOnly
    )
    
    $powershieldConfig = @{
        version = "1.0"
    }
    
    # Analysis settings
    if (-not $RulesOnly) {
        $powershieldConfig.analysis = @{
            severity_threshold = "Medium"
            exclude_paths = @()
            exclude_files = @()
        }
        
        # Map ExcludeRules if present
        if ($PSScriptAnalyzerConfig -and $PSScriptAnalyzerConfig.ContainsKey('ExcludeRules')) {
            Write-MigrationInfo "Found ExcludeRules in PSScriptAnalyzer config"
            # These will be handled in rule mapping
        }
        
        # Map IncludeRules if present
        if ($PSScriptAnalyzerConfig -and $PSScriptAnalyzerConfig.ContainsKey('IncludeRules')) {
            Write-MigrationInfo "Found IncludeRules in PSScriptAnalyzer config"
            # These will be handled in rule mapping
        }
    }
    
    # Rules configuration
    $powershieldConfig.rules = @{}
    
    # Add all PowerShield rules with defaults
    $defaultRules = @(
        @{ Name = "InsecureHashAlgorithms"; Severity = "High"; Enabled = $true }
        @{ Name = "CredentialExposure"; Severity = "Critical"; Enabled = $true }
        @{ Name = "CommandInjection"; Severity = "Critical"; Enabled = $true }
        @{ Name = "CertificateValidation"; Severity = "High"; Enabled = $true }
        @{ Name = "ExecutionPolicyBypass"; Severity = "Critical"; Enabled = $true }
        @{ Name = "UnsafePSRemoting"; Severity = "Critical"; Enabled = $true }
        @{ Name = "PowerShellVersionDowngrade"; Severity = "Critical"; Enabled = $true }
        @{ Name = "PrivilegeEscalation"; Severity = "Critical"; Enabled = $true }
    )
    
    foreach ($rule in $defaultRules) {
        $powershieldConfig.rules[$rule.Name] = @{
            enabled = $rule.Enabled
            severity = $rule.Severity
        }
    }
    
    # Map PSScriptAnalyzer rules to PowerShield
    if ($PSScriptAnalyzerConfig) {
        $includeRules = $PSScriptAnalyzerConfig.IncludeRules
        $excludeRules = $PSScriptAnalyzerConfig.ExcludeRules
        
        if ($excludeRules) {
            foreach ($excludedRule in $excludeRules) {
                if ($script:RuleMapping.ContainsKey($excludedRule)) {
                    $mapping = $script:RuleMapping[$excludedRule]
                    if ($mapping.PowerShieldRule) {
                        Write-MigrationInfo "Disabling $($mapping.PowerShieldRule) (mapped from excluded $excludedRule)"
                        if ($powershieldConfig.rules.ContainsKey($mapping.PowerShieldRule)) {
                            $powershieldConfig.rules[$mapping.PowerShieldRule].enabled = $false
                        }
                    }
                }
            }
        }
    }
    
    # Auto-fix configuration (disabled by default for safety)
    if (-not $RulesOnly) {
        $powershieldConfig.autofix = @{
            enabled = $false
            provider = "github-models"
            model = "gpt-4o-mini"
            confidence_threshold = 0.8
            apply_automatically = $false
        }
    }
    
    return $powershieldConfig
}

<#
.SYNOPSIS
    Generates migration report with gaps and recommendations
#>
function New-MigrationReport {
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$PSScriptAnalyzerConfig,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$PowerShieldConfig
    )
    
    $report = @"
# PSScriptAnalyzer to PowerShield Migration Report

**Generated**: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

---

## Migration Summary

"@
    
    if ($PSScriptAnalyzerConfig) {
        $psaRuleCount = if ($PSScriptAnalyzerConfig.IncludeRules) { $PSScriptAnalyzerConfig.IncludeRules.Count } else { "All default rules" }
        $psaExcludeCount = if ($PSScriptAnalyzerConfig.ExcludeRules) { $PSScriptAnalyzerConfig.ExcludeRules.Count } else { 0 }
        
        $report += @"

### PSScriptAnalyzer Configuration
- **Rules Enabled**: $psaRuleCount
- **Rules Excluded**: $psaExcludeCount
- **Configuration File**: Found and parsed

"@
    }
    else {
        $report += @"

### PSScriptAnalyzer Configuration
- **Status**: No existing configuration found
- **Action**: Creating default PowerShield configuration

"@
    }
    
    $psRuleCount = $PowerShieldConfig.rules.Count
    $psEnabledCount = ($PowerShieldConfig.rules.GetEnumerator() | Where-Object { $_.Value.enabled -eq $true }).Count
    
    $report += @"

### PowerShield Configuration
- **Total Rules**: $psRuleCount configured
- **Enabled Rules**: $psEnabledCount
- **Disabled Rules**: $($psRuleCount - $psEnabledCount)

---

## Rule Mapping Analysis

### Successfully Mapped Rules

"@
    
    # Add mapped rules
    if ($PSScriptAnalyzerConfig -and $PSScriptAnalyzerConfig.IncludeRules) {
        foreach ($psaRule in $PSScriptAnalyzerConfig.IncludeRules) {
            if ($script:RuleMapping.ContainsKey($psaRule)) {
                $mapping = $script:RuleMapping[$psaRule]
                if ($mapping.PowerShieldRule) {
                    $report += "- **$psaRule** → **$($mapping.PowerShieldRule)** (Confidence: $($mapping.Confidence))`n"
                    $report += "  - $($mapping.Notes)`n`n"
                }
            }
        }
    }
    
    $report += @"

### Rules Without Direct Equivalent

"@
    
    # Add unmapped rules
    if ($PSScriptAnalyzerConfig -and $PSScriptAnalyzerConfig.IncludeRules) {
        $unmappedCount = 0
        foreach ($psaRule in $PSScriptAnalyzerConfig.IncludeRules) {
            if ($script:RuleMapping.ContainsKey($psaRule)) {
                $mapping = $script:RuleMapping[$psaRule]
                if (-not $mapping.PowerShieldRule) {
                    $unmappedCount++
                    $report += "- **$psaRule**: $($mapping.Notes)`n"
                }
            }
            else {
                $unmappedCount++
                $report += "- **$psaRule**: No mapping information available`n"
            }
        }
        
        if ($unmappedCount -eq 0) {
            $report += "*None - all PSScriptAnalyzer rules have been mapped or are not security-related*`n"
        }
    }
    else {
        $report += "*No PSScriptAnalyzer rules to map*`n"
    }
    
    $report += @"

---

## PowerShield Exclusive Features

PowerShield includes advanced security features not available in PSScriptAnalyzer:

"@
    
    foreach ($feature in $script:PowerShieldExclusiveFeatures.GetEnumerator()) {
        $report += "- **$($feature.Key)**: $($feature.Value)`n"
    }
    
    $report += @"

---

## Migration Steps Completed

1. ✅ Analyzed PSScriptAnalyzer configuration
2. ✅ Mapped compatible rules to PowerShield equivalents
3. ✅ Generated PowerShield configuration
4. ✅ Identified coverage gaps
5. ✅ Added PowerShield-exclusive security rules

---

## Next Steps

### 1. Review Generated Configuration
Review the generated `.powershield.yml` file and adjust settings as needed.

### 2. Test PowerShield Analysis
Run PowerShield on your codebase to verify detection:
``````powershell
./psts analyze ./your-scripts
``````

### 3. Configure Auto-Fix (Optional)
If desired, enable AI-powered auto-fix in `.powershield.yml`:
``````yaml
autofix:
  enabled: true
  provider: "github-models"
  confidence_threshold: 0.8
``````

### 4. Set Up CI/CD Integration
Add PowerShield to your CI/CD pipeline. See [CI/CD Integration Guide](docs/CI_CD_INTEGRATION.md).

### 5. Migrate Suppressions
If you have PSScriptAnalyzer suppressions, convert them to PowerShield format:
``````powershell
# PSScriptAnalyzer format
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]

# PowerShield format
# POWERSHIELD-SUPPRESS-NEXT: CommandInjection - Reason here
``````

See [Suppression Guide](docs/SUPPRESSION_GUIDE.md) for details.

---

## Support

- **Documentation**: https://github.com/J-Ellette/PowerShield/docs
- **Migration Guide**: docs/MIGRATION_GUIDE.md
- **Issues**: https://github.com/J-Ellette/PowerShield/issues

---

*Generated by PowerShield Migration Utility v1.7.0*
"@
    
    return $report
}

<#
.SYNOPSIS
    Exports PowerShield configuration to YAML format
#>
function Export-PowerShieldConfig {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,
        
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    # Simple YAML export (without requiring powershell-yaml module)
    $yaml = @"
# PowerShield Configuration
# Migrated from PSScriptAnalyzer
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

version: "$($Config.version)"

"@
    
    if ($Config.analysis) {
        $yaml += @"
# Analysis Settings
analysis:
  severity_threshold: "$($Config.analysis.severity_threshold)"
  exclude_paths:
"@
        foreach ($path in $Config.analysis.exclude_paths) {
            $yaml += "`n    - `"$path`""
        }
        $yaml += "`n`n"
    }
    
    $yaml += @"
# Rule Configuration
rules:
"@
    
    foreach ($rule in $Config.rules.GetEnumerator() | Sort-Object Name) {
        $yaml += @"

  $($rule.Key):
    enabled: $($rule.Value.enabled.ToString().ToLower())
    severity: "$($rule.Value.severity)"
"@
    }
    
    if ($Config.autofix) {
        $yaml += @"

# Auto-Fix Configuration (disabled by default for safety)
autofix:
  enabled: $($Config.autofix.enabled.ToString().ToLower())
  provider: "$($Config.autofix.provider)"
  model: "$($Config.autofix.model)"
  confidence_threshold: $($Config.autofix.confidence_threshold)
  apply_automatically: $($Config.autofix.apply_automatically.ToString().ToLower())
"@
    }
    
    $yaml += @"

# For complete configuration options, see .powershield.yml.example
"@
    
    return $yaml
}

# Main execution
function Invoke-Migration {
    Write-Host "`n=== PSScriptAnalyzer to PowerShield Migration ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Read PSScriptAnalyzer config
    $psaConfig = Read-PSScriptAnalyzerConfig -Path $ConfigPath
    
    # Convert to PowerShield format
    Write-MigrationInfo "Converting configuration to PowerShield format..."
    $psConfig = Convert-ToPowerShieldConfig -PSScriptAnalyzerConfig $psaConfig -RulesOnly:$RulesOnly
    
    # Generate YAML
    $yaml = Export-PowerShieldConfig -Config $psConfig -Path $Output
    
    # Output results
    if ($DryRun) {
        Write-MigrationInfo "DRY RUN - Configuration preview:"
        Write-Host "`n$yaml`n" -ForegroundColor Gray
    }
    else {
        $yaml | Out-File -FilePath $Output -Encoding UTF8
        Write-MigrationSuccess "PowerShield configuration written to: $Output"
    }
    
    # Generate report if requested
    if ($GenerateReport) {
        Write-MigrationInfo "Generating migration report..."
        $report = New-MigrationReport -PSScriptAnalyzerConfig $psaConfig -PowerShieldConfig $psConfig
        
        if ($DryRun) {
            Write-Host "`n$report`n" -ForegroundColor Gray
        }
        else {
            $report | Out-File -FilePath $ReportPath -Encoding UTF8
            Write-MigrationSuccess "Migration report written to: $ReportPath"
        }
    }
    
    # Summary
    Write-Host "`n=== Migration Complete ===" -ForegroundColor Green
    Write-MigrationSuccess "PowerShield configuration ready"
    Write-MigrationInfo "Next steps:"
    Write-Host "  1. Review generated configuration: $Output" -ForegroundColor White
    Write-Host "  2. Test PowerShield: ./psts analyze" -ForegroundColor White
    if ($GenerateReport) {
        Write-Host "  3. Review migration report: $ReportPath" -ForegroundColor White
    }
    Write-Host ""
}

# Run migration
Invoke-Migration
