# Rule Marketplace & Community Plugins - Implementation Guide

## Overview

PowerShield now supports custom YAML-based security rules through the Rule Marketplace & Community Plugins feature. This allows security teams and the community to extend PowerShield's detection capabilities beyond the built-in rules.

## Installation

### Prerequisites

The custom rules feature requires the `powershell-yaml` module for YAML parsing:

```powershell
Install-Module -Name powershell-yaml -Scope CurrentUser -Force
```

**Note**: If this module is not available in your PowerShell Gallery, you can still use PowerShield's built-in rules. Custom YAML rules will only work when this module is installed.

## Quick Start

### 1. Enable Custom Rules

Create or update your `.powershield.yml` configuration:

```yaml
custom_rules:
  enabled: true
  directories:
    - "./rules/custom"      # Your organization's custom rules
    - "./rules/community"   # Community-contributed rules
  auto_load: true          # Automatically load on analyzer initialization
```

### 2. Create Your First Custom Rule

Use the CLI to generate a template:

```powershell
psts rule create --output ./rules/custom/my-first-rule.yml --template command
```

This creates a template file you can edit:

```yaml
rule:
  id: "CustomRule001"
  name: "Detect Unsafe Command"
  severity: "High"
  category: "Security"
  
  patterns:
    - type: "command"
      command: "Invoke-UnsafeCommand"
      message: "Unsafe command detected"
  
  remediation: |
    Use the safe alternative: Invoke-SafeCommand
```

### 3. Validate Your Rule

```powershell
psts rule validate ./rules/custom/my-first-rule.yml
```

### 4. Test Your Rule

Run analysis to see your custom rule in action:

```powershell
psts analyze ./scripts
```

## CLI Commands

### Create Rules

```powershell
# Create from templates
psts rule create --output ./rules/custom/command-rule.yml --template command
psts rule create --output ./rules/custom/regex-rule.yml --template regex
psts rule create --output ./rules/custom/ast-rule.yml --template ast
psts rule create --output ./rules/custom/param-rule.yml --template parameter
psts rule create --output ./rules/custom/full-rule.yml --template comprehensive
```

### Validate Rules

```powershell
# Validate a single rule
psts rule validate ./rules/custom/my-rule.yml

# Validate all rules in a directory
psts rule validate-all ./rules/custom
```

### List Rules

```powershell
# List all loaded rules (built-in + custom)
psts rule list

# List only custom rules
psts rule list --custom-only
```

## Rule Pattern Types

### 1. Command Detection

Detects specific PowerShell command usage:

```yaml
patterns:
  - type: "command"
    command: "Invoke-Expression"
    message: "Dangerous command usage detected"
```

**Use cases**:
- Detecting unsafe cmdlets
- Finding deprecated commands
- Identifying security-sensitive operations

### 2. Regex Pattern Matching

Matches code patterns using regular expressions:

```yaml
patterns:
  - type: "regex"
    pattern: '\$password\s*=\s*["\'].+["\']'
    message: "Hardcoded password detected"
```

**Use cases**:
- Finding hardcoded credentials
- Detecting IP addresses or URLs
- Matching code patterns

### 3. AST Node Detection

Detects specific Abstract Syntax Tree node types:

```yaml
patterns:
  - type: "ast"
    ast_type: "TypeExpressionAst"
    filter: '$args[0].TypeName.Name -eq "WebClient"'
    message: "Direct WebClient usage detected"
```

**Use cases**:
- Advanced code structure analysis
- Type usage detection
- Complex pattern matching

### 4. Parameter Detection

Detects commands with specific parameters:

```yaml
patterns:
  - type: "parameter"
    command: "Invoke-WebRequest"
    parameter: "SkipCertificateCheck"
    message: "Certificate validation bypassed"
```

**Use cases**:
- Detecting unsafe parameter usage
- Finding insecure configurations
- Parameter value validation

## Community Rules Included

PowerShield includes several community-contributed rules:

### 1. ClearHostDetection (Low)
Detects `Clear-Host` usage which can hide important output in production logs.

### 2. WriteHostDetection (Low)
Detects `Write-Host` usage which is not pipeline-friendly.

### 3. HardcodedIPAddress (Medium)
Detects hardcoded IP addresses in scripts.

## Architecture

### Module Structure

```
src/
├── CustomRuleLoader.psm1         # YAML rule loading and validation
├── PowerShellSecurityAnalyzer.psm1  # Main analyzer with custom rule support
└── ConfigLoader.psm1             # Configuration loader with custom rules config
```

### Directory Structure

```
rules/
├── custom/         # Organization-specific custom rules
├── community/      # Community-contributed rules
└── templates/      # Rule templates for easy creation
```

### Rule Loading Flow

1. Configuration loaded from `.powershield.yml`
2. If `custom_rules.enabled` and `custom_rules.auto_load` are true
3. For each directory in `custom_rules.directories`
4. Load all `.yml` and `.yaml` files
5. Validate rule definitions
6. Convert to SecurityRule objects
7. Add to analyzer's rule collection

## Programmatic Usage

### From PowerShell

```powershell
# Import modules
Import-Module ./src/CustomRuleLoader.psm1
Import-Module ./src/PowerShellSecurityAnalyzer.psm1

# Load custom rules manually
$customRules = Import-CustomRules -RulesDirectory "./rules/custom"

# Create analyzer with auto-loading
$analyzer = New-SecurityAnalyzer -WorkspacePath "."

# Custom rules are automatically loaded if configured

# Run analysis
$result = Invoke-SecurityAnalysis -ScriptPath "./script.ps1"
```

### Manual Rule Loading

```powershell
# Load analyzer
$analyzer = [PowerShellSecurityAnalyzer]::new()

# Load custom rules from specific directory
$analyzer.LoadCustomRules("./rules/custom")
$analyzer.LoadCustomRules("./rules/community")

# Run analysis
$result = $analyzer.AnalyzeScript("./script.ps1")
```

## Best Practices

### Rule Design

1. **Unique IDs**: Use descriptive, unique IDs (e.g., `HardcodedPasswordDetection`)
2. **Clear Messages**: Provide actionable violation messages
3. **Appropriate Severity**: Choose severity based on impact
4. **Include Metadata**: Add CWE, MITRE ATT&CK, OWASP mappings when applicable
5. **Remediation Guidance**: Include clear remediation steps with examples

### Testing

1. **Validate First**: Always validate rules before using them
2. **Test Positive Cases**: Ensure rules detect intended patterns
3. **Test Negative Cases**: Verify no false positives on safe code
4. **Performance**: Test on large codebases to check performance impact

### Organization

1. **Separate Directories**: Keep custom and community rules separate
2. **Version Control**: Track custom rules in your repository
3. **Documentation**: Document each rule's purpose and rationale
4. **Review Process**: Establish peer review for custom rules

## Troubleshooting

### Rule Not Loading

**Symptom**: Custom rule doesn't appear in analysis results

**Solutions**:
1. Check YAML syntax: `psts rule validate <rule-file>`
2. Verify rule is in configured directory
3. Ensure `custom_rules.enabled: true` in config
4. Check for validation errors in output
5. Verify `powershell-yaml` module is installed

### False Positives

**Symptom**: Rule matches unintended code patterns

**Solutions**:
1. Refine pattern specificity
2. Add filters to AST patterns
3. Use suppressions for legitimate cases
4. Test against wider code samples

### Performance Issues

**Symptom**: Analysis is slow with custom rules

**Solutions**:
1. Optimize regex patterns (avoid backtracking)
2. Use command/parameter patterns instead of regex
3. Limit AST filter complexity
4. Profile rules on sample codebase

## Advanced Features

### Multiple Patterns Per Rule

Combine multiple detection patterns:

```yaml
rule:
  id: "ComprehensiveCheck"
  name: "Multi-Pattern Check"
  severity: "High"
  
  patterns:
    - type: "command"
      command: "Invoke-WebRequest"
      message: "Web request detected"
    
    - type: "regex"
      pattern: 'http://(?!localhost)'
      message: "Non-HTTPS URL detected"
```

### Fix Suggestions

Include automated fix suggestions:

```yaml
patterns:
  - type: "command"
    command: "Get-FileHash"
    message: "Consider using SHA256"
    fix:
      description: "Use SHA256 algorithm"
      replacement: "Get-FileHash -Algorithm SHA256"
```

### Complex Filters

Use PowerShell scriptblocks for advanced filtering:

```yaml
patterns:
  - type: "ast"
    ast_type: "CommandAst"
    filter: |
      $cmd = $args[0]
      $cmdName = $cmd.GetCommandName()
      $cmdName -and $cmdName.StartsWith('Invoke-') -and
      $cmdName -ne 'Invoke-Command'
    message: "Potentially unsafe Invoke-* command"
```

## Contributing

We welcome community contributions! See the [rules/README.md](../rules/README.md) for detailed contribution guidelines.

### Rule Quality Checklist

- [ ] Unique and descriptive rule ID
- [ ] Clear violation message
- [ ] Appropriate severity level
- [ ] At least one tested pattern
- [ ] Remediation guidance with examples
- [ ] CWE/MITRE ATT&CK mappings (if applicable)
- [ ] Tested against real-world scripts
- [ ] No false positives on common patterns
- [ ] Metadata with author and version

## Future Enhancements

- [ ] Rule marketplace web interface
- [ ] Rule quality certification badges
- [ ] Usage analytics and popularity metrics
- [ ] Community voting and ratings
- [ ] Automated rule testing framework
- [ ] Rule update notifications

## Resources

- **Main README**: [../README.md](../README.md)
- **Rules Marketplace**: [../rules/README.md](../rules/README.md)
- **Phase 1 Master Plan**: [../buildplans/phase-1-master-plan.md](../buildplans/phase-1-master-plan.md)

---

**Version**: 1.0.0  
**Last Updated**: October 2025
