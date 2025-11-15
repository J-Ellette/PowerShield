# PowerShield Custom Rules & Community Marketplace

Welcome to the PowerShield Rule Marketplace! This directory contains custom security rules that extend PowerShield's built-in detection capabilities.

## Directory Structure

```
rules/
├── custom/         # Your organization's custom rules
├── community/      # Community-contributed rules
└── templates/      # Rule templates for creating new rules
```

## Quick Start

### 1. Enable Custom Rules

Add to your `.powershield.yml`:

```yaml
custom_rules:
  enabled: true
  directories:
    - "./rules/custom"
    - "./rules/community"
  auto_load: true
```

### 2. Create Your First Custom Rule

Use the rule generator:

```powershell
# Import the module
Import-Module ./src/CustomRuleLoader.psm1

# Create a new rule from template
New-CustomRuleTemplate -OutputPath "./rules/custom/my-rule.yml" -RuleType command
```

### 3. Validate Your Rule

```powershell
Test-CustomRule -RuleFile "./rules/custom/my-rule.yml"
```

### 4. Use Custom Rules

Custom rules are automatically loaded when you run analysis:

```powershell
# Custom rules are loaded automatically
$analyzer = New-SecurityAnalyzer -WorkspacePath "."
$result = Invoke-SecurityAnalysis -ScriptPath "script.ps1"
```

## Rule Definition Format

PowerShield uses YAML-based rule definitions with the following structure:

```yaml
rule:
  id: "UniqueRuleID"              # Required: Unique identifier
  name: "Rule Display Name"       # Required: Human-readable name
  description: "Rule description" # Optional: Detailed description
  severity: "High"                # Required: Low, Medium, High, Critical
  category: "Security"            # Optional: Rule category
  cwe: ["CWE-XXX"]               # Optional: CWE IDs
  mitre_attack: ["T1059.001"]    # Optional: MITRE ATT&CK techniques
  owasp: ["A03:2021"]            # Optional: OWASP categories
  help_uri: "https://..."        # Optional: Documentation URL
  
  patterns:                       # Required: At least one pattern
    - type: "command"             # Pattern type
      command: "CommandName"      # Pattern-specific fields
      message: "Violation message"
  
  remediation: |                  # Optional: Remediation guidance
    How to fix this issue...
  
  metadata:                       # Optional: Additional metadata
    author: "Your Name"
    version: "1.0.0"
```

## Pattern Types

### 1. Command Detection

Detects specific PowerShell commands:

```yaml
patterns:
  - type: "command"
    command: "Invoke-Expression"
    message: "Dangerous command detected"
    fix:
      description: "Remove unsafe usage"
      replacement: "# REVIEW: Use safer alternative"
```

### 2. Regex Pattern Matching

Detects code patterns using regular expressions:

```yaml
patterns:
  - type: "regex"
    pattern: '\$password\s*=\s*["\'].+["\']'
    message: "Hardcoded password detected"
```

### 3. AST Node Detection

Detects specific Abstract Syntax Tree node types:

```yaml
patterns:
  - type: "ast"
    ast_type: "TypeExpressionAst"
    filter: '$args[0].TypeName.Name -eq "WebClient"'
    message: "Direct WebClient usage detected"
```

### 4. Parameter Detection

Detects commands with specific parameters:

```yaml
patterns:
  - type: "parameter"
    command: "Invoke-WebRequest"
    parameter: "SkipCertificateCheck"
    message: "Certificate validation bypassed"
    value: "*"  # Optional: match specific value
```

## Rule Examples

### Example 1: Detect Hardcoded Credentials

```yaml
rule:
  id: "HardcodedPassword"
  name: "Hardcoded Password Detection"
  severity: "Critical"
  category: "Security"
  cwe: ["CWE-798"]
  
  patterns:
    - type: "regex"
      pattern: '\$password\s*=\s*["\'].{4,}["\']'
      message: "Hardcoded password detected"
  
  remediation: |
    Never hardcode passwords. Use:
    - SecureString with Read-Host
    - Get-Credential
    - Azure Key Vault
    - Environment variables (for non-production)
```

### Example 2: Detect Unsafe Command Usage

```yaml
rule:
  id: "InvokeExpressionUsage"
  name: "Invoke-Expression Usage"
  severity: "High"
  category: "Security"
  mitre_attack: ["T1059.001"]
  
  patterns:
    - type: "command"
      command: "Invoke-Expression"
      message: "Invoke-Expression usage detected"
    
    - type: "command"
      command: "iex"
      message: "iex alias detected (Invoke-Expression)"
  
  remediation: |
    Avoid Invoke-Expression as it can execute arbitrary code.
    Use safer alternatives like scriptblocks or direct function calls.
```

### Example 3: Detect Multiple Patterns

```yaml
rule:
  id: "ComprehensiveCheck"
  name: "Multi-Pattern Security Check"
  severity: "High"
  category: "Security"
  
  patterns:
    - type: "command"
      command: "Invoke-WebRequest"
      message: "Web request detected"
    
    - type: "regex"
      pattern: 'http://(?!localhost)'
      message: "Non-HTTPS URL detected"
    
    - type: "parameter"
      command: "Invoke-WebRequest"
      parameter: "UseBasicParsing"
      message: "UseBasicParsing parameter detected"
```

## CLI Commands

PowerShield provides CLI commands for rule management:

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

### Generate Templates

```powershell
# Generate command detection template
psts rule create --template command --output ./rules/custom/my-rule.yml

# Generate regex pattern template
psts rule create --template regex --output ./rules/custom/pattern-rule.yml

# Generate comprehensive template
psts rule create --template comprehensive --output ./rules/custom/advanced-rule.yml
```

## Best Practices

### 1. Rule Naming

- Use descriptive, unique IDs (e.g., `HardcodedPasswordDetection`, not `Rule001`)
- Choose appropriate severity levels
- Include relevant CWE/MITRE ATT&CK mappings

### 2. Pattern Design

- Test patterns thoroughly to avoid false positives
- Use specific patterns rather than overly broad ones
- Combine multiple patterns for comprehensive detection

### 3. Remediation Guidance

- Provide clear, actionable remediation steps
- Include code examples (unsafe vs. safe)
- Link to relevant documentation

### 4. Testing

- Test rules against real scripts
- Validate both positive and negative cases
- Check performance impact on large codebases

### 5. Documentation

- Document the rule's purpose and rationale
- Specify author and version in metadata
- Keep rules updated as best practices evolve

## Contributing to Community Rules

We welcome community contributions! To contribute a rule:

1. Create your rule following the format above
2. Test thoroughly with `Test-CustomRule`
3. Add comprehensive documentation
4. Submit a pull request to the repository

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

## Advanced Features

### Rule Filters (AST patterns)

For AST-based patterns, you can use filters to refine detection:

```yaml
patterns:
  - type: "ast"
    ast_type: "CommandAst"
    filter: |
      $cmd = $args[0]
      $cmdName = $cmd.GetCommandName()
      $cmdName -and $cmdName.StartsWith('Invoke-')
    message: "Invoke-* command detected"
```

### Fix Suggestions

Include automated fix suggestions:

```yaml
patterns:
  - type: "command"
    command: "Get-FileHash"
    message: "Insecure hash algorithm"
    fix:
      description: "Use SHA256 instead"
      replacement: "Get-FileHash -Algorithm SHA256"
```

### Multiple Values

Detect parameter values matching patterns:

```yaml
patterns:
  - type: "parameter"
    command: "Set-ExecutionPolicy"
    parameter: "ExecutionPolicy"
    value: "Bypass|Unrestricted"  # Regex pattern
    message: "Unsafe execution policy"
```

## Troubleshooting

### Rule Not Loading

1. Check YAML syntax: `Test-CustomRule -RuleFile path/to/rule.yml`
2. Verify the rule file is in a configured directory
3. Ensure `custom_rules.enabled` is `true` in `.powershield.yml`
4. Check for validation errors in the output

### False Positives

1. Refine pattern specificity
2. Add filters to AST patterns
3. Use suppression comments for legitimate cases:
   ```powershell
   # POWERSHIELD-SUPPRESS-NEXT: RuleID - Justification
   ```

### Performance Issues

1. Optimize regex patterns (avoid backtracking)
2. Use command/parameter patterns instead of regex when possible
3. Limit the scope of AST filters
4. Test rules on large codebases before deployment

## Resources

- **PowerShell AST Documentation**: Understanding AST types for advanced patterns
- **CWE Database**: https://cwe.mitre.org/
- **MITRE ATT&CK**: https://attack.mitre.org/
- **OWASP**: https://owasp.org/

## Support

For questions, issues, or contributions:

- GitHub Issues: https://github.com/J-Ellette/PowerShield/issues
- Documentation: https://github.com/J-Ellette/PowerShield/wiki
- Community: PowerShield Discussions

---

**Happy Rule Creating! 🛡️**
