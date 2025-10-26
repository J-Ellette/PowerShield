# Enhanced SARIF Output

PowerShield now generates SARIF 2.1.0 output with comprehensive security metadata, fix suggestions, and code flow tracking.

## Features

### 1. Rich Security Metadata

Every security rule now includes:

- **CWE (Common Weakness Enumeration)** - Industry-standard weakness classifications
- **MITRE ATT&CK Techniques** - Adversary tactics and techniques mappings
- **OWASP Categories** - OWASP Top 10 2021 classifications
- **Help URLs** - Links to detailed remediation documentation

#### Example Rule Metadata

```json
{
  "id": "InsecureHashAlgorithms",
  "helpUri": "https://cwe.mitre.org/data/definitions/327.html",
  "properties": {
    "cwe": ["CWE-327", "CWE-328"],
    "mitreAttack": "T1553.002",
    "owasp": "A02:2021-Cryptographic Failures",
    "precision": "high",
    "category": "security",
    "tags": ["security", "powershell"]
  }
}
```

### 2. Fix Suggestions

Many rules now include automated fix suggestions with multiple alternatives:

```json
{
  "fixes": [
    {
      "description": { "text": "Replace with SHA-256" },
      "artifactChanges": [{
        "artifactLocation": {
          "uri": "tests/TestScripts/powershell/insecure-hash.ps1",
          "uriBaseId": "SRCROOT"
        },
        "replacements": [{
          "deletedRegion": {
            "startLine": 4,
            "startColumn": 1
          },
          "insertedContent": {
            "text": "Get-FileHash -Path \"C:\\temp\\file.txt\" -Algorithm SHA256"
          }
        }]
      }]
    }
  ]
}
```

### 3. Code Flow Tracking

For complex vulnerabilities, SARIF output includes data flow visualization:

```json
{
  "codeFlows": [{
    "message": { "text": "Untrusted data flows into SQL query" },
    "threadFlows": [{
      "locations": [
        {
          "location": {
            "physicalLocation": { "region": { "startLine": 10 } },
            "message": { "text": "User input variable used here" }
          }
        },
        {
          "location": {
            "physicalLocation": { "region": { "startLine": 15 } },
            "message": { "text": "SQL query executed with concatenated string" }
          }
        }
      ]
    }]
  }]
}
```

## Rules with Fix Suggestions

The following rules currently include automated fix suggestions:

1. **InsecureHashAlgorithms** - Replace MD5/SHA1 with SHA-256 or SHA-512
2. **CredentialExposure** - Use secure credential prompts
3. **CommandInjection** - Refactor to use script blocks or switch statements
4. **SQLInjection** - Use parameterized queries

## Benefits

### For GitHub Security Tab

- **Better Categorization** - Rules grouped by CWE and OWASP categories
- **Enhanced Context** - MITRE ATT&CK mappings show attack context
- **Quick Fixes** - Suggested fixes appear directly in GitHub UI
- **Improved Tracking** - Consistent fingerprints for violation tracking

### For Developers

- **Learn Security** - Help URLs provide educational resources
- **Faster Remediation** - Multiple fix alternatives to choose from
- **Understand Impact** - MITRE ATT&CK shows real-world attack scenarios
- **Better Integration** - Standards-compliant metadata works with all tools

### For Security Teams

- **Compliance Mapping** - Direct CWE/OWASP mappings for compliance reports
- **Threat Intelligence** - MITRE ATT&CK integration for threat modeling
- **Risk Assessment** - Consistent severity and precision ratings
- **Audit Trail** - Rich metadata for security audits

## SARIF Schema Compliance

PowerShield's enhanced SARIF output is fully compliant with:

- **SARIF 2.1.0 Specification** - https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- **GitHub Code Scanning** - https://docs.github.com/en/code-security/code-scanning
- **VS Code SARIF Viewer** - https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer

## Testing

Run the enhanced SARIF test suite:

```powershell
./tests/Test-EnhancedSARIF.ps1
```

This validates:
- Metadata structure and completeness
- Fix suggestion format
- Code flow tracking
- SARIF 2.1.0 compliance
- JSON validity

## Examples

### Running Analysis with Enhanced Output

```powershell
# Import module
Import-Module ./src/PowerShellSecurityAnalyzer.psm1

# Analyze workspace
$result = Invoke-WorkspaceAnalysis -WorkspacePath "./src"

# Export with metadata
$exportData = @{
    metadata = @{
        version = '1.0.0'
        timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
        repository = 'my-project'
    }
    summary = $result.Summary
    violations = $result.Results.Violations
}

$exportData | ConvertTo-Json -Depth 10 | Out-File 'results.json'

# Convert to enhanced SARIF
. ./scripts/Convert-ToSARIF.ps1
Convert-ToSARIF -InputFile 'results.json' -OutputFile 'results.sarif'
```

### Viewing in GitHub

Upload the SARIF file to GitHub Security tab:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Results will appear with:
- CWE badges
- MITRE ATT&CK technique links
- OWASP category tags
- Fix suggestion buttons
- Help documentation links

## Metadata Reference

### All 52 Rules Include

Every security rule in PowerShield includes comprehensive metadata:

- **CWE IDs** - One or more CWE classifications
- **MITRE ATT&CK** - Technique IDs (e.g., T1027, T1059.001)
- **OWASP 2021** - Top 10 category mappings
- **Help URI** - Link to official documentation

### Example Mappings

| Rule | CWE | MITRE ATT&CK | OWASP |
|------|-----|--------------|-------|
| InsecureHashAlgorithms | CWE-327, CWE-328 | T1553.002 | A02:2021 |
| CredentialExposure | CWE-259, CWE-798 | T1552.001 | A02:2021, A07:2021 |
| CommandInjection | CWE-78, CWE-77 | T1059.001 | A03:2021 |
| SQLInjection | CWE-89 | T1190 | A03:2021 |
| AMSIEvasion | CWE-693 | T1562.001 | A04:2021 |

See `/tmp/rule-metadata.json` for complete mappings of all 52 rules.

## Future Enhancements

Planned improvements to SARIF output:

1. **CVE References** - Link specific vulnerabilities to CVE database
2. **Contextual Help** - Include code examples in help text
3. **Related Locations** - Show all related code locations for complex issues
4. **Graph Visualization** - Enhanced code flow graphs for data flow
5. **Taxonomies** - Add custom taxonomies for PowerShell-specific patterns

## References

- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [CWE Database](https://cwe.mitre.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
