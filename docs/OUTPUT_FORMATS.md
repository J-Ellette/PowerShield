# Universal Output Formats Reference

PowerShield supports multiple output formats for seamless integration with various CI/CD platforms, reporting tools, and workflows.

## Format Overview

| Format | Use Case | Platform Support | Human Readable |
|--------|----------|-----------------|----------------|
| **JSON** | Native PowerShield format | All | Partially |
| **SARIF** | Security analysis interchange | GitHub, Azure DevOps, IDEs | No |
| **JUnit XML** | Test result reporting | Jenkins, GitLab, CircleCI | No |
| **TAP** | Universal test protocol | Perl, many CI systems | Yes |
| **CSV/TSV** | Spreadsheet import | Excel, databases, BI tools | Yes |
| **Markdown** | Human-readable reports | PR comments, documentation | Yes |

## Format Details

### 1. JSON (Native Format)

**File**: `analysis.json`

**Description**: PowerShield's native format with complete violation information, metadata, and analysis context.

**Usage**:
```bash
psts analyze --format json --output results.json
```

**Structure**:
```json
{
  "metadata": {
    "version": "1.0.0",
    "timestamp": "2025-10-25T12:00:00Z",
    "tool": "PowerShield"
  },
  "Results": [...],
  "Summary": {
    "TotalCritical": 1,
    "TotalHigh": 3,
    "TotalMedium": 5,
    "TotalLow": 8
  },
  "TotalViolations": 17,
  "TotalFiles": 42
}
```

**Best For**: Custom tooling, detailed analysis, archiving

---

### 2. SARIF (Static Analysis Results Interchange Format)

**File**: `analysis.sarif`

**Description**: Industry-standard format (SARIF 2.1.0) for sharing static analysis results.

**Usage**:
```bash
psts analyze --format sarif --output results.sarif
```

**Key Features**:
- Code flow paths for complex vulnerabilities
- Fix suggestions with diffs
- CWE and MITRE ATT&CK mappings
- Rich text descriptions
- Tool metadata

**Integration**:
```yaml
# GitHub Actions
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif

# Azure DevOps
- task: PublishSecurityAnalysisLogs@3
  inputs:
    artifactName: 'CodeAnalysisLogs'
    sarifFile: 'results.sarif'
```

**Best For**: GitHub Code Scanning, Azure Security, IDE integration

---

### 3. JUnit XML

**File**: `analysis.junit.xml`

**Description**: XML format compatible with JUnit test results, widely supported in CI/CD.

**Usage**:
```bash
psts analyze --format junit --output results.junit.xml
```

**Structure**:
```xml
<testsuites name="PowerShield" tests="35" failures="8">
  <testsuite name="SecurityRules" tests="35" failures="8">
    <testcase classname="script.ps1" name="InsecureHashAlgorithms_Line15">
      <failure message="MD5 hash algorithm detected" type="Critical">
        Severity: Critical
        Rule: InsecureHashAlgorithms
        File: script.ps1
        Line: 15
        Message: MD5 hash algorithm detected
      </failure>
    </testcase>
  </testsuite>
</testsuites>
```

**Integration**:
```yaml
# GitLab CI
artifacts:
  reports:
    junit: results.junit.xml

# Jenkins
junit 'results.junit.xml'

# Azure DevOps
- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: 'results.junit.xml'
```

**Best For**: CI dashboards, test result reporting, build gates

---

### 4. TAP (Test Anything Protocol)

**File**: `analysis.tap`

**Description**: Simple, text-based protocol for test results, easy to parse.

**Usage**:
```bash
psts analyze --format tap --output results.tap
```

**Structure**:
```tap
TAP version 13
1..35
ok 1 - No execution policy bypass
not ok 2 - Insecure hash algorithm detected
  ---
  severity: Critical
  message: MD5 usage at line 15
  file: script.ps1
  line: 15
  ...
```

**Features**:
- Line-oriented format
- Machine and human readable
- YAML diagnostics for details
- Wide parser support

**Best For**: Custom parsers, Perl ecosystems, simple automation

---

### 5. CSV/TSV

**File**: `analysis.csv` or `analysis.tsv`

**Description**: Spreadsheet-compatible tabular format for data analysis.

**Usage**:
```bash
# CSV (comma-separated)
psts analyze --format csv --output results.csv

# TSV (tab-separated)
psts analyze --format tsv --output results.tsv
```

**Columns**:
```csv
RuleId,Severity,File,Line,Column,Message,Code,CWE,MitreAttack,Remediation,Suppressed
InsecureHashAlgorithms,Critical,script.ps1,15,1,"MD5 detected","$hash = MD5...",CWE-327,T1005,"Use SHA256",No
```

**Best For**: Excel analysis, databases, metrics dashboards, trend tracking

---

### 6. Markdown

**File**: `summary.md`

**Description**: Human-readable report with formatting, ideal for documentation and PR comments.

**Usage**:
```bash
psts analyze --format markdown --output report.md
```

**Features**:
- Severity summary with emojis
- Top issues with context
- Code snippets
- Remediation suggestions
- Compliance information (CWE, MITRE)

**Sample Output**:
```markdown
## 🛡️ PowerShield Security Analysis

### 📊 Summary
- **Critical**: 1 🔴
- **High**: 3 🟠
- **Medium**: 5 🟡
- **Low**: 8 ⚪

### 🔥 Top Issues
1. **MD5 Hash Algorithm** (Critical) - `crypto.ps1:15`
   ...
```

**Best For**: PR/MR comments, email reports, documentation

---

## Multi-Format Generation

### Reports Directory Mode

Generate all formats at once:

```bash
psts analyze --reports-dir
```

Creates `.powershield-reports/` directory:

```
.powershield-reports/
├── analysis.json           # Native format
├── analysis.sarif          # SARIF 2.1.0
├── analysis.junit.xml      # JUnit XML
├── analysis.tap           # TAP protocol
├── summary.md             # Markdown report
├── metrics.json           # Performance metrics
├── run.json              # CI metadata
└── suppressions.json     # Suppressions audit
```

### Additional Artifacts

#### metrics.json
Performance and statistics:
```json
{
  "version": "1.0",
  "performance": {
    "analysisTimeMs": 5432,
    "filesAnalyzed": 156,
    "filesPerSecond": 28.7
  },
  "counts": {
    "Critical": 1,
    "High": 3,
    "Medium": 5,
    "Low": 8
  },
  "rules": {
    "total": 45,
    "executed": 45,
    "triggered": 12
  }
}
```

#### run.json
CI/CD context and gate results:
```json
{
  "version": "1.0",
  "ci": {
    "provider": "github",
    "repo": "owner/name",
    "branch": "feature/x",
    "sha": "abc123",
    "pr": "42"
  },
  "counts": {
    "Critical": 1,
    "High": 3
  },
  "gate": {
    "failOn": ["Critical", "High"],
    "result": "pass"
  }
}
```

#### suppressions.json
Active suppression audit trail:
```json
{
  "version": "1.0",
  "active": [
    {
      "ruleId": "InsecureHashAlgorithms",
      "filePath": "legacy.ps1",
      "lineNumber": 42,
      "justification": "Legacy system requirement",
      "expiresAt": "2025-12-31"
    }
  ],
  "summary": {
    "totalActive": 3,
    "totalExpired": 1
  }
}
```

## Format Conversion

### Converting Between Formats

PowerShield provides standalone converters:

```powershell
# JSON to SARIF
./scripts/Convert-ToSARIF.ps1 -InputFile results.json -OutputFile results.sarif

# JSON to JUnit
./scripts/Export-ToJUnit.ps1 -InputFile results.json -OutputFile results.junit.xml

# JSON to TAP
./scripts/Export-ToTAP.ps1 -InputFile results.json -OutputFile results.tap

# JSON to CSV
./scripts/Export-ToCSV.ps1 -InputFile results.json -OutputFile results.csv
```

### Batch Conversion

```powershell
# Convert to all formats
$result = Get-Content results.json
./scripts/Convert-ToSARIF.ps1 -InputFile results.json -OutputFile results.sarif
./scripts/Export-ToJUnit.ps1 -InputFile results.json -OutputFile results.junit.xml
./scripts/Export-ToTAP.ps1 -InputFile results.json -OutputFile results.tap
./scripts/Export-ToCSV.ps1 -InputFile results.json -OutputFile results.csv
```

## Format Selection Guide

### By Use Case

**Security Analysis Dashboard**: Use SARIF
- GitHub Security tab
- Azure DevOps security alerts
- IDE warnings

**CI/CD Test Results**: Use JUnit XML
- Jenkins test dashboard
- GitLab test reports
- CircleCI test insights

**Metrics & Trends**: Use CSV/TSV
- Import to Excel/Google Sheets
- Database loading
- BI tool analysis

**PR/MR Communication**: Use Markdown
- Automated comments
- Email reports
- Team wikis

**Custom Automation**: Use JSON
- Full data access
- Custom processing
- Archival

### By Platform

| Platform | Recommended Format | Alternative |
|----------|-------------------|-------------|
| GitHub Actions | SARIF | JUnit, Markdown |
| Azure DevOps | SARIF, JUnit | Markdown |
| GitLab CI | JUnit, SARIF | TAP |
| Jenkins | JUnit | TAP, CSV |
| CircleCI | JUnit | TAP |
| TeamCity | JUnit | TAP |
| Bitbucket Pipelines | JUnit | Markdown |

## Examples

### GitHub Actions - Multiple Outputs

```yaml
- name: Analyze with Multiple Formats
  run: psts analyze --reports-dir

- name: Upload SARIF to Security Tab
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: .powershield-reports/analysis.sarif

- name: Publish Test Results
  uses: EnricoMi/publish-unit-test-result-action@v2
  with:
    files: .powershield-reports/analysis.junit.xml

- name: Comment on PR
  uses: actions/github-script@v6
  with:
    script: |
      const fs = require('fs');
      const report = fs.readFileSync('.powershield-reports/summary.md', 'utf8');
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: report
      });
```

### Azure DevOps - Complete Integration

```yaml
- pwsh: './psts.ps1 analyze --reports-dir'
  displayName: 'Security Analysis'

- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: '.powershield-reports/analysis.junit.xml'

- task: PublishSecurityAnalysisLogs@3
  inputs:
    artifactName: 'CodeAnalysisLogs'
    sarifFile: '.powershield-reports/analysis.sarif'
```

## Best Practices

1. **Always Use Reports Directory** in CI/CD for complete output
2. **Version Your Baselines** to track security progress
3. **Archive Artifacts** for compliance and auditing
4. **Use SARIF** for security-specific features
5. **Use JUnit** for test dashboard integration
6. **Use Markdown** for team communication

## Troubleshooting

**Issue**: Format not generated
**Solution**: Check file permissions and disk space

**Issue**: SARIF not appearing in GitHub Security
**Solution**: Verify `security-events: write` permission

**Issue**: JUnit results not parsed
**Solution**: Ensure testResultsFormat matches format

**Issue**: CSV encoding issues
**Solution**: Use UTF-8 encoding for international characters

## References

- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [JUnit XML Format](https://llg.cubic.org/docs/junit/)
- [TAP Specification](https://testanything.org/)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
