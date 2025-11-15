# Test Scripts for PowerShield (Comprehensive PowerShell Security Platform)

## ⚠️ IMPORTANT: Intentional Security Violations & Fake Credentials

This directory contains test scripts with **intentional security violations** used to validate the PowerShield security analyzer. 

**ALL CREDENTIALS, KEYS, AND SECRETS IN THESE FILES ARE FAKE EXAMPLES AND NOT REAL.**

These scripts are automatically excluded from workspace-level security scans but can be analyzed individually to verify the analyzer is working correctly.

## Directory Structure

```
TestScripts/
├── powershell/       # PowerShell-specific security tests (Phase 1 & 1.5A)
├── network/          # Network security tests (Phase 1.5B)
├── filesystem/       # File system security tests (Phase 1.5B)
├── registry/         # Registry security tests (Phase 1.5B)
└── data/             # Data security tests (Phase 1.5B)
```

## Test Script Categories

### PowerShell-Specific Tests (`powershell/`)

These test scripts validate PowerShell-specific security rules implemented in Phase 1 and Phase 1.5A:

1. **insecure-hash.ps1** - Tests detection of weak hash algorithms (MD5, SHA1, RIPEMD160)
2. **credential-exposure.ps1** - Tests detection of plaintext credential handling
3. **command-injection.ps1** - Tests detection of unsafe `Invoke-Expression` usage
4. **certificate-bypass.ps1** - Tests detection of certificate validation bypasses
5. **execution-policy-bypass.ps1** - Tests detection of execution policy bypass attempts
6. **script-block-logging.ps1** - Tests detection of missing security logging configuration
7. **unsafe-ps-remoting.ps1** - Tests detection of insecure PowerShell remoting
8. **dangerous-modules.ps1** - Tests detection of untrusted module imports
9. **powershell-version-downgrade.ps1** - Tests detection of PowerShell v2 usage
10. **unsafe-deserialization.ps1** - Tests detection of unsafe XML/CLIXML deserialization
11. **privilege-escalation.ps1** - Tests detection of privilege escalation attempts
12. **script-injection.ps1** - Tests detection of dynamic script generation vulnerabilities
13. **unsafe-reflection.ps1** - Tests detection of unsafe .NET reflection usage
14. **constrained-mode.ps1** - Tests detection of constrained language mode issues
15. **unsafe-file-inclusion.ps1** - Tests detection of untrusted script dot-sourcing
16. **powershell-web-requests.ps1** - Tests detection of unvalidated web requests
17. **amsi-evasion.ps1** - Tests detection of AMSI bypass attempts (Phase 1.5C-A)
18. **etw-evasion.ps1** - Tests detection of ETW manipulation (Phase 1.5C-A)
19. **enhanced-powershell2-detection.ps1** - Enhanced PowerShell 2.0 detection (Phase 1.5C-A)
20. **azure-credential-leaks.ps1** - Tests detection of Azure credential exposure (Phase 1.5C-B)
21. **powershell-gallery-security.ps1** - Tests supply chain security protection (Phase 1.5C-B)
22. **certificate-store-manipulation.ps1** - Tests PKI security vulnerabilities (Phase 1.5C-B)
23. **active-directory-dangerous-operations.ps1** - Tests enterprise identity protection (Phase 1.5C-B)
24. **jea-configuration-vulnerabilities.ps1** - Tests Just Enough Administration security (Phase 1.5C-C)
25. **dsc-security-issues.ps1** - Tests Desired State Configuration security (Phase 1.5C-C)
26. **deprecated-cmdlet-usage.ps1** - Tests legacy security improvements (Phase 1.5C-C)
27. **all-violations.ps1** - Mixed violations for comprehensive testing

### Network Security Tests (`network/`)

These test scripts validate network security rules for Phase 1.5B:

1. **insecure-http.ps1** - Tests detection of unencrypted HTTP requests
2. **weak-tls.ps1** - Tests detection of weak TLS/SSL configurations
3. **hardcoded-urls.ps1** - Tests detection of hardcoded production URLs and endpoints

### File System Security Tests (`filesystem/`)

These test scripts validate file system security rules for Phase 1.5B:

1. **unsafe-file-permissions.ps1** - Tests detection of overly permissive file/folder permissions
2. **temp-file-exposure.ps1** - Tests detection of unsafe temporary file handling
3. **path-traversal.ps1** - Tests detection of directory traversal vulnerabilities
4. **unsafe-file-operations.ps1** - Tests detection of dangerous file operations without validation

### Registry Security Tests (`registry/`)

These test scripts validate registry security rules for Phase 1.5B:

1. **dangerous-registry-modifications.ps1** - Tests detection of unsafe registry modifications
2. **registry-credentials.ps1** - Tests detection of credentials stored in registry keys
3. **privileged-registry-access.ps1** - Tests detection of unnecessary privileged registry operations

### Data Security Tests (`data/`)

These test scripts validate data security rules for Phase 1.5B:

1. **sql-injection.ps1** - Tests detection of SQL injection vulnerabilities
2. **ldap-injection.ps1** - Tests detection of LDAP injection vulnerabilities
3. **xml-security.ps1** - Tests detection of XXE and unsafe XML parsing vulnerabilities
4. **log-injection.ps1** - Tests detection of log injection vulnerabilities

## Usage

### Testing Individual Scripts

To analyze a specific test script:

```powershell
Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
$result = Invoke-SecurityAnalysis -ScriptPath "./tests/TestScripts/powershell/insecure-hash.ps1"
$result.Violations | Format-Table RuleId, Severity, LineNumber, Message
```

### Testing All Scripts

To validate the analyzer against all test scripts:

```powershell
Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force

# Get all test scripts recursively
$testScripts = Get-ChildItem -Path ./tests/TestScripts -Filter *.ps1 -Recurse

$totalViolations = 0
foreach ($script in $testScripts) {
    Write-Host "`nTesting: $($script.Name)"
    $result = Invoke-SecurityAnalysis -ScriptPath $script.FullName
    Write-Host "  Violations: $($result.Violations.Count)"
    $totalViolations += $result.Violations.Count
}

Write-Host "`nTotal violations detected: $totalViolations"
```

### Automated Testing

These test scripts are automatically tested by the GitHub Actions workflow in the `test-analyzer` job to ensure the analyzer is working correctly before analyzing the actual codebase.

## Exclusion from Scans

**These test files are excluded from security scanning through multiple mechanisms:**

1. **PowerShield Analyzer Exclusion**: Files in `tests/TestScripts/` are automatically excluded from workspace-level security scans via the analyzer's default exclusion paths:
   ```powershell
   ExcludedPaths = @('tests/TestScripts', '*/TestScripts', 'test/*', 'tests/*')
   ```

2. **GitHub Secret Scanning Exclusion**: The `.github/secret_scanning.yml` file excludes test directories from GitHub's built-in secret scanning to prevent false positives.

3. **Clear Warning Headers**: Each test script includes a prominent warning header indicating it contains fake credentials for testing purposes.

This ensures that intentional violations in test scripts don't appear as real security issues in the analysis results or trigger false positive security alerts.

## Adding New Test Scripts

When adding new security rules to PowerShield:

1. Create a test script in the appropriate subdirectory based on the rule category
2. Include both **violation examples** (marked with ❌) and **safe examples** (marked with ✅)
3. Add comments explaining what each violation tests
4. Name the file descriptively (e.g., `rule-name.ps1`)
5. Test that the analyzer detects the expected violations

### Test Script Template

```powershell
# Test script for [RuleName] rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: [Description of what this violates]
# [Code that should be flagged]

# ❌ VIOLATION: [Description of another violation]
# [Another violation example]

# ✅ SAFE: [Description of safe alternative]
# [Code that should NOT be flagged]
```

## Notes

- **⚠️ WARNING**: These scripts contain intentional security vulnerabilities and should **NEVER** be executed in production environments
- **ALL CREDENTIALS ARE FAKE**: No real passwords, API keys, certificates, or secrets are included in these files
- Test scripts are for validation purposes only and should not be run directly
- Each script is designed to test specific security rules and may contain multiple violation patterns
- The number of violations detected may change as rules are refined and improved
- **For Security Reviewers**: Any security alerts from files in `tests/TestScripts/` should be marked as false positives or "used in tests"

## Related Documentation

- [Security Rules Documentation](../../README.md#-security-rules)
- [Phase 1 Master Plan](../../buildplans/phase-1-master-plan.md)
- [Implementation Summary](../../docs/implementation/IMPLEMENTATION_SUMMARY.md)

---

*Last Updated: October 26, 2025*
*Total Test Scripts: 38 (includes Phase 1.5C-B and 1.5C-C additions)*
