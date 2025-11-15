# PowerShield Suppression Guide

## Overview

PowerShield supports suppression comments to temporarily or permanently exclude specific violations from analysis. This is useful for:

- Known false positives
- Legacy code requiring security exceptions
- Temporarily accepting risk with tracking
- Code under active migration

## Suppression Formats

### 1. POWERSHIELD-SUPPRESS-NEXT

Suppresses the violation on the **next line**:

```powershell
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy system requirement
$hash = Get-FileHash -Path "file.txt" -Algorithm MD5
```

**Syntax**: `# POWERSHIELD-SUPPRESS-NEXT: RuleId - Justification`

### 2. POWERSHIELD-SUPPRESS (Inline)

Suppresses the violation on the **same line**:

```powershell
$password = "test123" # POWERSHIELD-SUPPRESS: CredentialExposure - Test credential
```

**Syntax**: `# POWERSHIELD-SUPPRESS: RuleId - Justification`

### 3. POWERSHIELD-SUPPRESS-START/END (Block)

Suppresses violations in a **code block**:

```powershell
# POWERSHIELD-SUPPRESS-START: CommandInjection - Admin console with validated input
$commands = @("Get-Process", "Get-Service")
foreach ($cmd in $commands) {
    Invoke-Expression $cmd
}
# POWERSHIELD-SUPPRESS-END
```

**Syntax**:
```powershell
# POWERSHIELD-SUPPRESS-START: RuleId - Justification
# ... code ...
# POWERSHIELD-SUPPRESS-END
```

### 4. Expiring Suppressions

Add an expiry date to auto-expire suppressions:

```powershell
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Until migration (2025-12-31)
$hash = Get-FileHash -Path "data.bin" -Algorithm SHA1
```

**Syntax**: `# POWERSHIELD-SUPPRESS-NEXT: RuleId - Justification (YYYY-MM-DD)`

**Benefits**:
- Prevents forgotten suppressions
- Forces periodic review
- Automatic expiry warnings in CI/CD

### 5. Suppress All Rules

Suppress all rules on a line (use sparingly):

```powershell
# POWERSHIELD-SUPPRESS-NEXT: all - Complex legacy code pending refactor
$complexLegacyCode = Invoke-ComplexOperation
```

## Configuration

Configure suppression behavior in `.powershield.yml`:

```yaml
suppressions:
  require_justification: true   # Comments must include reason
  max_duration_days: 90         # Maximum suppression duration
  allow_permanent: false        # Disallow permanent suppressions
```

### require_justification

When `true`, all suppressions must include a justification:

```powershell
# ❌ Invalid - No justification
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms
$hash = Get-FileHash -Algorithm MD5

# ✅ Valid - Includes justification
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Required for legacy API
$hash = Get-FileHash -Algorithm MD5
```

### max_duration_days

Limits how long suppressions can last. Suppressions without expiry dates are automatically assigned this duration:

```yaml
suppressions:
  max_duration_days: 90  # 90 days maximum
```

### allow_permanent

When `false`, all suppressions must have expiry dates:

```yaml
suppressions:
  allow_permanent: false  # Force expiry dates
```

## Best Practices

### 1. Always Include Justification

Good justifications explain **why** the violation is acceptable:

```powershell
# ❌ Poor justification
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Required

# ✅ Good justification
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy API requires MD5 checksums
```

### 2. Use Expiry Dates for Temporary Issues

```powershell
# Migration in progress
# POWERSHIELD-SUPPRESS-NEXT: CredentialExposure - Temp until secret vault ready (2025-06-30)
$password = Get-LegacyPassword
```

### 3. Prefer Narrow Suppressions

Use `POWERSHIELD-SUPPRESS-NEXT` or inline over block suppressions:

```powershell
# ❌ Too broad - Suppresses entire function
# POWERSHIELD-SUPPRESS-START: InsecureHashAlgorithms - Legacy requirement
function Get-FileChecksum {
    $hash1 = Get-FileHash -Algorithm MD5 "file1.txt"
    $hash2 = Get-FileHash -Algorithm SHA256 "file2.txt"  # Unnecessarily suppressed
    # More code...
}
# POWERSHIELD-SUPPRESS-END

# ✅ Precise - Only suppresses needed line
function Get-FileChecksum {
    # POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy API requirement
    $hash1 = Get-FileHash -Algorithm MD5 "file1.txt"
    $hash2 = Get-FileHash -Algorithm SHA256 "file2.txt"  # Not suppressed
    # More code...
}
```

### 4. Review Suppressions Regularly

Generate suppression reports to track suppressions:

```powershell
Import-Module ./src/SuppressionParser.psm1
$parser = New-SuppressionParser
$parser.ParseFile("script.ps1")
$report = Get-SuppressionReport -Parser $parser -AsMarkdown
$report | Out-File "suppression-report.md"
```

### 5. Avoid 'all' Rule Suppression

Only use `all` for extreme cases:

```powershell
# ❌ Avoid - Hides all violations
# POWERSHIELD-SUPPRESS-START: all - Legacy code
# ... risky code ...
# POWERSHIELD-SUPPRESS-END

# ✅ Better - Suppress specific rules
# POWERSHIELD-SUPPRESS-START: InsecureHashAlgorithms - Legacy requirement
# POWERSHIELD-SUPPRESS-START: CredentialExposure - Documented exception
# ... risky code ...
# POWERSHIELD-SUPPRESS-END
# POWERSHIELD-SUPPRESS-END
```

## Suppression Reports

Generate reports on all suppressions:

```powershell
Import-Module ./src/SuppressionParser.psm1
$parser = New-SuppressionParser

# Parse all scripts
Get-ChildItem -Path . -Filter *.ps1 -Recurse | ForEach-Object {
    $parser.ParseFile($_.FullName)
}

# Get report
$report = Get-SuppressionReport -Parser $parser
Write-Host "Total suppressions: $($report.TotalSuppressions)"
Write-Host "Expired: $($report.ExpiredCount)"
Write-Host "Expiring soon: $($report.ExpiringSoonCount)"
```

### Markdown Reports

```powershell
$markdown = Get-SuppressionReport -Parser $parser -AsMarkdown
$markdown | Out-File "suppression-audit.md"
```

## CI/CD Integration

### Check for Expired Suppressions

```yaml
- name: Check Suppressions
  shell: pwsh
  run: |
    Import-Module ./src/SuppressionParser.psm1
    $parser = New-SuppressionParser
    
    # Parse all files
    Get-ChildItem -Recurse -Filter *.ps1 | ForEach-Object {
        $parser.ParseFile($_.FullName)
    }
    
    # Check for expired suppressions
    $expired = $parser.GetExpiredSuppressions()
    if ($expired.Count -gt 0) {
        Write-Error "Found $($expired.Count) expired suppressions"
        exit 1
    }
```

### Warn on Expiring Suppressions

```yaml
- name: Warn Expiring Suppressions
  shell: pwsh
  run: |
    Import-Module ./src/SuppressionParser.psm1
    $parser = New-SuppressionParser
    
    # Parse all files
    Get-ChildItem -Recurse -Filter *.ps1 | ForEach-Object {
        $parser.ParseFile($_.FullName)
    }
    
    # Check for expiring suppressions (30 days)
    $expiring = $parser.GetExpiringSuppressions(30)
    if ($expiring.Count -gt 0) {
        Write-Warning "$($expiring.Count) suppressions expiring in 30 days"
        foreach ($s in $expiring) {
            Write-Warning "$($s.RuleId) in $($s.FilePath):$($s.StartLine) expires $($s.ExpiryDate)"
        }
    }
```

## Usage in Analysis

Enable suppression checking during analysis:

```powershell
# Single file
Import-Module ./src/PowerShellSecurityAnalyzer.psm1
$result = Invoke-SecurityAnalysis `
    -ScriptPath "./script.ps1" `
    -EnableSuppressions

# Workspace
$result = Invoke-WorkspaceAnalysis `
    -WorkspacePath "." `
    -EnableSuppressions
```

## Examples

### Example 1: Legacy System Integration

```powershell
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy banking API requires MD5
# TODO: Migrate to SHA256 when API v2 available (ETA Q2 2025)
$checksum = Get-FileHash -Path $file -Algorithm MD5
```

### Example 2: Development/Test Credentials

```powershell
# POWERSHIELD-SUPPRESS-NEXT: CredentialExposure - Test credential, not used in production
$testPassword = "TestPassword123!"

# POWERSHIELD-SUPPRESS-NEXT: CredentialExposure - Dev environment only (2025-06-30)
$devApiKey = "dev-api-key-12345"
```

### Example 3: Controlled Admin Operations

```powershell
# POWERSHIELD-SUPPRESS-START: CommandInjection - Admin console with input validation
if ($IsAdminSession -and (Test-ValidCommand $command)) {
    Invoke-Expression $command
}
# POWERSHIELD-SUPPRESS-END
```

### Example 4: Certificate Validation Override (Development)

```powershell
if ($env:ENVIRONMENT -eq 'Development') {
    # POWERSHIELD-SUPPRESS-NEXT: CertificateValidation - Dev environment only (2025-12-31)
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}
```

## Troubleshooting

### Suppression Not Working

1. Check comment syntax exactly matches format
2. Ensure justification is included if `require_justification: true`
3. Verify rule ID is correct (case-sensitive)
4. Enable suppressions: `-EnableSuppressions` flag
5. Check suppression hasn't expired

### Multiple Rules on Same Line

Suppress each rule separately:

```powershell
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy requirement
# POWERSHIELD-SUPPRESS-NEXT: CredentialExposure - Test environment
$result = Get-LegacyHash -Password "test" -Algorithm MD5
```

### Block Suppression Not Ending

Ensure `POWERSHIELD-SUPPRESS-END` is present:

```powershell
# POWERSHIELD-SUPPRESS-START: RuleId - Reason
# ... code ...
# POWERSHIELD-SUPPRESS-END  # Must have this!
```

## See Also

- [Configuration Guide](CONFIGURATION_GUIDE.md) - Configure suppression behavior
- [README.md](../README.md) - Main documentation
- [.powershield.yml.example](../.powershield.yml.example) - Example configuration
