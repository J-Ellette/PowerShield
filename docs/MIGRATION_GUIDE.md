# PowerShield v1.1.0 Migration Guide

## ⚠️ Important: Rebranding Notice

**PSTS (PowerShell Testing Suite)** has been rebranded to **PowerShield - Comprehensive PowerShell Security Platform**.

### Name Changes
- **Product Name**: PSTS → PowerShield
- **Config Files**: `.psts.yml` → `.powershield.yml`, `.pstsignore` → `.powershieldignore`
- **Result Files**: `psts-results.json` → `powershield-results.json`
- **Environment Variables**: `PSTS_VERSION` → `POWERSHIELD_VERSION`, `PSTS_IGNORE` → `POWERSHIELD_IGNORE`
- **Suppression Comments**: `PSTS-SUPPRESS` → `POWERSHIELD-SUPPRESS`
- **PowerShell Functions**: `Import-PSSTConfiguration` → `Import-PowerShieldConfiguration`

### Backward Compatibility
The rebranding includes updates to all file names, configuration references, and documentation. Update your workflows and configurations to use the new names. Legacy file names in `.gitignore` are maintained during the transition period.

## Overview

PowerShield v1.1.0 introduces significant new features while maintaining backward compatibility. This guide helps you migrate from v1.0.0 to v1.1.0 and take advantage of the new capabilities.

## What's New

### Major Features

1. **Real AI Auto-Fix**: Multi-provider AI integration for automatic security fixes
2. **Configuration System**: Flexible `.powershield.yml` configuration with hierarchical support
3. **Suppression Comments**: Document and track security exceptions with expiry dates

## Breaking Changes

**None** - v1.1.0 is fully backward compatible with v1.0.0. All existing workflows will continue to work without modifications.

## Recommended Migration Steps

### Step 1: Update Version References

Update version badges in README (optional):

```markdown
![Version](https://img.shields.io/badge/version-1.1.0-blue)
```

### Step 2: Add Configuration File (Optional)

Create `.powershield.yml` in your repository root to customize behavior:

```bash
# Copy example configuration
cp .powershield.yml.example .powershield.yml

# Edit to match your needs
vim .powershield.yml
```

**Basic configuration**:
```yaml
version: "1.0"

analysis:
  severity_threshold: "High"  # Adjust as needed

autofix:
  enabled: true
  provider: "github-models"
  fallback_to_templates: true

suppressions:
  require_justification: true
  max_duration_days: 90
```

### Step 3: Enable Suppressions in Workflow

Update your GitHub Actions workflow to enable suppression support:

**Before** (v1.0.0):
```yaml
- name: Run PowerShield Analysis
  shell: pwsh
  run: |
    Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
    $result = Invoke-WorkspaceAnalysis -WorkspacePath "."
```

**After** (v1.1.0):
```yaml
- name: Run PowerShield Analysis
  shell: pwsh
  run: |
    Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
    $result = Invoke-WorkspaceAnalysis -WorkspacePath "." -EnableSuppressions
```

### Step 4: Add Suppression Comments (As Needed)

Add suppression comments to document known exceptions:

```powershell
# Legacy API requirement
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Required by legacy banking API (2025-06-30)
$hash = Get-FileHash -Path $file -Algorithm MD5
```

### Step 5: Configure AI Auto-Fix (Optional)

Add auto-fix step to your workflow:

```yaml
- name: Auto-Fix Violations
  uses: ./actions/copilot-autofix
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    violations-file: powershield-results.json
    apply-fixes: false  # Start with preview mode
    max-fixes: 5
    confidence-threshold: 0.85
```

**Start conservatively**:
1. Use `apply-fixes: false` (preview mode)
2. Review generated fixes
3. Enable for specific rules first
4. Gradually increase `max-fixes`

## Feature-by-Feature Migration

### Configuration System

#### No Configuration (v1.0.0 behavior)

If you don't create `.powershield.yml`, PowerShield uses default configuration identical to v1.0.0:

- Severity threshold: Medium
- All rules enabled
- Standard exclusions
- No auto-fix

#### Add Basic Configuration

```yaml
# .powershield.yml
version: "1.0"

analysis:
  severity_threshold: "High"
```

#### Override Specific Rules

```yaml
rules:
  CommandInjection:
    enabled: false  # Too many false positives in our codebase
  
  CredentialExposure:
    enabled: true
    severity: "Critical"
```

### AI Auto-Fix

#### Start with Template-Based Fixes

Begin with template-based fixes (no AI, no API keys):

```yaml
autofix:
  enabled: true
  provider: "template"
```

#### Enable GitHub Models (Free)

Use GitHub's free AI tier:

```yaml
autofix:
  enabled: true
  provider: "github-models"
  model: "gpt-4o-mini"
  confidence_threshold: 0.85
  fallback_to_templates: true
```

**No additional setup required** - uses existing `GITHUB_TOKEN`.

#### Add Other Providers

For OpenAI, Azure, or Claude:

1. Set environment variables or secrets
2. Update configuration
3. Test in preview mode first

See [AI Auto-Fix Guide](AI_AUTOFIX_GUIDE.md) for details.

### Suppression Comments

#### Add to Legacy Code

For known legacy issues requiring exceptions:

```powershell
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy MD5 requirement
# TODO: Migrate to SHA256 when API v2 available
$hash = Get-FileHash -Algorithm MD5 $file
```

#### Add to Test Code

For test credentials and fixtures:

```powershell
# POWERSHIELD-SUPPRESS-NEXT: CredentialExposure - Test credential, not production
$testPassword = "TestPassword123!"
```

#### Use Expiry Dates

For temporary exceptions:

```powershell
# POWERSHIELD-SUPPRESS-NEXT: CommandInjection - Until refactor complete (2025-03-31)
Invoke-Expression $validatedCommand
```

## Common Migration Scenarios

### Scenario 1: Currently Using .powershieldignore

If you're using `.powershieldignore` to exclude files:

**Before**:
```
# .powershieldignore
vendor/
build/
*.tests.ps1
```

**After** (migrate to `.powershield.yml`):
```yaml
# .powershield.yml
version: "1.0"

analysis:
  exclude_paths:
    - "vendor/**"
    - "build/**"
  exclude_files:
    - "*.tests.ps1"
```

**Note**: `.powershieldignore` still works, but `.powershield.yml` is recommended for consistency.

### Scenario 2: Lots of False Positives

If certain rules generate too many false positives:

```yaml
# .powershield.yml
rules:
  # Disable problematic rule temporarily
  SpecificRule:
    enabled: false
  
  # Or use suppressions with documentation
  # (preferred - keeps rule active for new code)
```

### Scenario 3: Enterprise Environment

For enterprise with strict requirements:

```yaml
# .powershield.yml
version: "1.0"

analysis:
  severity_threshold: "High"

autofix:
  enabled: false  # Disable auto-fix in production

suppressions:
  require_justification: true
  max_duration_days: 30
  allow_permanent: false

ci:
  fail_on: ["Critical", "High"]
  max_warnings: 0  # Zero tolerance
```

### Scenario 4: Development Environment

For more permissive development:

```yaml
# .powershield.local.yml (gitignored)
version: "1.0"

analysis:
  severity_threshold: "Low"

autofix:
  enabled: true
  provider: "github-models"
  confidence_threshold: 0.7

suppressions:
  require_justification: false
  allow_permanent: true
```

## Testing Your Migration

### 1. Test Configuration Loading

```powershell
Import-Module ./src/ConfigLoader.psm1
$config = Import-PowerShieldConfiguration -WorkspacePath "."
Test-PowerShieldConfiguration -Configuration $config
```

### 2. Test Analysis with New Features

```powershell
Import-Module ./src/PowerShellSecurityAnalyzer.psm1

# Without suppressions (baseline)
$result1 = Invoke-WorkspaceAnalysis -WorkspacePath "."
Write-Host "Violations without suppressions: $($result1.TotalViolations)"

# With suppressions
$result2 = Invoke-WorkspaceAnalysis -WorkspacePath "." -EnableSuppressions
Write-Host "Violations with suppressions: $($result2.TotalViolations)"
Write-Host "Suppressed: $($result1.TotalViolations - $result2.TotalViolations)"
```

### 3. Test Auto-Fix in Preview Mode

```bash
# Generate violations file
pwsh -c "Import-Module ./src/PowerShellSecurityAnalyzer.psm1; 
         \$r = Invoke-WorkspaceAnalysis '.'; 
         \$r | ConvertTo-Json -Depth 10 | Out-File 'powershield-results.json'"

# Preview fixes (doesn't modify files)
node actions/copilot-autofix/dist/index.js \
  --violations-file powershield-results.json \
  --apply-fixes false
```

## Rollback Plan

If you encounter issues, rolling back is simple:

### 1. Remove Configuration File

```bash
rm .powershield.yml
```

### 2. Revert Workflow Changes

```yaml
# Remove -EnableSuppressions flag
$result = Invoke-WorkspaceAnalysis -WorkspacePath "."
```

### 3. Keep Suppression Comments

Suppression comments are just comments - they won't affect analysis if suppressions are disabled.

## Troubleshooting

### Issue: Configuration Not Loading

**Symptoms**: Configuration changes not taking effect

**Solutions**:
1. Check file name: `.powershield.yml` (not `powershield.yml`)
2. Validate YAML syntax: `yamllint .powershield.yml`
3. Check file location (repository root)
4. Enable verbose mode: `$VerbosePreference = 'Continue'`

### Issue: Suppressions Not Working

**Symptoms**: Violations still reported despite suppression comments

**Solutions**:
1. Ensure `-EnableSuppressions` flag is set
2. Check comment syntax exactly matches format
3. Verify rule ID is correct (case-sensitive)
4. Check suppression hasn't expired

### Issue: AI Provider Errors

**Symptoms**: Auto-fix fails with provider errors

**Solutions**:
1. Enable fallback: `fallback_to_templates: true`
2. Verify API keys are set
3. Check network connectivity
4. Try template provider: `provider: "template"`

### Issue: Module Loading Errors

**Symptoms**: "Module not found" or "Unable to find type" errors

**Solutions**:
1. Use exported functions, not classes directly
2. Import modules with `-Force` flag
3. Check PowerShell version (requires 7.0+)
4. Verify file paths are correct

## Additional Resources

- [Configuration Guide](CONFIGURATION_GUIDE.md) - Complete configuration reference
- [AI Auto-Fix Guide](AI_AUTOFIX_GUIDE.md) - AI provider setup and usage
- [Suppression Guide](SUPPRESSION_GUIDE.md) - Suppression syntax and best practices
- [README.md](../README.md) - Main documentation

## Support

If you encounter issues during migration:

1. Check existing [GitHub Issues](https://github.com/J-Ellette/PowerShellTestingSuite/issues)
2. Review documentation in `docs/` folder
3. Open a new issue with:
   - PowerShield version
   - Configuration file (sanitized)
   - Error messages
   - PowerShell version

## Summary

**Minimal Migration** (5 minutes):
1. Update version badge
2. Add `-EnableSuppressions` to workflow
3. Done - all other features optional

**Recommended Migration** (30 minutes):
1. Create `.powershield.yml` configuration
2. Enable suppressions in workflow
3. Add suppression comments to legacy code
4. Test auto-fix in preview mode
5. Review and adjust configuration

**Full Migration** (1-2 hours):
1. Complete configuration customization
2. Document all suppressions
3. Enable AI auto-fix
4. Set up per-rule configurations
5. Train team on new features

**Remember**: All new features are optional. PowerShield v1.1.0 works exactly like v1.0.0 without any configuration changes.
