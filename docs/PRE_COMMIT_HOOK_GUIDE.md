# PowerShield Pre-Commit Hook Guide

## Overview

PowerShield includes a Git pre-commit hook that performs security analysis on staged PowerShell files before allowing commits. This provides immediate feedback on security issues and helps maintain code quality by catching violations early in the development process.

## Features

- **Staged Files Only**: Analyzes only PowerShell files that are staged for commit (`.ps1`, `.psm1`, `.psd1`)
- **Configurable Blocking**: Block commits based on severity levels (Critical, High, Medium, Low)
- **Fast Incremental Analysis**: Only analyzes files that have changed
- **Detailed Feedback**: Shows top security violations with file locations and line numbers
- **Suppressions Support**: Respects suppression comments in your code
- **Bypass Option**: Can be bypassed when needed using `--no-verify`

## Installation

### Quick Installation

```bash
pwsh powershield.ps1 install-hooks
```

This will:
1. Copy the pre-commit hook to `.git/hooks/pre-commit`
2. Make the hook executable (on Unix-like systems)
3. Display configuration information

### Manual Installation

If you prefer manual installation:

```bash
cp .powershield/hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit  # Unix/Linux/macOS only
```

## Configuration

Configure the pre-commit hook behavior in your `.powershield.yml` file:

```yaml
# Git Hooks Configuration
hooks:
  enabled: true                    # Enable/disable the hook
  block_on: ["Critical", "High"]   # Severities that block commits
  auto_fix: false                  # Apply fixes automatically (experimental)
  skip_on_no_violations: true      # Skip output when no violations found
```

### Configuration Options

#### `enabled`
- **Type**: Boolean
- **Default**: `true`
- **Description**: Master switch to enable or disable the pre-commit hook

#### `block_on`
- **Type**: Array of severities
- **Default**: `["Critical", "High"]`
- **Options**: `"Critical"`, `"High"`, `"Medium"`, `"Low"`
- **Description**: Security violation severities that will block the commit

Examples:
```yaml
# Block only critical violations
hooks:
  block_on: ["Critical"]

# Block all violations
hooks:
  block_on: ["Critical", "High", "Medium", "Low"]

# Allow all commits (warning only)
hooks:
  block_on: []
```

#### `auto_fix`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Automatically apply fixes before commit (experimental feature)

#### `skip_on_no_violations`
- **Type**: Boolean
- **Default**: `true`
- **Description**: Skip hook output when no violations are found

## Usage

Once installed, the pre-commit hook runs automatically on every `git commit`:

### Normal Workflow

1. Make changes to PowerShell files
2. Stage your changes: `git add file.ps1`
3. Attempt to commit: `git commit -m "Your message"`
4. Hook analyzes staged files and either:
   - **Allows commit** if no blocking violations found
   - **Blocks commit** if violations exceed threshold

### Example Output

#### When Violations Are Found

```
PowerShield: Analyzing 2 staged PowerShell file(s)...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PowerShield Security Analysis Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Summary:
  Critical: 2
  High: 1

Total violations: 3

Top Issues:
  [Critical] ./scripts/deploy.ps1:45
    CredentialExposure: Plaintext password conversion detected

  [Critical] ./scripts/utils.ps1:12
    CommandInjection: Unsafe use of Invoke-Expression with variable

  [High] ./scripts/hash.ps1:8
    InsecureHashAlgorithms: Insecure hash algorithm 'MD5' detected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✗ Commit blocked due to security violations

To proceed, you can:
  1. Fix the security issues
  2. Add suppression comments (see docs/SUPPRESSION_GUIDE.md)
  3. Bypass this check: git commit --no-verify
  4. Disable hook in .powershield.yml: hooks.enabled = false

For more information, run: pwsh powershield.ps1 analyze
```

#### When No Violations Found

```
✓ No security violations found
```

## Bypassing the Hook

There are several ways to bypass the hook when necessary:

### 1. Use --no-verify Flag

```bash
git commit -m "Emergency fix" --no-verify
```

⚠️ **Warning**: This bypasses all pre-commit hooks, not just PowerShield.

### 2. Disable in Configuration

Temporarily disable the hook in `.powershield.yml`:

```yaml
hooks:
  enabled: false
```

### 3. Add Suppression Comments

Add suppression comments to your code for specific violations:

```powershell
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy system requirement
$hash = Get-FileHash -Algorithm MD5 $file
```

See [Suppression Guide](SUPPRESSION_GUIDE.md) for more details.

### 4. Uninstall the Hook

```bash
pwsh powershield.ps1 uninstall-hooks
```

## Troubleshooting

### Hook Not Running

**Problem**: The hook doesn't execute when you commit.

**Solutions**:
1. Verify hook is installed: `ls -la .git/hooks/pre-commit`
2. Check hook is executable: `chmod +x .git/hooks/pre-commit`
3. Reinstall: `pwsh powershield.ps1 install-hooks -Force`

### Hook Fails to Load Modules

**Problem**: Hook shows "Failed to load PowerShield modules" error.

**Solutions**:
1. Ensure you're in a Git repository
2. Verify PowerShield modules exist in `src/` directory
3. Check PowerShell version: `pwsh --version` (requires 7.0+)

### Hook Too Slow

**Problem**: Hook takes too long to analyze files.

**Solutions**:
1. Analyze fewer files by staging selectively
2. Increase timeout in configuration:
   ```yaml
   analysis:
     timeout_seconds: 60
   ```
3. Disable parallel analysis if causing issues:
   ```yaml
   analysis:
     parallel_analysis: false
   ```

### False Positives Blocking Commits

**Problem**: Hook blocks commits for legitimate code patterns.

**Solutions**:
1. Add suppression comments with justification
2. Adjust blocking threshold:
   ```yaml
   hooks:
     block_on: ["Critical"]  # Only block critical
   ```
3. Disable specific rules in configuration:
   ```yaml
   rules:
     InsecureHashAlgorithms:
       enabled: false
   ```

## Best Practices

### 1. Start with Conservative Settings

Begin with blocking only critical violations:

```yaml
hooks:
  block_on: ["Critical"]
```

Gradually increase strictness as your team adapts.

### 2. Use Suppressions Responsibly

- Always provide justification in suppression comments
- Set expiry dates for temporary suppressions
- Review suppressions regularly

### 3. Educate Your Team

- Document why the hook is in place
- Provide examples of common violations
- Share the suppression guide

### 4. Integrate with CI/CD

The pre-commit hook is a first line of defense. Always run full analysis in CI/CD:

```yaml
- name: PowerShield Analysis
  run: pwsh powershield.ps1 analyze -Format sarif -OutputFile results.sarif
```

### 5. Monitor Hook Performance

If the hook becomes too slow:
- Consider analyzing only modified files
- Review timeout settings
- Optimize rule performance

## Team Setup

### Shared Configuration

Commit `.powershield.yml` to version control so all team members use the same settings:

```bash
git add .powershield.yml
git commit -m "Add PowerShield configuration"
```

### Installation Script

Create a setup script for new team members (`setup-dev.sh`):

```bash
#!/bin/bash
# Install PowerShield pre-commit hook
pwsh powershield.ps1 install-hooks

echo "Development environment setup complete!"
```

### Document in README

Add to your project README:

```markdown
## Development Setup

1. Clone the repository
2. Install PowerShield hooks:
   ```bash
   pwsh powershield.ps1 install-hooks
   ```
3. Configure as needed in `.powershield.yml`
```

## Advanced Usage

### Selective Analysis

The hook automatically analyzes only staged PowerShell files. To see what will be analyzed:

```bash
git diff --cached --name-only --diff-filter=ACM | grep '\.ps1$'
```

### Custom Hook Scripts

You can customize the hook behavior by editing `.powershield/hooks/pre-commit` and reinstalling.

### Hook with Auto-Fix (Experimental)

Enable auto-fix to automatically apply security fixes before commit:

```yaml
hooks:
  auto_fix: true
```

⚠️ **Warning**: This is experimental. Always review auto-fixed changes.

## Uninstallation

To remove the pre-commit hook:

```bash
pwsh powershield.ps1 uninstall-hooks
```

This removes `.git/hooks/pre-commit`. The PowerShield configuration and modules remain intact.

## Related Documentation

- [Configuration Guide](CONFIGURATION_GUIDE.md) - Configure PowerShield behavior
- [Suppression Guide](SUPPRESSION_GUIDE.md) - Document security exceptions
- [AI Auto-Fix Guide](AI_AUTOFIX_GUIDE.md) - Use AI-powered fixes

## FAQ

**Q: Can I use PowerShield hooks with other Git hooks?**

A: Yes! If you have existing pre-commit hooks, you can chain them together using a hook manager like [Husky](https://github.com/typicode/husky) or create a wrapper script.

**Q: Does the hook work on Windows?**

A: Yes! PowerShell 7.0+ works cross-platform on Windows, Linux, and macOS.

**Q: Can I run the hook manually?**

A: Yes! The hook script can be executed directly:
```bash
.git/hooks/pre-commit
```

**Q: How do I update the hook?**

A: Reinstall it:
```bash
pwsh powershield.ps1 install-hooks -Force
```

**Q: Can I use different settings per branch?**

A: You can use branch-specific configuration by checking out different `.powershield.yml` files per branch, or use `.powershield.local.yml` which is git-ignored.

## Support

For issues or questions:
- [GitHub Issues](https://github.com/J-Ellette/PowerShield/issues)
- [Documentation](https://github.com/J-Ellette/PowerShield/docs)
- [Discussions](https://github.com/J-Ellette/PowerShield/discussions)

---

**Version**: 1.2.0
**Last Updated**: October 2025
