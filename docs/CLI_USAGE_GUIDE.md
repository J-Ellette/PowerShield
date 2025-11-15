# PowerShield CLI Usage Guide

> **PowerShield** - Comprehensive Command-Line Interface

The PowerShield CLI provides a user-friendly command-line interface for PowerShield security analysis, configuration management, baseline tracking, and fix management.

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Commands Reference](#commands-reference)
  - [analyze](#analyze)
  - [baseline](#baseline)
  - [fix](#fix)
  - [config](#config)
  - [install-hooks](#install-hooks)
  - [interactive](#interactive)
  - [version](#version)
  - [help](#help)
- [Common Workflows](#common-workflows)
- [Output Formats](#output-formats)
- [Exit Codes](#exit-codes)
- [Troubleshooting](#troubleshooting)

## Installation

The PowerShield CLI is included with PowerShield. Clone the repository and use the `psts` or `psts.ps1` scripts:

```bash
git clone https://github.com/J-Ellette/PowerShield.git
cd PowerShield

# Make psts executable (Linux/macOS)
chmod +x psts

# Test installation
./psts version
```

**Windows PowerShell:**
```powershell
pwsh psts.ps1 version
```

## Basic Usage

```bash
# Interactive mode (recommended for first-time users)
./psts interactive

# Analyze current directory
./psts analyze

# Analyze specific path
./psts analyze ./src

# Get help
./psts help
```

## Commands Reference

### analyze

Analyze PowerShell scripts for security violations.

**Syntax:**
```bash
psts analyze [path] [options]
```

**Options:**
- `--format <type>` - Output format: `text`, `json`, `sarif`, `markdown` (default: `text`)
- `--output <file>` - Output file path for results
- `--baseline <file>` - Compare against baseline file
- `--suppressions` - Enable suppression comment processing

**Examples:**

```bash
# Analyze current directory (text output)
./psts analyze

# Analyze specific directory
./psts analyze ./src

# JSON output to file
./psts analyze --format json --output results.json

# SARIF output for GitHub Security tab
./psts analyze --format sarif --output results.sarif

# Markdown report
./psts analyze --format markdown --output report.md

# Compare with baseline
./psts analyze --baseline .powershield-baseline.json

# Enable suppression comments
./psts analyze --suppressions
```

**Output:**

Text format shows:
- Files analyzed
- Total violations
- Severity breakdown (Critical, High, Medium, Low)
- Top 10 issues with file path and line numbers
- Color-coded severity indicators

### baseline

Create and manage security analysis baselines to track new violations over time.

**Syntax:**
```bash
psts baseline <create|compare> [path] [options]
```

**Subcommands:**

#### baseline create

Create a baseline from current analysis results.

**Options:**
- `--output <file>` - Custom baseline file path (default: `.powershield-baseline.json`)

**Examples:**

```bash
# Create baseline for current directory
./psts baseline create

# Create baseline for specific path
./psts baseline create ./src

# Custom output file
./psts baseline create --output prod-baseline.json
```

#### baseline compare

Compare current state with existing baseline.

**Options:**
- `--output <file>` - Custom baseline file path to compare against

**Examples:**

```bash
# Compare with default baseline
./psts baseline compare

# Compare specific path
./psts baseline compare ./src

# Compare with custom baseline
./psts baseline compare --output prod-baseline.json
```

**Output:**

Shows:
- Baseline creation date
- Total violations in baseline vs. current
- Number of fixed issues (removed violations)
- Number of new issues (added violations)
- Details of new violations

Exit code 1 if new violations found, 0 otherwise.

### fix

Preview and apply security fixes.

**Syntax:**
```bash
psts fix <preview|apply> [path] [options]
```

**Subcommands:**

#### fix preview

Preview available fixes without applying them.

**Options:**
- `--confidence <0-1>` - Confidence threshold (default: 0.8)
- `--violations <file>` - Path to violations file

**Examples:**

```bash
# Preview fixes for current directory
./psts fix preview

# Higher confidence threshold
./psts fix preview --confidence 0.9

# Preview fixes for specific violations file
./psts fix preview --violations results.json
```

**Output:**

Shows:
- Total violations found
- Number of fixable violations
- Violations grouped by rule
- Preview of affected files
- Instructions for applying fixes

#### fix apply

Apply fixes with confidence threshold.

**Options:**
- `--confidence <0-1>` - Confidence threshold (default: 0.8)

**Examples:**

```bash
# Apply fixes with default confidence
./psts fix apply --confidence 0.8

# Higher confidence (fewer but safer fixes)
./psts fix apply --confidence 0.95
```

**Note:** Fix application requires AI provider configuration in `.powershield.yml`. See [AI Auto-Fix Guide](AI_AUTOFIX_GUIDE.md) for setup.

### config

Manage PowerShield configuration.

**Syntax:**
```bash
psts config <validate|show|init>
```

**Subcommands:**

#### config validate

Validate `.powershield.yml` configuration file.

**Example:**
```bash
./psts config validate
```

**Output:**
- Configuration validity status
- Summary of key settings
- Errors if configuration is invalid

#### config show

Display current configuration as JSON.

**Example:**
```bash
./psts config show
```

**Output:**
Full configuration object in JSON format.

#### config init

Create default configuration file in current directory.

**Example:**
```bash
./psts config init
```

**Output:**
Creates `.powershield.yml` from the example template. Prompts before overwriting existing file.

### install-hooks

Install PowerShield pre-commit hook for automatic validation.

**Syntax:**
```bash
psts install-hooks [options]
```

**Options:**
- `--force` - Overwrite existing pre-commit hook

**Examples:**

```bash
# Install interactively
./psts install-hooks

# Force overwrite
./psts install-hooks --force
```

**Output:**
- Installation status
- Hook location
- Usage instructions
- Bypass method (`git commit --no-verify`)

See [Pre-Commit Hook Guide](PRE_COMMIT_HOOK_GUIDE.md) for details.

### interactive

Run PowerShield in interactive mode with guided prompts.

**Syntax:**
```bash
psts interactive
```

**Features:**

Interactive mode provides a menu-driven interface for:

1. **Analyze files** - Run security analysis with format options
2. **Create or manage baseline** - Create or compare baselines
3. **Preview available fixes** - See fixable violations
4. **Configure PowerShield** - Validate, show, or initialize config
5. **Install pre-commit hooks** - Set up local validation
6. **Show help** - Display help information
7. **Exit** - Leave interactive mode

**Usage:**

```bash
# Start interactive mode
./psts interactive

# Or run without arguments
./psts
```

Type `exit` or `quit` at any time to leave interactive mode.

### version

Display PowerShield version information.

**Syntax:**
```bash
psts version
```

**Output:**
- PowerShield version
- PowerShell version
- Platform information
- CLI name
- Repository URL

### help

Display comprehensive help information.

**Syntax:**
```bash
psts help
```

**Output:**
- Usage syntax
- All commands with descriptions
- Options for each command
- Examples
- Configuration information
- Documentation links

## Common Workflows

### Initial Setup

```bash
# 1. Initialize configuration
./psts config init

# 2. Validate configuration
./psts config validate

# 3. Install pre-commit hook
./psts install-hooks

# 4. Create baseline
./psts baseline create
```

### Daily Development

```bash
# Run analysis before committing
./psts analyze

# Preview available fixes
./psts fix preview

# Compare with baseline to see new issues
./psts baseline compare
```

### CI/CD Integration

```bash
# Generate SARIF for GitHub Security tab
./psts analyze --format sarif --output powershield-results.sarif

# Generate JSON for further processing
./psts analyze --format json --output powershield-results.json

# Generate markdown report for artifacts
./psts analyze --format markdown --output security-report.md
```

### New Project Onboarding

```bash
# 1. Start interactive mode
./psts interactive

# 2. Create initial baseline
./psts baseline create

# 3. Review violations
./psts analyze --format markdown --output onboarding-report.md

# 4. Address high-severity issues
./psts fix preview --confidence 0.9
```

## Output Formats

### text (default)

Human-readable terminal output with:
- Color-coded severity levels
- Summary statistics
- Top 10 issues
- File paths and line numbers

**Use case:** Daily development, quick checks

### json

Structured JSON output with complete violation details.

**Use case:** Programmatic processing, custom tooling integration

**Structure:**
```json
{
  "Results": [...],
  "Summary": {
    "TotalCritical": 2,
    "TotalHigh": 5,
    "TotalMedium": 10,
    "TotalLow": 3
  },
  "TotalViolations": 20,
  "TotalFiles": 15
}
```

### sarif

SARIF 2.1.0 format for GitHub Security tab integration.

**Use case:** CI/CD pipelines, GitHub Security tab, IDE integration

**Features:**
- CWE mappings
- Code flows
- Fix suggestions
- Rich metadata

### markdown

Human-readable markdown report with:
- Executive summary
- Severity breakdown
- Detailed findings
- Recommendations

**Use case:** Documentation, team reports, artifact storage

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - No violations or violations below threshold |
| 1 | Failure - Violations found matching fail criteria |
| 1 | Error - Command failed or invalid input |

**Configuration-based exit:**

Exit code depends on `.powershield.yml` configuration:

```yaml
ci:
  fail_on: ["Critical", "High"]
```

If violations match `fail_on` severities, exit code is 1.

## Troubleshooting

### Command not found

**Problem:** `psts: command not found`

**Solution:**
```bash
# Use explicit path
./psts version

# Or use PowerShell directly
pwsh psts.ps1 version

# Make executable (Linux/macOS)
chmod +x psts
```

### Module import errors

**Problem:** `Failed to load PowerShield modules`

**Solution:**
```bash
# Ensure you're in the PowerShield directory
cd /path/to/PowerShield

# Run from repository root
./psts version
```

### Configuration not found

**Problem:** `No configuration found, using defaults`

**Solution:**
```bash
# Create configuration file
./psts config init

# Validate it
./psts config validate
```

### Baseline file not found

**Problem:** `Baseline file not found`

**Solution:**
```bash
# Create baseline first
./psts baseline create

# Then compare
./psts baseline compare
```

### Permission denied

**Problem:** `Permission denied` when running `./psts`

**Solution:**
```bash
# Make executable
chmod +x psts

# Or use pwsh directly
pwsh psts.ps1 <command>
```

## Advanced Usage

### Scripting with PowerShield

```bash
#!/bin/bash
# Example: Run analysis and email results if violations found

./psts analyze --format json --output results.json

if [ $? -ne 0 ]; then
    # Violations found, send email
    mail -s "PowerShield Violations Found" team@example.com < results.json
fi
```

### Custom Baseline Workflows

```bash
# Create baseline per environment
./psts baseline create --output dev-baseline.json
./psts baseline create --output prod-baseline.json

# Compare different environments
./psts baseline compare --output dev-baseline.json
./psts baseline compare --output prod-baseline.json
```

### Confidence Threshold Tuning

```bash
# Start conservative (high confidence)
./psts fix preview --confidence 0.95

# If too few fixes, reduce threshold
./psts fix preview --confidence 0.85

# Find your sweet spot
./psts fix preview --confidence 0.8
```

## See Also

- [Configuration Guide](CONFIGURATION_GUIDE.md) - Configure PowerShield behavior
- [AI Auto-Fix Guide](AI_AUTOFIX_GUIDE.md) - Setup and use AI-powered fixes
- [Suppression Guide](SUPPRESSION_GUIDE.md) - Document security exceptions
- [Pre-Commit Hook Guide](PRE_COMMIT_HOOK_GUIDE.md) - Local validation setup
- [Advanced Attack Detection](ADVANCED_ATTACK_DETECTION.md) - Security rules reference

## Support

For issues, questions, or contributions:

- **GitHub Issues:** https://github.com/J-Ellette/PowerShield/issues
- **Documentation:** https://github.com/J-Ellette/PowerShield/blob/main/docs/
- **Repository:** https://github.com/J-Ellette/PowerShield

---

**Last Updated:** October 2025  
**Version:** 1.2.0
