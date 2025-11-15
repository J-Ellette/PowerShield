# PowerShield Baseline Management Guide

This guide explains how to use PowerShield's baseline and diff mode features to track security violations over time and focus on new issues.

## Overview

Baseline mode allows you to:
- **Create versioned baselines** of your current security state
- **Track new violations** introduced since the baseline
- **Ignore existing issues** while preventing regression
- **Share baselines** across teams for consistency
- **Monitor improvements** over time

## Quick Start

### Create Your First Baseline

```powershell
# Create a baseline of current directory
psts baseline create

# Create with description
psts baseline create --description "Release 1.0 baseline"

# Create for specific path
psts baseline create ./src --description "Source code baseline"
```

This creates `.powershield-baseline.json` containing:
- All current violations
- Git commit information
- Timestamp and creator
- Severity counts
- Description

### Compare Against Baseline

```powershell
# Compare current state with baseline
psts baseline compare

# Compare specific path
psts baseline compare ./src
```

**Output**:
- ✓ Fixed issues (violations present in baseline but not current)
- ✗ New issues (violations not in baseline)
- Change percentage

**Exit Code**:
- `0` - No new violations
- `1` - New violations found (fails CI/CD)

## Baseline Management

### List Baselines

```powershell
# List all baseline versions
psts baseline list

# List baselines in specific directory
psts baseline list ./baselines
```

Shows:
- File name
- Creation date
- Creator
- Total violations
- Git commit
- Description

### Delete Baseline

```powershell
# Delete a baseline file
psts baseline delete --output .powershield-baseline.json
```

### Export Comparison Report

```powershell
# Export as markdown (default)
psts baseline export

# Export as HTML
psts baseline export --format html

# Export as JSON
psts baseline export --format json

# Custom output file
psts baseline export --output my-comparison.html --format html
```

**Report Contents**:
- Summary statistics
- List of fixed violations
- List of new violations (with details)
- Change percentage

## Team Baseline Sharing

### Share Baseline with Team

```powershell
# Share with default team
psts baseline share

# Share with specific team
psts baseline share --team "DevOps"

# Share specific baseline
psts baseline share --output custom-baseline.json --team "Security"
```

Creates `team-baseline-<TeamName>.json` with:
- Original baseline data
- Team metadata (team name, shared by, shared at)
- Source file information

### Using Shared Baseline

```powershell
# Team member uses shared baseline
psts baseline compare --output team-baseline-DevOps.json
```

## Use Cases

### 1. Brownfield Project Adoption

**Scenario**: Existing project with many security issues

```powershell
# Step 1: Create baseline of current state
psts baseline create --description "Initial state - 100 violations"

# Step 2: Start fixing issues incrementally
# ... fix some issues ...

# Step 3: Compare to ensure no new issues introduced
psts baseline compare

# Step 4: Create new baseline after major improvements
psts baseline create --description "After Q1 security sprint - 60 violations"
```

### 2. CI/CD Integration

**Scenario**: Prevent new security violations in pipeline

```yaml
# .github/workflows/powershell-security.yml
- name: Create baseline (if doesn't exist)
  run: |
    if [ ! -f .powershield-baseline.json ]; then
      pwsh psts.ps1 baseline create --description "CI baseline"
    fi

- name: Compare with baseline
  run: pwsh psts.ps1 baseline compare
```

### 3. Release Baselines

**Scenario**: Track security posture across releases

```powershell
# Before release 1.0
psts baseline create --description "Release 1.0.0"
mv .powershield-baseline.json baseline-1.0.0.json

# Before release 1.1
psts baseline create --description "Release 1.1.0"
mv .powershield-baseline.json baseline-1.1.0.json

# Compare releases
psts baseline compare --output baseline-1.0.0.json
```

### 4. Team Onboarding

**Scenario**: New team member needs consistent baseline

```powershell
# Team lead shares baseline
psts baseline share --team "Frontend" --output baseline-latest.json

# Team member receives team-baseline-Frontend.json
git clone <repo>
psts baseline compare --output team-baseline-Frontend.json
```

## Baseline Versioning

### Manual Versioning

```powershell
# Create dated baselines
psts baseline create --description "$(date +%Y-%m-%d)"
mv .powershield-baseline.json "baseline-$(date +%Y%m%d).json"
```

### Git-Based Versioning

PowerShield automatically includes:
- Git commit SHA
- Branch name
- Creation timestamp

```json
{
  "Version": "1.0.0",
  "CreatedAt": "2025-10-26T10:00:00Z",
  "CreatedBy": "developer",
  "GitCommit": "abc123...",
  "Branch": "main",
  "Description": "Release baseline"
}
```

## Configuration

Configure baseline behavior in `.powershield.yml`:

```yaml
baseline:
  enabled: true
  auto_create: false         # Auto-create on first run
  baseline_file: ".powershield-baseline.json"
  track_changes: true        # Track changes over time
  fail_on_new_violations: true  # Fail if new issues found

ci:
  baseline_mode: true        # Enable baseline mode in CI
  baseline_file: ".powershield-baseline.json"
```

## Advanced Usage

### Baseline with Specific Configuration

```powershell
# Create baseline with custom config
psts analyze --format json --output temp-results.json
psts baseline create --input temp-results.json
```

### Multiple Baselines for Different Areas

```powershell
# Backend baseline
psts baseline create ./backend --output backend-baseline.json

# Frontend baseline
psts baseline create ./frontend --output frontend-baseline.json

# Compare separately
psts baseline compare ./backend --output backend-baseline.json
psts baseline compare ./frontend --output frontend-baseline.json
```

### Baseline with Suppressions

```powershell
# Create baseline that respects suppressions
psts analyze --suppressions > temp.json
# Process temp.json to create baseline
```

## Baseline File Structure

Example `.powershield-baseline.json`:

```json
{
  "Version": "1.0.0",
  "CreatedAt": "2025-10-26T10:00:00Z",
  "CreatedBy": "developer",
  "Description": "Release 1.0 baseline",
  "GitCommit": "abc123def456...",
  "Branch": "main",
  "TotalViolations": 42,
  "SeverityCounts": {
    "Critical": 5,
    "High": 12,
    "Medium": 20,
    "Low": 5
  },
  "Violations": [
    {
      "RuleId": "CredentialExposure",
      "FilePath": "./src/script.ps1",
      "LineNumber": 10,
      "Severity": "Critical",
      "Message": "..."
    }
  ]
}
```

## Best Practices

### 1. Regular Baseline Updates

```powershell
# Create baseline at regular intervals
# Daily: psts baseline create --description "Daily $(date)"
# Weekly: psts baseline create --description "Weekly $(date)"
# Per Release: psts baseline create --description "Release $VERSION"
```

### 2. Baseline Storage

- ✅ **DO**: Store team baselines in version control
- ✅ **DO**: Use descriptive names (baseline-v1.0.0.json)
- ❌ **DON'T**: Store temporary baselines in version control
- ❌ **DON'T**: Commit `.powershield-baseline.json` (add to .gitignore)

### 3. CI/CD Best Practices

```yaml
# Good: Fail build on new violations
- name: Baseline check
  run: psts baseline compare
  # Exit 1 if new violations

# Good: Allow baseline update on main branch
- name: Update baseline
  if: github.ref == 'refs/heads/main'
  run: |
    psts baseline create --description "Auto-update $(date)"
    git add .powershield-baseline.json
    git commit -m "Update baseline [skip ci]"
    git push
```

### 4. Team Coordination

- Designate a baseline owner per team
- Schedule baseline reviews (quarterly)
- Document baseline update process
- Communicate baseline changes to team

## Troubleshooting

### Issue: Baseline comparison shows many "new" violations

**Cause**: File paths changed or baseline is outdated

**Solution**:
```powershell
# Recreate baseline
psts baseline create --description "Recreated baseline"
```

### Issue: Cannot find baseline file

**Cause**: Wrong directory or file deleted

**Solution**:
```powershell
# List available baselines
psts baseline list

# Use specific baseline
psts baseline compare --output path/to/baseline.json
```

### Issue: Baseline comparison is too strict

**Cause**: Minor changes trigger new violations

**Solution**:
```yaml
# Adjust configuration
baseline:
  fail_on_new_violations: false  # Warning only
```

## Migration from Old Format

If you have old baseline files without metadata:

```powershell
# Recreate with new format
psts baseline create --description "Migrated baseline"
```

## Automation Scripts

### Auto-Update Baseline Weekly

```bash
#!/bin/bash
# update-baseline.sh
cd /path/to/project
pwsh psts.ps1 baseline create --description "Weekly update $(date +%Y-%m-%d)"
git add .powershield-baseline.json
git commit -m "chore: Update security baseline [skip ci]"
git push
```

### Compare Before Merge

```bash
#!/bin/bash
# pre-merge-check.sh
pwsh psts.ps1 baseline compare
if [ $? -ne 0 ]; then
    echo "❌ New security violations detected!"
    echo "Fix violations or update baseline if intentional"
    exit 1
fi
```

## Questions or Issues?

- **Documentation**: See main README.md
- **Issues**: [GitHub Issues](https://github.com/J-Ellette/PowerShield/issues)
- **Discussions**: [GitHub Discussions](https://github.com/J-Ellette/PowerShield/discussions)
