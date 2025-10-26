# PowerShield Configuration Guide

## Overview

PowerShield (Comprehensive PowerShell Security Platform) supports flexible, hierarchical configuration through `.powershield.yml` files. Configuration can be defined at multiple levels:

1. **Global**: `~/.powershield.yml` (user home directory)
2. **Project**: `.powershield.yml` in repository root
3. **Local**: `.powershield.local.yml` in repository root (gitignored)

Later configurations override earlier ones, allowing for flexible customization.

## Quick Start

### 1. Create Configuration File

Copy the example configuration:

```bash
cp .powershield.yml.example .powershield.yml
```

### 2. Customize for Your Project

Edit `.powershield.yml` to match your requirements:

```yaml
version: "1.0"

analysis:
  severity_threshold: "High"  # Only report High and Critical
  exclude_paths:
    - "vendor/**"
    - "build/**"

rules:
  InsecureHashAlgorithms:
    enabled: true
  CommandInjection:
    enabled: true

autofix:
  enabled: true
  provider: "github-models"
  confidence_threshold: 0.85
```

## Configuration Sections

### Analysis Settings

Controls how PowerShield analyzes your code:

```yaml
analysis:
  severity_threshold: "Medium"  # Minimum severity to report
  max_file_size: 10485760       # 10MB file size limit
  timeout_seconds: 30           # Analysis timeout per file
  parallel_analysis: true       # Enable parallel processing
  
  exclude_paths:                # Paths to skip (glob patterns)
    - "**/node_modules/**"
    - "**/dist/**"
    - "**/*.min.ps1"
  
  exclude_files:                # File patterns to skip
    - "*.tests.ps1"
```

**Severity Levels**: `Low`, `Medium`, `High`, `Critical`

### Rule Configuration

Enable/disable rules and override severities:

```yaml
rules:
  InsecureHashAlgorithms:
    enabled: true
    severity: "High"
  
  CredentialExposure:
    enabled: true
    severity: "Critical"
  
  CommandInjection:
    enabled: false  # Disable specific rules
```

### Auto-Fix Configuration

Configure AI-powered automatic fixes:

```yaml
autofix:
  enabled: true
  provider: "github-models"
  model: "gpt-4o-mini"
  max_fixes: 10
  confidence_threshold: 0.8
  apply_automatically: false
  fallback_to_templates: true
```

See [AI_AUTOFIX_GUIDE.md](AI_AUTOFIX_GUIDE.md) for provider details.

### Suppression Settings

```yaml
suppressions:
  require_justification: true
  max_duration_days: 90
  allow_permanent: false
```

See [SUPPRESSION_GUIDE.md](SUPPRESSION_GUIDE.md) for usage.

For complete documentation, see the example configuration file: `.powershield.yml.example`
