# PowerShield Examples

This directory contains example configurations and workflow files demonstrating various PowerShield features.

## Available Examples

### [enterprise-workflow.yml](./enterprise-workflow.yml)

Complete GitHub Actions workflow demonstrating enterprise features:
- Webhook notifications (Slack/Teams)
- Pester security testing integration
- Auto-generated security tests
- SARIF upload to GitHub Security tab

**Usage:**
1. Copy to `.github/workflows/` in your repository
2. Add webhook URLs as secrets (optional):
   - `SLACK_WEBHOOK_URL` for Slack notifications
   - `TEAMS_WEBHOOK_URL` for Teams notifications
3. Configure `.powershield.yml` for additional settings (optional)

**Features demonstrated:**
- Webhook notifications to Slack and Teams
- Auto-generated Pester security tests
- SARIF upload to GitHub Security tab
- Test results artifact upload
- Error handling and graceful degradation

## Configuration Examples

### Minimal Configuration

```yaml
# .powershield.yml
version: "1.0"

analysis:
  severity_threshold: "Medium"

webhooks:
  - url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    format: "Slack"
    events: ["critical_found"]
    severity_filter: ["Critical"]
```

### Full Enterprise Configuration

```yaml
# .powershield.yml
version: "1.0"

analysis:
  severity_threshold: "Medium"
  parallel_analysis: true
  exclude_paths:
    - "**/node_modules/**"
    - "**/dist/**"

# Webhook notifications
webhooks:
  # Slack for dev team
  - url: "https://hooks.slack.com/services/YOUR/DEV/WEBHOOK"
    format: "Slack"
    events: ["critical_found", "analysis_complete"]
    severity_filter: ["Critical", "High"]
  
  # Teams for security team
  - url: "https://outlook.office.com/webhook/YOUR/SEC/WEBHOOK"
    format: "Teams"
    events: ["critical_found"]
    severity_filter: ["Critical"]

# Pester integration
integrations:
  pester:
    enabled: true
    security_tests: "./tests/Security.Tests.ps1"
    run_after_fixes: true
    validate_fixes: true

# CI/CD settings
ci:
  fail_on: ["Critical", "High"]
  max_warnings: 50
  incremental_mode: false

# Auto-fix configuration
autofix:
  enabled: true
  provider: "github-models"
  model: "gpt-4o-mini"
  max_fixes: 10
  confidence_threshold: 0.8
  apply_automatically: false
```

## Usage Patterns

### Pattern 1: Slack Notifications Only

```yaml
webhooks:
  - url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    format: "Slack"
    events: ["critical_found"]
    severity_filter: ["Critical"]
```

### Pattern 2: Pester Testing Only

```yaml
integrations:
  pester:
    enabled: true
    security_tests: "./tests/Security.Tests.ps1"
```

### Pattern 3: Full Enterprise Stack

```yaml
webhooks:
  - url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    format: "Slack"
    events: ["critical_found", "analysis_complete"]
    severity_filter: ["Critical", "High"]

integrations:
  pester:
    enabled: true
    security_tests: "./tests/Security.Tests.ps1"
    run_after_fixes: true

ci:
  fail_on: ["Critical", "High"]
```

## Testing Examples

### Test Webhook Configuration

```powershell
# Test your webhooks with dry run
./scripts/Test-Webhooks.ps1 -DryRun

# Interactive testing (prompts before sending)
./scripts/Test-Webhooks.ps1 -Interactive
```

### Generate Security Tests

```powershell
# Import modules
Import-Module ./src/PowerShellSecurityAnalyzer.psm1
Import-Module ./src/PesterIntegration.psm1

# Run analysis
$result = Invoke-WorkspaceAnalysis -WorkspacePath "."

# Generate tests
$config = @{
    enabled = $true
    security_tests = './tests/Security.Tests.ps1'
}

$integration = New-PesterIntegration -Configuration $config
New-SecurityTests -Integration $integration -AnalysisResult $result

# Run tests
Invoke-SecurityTests -Integration $integration
```

## Integration Scenarios

### Scenario 1: Critical Alert Workflow

Send immediate alerts for critical issues to security team:

```yaml
webhooks:
  - url: "https://outlook.office.com/webhook/SECURITY/TEAM/URL"
    format: "Teams"
    events: ["critical_found"]
    severity_filter: ["Critical"]
```

### Scenario 2: Development Team Updates

Keep dev team informed of all analysis results:

```yaml
webhooks:
  - url: "https://hooks.slack.com/services/DEV/TEAM/URL"
    format: "Slack"
    events: ["analysis_complete"]
    severity_filter: ["Critical", "High", "Medium"]
```

### Scenario 3: Fix Validation Pipeline

Ensure fixes don't break functionality:

```yaml
integrations:
  pester:
    enabled: true
    security_tests: "./tests/Security.Tests.ps1"
    run_after_fixes: true
    validate_fixes: true
```

## Tips

1. **Start Simple**: Begin with one webhook or Pester integration
2. **Test Locally**: Use Test-Webhooks.ps1 before CI/CD integration
3. **Adjust Filters**: Fine-tune severity filters based on your needs
4. **Monitor Noise**: Start with stricter filters, relax as needed
5. **Document URLs**: Keep webhook URLs secure and documented

## Support

- 📚 [Webhook Integration Guide](../webhook-integration.md)
- 📚 [Pester Integration Guide](../pester-integration.md)
- 📚 [Configuration Guide](../CONFIGURATION_GUIDE.md)
- 🐛 [Report Issues](https://github.com/J-Ellette/PowerShield/issues)
