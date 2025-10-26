# Webhook Integration Guide

PowerShield supports webhook notifications to Slack, Microsoft Teams, and custom endpoints for real-time security analysis alerts.

## Table of Contents
- [Overview](#overview)
- [Configuration](#configuration)
- [Slack Integration](#slack-integration)
- [Microsoft Teams Integration](#microsoft-teams-integration)
- [Custom Webhooks](#custom-webhooks)
- [Events and Filtering](#events-and-filtering)
- [Testing Webhooks](#testing-webhooks)
- [Troubleshooting](#troubleshooting)

## Overview

Webhook notifications allow you to receive security analysis alerts directly in your team communication platforms. PowerShield supports:

- **Rich notifications** with formatted messages and actionable buttons
- **Event filtering** to receive only relevant notifications
- **Severity filtering** to focus on critical issues
- **Multiple endpoints** to send notifications to different channels

## Configuration

Add webhook configurations to your `.powershield.yml` file:

```yaml
webhooks:
  - url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    format: "Slack"
    events: ["critical_found", "analysis_complete"]
    severity_filter: ["Critical", "High"]
    
  - url: "https://outlook.office.com/webhook/YOUR/TEAMS/WEBHOOK"
    format: "Teams"
    events: ["critical_found"]
    severity_filter: ["Critical"]
```

### Configuration Options

| Option | Required | Description |
|--------|----------|-------------|
| `url` | Yes | The webhook endpoint URL |
| `format` | No | Format: `Slack`, `Teams`, or `Generic` (default: Generic) |
| `events` | No | Events to trigger notifications (default: `["analysis_complete"]`) |
| `severity_filter` | No | Severity levels to include (default: all levels) |

### Available Events

- `critical_found` - Triggered when critical severity violations are found
- `analysis_complete` - Triggered when analysis completes (regardless of findings)
- `fix_applied` - Triggered when auto-fixes are applied

### Severity Levels

- `Critical` - Critical security vulnerabilities
- `High` - High severity issues
- `Medium` - Medium severity issues
- `Low` - Low severity issues

## Slack Integration

### Setting Up Slack Webhook

1. Go to your Slack workspace settings
2. Navigate to **Apps** → **Custom Integrations** → **Incoming Webhooks**
3. Click **Add to Slack**
4. Choose a channel and click **Add Incoming WebHooks integration**
5. Copy the **Webhook URL**

### Slack Configuration Example

```yaml
webhooks:
  - url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"
    format: "Slack"
    events: ["critical_found", "analysis_complete"]
    severity_filter: ["Critical", "High"]
```

### Slack Notification Features

- **Header** with status emoji (✅, ⚠️, 🚨)
- **Repository information** (name, branch, commit)
- **Severity breakdown** with counts
- **Top issues** highlighting critical/high violations
- **View Build button** linking to CI/CD run
- **Color coding** based on severity (green, yellow, orange, red)

### Example Slack Message

```
🚨 PowerShield Security Analysis

Repository: PowerShield/MyProject
Branch: main
Commit: abc123d
Status: 8 violation(s) detected

Critical: 2    High: 3
Medium: 2      Low: 1

Top Issues:
• CredentialExposure: Plaintext password detected: ConvertTo-SecureString with -AsPlainText and -Force
• InsecureHashAlgorithms: Insecure hash algorithm MD5 detected
• CommandInjection: Unsafe Invoke-Expression detected with variable input

[View Build]
```

## Microsoft Teams Integration

### Setting Up Teams Webhook

1. Open Microsoft Teams and navigate to the channel
2. Click the **...** menu next to the channel name
3. Select **Connectors**
4. Find **Incoming Webhook** and click **Configure**
5. Provide a name and upload an image (optional)
6. Copy the **Webhook URL**

### Teams Configuration Example

```yaml
webhooks:
  - url: "https://outlook.office.com/webhook/xxxxx/IncomingWebhook/yyyyy"
    format: "Teams"
    events: ["critical_found", "analysis_complete"]
    severity_filter: ["Critical", "High"]
```

### Teams Notification Features

- **MessageCard format** with theme color based on severity
- **Activity title** with status emoji
- **Facts section** with all analysis metrics
- **Action button** to view build in CI/CD platform

### Example Teams Message

```
🚨 PowerShield Security Analysis
8 violation(s) detected

Repository:        PowerShield/MyProject
Branch:            main
Commit:            abc123d
Critical:          2
High:              3
Medium:            2
Low:               1
Total Violations:  8
Platform:          GitHub Actions

[View Build]
```

## Custom Webhooks

For custom endpoints or generic webhooks, use the `Generic` format:

```yaml
webhooks:
  - url: "https://your-endpoint.com/webhook"
    format: "Generic"
    events: ["analysis_complete"]
    severity_filter: ["Critical", "High", "Medium", "Low"]
```

### Generic Payload Format

```json
{
  "event": "analysis_complete",
  "timestamp": "2025-10-26T03:06:08Z",
  "repository": "PowerShield/MyProject",
  "branch": "main",
  "commit": "abc123def456",
  "total_violations": 8,
  "files_analyzed": 15,
  "summary": {
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 1
  },
  "build_url": "https://github.com/PowerShield/MyProject/actions/runs/123"
}
```

## Events and Filtering

### Event: `critical_found`

Triggered only when violations matching the severity filter are found.

```yaml
webhooks:
  - url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    format: "Slack"
    events: ["critical_found"]
    severity_filter: ["Critical"]  # Only critical issues
```

### Event: `analysis_complete`

Triggered after every analysis, regardless of findings.

```yaml
webhooks:
  - url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    format: "Slack"
    events: ["analysis_complete"]
    severity_filter: ["Critical", "High", "Medium", "Low"]  # All violations
```

### Multiple Webhooks

Configure multiple webhooks for different purposes:

```yaml
webhooks:
  # Critical alerts to security team
  - url: "https://hooks.slack.com/services/.../security-team"
    format: "Slack"
    events: ["critical_found"]
    severity_filter: ["Critical"]
  
  # All analysis results to dev team
  - url: "https://hooks.slack.com/services/.../dev-team"
    format: "Slack"
    events: ["analysis_complete"]
    severity_filter: ["Critical", "High", "Medium"]
  
  # Teams notification for management
  - url: "https://outlook.office.com/webhook/.../management"
    format: "Teams"
    events: ["critical_found"]
    severity_filter: ["Critical", "High"]
```

## Testing Webhooks

PowerShield includes a webhook testing utility to verify your configuration:

### Using Test-Webhooks.ps1

```powershell
# Test with default configuration file
./scripts/Test-Webhooks.ps1

# Test specific configuration
./scripts/Test-Webhooks.ps1 -ConfigPath /path/to/.powershield.yml

# Interactive mode (prompts before sending)
./scripts/Test-Webhooks.ps1 -Interactive

# Dry run (generate payloads without sending)
./scripts/Test-Webhooks.ps1 -DryRun
```

### Using PowerShell Module

```powershell
# Import the module
Import-Module ./src/WebhookNotifier.psm1

# Test webhook configuration
$webhooks = @(
    @{
        url = 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        format = 'Slack'
        events = @('analysis_complete')
        severity_filter = @('Critical', 'High')
    }
)

Test-WebhookConfiguration -WebhookConfigs $webhooks
```

## Troubleshooting

### Webhook Not Sending

**Issue**: No webhooks are being sent

**Solutions**:
1. Verify `webhooks` section exists in `.powershield.yml`
2. Check that the webhook URL is correct
3. Ensure events match the trigger condition
4. Verify severity filter includes violations found
5. Check network connectivity to webhook endpoint

### Slack Messages Not Appearing

**Issue**: Slack webhook succeeds but message doesn't appear

**Solutions**:
1. Verify the webhook URL is correct and active
2. Check that the Slack app has permission to post to the channel
3. Review Slack webhook configuration in workspace settings
4. Test with a simple curl command to isolate the issue:

```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"text":"Test message"}' \
  https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Teams Messages Failing

**Issue**: Teams webhook returns error

**Solutions**:
1. Verify the webhook connector is still active in Teams
2. Check that the webhook URL hasn't expired
3. Ensure the message payload is valid MessageCard format
4. Review Teams connector configuration

### Event Not Triggering

**Issue**: Expected event doesn't trigger notification

**Solutions**:
1. Check event name spelling (case-sensitive)
2. Verify severity filter matches violations
3. For `critical_found`, ensure violations exist with matching severity
4. Review PowerShield logs for webhook processing

### Testing Specific Webhooks

To test a specific webhook format:

```powershell
Import-Module ./src/WebhookNotifier.psm1

# Create test data
$testResult = @{
    TotalViolations = 5
    FilesAnalyzed = 10
    Summary = @{ Critical = 2; High = 3; Medium = 0; Low = 0 }
    Results = @()
}

$context = @{
    repository = 'Test/Repo'
    branch = 'main'
    commit = 'abc123'
    build_url = 'https://example.com'
}

# Create notifier
$notifier = New-WebhookNotifier -WebhookConfigs @(
    @{
        url = 'YOUR_WEBHOOK_URL'
        format = 'Slack'
        events = @('analysis_complete')
        severity_filter = @('Critical', 'High')
    }
)

# Send test notification
Send-WebhookNotification -Notifier $notifier -Event 'analysis_complete' -AnalysisResult $testResult -Context $context
```

## Security Considerations

1. **Webhook URLs contain secrets** - Store them securely:
   - Use environment variables in CI/CD
   - Keep `.powershield.yml` out of version control if it contains webhook URLs
   - Use `.powershield.local.yml` for local testing (add to .gitignore)

2. **Sensitive information in notifications**:
   - Webhooks may contain file paths and code snippets
   - Ensure webhook endpoints are secured
   - Consider severity filtering to limit exposed information

3. **Rate limiting**:
   - Be aware of webhook rate limits in Slack/Teams
   - Use appropriate event filtering to avoid excessive notifications

## Best Practices

1. **Use severity filtering** to reduce noise
2. **Configure multiple channels** for different severity levels
3. **Test webhooks** before committing configuration
4. **Monitor webhook delivery** to ensure notifications are received
5. **Document webhook purposes** in team documentation
6. **Rotate webhook URLs** periodically for security

## Integration with CI/CD

Webhooks automatically work with PowerShield's CI/CD integration. The context information (repository, branch, commit, build URL) is automatically detected from:

- GitHub Actions
- Azure DevOps
- GitLab CI
- Jenkins
- CircleCI
- TeamCity

## Further Reading

- [Slack Incoming Webhooks Documentation](https://api.slack.com/messaging/webhooks)
- [Microsoft Teams Incoming Webhooks](https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
- [PowerShield Configuration Guide](./configuration.md)
- [PowerShield CI/CD Integration](../integrations/README.md)
