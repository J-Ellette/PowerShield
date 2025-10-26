# PowerShield AI Auto-Fix Guide

## Overview

PowerShield uses AI to automatically generate and apply security fixes for detected violations. The system supports multiple AI providers with automatic fallback to template-based fixes.

## Supported Providers

### 1. GitHub Models (Recommended for GitHub Actions)

Uses GitHub's AI inference endpoint with your existing `GITHUB_TOKEN`.

**Features**:
- ✅ Free tier available (gpt-4o-mini)
- ✅ No additional API key needed
- ✅ Integrated with GitHub Actions
- ✅ Rate limits per repository

**Configuration**:
```yaml
autofix:
  provider: "github-models"
  model: "gpt-4o-mini"
```

**Setup**: None required - uses existing `GITHUB_TOKEN`

### 2. OpenAI

Direct integration with OpenAI's API.

**Features**:
- ✅ High-quality fixes
- ✅ Multiple model options
- ⚠️ Requires API key
- ⚠️ Usage costs apply

**Configuration**:
```yaml
autofix:
  provider: "openai"
  model: "gpt-4o-mini"  # or gpt-4, gpt-3.5-turbo
```

**Setup**:
```bash
export OPENAI_API_KEY="sk-..."
```

### 3. Azure OpenAI

For organizations using Azure OpenAI Service.

**Features**:
- ✅ Enterprise-grade
- ✅ Private deployment
- ✅ Compliance-friendly
- ⚠️ Requires Azure subscription

**Configuration**:
```yaml
autofix:
  provider: "azure"
  model: "gpt-4o-mini"  # Your deployment name
```

**Setup**:
```bash
export AZURE_OPENAI_KEY="..."
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
export AZURE_OPENAI_DEPLOYMENT="your-deployment-name"
```

### 4. Anthropic Claude

Integration with Claude AI.

**Features**:
- ✅ Advanced reasoning
- ✅ Context-aware fixes
- ⚠️ Requires API key
- ⚠️ Usage costs apply

**Configuration**:
```yaml
autofix:
  provider: "claude"
  model: "claude-3-5-sonnet-20241022"
```

**Setup**:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### 5. Template-Based (Fallback)

Rule-based fixes without AI.

**Features**:
- ✅ No API required
- ✅ Fast and free
- ✅ Deterministic
- ⚠️ Limited to simple patterns

**Configuration**:
```yaml
autofix:
  provider: "template"
  fallback_to_templates: true  # Auto-fallback if AI fails
```

## Configuration

### Basic Setup

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

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable auto-fix |
| `provider` | string | `"github-models"` | AI provider to use |
| `model` | string | `"gpt-4o-mini"` | Model name |
| `max_fixes` | number | `10` | Maximum fixes per run |
| `confidence_threshold` | float | `0.8` | Minimum confidence (0.0-1.0) |
| `apply_automatically` | boolean | `false` | Apply without review |
| `fallback_to_templates` | boolean | `true` | Use templates if AI fails |

### Per-Rule Control

Disable auto-fix for specific rules:

```yaml
autofix:
  enabled: true
  rule_fixes:
    InsecureHashAlgorithms: true      # Safe to auto-fix
    CredentialExposure: true          # Safe to auto-fix
    CommandInjection: false           # Too risky
    CertificateValidation: false      # Requires manual review
```

## Confidence Levels

Fixes are scored from 0.0 to 1.0:

| Range | Description | Recommendation |
|-------|-------------|----------------|
| 0.9-1.0 | Very High | Safe for production |
| 0.8-0.9 | High | Default, good balance |
| 0.7-0.8 | Medium | More fixes, higher risk |
| 0.5-0.7 | Low | Experimental only |
| <0.5 | Very Low | Rejected automatically |

Configure threshold based on your risk tolerance:

```yaml
autofix:
  confidence_threshold: 0.85  # Conservative
  # OR
  confidence_threshold: 0.70  # Aggressive
```

## Usage

### In GitHub Actions

```yaml
- name: Auto-Fix Violations
  uses: ./actions/copilot-autofix
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    violations-file: powershield-results.json
    apply-fixes: true  # or false for preview
    max-fixes: 10
    confidence-threshold: 0.8
```

### Command Line (Preview Mode)

```bash
# Generate fixes without applying
node actions/copilot-autofix/dist/index.js \
  --violations-file powershield-results.json \
  --apply-fixes false
```

### Command Line (Apply Fixes)

```bash
# Apply fixes automatically
node actions/copilot-autofix/dist/index.js \
  --violations-file powershield-results.json \
  --apply-fixes true \
  --max-fixes 5 \
  --confidence-threshold 0.85
```

## Fix Types

### 1. Insecure Hash Algorithms

**Before**:
```powershell
$hash = Get-FileHash -Path "file.txt" -Algorithm MD5
```

**After**:
```powershell
$hash = Get-FileHash -Path "file.txt" -Algorithm SHA256
```

### 2. Credential Exposure

**Before**:
```powershell
$password = ConvertTo-SecureString "MyPassword123!" -AsPlainText -Force
```

**After**:
```powershell
$password = Read-Host "Enter password" -AsSecureString
```

### 3. Command Injection

**Before**:
```powershell
Invoke-Expression $userInput
```

**After**:
```powershell
# SECURITY: Removed Invoke-Expression - validate input and use safer alternatives
# Consider: & $command -ArgumentList $args
```

### 4. Certificate Validation

**Before**:
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
```

**After**:
```powershell
# SECURITY: Implement proper certificate validation instead of bypassing
```

## AI-Generated Fixes

AI providers generate context-aware fixes:

### Example: Complex Refactoring

**Original**:
```powershell
function Get-UserData {
    $password = "Admin123!"
    $hash = Get-FileHash -Algorithm MD5 "data.txt"
    Invoke-Expression $userCommand
}
```

**AI Fix**:
```powershell
function Get-UserData {
    $password = Read-Host "Enter password" -AsSecureString
    $hash = Get-FileHash -Algorithm SHA256 "data.txt"
    # SECURITY: Replaced Invoke-Expression with safer command execution
    if ($allowedCommands -contains $userCommand) {
        & $userCommand
    }
}
```

## Best Practices

### 1. Start with Preview Mode

Always preview fixes before applying:

```yaml
autofix:
  apply_automatically: false  # Review first
```

### 2. Set Conservative Thresholds Initially

```yaml
autofix:
  confidence_threshold: 0.85  # High confidence only
  max_fixes: 5                # Start small
```

### 3. Enable Rule-Specific Control

```yaml
autofix:
  rule_fixes:
    InsecureHashAlgorithms: true   # Low risk
    CommandInjection: false        # High risk - manual only
```

### 4. Use Fallback for Reliability

```yaml
autofix:
  fallback_to_templates: true  # Ensure fixes always generated
```

### 5. Re-Analyze After Fixes

```bash
# 1. Generate fixes
./run-autofix.sh

# 2. Re-analyze to verify
pwsh -c "Import-Module ./src/PowerShellSecurityAnalyzer.psm1; 
         Invoke-WorkspaceAnalysis -WorkspacePath '.'"
```

## Provider Comparison

| Feature | GitHub Models | OpenAI | Azure | Claude | Template |
|---------|--------------|---------|-------|---------|----------|
| **Cost** | Free tier | Pay per use | Enterprise | Pay per use | Free |
| **Setup** | None | API key | Azure config | API key | None |
| **Quality** | High | Very High | Very High | Very High | Medium |
| **Speed** | Fast | Fast | Fast | Fast | Very Fast |
| **Context** | Yes | Yes | Yes | Yes | No |
| **Offline** | No | No | No | No | Yes |

## Troubleshooting

### API Errors

**GitHub Models**:
```bash
# Check token has required permissions
echo $GITHUB_TOKEN | gh auth status

# Verify endpoint accessible
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://models.inference.ai.azure.com/chat/completions
```

**OpenAI**:
```bash
# Test API key
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

**Azure OpenAI**:
```bash
# Test endpoint
curl "$AZURE_OPENAI_ENDPOINT/openai/deployments?api-version=2024-02-15-preview" \
  -H "api-key: $AZURE_OPENAI_KEY"
```

### Low Confidence Fixes

If fixes have low confidence:

1. **Increase AI model capability**:
   ```yaml
   model: "gpt-4"  # Instead of gpt-4o-mini
   ```

2. **Provide more context**: Analyzer automatically includes surrounding code

3. **Lower threshold temporarily**:
   ```yaml
   confidence_threshold: 0.7  # Preview mode only
   ```

4. **Check rule-specific settings**: Some rules are harder to fix automatically

### No Fixes Generated

1. **Check provider configuration**: Verify API keys and endpoints
2. **Enable fallback**: `fallback_to_templates: true`
3. **Check rule enabled**: Verify `rule_fixes` configuration
4. **Review violations file**: Ensure `powershield-results.json` has violations

### Fixes Not Applied

1. **File permissions**: Ensure files are writable
2. **Git status**: Check for merge conflicts
3. **Pattern matching**: Complex code may need manual fix
4. **Confidence threshold**: May be too high

## Security Considerations

### 1. Code Submission to AI

When using cloud AI providers, code is sent to external services. For sensitive code:

- Use **template-based** fixes (no external API)
- Use **Azure OpenAI** (private deployment)
- Review fixes before committing
- Use `.gitignore` to exclude sensitive files from analysis

### 2. API Key Security

**Never commit API keys**:
```bash
# Add to .gitignore
echo ".env" >> .gitignore
echo "*.key" >> .gitignore
```

**Use GitHub Secrets**:
```yaml
env:
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### 3. Fix Validation

Always validate AI-generated fixes:

1. Review changes in PR
2. Run tests
3. Re-analyze with PowerShield
4. Manual code review for critical changes

## See Also

- [Configuration Guide](CONFIGURATION_GUIDE.md) - Configure auto-fix settings
- [README.md](../README.md) - Main documentation
- [.powershield.yml.example](../.powershield.yml.example) - Example configuration
- [GitHub Models Documentation](https://github.com/marketplace/models)
