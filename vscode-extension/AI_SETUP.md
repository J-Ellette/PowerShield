# PowerShield AI Integration Guide

## Overview

PowerShield VS Code Extension now includes AI-powered security fix generation and intelligent code actions. This guide explains how to set up and use AI providers.

## Supported AI Providers

PowerShield supports multiple AI providers with automatic fallback:

1. **GitHub Models** (Recommended - Free for GitHub users)
2. **OpenAI** (GPT-4, GPT-3.5-turbo)
3. **Anthropic Claude** (Claude 3.5 Sonnet)
4. **Azure OpenAI** (Enterprise deployments)
5. **Template-Based** (Always available as fallback, no API required)

## Configuration

### GitHub Models (Recommended)

GitHub Models is the recommended provider as it's free for GitHub users and provides excellent results.

1. **Set your GitHub token:**
   ```bash
   export GITHUB_TOKEN="your_github_token"
   ```

2. **Configure in VS Code:**
   ```json
   {
     "powershield.aiProvider.primary": "github-models",
     "powershield.aiProvider.fallback": ["template-based"]
   }
   ```

### OpenAI

1. **Get an API key:** https://platform.openai.com/api-keys

2. **Set environment variable:**
   ```bash
   export OPENAI_API_KEY="sk-..."
   ```

3. **Configure in VS Code:**
   ```json
   {
     "powershield.aiProvider.primary": "openai",
     "powershield.aiProvider.fallback": ["template-based"],
     "powershield.aiProvider.openai.model": "gpt-4"
   }
   ```

### Anthropic Claude

1. **Get an API key:** https://console.anthropic.com/

2. **Set environment variable:**
   ```bash
   export ANTHROPIC_API_KEY="sk-ant-..."
   ```

3. **Configure in VS Code:**
   ```json
   {
     "powershield.aiProvider.primary": "anthropic",
     "powershield.aiProvider.fallback": ["template-based"],
     "powershield.aiProvider.anthropic.model": "claude-3-5-sonnet-20241022"
   }
   ```

### Azure OpenAI

1. **Deploy Azure OpenAI service**
2. **Get your endpoint and API key**

3. **Set environment variables:**
   ```bash
   export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
   export AZURE_OPENAI_API_KEY="your-key"
   ```

4. **Configure in VS Code:**
   ```json
   {
     "powershield.aiProvider.primary": "azure-openai",
     "powershield.aiProvider.fallback": ["template-based"],
     "powershield.aiProvider.azure-openai.model": "gpt-4"
   }
   ```

### Template-Based (No API Required)

Template-based fixes work without any API keys and provide rule-based fixes for common security issues:

```json
{
  "powershield.aiProvider.primary": "template-based",
  "powershield.aiProvider.fallback": []
}
```

## Available Configuration Options

### Primary Provider
```json
"powershield.aiProvider.primary": "github-models"
```
Choose: `"github-models"`, `"openai"`, `"anthropic"`, `"azure-openai"`, or `"template-based"`

### Fallback Chain
```json
"powershield.aiProvider.fallback": ["template-based"]
```
Array of providers to try if primary fails.

### Confidence Threshold
```json
"powershield.aiProvider.confidenceThreshold": 0.8
```
Minimum confidence score (0-1) required to accept AI-generated fixes. Lower values accept more suggestions but may be less reliable.

### Max Tokens
```json
"powershield.aiProvider.maxTokens": 1000
```
Maximum tokens for AI responses. Higher values allow more detailed fixes but cost more.

## Using AI Features

### Quick Fixes

When PowerShield detects a security violation:

1. **Hover over the underlined code** to see details
2. **Click the lightbulb** (💡) or press `Ctrl+.` / `Cmd+.`
3. **Choose an action:**
   - 🤖 **AI Fix** - Generate context-aware fix using AI
   - 🔧 **Quick Fix** - Apply template-based fix
   - 📖 **Explain** - Get detailed explanation
   - 🙈 **Suppress** - Add suppression comment

### Commands

Access these from the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

- **PowerShield: Analyze Current File** - Run security analysis
- **PowerShield: Analyze Workspace** - Analyze all PowerShell files
- **PowerShield: Generate AI Fix** - Generate fix for selected violation
- **PowerShield: Explain Security Issue** - Get detailed explanation
- **PowerShield: Configure Settings** - Open settings

## How AI Fix Generation Works

1. **Context Collection:**
   - Extracts code around the violation (5 lines before/after)
   - Identifies containing function and parameters
   - Detects module context and conventions

2. **AI Provider Chain:**
   - Tries primary provider first
   - Falls back to secondary providers if needed
   - Always falls back to template-based as last resort

3. **Confidence Scoring:**
   - Each fix includes a confidence score (0-1)
   - Only fixes above threshold are presented
   - Users can review and accept/reject fixes

4. **Fix Preview:**
   - Shows proposed fix in side-by-side view
   - Includes explanation of security improvement
   - Optional alternative approaches

## Template-Based Fixes

Template-based provider handles these common security issues without AI:

- **Insecure Hash Algorithms** - Replaces MD5/SHA1 with SHA256
- **Credential Exposure** - Uses SecureString instead of plain text
- **Command Injection** - Removes dangerous Invoke-Expression
- **Certificate Bypass** - Removes SSL/TLS validation bypass

## Best Practices

1. **Start with GitHub Models** - Free and effective for most users
2. **Set appropriate confidence threshold** - 0.8 is recommended balance
3. **Review AI fixes** - Always review before accepting
4. **Use template fixes for known patterns** - Faster and no API calls
5. **Configure fallback chain** - Ensures fixes always available

## Troubleshooting

### "API key not configured"
- Verify environment variable is set correctly
- Restart VS Code after setting environment variables
- Check provider is enabled in settings

### "All providers failed"
- Check internet connectivity
- Verify API keys are valid
- Check API rate limits
- Template-based should always work as fallback

### "Low confidence fix"
- Review the generated fix carefully
- Consider using template-based fix instead
- Adjust confidence threshold if needed

### "Fix doesn't work"
- Template fixes may need manual adjustment
- Some violations require domain knowledge
- Provide feedback via GitHub issues

## Privacy & Security

- **Code is sent to AI providers** when using cloud-based providers
- **Template-based provider** works completely offline
- **No telemetry** - Your code stays private
- **API keys** stored in environment variables only
- Consider using template-based for sensitive code

## Examples

### Example 1: Fixing Insecure Hash

**Before:**
```powershell
$hash = [System.Security.Cryptography.MD5]::Create()
```

**AI Fix:**
```powershell
# Use SHA256 instead of insecure MD5
$hash = [System.Security.Cryptography.SHA256]::Create()
```

### Example 2: Securing Credentials

**Before:**
```powershell
$password = "PlainTextPassword123"
```

**AI Fix:**
```powershell
# Prompt user for password securely (not stored in plain text)
$password = Read-Host -Prompt "Enter password" -AsSecureString
$credential = New-Object System.Management.Automation.PSCredential("username", $password)
```

### Example 3: Preventing Command Injection

**Before:**
```powershell
Invoke-Expression $userInput
```

**AI Fix:**
```powershell
# SECURITY WARNING: Invoke-Expression with user input removed
# Use specific cmdlets or validated parameter sets instead
# Consider using switch statement with allowlist
```

## Contributing

Help improve AI fix generation:

1. Report issues with generated fixes
2. Suggest fix templates for common patterns
3. Contribute prompts and examples
4. Test with different AI providers

## Resources

- [PowerShield Documentation](https://github.com/J-Ellette/PowerShield)
- [GitHub Models](https://github.com/marketplace/models)
- [OpenAI API](https://platform.openai.com/)
- [Anthropic Claude](https://www.anthropic.com/)
- [Azure OpenAI](https://azure.microsoft.com/en-us/products/ai-services/openai-service)

## Support

- **Issues:** https://github.com/J-Ellette/PowerShield/issues
- **Discussions:** https://github.com/J-Ellette/PowerShield/discussions
