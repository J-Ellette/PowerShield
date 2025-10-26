# PowerShield VS Code Extension

Real-time PowerShell security analysis with AI-powered fixes for VS Code.

## Features

### Phase 2.1: Extension Foundation ✅

- **Real-time Security Analysis**: Analyzes PowerShell files as you type with configurable debouncing
- **Intelligent Caching**: Performance-optimized with configurable cache size
- **VS Code Integration**: Native diagnostics, problems panel, and inline warnings
- **Comprehensive Configuration**: Extensive settings for customization
- **Multi-file Analysis**: Analyze entire workspace or individual files

### Phase 2.2: AI Integration & Smart Fixes ✅

- **Multi-Provider AI Support**: GitHub Models, OpenAI, Anthropic Claude, Azure OpenAI
- **AI-Powered Fix Generation**: Context-aware security fixes using AI
- **Template-Based Fixes**: Rule-based fixes that work without API keys
- **Intelligent Code Actions**: Quick fixes, explanations, and suppressions
- **Automatic Fallback Chain**: Primary → Fallbacks → Template-based
- **Confidence Scoring**: Each fix includes reliability score (0-1)

### Coming in Future Phases

- **Phase 2.3**: Interactive hover explanations and security education
- **Phase 2.4**: Advanced performance optimizations with incremental analysis
- **Phase 2.5**: Security dashboard, CodeLens, and reports

## Requirements

- **Visual Studio Code**: Version 1.85.0 or higher
- **PowerShell Core**: Version 7.0 or higher
- **PowerShield Analyzer**: The core PowerShell modules must be present in the repository

## Installation

### From Source

1. Clone the PowerShield repository
2. Navigate to the `vscode-extension` directory
3. Run `npm install` to install dependencies
4. Run `npm run compile` to build the extension
5. Press F5 in VS Code to launch the extension in a new window

### From Marketplace (Coming Soon)

Search for "PowerShield" in the VS Code Extensions marketplace and click Install.

## Configuration

Configure PowerShield through VS Code settings (`File > Preferences > Settings` or `Cmd/Ctrl + ,`):

### AI Provider Configuration

```json
{
  "powershield.aiProvider.primary": "github-models",
  "powershield.aiProvider.fallback": ["template-based"],
  "powershield.aiProvider.confidenceThreshold": 0.8
}
```

**Supported Providers:**
- `github-models` - Free for GitHub users (recommended)
- `openai` - OpenAI GPT-4
- `anthropic` - Anthropic Claude
- `azure-openai` - Azure OpenAI Service
- `template-based` - No API required (always available)

**See [AI Setup Guide](./AI_SETUP.md) for detailed configuration instructions.**

### Real-Time Analysis

```json
{
  "powershield.realTimeAnalysis.enabled": true,
  "powershield.realTimeAnalysis.debounceMs": 1000,
  "powershield.realTimeAnalysis.backgroundAnalysis": true
}
```

### Performance

```json
{
  "powershield.performance.enableCaching": true,
  "powershield.performance.maxCacheSize": "100MB",
  "powershield.performance.enableIncrementalAnalysis": true
}
```

### UI Preferences

```json
{
  "powershield.ui.showInlineDecorations": true,
  "powershield.ui.showHoverExplanations": true,
  "powershield.ui.showCodeLens": true
}
```

### Rule Management

```json
{
  "powershield.rules.enabled": [],  // Empty = all rules enabled
  "powershield.rules.disabled": ["RuleIdToDisable"]
}
```

## Commands

Access commands via the Command Palette (`Cmd/Ctrl + Shift + P`):

- **PowerShield: Analyze Current File** - Analyze the currently open PowerShell file
- **PowerShield: Analyze Workspace** - Analyze all PowerShell files in the workspace
- **PowerShield: Generate AI Fix** - Generate AI-powered fix for a security issue
- **PowerShield: Apply Template Fix** - Apply rule-based fix without AI
- **PowerShield: Explain Security Issue** - Get detailed explanation of a violation
- **PowerShield: Suppress Violation** - Add suppression comment for false positives
- **PowerShield: Configure Settings** - Open PowerShield settings
- **PowerShield: Clear Cache** - Clear the analysis cache
- **PowerShield: Show Output** - Show PowerShield output logs

## Usage

### Basic Analysis

1. **Open a PowerShell file** - PowerShield automatically activates
2. **Edit your code** - Real-time analysis runs as you type (with debouncing)
3. **View issues** - Security violations appear in:
   - Inline squiggles in the editor
   - Problems panel (`Cmd/Ctrl + Shift + M`)
   - Diagnostics in the status bar
4. **Click on issues** - View detailed information about security violations
5. **Save your file** - Triggers immediate re-analysis

### Using AI-Powered Fixes

1. **Hover over** a security violation (underlined code)
2. **Click the lightbulb** (💡) icon or press `Ctrl+.` / `Cmd+.`
3. **Choose an action:**
   - 🤖 **AI Fix** - Generate context-aware fix using AI provider
   - 🔧 **Quick Fix** - Apply template-based fix (no API required)
   - 📖 **Explain** - Get detailed explanation of the security issue
   - 🙈 **Suppress** - Add suppression comment for false positives

4. **Review the AI-generated fix** in the preview panel
5. **Accept or reject** the proposed fix

### AI Provider Setup

To use AI-powered fixes, set up an AI provider:

**GitHub Models (Recommended - Free):**
```bash
export GITHUB_TOKEN="your_github_token"
```

**OpenAI:**
```bash
export OPENAI_API_KEY="sk-..."
```

**See [AI Setup Guide](./AI_SETUP.md) for complete setup instructions.**

## Security Rules

PowerShield includes 35+ security rules covering:

- **PowerShell Security**: Insecure hash algorithms, credential exposure, command injection
- **Network Security**: Insecure HTTP, certificate validation bypasses
- **Azure Security**: Key vault issues, storage account misconfigurations
- **Data Security**: Secret exposure, hardcoded credentials
- **File System**: Insecure permissions, path traversal
- **Registry**: Security policy modifications

## Troubleshooting

### Extension Won't Activate

- Ensure PowerShell 7+ is installed: `pwsh --version`
- Check the PowerShield output channel: `PowerShield: Show Output`
- Verify the analyzer module path in the logs

### No Violations Detected

- Verify real-time analysis is enabled in settings
- Check that the file is recognized as PowerShell (bottom-right status bar)
- Try running `PowerShield: Analyze Current File` manually

### No AI Fixes Available

- Check that an AI provider is configured: see [AI Setup Guide](./AI_SETUP.md)
- Verify API keys are set in environment variables
- Template-based fixes always work without configuration
- Check the PowerShield output channel for errors

### AI Provider Errors

- **"API key not configured"** - Set appropriate environment variable
- **"All providers failed"** - Check internet connectivity and API keys
- **"Low confidence fix"** - AI is unsure; use template fix or manual fix
- Restart VS Code after setting environment variables

## Development

### Building from Source

```bash
cd vscode-extension
npm install
npm run compile
```

### Running Tests

```bash
npm test
```

### Packaging

```bash
npm run package
```

This creates a `.vsix` file that can be installed manually or published to the marketplace.

## Contributing

Contributions are welcome! Please see the main [PowerShield repository](https://github.com/J-Ellette/PowerShield) for contribution guidelines.

## License

MIT License - See the main repository for details.

## Links

- [GitHub Repository](https://github.com/J-Ellette/PowerShield)
- [Documentation](https://github.com/J-Ellette/PowerShield/tree/main/docs)
- [Issue Tracker](https://github.com/J-Ellette/PowerShield/issues)
- [Phase 2 Master Plan](https://github.com/J-Ellette/PowerShield/blob/main/buildplans/phase-2-master-plan.md)

## Version History

### 2.1.0 (Phase 2.2) - Current

- **AI Integration**: Multi-provider AI support (GitHub Models, OpenAI, Anthropic, Azure OpenAI)
- **AI-Powered Fixes**: Context-aware security fixes with confidence scoring
- **Intelligent Code Actions**: Quick fixes, explanations, and suppressions
- **Template-Based Fixes**: Rule-based fixes that work without API keys
- **Automatic Fallback**: Primary → Fallback → Template-based provider chain
- **Fix Preview**: Review and accept/reject AI-generated fixes
- **Comprehensive Documentation**: AI setup guide with examples

### 2.0.0 (Phase 2.1)

- Initial VS Code extension release
- Core extension architecture
- PowerShell integration layer
- Real-time analysis system
- Configuration system integration
- Performance optimization foundations

### Coming Soon

- Phase 2.2: AI integration and smart fixes
- Phase 2.3: Enhanced developer experience
- Phase 2.4: Performance optimization
- Phase 2.5: Advanced features and polish
