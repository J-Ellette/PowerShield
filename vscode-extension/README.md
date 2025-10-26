# PowerShield VS Code Extension

Real-time PowerShell security analysis with AI-powered fixes for VS Code.

## Features

### Phase 2.1: Extension Foundation ✅

- **Real-time Security Analysis**: Analyzes PowerShell files as you type with configurable debouncing
- **Intelligent Caching**: Performance-optimized with configurable cache size
- **VS Code Integration**: Native diagnostics, problems panel, and inline warnings
- **Comprehensive Configuration**: Extensive settings for customization
- **Multi-file Analysis**: Analyze entire workspace or individual files

### Coming in Future Phases

- **Phase 2.2**: AI-powered fix generation with multiple provider support
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
- **PowerShield: Configure Settings** - Open PowerShield settings
- **PowerShield: Clear Cache** - Clear the analysis cache
- **PowerShield: Show Output** - Show PowerShield output logs

## Usage

1. **Open a PowerShell file** - PowerShield automatically activates
2. **Edit your code** - Real-time analysis runs as you type (with debouncing)
3. **View issues** - Security violations appear in:
   - Inline squiggles in the editor
   - Problems panel (`Cmd/Ctrl + Shift + M`)
   - Diagnostics in the status bar
4. **Click on issues** - View detailed information about security violations
5. **Save your file** - Triggers immediate re-analysis

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

### Slow Performance

- Increase the debounce time: `powershield.realTimeAnalysis.debounceMs`
- Disable background analysis if needed
- Clear the cache: `PowerShield: Clear Cache`

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

### 2.0.0 (Phase 2.1) - Current

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
