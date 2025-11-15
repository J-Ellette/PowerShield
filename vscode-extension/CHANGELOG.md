# VS Code Extension Changelog

All notable changes to the PowerShield VS Code extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-10-26 - Phase 2.1: Extension Foundation

### Added

#### Core Extension Architecture (2.1.1)
- Extension entry point with `activate()` and `deactivate()` lifecycle
- PowerShield configuration system integration
- Command registration for 7+ commands:
  - `powershield.analyzeFile` - Analyze current PowerShell file
  - `powershield.analyzeWorkspace` - Analyze all workspace PowerShell files
  - `powershield.configureSettings` - Open PowerShield settings
  - `powershield.clearCache` - Clear analysis cache
  - `powershield.reloadConfig` - Reload configuration
  - `powershield.showOutput` - Show PowerShield output logs
  - Placeholder commands for Phase 2.2+ (AI fixes, explanations, dashboard)
- VS Code diagnostics collection for security violations
- Comprehensive error handling and logging

#### PowerShell Integration Layer (2.1.2)
- **PowerShieldEngine**: Bridge between TypeScript and PowerShell
  - PowerShell 7+ version verification
  - PowerShell script execution via child process spawning
  - Analysis of scripts by file path or content
  - JSON result parsing from PowerShell modules
  - Automatic path resolution for analyzer modules
  - 30-second timeout protection for long-running analysis
- **PSSecurityProvider**: Document analysis with caching
  - SHA-256 content-based cache keys
  - Configurable LRU cache with size limits
  - Cache statistics and hit rate tracking
  - Document-level and range-based analysis
  - Cache invalidation on document changes
  - Integration with PowerShieldEngine for analysis execution

#### Real-Time Analysis System (2.1.3)
- **RealTimeAnalysisProvider**: Document change monitoring
  - Debounced analysis on document changes (configurable delay)
  - Immediate analysis on document save
  - Automatic analysis when PowerShell documents are opened
  - PowerShell file type detection (.ps1, .psm1, .psd1)
  - Progress notifications for long-running analysis
  - Warning notifications for critical security issues
  - Diagnostic cleanup on document close
- VS Code diagnostic conversion:
  - Severity mapping (Critical/High → Error, Medium → Warning, Low → Info)
  - CWE link generation in diagnostic codes
  - Range creation with line/column positioning
  - Support for related information and code actions

#### Configuration System
- **Real-Time Analysis Settings**:
  - `powershield.realTimeAnalysis.enabled` - Enable/disable real-time analysis
  - `powershield.realTimeAnalysis.debounceMs` - Typing debounce delay (default: 1000ms)
  - `powershield.realTimeAnalysis.backgroundAnalysis` - Background worker threads
- **AI Provider Configuration** (for Phase 2.2):
  - `powershield.aiProvider.primary` - Primary AI provider selection
  - `powershield.aiProvider.fallback` - Fallback provider chain
  - `powershield.aiProvider.confidenceThreshold` - Minimum fix confidence (0-1)
- **UI Preferences**:
  - `powershield.ui.showInlineDecorations` - Inline security decorations
  - `powershield.ui.showHoverExplanations` - Hover explanations
  - `powershield.ui.showCodeLens` - CodeLens integration
- **Performance Settings**:
  - `powershield.performance.enableCaching` - Enable/disable caching
  - `powershield.performance.maxCacheSize` - Cache size limit (e.g., "100MB")
  - `powershield.performance.enableIncrementalAnalysis` - Incremental analysis
- **Rule Management**:
  - `powershield.rules.enabled` - Enabled rule IDs
  - `powershield.rules.disabled` - Disabled rule IDs
  - `powershield.suppressions.enabled` - Suppression comments

#### Type System
- Comprehensive TypeScript interfaces and types:
  - `SecurityViolation` - Security violation representation
  - `SecuritySeverity` - Severity enumeration
  - `AnalysisResult` - Analysis output format
  - `CacheEntry` - Cache storage format
  - `PowerShieldConfig` - Configuration structure
  - `AIProviderConfig` - AI provider configuration (Phase 2.2)
  - `FixSuggestion` - Fix suggestion format (Phase 2.2)

#### Testing & Validation
- Integration test suite (test-integration.ps1):
  - PowerShell module existence verification
  - Module import validation
  - Security analysis execution test
  - VS Code diagnostic conversion test
  - JSON export format validation
  - All tests passing ✅

#### Documentation
- Comprehensive README with:
  - Feature overview and roadmap
  - Installation instructions
  - Configuration guide with examples
  - Command reference
  - Usage instructions
  - Troubleshooting guide
  - Development and building instructions

### Dependencies
- TypeScript 5.3.3 with strict mode enabled
- VS Code API 1.85.0+
- Node.js 20+
- PowerShell Core 7.0+
- ESLint for code quality

### Build System
- TypeScript compilation with source maps
- Declaration file generation (.d.ts)
- Watch mode for development
- Package command for VSIX creation

## Future Releases

### [2.1.x] - Coming Soon - Phase 2.2: AI Integration
- Multi-provider AI architecture
- AI-powered fix generation
- Context-aware suggestions
- Fallback chain implementation

### [2.2.x] - Phase 2.3: Enhanced Developer Experience
- Rich diagnostics with hover providers
- Interactive security education
- Security overview sidebar
- Command palette integration

### [2.3.x] - Phase 2.4: Performance Optimization
- Incremental analysis implementation
- Background worker threads
- Multi-level caching
- Performance monitoring

### [2.4.x] - Phase 2.5: Advanced Features
- CodeLens integration
- Security dashboard webview
- Comprehensive settings UI
- Report export functionality

---

## Development

### Building
```bash
npm install
npm run compile
```

### Testing
```bash
pwsh ./test-integration.ps1
```

### Packaging
```bash
npm run package
```

## Links
- [GitHub Repository](https://github.com/J-Ellette/PowerShield)
- [Phase 2 Master Plan](https://github.com/J-Ellette/PowerShield/blob/main/buildplans/phase-2-master-plan.md)
- [Issue Tracker](https://github.com/J-Ellette/PowerShield/issues)
