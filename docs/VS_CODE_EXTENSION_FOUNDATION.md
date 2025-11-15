# VS Code Extension Foundation

**Phase 2 Preparation Feature**  
**Status**: ✅ Foundation Complete (Phase 1)  
**Version**: 1.8.0

## Overview

The VS Code Extension Foundation provides the necessary infrastructure and APIs to support a future PowerShield VS Code extension with real-time security analysis capabilities.

## What Was Implemented

### 1. VSCodeIntegration Module (`src/VSCodeIntegration.psm1`)

A comprehensive module that bridges PowerShield analysis with VS Code Language Server Protocol (LSP).

**Key Classes:**
- `VSCodeDiagnostic` - VS Code diagnostic representation with severity, range, and code actions
- `Position` - Zero-indexed line/character position
- `Range` - Start and end positions for code spans
- `CodeAction` - Quick fix actions that can be applied
- `QuickFix` - Security fix suggestions with confidence scores
- `VSCodeIntegration` - Main integration class with analysis APIs

### 2. Diagnostic Export Format

**Language Server Protocol (LSP) Compliant:**
```json
{
  "jsonrpc": "2.0",
  "method": "textDocument/publishDiagnostics",
  "params": {
    "uri": "file:///path/to/script.ps1",
    "diagnostics": [
      {
        "message": "MD5 hash algorithm detected (insecure)",
        "severity": 1,
        "range": {
          "start": {"line": 14, "character": 0},
          "end": {"line": 14, "character": 100}
        },
        "code": "InsecureHashAlgorithms",
        "source": "PowerShield",
        "codeActions": [
          {
            "title": "Fix: Replace MD5 with SHA256",
            "kind": "quickfix",
            "isPreferred": true
          }
        ]
      }
    ],
    "version": 1
  }
}
```

**Severity Mapping:**
- PowerShield `Critical` / `High` → VS Code `Error` (1)
- PowerShield `Medium` → VS Code `Warning` (2)
- PowerShield `Low` → VS Code `Information` (3)

### 3. Real-Time Analysis API

**Document Analysis Endpoint:**
```powershell
$integration = New-VSCodeIntegration

$result = $integration.AnalyzeDocument(
    "file:///path/to/script.ps1",
    $fileContent,
    $version
)
```

**Response Structure:**
```powershell
@{
    uri = "file:///path/to/script.ps1"
    version = 1
    diagnostics = @(...)  # Array of VSCodeDiagnostic objects
    timestamp = "2025-10-26T12:00:00Z"
    analysisTime = 125  # milliseconds
}
```

**Features:**
- Debouncing support (configurable delay)
- Incremental analysis for large files
- Version tracking for document changes
- Performance metrics collection

### 4. Quick Fix Suggestions

**Format:**
```powershell
class QuickFix {
    [string]$description        # Human-readable description
    [string]$fixedCode          # Corrected code
    [double]$confidence         # 0.0-1.0 confidence score
    [string]$category           # "security", "performance", "style"
    [Range]$range               # Affected code range
}
```

**Usage:**
```powershell
$fixes = Get-VSCodeQuickFixes -Violation $violation -FileContent $content

foreach ($fix in $fixes) {
    Write-Host "$($fix.description) (confidence: $($fix.confidence))"
    Write-Host "  Fixed: $($fix.fixedCode)"
}
```

**Supported Rules:**
- `InsecureHashAlgorithms` - Replace MD5/SHA1 with SHA256
- `CredentialExposure` - Suggest Read-Host -AsSecureString
- `CommandInjection` - Suggest alternatives to Invoke-Expression
- `InsecureHTTP` - Replace http:// with https://

### 5. VS Code Command Schema

**Command Definitions:**

```powershell
$schema = Get-VSCodeCommandSchema

# Available commands:
# - powershield.analyzeFile
# - powershield.analyzeWorkspace
# - powershield.applyFix
# - powershield.suppressViolation
# - powershield.showRuleDocumentation
# - powershield.configureSettings
# - powershield.viewSecurityDashboard
```

**Code Action Kinds:**
- `quickfix` - Apply security fix
- `source.fixAll.powershield` - Fix all violations in file
- `refactor.rewrite.powershield` - Refactor for security

### 6. Module Security Validation (Test-ScriptFileInfo Integration)

**Validate PowerShell Module Manifests:**

```powershell
$validation = Test-ModuleSecurity -ManifestPath "./MyModule.psd1"

if ($validation.isValid) {
    Write-Host "✅ Module manifest is valid"
} else {
    Write-Host "❌ Errors found:"
    $validation.errors | ForEach-Object { Write-Host "  - $_" }
}

# Security issues
$validation.securityIssues | ForEach-Object {
    Write-Host "⚠️  $($_.severity): $($_.message)"
    Write-Host "   Recommendation: $($_.recommendation)"
}
```

**Security Checks:**
1. **Version Pinning** - Ensures required modules specify versions
2. **External Dependencies** - Flags modules with external dependencies
3. **Manifest Validation** - Uses `Test-ModuleManifest` for structural validation
4. **Security Tags** - Checks for security-related metadata

**Example Output:**
```powershell
@{
    isValid = $true
    errors = @()
    warnings = @("Module does not have 'Security' tag")
    securityIssues = @(
        @{
            severity = "Medium"
            message = "Required module 'Az.Accounts' does not specify a version"
            recommendation = "Always specify exact module versions to prevent supply chain attacks"
        }
    )
}
```

## Usage Examples

### Basic Diagnostic Export

```powershell
# Import the module
Import-Module ./src/VSCodeIntegration.psm1

# Analyze a file
Import-Module ./src/PowerShellSecurityAnalyzer.psm1
$result = Invoke-SecurityAnalysis -ScriptPath "./script.ps1"

# Export to VS Code diagnostic format
$json = Export-VSCodeDiagnostics `
    -Violations $result.Violations `
    -FilePath "./script.ps1" `
    -OutputPath "./diagnostics.json"
```

### Real-Time Analysis Integration

```powershell
$integration = New-VSCodeIntegration

# Configure
$integration.Configuration.debounceMs = 300
$integration.Configuration.maxDiagnostics = 50

# Analyze document
$diagnostics = $integration.ConvertToDiagnostics(
    $violations,
    "file:///workspace/script.ps1"
)
```

### Quick Fix Generation

```powershell
# Get quick fixes for a violation
$fileContent = Get-Content -Path "./script.ps1" -Raw
$fixes = Get-VSCodeQuickFixes -Violation $violation -FileContent $fileContent

# Apply the best fix (highest confidence)
$bestFix = $fixes | Sort-Object -Property confidence -Descending | Select-Object -First 1
if ($bestFix.confidence -gt 0.8) {
    # Apply the fix to the file
    $lines = $fileContent -split "`n"
    $lines[$bestFix.range.start.line] = $bestFix.fixedCode
    $lines -join "`n" | Set-Content -Path "./script.ps1"
}
```

### Module Security Validation

```powershell
# Validate a module manifest
$moduleValidation = Test-ModuleSecurity -ManifestPath "./MyModule/MyModule.psd1"

# Report results
Write-Host "`n📦 Module Security Validation"
Write-Host "Valid: $($moduleValidation.isValid)"

if ($moduleValidation.errors.Count -gt 0) {
    Write-Host "`n❌ Errors:"
    $moduleValidation.errors | ForEach-Object { Write-Host "  - $_" }
}

if ($moduleValidation.securityIssues.Count -gt 0) {
    Write-Host "`n⚠️  Security Issues:"
    $moduleValidation.securityIssues | ForEach-Object {
        Write-Host "  [$($_.severity)] $($_.message)"
        Write-Host "    → $($_.recommendation)"
    }
}
```

## Configuration

The VS Code integration can be configured through the `.powershield.yml` file:

```yaml
vscode:
  # Real-time analysis settings
  realtime_analysis:
    enabled: true
    debounce_ms: 500        # Delay before analysis starts
    max_diagnostics: 100    # Maximum diagnostics per file
    
  # Diagnostic settings
  diagnostics:
    show_informational: false
    show_hints: true
    inline_suggestions: true
    
  # Quick fix settings
  quick_fixes:
    enabled: true
    auto_apply: false       # Never auto-apply fixes
    confidence_threshold: 0.8
    
  # Code actions
  code_actions:
    enable_fix_all: true
    enable_refactor: true
```

## Phase 2 Roadmap

This foundation enables the following Phase 2 features:

### Planned VS Code Extension Features

1. **Real-Time Analysis**
   - Analyze as you type with debouncing
   - Inline diagnostics with squiggly underlines
   - Problems panel integration

2. **Quick Fixes**
   - Light bulb code actions
   - Context menu integration
   - Batch fix all violations

3. **Enhanced IntelliSense**
   - Security-aware completions
   - Parameter validation hints
   - Dangerous cmdlet warnings

4. **Security Dashboard**
   - Workspace-wide security overview
   - Violation trends over time
   - Compliance status

5. **Module Validation**
   - Automatic manifest validation on save
   - Supply chain security checks
   - Version pinning enforcement

6. **Team Features**
   - Shared configurations
   - Team security policies
   - Suppression review workflow

### Integration Points

**Language Server Protocol (LSP):**
- `textDocument/publishDiagnostics` - Push diagnostics to VS Code
- `textDocument/codeAction` - Provide quick fixes
- `workspace/executeCommand` - Execute PowerShield commands

**VS Code Extension API:**
- `vscode.languages.registerCodeActionsProvider` - Register quick fixes
- `vscode.languages.createDiagnosticCollection` - Manage diagnostics
- `vscode.commands.registerCommand` - Register PowerShield commands

## Testing

### Manual Testing

```powershell
# Test diagnostic export
Import-Module ./src/VSCodeIntegration.psm1
Import-Module ./src/PowerShellSecurityAnalyzer.psm1

$result = Invoke-SecurityAnalysis -ScriptPath "./tests/TestScripts/powershell/insecure-hash.ps1"
$json = Export-VSCodeDiagnostics -Violations $result.Violations -FilePath "./tests/TestScripts/powershell/insecure-hash.ps1"

# Verify JSON structure
$diagnostics = $json | ConvertFrom-Json
Write-Host "Found $($diagnostics.params.diagnostics.Count) diagnostics"
$diagnostics.params.diagnostics | ForEach-Object {
    Write-Host "  [$($_.severity)] $($_.code): $($_.message)"
}

# Test quick fixes
$fileContent = Get-Content -Path "./tests/TestScripts/powershell/insecure-hash.ps1" -Raw
$fixes = Get-VSCodeQuickFixes -Violation $result.Violations[0] -FileContent $fileContent
Write-Host "`nQuick fixes available: $($fixes.Count)"
$fixes | ForEach-Object {
    Write-Host "  - $($_.description) (confidence: $($_.confidence))"
}

# Test module validation
$moduleTest = Test-ModuleSecurity -ManifestPath "./tests/TestModule.psd1"
Write-Host "`nModule validation:"
Write-Host "  Valid: $($moduleTest.isValid)"
Write-Host "  Security issues: $($moduleTest.securityIssues.Count)"
```

### Automated Testing

Create `tests/Test-VSCodeIntegration.ps1`:

```powershell
#Requires -Version 7.0

Import-Module ./src/VSCodeIntegration.psm1 -Force
Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force

$testsPassed = 0
$testsFailed = 0

# Test 1: Diagnostic export
try {
    $result = Invoke-SecurityAnalysis -ScriptPath "./tests/TestScripts/powershell/insecure-hash.ps1"
    $json = Export-VSCodeDiagnostics -Violations $result.Violations -FilePath "./test.ps1"
    $data = $json | ConvertFrom-Json
    
    if ($data.method -eq "textDocument/publishDiagnostics") {
        Write-Host "✅ Test 1: Diagnostic export" -ForegroundColor Green
        $testsPassed++
    } else {
        throw "Invalid method"
    }
} catch {
    Write-Host "❌ Test 1: Diagnostic export - $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

# Test 2: Command schema
try {
    $schema = Get-VSCodeCommandSchema
    if ($schema.commands.Count -ge 5) {
        Write-Host "✅ Test 2: Command schema" -ForegroundColor Green
        $testsPassed++
    } else {
        throw "Insufficient commands"
    }
} catch {
    Write-Host "❌ Test 2: Command schema - $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
}

Write-Host "`n📊 Results: $testsPassed passed, $testsFailed failed"
exit $testsFailed
```

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    VS Code Extension                    │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Diagnostics│  │  Code Actions│  │   Commands   │  │
│  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘  │
└─────────┼─────────────────┼──────────────────┼──────────┘
          │                 │                  │
          │   Language Server Protocol (LSP)   │
          │                 │                  │
┌─────────▼─────────────────▼──────────────────▼──────────┐
│            VSCodeIntegration.psm1                        │
│  ┌────────────────────────────────────────────────────┐ │
│  │  ConvertToDiagnostics()                           │ │
│  │  ExportDiagnosticsJSON()                          │ │
│  │  GenerateQuickFixes()                             │ │
│  │  GetCommandSchema()                               │ │
│  │  ValidateModuleManifest()                         │ │
│  └────────────────┬───────────────────────────────────┘ │
└───────────────────┼──────────────────────────────────────┘
                    │
┌───────────────────▼──────────────────────────────────────┐
│      PowerShellSecurityAnalyzer.psm1                     │
│  ┌────────────────────────────────────────────────────┐ │
│  │  Invoke-SecurityAnalysis()                        │ │
│  │  52 Security Rules                                │ │
│  │  Violation Detection                              │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

## API Reference

### Functions

#### `New-VSCodeIntegration`
Creates a new VS Code integration instance.

**Returns:** `VSCodeIntegration` object

#### `Export-VSCodeDiagnostics`
Exports violations to VS Code diagnostic JSON format.

**Parameters:**
- `Violations` - Array of violation objects
- `FilePath` - Path to the analyzed file
- `OutputPath` - Optional output file path

**Returns:** JSON string in LSP format

#### `Get-VSCodeQuickFixes`
Generates quick fix suggestions for a violation.

**Parameters:**
- `Violation` - Violation object
- `FileContent` - Complete file content

**Returns:** Array of `QuickFix` objects

#### `Get-VSCodeCommandSchema`
Returns the command schema for VS Code extension.

**Returns:** Hashtable with commands, code actions, and diagnostics

#### `Test-ModuleSecurity`
Validates PowerShell module manifest security.

**Parameters:**
- `ManifestPath` - Path to .psd1 manifest file

**Returns:** Validation result with errors and security issues

## Best Practices

### For Extension Developers

1. **Debouncing** - Always debounce real-time analysis (500ms recommended)
2. **Incremental Analysis** - Analyze only changed portions of large files
3. **Error Handling** - Gracefully handle malformed PowerShell syntax
4. **Performance** - Cache analysis results with file version tracking
5. **User Experience** - Show progress for long-running analyses

### For Security Rule Authors

1. **Quick Fixes** - Provide at least one quick fix per rule
2. **Confidence Scores** - Be conservative; high confidence = 0.8+
3. **Ranges** - Specify exact code ranges for precise highlighting
4. **Messages** - Keep messages concise and actionable
5. **Related Information** - Link to documentation for complex issues

## Limitations

### Current Limitations

1. **No Streaming** - Full file analysis only (no incremental parsing)
2. **No Multi-Root** - Single workspace support
3. **Basic Fixes** - Template-based fixes (Phase 1), AI-powered in Phase 2
4. **English Only** - No internationalization yet

### Future Enhancements (Phase 2)

1. **Streaming Analysis** - Real-time parsing as you type
2. **AI-Powered Fixes** - Context-aware fix suggestions
3. **Multi-Language** - Support for multiple languages
4. **Team Sync** - Real-time collaboration features
5. **Advanced Caching** - Persistent cache across sessions

## References

- [Language Server Protocol](https://microsoft.github.io/language-server-protocol/)
- [VS Code Extension API](https://code.visualstudio.com/api)
- [PowerShell Language Server](https://github.com/PowerShell/PowerShellEditorServices)
- [Test-ModuleManifest Documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/test-modulemanifest)

---

**Implementation Date**: October 26, 2025  
**Implemented By**: GitHub Copilot Agent  
**Phase**: 1 - Item 22 (Phase 2 Preparation)  
**Status**: Foundation Complete ✅
