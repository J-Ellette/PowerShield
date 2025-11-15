# PowerShield (PowerShellTestingSuite) - Copilot Implementation Guide

## Overview
PowerShield is a comprehensive PowerShell security testing suite with three main phases:
1. **Phase 1**: GitHub Workflow Integration (Weeks 1-4)
2. **Phase 2**: VS Code Extension (Weeks 5-8)  
3. **Phase 3**: Standalone Sandbox Application (Weeks 9-12)

## Current Task: Phase 1 Implementation

### Phase 1 Goal
Create a comprehensive GitHub Actions workflow with GitHub Copilot integration for automated PowerShell security analysis and fixes.

### Technical Architecture
- Docker-based analysis engine
- GitHub Actions workflow runner
- GitHub Copilot API integration
- SARIF output for security tab integration
- Automated PR creation for fixes

## Key Components to Implement

### 1. Core Security Analysis Engine
**File**: `src/PowerShellSecurityAnalyzer.psm1`

**Purpose**: PowerShell module that analyzes scripts for security vulnerabilities

**Key Features**:
- Security violation detection (insecure hashes, credential exposure, command injection, cert validation)
- PowerShell AST (Abstract Syntax Tree) parsing
- Rule-based security analysis
- Severity classification (Low, Medium, High, Critical)
- Support for analyzing single files or entire workspaces

**Security Rules to Implement**:
1. **InsecureHashAlgorithms**: Detect MD5, SHA1 usage → recommend SHA256+
2. **CredentialExposure**: Detect plaintext passwords → recommend secure alternatives
3. **CommandInjection**: Detect Invoke-Expression with user input → recommend parameterization
4. **CertificateValidation**: Detect certificate validation bypasses → enforce proper validation

### 2. GitHub Actions Workflow
**File**: `.github/workflows/powershell-security.yml`

**Purpose**: Automated security analysis on push/PR events

**Key Features**:
- Triggered on push to main/develop, PRs, and manual workflow_dispatch
- Runs security analysis using PowerShellSecurityAnalyzer
- Generates SARIF output for GitHub Security tab
- Creates PR comments with analysis results
- Integrates with Copilot for auto-fixes
- Uploads artifacts for reporting

**Jobs**:
1. **security-analysis**: Main analysis job
2. **copilot-autofix**: AI-powered fix generation and PR creation

### 3. GitHub Copilot Integration Action
**Files**: 
- `actions/copilot-autofix/action.yml`
- `actions/copilot-autofix/src/index.ts`

**Purpose**: Custom GitHub Action to generate and apply security fixes using AI

**Key Features**:
- Reads violations from analysis results
- Generates fixes using GitHub Copilot API (or mock implementation)
- Confidence scoring for fixes
- Applies fixes to files
- Creates detailed PR with changes

**Configuration Options**:
- `max-fixes`: Limit number of fixes to apply
- `confidence-threshold`: Minimum confidence to apply fix (0-1)
- `apply-fixes`: Whether to actually modify files
- `create-pr`: Whether to create PR with fixes

### 4. Supporting Scripts

**File**: `scripts/Convert-ToSARIF.ps1`
- Converts PowerShield JSON results to SARIF format
- Enables GitHub Security tab integration
- Maps severity levels to SARIF standards

**File**: `scripts/Generate-SecurityReport.ps1`
- Creates human-readable security reports
- Summarizes violations by severity and type
- Generates markdown output for PRs

## Implementation Plan

### Step 1: Set Up Directory Structure
```
PowerShellTestingSuite/
├── .github/
│   └── workflows/
│       └── powershell-security.yml
├── actions/
│   └── copilot-autofix/
│       ├── action.yml
│       ├── src/
│       │   └── index.ts
│       ├── dist/
│       ├── package.json
│       └── tsconfig.json
├── src/
│   └── PowerShellSecurityAnalyzer.psm1
├── scripts/
│   ├── Convert-ToSARIF.ps1
│   └── Generate-SecurityReport.ps1
├── tests/
│   ├── TestScripts/
│   │   ├── powershell/
│   │   │   ├── insecure-hash.ps1
│   │   │   ├── credential-exposure.ps1
│   │   │   └── command-injection.ps1
│   │   ├── network/
│   │   ├── filesystem/
│   │   ├── registry/
│   │   └── data/
│   └── PowerShellSecurityAnalyzer.Tests.ps1
└── README.md
```

### Step 2: Implement Core Security Analyzer
1. Create PowerShell module with class-based architecture
2. Implement SecurityViolation, SecurityRule, and PowerShellSecurityAnalyzer classes
3. Add default security rules (4 core rules)
4. Implement AST parsing and analysis
5. Add workspace scanning capability

### Step 3: Create GitHub Actions Workflow
1. Define workflow triggers (push, PR, manual)
2. Set up PowerShell environment
3. Import and run security analyzer
4. Generate SARIF and JSON outputs
5. Add PR commenting functionality
6. Configure artifact uploads

### Step 4: Implement Copilot Auto-Fix Action
1. Create TypeScript action structure
2. Implement violation parsing
3. Add fix generation logic (mock Copilot API)
4. Implement confidence scoring
5. Add file modification capability
6. Build and compile action

### Step 5: Create Supporting Scripts
1. SARIF converter for GitHub Security integration
2. Security report generator for human-readable output
3. Helper functions for common operations

### Step 6: Add Tests
1. Create test PowerShell scripts with known violations
2. Write unit tests for analyzer
3. Test workflow locally with act or manual testing
4. Validate SARIF output format

## Security Considerations

### For Analysis Engine:
- Parse PowerShell safely using official Parser API
- Set file size limits to prevent DoS
- Set analysis timeouts
- Validate input paths

### For GitHub Actions:
- Use minimal required permissions
- Store sensitive data in secrets
- Validate all inputs
- Use official actions from verified publishers
- Enable security events writing for SARIF upload

### For Auto-Fix:
- Set confidence thresholds
- Validate all fixes before applying
- Create separate PRs for review
- Provide detailed explanations
- Allow manual override

## Testing Strategy

### Unit Tests:
- Test each security rule individually
- Test parser with valid/invalid PowerShell
- Test violation detection accuracy

### Integration Tests:
- Run full analysis on sample scripts
- Validate SARIF output structure
- Test workflow end-to-end

### Test Scripts:
Create PowerShell files with intentional violations:
1. `insecure-hash.ps1`: Contains MD5/SHA1 usage
2. `credential-exposure.ps1`: Contains plaintext passwords
3. `command-injection.ps1`: Uses Invoke-Expression unsafely
4. `certificate-bypass.ps1`: Bypasses cert validation
5. `all-violations.ps1`: Contains multiple violation types

## Success Criteria

Phase 1 is complete when:
- [x] Core security analyzer module works correctly
- [x] GitHub Actions workflow runs successfully
- [x] SARIF output appears in Security tab
- [x] PR comments are generated with results
- [x] Copilot auto-fix action generates fixes
- [x] Auto-fix PR is created with changes
- [x] All tests pass
- [x] Documentation is complete

## Future Phases (Reference)

### Phase 2: VS Code Extension
- Real-time analysis in editor
- Multi-AI provider support (Copilot, OpenAI, Claude)
- Code actions for quick fixes
- Diagnostic integration
- Configuration UI

### Phase 3: Standalone Application
- Electron desktop app
- Docker sandbox isolation
- Local AI with Ollama
- Enterprise security policies
- Offline capability
- Advanced reporting

## Notes for Implementation

### PowerShell Module Best Practices:
- Use approved verbs (Get-, Test-, New-, etc.)
- Include comment-based help
- Export only necessary functions
- Use proper error handling
- Follow PowerShell style guide

### GitHub Actions Best Practices:
- Use explicit action versions (@v4, not @latest)
- Cache dependencies when possible
- Use matrix builds for multiple PowerShell versions
- Set appropriate timeouts
- Use continues-on-error strategically

### TypeScript Action Best Practices:
- Use @actions/core for workflow commands
- Use @actions/github for API access
- Compile to dist/ for deployment
- Include all dependencies in node_modules or bundle
- Test locally before committing

## Quick Reference Commands

### Test Analyzer Locally:
```powershell
Import-Module ./src/PowerShellSecurityAnalyzer.psm1
$analyzer = [PowerShellSecurityAnalyzer]::new()
$result = $analyzer.AnalyzeScript("./tests/TestScripts/powershell/insecure-hash.ps1")
$result.Violations
```

### Build TypeScript Action:
```bash
cd actions/copilot-autofix
npm install
npm run build
```

### Test Workflow Locally (with act):
```bash
act -j security-analysis
```

### Generate SARIF:
```powershell
. ./scripts/Convert-ToSARIF.ps1
Convert-ToSARIF -InputFile results.json -OutputFile results.sarif
```

## Implementation Priorities

1. **High Priority** (Core functionality):
   - PowerShell security analyzer module
   - Basic GitHub Actions workflow
   - SARIF output generation

2. **Medium Priority** (Enhanced features):
   - Copilot auto-fix action
   - PR commenting
   - Multiple security rules

3. **Low Priority** (Nice to have):
   - Advanced reporting
   - Custom rule configuration
   - Performance optimizations

## Current Status
- **Phase 1**: In Progress
- **Next**: Implement core security analyzer module
