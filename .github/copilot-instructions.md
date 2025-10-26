# Copilot Agent Instructions for PowerShellTestingSuite

## Repository Overview

**PowerShield (Comprehensive PowerShell Security Platform)** is a comprehensive security analysis tool for PowerShell scripts with three development phases:

1. **Phase 1 (Complete)**: GitHub Actions workflow integration with automated security analysis and AI-powered auto-fix
2. **Phase 2 (Planned)**: VS Code extension with real-time analysis and multi-AI provider support
3. **Phase 3 (Planned)**: Standalone Electron desktop application with Docker isolation

## Repository Structure

```
PowerShellTestingSuite/
├── .github/
│   ├── workflows/
│   │   └── powershell-security.yml    # Main CI/CD workflow
│   └── copilot-instructions.md        # This file
├── actions/
│   └── copilot-autofix/               # Custom GitHub Action for auto-fixes
│       ├── action.yml                 # Action definition
│       ├── src/index.ts               # TypeScript source
│       ├── dist/index.js              # Compiled JavaScript (required)
│       ├── package.json               # Node dependencies
│       └── tsconfig.json              # TypeScript config
├── src/
│   └── PowerShellSecurityAnalyzer.psm1  # Core analyzer module
├── scripts/
│   ├── Convert-ToSARIF.ps1            # SARIF format converter
│   └── Generate-SecurityReport.ps1     # Report generator
├── tests/
│   └── TestScripts/                   # Test files with intentional violations
│       ├── insecure-hash.ps1
│       ├── credential-exposure.ps1
│       ├── command-injection.ps1
│       ├── certificate-bypass.ps1
│       └── all-violations.ps1
├── buildplans/                        # Technical documentation
├── copilot.md                         # Original implementation guide
├── IMPLEMENTATION_SUMMARY.md          # Phase 1 completion summary
└── README.md                          # User documentation
```

## Core Components

### 1. PowerShell Security Analyzer (`src/PowerShellSecurityAnalyzer.psm1`)

**Purpose**: Analyzes PowerShell scripts for security vulnerabilities using AST (Abstract Syntax Tree) parsing.

**Architecture**:
- Class-based PowerShell module (requires PowerShell 7.0+)
- Uses `System.Management.Automation.Language` namespace for AST parsing
- Exports three main functions: `New-SecurityAnalyzer`, `Invoke-SecurityAnalysis`, `Invoke-WorkspaceAnalysis`

**Security Rules Implemented**:
1. **InsecureHashAlgorithms** (High): Detects MD5, SHA1, RIPEMD160 usage
2. **CredentialExposure** (Critical): Identifies plaintext password handling
3. **CommandInjection** (Critical): Finds unsafe `Invoke-Expression` usage
4. **CertificateValidation** (High): Catches certificate validation bypasses

**Key Classes**:
- `SecurityViolation`: Represents a single violation with metadata
- `SecurityRule`: Defines a rule with evaluation logic
- `PowerShellSecurityAnalyzer`: Main analyzer with rule collection

**Usage**:
```powershell
Import-Module ./src/PowerShellSecurityAnalyzer.psm1
$result = Invoke-SecurityAnalysis -ScriptPath "./script.ps1"
$workspaceResult = Invoke-WorkspaceAnalysis -WorkspacePath "."
```

### 2. GitHub Actions Workflow (`.github/workflows/powershell-security.yml`)

**Purpose**: Automated security analysis on push, pull request, and manual triggers.

**Jobs**:
- **security-analysis**: Main analysis job that runs the analyzer, generates SARIF, creates reports, and posts PR comments
- **test-analyzer**: Validates the analyzer works correctly on test scripts

**Key Features**:
- SARIF upload to GitHub Security tab
- PR comments with detailed results
- Artifact uploads (JSON, SARIF, markdown reports)
- Configurable severity threshold via workflow_dispatch

**Required Permissions**:
```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write
  issues: write
```

### 3. Auto-Fix Action (`actions/copilot-autofix/`)

**Purpose**: Generates and applies security fixes using rule-based patterns.

**Implementation**: TypeScript-based GitHub Action using:
- `@actions/core`: For workflow commands and outputs
- `@actions/github`: For GitHub API access

**Build Process**:
```bash
cd actions/copilot-autofix
npm install
npm run build  # Compiles to dist/index.js using @vercel/ncc
```

**Important**: The `dist/` folder MUST be committed to the repository for the action to work.

**Inputs**:
- `github-token`: GitHub token (required)
- `violations-file`: Path to violations JSON (default: powershield-results.json)
- `max-fixes`: Maximum fixes to apply (default: 10)
- `confidence-threshold`: Minimum confidence 0-1 (default: 0.8)
- `apply-fixes`: Whether to modify files (default: false)

**Fix Capabilities**:
- MD5/SHA1 → SHA256 replacement
- Plaintext passwords → Read-Host -AsSecureString
- Unsafe Invoke-Expression → Comment/removal
- Certificate validation bypasses → Comments

### 4. Supporting Scripts

**Convert-ToSARIF.ps1**:
- Converts PowerShield JSON results to SARIF 2.1.0 format
- Enables GitHub Security tab integration
- Handles null values gracefully (important!)

**Generate-SecurityReport.ps1**:
- Creates human-readable markdown reports
- Includes severity breakdown and top issues
- Provides actionable recommendations

## Common Errors Encountered and Solutions

### Error 1: PowerShell Class Export Issues

**Problem**: PowerShell classes are not exported from modules by default. Attempting to use `[PowerShellSecurityAnalyzer]::new()` after importing the module failed.

**Error Message**:
```
Unable to find type [PowerShellSecurityAnalyzer].
```

**Solution**: Create wrapper functions that instantiate and use the classes internally:
```powershell
function New-SecurityAnalyzer {
    return [PowerShellSecurityAnalyzer]::new()
}

function Invoke-SecurityAnalysis {
    param([Parameter(Mandatory)][string]$ScriptPath)
    $analyzer = [PowerShellSecurityAnalyzer]::new()
    return $analyzer.AnalyzeScript($ScriptPath)
}

Export-ModuleMember -Function New-SecurityAnalyzer, Invoke-SecurityAnalysis, Invoke-WorkspaceAnalysis
```

**Commit**: `a0a423a` - Initial implementation included the fix

### Error 2: Null Reference Violations in Analysis

**Problem**: The certificate validation rule was too broad and returned AST nodes without proper violation objects, causing null reference errors in summary generation and SARIF conversion.

**Error Message**:
```
You cannot call a method on a null-valued expression.
Exception calling "ContainsKey" with "1" argument(s): "Value cannot be null. (Parameter 'key')"
```

**Solution**: 
1. Refined the certificate validation rule to only detect specific patterns (assignments with `{ $true }`)
2. Added null checks throughout summary generation and SARIF conversion:

```powershell
# In GenerateSummary
foreach ($result in $Results) {
    if ($result.Violations) {
        foreach ($violation in $result.Violations) {
            if ($violation) {
                # Process violation
                $severityStr = if ($violation.Severity) { $violation.Severity.ToString() } else { 'Low' }
                # ...
            }
        }
    }
}

# In Convert-ToSARIF
foreach ($violation in $results.violations) {
    if ($violation -and $violation.RuleId -and $violation.LineNumber) {
        # Process violation
    }
}
```

**Commit**: `f35effd` - Fixed null handling and improved certificate validation rule

### Error 3: Export-ModuleMember Called Outside Module

**Problem**: Scripts that were meant to be dot-sourced (`. ./scripts/Convert-ToSARIF.ps1`) had `Export-ModuleMember` commands that are only valid inside modules.

**Error Message**:
```
Export-ModuleMember: The Export-ModuleMember cmdlet can only be called from inside a module.
```

**Solution**: These errors are warnings and don't break functionality. The functions still work when dot-sourced. To fix properly, remove `Export-ModuleMember` from standalone scripts or convert them to modules.

**Note**: Not critical for Phase 1, but should be addressed in future refactoring.

### Error 4: GitHub Action dist/ Folder Required

**Problem**: GitHub Actions that use `runs: using: node20` require the compiled JavaScript to be committed in the `dist/` folder, but `.gitignore` patterns initially excluded it.

**Error**: Workflow would fail when trying to use the action because `dist/index.js` was missing.

**Solution**: 
1. Created action-specific `.gitignore` in `actions/copilot-autofix/.gitignore`
2. Used `git add -f dist/` to force-add the compiled files
3. Ensured `npm run build` is run before committing changes to the action

**Commit**: `dc1842c` - Added compiled dist folder

### Error 5: Test Artifacts in Repository

**Problem**: During testing, generated files (powershield-results.json, test-results.sarif, etc.) were accidentally committed.

**Solution**: 
1. Created `.gitignore` at repository root with patterns:
```gitignore
powershield-results.json
powershield-results.sarif
security-report.md
test-*.json
test-*.sarif
test-*.md
```
2. Removed test artifacts using `git rm`

**Commit**: `086ac02` - Added .gitignore and cleaned up

## Development Workflow

### Making Changes to the Analyzer

1. **Edit the module**: `src/PowerShellSecurityAnalyzer.psm1`
2. **Test locally**:
   ```powershell
   Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
   $result = Invoke-SecurityAnalysis -ScriptPath "./tests/TestScripts/powershell/insecure-hash.ps1"
   $result.Violations
   ```
3. **Test on workspace**:
   ```powershell
   $workspaceResult = Invoke-WorkspaceAnalysis -WorkspacePath "./tests/TestScripts"
   ```
4. **Verify output**: Check that violations are detected correctly

### Making Changes to the Auto-Fix Action

1. **Edit TypeScript**: `actions/copilot-autofix/src/index.ts`
2. **Build**:
   ```bash
   cd actions/copilot-autofix
   npm install  # If dependencies changed
   npm run build
   ```
3. **Verify dist updated**: Check that `dist/index.js` has changes
4. **Commit both src/ and dist/**:
   ```bash
   git add actions/copilot-autofix/src/
   git add actions/copilot-autofix/dist/
   ```

### Testing the Complete Workflow Locally

```powershell
# Run analysis
Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
$result = Invoke-WorkspaceAnalysis -WorkspacePath "./tests/TestScripts"

# Export results
$allViolations = @()
foreach ($fileResult in $result.Results) {
    if ($fileResult.Violations) {
        $allViolations += $fileResult.Violations
    }
}

$exportData = @{
    metadata = @{
        version = '1.0.0'
        timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
        repository = 'J-Ellette/PowerShellTestingSuite'
    }
    summary = $result.Summary
    violations = $allViolations
}

$exportData | ConvertTo-Json -Depth 10 | Out-File 'test-results.json'

# Generate SARIF
. ./scripts/Convert-ToSARIF.ps1
Convert-ToSARIF -InputFile 'test-results.json' -OutputFile 'test-results.sarif'

# Generate report
. ./scripts/Generate-SecurityReport.ps1
Generate-SecurityReport -InputFile 'test-results.json' -OutputFile 'test-report.md'

# Clean up
Remove-Item test-results.* -Force
```

## Best Practices for This Repository

### PowerShell Development

1. **Always use PowerShell 7.0+**: The module requires PowerShell 7 for class support
2. **Test with -Force flag**: `Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force` to reload changes
3. **Handle nulls defensively**: AST analysis can return nulls, always check before accessing properties
4. **Use approved verbs**: Follow PowerShell naming conventions (Invoke-, Get-, New-, etc.)

### GitHub Actions Development

1. **Pin action versions**: Use `@v4` not `@latest` for stability
2. **Set minimal permissions**: Only request what's needed
3. **Test workflow syntax**: Use `yamllint` or GitHub's workflow validator
4. **Cache when possible**: Use `actions/cache` for dependencies

### TypeScript Action Development

1. **Compile before committing**: Always run `npm run build` before committing
2. **Commit dist/**: The `dist/` folder must be in the repository
3. **Use @actions packages**: Leverage `@actions/core` and `@actions/github`
4. **Handle errors gracefully**: Use try-catch and `core.setFailed()`

### Testing

1. **Use test scripts**: The `tests/TestScripts/` folder contains intentional violations organized by category (powershell/, network/, filesystem/, registry/, data/)
2. **Verify detection**: Ensure all 4 rule types are detected
3. **Check counts**: Expected violations: ~28 across all test scripts
4. **Test SARIF**: Validate SARIF format with schema

## Performance Considerations

1. **File size limits**: Default 10MB max file size (configurable)
2. **Analysis timeout**: Default 30 seconds per file (configurable)
3. **Workspace analysis**: Uses Write-Progress for large directories
4. **Parallel analysis**: Configurable but not implemented in Phase 1

## Security Considerations

1. **No code execution**: Uses AST parsing only, never runs analyzed scripts
2. **Input validation**: File paths and sizes are validated
3. **Timeout protection**: Prevents long-running analysis
4. **Minimal permissions**: GitHub Actions use least privilege

## Common Tasks

### Adding a New Security Rule

1. Edit `src/PowerShellSecurityAnalyzer.psm1`
2. Add to `InitializeDefaultRules()` method:
   ```powershell
   $this.SecurityRules.Add([SecurityRule]::new(
       "RuleName",
       "Description",
       [SecuritySeverity]::High,
       {
           param($Ast, $FilePath)
           $violations = @()
           # Rule logic here
           return $violations
       }
   ))
   ```
3. Create test script in `tests/TestScripts/` in the appropriate category subfolder (powershell/, network/, filesystem/, registry/, data/)
4. Test the rule

### Adding a Fix Pattern

1. Edit `actions/copilot-autofix/src/index.ts`
2. Add to `getRuleBasedFix()` method in the `ruleFixes` object
3. Build: `npm run build`
4. Test with a sample violation

### Updating Documentation

- **User docs**: Update `README.md`
- **Developer docs**: Update `copilot.md` or this file
- **Implementation notes**: Update `IMPLEMENTATION_SUMMARY.md`

## Troubleshooting

### Workflow fails with "Module not found"
- Ensure `src/PowerShellSecurityAnalyzer.psm1` exists
- Check path in workflow is correct: `./src/PowerShellSecurityAnalyzer.psm1`

### Action fails with "Cannot find module"
- Rebuild the action: `cd actions/copilot-autofix && npm run build`
- Ensure `dist/` folder is committed

### No violations detected
- Check PowerShell version (needs 7.0+)
- Verify test scripts exist in `tests/TestScripts/` and subdirectories
- Check file extensions (.ps1, .psm1, .psd1)

### SARIF upload fails
- Verify permissions include `security-events: write`
- Check SARIF format with validator
- Ensure at least one violation exists (empty SARIF may fail)

## Future Development (Phases 2 & 3)

### Phase 2: VS Code Extension
- Real-time analysis as you type
- Multi-AI provider support (Copilot, OpenAI, Claude)
- Code actions for quick fixes
- Diagnostic integration
- See `buildplans/SoftwarePlan/Phase_2_VS_Code_Extension_Implementation.md`

### Phase 3: Standalone Application  
- Electron desktop app
- Docker sandbox for isolated analysis
- Local AI integration (Ollama/CodeLlama)
- Enterprise security policies
- See `buildplans/SoftwarePlan/Phase_3_Standalone_Sandbox_Application.md`

## Key Files to Review Before Changes

1. **Technical Plan**: `buildplans/TechnicalPlan.md` - Overall architecture
2. **Implementation Summary**: `IMPLEMENTATION_SUMMARY.md` - What was built
3. **User README**: `README.md` - How users interact with PowerShield
4. **Original Guide**: `copilot.md` - Implementation planning notes

## Contact and Resources

- **Repository**: https://github.com/J-Ellette/PowerShellTestingSuite
- **Issues**: Use GitHub Issues for bugs and feature requests
- **Discussions**: Use GitHub Discussions for questions

## Version History

- **v1.0.0** (Phase 1): Initial release with GitHub Actions integration
- **Future**: Phase 2 (VS Code) and Phase 3 (Standalone app)

---

*Last Updated: October 23, 2025*
*Phase 1 Status: Complete ✅*
