# CI/CD Integration Guide

PowerShield provides comprehensive CI/CD integration with support for multiple platforms and output formats.

## Table of Contents

- [Quick Start](#quick-start)
- [Supported Platforms](#supported-platforms)
- [Universal Output Formats](#universal-output-formats)
- [Platform-Specific Integration](#platform-specific-integration)
- [Docker Container](#docker-container)
- [Performance Optimization](#performance-optimization)
- [Advanced Features](#advanced-features)

## Quick Start

### Basic Analysis in CI

```yaml
# .github/workflows/security.yml
- name: Run PowerShield Security Analysis
  run: |
    pwsh ./psts.ps1 analyze --reports-dir --format junit
    
- name: Upload SARIF Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: .powershield-reports/analysis.sarif
```

### With Artifacts

```yaml
- name: Upload Security Reports
  uses: actions/upload-artifact@v3
  with:
    name: security-reports
    path: .powershield-reports/
```

## Supported Platforms

PowerShield automatically detects and integrates with:

- **GitHub Actions** ✓ - Complete integration with SARIF upload and PR comments
- **Azure DevOps Pipelines** ✓ - Native task support with test results and artifacts
- **GitLab CI/CD** ✓ - SAST integration with Security Dashboard and MR comments
- **Jenkins** ✓ - Shared library support with Warnings NG integration
- **CircleCI** ✓ - Orb support with test results and artifacts
- **TeamCity** ✓ - Meta-runner with service messages and build statistics
- **Generic/Local** ✓ - Fallback for any CI system

### Automatic CI Detection

PowerShield automatically detects your CI environment and extracts:
- Repository information
- Branch and commit details
- Pull request / Merge request numbers
- Build URLs and identifiers

```powershell
# The CI context is automatically detected
psts analyze --reports-dir
# Creates run.json with CI metadata
```

## Universal Output Formats

PowerShield generates multiple output formats for different CI/CD tools:

### 1. SARIF (Static Analysis Results Interchange Format)

Standard format for security tools, supported by GitHub, Azure DevOps, and many others.

```bash
psts analyze --format sarif --output results.sarif
```

**Use Cases:**
- GitHub Code Scanning
- Azure DevOps security alerts
- IDE integration (VS Code, Visual Studio)

### 2. JUnit XML

Universal test result format supported by most CI platforms.

```bash
psts analyze --format junit --output results.junit.xml
```

**Use Cases:**
- Test result dashboards
- Build failure reporting
- Jenkins, GitLab CI, CircleCI native integration

### 3. TAP (Test Anything Protocol)

Simple text-based format for test results.

```bash
psts analyze --format tap --output results.tap
```

**Use Cases:**
- Simple parsers
- Custom tooling
- Perl-based CI systems

### 4. CSV/TSV

Spreadsheet-compatible format for reporting and analysis.

```bash
psts analyze --format csv --output results.csv
```

**Use Cases:**
- Metrics dashboards
- Trend analysis
- Excel/Google Sheets integration

### 5. Markdown

Human-readable reports for pull requests.

```bash
psts analyze --format markdown --output report.md
```

**Use Cases:**
- PR/MR comments
- Documentation
- Email reports

### Reports Directory Mode

Generate all formats at once:

```bash
psts analyze --reports-dir
```

Creates `.powershield-reports/` with:
```
.powershield-reports/
├── analysis.sarif          # SARIF 2.1.0 format
├── analysis.json           # Native PowerShield format
├── analysis.junit.xml      # JUnit XML format
├── analysis.tap           # TAP format
├── summary.md             # Markdown report
├── metrics.json           # Performance metrics
├── run.json              # CI run metadata
└── suppressions.json     # Active suppressions
```

## Platform-Specific Integration

### GitHub Actions

```yaml
name: PowerShield Security Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Run PowerShield Analysis
        run: |
          pwsh ./psts.ps1 analyze --reports-dir
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: .powershield-reports/analysis.sarif
      
      - name: Upload All Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: .powershield-reports/
      
      - name: Publish Test Results
        uses: EnricoMi/publish-unit-test-result-action@v2
        if: always()
        with:
          files: .powershield-reports/analysis.junit.xml
```

### Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: PowerShell@2
    displayName: 'Run PowerShield Analysis'
    inputs:
      targetType: 'inline'
      script: |
        ./psts.ps1 analyze --reports-dir
  
  - task: PublishTestResults@2
    displayName: 'Publish Security Test Results'
    inputs:
      testResultsFormat: 'JUnit'
      testResultsFiles: '.powershield-reports/analysis.junit.xml'
      failTaskOnFailedTests: true
  
  - task: PublishBuildArtifacts@1
    displayName: 'Publish Security Reports'
    inputs:
      PathtoPublish: '.powershield-reports'
      ArtifactName: 'security-reports'
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security_analysis:
  stage: test
  image: mcr.microsoft.com/powershell:7.4-alpine-3.20
  script:
    - pwsh ./psts.ps1 analyze --reports-dir
  artifacts:
    reports:
      junit: .powershield-reports/analysis.junit.xml
      codequality: .powershield-reports/analysis.sarif
    paths:
      - .powershield-reports/
    when: always
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    stages {
        stage('Security Analysis') {
            steps {
                pwsh './psts.ps1 analyze --reports-dir'
            }
        }
    }
    
    post {
        always {
            junit '.powershield-reports/analysis.junit.xml'
            archiveArtifacts artifacts: '.powershield-reports/**'
        }
    }
}
```

### CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security:
    docker:
      - image: mcr.microsoft.com/powershell:7.4-alpine-3.20
    steps:
      - checkout
      - run:
          name: Run PowerShield Analysis
          command: pwsh ./psts.ps1 analyze --reports-dir
      - store_test_results:
          path: .powershield-reports
      - store_artifacts:
          path: .powershield-reports
```

### TeamCity

```yaml
# TeamCity build step (Kotlin DSL)
steps {
    powerShell {
        name = "PowerShield Security Analysis"
        scriptMode = file {
            path = "integrations/teamcity/powershield-analysis.ps1"
        }
    }
}

features {
    xmlReportProcessing {
        reportType = XmlReport.XmlReportType.JUNIT
        rules = ".powershield-reports/junit-report.xml"
    }
}
```

## Platform-Specific Integration Guides

Each platform has a dedicated integration guide with detailed setup instructions, native integrations, and best practices:

### 📘 Platform Documentation

| Platform | Integration Type | Documentation |
|----------|------------------|---------------|
| **Azure DevOps** | Pipeline Task/Extension | [Azure DevOps Guide](../integrations/azure-devops/README.md) |
| **GitLab CI** | CI Template/Component | [GitLab CI Guide](../integrations/gitlab/README.md) |
| **Jenkins** | Shared Library/Plugin | [Jenkins Guide](../integrations/jenkins/README.md) |
| **CircleCI** | Orb | [CircleCI Guide](../integrations/circleci/README.md) |
| **TeamCity** | Meta-Runner | [TeamCity Guide](../integrations/teamcity/README.md) |

### Quick Start by Platform

#### Azure DevOps - Native Task

```yaml
# Install PowerShield extension from marketplace, then:
- task: PowerShieldSecurityAnalysis@1
  inputs:
    severityThreshold: 'High'
    failOnCritical: true
```

[View complete Azure DevOps examples →](../integrations/azure-devops/azure-pipelines.yml)

#### GitLab CI - SAST Integration

```yaml
# Integrates with GitLab Security Dashboard
powershield:
  stage: test
  image: mcr.microsoft.com/powershell:7.4-alpine-3.20
  script:
    - pwsh /path/to/psts.ps1 analyze --reports-dir
  artifacts:
    reports:
      sast: .powershield-reports/analysis.sarif
      junit: .powershield-reports/analysis.junit.xml
```

[View complete GitLab CI examples →](../integrations/gitlab/.gitlab-ci.yml)

#### Jenkins - Shared Library

```groovy
// Add to Jenkinsfile
@Library('powershield') _

pipeline {
    agent any
    stages {
        stage('Security') {
            steps {
                powershieldAnalysis(
                    severityThreshold: 'High',
                    failOnCritical: true
                )
            }
        }
    }
}
```

[View complete Jenkins examples →](../integrations/jenkins/Jenkinsfile)

#### CircleCI - Orb

```yaml
# .circleci/config.yml
version: 2.1
orbs:
  powershield: powershield/powershield@1.0.0

workflows:
  security:
    jobs:
      - powershield/analyze:
          severity-threshold: "High"
```

[View complete CircleCI examples →](../integrations/circleci/config.yml)

#### TeamCity - Meta-Runner

Upload the PowerShield meta-runner to TeamCity and add the step to your build configuration.

[View complete TeamCity examples →](../integrations/teamcity/README.md)

## Docker Container

### Building the Container

```bash
docker build -t powershield:latest .
```

### Running Analysis

```bash
# Analyze current directory
docker run --rm -v $(pwd):/workspace powershield analyze /workspace

# Generate all reports
docker run --rm -v $(pwd):/workspace powershield analyze /workspace --reports-dir

# Export to specific format
docker run --rm -v $(pwd):/workspace powershield analyze /workspace --format sarif --output results.sarif
```

### In CI/CD

```yaml
# GitHub Actions with Docker
- name: Run PowerShield in Docker
  run: |
    docker run --rm -v ${{ github.workspace }}:/workspace \
      powershield:latest analyze /workspace --reports-dir
```

## Performance Optimization

### Performance Profiles

PowerShield supports three performance profiles:

#### Fast Mode (3x faster)
- Skips low-severity rules
- Lower file size limits (5MB)
- Reduced timeout per file (10s)
- Best for: Quick feedback, pre-commit hooks

```bash
psts analyze --profile fast
```

#### Balanced Mode (default)
- Comprehensive analysis
- Standard file limits (10MB)
- Reasonable timeouts (30s)
- Best for: CI/CD pipelines

```bash
psts analyze --profile balanced
```

#### Thorough Mode (most comprehensive)
- All rules including experimental
- Large file support (50MB)
- Extended timeouts (60s)
- Best for: Security audits, releases

```bash
psts analyze --profile thorough
```

### Incremental Analysis

Only analyze changed files (requires git repository):

```bash
# Only analyze files changed in this PR/commit
psts analyze --incremental
```

```yaml
# GitHub Actions
- name: Incremental Analysis
  run: pwsh ./psts.ps1 analyze --incremental --reports-dir
```

### Parallel Processing

PowerShield automatically uses parallel processing when appropriate. Configure in `.powershield.yml`:

```yaml
analysis:
  parallel_analysis: true
  max_workers: 4  # or auto for CPU count
```

## Advanced Features

### Baseline Mode

Track only new violations (prevents technical debt):

```bash
# Create baseline
psts baseline create

# Compare with baseline (only show new issues)
psts analyze --baseline .powershield-baseline.json
```

```yaml
# GitHub Actions with baseline
- name: Create Baseline (main branch)
  if: github.ref == 'refs/heads/main'
  run: psts baseline create
  
- name: Compare with Baseline (PRs)
  if: github.event_name == 'pull_request'
  run: psts baseline compare
```

### Fail on Severity

Configure CI gate in `.powershield.yml`:

```yaml
ci:
  fail_on: ["Critical", "High"]
  max_warnings: 50
```

Or via command line:

```bash
# Fail only on Critical issues
psts analyze --fail-on Critical
```

### Enhanced PR Comments

Generate rich PR/MR comments with code snippets and recommendations:

```yaml
- name: Generate PR Comment
  run: |
    pwsh -Command "
      Import-Module ./src/PRCommentRenderer.psm1
      \$result = Get-Content .powershield-reports/analysis.json | ConvertFrom-Json
      \$comment = New-EnhancedPRComment -Results \$result -IncludeCodeSnippets
      \$comment | Out-File pr-comment.md
    "
    
- name: Post PR Comment
  uses: actions/github-script@v6
  with:
    script: |
      const fs = require('fs');
      const comment = fs.readFileSync('pr-comment.md', 'utf8');
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: comment
      });
```

### Custom Workflows

#### Security Gates for Releases

```yaml
name: Release Security Gate

on:
  push:
    tags:
      - 'v*'

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Thorough Security Analysis
        run: |
          pwsh ./psts.ps1 analyze --profile thorough --reports-dir
      
      - name: Block on Any Critical Issues
        run: |
          \$critical = (Get-Content .powershield-reports/metrics.json | ConvertFrom-Json).counts.Critical
          if (\$critical -gt 0) {
            Write-Error "❌ Cannot release with \$critical critical security issues"
            exit 1
          }
```

#### Scheduled Security Audits

```yaml
name: Weekly Security Audit

on:
  schedule:
    - cron: '0 0 * * 0'  # Every Sunday

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Comprehensive Audit
        run: |
          pwsh ./psts.ps1 analyze --profile thorough --reports-dir
      
      - name: Send Audit Report
        # Email or Slack notification with reports
```

## Troubleshooting

### Common Issues

**Issue**: SARIF upload fails
**Solution**: Ensure `security-events: write` permission is granted

**Issue**: No violations detected
**Solution**: Check PowerShell version (requires 7.0+) and file extensions (.ps1, .psm1, .psd1)

**Issue**: Performance is slow
**Solution**: Use `--profile fast` or `--incremental` mode

**Issue**: False positives
**Solution**: Use suppression comments or baseline mode

### Getting Help

- **Documentation**: https://github.com/J-Ellette/PowerShield/tree/main/docs
- **Issues**: https://github.com/J-Ellette/PowerShield/issues
- **Discussions**: https://github.com/J-Ellette/PowerShield/discussions

## Native Integrations

PowerShield provides native integrations for popular CI/CD platforms, making setup easier and providing better integration with platform features.

### Available Integrations

| Platform | Integration Type | Status | Installation |
|----------|------------------|--------|--------------|
| Azure DevOps | Pipeline Task | ✅ Ready | Install from [Azure DevOps Marketplace](#) |
| GitLab CI | CI Component | ✅ Ready | Use `include: component` in `.gitlab-ci.yml` |
| Jenkins | Shared Library | ✅ Ready | Configure in Jenkins global settings |
| CircleCI | Orb | ✅ Ready | Reference in `.circleci/config.yml` |
| TeamCity | Meta-Runner | ✅ Ready | Upload XML to TeamCity |
| GitHub Actions | Action | ✅ Built-in | Use workflow YAML |

### Benefits of Native Integrations

- **Zero Configuration**: Works out of the box with sensible defaults
- **Platform Features**: Deep integration with platform-specific features
  - SARIF upload to security dashboards
  - Test result integration
  - Build annotations and inline comments
  - Artifact publishing
- **Simplified Maintenance**: Updates managed through platform package managers
- **Better Performance**: Optimized for each platform's execution model

### Installation Guides

Detailed installation and configuration guides are available in the `integrations/` directory:

```
integrations/
├── azure-devops/     # Azure DevOps Pipeline Task
│   ├── README.md
│   ├── task.json
│   └── azure-pipelines.yml
├── gitlab/           # GitLab CI Component
│   ├── README.md
│   └── .gitlab-ci.yml
├── jenkins/          # Jenkins Shared Library
│   ├── README.md
│   └── Jenkinsfile
├── circleci/         # CircleCI Orb
│   ├── README.md
│   └── config.yml
└── teamcity/         # TeamCity Meta-Runner
    └── README.md
```

Each integration includes:
- Complete setup instructions
- Copy-paste configuration examples
- Platform-specific features and best practices
- Troubleshooting guides

## Next Steps

- Configure `.powershield.yml` for your project
- Set up baseline for existing projects
- Integrate with your CI/CD platform
- Configure PR/MR comments
- Set up scheduled security audits
