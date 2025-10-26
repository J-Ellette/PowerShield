# PowerShield CI/CD Platform Integrations

This directory contains native integrations for PowerShield with popular CI/CD platforms. Each integration provides platform-specific features, simplified configuration, and optimized performance.

## 🚀 Quick Start

Choose your CI/CD platform and follow the integration guide:

| Platform | Documentation | Status |
|----------|---------------|--------|
| [Azure DevOps](./azure-devops/) | Pipeline Task/Extension | ✅ Production Ready |
| [GitLab CI](./gitlab/) | CI Template/Component | ✅ Production Ready |
| [Jenkins](./jenkins/) | Shared Library/Plugin | ✅ Production Ready |
| [CircleCI](./circleci/) | Orb | ✅ Production Ready |
| [TeamCity](./teamcity/) | Meta-Runner | ✅ Production Ready |

## 📋 What's Included

Each integration directory contains:

- **README.md**: Complete setup and configuration guide
- **Example Configurations**: Copy-paste ready pipeline/workflow files
- **Best Practices**: Platform-specific recommendations
- **Troubleshooting**: Common issues and solutions

## 🎯 Features by Platform

### Azure DevOps
- Native pipeline task
- Test result integration
- SARIF upload to security alerts
- PR comment posting via REST API
- Build artifacts publishing

**Quick Start:**
```yaml
- task: PowerShieldSecurityAnalysis@1
  inputs:
    severityThreshold: 'High'
    failOnCritical: true
```

### GitLab CI
- CI component/template
- SAST report format for Security Dashboard
- JUnit test reports
- Merge request comments
- Code quality integration

**Quick Start:**
```yaml
powershield:
  stage: test
  image: mcr.microsoft.com/powershell:7.4-alpine-3.20
  artifacts:
    reports:
      sast: .powershield-reports/analysis.sarif
```

### Jenkins
- Shared library integration
- Warnings Next Generation plugin support
- JUnit test results
- HTML report publishing
- Pipeline as code (Jenkinsfile)

**Quick Start:**
```groovy
@Library('powershield') _
powershieldAnalysis(severityThreshold: 'High')
```

### CircleCI
- CircleCI orb
- Test result integration
- Artifact storage
- Workflow composition
- Docker executor support

**Quick Start:**
```yaml
orbs:
  powershield: powershield/powershield@1.0.0
workflows:
  security:
    jobs:
      - powershield/analyze
```

### TeamCity
- Meta-runner definition
- TeamCity service messages
- Build statistics tracking
- XML report processing
- Build status updates

**Quick Start:**
Upload meta-runner XML and add build step via TeamCity UI

## 🔧 Installation Methods

### Method 1: Native Integration (Recommended)

Use the platform-specific package/extension:

- **Azure DevOps**: Install from Azure DevOps Marketplace
- **GitLab**: Use component include in `.gitlab-ci.yml`
- **Jenkins**: Configure shared library in Jenkins settings
- **CircleCI**: Reference orb in config.yml
- **TeamCity**: Upload meta-runner XML

### Method 2: Direct Script Execution

All platforms support direct PowerShell script execution:

```yaml
# Generic approach for any platform
script:
  - git clone https://github.com/J-Ellette/PowerShield.git /tmp/powershield
  - pwsh /tmp/powershield/psts.ps1 analyze --reports-dir
```

### Method 3: Docker Container

Use the PowerShield Docker image:

```yaml
docker:
  image: powershield/powershield:latest
script:
  - powershield analyze --reports-dir
```

## 📊 Output Formats

All integrations support multiple output formats:

| Format | Use Case | Platforms |
|--------|----------|-----------|
| **SARIF** | Security dashboards, code scanning | All |
| **JUnit XML** | Test result reporting | All |
| **JSON** | Custom processing, APIs | All |
| **Markdown** | PR/MR comments, reports | All |
| **CSV** | Metrics, spreadsheets | All |
| **HTML** | Human-readable reports | Jenkins, TeamCity |

## 🎨 Common Configuration

All integrations support configuration via `.powershield.yml`:

```yaml
version: "1.0"

analysis:
  severity_threshold: "High"
  parallel_analysis: true
  exclude_paths:
    - "**/node_modules/**"
    - "**/dist/**"

ci:
  fail_on: ["Critical", "High"]
  max_warnings: 50

reporting:
  formats: ["sarif", "junit", "markdown"]
```

## 🔍 CI Context Detection

PowerShield automatically detects CI environment and extracts:

- Repository information
- Branch and commit details
- Pull/Merge request IDs
- Build URLs and identifiers

This information is included in all reports and enables smart features like:
- Incremental analysis (only changed files)
- PR/MR comment posting
- Build status updates
- Context-aware reporting

## 🚦 Quality Gates

Configure build failure conditions:

```yaml
# .powershield.yml
ci:
  fail_on: ["Critical", "High"]  # Fail build on these severities
  max_warnings: 50               # Maximum allowed violations
  baseline_mode: true            # Only fail on new violations
```

Or via command-line:

```bash
psts analyze --fail-on Critical --max-warnings 50
```

## 📈 Metrics and Reporting

All integrations provide:

- **Test Results**: Violations as test failures
- **Build Statistics**: Violation counts by severity
- **Artifacts**: All reports preserved for history
- **Trends**: Track security posture over time

### Platform-Specific Features

- **Azure DevOps**: Build statistics, test results, work item integration
- **GitLab**: Security Dashboard, vulnerability management, compliance reports
- **Jenkins**: Warnings NG charts, trend analysis, build health
- **CircleCI**: Insights, test analytics, workflow optimization
- **TeamCity**: Custom charts, investigation tracking, build badges

## 🔐 Security Considerations

### Secrets Management

Never hardcode credentials. Use platform secret management:

- **Azure DevOps**: Azure Key Vault, Variable Groups
- **GitLab**: CI/CD Variables (masked, protected)
- **Jenkins**: Credentials Plugin
- **CircleCI**: Contexts, Project Environment Variables
- **TeamCity**: Password Parameters

### Permissions

Minimal required permissions:

- Read repository code
- Write test results
- Upload security reports
- Post PR/MR comments (optional)

### Isolation

Consider using:
- Container-based execution for isolation
- Dedicated build agents for security scanning
- Network policies to limit outbound access

## 🐛 Troubleshooting

### Common Issues Across Platforms

**Issue**: PowerShell not found or wrong version
**Solution**: Use Docker image `mcr.microsoft.com/powershell:7.4-alpine-3.20`

**Issue**: No violations detected
**Solution**: Check file extensions (.ps1, .psm1, .psd1) and paths

**Issue**: Slow performance
**Solution**: Use `--profile fast` or `--incremental` mode

**Issue**: SARIF upload fails
**Solution**: Verify SARIF 2.1.0 format and proper permissions

### Platform-Specific Troubleshooting

See individual platform READMEs for platform-specific issues.

## 📚 Additional Resources

- [Main CI/CD Integration Guide](../docs/CI_CD_INTEGRATION.md)
- [Configuration Guide](../docs/CONFIGURATION_GUIDE.md)
- [CLI Usage Guide](../docs/CLI_USAGE_GUIDE.md)
- [Output Formats](../docs/OUTPUT_FORMATS.md)
- [Performance Guide](../docs/PERFORMANCE_IMPLEMENTATION.md)

## 🤝 Contributing

To add a new platform integration:

1. Create a directory for the platform: `integrations/platform-name/`
2. Add a comprehensive README.md with:
   - Installation instructions
   - Configuration examples
   - Best practices
   - Troubleshooting
3. Provide working example configurations
4. Update the CIAdapter.psm1 if needed for environment detection
5. Test the integration thoroughly
6. Submit a pull request

## 📄 License

PowerShield is licensed under the MIT License. See [LICENSE](../LICENSE) for details.

## 💬 Support

- **Documentation**: https://github.com/J-Ellette/PowerShield/docs
- **Issues**: https://github.com/J-Ellette/PowerShield/issues
- **Discussions**: https://github.com/J-Ellette/PowerShield/discussions
- **Security**: Report vulnerabilities via GitHub Security Advisories
