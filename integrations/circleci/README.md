# PowerShield for CircleCI

PowerShield security analysis integration for CircleCI.

## Installation

### Option 1: Using CircleCI Orb (Recommended)

Add this to your `.circleci/config.yml`:

```yaml
version: 2.1

orbs:
  powershield: powershield/powershield@1.0.0

workflows:
  security:
    jobs:
      - powershield/analyze:
          severity-threshold: "High"
          fail-on-critical: true
```

### Option 2: Direct Job Definition

Add this to your `.circleci/config.yml`:

```yaml
version: 2.1

jobs:
  powershield-security:
    docker:
      - image: mcr.microsoft.com/powershell:7.4-alpine-3.20
    steps:
      - checkout
      - run:
          name: Install PowerShield
          command: |
            apk add --no-cache git
            git clone --depth 1 https://github.com/J-Ellette/PowerShield.git /tmp/powershield
      - run:
          name: Run Security Analysis
          command: |
            pwsh -Command "
              Import-Module /tmp/powershield/src/PowerShellSecurityAnalyzer.psm1 -Force
              \$result = Invoke-WorkspaceAnalysis -WorkspacePath '.' -EnableSuppressions
              
              # Export results
              \$exportData = @{
                  metadata = @{
                      version = '1.0.0'
                      timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                      repository = '$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME'
                      branch = '$CIRCLE_BRANCH'
                      sha = '$CIRCLE_SHA1'
                  }
                  summary = \$result.Summary
                  violations = \$result.Results.Violations
              }
              
              \$exportData | ConvertTo-Json -Depth 10 | Out-File 'powershield-results.json'
              
              # Generate JUnit XML for CircleCI
              . /tmp/powershield/scripts/Convert-ToJUnit.ps1
              Convert-ToJUnit -InputFile 'powershield-results.json' -OutputFile 'test-results/powershield.xml'
              
              # Check for critical violations
              \$critical = (\$result.Results.Violations | Where-Object { \$_.Severity -eq 'Critical' }).Count
              if (\$critical -gt 0) {
                  Write-Error 'Found \$critical critical security violations'
                  exit 1
              }
            "
      - store_test_results:
          path: test-results
      - store_artifacts:
          path: powershield-results.json
          destination: security-reports

workflows:
  version: 2
  security-scan:
    jobs:
      - powershield-security
```

## Configuration

### Using .powershield.yml

Create a `.powershield.yml` file in your repository root:

```yaml
version: "1.0"

analysis:
  severity_threshold: "High"
  parallel_analysis: true
  
ci:
  fail_on: ["Critical", "High"]
  max_warnings: 50

reporting:
  formats: ["junit", "sarif", "markdown"]
```

### CircleCI Environment Variables

Configure PowerShield using CircleCI environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `POWERSHIELD_SEVERITY` | Minimum severity threshold | `Medium` |
| `POWERSHIELD_FAIL_ON_CRITICAL` | Fail build on critical issues | `true` |

## Orb Reference

### Jobs

#### `analyze`

Run PowerShield security analysis.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `workspace-path` | string | `.` | Path to analyze |
| `severity-threshold` | enum | `Medium` | Minimum severity (Low, Medium, High, Critical) |
| `fail-on-critical` | boolean | `true` | Fail on critical issues |
| `enable-suppressions` | boolean | `true` | Enable suppression comments |

**Example:**

```yaml
workflows:
  security:
    jobs:
      - powershield/analyze:
          severity-threshold: "High"
          fail-on-critical: true
```

### Commands

#### `install`

Install PowerShield.

**Example:**

```yaml
steps:
  - powershield/install
```

#### `run-analysis`

Run security analysis.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `workspace-path` | string | `.` | Path to analyze |
| `output-format` | string | `junit` | Output format |

**Example:**

```yaml
steps:
  - powershield/run-analysis:
      workspace-path: "./src"
      output-format: "junit"
```

## Examples

### Basic Workflow

```yaml
version: 2.1

orbs:
  powershield: powershield/powershield@1.0.0

workflows:
  main:
    jobs:
      - powershield/analyze
```

### Advanced Workflow

```yaml
version: 2.1

orbs:
  powershield: powershield/powershield@1.0.0

workflows:
  security-pipeline:
    jobs:
      - powershield/analyze:
          name: security-scan
          severity-threshold: "High"
          fail-on-critical: true
          filters:
            branches:
              only:
                - main
                - develop
```

### Multi-Environment

```yaml
version: 2.1

orbs:
  powershield: powershield/powershield@1.0.0

workflows:
  version: 2
  test-and-secure:
    jobs:
      - test
      - powershield/analyze:
          name: security-check
          requires:
            - test
          severity-threshold: "Critical"
```

## Docker Image

PowerShield provides a pre-built Docker image:

```yaml
jobs:
  security:
    docker:
      - image: powershield/powershield:latest
    steps:
      - checkout
      - run: powershield analyze --reports-dir
```

## Troubleshooting

### PowerShell Version
Ensure you're using PowerShell 7.0 or later. The CircleCI executor must support PowerShell.

### Test Results Not Appearing
Verify the test results path matches the `store_test_results` configuration.

### Permission Issues
Ensure the job has permission to clone repositories and access required resources.

## Support

- Documentation: https://github.com/J-Ellette/PowerShield/docs
- Issues: https://github.com/J-Ellette/PowerShield/issues
- Orb Registry: https://circleci.com/developer/orbs/orb/powershield/powershield
