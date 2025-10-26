# PowerShield for GitLab CI

PowerShield security analysis integration for GitLab CI/CD.

## Installation

### Option 1: Using GitLab CI Component (Recommended)

Add this to your `.gitlab-ci.yml`:

```yaml
include:
  - component: $CI_SERVER_FQDN/powershield/powershield-security@1.0.0
```

### Option 2: Direct Job Definition

Add this to your `.gitlab-ci.yml`:

```yaml
powershield-security:
  stage: test
  image: mcr.microsoft.com/powershell:7.4-alpine-3.20
  script:
    - |
      # Clone PowerShield (in production, use a specific version or package)
      git clone --depth 1 https://github.com/J-Ellette/PowerShield.git /tmp/powershield
      
      # Import modules
      pwsh -Command "
        Import-Module /tmp/powershield/src/PowerShellSecurityAnalyzer.psm1 -Force
        \$result = Invoke-WorkspaceAnalysis -WorkspacePath '.' -EnableSuppressions
        
        # Export results
        \$exportData = @{
            metadata = @{
                version = '1.0.0'
                timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                repository = '$CI_PROJECT_PATH'
                branch = '$CI_COMMIT_REF_NAME'
                sha = '$CI_COMMIT_SHA'
            }
            summary = \$result.Summary
            violations = \$result.Results.Violations
        }
        
        \$exportData | ConvertTo-Json -Depth 10 | Out-File 'powershield-results.json'
        
        # Generate SARIF
        . /tmp/powershield/scripts/Convert-ToSARIF.ps1
        Convert-ToSARIF -InputFile 'powershield-results.json' -OutputFile 'powershield-results.sarif'
        
        # Generate JUnit XML for GitLab test reports
        . /tmp/powershield/scripts/Convert-ToJUnit.ps1
        Convert-ToJUnit -InputFile 'powershield-results.json' -OutputFile 'powershield-results.junit.xml'
        
        # Check for critical violations
        \$critical = (\$result.Results.Violations | Where-Object { \$_.Severity -eq 'Critical' }).Count
        if (\$critical -gt 0) {
            Write-Error 'Found \$critical critical security violations'
            exit 1
        }
      "
  artifacts:
    reports:
      junit: powershield-results.junit.xml
      # SAST report format (GitLab converts SARIF)
      sast: powershield-results.sarif
    paths:
      - powershield-results.json
      - powershield-results.sarif
      - powershield-results.junit.xml
    when: always
    expire_in: 30 days
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
  formats: ["sarif", "junit", "markdown"]
```

### Pipeline Variables

You can configure PowerShield using GitLab CI/CD variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `POWERSHIELD_SEVERITY` | Minimum severity threshold | `Medium` |
| `POWERSHIELD_FAIL_ON_CRITICAL` | Fail pipeline on critical issues | `true` |
| `POWERSHIELD_ENABLE_SUPPRESSIONS` | Enable suppression comments | `true` |

## Merge Request Comments

To post analysis results as MR comments:

```yaml
powershield-mr-comment:
  stage: .post
  image: curlimages/curl:latest
  script:
    - |
      # Read the security report
      REPORT=$(cat security-report.md)
      
      # Post comment using GitLab API
      curl --request POST \
        --header "PRIVATE-TOKEN: $CI_JOB_TOKEN" \
        --header "Content-Type: application/json" \
        --data "{\"body\": \"$REPORT\"}" \
        "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
  rules:
    - if: $CI_MERGE_REQUEST_IID
  needs:
    - powershield-security
```

## Security Dashboard Integration

PowerShield results automatically appear in GitLab's Security Dashboard when using the `sast` report format:

```yaml
artifacts:
  reports:
    sast: powershield-results.sarif
```

## Examples

### Basic Analysis

```yaml
stages:
  - test

powershield:
  stage: test
  image: mcr.microsoft.com/powershell:7.4-alpine-3.20
  script:
    - pwsh /path/to/powershield/psts.ps1 analyze --reports-dir
  artifacts:
    reports:
      junit: .powershield-reports/analysis.junit.xml
      sast: .powershield-reports/analysis.sarif
```

### With Custom Thresholds

```yaml
powershield:
  stage: test
  image: mcr.microsoft.com/powershell:7.4-alpine-3.20
  variables:
    SEVERITY_THRESHOLD: "Critical"
  script:
    - pwsh /path/to/powershield/psts.ps1 analyze --fail-on Critical
```

### Multi-Project Pipeline

```yaml
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

stages:
  - security
  - test
  - deploy

security:powershield:
  stage: security
  image: mcr.microsoft.com/powershell:7.4-alpine-3.20
  script:
    - pwsh /path/to/powershield/psts.ps1 analyze --profile thorough
  artifacts:
    reports:
      sast: .powershield-reports/analysis.sarif
```

## Docker Image

PowerShield provides a pre-built Docker image:

```yaml
powershield:
  stage: test
  image: powershield/powershield:latest
  script:
    - powershield analyze --reports-dir
```

## Troubleshooting

### PowerShell Version
Ensure you're using PowerShell 7.0 or later. The `mcr.microsoft.com/powershell:7.4-alpine-3.20` image is recommended.

### SARIF Format
GitLab expects SARIF 2.1.0 format. PowerShield generates compatible SARIF by default.

### Job Token Permissions
For MR comments, ensure the job token has `api` scope in your project settings.

## Support

- Documentation: https://github.com/J-Ellette/PowerShield/docs
- Issues: https://github.com/J-Ellette/PowerShield/issues
