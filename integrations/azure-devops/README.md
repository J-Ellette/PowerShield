# PowerShield for Azure DevOps

PowerShield security analysis task for Azure DevOps Pipelines.

## Installation

### Option 1: Using the PowerShield Task (Recommended)

1. Install the PowerShield extension from the Azure DevOps Marketplace (when published)
2. Add the task to your pipeline:

```yaml
- task: PowerShieldSecurityAnalysis@1
  inputs:
    workspacePath: '$(Build.SourcesDirectory)'
    severityThreshold: 'High'
    failOnCritical: true
```

### Option 2: Direct Script Execution

Add this to your `azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
  - checkout: self
    fetchDepth: 0
  
  - task: PowerShell@2
    displayName: 'Install PowerShield'
    inputs:
      targetType: 'inline'
      script: |
        # Clone or install PowerShield
        git clone https://github.com/J-Ellette/PowerShield.git /tmp/powershield
        
  - task: PowerShell@2
    displayName: 'Run PowerShield Security Analysis'
    inputs:
      targetType: 'inline'
      pwsh: true
      script: |
        # Import PowerShield
        Import-Module /tmp/powershield/src/PowerShellSecurityAnalyzer.psm1 -Force
        
        # Run analysis
        $result = Invoke-WorkspaceAnalysis -WorkspacePath "$(Build.SourcesDirectory)" -EnableSuppressions
        
        # Export results
        $exportData = @{
            metadata = @{
                version = '1.0.0'
                timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                repository = "$(Build.Repository.Name)"
                branch = "$(Build.SourceBranchName)"
                sha = "$(Build.SourceVersion)"
            }
            summary = $result.Summary
            violations = $result.Results.Violations
        }
        
        $exportData | ConvertTo-Json -Depth 10 | Out-File 'powershield-results.json'
        
        # Generate SARIF
        . /tmp/powershield/scripts/Convert-ToSARIF.ps1
        Convert-ToSARIF -InputFile 'powershield-results.json' -OutputFile 'powershield-results.sarif'
        
        # Generate report
        . /tmp/powershield/scripts/Generate-SecurityReport.ps1
        Generate-SecurityReport -InputFile 'powershield-results.json' -OutputFile 'security-report.md'
        
        # Check for critical violations
        $critical = ($result.Results.Violations | Where-Object { $_.Severity -eq 'Critical' }).Count
        if ($critical -gt 0) {
            Write-Error "Found $critical critical security violations"
            exit 1
        }
  
  - task: PublishTestResults@2
    displayName: 'Publish Security Test Results'
    condition: always()
    inputs:
      testResultsFormat: 'JUnit'
      testResultsFiles: 'powershield-results.junit.xml'
      failTaskOnFailedTests: true
      testRunTitle: 'PowerShield Security Analysis'
  
  - task: PublishBuildArtifacts@1
    displayName: 'Publish Security Reports'
    condition: always()
    inputs:
      PathtoPublish: '$(Build.SourcesDirectory)'
      ArtifactName: 'security-reports'
      publishLocation: 'Container'
```

## Configuration

### Task Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `workspacePath` | Path to analyze | `$(Build.SourcesDirectory)` | Yes |
| `configFile` | Path to .powershield.yml | `.powershield.yml` | No |
| `severityThreshold` | Minimum severity to report | `Medium` | No |
| `failOnCritical` | Fail build on critical issues | `true` | No |
| `enableSuppressions` | Enable suppression comments | `true` | No |
| `outputFormats` | Output formats (sarif,junit,markdown) | `sarif,junit,markdown` | No |

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

## PR Comment Integration

To post analysis results as PR comments:

```yaml
- task: PowerShell@2
  displayName: 'Post PR Comment'
  condition: and(succeeded(), eq(variables['Build.Reason'], 'PullRequest'))
  inputs:
    targetType: 'inline'
    pwsh: true
    script: |
      $token = "$(System.AccessToken)"
      $org = "$(System.TeamFoundationCollectionUri)"
      $project = "$(System.TeamProject)"
      $repo = "$(Build.Repository.Name)"
      $prId = "$(System.PullRequest.PullRequestId)"
      
      # Read report
      $report = Get-Content security-report.md -Raw
      
      # Post comment using Azure DevOps REST API
      $uri = "$org$project/_apis/git/repositories/$repo/pullRequests/$prId/threads?api-version=7.0"
      $body = @{
          comments = @(
              @{
                  parentCommentId = 0
                  content = $report
                  commentType = 1
              }
          )
          status = 1
      } | ConvertTo-Json -Depth 10
      
      Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType "application/json" -Headers @{
          Authorization = "Bearer $token"
      }
```

## SARIF Upload

Azure DevOps supports SARIF files natively. The results will appear in the Build Summary.

## Examples

### Basic Analysis

```yaml
steps:
  - task: PowerShieldSecurityAnalysis@1
```

### With Custom Configuration

```yaml
steps:
  - task: PowerShieldSecurityAnalysis@1
    inputs:
      severityThreshold: 'Critical'
      failOnCritical: true
      enableSuppressions: true
```

### Multi-Stage Pipeline

```yaml
stages:
  - stage: SecurityAnalysis
    displayName: 'Security Analysis'
    jobs:
      - job: PowerShield
        displayName: 'PowerShield Scan'
        steps:
          - task: PowerShieldSecurityAnalysis@1
            inputs:
              failOnCritical: true
```

## Troubleshooting

### Task Not Found
Ensure the PowerShield extension is installed in your Azure DevOps organization.

### PowerShell Version
The task requires PowerShell 7.0 or later. Use `pwsh: true` in PowerShell tasks.

### Authentication
For PR comments, ensure the build service has "Contribute to pull requests" permission.

## Support

- Documentation: https://github.com/J-Ellette/PowerShield/docs
- Issues: https://github.com/J-Ellette/PowerShield/issues
