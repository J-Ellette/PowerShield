# PowerShield for Jenkins

PowerShield security analysis integration for Jenkins.

## Installation

### Option 1: Using Jenkins Shared Library (Recommended)

1. Configure the PowerShield Shared Library in Jenkins global settings
2. Add this to your Jenkinsfile:

```groovy
@Library('powershield') _

pipeline {
    agent any
    
    stages {
        stage('Security Analysis') {
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

### Option 2: Direct Jenkinsfile Implementation

Add this to your Jenkinsfile:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('PowerShield Security Analysis') {
            agent {
                docker {
                    image 'mcr.microsoft.com/powershell:7.4-alpine-3.20'
                    reuseNode true
                }
            }
            steps {
                sh '''
                    # Clone PowerShield
                    git clone --depth 1 https://github.com/J-Ellette/PowerShield.git /tmp/powershield
                    
                    # Run analysis
                    pwsh -Command "
                        Import-Module /tmp/powershield/src/PowerShellSecurityAnalyzer.psm1 -Force
                        \$result = Invoke-WorkspaceAnalysis -WorkspacePath '$WORKSPACE' -EnableSuppressions
                        
                        # Export results
                        \$exportData = @{
                            metadata = @{
                                version = '1.0.0'
                                timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                                repository = '$GIT_URL'
                                branch = '$GIT_BRANCH'
                                sha = '$GIT_COMMIT'
                            }
                            summary = \$result.Summary
                            violations = \$result.Results.Violations
                        }
                        
                        \$exportData | ConvertTo-Json -Depth 10 | Out-File 'powershield-results.json'
                        
                        # Generate JUnit XML for Jenkins
                        . /tmp/powershield/scripts/Convert-ToJUnit.ps1
                        Convert-ToJUnit -InputFile 'powershield-results.json' -OutputFile 'powershield-results.xml'
                        
                        # Check for critical violations
                        \$critical = (\$result.Results.Violations | Where-Object { \$_.Severity -eq 'Critical' }).Count
                        if (\$critical -gt 0) {
                            Write-Error 'Found \$critical critical security violations'
                            exit 1
                        }
                    "
                '''
            }
            post {
                always {
                    junit 'powershield-results.xml'
                    archiveArtifacts artifacts: 'powershield-results.*', fingerprint: true
                }
            }
        }
    }
}
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

### Jenkins Environment Variables

Configure PowerShield using Jenkins environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `POWERSHIELD_SEVERITY` | Minimum severity threshold | `Medium` |
| `POWERSHIELD_FAIL_ON_CRITICAL` | Fail build on critical issues | `true` |
| `POWERSHIELD_CONFIG` | Path to config file | `.powershield.yml` |

## Jenkins Shared Library

Create a shared library with this structure:

```
jenkins-powershield-lib/
├── vars/
│   └── powershieldAnalysis.groovy
└── resources/
    └── powershield/
        └── analyze.ps1
```

**vars/powershieldAnalysis.groovy:**

```groovy
def call(Map config = [:]) {
    def severityThreshold = config.severityThreshold ?: 'Medium'
    def failOnCritical = config.failOnCritical ?: true
    def enableSuppressions = config.enableSuppressions ?: true
    
    docker.image('mcr.microsoft.com/powershell:7.4-alpine-3.20').inside {
        sh """
            # Clone PowerShield
            git clone --depth 1 https://github.com/J-Ellette/PowerShield.git /tmp/powershield
            
            # Run analysis
            pwsh /tmp/powershield/psts.ps1 analyze \
                --severity-threshold ${severityThreshold} \
                --fail-on-critical ${failOnCritical} \
                --reports-dir
        """
        
        // Publish results
        junit '.powershield-reports/analysis.junit.xml'
        archiveArtifacts artifacts: '.powershield-reports/**', fingerprint: true
        
        // Publish HTML report
        publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: '.powershield-reports',
            reportFiles: 'security-report.html',
            reportName: 'PowerShield Security Report'
        ])
    }
}
```

## PR Comment Integration

For GitHub/GitLab pull requests via Jenkins:

```groovy
stage('Post PR Comment') {
    when {
        changeRequest()
    }
    steps {
        script {
            def report = readFile('.powershield-reports/security-report.md')
            
            // For GitHub
            pullRequest.comment("## 🛡️ PowerShield Security Analysis\n\n${report}")
            
            // For GitLab
            gitlabCommitStatus(name: 'PowerShield') {
                // GitLab integration
            }
        }
    }
}
```

## Warnings Next Generation Plugin

Integrate with Jenkins Warnings NG plugin for rich UI:

```groovy
post {
    always {
        recordIssues(
            tools: [sarif(pattern: '.powershield-reports/analysis.sarif')],
            qualityGates: [[threshold: 1, type: 'TOTAL', criticality: 'UNSTABLE']]
        )
    }
}
```

## Examples

### Basic Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security') {
            steps {
                powershieldAnalysis()
            }
        }
    }
}
```

### Multi-Branch Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Analysis') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    changeRequest()
                }
            }
            steps {
                powershieldAnalysis(
                    severityThreshold: env.BRANCH_NAME == 'main' ? 'High' : 'Medium',
                    failOnCritical: true
                )
            }
        }
    }
    
    post {
        always {
            junit '.powershield-reports/analysis.junit.xml'
            archiveArtifacts '.powershield-reports/**'
        }
    }
}
```

### With Docker Agent

```groovy
pipeline {
    agent {
        docker {
            image 'powershield/powershield:latest'
        }
    }
    
    stages {
        stage('Analyze') {
            steps {
                sh 'powershield analyze --reports-dir'
            }
        }
    }
}
```

## Troubleshooting

### PowerShell Not Found
Ensure the agent has PowerShell 7.0+ installed or use a Docker agent.

### Permission Issues
Ensure Jenkins has permission to clone the PowerShield repository and write artifacts.

### JUnit XML Not Found
Verify the output path matches the `junit` step configuration.

## Support

- Documentation: https://github.com/J-Ellette/PowerShield/docs
- Issues: https://github.com/J-Ellette/PowerShield/issues
