# PowerShield for TeamCity

PowerShield security analysis integration for TeamCity.

## Installation

### Option 1: Using TeamCity Meta-Runner (Recommended)

1. Download the PowerShield meta-runner XML from this directory
2. In TeamCity:
   - Go to Administration → Meta-Runners
   - Click "Upload Meta-Runner"
   - Select the `powershield-meta-runner.xml` file
3. Add the PowerShield build step to your build configuration

### Option 2: PowerShell Build Step

Add a PowerShell build step to your build configuration:

**Step Name:** PowerShield Security Analysis  
**Script:** From file or inline  
**Script Source:**

```powershell
# Clone PowerShield
git clone --depth 1 https://github.com/J-Ellette/PowerShield.git /tmp/powershield

# Import modules
Import-Module /tmp/powershield/src/PowerShellSecurityAnalyzer.psm1 -Force
Import-Module /tmp/powershield/src/CIAdapter.psm1 -Force

Write-Host "Starting PowerShield security analysis..."

# Detect CI context
$ciAdapter = New-CIAdapter
$context = $ciAdapter.GetContext()
Write-Host "CI Environment: $($context.Provider)"
Write-Host "Repository: $($context.Repository)"

# Run analysis
$result = Invoke-WorkspaceAnalysis -WorkspacePath "%teamcity.build.checkoutDir%" -EnableSuppressions

if ($null -eq $result -or $null -eq $result.Results) {
    Write-Warning "Analysis returned no results"
    exit 0
}

Write-Host "Files analyzed: $($result.FilesAnalyzed)"
Write-Host "Total violations: $($result.TotalViolations)"

# Collect violations
$allViolations = @()
foreach ($fileResult in $result.Results) {
    if ($fileResult.Violations) {
        $allViolations += $fileResult.Violations
    }
}

# Count by severity
$criticalCount = ($allViolations | Where-Object { $_.Severity -eq 'Critical' }).Count
$highCount = ($allViolations | Where-Object { $_.Severity -eq 'High' }).Count
$mediumCount = ($allViolations | Where-Object { $_.Severity -eq 'Medium' }).Count
$lowCount = ($allViolations | Where-Object { $_.Severity -eq 'Low' }).Count

Write-Host "Critical: $criticalCount"
Write-Host "High: $highCount"
Write-Host "Medium: $mediumCount"
Write-Host "Low: $lowCount"

# Export results
$exportData = @{
    metadata = @{
        version = '1.0.0'
        timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        ci = @{
            provider = $context.Provider
            repository = $context.Repository
            branch = $context.Branch
            sha = $context.CommitSha
            buildId = $context.BuildId
        }
    }
    summary = @{
        TotalCritical = $criticalCount
        TotalHigh = $highCount
        TotalMedium = $mediumCount
        TotalLow = $lowCount
        FilesAnalyzed = $result.FilesAnalyzed
    }
    violations = $allViolations
}

# Create reports directory
New-Item -ItemType Directory -Force -Path ".powershield-reports" | Out-Null

# Save JSON
$exportData | ConvertTo-Json -Depth 10 | Out-File '.powershield-reports/analysis.json' -Encoding UTF8

# Generate SARIF
. /tmp/powershield/scripts/Convert-ToSARIF.ps1
Convert-ToSARIF -InputFile '.powershield-reports/analysis.json' -OutputFile '.powershield-reports/analysis.sarif'

# Generate TeamCity service messages
foreach ($violation in $allViolations) {
    $status = if ($violation.Severity -eq 'Critical' -or $violation.Severity -eq 'High') { 'ERROR' } else { 'WARNING' }
    $message = "$($violation.RuleId): $($violation.Message)" -replace '\|', '||' -replace "'", "|'" -replace '\n', '|n' -replace '\r', '|r' -replace '\[', '|[' -replace '\]', '|]'
    $file = $violation.FilePath -replace '\|', '||' -replace "'", "|'" -replace '\n', '|n' -replace '\r', '|r' -replace '\[', '|[' -replace '\]', '|]'
    
    Write-Host "##teamcity[message text='$message' status='$status' file='$file' line='$($violation.LineNumber)']"
}

# Set TeamCity statistics
Write-Host "##teamcity[buildStatisticValue key='PowerShield.Critical' value='$criticalCount']"
Write-Host "##teamcity[buildStatisticValue key='PowerShield.High' value='$highCount']"
Write-Host "##teamcity[buildStatisticValue key='PowerShield.Medium' value='$mediumCount']"
Write-Host "##teamcity[buildStatisticValue key='PowerShield.Low' value='$lowCount']"
Write-Host "##teamcity[buildStatisticValue key='PowerShield.Total' value='$($allViolations.Count)']"

# Fail build if critical issues found
if ($criticalCount -gt 0) {
    Write-Host "##teamcity[buildProblem description='Found $criticalCount critical security violations']"
    exit 1
}

Write-Host "##teamcity[buildStatus text='Security scan complete: $($allViolations.Count) violations found']"
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

### TeamCity Build Parameters

Configure PowerShield using TeamCity build parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `powershield.severity` | Minimum severity threshold | `Medium` |
| `powershield.failOnCritical` | Fail build on critical issues | `true` |

## TeamCity Service Messages

PowerShield generates TeamCity service messages for:

- **Build Problems**: Critical security violations
- **Build Statistics**: Violation counts by severity
- **Test Reports**: Security violations as test failures
- **Inspection Reports**: SARIF format for code inspection

## Build Features

### XML Report Processing

Add an XML Report Processing build feature:

- **Report Type:** Ant JUnit
- **Report Paths:** `.powershield-reports/junit-report.xml`

### Code Inspection (SARIF)

TeamCity supports SARIF inspection reports. PowerShield generates compatible SARIF files.

## Examples

### Basic Build Configuration

```kotlin
// build.gradle.kts (Kotlin DSL)
object PowerShieldSecurity : BuildType({
    name = "PowerShield Security Analysis"
    
    vcs {
        root(DslContext.settingsRoot)
    }
    
    steps {
        powerShell {
            name = "Run PowerShield"
            scriptMode = file {
                path = "integrations/teamcity/powershield-analysis.ps1"
            }
            noProfile = false
        }
    }
    
    features {
        xmlReportProcessing {
            reportType = XmlReport.XmlReportType.JUNIT
            rules = ".powershield-reports/junit-report.xml"
        }
    }
    
    failureConditions {
        errorMessage = true
        nonZeroExitCode = false
        testFailure = false
    }
})
```

### With Docker

```kotlin
steps {
    dockerCommand {
        name = "PowerShield Security Scan"
        commandType = other {
            subCommand = "run"
            commandArgs = """
                --rm
                -v %teamcity.build.checkoutDir%:/workspace
                powershield/powershield:latest
                analyze /workspace --reports-dir
            """.trimIndent()
        }
    }
}
```

### Multi-Configuration

```kotlin
object SecurityAudit : BuildType({
    name = "Security Audit"
    
    params {
        select("powershield.threshold", "High",
            options = listOf("Low", "Medium", "High", "Critical")
        )
    }
    
    steps {
        powerShell {
            scriptMode = file {
                path = "integrations/teamcity/powershield-analysis.ps1"
            }
            param("env.SEVERITY_THRESHOLD", "%powershield.threshold%")
        }
    }
})
```

## Visualization

### Build Statistics

TeamCity will display PowerShield violation counts as build statistics. You can create custom charts:

1. Go to Project Settings → Statistics
2. Add custom charts for:
   - `PowerShield.Critical`
   - `PowerShield.High`
   - `PowerShield.Total`

### Build Status Text

PowerShield updates the build status text with violation counts.

## Artifacts

Configure artifact publishing:

**Artifact paths:**
```
.powershield-reports/** => security-reports
```

## Troubleshooting

### PowerShell Version
Ensure the build agent has PowerShell 7.0 or later installed.

### Service Messages Not Working
Verify that service messages are properly escaped using TeamCity format.

### Reports Not Appearing
Check that XML report processing feature is configured correctly.

## Support

- Documentation: https://github.com/J-Ellette/PowerShield/docs
- Issues: https://github.com/J-Ellette/PowerShield/issues
