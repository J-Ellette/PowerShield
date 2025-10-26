#Requires -Version 7.0

<#
.SYNOPSIS
    Export PowerShield analysis results to JUnit XML format
.DESCRIPTION
    Converts PowerShield analysis results to JUnit XML format for CI/CD integration.
    This format is widely supported by Jenkins, GitLab CI, Azure DevOps, and other platforms.
.PARAMETER InputFile
    Path to PowerShield results JSON file
.PARAMETER OutputFile
    Path to output JUnit XML file
.EXAMPLE
    Export-ToJUnit -InputFile results.json -OutputFile results.junit.xml
.NOTES
    Version: 1.0.0
    JUnit XML Schema: https://www.ibm.com/docs/en/developer-for-zos/14.1?topic=formats-junit-xml-format
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InputFile,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputFile
)

function Convert-ToJUnit {
    param(
        [Parameter(Mandatory = $true)]
        $Results
    )
    
    # Extract violations from results
    $allViolations = @()
    if ($Results.Results) {
        foreach ($fileResult in $Results.Results) {
            if ($fileResult.Violations) {
                $allViolations += $fileResult.Violations
            }
        }
    } elseif ($Results.violations) {
        $allViolations = $Results.violations
    }
    
    # Calculate summary stats
    $totalTests = $allViolations.Count
    $failures = $allViolations.Count  # All violations are considered failures
    $errors = 0
    $skipped = 0
    
    # Calculate timing
    $timestamp = Get-Date -Format "o"
    if ($Results.metadata -and $Results.metadata.timestamp) {
        $timestamp = $Results.metadata.timestamp
    }
    
    $time = 0.0
    if ($Results.performance -and $Results.performance.analysisTimeMs) {
        $time = $Results.performance.analysisTimeMs / 1000.0
    }
    
    # Build XML
    $xml = New-Object System.Xml.XmlDocument
    $xmlDeclaration = $xml.CreateXmlDeclaration("1.0", "UTF-8", $null)
    $xml.AppendChild($xmlDeclaration) | Out-Null
    
    # Root element
    $testsuites = $xml.CreateElement("testsuites")
    $testsuites.SetAttribute("name", "PowerShield")
    $testsuites.SetAttribute("tests", $totalTests)
    $testsuites.SetAttribute("failures", $failures)
    $testsuites.SetAttribute("errors", $errors)
    $testsuites.SetAttribute("skipped", $skipped)
    $testsuites.SetAttribute("time", $time.ToString("F3"))
    $testsuites.SetAttribute("timestamp", $timestamp)
    
    # Group violations by rule ID
    $violationsByRule = $allViolations | Group-Object -Property RuleId
    
    foreach ($ruleGroup in $violationsByRule) {
        $ruleName = $ruleGroup.Name
        $ruleViolations = $ruleGroup.Group
        
        # Create testsuite for each rule
        $testsuite = $xml.CreateElement("testsuite")
        $testsuite.SetAttribute("name", $ruleName)
        $testsuite.SetAttribute("tests", $ruleViolations.Count)
        $testsuite.SetAttribute("failures", $ruleViolations.Count)
        $testsuite.SetAttribute("errors", 0)
        $testsuite.SetAttribute("skipped", 0)
        $testsuite.SetAttribute("time", "0.000")
        $testsuite.SetAttribute("timestamp", $timestamp)
        
        # Create testcase for each violation
        foreach ($violation in $ruleViolations) {
            $testcase = $xml.CreateElement("testcase")
            
            # Use file path as classname
            $className = if ($violation.FilePath) {
                $violation.FilePath -replace '[\\/]', '.'
            } else {
                "Unknown"
            }
            $testcase.SetAttribute("classname", $className)
            
            # Use combination of rule and location as test name
            $testName = "$($violation.RuleId)"
            if ($violation.LineNumber) {
                $testName += "_Line$($violation.LineNumber)"
            }
            $testcase.SetAttribute("name", $testName)
            $testcase.SetAttribute("time", "0.000")
            
            # Add failure element
            $failure = $xml.CreateElement("failure")
            $failure.SetAttribute("message", $violation.Message)
            $failure.SetAttribute("type", $violation.Severity)
            
            # Build detailed failure content
            $failureContent = ""
            $failureContent += "Severity: $($violation.Severity)`n"
            $failureContent += "Rule: $($violation.RuleId)`n"
            $failureContent += "File: $($violation.FilePath)`n"
            $failureContent += "Line: $($violation.LineNumber)`n"
            $failureContent += "Message: $($violation.Message)`n"
            
            if ($violation.Code) {
                $failureContent += "`nCode:`n$($violation.Code)`n"
            }
            
            if ($violation.Remediation) {
                $failureContent += "`nRemediation:`n$($violation.Remediation)`n"
            }
            
            if ($violation.CWE) {
                $failureContent += "`nCWE: $($violation.CWE)`n"
            }
            
            $failure.AppendChild($xml.CreateTextNode($failureContent)) | Out-Null
            $testcase.AppendChild($failure) | Out-Null
            
            $testsuite.AppendChild($testcase) | Out-Null
        }
        
        $testsuites.AppendChild($testsuite) | Out-Null
    }
    
    # If no violations, add a passing test
    if ($totalTests -eq 0) {
        $testsuite = $xml.CreateElement("testsuite")
        $testsuite.SetAttribute("name", "PowerShield")
        $testsuite.SetAttribute("tests", "1")
        $testsuite.SetAttribute("failures", "0")
        $testsuite.SetAttribute("errors", "0")
        $testsuite.SetAttribute("skipped", "0")
        $testsuite.SetAttribute("time", $time.ToString("F3"))
        $testsuite.SetAttribute("timestamp", $timestamp)
        
        $testcase = $xml.CreateElement("testcase")
        $testcase.SetAttribute("classname", "PowerShield")
        $testcase.SetAttribute("name", "NoViolationsFound")
        $testcase.SetAttribute("time", "0.000")
        
        $testsuite.AppendChild($testcase) | Out-Null
        $testsuites.AppendChild($testsuite) | Out-Null
    }
    
    $xml.AppendChild($testsuites) | Out-Null
    
    return $xml
}

# Main execution
try {
    # Validate input file
    if (-not (Test-Path $InputFile)) {
        throw "Input file not found: $InputFile"
    }
    
    # Load results
    $results = Get-Content $InputFile -Raw | ConvertFrom-Json
    
    # Convert to JUnit XML
    $xml = Convert-ToJUnit -Results $results
    
    # Save to file
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.IndentChars = "  "
    $settings.NewLineChars = "`n"
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    
    $writer = [System.Xml.XmlWriter]::Create($OutputFile, $settings)
    try {
        $xml.Save($writer)
    } finally {
        $writer.Close()
    }
    
    Write-Host "✓ JUnit XML exported to: $OutputFile" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to export JUnit XML: $_"
    exit 1
}
