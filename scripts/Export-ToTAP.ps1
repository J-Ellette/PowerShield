#Requires -Version 7.0

<#
.SYNOPSIS
    Export PowerShield analysis results to TAP (Test Anything Protocol) format
.DESCRIPTION
    Converts PowerShield analysis results to TAP format for universal CI/CD integration.
    TAP is a simple text-based format supported by many testing frameworks and CI systems.
.PARAMETER InputFile
    Path to PowerShield results JSON file
.PARAMETER OutputFile
    Path to output TAP file
.EXAMPLE
    Export-ToTAP -InputFile results.json -OutputFile results.tap
.NOTES
    Version: 1.0.0
    TAP Specification: https://testanything.org/tap-version-13-specification.html
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InputFile,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputFile
)

function Convert-ToTAP {
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
    
    # Build TAP output
    $tapOutput = @()
    
    # TAP version
    $tapOutput += "TAP version 13"
    
    # Plan line - total number of tests
    $totalTests = $allViolations.Count
    if ($totalTests -eq 0) {
        $totalTests = 1  # Always report at least one test
    }
    $tapOutput += "1..$totalTests"
    
    if ($allViolations.Count -eq 0) {
        # No violations - report success
        $tapOutput += "ok 1 - No security violations found"
        $tapOutput += "# PowerShield analysis completed successfully"
        
        if ($Results.Summary) {
            $tapOutput += "# Files analyzed: $($Results.TotalFiles)"
        }
    } else {
        # Report each violation as a test
        $testNumber = 1
        
        foreach ($violation in $allViolations) {
            # Each violation is a failed test
            $testLine = "not ok $testNumber - $($violation.RuleId)"
            
            # Add description with file and line
            if ($violation.FilePath -and $violation.LineNumber) {
                $testLine += " at $($violation.FilePath):$($violation.LineNumber)"
            }
            
            $tapOutput += $testLine
            
            # Add diagnostic lines (prefixed with #)
            $tapOutput += "  ---"
            $tapOutput += "  severity: $($violation.Severity)"
            $tapOutput += "  message: $($violation.Message)"
            
            if ($violation.FilePath) {
                $tapOutput += "  file: $($violation.FilePath)"
            }
            
            if ($violation.LineNumber) {
                $tapOutput += "  line: $($violation.LineNumber)"
            }
            
            if ($violation.Code) {
                $codeLines = $violation.Code -split "`n"
                $tapOutput += "  code: |"
                foreach ($codeLine in $codeLines) {
                    $tapOutput += "    $codeLine"
                }
            }
            
            if ($violation.CWE) {
                $tapOutput += "  cwe: $($violation.CWE)"
            }
            
            if ($violation.Remediation) {
                $remediationLines = $violation.Remediation -split "`n"
                $tapOutput += "  remediation: |"
                foreach ($remLine in $remediationLines) {
                    $tapOutput += "    $remLine"
                }
            }
            
            $tapOutput += "  ..."
            
            $testNumber++
        }
        
        # Add summary diagnostics
        $tapOutput += ""
        $tapOutput += "# Summary"
        if ($Results.Summary) {
            $tapOutput += "# Critical: $($Results.Summary.TotalCritical)"
            $tapOutput += "# High: $($Results.Summary.TotalHigh)"
            $tapOutput += "# Medium: $($Results.Summary.TotalMedium)"
            $tapOutput += "# Low: $($Results.Summary.TotalLow)"
        }
        $tapOutput += "# Total violations: $($allViolations.Count)"
        
        if ($Results.TotalFiles) {
            $tapOutput += "# Files analyzed: $($Results.TotalFiles)"
        }
    }
    
    return $tapOutput -join "`n"
}

# Main execution
try {
    # Validate input file
    if (-not (Test-Path $InputFile)) {
        throw "Input file not found: $InputFile"
    }
    
    # Load results
    $results = Get-Content $InputFile -Raw | ConvertFrom-Json
    
    # Convert to TAP
    $tapContent = Convert-ToTAP -Results $results
    
    # Save to file
    $tapContent | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline
    
    Write-Host "✓ TAP format exported to: $OutputFile" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to export TAP format: $_"
    exit 1
}
