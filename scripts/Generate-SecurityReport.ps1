<#
.SYNOPSIS
    Generates human-readable security reports from PowerShield analysis results.
.DESCRIPTION
    Creates markdown-formatted security reports for use in PRs and documentation.
.PARAMETER InputFile
    Path to the PowerShield JSON results file
.PARAMETER OutputFile
    Path where the markdown report should be written
.EXAMPLE
    Generate-SecurityReport -InputFile results.json -OutputFile security-report.md
#>

function Generate-SecurityReport {
    param(
        [Parameter(Mandatory)]
        [string]$InputFile,
        
        [Parameter(Mandatory)]
        [string]$OutputFile
    )

    if (-not (Test-Path $InputFile)) {
        throw "Input file not found: $InputFile"
    }

    $results = Get-Content $InputFile -Raw | ConvertFrom-Json
    
    # Handle missing violations property safely
    $violations = @()
    if ($results -and $results.PSObject.Properties.Match('violations')) {
      $violations = $results.violations
    }
    if ($null -eq $violations) { $violations = @() }
    $totalViolations = $violations.Count
    
    # Build markdown report
    $report = @"
# PowerShield Security Analysis Report

**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
**Repository:** $($results.metadata.repository)
**Branch:** $($results.metadata.ref)
**Commit:** $($results.metadata.sha)

---

## Summary

"@

    $criticalCount = @($violations | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = @($violations | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = @($violations | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount = @($violations | Where-Object { $_.Severity -eq 'Low' }).Count

    if ($totalViolations -eq 0) {
        $report += @"

✅ **No security violations found!**

All analyzed PowerShell scripts passed security checks.

"@
    } else {
        $report += @"

⚠️ **Total Violations:** $totalViolations

| Severity | Count |
|----------|-------|
| 🔴 Critical | $criticalCount |
| 🟠 High | $highCount |
| 🟡 Medium | $mediumCount |
| 🔵 Low | $lowCount |

"@

        if ($criticalCount -gt 0) {
            $report += @"

### ⚠️ Critical Issues Require Immediate Attention

$criticalCount critical security issues were found that need to be addressed before merging.

"@
        }
    }

    # Add summary by rule
    if ($results.summary.ByCategory.PSObject.Properties.Count -gt 0) {
        $report += @"

## Violations by Type

"@
        foreach ($category in $results.summary.TopIssues) {
            $report += "- **$($category.Rule):** $($category.Count) occurrence(s)`n"
        }
    }

    # Add detailed violations
    if ($totalViolations -gt 0) {
        $report += @"

---

## Detailed Findings

"@

        # Group violations by severity
        $violationsBySeverity = $violations | Group-Object -Property Severity | Sort-Object { 
            switch ($_.Name) {
                'Critical' { 1 }
                'High' { 2 }
                'Medium' { 3 }
                'Low' { 4 }
                default { 5 }
            }
        }

        foreach ($severityGroup in $violationsBySeverity) {
            $icon = switch ($severityGroup.Name) {
                'Critical' { '🔴' }
                'High' { '🟠' }
                'Medium' { '🟡' }
                'Low' { '🔵' }
                default { '⚪' }
            }

            $report += @"

### $icon $($severityGroup.Name) Severity ($($severityGroup.Count))

"@

            foreach ($violation in $severityGroup.Group) {
                $filePath = $null
                if ($violation.PSObject.Properties.Match('FilePath').Count -gt 0) { 
                    $filePath = $violation.FilePath 
                }
                elseif ($violation.PSObject.Properties.Match('Path').Count -gt 0) { 
                    $filePath = $violation.Path 
                }
                $fileName = if ($filePath) { Split-Path $filePath -Leaf } else { '<unknown>' }
                $report += @"

#### $($violation.RuleId)

**File:** ``$fileName`` (Line $($violation.LineNumber))  
**Message:** $($violation.Message)

``````powershell
$($violation.Code)
``````

"@
            }
        }
    }

    # Add recommendations
    $report += @"

---

## Recommendations

"@

    if ($criticalCount -gt 0 -or $highCount -gt 0) {
        $report += @"

### Immediate Actions Required

1. **Address Critical Issues:** Fix all critical severity violations before deployment
2. **Review High Severity Issues:** Evaluate and remediate high severity findings
3. **Run Re-Analysis:** After fixes, re-run PowerShield to verify all issues are resolved

"@
    }

    $report += @"

### Best Practices

- Use SHA-256 or higher for cryptographic hashing
- Never store credentials in plaintext
- Avoid `Invoke-Expression` with user input
- Always validate SSL/TLS certificates
- Use PowerShell approved verbs and cmdlets
- Implement proper error handling
- Follow the principle of least privilege

### Resources

- [PowerShell Security Best Practices](https://docs.microsoft.com/powershell/scripting/security/)
- [PowerShield Documentation](https://github.com/J-Ellette/PowerShellTestingSuite)

---

*Generated by PowerShield v$($results.metadata.version)*
"@

    # Write report to file
    $report | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "Security report written to: $OutputFile"
}

if ($MyInvocation.PSScriptRoot -eq $null -or $MyInvocation.InvocationName -eq '.') {
    # Do not call Export-ModuleMember when dot-sourced
} else {
    Export-ModuleMember -Function Convert-ToSARIF  # or Generate-SecurityReport
}
