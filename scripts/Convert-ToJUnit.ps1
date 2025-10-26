#Requires -Version 7.0

<#
.SYNOPSIS
    Convert PowerShield analysis results to JUnit XML format
.DESCRIPTION
    Converts PowerShield JSON analysis results to JUnit XML format for CI/CD integration
.PARAMETER InputFile
    Path to PowerShield JSON results file
.PARAMETER OutputFile
    Path to output JUnit XML file
.EXAMPLE
    Convert-ToJUnit -InputFile 'analysis.json' -OutputFile 'results.junit.xml'
#>

function Convert-ToJUnit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputFile,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )
    
    try {
        # Read input file
        if (-not (Test-Path $InputFile)) {
            throw "Input file not found: $InputFile"
        }
        
        $results = Get-Content $InputFile -Raw | ConvertFrom-Json
        
        # Extract violations
        $violations = @()
        if ($results.violations) {
            $violations = $results.violations
        } elseif ($results.Results) {
            foreach ($fileResult in $results.Results) {
                if ($fileResult.Violations) {
                    $violations += $fileResult.Violations
                }
            }
        }
        
        # Count by severity
        $failureCount = ($violations | Where-Object { 
            $_.Severity -in @('Critical', 'High') 
        }).Count
        
        $totalCount = $violations.Count
        
        # Build JUnit XML
        $xml = [System.Text.StringBuilder]::new()
        [void]$xml.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
        [void]$xml.AppendLine("<testsuites name=`"PowerShield Security Analysis`" tests=`"$totalCount`" failures=`"$failureCount`">")
        [void]$xml.AppendLine("  <testsuite name=`"SecurityRules`" tests=`"$totalCount`" failures=`"$failureCount`">")
        
        foreach ($violation in $violations) {
            $ruleId = if ($violation.RuleId) { $violation.RuleId } else { 'UnknownRule' }
            $filePath = if ($violation.FilePath) { $violation.FilePath } elseif ($violation.Path) { $violation.Path } else { 'UnknownFile' }
            $lineNumber = if ($violation.LineNumber) { $violation.LineNumber } else { 0 }
            $message = if ($violation.Message) { $violation.Message } else { 'No message' }
            $severity = if ($violation.Severity) { $violation.Severity } else { 'Medium' }
            
            # Escape XML entities
            $message = $message -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&apos;'
            $filePath = $filePath -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&apos;'
            
            $testName = "${filePath}:${lineNumber}"
            
            [void]$xml.Append("    <testcase classname=`"$ruleId`" name=`"$testName`"")
            
            if ($severity -in @('Critical', 'High')) {
                [void]$xml.AppendLine(">")
                [void]$xml.AppendLine("      <failure message=`"$message`" type=`"$severity`"/>")
                [void]$xml.AppendLine("    </testcase>")
            } else {
                [void]$xml.AppendLine(" />")
            }
        }
        
        [void]$xml.AppendLine("  </testsuite>")
        [void]$xml.AppendLine("</testsuites>")
        
        # Write output file
        $xml.ToString() | Out-File -FilePath $OutputFile -Encoding UTF8
        
        Write-Verbose "Successfully converted to JUnit XML: $OutputFile"
        Write-Verbose "Total tests: $totalCount, Failures: $failureCount"
        
    } catch {
        Write-Error "Failed to convert to JUnit XML: $_"
        throw
    }
}

# Export function
Export-ModuleMember -Function Convert-ToJUnit

# Allow direct script execution
if ($MyInvocation.InvocationName -ne '.' -and -not $MyInvocation.Line) {
    # Script is being run directly, not dot-sourced or as module
    if ($args.Count -ge 2) {
        Convert-ToJUnit -InputFile $args[0] -OutputFile $args[1]
    } else {
        Write-Host "Usage: Convert-ToJUnit.ps1 <input-file> <output-file>"
        Write-Host "Example: Convert-ToJUnit.ps1 analysis.json results.junit.xml"
    }
}
