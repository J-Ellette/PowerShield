#Requires -Version 7.0

<#
.SYNOPSIS
    Convert PowerShield analysis results to TAP (Test Anything Protocol) format
.DESCRIPTION
    Converts PowerShield JSON analysis results to TAP format for CI/CD integration
.PARAMETER InputFile
    Path to PowerShield JSON results file
.PARAMETER OutputFile
    Path to output TAP file
.EXAMPLE
    Convert-ToTAP -InputFile 'analysis.json' -OutputFile 'results.tap'
#>

function Convert-ToTAP {
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
        
        $totalCount = $violations.Count
        
        # Build TAP output
        $tap = [System.Text.StringBuilder]::new()
        
        # TAP header
        [void]$tap.AppendLine("1..$totalCount")
        
        $testNum = 0
        foreach ($violation in $violations) {
            $testNum++
            
            $ruleId = if ($violation.RuleId) { $violation.RuleId } else { 'UnknownRule' }
            $filePath = if ($violation.FilePath) { $violation.FilePath } elseif ($violation.Path) { $violation.Path } else { 'UnknownFile' }
            $lineNumber = if ($violation.LineNumber) { $violation.LineNumber } else { 0 }
            $message = if ($violation.Message) { $violation.Message } else { 'No message' }
            $severity = if ($violation.Severity) { $violation.Severity } else { 'Medium' }
            
            # Determine if test passed or failed
            $status = if ($severity -in @('Critical', 'High')) { 'not ok' } else { 'ok' }
            
            # Test line
            $testLine = "$status $testNum - $ruleId at ${filePath}:${lineNumber}"
            [void]$tap.AppendLine($testLine)
            
            # Diagnostics (only for failures)
            if ($status -eq 'not ok') {
                [void]$tap.AppendLine("  ---")
                [void]$tap.AppendLine("  severity: $severity")
                [void]$tap.AppendLine("  message: $message")
                [void]$tap.AppendLine("  file: $filePath")
                [void]$tap.AppendLine("  line: $lineNumber")
                [void]$tap.AppendLine("  ...")
            }
        }
        
        # Write output file
        $tap.ToString() | Out-File -FilePath $OutputFile -Encoding UTF8
        
        Write-Verbose "Successfully converted to TAP format: $OutputFile"
        Write-Verbose "Total tests: $totalCount"
        
    } catch {
        Write-Error "Failed to convert to TAP format: $_"
        throw
    }
}

# Export function
Export-ModuleMember -Function Convert-ToTAP

# Allow direct script execution
if ($MyInvocation.InvocationName -ne '.' -and -not $MyInvocation.Line) {
    # Script is being run directly, not dot-sourced or as module
    if ($args.Count -ge 2) {
        Convert-ToTAP -InputFile $args[0] -OutputFile $args[1]
    } else {
        Write-Host "Usage: Convert-ToTAP.ps1 <input-file> <output-file>"
        Write-Host "Example: Convert-ToTAP.ps1 analysis.json results.tap"
    }
}
