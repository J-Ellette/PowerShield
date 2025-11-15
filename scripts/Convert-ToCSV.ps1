#Requires -Version 7.0

<#
.SYNOPSIS
    Convert PowerShield analysis results to CSV format
.DESCRIPTION
    Converts PowerShield JSON analysis results to CSV format for reporting and analysis
.PARAMETER InputFile
    Path to PowerShield JSON results file
.PARAMETER OutputFile
    Path to output CSV file
.PARAMETER Delimiter
    CSV delimiter character (default: comma)
.EXAMPLE
    Convert-ToCSV -InputFile 'analysis.json' -OutputFile 'results.csv'
.EXAMPLE
    Convert-ToCSV -InputFile 'analysis.json' -OutputFile 'results.tsv' -Delimiter "`t"
#>

function Convert-ToCSV {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputFile,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputFile,
        
        [Parameter(Mandatory = $false)]
        [string]$Delimiter = ','
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
        
        # Convert violations to CSV-friendly objects
        $csvData = $violations | ForEach-Object {
            [PSCustomObject]@{
                RuleId = if ($_.RuleId) { $_.RuleId } else { '' }
                Severity = if ($_.Severity) { $_.Severity } else { '' }
                File = if ($_.FilePath) { $_.FilePath } elseif ($_.Path) { $_.Path } else { '' }
                Line = if ($_.LineNumber) { $_.LineNumber } else { 0 }
                Column = if ($_.Column) { $_.Column } else { 0 }
                Message = if ($_.Message) { $_.Message -replace "`n", ' ' -replace "`r", '' } else { '' }
                Recommendation = if ($_.Recommendation) { $_.Recommendation -replace "`n", ' ' -replace "`r", '' } else { '' }
                CWE = if ($_.CWE) { $_.CWE } else { '' }
            }
        }
        
        # Export to CSV
        if ($csvData.Count -gt 0) {
            $csvData | Export-Csv -Path $OutputFile -NoTypeInformation -Delimiter $Delimiter -Encoding UTF8
            Write-Verbose "Successfully converted to CSV: $OutputFile"
            Write-Verbose "Total violations: $($csvData.Count)"
        } else {
            # Create empty CSV with headers
            [PSCustomObject]@{
                RuleId = ''
                Severity = ''
                File = ''
                Line = 0
                Column = 0
                Message = ''
                Recommendation = ''
                CWE = ''
            } | Export-Csv -Path $OutputFile -NoTypeInformation -Delimiter $Delimiter -Encoding UTF8
            Write-Verbose "No violations found, created empty CSV with headers"
        }
        
    } catch {
        Write-Error "Failed to convert to CSV: $_"
        throw
    }
}

# Export function
Export-ModuleMember -Function Convert-ToCSV

# Allow direct script execution
if ($MyInvocation.InvocationName -ne '.' -and -not $MyInvocation.Line) {
    # Script is being run directly, not dot-sourced or as module
    if ($args.Count -ge 2) {
        $delimiter = if ($args.Count -ge 3) { $args[2] } else { ',' }
        Convert-ToCSV -InputFile $args[0] -OutputFile $args[1] -Delimiter $delimiter
    } else {
        Write-Host "Usage: Convert-ToCSV.ps1 <input-file> <output-file> [delimiter]"
        Write-Host "Example: Convert-ToCSV.ps1 analysis.json results.csv"
        Write-Host "Example: Convert-ToCSV.ps1 analysis.json results.tsv `"`t`""
    }
}
