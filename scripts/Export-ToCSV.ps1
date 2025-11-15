#Requires -Version 7.0

<#
.SYNOPSIS
    Export PowerShield analysis results to CSV/TSV format
.DESCRIPTION
    Converts PowerShield analysis results to CSV or TSV format for reporting and metrics.
    Useful for importing into spreadsheets, databases, or reporting tools.
.PARAMETER InputFile
    Path to PowerShield results JSON file
.PARAMETER OutputFile
    Path to output CSV/TSV file
.PARAMETER Delimiter
    Delimiter to use (comma or tab)
.EXAMPLE
    Export-ToCSV -InputFile results.json -OutputFile results.csv
.EXAMPLE
    Export-ToCSV -InputFile results.json -OutputFile results.tsv -Delimiter Tab
.NOTES
    Version: 1.0.0
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InputFile,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputFile,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Comma', 'Tab')]
    [string]$Delimiter = 'Comma'
)

function Convert-ToCSV {
    param(
        [Parameter(Mandatory = $true)]
        $Results,
        
        [Parameter(Mandatory = $true)]
        [string]$DelimiterChar
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
    
    # Build CSV/TSV output
    $csvData = @()
    
    # Add header row
    $csvData += [PSCustomObject]@{
        RuleId = 'RuleId'
        Severity = 'Severity'
        File = 'File'
        Line = 'Line'
        Column = 'Column'
        Message = 'Message'
        Code = 'Code'
        CWE = 'CWE'
        MitreAttack = 'MitreAttack'
        Remediation = 'Remediation'
        Suppressed = 'Suppressed'
    }
    
    foreach ($violation in $allViolations) {
        # Sanitize values for CSV (escape quotes, remove newlines)
        $sanitize = {
            param($value)
            if ($null -eq $value) { return '' }
            $str = $value.ToString()
            # Replace newlines with space
            $str = $str -replace '[\r\n]+', ' '
            # Escape quotes
            $str = $str -replace '"', '""'
            return $str
        }
        
        $csvData += [PSCustomObject]@{
            RuleId = & $sanitize $violation.RuleId
            Severity = & $sanitize $violation.Severity
            File = & $sanitize $violation.FilePath
            Line = if ($violation.LineNumber) { $violation.LineNumber } else { '' }
            Column = if ($violation.Column) { $violation.Column } else { '' }
            Message = & $sanitize $violation.Message
            Code = & $sanitize $violation.Code
            CWE = & $sanitize $violation.CWE
            MitreAttack = if ($violation.MitreAttack) { ($violation.MitreAttack -join '; ') } else { '' }
            Remediation = & $sanitize $violation.Remediation
            Suppressed = if ($violation.Suppressed) { 'Yes' } else { 'No' }
        }
    }
    
    # Convert to CSV/TSV
    if ($csvData.Count -gt 1) {
        # Skip header object and export with custom delimiter
        $output = $csvData | ConvertTo-Csv -NoTypeInformation -Delimiter $DelimiterChar
        return $output -join "`n"
    } else {
        # No violations - just return header
        $header = "RuleId${DelimiterChar}Severity${DelimiterChar}File${DelimiterChar}Line${DelimiterChar}Column${DelimiterChar}Message${DelimiterChar}Code${DelimiterChar}CWE${DelimiterChar}MitreAttack${DelimiterChar}Remediation${DelimiterChar}Suppressed"
        return $header
    }
}

# Main execution
try {
    # Validate input file
    if (-not (Test-Path $InputFile)) {
        throw "Input file not found: $InputFile"
    }
    
    # Load results
    $results = Get-Content $InputFile -Raw | ConvertFrom-Json
    
    # Determine delimiter character
    $delimiterChar = switch ($Delimiter) {
        'Comma' { ',' }
        'Tab' { "`t" }
        default { ',' }
    }
    
    # Convert to CSV/TSV
    $csvContent = Convert-ToCSV -Results $results -DelimiterChar $delimiterChar
    
    # Save to file
    $csvContent | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline
    
    $format = if ($Delimiter -eq 'Tab') { 'TSV' } else { 'CSV' }
    Write-Host "✓ $format format exported to: $OutputFile" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to export CSV/TSV format: $_"
    exit 1
}
