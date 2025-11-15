#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    PowerShield CLI - Comprehensive PowerShell Security Platform Command Line Interface
.DESCRIPTION
    Comprehensive command-line interface for PowerShield security analysis,
    configuration management, baseline tracking, and fix management.
.NOTES
    Version: 1.6.0
    Author: PowerShield Project
.EXAMPLE
    psts analyze ./scripts
    psts analyze --format sarif --output results.sarif
    psts baseline create
    psts fix preview
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $false)]
    [ValidateSet('analyze', 'config', 'baseline', 'fix', 'rule', 'compliance', 'install-hooks', 'version', 'help', 'interactive')]
    [string]$Command,
    
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

# Script directory
$scriptRoot = $PSScriptRoot

# Color helper functions
function Write-Success { param([string]$Message) Write-Host "✓ $Message" -ForegroundColor Green }
function Write-Info { param([string]$Message) Write-Host "ℹ $Message" -ForegroundColor Cyan }
function Write-Warning { param([string]$Message) Write-Host "⚠ $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "✗ $Message" -ForegroundColor Red }
function Write-Header { param([string]$Message) Write-Host "`n$Message" -ForegroundColor Cyan }

# Import modules
try {
    # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Controlled path within repository
    Import-Module "$scriptRoot/src/PowerShellSecurityAnalyzer.psm1" -Force -ErrorAction Stop
    # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Controlled path within repository
    Import-Module "$scriptRoot/src/ConfigLoader.psm1" -Force -ErrorAction Stop
    # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Controlled path within repository
    Import-Module "$scriptRoot/src/BaselineManager.psm1" -Force -ErrorAction Stop
    # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Controlled path within repository
    Import-Module "$scriptRoot/src/ComplianceReporter.psm1" -Force -ErrorAction Stop
} catch {
    Write-Error "Failed to load PowerShield modules: $_"
    exit 1
}

#region Command Functions

function Invoke-Analyze {
    <#
    .SYNOPSIS
        Analyze PowerShell scripts for security violations
    .PARAMETER Path
        Path to file or directory to analyze (default: current directory)
    .PARAMETER Format
        Output format: json, sarif, markdown, text, junit, tap, csv (default: text)
    .PARAMETER Output
        Output file path for results
    .PARAMETER Baseline
        Compare against baseline file
    .PARAMETER EnableSuppressions
        Enable suppression comment processing
    .PARAMETER PerformanceProfile
        Performance profile: fast, balanced, thorough (default: balanced)
    .PARAMETER UseReportsDirectory
        Generate all artifacts in .powershield-reports/ directory
    .PARAMETER Incremental
        Only analyze changed files (requires git repository)
    #>
    param(
        [string]$Path = ".",
        [ValidateSet('json', 'sarif', 'markdown', 'text', 'junit', 'tap', 'csv')]
        [string]$Format = 'text',
        [string]$Output,
        [string]$Baseline,
        [switch]$EnableSuppressions,
        [ValidateSet('fast', 'balanced', 'thorough')]
        [string]$PerformanceProfile = 'balanced',
        [switch]$UseReportsDirectory,
        [switch]$Incremental
    )
    
    $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
    if (-not $targetPath) {
        Write-Error "Path not found: $Path"
        exit 1
    }
    
    Write-Info "Analyzing: $targetPath"
    
    # Load configuration
    try {
        $config = Import-PowerShieldConfiguration -WorkspacePath $scriptRoot
    } catch {
        Write-Warning "No configuration found, using defaults"
        $config = $null
    }
    
    # Set up performance profile
    if ($PerformanceProfile -ne 'balanced') {
        Write-Info "Using performance profile: $PerformanceProfile"
        # Note: Profile filtering would be integrated into the analyzer in production
    }
    
    # Check for incremental analysis
    $filesToAnalyze = $null
    if ($Incremental) {
        Write-Info "Incremental mode: detecting changed files..."
        try {
            # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Safe: $scriptRoot is $PSScriptRoot (line 31), controlled within repo
            Import-Module "$scriptRoot/src/CIAdapter.psm1" -Force -ErrorAction Stop
            $adapter = New-CIAdapter
            $changedFiles = $adapter.DiscoverChangedFiles($targetPath)
            
            if ($changedFiles.Count -eq 0) {
                Write-Success "No PowerShell files changed - skipping analysis"
                exit 0
            }
            
            Write-Info "Found $($changedFiles.Count) changed file(s)"
            $filesToAnalyze = $changedFiles
        } catch {
            Write-Warning "Could not detect changed files: $_"
            Write-Warning "Falling back to full analysis"
        }
    }
    
    # Analyze
    if ($filesToAnalyze) {
        # Analyze specific files
        $results = @()
        foreach ($file in $filesToAnalyze) {
            $fileResult = Invoke-SecurityAnalysis -ScriptPath $file -EnableSuppressions:$EnableSuppressions
            $results += $fileResult
        }
        
        $result = @{
            Results = $results
            Summary = @{
                TotalCritical = 0
                TotalHigh = 0
                TotalMedium = 0
                TotalLow = 0
            }
            TotalViolations = 0
            TotalFiles = $results.Count
        }
        
        # Calculate summary
        foreach ($fileResult in $results) {
            if ($fileResult.Violations) {
                $result.Summary.TotalCritical += ($fileResult.Violations | Where-Object { $_.Severity -eq 'Critical' }).Count
                $result.Summary.TotalHigh += ($fileResult.Violations | Where-Object { $_.Severity -eq 'High' }).Count
                $result.Summary.TotalMedium += ($fileResult.Violations | Where-Object { $_.Severity -eq 'Medium' }).Count
                $result.Summary.TotalLow += ($fileResult.Violations | Where-Object { $_.Severity -eq 'Low' }).Count
                $result.TotalViolations += $fileResult.Violations.Count
            }
        }
    } elseif (Test-Path $targetPath -PathType Container) {
        $result = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath -EnableSuppressions:$EnableSuppressions
    } else {
        $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath -EnableSuppressions:$EnableSuppressions
        $result = @{
            Results = @($singleResult)
            Summary = @{
                TotalCritical = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Critical' }).Count
                TotalHigh = ($singleResult.Violations | Where-Object { $_.Severity -eq 'High' }).Count
                TotalMedium = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Medium' }).Count
                TotalLow = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Low' }).Count
            }
            TotalViolations = $singleResult.Violations.Count
            TotalFiles = 1
        }
    }
    
    # Handle baseline comparison if requested
    if ($Baseline) {
        if (-not (Test-Path $Baseline)) {
            Write-Error "Baseline file not found: $Baseline"
            exit 1
        }
        
        $baselineData = Get-Content $Baseline -Raw | ConvertFrom-Json
        $result = Compare-WithBaseline -CurrentResult $result -BaselineResult $baselineData
    }
    
    # Generate all artifacts if using reports directory
    if ($UseReportsDirectory) {
        Write-Info "Generating artifacts in .powershield-reports/"
        try {
            # Determine workspace path (directory containing analysis target)
            $workspacePath = if (Test-Path $targetPath -PathType Container) {
                $targetPath
            } else {
                Split-Path $targetPath -Parent
            }
            
            # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Safe: $scriptRoot is $PSScriptRoot (line 31), controlled within repo
            Import-Module "$scriptRoot/src/ArtifactManager.psm1" -Force -ErrorAction Stop
            $artifacts = New-ArtifactReport -WorkspacePath $workspacePath -AnalysisResult $result -Config $config
            
            Write-Success "Artifacts generated:"
            foreach ($key in $artifacts.Keys) {
                $relativePath = $artifacts[$key] -replace [regex]::Escape($workspacePath), '.'
                Write-Host "  - $key`: $relativePath" -ForegroundColor Gray
            }
            
            # Display results
            Show-AnalysisResults -Result $result
            
            # Exit with appropriate code
            Test-CIGateAndExit -Result $result -Config $config
        } catch {
            Write-Error "Failed to generate artifacts: $_"
            Write-Error $_.ScriptStackTrace
            exit 1
        }
    } else {
        # Display results
        if ($Format -eq 'text') {
            Show-AnalysisResults -Result $result
        }
        
        # Export results if requested
        if ($Output) {
            Export-AnalysisResults -Result $result -Format $Format -OutputFile $Output
        }
        
        # Exit with appropriate code
        Test-CIGateAndExit -Result $result -Config $config
    }
}

function Show-AnalysisResults {
    param($Result)
    
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "PowerShield Security Analysis Results" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    
    Write-Host "`nFiles Analyzed: $($Result.TotalFiles)" -ForegroundColor White
    Write-Host "Total Violations: $($Result.TotalViolations)" -ForegroundColor White
    
    if ($Result.Summary) {
        Write-Host "`nSeverity Breakdown:" -ForegroundColor White
        foreach ($severity in @('Critical', 'High', 'Medium', 'Low')) {
            $count = $Result.Summary["Total$severity"]
            if ($count -gt 0) {
                $color = switch ($severity) {
                    'Critical' { 'Red' }
                    'High' { 'Red' }
                    'Medium' { 'Yellow' }
                    'Low' { 'Gray' }
                }
                Write-Host "  $severity`: $count" -ForegroundColor $color
            }
        }
    }
    
    # Show violations
    if ($Result.TotalViolations -gt 0) {
        $allViolations = @()
        foreach ($fileResult in $Result.Results) {
            if ($fileResult.Violations) {
                $allViolations += $fileResult.Violations
            }
        }
        
        $topViolations = $allViolations | Sort-Object -Property Severity -Descending | Select-Object -First 10
        
        Write-Host "`nTop Issues:" -ForegroundColor White
        foreach ($violation in $topViolations) {
            $severityColor = switch ($violation.Severity) {
                'Critical' { 'Red' }
                'High' { 'Red' }
                'Medium' { 'Yellow' }
                'Low' { 'Gray' }
                default { 'White' }
            }
            
            Write-Host "`n  [$($violation.Severity)] $($violation.FilePath):$($violation.LineNumber)" -ForegroundColor $severityColor
            Write-Host "    $($violation.RuleId): $($violation.Message)" -ForegroundColor Gray
            if ($violation.Code) {
                Write-Host "    Code: $($violation.Code)" -ForegroundColor DarkGray
            }
        }
        
        if ($allViolations.Count -gt 10) {
            Write-Host "`n  ... and $($allViolations.Count - 10) more violations" -ForegroundColor Gray
        }
    } else {
        Write-Success "`nNo security violations found!"
    }
    
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
}

function Export-AnalysisResults {
    param(
        $Result,
        [string]$Format,
        [string]$OutputFile
    )
    
    # Create temp JSON file for converters
    # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Legitimate temporary file usage for format conversion (2026-12-31)
    $jsonTemp = (New-TemporaryFile).FullName
    $Result | ConvertTo-Json -Depth 10 | Out-File $jsonTemp
    
    try {
        switch ($Format) {
            'json' {
                $Result | ConvertTo-Json -Depth 10 | Out-File $OutputFile
                Write-Success "Results exported to: $OutputFile"
            }
            'sarif' {
                # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Controlled path within repository
                . "$scriptRoot/scripts/Convert-ToSARIF.ps1"
                Convert-ToSARIF -InputFile $jsonTemp -OutputFile $OutputFile
                Write-Success "SARIF results exported to: $OutputFile"
            }
            'markdown' {
                # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Controlled path within repository
                . "$scriptRoot/scripts/Generate-SecurityReport.ps1"
                Generate-SecurityReport -InputFile $jsonTemp -OutputFile $OutputFile
                Write-Success "Markdown report exported to: $OutputFile"
            }
            'junit' {
                # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Controlled path within repository
                & "$scriptRoot/scripts/Export-ToJUnit.ps1" -InputFile $jsonTemp -OutputFile $OutputFile
                Write-Success "JUnit XML exported to: $OutputFile"
            }
            'tap' {
                # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Controlled path within repository
                & "$scriptRoot/scripts/Export-ToTAP.ps1" -InputFile $jsonTemp -OutputFile $OutputFile
                Write-Success "TAP format exported to: $OutputFile"
            }
            'csv' {
                # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Controlled path within repository
                & "$scriptRoot/scripts/Export-ToCSV.ps1" -InputFile $jsonTemp -OutputFile $OutputFile
                Write-Success "CSV format exported to: $OutputFile"
            }
        }
    } finally {
        if (Test-Path $jsonTemp) {
            Remove-Item $jsonTemp -Force
        }
    }
}

function Test-CIGateAndExit {
    param($Result, $Config)
    
    if ($Config -and $Config.CI -and $Config.CI.fail_on) {
        $shouldFail = $false
        foreach ($severity in $Config.CI.fail_on) {
            $count = $Result.Summary["Total$severity"]
            if ($count -gt 0) {
                $shouldFail = $true
                break
            }
        }
        if ($shouldFail) {
            Write-Error "Analysis failed due to violations matching fail_on criteria"
            exit 1
        }
    }
    
    exit 0
}

function Compare-WithBaseline {
    param($CurrentResult, $BaselineResult)
    
    Write-Info "Comparing with baseline..."
    
    # Extract all violations from current result
    $currentViolations = @()
    foreach ($fileResult in $CurrentResult.Results) {
        if ($fileResult.Violations) {
            $currentViolations += $fileResult.Violations
        }
    }
    
    # Extract baseline violations
    $baselineViolations = @()
    if ($BaselineResult.Results) {
        foreach ($fileResult in $BaselineResult.Results) {
            if ($fileResult.Violations) {
                $baselineViolations += $fileResult.Violations
            }
        }
    } elseif ($BaselineResult.violations) {
        $baselineViolations = $BaselineResult.violations
    }
    
    # Find new violations
    $newViolations = @()
    foreach ($current in $currentViolations) {
        $found = $false
        foreach ($baseline in $baselineViolations) {
            if ($current.RuleId -eq $baseline.RuleId -and 
                $current.FilePath -eq $baseline.FilePath -and 
                $current.LineNumber -eq $baseline.LineNumber) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            $newViolations += $current
        }
    }
    
    # Find fixed violations
    $fixedViolations = @()
    foreach ($baseline in $baselineViolations) {
        $found = $false
        foreach ($current in $currentViolations) {
            if ($baseline.RuleId -eq $current.RuleId -and 
                $baseline.FilePath -eq $current.FilePath -and 
                $baseline.LineNumber -eq $current.LineNumber) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            $fixedViolations += $baseline
        }
    }
    
    # Add comparison info
    $CurrentResult.BaselineComparison = @{
        NewViolations = $newViolations
        FixedViolations = $fixedViolations
        TotalNew = $newViolations.Count
        TotalFixed = $fixedViolations.Count
    }
    
    Write-Info "New violations: $($newViolations.Count)"
    Write-Info "Fixed violations: $($fixedViolations.Count)"
    
    return $CurrentResult
}

function Invoke-Config {
    <#
    .SYNOPSIS
        Configuration management commands
    .PARAMETER SubCommand
        validate - Validate configuration file
        init - Create default configuration
        show - Display current configuration
    #>
    param([string]$SubCommand)
    
    switch ($SubCommand) {
        'validate' {
            Write-Info "Validating PowerShield configuration..."
            try {
                $config = Import-PowerShieldConfiguration -WorkspacePath $scriptRoot
                Write-Success "Configuration is valid"
                Write-Host "`nConfiguration Summary:"
                Write-Host "  Version: $($config.Version)"
                Write-Host "  Severity Threshold: $($config.Analysis.severity_threshold)"
                Write-Host "  Parallel Analysis: $($config.Analysis.parallel_analysis)"
                Write-Host "  Auto-Fix Enabled: $($config.AutoFix.enabled)"
                if ($config.Hooks) {
                    Write-Host "  Hooks Enabled: $($config.Hooks.enabled)"
                }
            } catch {
                Write-Error "Configuration validation failed: $_"
                exit 1
            }
        }
        'show' {
            try {
                $config = Import-PowerShieldConfiguration -WorkspacePath $scriptRoot
                $config | ConvertTo-Json -Depth 10
            } catch {
                Write-Error "Failed to load configuration: $_"
                exit 1
            }
        }
        'init' {
            $configPath = Join-Path (Get-Location) ".powershield.yml"
            if (Test-Path $configPath) {
                Write-Warning "Configuration already exists: $configPath"
                $response = Read-Host "Overwrite? (y/N)"
                if ($response -ne 'y' -and $response -ne 'Y') {
                    exit 0
                }
            }
            
            $examplePath = Join-Path $scriptRoot ".powershield.yml.example"
            if (Test-Path $examplePath) {
                Copy-Item $examplePath $configPath
                Write-Success "Created configuration file: $configPath"
                Write-Info "Edit this file to customize PowerShield behavior"
            } else {
                Write-Error "Example configuration not found"
                exit 1
            }
        }
        default {
            Write-Error "Unknown config subcommand: $SubCommand"
            Write-Info "Available subcommands: validate, show, init"
            exit 1
        }
    }
}

function Invoke-Baseline {
    <#
    .SYNOPSIS
        Baseline management commands
    .PARAMETER SubCommand
        create - Create baseline from current analysis
        compare - Compare current state with baseline
        list - List all baseline versions
        delete - Delete a baseline file
        export - Export baseline comparison report
        share - Prepare baseline for team sharing
    #>
    param(
        [string]$SubCommand,
        [string]$Path = ".",
        [string]$Output,
        [string]$Description = "",
        [string]$Format = "markdown",
        [string]$TeamName = "Default"
    )
    
    switch ($SubCommand) {
        'create' {
            Write-Info "Creating baseline from current analysis..."
            
            $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (-not $targetPath) {
                Write-Error "Path not found: $Path"
                exit 1
            }
            
            # Perform analysis
            if (Test-Path $targetPath -PathType Container) {
                $result = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
            } else {
                $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                $result = @{
                    Results = @($singleResult)
                    Summary = @{
                        TotalCritical = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Critical' }).Count
                        TotalHigh = ($singleResult.Violations | Where-Object { $_.Severity -eq 'High' }).Count
                        TotalMedium = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Medium' }).Count
                        TotalLow = ($singleResult.Violations | Where-Object { $_.Severity -eq 'Low' }).Count
                    }
                    TotalViolations = $singleResult.Violations.Count
                    TotalFiles = 1
                }
            }
            
            # Determine output file
            $baselineFile = if ($Output) { $Output } else { ".powershield-baseline.json" }
            
            # Create baseline using new module
            $baseline = New-BaselineVersion -AnalysisResult $result -Description $Description -OutputPath $baselineFile
            
            Write-Success "Baseline created: $baselineFile"
            Write-Info "Files analyzed: $($result.TotalFiles)"
            Write-Info "Total violations: $($baseline.TotalViolations)"
            Write-Info "Created by: $($baseline.CreatedBy)"
            if ($baseline.GitCommit) {
                Write-Info "Git commit: $($baseline.GitCommit)"
            }
        }
        'compare' {
            Write-Info "Comparing current state with baseline..."
            
            # Find baseline file
            $baselineFile = if ($Output) { $Output } else { ".powershield-baseline.json" }
            if (-not (Test-Path $baselineFile)) {
                Write-Error "Baseline file not found: $baselineFile"
                Write-Info "Create a baseline first with: psts baseline create"
                exit 1
            }
            
            $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (-not $targetPath) {
                Write-Error "Path not found: $Path"
                exit 1
            }
            
            # Perform current analysis
            if (Test-Path $targetPath -PathType Container) {
                $currentResult = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
            } else {
                $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                $currentResult = @{
                    Results = @($singleResult)
                    TotalViolations = $singleResult.Violations.Count
                    TotalFiles = 1
                }
            }
            
            # Compare using new module
            $comparison = Compare-Baseline -CurrentResult $currentResult -BaselinePath $baselineFile
            
            # Display comparison results
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host "Baseline Comparison Results" -ForegroundColor Cyan
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            
            Write-Host "`nBaseline Date: $($comparison.Summary.BaselineDate)" -ForegroundColor Gray
            Write-Host "Baseline Violations: $($comparison.Summary.BaselineViolations)" -ForegroundColor White
            Write-Host "Current Violations: $($comparison.Summary.CurrentViolations)" -ForegroundColor White
            Write-Host "Change: $($comparison.Summary.ChangePercentage)%" -ForegroundColor White
            
            if ($comparison.TotalFixed -gt 0) {
                Write-Host "`n✓ Fixed Issues: $($comparison.TotalFixed)" -ForegroundColor Green
            }
            
            if ($comparison.TotalNew -gt 0) {
                Write-Host "✗ New Issues: $($comparison.TotalNew)" -ForegroundColor Red
                
                Write-Host "`nNew Violations:" -ForegroundColor White
                foreach ($violation in $comparison.NewViolations | Select-Object -First 10) {
                    $severityColor = switch ($violation.Severity) {
                        'Critical' { 'Red' }
                        'High' { 'Red' }
                        'Medium' { 'Yellow' }
                        'Low' { 'Gray' }
                        default { 'White' }
                    }
                    Write-Host "  [$($violation.Severity)] $($violation.FilePath):$($violation.LineNumber)" -ForegroundColor $severityColor
                    Write-Host "    $($violation.RuleId): $($violation.Message)" -ForegroundColor Gray
                }
                
                if ($comparison.TotalNew -gt 10) {
                    Write-Host "  ... and $($comparison.TotalNew - 10) more new violations" -ForegroundColor Gray
                }
            } else {
                Write-Success "`nNo new violations found!"
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            
            # Exit with error if new violations found
            if ($comparison.TotalNew -gt 0) {
                exit 1
            }
        }
        'list' {
            Write-Info "Listing baseline versions..."
            
            $baselines = Get-BaselineHistory -Directory $Path
            
            if ($baselines.Count -eq 0) {
                Write-Warning "No baseline files found in $Path"
                exit 0
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host "Baseline Versions" -ForegroundColor Cyan
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            
            foreach ($baseline in $baselines) {
                Write-Host "`n📁 $($baseline.FileName)" -ForegroundColor Cyan
                Write-Host "   Created: $($baseline.CreatedAt)" -ForegroundColor Gray
                Write-Host "   By: $($baseline.CreatedBy)" -ForegroundColor Gray
                Write-Host "   Violations: $($baseline.TotalViolations)" -ForegroundColor White
                if ($baseline.GitCommit) {
                    Write-Host "   Git Commit: $($baseline.GitCommit)" -ForegroundColor Gray
                }
                if ($baseline.Description) {
                    Write-Host "   Description: $($baseline.Description)" -ForegroundColor Gray
                }
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
        }
        'delete' {
            if (-not $Output) {
                Write-Error "Baseline file path required. Use --output <path>"
                exit 1
            }
            
            Remove-Baseline -Path $Output -WhatIf:$false
        }
        'export' {
            Write-Info "Exporting baseline comparison report..."
            
            # Find baseline file
            $baselineFile = if ($Output) { $Output } else { ".powershield-baseline.json" }
            if (-not (Test-Path $baselineFile)) {
                Write-Error "Baseline file not found: $baselineFile"
                exit 1
            }
            
            # Perform current analysis
            $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (Test-Path $targetPath -PathType Container) {
                $currentResult = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
            } else {
                $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                $currentResult = @{
                    Results = @($singleResult)
                    TotalViolations = $singleResult.Violations.Count
                    TotalFiles = 1
                }
            }
            
            # Compare
            $comparison = Compare-Baseline -CurrentResult $currentResult -BaselinePath $baselineFile
            
            # Export report
            $reportFile = "baseline-comparison-report.$Format"
            Export-BaselineReport -Comparison $comparison -Format $Format -OutputPath $reportFile
            Write-Success "Baseline comparison report exported to: $reportFile"
        }
        'share' {
            Write-Info "Preparing baseline for team sharing..."
            
            $sourceFile = if ($Output) { $Output } else { ".powershield-baseline.json" }
            if (-not (Test-Path $sourceFile)) {
                Write-Error "Source baseline not found: $sourceFile"
                exit 1
            }
            
            $teamFile = "team-baseline-$TeamName.json"
            Copy-BaselineForTeam -SourcePath $sourceFile -DestinationPath $teamFile -TeamName $TeamName
            
            Write-Info "Share this file with your team to maintain a common baseline"
        }
        default {
            Write-Error "Unknown baseline subcommand: $SubCommand"
            Write-Info "Available subcommands: create, compare, list, delete, export, share"
            exit 1
        }
    }
}

function Invoke-Fix {
    <#
    .SYNOPSIS
        Fix management commands
    .PARAMETER SubCommand
        preview - Preview available fixes without applying
        apply - Apply fixes with confidence threshold
    #>
    param(
        [string]$SubCommand,
        [string]$Path = ".",
        [double]$Confidence = 0.8,
        [string]$ViolationsFile
    )
    
    switch ($SubCommand) {
        'preview' {
            Write-Info "Previewing available fixes..."
            
            # Find or create violations file
            if (-not $ViolationsFile) {
                $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
                if (-not $targetPath) {
                    Write-Error "Path not found: $Path"
                    exit 1
                }
                
                # Perform analysis
                if (Test-Path $targetPath -PathType Container) {
                    $result = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
                } else {
                    $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                    $result = @{
                        Results = @($singleResult)
                    }
                }
                
                # Collect violations
                $allViolations = @()
                foreach ($fileResult in $result.Results) {
                    if ($fileResult.Violations) {
                        $allViolations += $fileResult.Violations
                    }
                }
            } else {
                if (-not (Test-Path $ViolationsFile)) {
                    Write-Error "Violations file not found: $ViolationsFile"
                    exit 1
                }
                $violationsData = Get-Content $ViolationsFile -Raw | ConvertFrom-Json
                $allViolations = $violationsData.violations
            }
            
            if ($allViolations.Count -eq 0) {
                Write-Success "No violations found that need fixing!"
                exit 0
            }
            
            # Load configuration for auto-fix settings
            try {
                $config = Import-PowerShieldConfiguration -WorkspacePath $scriptRoot
            } catch {
                Write-Warning "No configuration found, using defaults"
                $config = @{
                    AutoFix = @{
                        enabled = $true
                        confidence_threshold = 0.8
                        rule_fixes = @{}
                    }
                }
            }
            
            # Filter fixable violations
            $fixableViolations = @()
            foreach ($violation in $allViolations) {
                # Check if fixes are enabled for this rule
                $ruleFixEnabled = $true
                if ($config.AutoFix.rule_fixes -and $config.AutoFix.rule_fixes.ContainsKey($violation.RuleId)) {
                    $ruleFixEnabled = $config.AutoFix.rule_fixes[$violation.RuleId]
                }
                
                if ($ruleFixEnabled) {
                    $fixableViolations += $violation
                }
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host "Fix Preview" -ForegroundColor Cyan
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            
            Write-Host "`nTotal Violations: $($allViolations.Count)" -ForegroundColor White
            Write-Host "Fixable Violations: $($fixableViolations.Count)" -ForegroundColor White
            Write-Host "Confidence Threshold: $Confidence" -ForegroundColor White
            
            if ($fixableViolations.Count -gt 0) {
                Write-Host "`nFixable Issues:" -ForegroundColor White
                
                $grouped = $fixableViolations | Group-Object RuleId
                foreach ($group in $grouped) {
                    Write-Host "`n  Rule: $($group.Name)" -ForegroundColor Cyan
                    Write-Host "  Count: $($group.Count)" -ForegroundColor White
                    
                    foreach ($violation in $group.Group | Select-Object -First 3) {
                        Write-Host "    • $($violation.FilePath):$($violation.LineNumber)" -ForegroundColor Gray
                    }
                    
                    if ($group.Count -gt 3) {
                        Write-Host "    ... and $($group.Count - 3) more" -ForegroundColor DarkGray
                    }
                }
                
                Write-Host "`n💡 To apply fixes, run:" -ForegroundColor Yellow
                Write-Host "   psts fix apply --confidence $Confidence" -ForegroundColor White
            } else {
                Write-Info "No fixable violations found (check auto-fix configuration)"
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
        }
        'apply' {
            Write-Info "Applying fixes with confidence threshold: $Confidence"
            Write-Warning "Note: This feature requires the PowerShield auto-fix action to be configured"
            Write-Info "For manual fix application, use the GitHub Actions workflow or run:"
            Write-Info "  pwsh -File actions/copilot-autofix/apply-fixes.ps1"
            
            # This would typically be handled by the GitHub Action
            # For local use, we provide instructions
            Write-Host "`nTo apply fixes locally:" -ForegroundColor Cyan
            Write-Host "1. Ensure violations file exists (run psts analyze first)" -ForegroundColor White
            Write-Host "2. Configure AI provider in .powershield.yml" -ForegroundColor White
            Write-Host "3. Run the auto-fix action through GitHub Actions workflow" -ForegroundColor White
        }
        default {
            Write-Error "Unknown fix subcommand: $SubCommand"
            Write-Info "Available subcommands: preview, apply"
            exit 1
        }
    }
}

function Invoke-Compliance {
    <#
    .SYNOPSIS
        Compliance reporting and assessment commands
    .PARAMETER SubCommand
        dashboard - Generate compliance dashboard for all frameworks
        assess - Assess compliance for specific framework
        gap-analysis - Generate gap analysis report
        audit - Export audit evidence package
    .PARAMETER Framework
        Compliance framework: NIST, CIS, OWASP, SOC2, PCI-DSS, HIPAA, All
    .PARAMETER Path
        Path to analyze (default: current directory)
    .PARAMETER Output
        Output file path for reports
    .PARAMETER Format
        Output format: markdown, html, json
    #>
    param(
        [string]$SubCommand,
        [string]$Framework = "All",
        [string]$Path = ".",
        [string]$Output,
        [string]$Format = "markdown"
    )
    
    switch ($SubCommand) {
        'dashboard' {
            Write-Info "Generating compliance dashboard..."
            
            # Perform analysis
            $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (-not $targetPath) {
                Write-Error "Path not found: $Path"
                exit 1
            }
            
            if (Test-Path $targetPath -PathType Container) {
                $result = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
            } else {
                $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                $result = @{
                    Results = @($singleResult)
                    TotalViolations = $singleResult.Violations.Count
                    TotalFiles = 1
                }
            }
            
            # Get compliance status
            $complianceStatus = Get-ComplianceStatus -AnalysisResult $result -Framework $Framework
            
            # Display summary
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host "Compliance Dashboard" -ForegroundColor Cyan
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            
            foreach ($fwName in $complianceStatus.Keys) {
                $fw = $complianceStatus[$fwName]
                $statusColor = if ($fw.CompliancePercentage -ge 90) { 'Green' }
                               elseif ($fw.CompliancePercentage -ge 70) { 'Yellow' }
                               else { 'Red' }
                
                Write-Host "`n$($fw.Framework) - $($fw.Version)" -ForegroundColor Cyan
                Write-Host "  Compliance: $($fw.CompliancePercentage)%" -ForegroundColor $statusColor
                Write-Host "  ✓ Compliant: $($fw.CompliantControls)/$($fw.TotalControls)" -ForegroundColor Green
                Write-Host "  ⚠ Partially: $($fw.PartiallyCompliantControls)" -ForegroundColor Yellow
                Write-Host "  ✗ Non-Compliant: $($fw.NonCompliantControls)" -ForegroundColor Red
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            
            # Export if output specified
            if ($Output) {
                Export-ComplianceDashboard -ComplianceStatus $complianceStatus -OutputPath $Output -Format $Format
            }
        }
        'assess' {
            Write-Info "Assessing compliance with $Framework..."
            
            # Perform analysis
            $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (-not $targetPath) {
                Write-Error "Path not found: $Path"
                exit 1
            }
            
            if (Test-Path $targetPath -PathType Container) {
                $result = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
            } else {
                $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                $result = @{
                    Results = @($singleResult)
                    TotalViolations = $singleResult.Violations.Count
                    TotalFiles = 1
                }
            }
            
            # Get compliance status for specific framework
            $complianceStatus = Get-ComplianceStatus -AnalysisResult $result -Framework $Framework
            
            # Display detailed results
            foreach ($fwName in $complianceStatus.Keys) {
                $fw = $complianceStatus[$fwName]
                
                Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
                Write-Host "$($fw.Framework) Assessment" -ForegroundColor Cyan
                Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
                
                Write-Host "`nOverall Compliance: $($fw.CompliancePercentage)%" -ForegroundColor White
                
                # Show non-compliant controls
                $nonCompliant = $fw.Controls | Where-Object { $_.Status -eq 'NonCompliant' }
                if ($nonCompliant.Count -gt 0) {
                    Write-Host "`n❌ Non-Compliant Controls:" -ForegroundColor Red
                    foreach ($control in $nonCompliant) {
                        Write-Host "`n  $($control.ControlId): $($control.Category)" -ForegroundColor Red
                        Write-Host "  $($control.Description)" -ForegroundColor Gray
                        Write-Host "  Violations: $($control.ViolationCount)" -ForegroundColor White
                        Write-Host "  Affected Rules: $($control.MappedRules -join ', ')" -ForegroundColor DarkGray
                    }
                }
                
                # Show partially compliant controls
                $partial = $fw.Controls | Where-Object { $_.Status -eq 'PartiallyCompliant' }
                if ($partial.Count -gt 0) {
                    Write-Host "`n⚠️  Partially Compliant Controls:" -ForegroundColor Yellow
                    foreach ($control in $partial) {
                        Write-Host "  $($control.ControlId): $($control.Category) ($($control.ViolationCount) violations)" -ForegroundColor Yellow
                    }
                }
                
                Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            }
            
            # Export if output specified
            if ($Output) {
                $outputFile = if ($Output) { $Output } else { "compliance-assessment-$Framework.$Format" }
                Export-ComplianceDashboard -ComplianceStatus $complianceStatus -OutputPath $outputFile -Format $Format
            }
        }
        'gap-analysis' {
            Write-Info "Generating gap analysis report..."
            
            # Perform analysis
            $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (-not $targetPath) {
                Write-Error "Path not found: $Path"
                exit 1
            }
            
            if (Test-Path $targetPath -PathType Container) {
                $result = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
            } else {
                $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                $result = @{
                    Results = @($singleResult)
                    TotalViolations = $singleResult.Violations.Count
                    TotalFiles = 1
                }
            }
            
            # Get compliance status
            $complianceStatus = Get-ComplianceStatus -AnalysisResult $result -Framework $Framework
            
            # Generate gap analysis
            $outputFile = if ($Output) { $Output } else { "compliance-gap-analysis.md" }
            Export-GapAnalysis -ComplianceStatus $complianceStatus -OutputPath $outputFile
            
            Write-Success "Gap analysis report generated: $outputFile"
        }
        'audit' {
            Write-Info "Generating audit evidence package..."
            
            # Perform analysis
            $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (-not $targetPath) {
                Write-Error "Path not found: $Path"
                exit 1
            }
            
            if (Test-Path $targetPath -PathType Container) {
                $result = Invoke-WorkspaceAnalysis -WorkspacePath $targetPath
            } else {
                $singleResult = Invoke-SecurityAnalysis -ScriptPath $targetPath
                $result = @{
                    Results = @($singleResult)
                    TotalViolations = $singleResult.Violations.Count
                    TotalFiles = 1
                }
            }
            
            # Get compliance status
            $complianceStatus = Get-ComplianceStatus -AnalysisResult $result -Framework "All"
            
            # Export audit evidence
            $outputFile = if ($Output) { $Output } else { "audit-evidence-$(Get-Date -Format 'yyyyMMdd-HHmmss').json" }
            Export-AuditEvidence -AnalysisResult $result -ComplianceStatus $complianceStatus -OutputPath $outputFile
            
            Write-Success "Audit evidence package created: $outputFile"
            Write-Info "This package can be provided to auditors for compliance verification"
        }
        default {
            Write-Error "Unknown compliance subcommand: $SubCommand"
            Write-Info "Available subcommands: dashboard, assess, gap-analysis, audit"
            exit 1
        }
    }
}

function Install-Hooks {
    <#
    .SYNOPSIS
        Install PowerShield pre-commit hook
    #>
    param([switch]$Force)
    
    $gitDir = git rev-parse --git-dir 2>$null
    if (-not $gitDir) {
        Write-Error "Not a git repository"
        exit 1
    }
    
    $gitDir = Resolve-Path $gitDir
    $hooksDir = Join-Path $gitDir "hooks"
    $targetHook = Join-Path $hooksDir "pre-commit"
    $sourceHook = Join-Path $scriptRoot ".powershield/hooks/pre-commit"
    
    if (-not (Test-Path $sourceHook)) {
        Write-Error "Hook source not found: $sourceHook"
        exit 1
    }
    
    # Create hooks directory if it doesn't exist
    if (-not (Test-Path $hooksDir)) {
        New-Item -ItemType Directory -Path $hooksDir -Force | Out-Null
    }
    
    # Check if hook already exists
    if ((Test-Path $targetHook) -and -not $Force) {
        Write-Warning "Pre-commit hook already exists at: $targetHook"
        Write-Info "Use --force to overwrite"
        
        $response = Read-Host "Do you want to overwrite? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Info "Installation cancelled"
            exit 0
        }
    }
    
    # Copy hook
    try {
        Copy-Item $sourceHook $targetHook -Force
        
        # Make executable on Unix-like systems
        if ($IsLinux -or $IsMacOS) {
            chmod +x $targetHook
        }
        
        Write-Success "Pre-commit hook installed successfully"
        Write-Info "Location: $targetHook"
        Write-Host "`nThe hook will:"
        Write-Host "  • Analyze staged PowerShell files before each commit"
        Write-Host "  • Block commits with Critical/High severity violations"
        Write-Host "  • Can be bypassed with: git commit --no-verify"
        Write-Host "`nConfigure in .powershield.yml:"
        Write-Host "  hooks:"
        Write-Host "    enabled: true"
        Write-Host "    block_on: ['Critical', 'High']"
        
    } catch {
        Write-Error "Failed to install hook: $_"
        exit 1
    }
}

function Invoke-Rule {
    <#
    .SYNOPSIS
        Custom rule management commands
    .PARAMETER SubCommand
        validate - Validate a custom rule file
        validate-all - Validate all rules in a directory
        list - List all loaded rules
        create - Generate a new rule template
    #>
    param(
        [string]$SubCommand,
        [string]$Path,
        [string]$Output,
        [ValidateSet('command', 'regex', 'ast', 'parameter', 'comprehensive')]
        [string]$Template = 'command',
        [switch]$CustomOnly
    )
    
    # Import CustomRuleLoader module
    try {
        # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Safe: $scriptRoot is $PSScriptRoot (line 31), controlled within repo
        Import-Module "$scriptRoot/src/CustomRuleLoader.psm1" -Force -ErrorAction Stop
    } catch {
        Write-Error "Failed to load CustomRuleLoader module: $_"
        exit 1
    }
    
    switch ($SubCommand) {
        'validate' {
            if (-not $Path) {
                Write-Error "Path required for validate command"
                Write-Info "Usage: psts rule validate <rule-file.yml>"
                exit 1
            }
            
            $rulePath = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (-not $rulePath) {
                Write-Error "Rule file not found: $Path"
                exit 1
            }
            
            Write-Info "Validating rule: $rulePath"
            
            $isValid = Test-CustomRule -RuleFile $rulePath
            if ($isValid) {
                exit 0
            } else {
                exit 1
            }
        }
        
        'validate-all' {
            if (-not $Path) {
                Write-Error "Path required for validate-all command"
                Write-Info "Usage: psts rule validate-all <rules-directory>"
                exit 1
            }
            
            $rulesDir = Resolve-Path $Path -ErrorAction SilentlyContinue
            if (-not $rulesDir) {
                Write-Error "Directory not found: $Path"
                exit 1
            }
            
            Write-Info "Validating all rules in: $rulesDir"
            
            $ruleFiles = Get-ChildItem -Path $rulesDir -Filter "*.yml" -Recurse -ErrorAction SilentlyContinue
            $ruleFiles += Get-ChildItem -Path $rulesDir -Filter "*.yaml" -Recurse -ErrorAction SilentlyContinue
            
            if ($ruleFiles.Count -eq 0) {
                Write-Warning "No rule files found in: $rulesDir"
                exit 0
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host "Validating $($ruleFiles.Count) rule files" -ForegroundColor Cyan
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host ""
            
            $validCount = 0
            $invalidCount = 0
            
            foreach ($ruleFile in $ruleFiles) {
                $isValid = Test-CustomRule -RuleFile $ruleFile.FullName
                if ($isValid) {
                    $validCount++
                } else {
                    $invalidCount++
                }
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host "Validation Summary" -ForegroundColor Cyan
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host "Total: $($ruleFiles.Count)" -ForegroundColor White
            Write-Host "Valid: $validCount" -ForegroundColor Green
            if ($invalidCount -gt 0) {
                Write-Host "Invalid: $invalidCount" -ForegroundColor Red
            }
            
            if ($invalidCount -gt 0) {
                exit 1
            }
        }
        
        'list' {
            Write-Info "Loading rules..."
            
            # Create analyzer and load rules
            $analyzer = New-SecurityAnalyzer -WorkspacePath $scriptRoot
            
            # Filter custom rules if requested
            $rules = if ($CustomOnly) {
                $analyzer.SecurityRules | Where-Object { 
                    $_.Tags -contains 'custom' -or $_.Tags -contains 'community' 
                }
            } else {
                $analyzer.SecurityRules
            }
            
            if ($rules.Count -eq 0) {
                Write-Warning "No rules loaded"
                exit 0
            }
            
            Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            if ($CustomOnly) {
                Write-Host "Custom Rules ($($rules.Count))" -ForegroundColor Cyan
            } else {
                Write-Host "All Loaded Rules ($($rules.Count))" -ForegroundColor Cyan
            }
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
            Write-Host ""
            
            # Group by category
            $byCategory = $rules | Group-Object -Property Category
            
            foreach ($category in $byCategory) {
                Write-Host "[$($category.Name)]" -ForegroundColor Yellow
                foreach ($rule in $category.Group) {
                    $severityColor = switch ($rule.Severity) {
                        4 { 'Red' }      # Critical
                        3 { 'DarkRed' }  # High
                        2 { 'Yellow' }   # Medium
                        1 { 'Gray' }     # Low
                        default { 'White' }
                    }
                    
                    $severityName = switch ($rule.Severity) {
                        4 { 'Critical' }
                        3 { 'High' }
                        2 { 'Medium' }
                        1 { 'Low' }
                        default { 'Unknown' }
                    }
                    
                    $tags = if ($rule.Tags) { " (" + ($rule.Tags -join ', ') + ")" } else { "" }
                    
                    Write-Host "  • " -NoNewline -ForegroundColor Gray
                    Write-Host $rule.Name -NoNewline -ForegroundColor White
                    Write-Host " [$severityName]" -NoNewline -ForegroundColor $severityColor
                    Write-Host $tags -ForegroundColor DarkGray
                    
                    if ($rule.Description) {
                        Write-Host "    $($rule.Description)" -ForegroundColor DarkGray
                    }
                }
                Write-Host ""
            }
        }
        
        'create' {
            if (-not $Output) {
                Write-Error "Output path required for create command"
                Write-Info "Usage: psts rule create --output <path> --template <type>"
                Write-Info "Templates: command, regex, ast, parameter, comprehensive"
                exit 1
            }
            
            Write-Info "Creating rule template: $Template"
            
            try {
                New-CustomRuleTemplate -OutputPath $Output -RuleType $Template
                Write-Host "`nNext steps:" -ForegroundColor Cyan
                Write-Host "  1. Edit the rule file: $Output" -ForegroundColor White
                Write-Host "  2. Validate: psts rule validate $Output" -ForegroundColor White
                Write-Host "  3. Test with analysis: psts analyze" -ForegroundColor White
            } catch {
                Write-Error "Failed to create template: $_"
                exit 1
            }
        }
        
        default {
            Write-Error "Unknown rule subcommand: $SubCommand"
            Write-Info "Available subcommands: validate, validate-all, list, create"
            Write-Info ""
            Write-Info "Examples:"
            Write-Info "  psts rule validate ./rules/custom/my-rule.yml"
            Write-Info "  psts rule validate-all ./rules/custom"
            Write-Info "  psts rule list"
            Write-Info "  psts rule list --custom-only"
            Write-Info "  psts rule create --output ./rules/custom/new-rule.yml --template command"
            exit 1
        }
    }
}

function Show-Version {
    <#
    .SYNOPSIS
        Display PowerShield version information
    #>
    Write-Host "PowerShield - Comprehensive PowerShell Security Platform" -ForegroundColor Cyan
    Write-Host "Version: 1.6.0" -ForegroundColor White
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host "Platform: $($PSVersionTable.Platform)" -ForegroundColor Gray
    Write-Host "`nCLI: psts (PowerShield)" -ForegroundColor Gray
    Write-Host "Repository: https://github.com/J-Ellette/PowerShield" -ForegroundColor Gray
}

function Invoke-InteractiveMode {
    <#
    .SYNOPSIS
        Run PowerShield in interactive mode
    #>
    
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "PowerShield Interactive Mode" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    
    Write-Host "`nWelcome to PowerShield! This interactive mode helps you get started." -ForegroundColor White
    Write-Host "Type 'exit' or 'quit' at any time to leave interactive mode.`n" -ForegroundColor Gray
    
    # Menu options
    $maxMenuOption = 7
    
    while ($true) {
        Write-Host "`nWhat would you like to do?" -ForegroundColor Cyan
        Write-Host "  1. Analyze files for security issues" -ForegroundColor White
        Write-Host "  2. Create or manage baseline" -ForegroundColor White
        Write-Host "  3. Preview available fixes" -ForegroundColor White
        Write-Host "  4. Configure PowerShield" -ForegroundColor White
        Write-Host "  5. Install pre-commit hooks" -ForegroundColor White
        Write-Host "  6. Show help" -ForegroundColor White
        Write-Host "  7. Exit" -ForegroundColor White
        
        $choice = Read-Host "`nEnter your choice (1-$maxMenuOption)"
        
        switch ($choice) {
            '1' {
                # Analyze
                Write-Host "`n[Analyze Mode]" -ForegroundColor Cyan
                $path = Read-Host "Enter path to analyze (default: current directory)"
                if (-not $path) { $path = "." }
                
                $formatChoice = Read-Host "Output format? (1=text, 2=json, 3=sarif, 4=markdown) [default: text]"
                $format = switch ($formatChoice) {
                    '2' { 'json' }
                    '3' { 'sarif' }
                    '4' { 'markdown' }
                    default { 'text' }
                }
                
                $outputFile = $null
                if ($format -ne 'text') {
                    $outputFile = Read-Host "Output file path (optional, press Enter to skip)"
                    if (-not $outputFile) { $outputFile = $null }
                }
                
                Write-Host "`nRunning analysis..." -ForegroundColor Yellow
                $params = @{ Path = $path; Format = $format }
                if ($outputFile) { $params['Output'] = $outputFile }
                
                try {
                    Invoke-Analyze @params
                } catch {
                    Write-Error "Analysis failed: $_"
                }
            }
            '2' {
                # Baseline
                Write-Host "`n[Baseline Mode]" -ForegroundColor Cyan
                Write-Host "  1. Create new baseline" -ForegroundColor White
                Write-Host "  2. Compare with existing baseline" -ForegroundColor White
                
                $baselineChoice = Read-Host "Enter choice (1-2)"
                
                if ($baselineChoice -eq '1') {
                    $path = Read-Host "Enter path to analyze (default: current directory)"
                    if (-not $path) { $path = "." }
                    
                    Write-Host "`nCreating baseline..." -ForegroundColor Yellow
                    try {
                        Invoke-Baseline -SubCommand 'create' -Path $path
                    } catch {
                        Write-Error "Baseline creation failed: $_"
                    }
                } elseif ($baselineChoice -eq '2') {
                    $path = Read-Host "Enter path to analyze (default: current directory)"
                    if (-not $path) { $path = "." }
                    
                    Write-Host "`nComparing with baseline..." -ForegroundColor Yellow
                    try {
                        Invoke-Baseline -SubCommand 'compare' -Path $path
                    } catch {
                        Write-Error "Baseline comparison failed: $_"
                    }
                } else {
                    Write-Warning "Invalid choice"
                }
            }
            '3' {
                # Fix preview
                Write-Host "`n[Fix Preview Mode]" -ForegroundColor Cyan
                $path = Read-Host "Enter path to analyze (default: current directory)"
                if (-not $path) { $path = "." }
                
                $confidenceInput = Read-Host "Confidence threshold (0.0-1.0, default: 0.8)"
                $confidence = 0.8
                if ($confidenceInput) {
                    try {
                        $parsedConfidence = [double]$confidenceInput
                        if ($parsedConfidence -ge 0.0 -and $parsedConfidence -le 1.0) {
                            $confidence = $parsedConfidence
                        } else {
                            Write-Warning "Invalid confidence value. Using default: 0.8"
                        }
                    } catch {
                        Write-Warning "Invalid confidence value. Using default: 0.8"
                    }
                }
                
                Write-Host "`nPreviewing fixes..." -ForegroundColor Yellow
                try {
                    Invoke-Fix -SubCommand 'preview' -Path $path -Confidence $confidence
                } catch {
                    Write-Error "Fix preview failed: $_"
                }
            }
            '4' {
                # Configuration
                Write-Host "`n[Configuration Mode]" -ForegroundColor Cyan
                Write-Host "  1. Validate configuration" -ForegroundColor White
                Write-Host "  2. Show configuration" -ForegroundColor White
                Write-Host "  3. Initialize configuration" -ForegroundColor White
                
                $configChoice = Read-Host "Enter choice (1-3)"
                
                try {
                    switch ($configChoice) {
                        '1' { Invoke-Config -SubCommand 'validate' }
                        '2' { Invoke-Config -SubCommand 'show' }
                        '3' { Invoke-Config -SubCommand 'init' }
                        default { Write-Warning "Invalid choice" }
                    }
                } catch {
                    Write-Error "Configuration operation failed: $_"
                }
            }
            '5' {
                # Install hooks
                Write-Host "`n[Install Hooks Mode]" -ForegroundColor Cyan
                $confirm = Read-Host "Install pre-commit hooks? (y/N)"
                
                if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                    try {
                        Install-Hooks
                    } catch {
                        Write-Error "Hook installation failed: $_"
                    }
                }
            }
            '6' {
                # Help
                Show-Help
            }
            '7' {
                # Exit
                Write-Host "`nExiting PowerShield interactive mode. Goodbye!" -ForegroundColor Cyan
                return
            }
            'exit' {
                Write-Host "`nExiting PowerShield interactive mode. Goodbye!" -ForegroundColor Cyan
                return
            }
            'quit' {
                Write-Host "`nExiting PowerShield interactive mode. Goodbye!" -ForegroundColor Cyan
                return
            }
            default {
                Write-Warning "Invalid choice. Please enter a number from 1-$maxMenuOption."
            }
        }
    }
}

function Show-Help {
    <#
    .SYNOPSIS
        Display help information
    #>
    Write-Host @"
PowerShield (psts) - Comprehensive PowerShell Security Platform

USAGE:
    psts <command> [options]

COMMANDS:
    
    analyze [path]                Analyze PowerShell scripts for security violations
        Options:
            --format <type>       Output format: json, sarif, markdown, text (default: text)
            --output <file>       Output file path for results
            --baseline <file>     Compare against baseline file
            --suppressions        Enable suppression comment processing
        
        Examples:
            psts analyze                           # Analyze current directory
            psts analyze ./scripts                 # Analyze specific path
            psts analyze --format sarif            # Output in SARIF format
            psts analyze --output results.json --format json
            psts analyze --baseline .powershield-baseline.json
    
    config <subcommand>           Configuration management
        Subcommands:
            validate              Validate configuration file
            show                  Display current configuration (JSON)
            init                  Create default configuration file
        
        Examples:
            psts config validate                   # Validate .powershield.yml
            psts config show                       # Show current config
            psts config init                       # Create default config
    
    baseline <subcommand>         Baseline management for tracking changes over time
        Subcommands:
            create [path]         Create baseline from current analysis
            compare [path]        Compare current state with baseline
            list [path]           List all baseline versions
            delete                Delete a baseline file
            export                Export baseline comparison report
            share                 Prepare baseline for team sharing
        
        Options:
            --output <file>       Custom baseline file path or report output
            --description <text>  Description for the baseline
            --format <format>     Report format: markdown, html, json (default: markdown)
            --team <name>         Team name for sharing (default: Default)
        
        Examples:
            psts baseline create                             # Create baseline
            psts baseline create --description "Release 1.0"
            psts baseline compare                            # Compare with baseline
            psts baseline list                               # List all baselines
            psts baseline export --format html               # Export comparison report
            psts baseline share --team "DevOps"              # Share with team
    
    compliance <subcommand>       Compliance reporting and assessment
        Subcommands:
            dashboard             Generate compliance dashboard for all frameworks
            assess                Assess compliance for specific framework
            gap-analysis          Generate gap analysis report
            audit                 Export audit evidence package
        
        Options:
            --framework <name>    Framework: NIST, CIS, OWASP, SOC2, PCI-DSS, HIPAA, All (default: All)
            --output <file>       Output file path for reports
            --format <format>     Report format: markdown, html, json (default: markdown)
            --path <path>         Path to analyze (default: current directory)
        
        Examples:
            psts compliance dashboard                        # All frameworks dashboard
            psts compliance assess --framework NIST          # Assess NIST compliance
            psts compliance gap-analysis --framework PCI-DSS # PCI-DSS gap analysis
            psts compliance audit                            # Generate audit evidence
            psts compliance dashboard --output report.html --format html
    
    fix <subcommand>              Fix management
        Subcommands:
            preview [path]        Preview available fixes without applying
            apply [path]          Apply fixes with confidence threshold
        
        Options:
            --confidence <0-1>    Confidence threshold (default: 0.8)
            --violations <file>   Path to violations file
        
        Examples:
            psts fix preview                       # Preview all fixable issues
            psts fix preview --confidence 0.9      # Higher confidence threshold
            psts fix apply --confidence 0.8        # Apply fixes
    
    rule <subcommand>             Custom rule management
        Subcommands:
            validate <file>       Validate a custom rule file
            validate-all <dir>    Validate all rules in a directory
            list                  List all loaded rules
            create                Generate a new rule template
        
        Options:
            --output <file>       Output path for new rule template
            --template <type>     Template type: command, regex, ast, parameter, comprehensive
            --custom-only         Show only custom rules (for list command)
        
        Examples:
            psts rule create --output ./rules/custom/my-rule.yml --template command
            psts rule validate ./rules/custom/my-rule.yml
            psts rule validate-all ./rules/custom
            psts rule list                         # List all rules
            psts rule list --custom-only           # List only custom rules
    
    install-hooks                 Install pre-commit hook for local validation
        Options:
            --force               Overwrite existing hook
        
        Examples:
            psts install-hooks                     # Install hook interactively
            psts install-hooks --force             # Force overwrite
    
    version                       Display version information
    
    interactive                   Run in interactive mode with guided prompts
    
    help                          Display this help message

CONFIGURATION:
    PowerShield uses .powershield.yml for configuration. Create one with:
        psts config init
    
    Configuration file locations (in priority order):
        1. .powershield.yml (current directory)
        2. .powershield.yml (repository root)
        3. ~/.powershield.yml (user home)

EXAMPLES:
    # Quick security scan
    psts analyze
    
    # Detailed analysis with SARIF output
    psts analyze ./src --format sarif --output security-results.sarif
    
    # Create baseline and track new issues
    psts baseline create
    psts baseline compare
    
    # Preview and apply security fixes
    psts fix preview
    psts fix apply --confidence 0.8
    
    # Install local validation
    psts install-hooks
    
    # Validate configuration
    psts config validate
    
    # Run in interactive mode
    psts interactive

DOCUMENTATION:
    https://github.com/J-Ellette/PowerShield
    https://github.com/J-Ellette/PowerShield/blob/main/docs/

"@ -ForegroundColor White
}

#endregion

#region Main Execution

# Parse arguments
$params = @{}
$subCommand = $null

for ($i = 0; $i -lt $Arguments.Count; $i++) {
    $arg = $Arguments[$i]
    
    if ($arg -match '^--') {
        # Long option
        $optionName = $arg -replace '^--', ''
        
        switch ($optionName) {
            'format' {
                $params['Format'] = $Arguments[++$i]
            }
            'output' {
                $params['Output'] = $Arguments[++$i]
            }
            'baseline' {
                if ($i + 1 -lt $Arguments.Count -and $Arguments[$i + 1] -notmatch '^--') {
                    $params['Baseline'] = $Arguments[++$i]
                } else {
                    $params['Baseline'] = '.powershield-baseline.json'
                }
            }
            'suppressions' {
                $params['EnableSuppressions'] = $true
            }
            'profile' {
                $params['PerformanceProfile'] = $Arguments[++$i]
            }
            'reports-dir' {
                $params['UseReportsDirectory'] = $true
            }
            'incremental' {
                $params['Incremental'] = $true
            }
            'confidence' {
                $params['Confidence'] = [double]$Arguments[++$i]
            }
            'violations' {
                $params['ViolationsFile'] = $Arguments[++$i]
            }
            'force' {
                $params['Force'] = $true
            }
            'template' {
                $params['Template'] = $Arguments[++$i]
            }
            'custom-only' {
                $params['CustomOnly'] = $true
            }
            'framework' {
                $params['Framework'] = $Arguments[++$i]
            }
            'description' {
                $params['Description'] = $Arguments[++$i]
            }
            'team' {
                $params['TeamName'] = $Arguments[++$i]
            }
            default {
                Write-Warning "Unknown option: --$optionName"
            }
        }
    } elseif ($arg -match '^-') {
        # Short option (for compatibility)
        $optionName = $arg -replace '^-', ''
        
        switch ($optionName) {
            'f' {
                $params['Format'] = $Arguments[++$i]
            }
            'o' {
                $params['Output'] = $Arguments[++$i]
            }
            default {
                Write-Warning "Unknown option: -$optionName"
            }
        }
    } else {
        # Positional argument
        if ($null -eq $subCommand) {
            $subCommand = $arg
        } elseif (-not $params.ContainsKey('Path')) {
            $params['Path'] = $arg
        }
    }
}

# Execute command
# If no command provided, start interactive mode
if (-not $Command) {
    Invoke-InteractiveMode
    exit 0
}

switch ($Command) {
    'analyze' {
        if ($subCommand) {
            $params['Path'] = $subCommand
        }
        Invoke-Analyze @params
    }
    
    'config' {
        if (-not $subCommand) {
            Write-Error "Config subcommand required"
            Show-Help
            exit 1
        }
        Invoke-Config -SubCommand $subCommand
    }
    
    'baseline' {
        if (-not $subCommand) {
            Write-Error "Baseline subcommand required"
            Show-Help
            exit 1
        }
        $params['SubCommand'] = $subCommand
        Invoke-Baseline @params
    }
    
    'fix' {
        if (-not $subCommand) {
            Write-Error "Fix subcommand required"
            Show-Help
            exit 1
        }
        $params['SubCommand'] = $subCommand
        Invoke-Fix @params
    }
    
    'rule' {
        if (-not $subCommand) {
            Write-Error "Rule subcommand required"
            Show-Help
            exit 1
        }
        $params['SubCommand'] = $subCommand
        Invoke-Rule @params
    }
    
    'compliance' {
        if (-not $subCommand) {
            Write-Error "Compliance subcommand required"
            Show-Help
            exit 1
        }
        $params['SubCommand'] = $subCommand
        Invoke-Compliance @params
    }
    
    'install-hooks' {
        Install-Hooks @params
    }
    
    'interactive' {
        Invoke-InteractiveMode
    }
    
    'version' {
        Show-Version
    }
    
    'help' {
        Show-Help
    }
    
    default {
        Write-Error "Unknown command: $Command"
        Show-Help
        exit 1
    }
}

#endregion
