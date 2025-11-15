#Requires -Version 7.0

<#
.SYNOPSIS
    Artifact management for PowerShield reports
.DESCRIPTION
    Manages the .powershield-reports directory structure and generates standardized
    artifacts including run metadata, metrics, and multiple output formats.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

class ArtifactManager {
    [string]$WorkspacePath
    [string]$ReportsDirectory
    [bool]$CompressSarif
    
    ArtifactManager([string]$workspacePath) {
        $this.WorkspacePath = $workspacePath
        $this.ReportsDirectory = Join-Path $workspacePath '.powershield-reports'
        $this.CompressSarif = $false
    }
    
    [void] EnsureReportsDirectory() {
        if (-not (Test-Path $this.ReportsDirectory)) {
            New-Item -Path $this.ReportsDirectory -ItemType Directory -Force | Out-Null
            Write-Verbose "Created reports directory: $($this.ReportsDirectory)"
        }
    }
    
    [hashtable] GenerateAllArtifacts([object]$analysisResult, [object]$config) {
        $this.EnsureReportsDirectory()
        
        $artifacts = @{}
        $timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
        
        # 1. Native JSON format
        $jsonPath = Join-Path $this.ReportsDirectory 'analysis.json'
        $this.SaveAnalysisJson($analysisResult, $jsonPath)
        $artifacts['json'] = $jsonPath
        
        # 2. SARIF format
        $sarifPath = Join-Path $this.ReportsDirectory 'analysis.sarif'
        $this.ConvertAndSaveSarif($jsonPath, $sarifPath)
        $artifacts['sarif'] = $sarifPath
        
        # 3. JUnit XML format
        $junitPath = Join-Path $this.ReportsDirectory 'analysis.junit.xml'
        $this.ConvertAndSaveJUnit($jsonPath, $junitPath)
        $artifacts['junit'] = $junitPath
        
        # 4. TAP format
        $tapPath = Join-Path $this.ReportsDirectory 'analysis.tap'
        $this.ConvertAndSaveTAP($jsonPath, $tapPath)
        $artifacts['tap'] = $tapPath
        
        # 5. CSV format (optional, based on config)
        if ($config -and $config.output -and $config.output.csv) {
            $csvPath = Join-Path $this.ReportsDirectory 'analysis.csv'
            $this.ConvertAndSaveCSV($jsonPath, $csvPath)
            $artifacts['csv'] = $csvPath
        }
        
        # 6. Markdown summary
        $markdownPath = Join-Path $this.ReportsDirectory 'summary.md'
        $this.GenerateMarkdownSummary($analysisResult, $markdownPath)
        $artifacts['markdown'] = $markdownPath
        
        # 7. Metrics JSON
        $metricsPath = Join-Path $this.ReportsDirectory 'metrics.json'
        $this.GenerateMetrics($analysisResult, $metricsPath)
        $artifacts['metrics'] = $metricsPath
        
        # 8. Run summary JSON
        $runPath = Join-Path $this.ReportsDirectory 'run.json'
        $this.GenerateRunSummary($analysisResult, $config, $runPath)
        $artifacts['run'] = $runPath
        
        # 9. Suppressions JSON
        if ($analysisResult.Suppressions -or $analysisResult.SuppressedCount -gt 0) {
            $suppressionsPath = Join-Path $this.ReportsDirectory 'suppressions.json'
            $this.GenerateSuppressions($analysisResult, $suppressionsPath)
            $artifacts['suppressions'] = $suppressionsPath
        }
        
        return $artifacts
    }
    
    [void] SaveAnalysisJson([object]$result, [string]$path) {
        # Enhance result with metadata if not present
        if (-not $result.metadata) {
            $result | Add-Member -NotePropertyName 'metadata' -NotePropertyValue @{
                version = '1.0.0'
                timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
                tool = 'PowerShield'
            } -Force
        }
        
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8
        Write-Verbose "Saved analysis JSON: $path"
    }
    
    [void] ConvertAndSaveSarif([string]$jsonPath, [string]$sarifPath) {
        # Find script relative to repository root
        $repoRoot = $this.WorkspacePath
        while (-not (Test-Path (Join-Path $repoRoot 'scripts/Convert-ToSARIF.ps1')) -and $repoRoot -ne (Split-Path $repoRoot -Parent)) {
            $repoRoot = Split-Path $repoRoot -Parent
        }
        
        $scriptPath = Join-Path $repoRoot 'scripts/Convert-ToSARIF.ps1'
        if (Test-Path $scriptPath) {
            & $scriptPath -InputFile $jsonPath -OutputFile $sarifPath 2>&1 | Write-Verbose
            Write-Verbose "Saved SARIF: $sarifPath"
        } else {
            Write-Warning "Convert-ToSARIF.ps1 not found at: $scriptPath"
        }
    }
    
    [void] ConvertAndSaveJUnit([string]$jsonPath, [string]$junitPath) {
        # Find script relative to repository root
        $repoRoot = $this.WorkspacePath
        while (-not (Test-Path (Join-Path $repoRoot 'scripts/Export-ToJUnit.ps1')) -and $repoRoot -ne (Split-Path $repoRoot -Parent)) {
            $repoRoot = Split-Path $repoRoot -Parent
        }
        
        $scriptPath = Join-Path $repoRoot 'scripts/Export-ToJUnit.ps1'
        if (Test-Path $scriptPath) {
            & $scriptPath -InputFile $jsonPath -OutputFile $junitPath 2>&1 | Write-Verbose
            Write-Verbose "Saved JUnit XML: $junitPath"
        } else {
            Write-Warning "Export-ToJUnit.ps1 not found at: $scriptPath"
        }
    }
    
    [void] ConvertAndSaveTAP([string]$jsonPath, [string]$tapPath) {
        # Find script relative to repository root
        $repoRoot = $this.WorkspacePath
        while (-not (Test-Path (Join-Path $repoRoot 'scripts/Export-ToTAP.ps1')) -and $repoRoot -ne (Split-Path $repoRoot -Parent)) {
            $repoRoot = Split-Path $repoRoot -Parent
        }
        
        $scriptPath = Join-Path $repoRoot 'scripts/Export-ToTAP.ps1'
        if (Test-Path $scriptPath) {
            & $scriptPath -InputFile $jsonPath -OutputFile $tapPath 2>&1 | Write-Verbose
            Write-Verbose "Saved TAP: $tapPath"
        } else {
            Write-Warning "Export-ToTAP.ps1 not found at: $scriptPath"
        }
    }
    
    [void] ConvertAndSaveCSV([string]$jsonPath, [string]$csvPath) {
        # Find script relative to repository root
        $repoRoot = $this.WorkspacePath
        while (-not (Test-Path (Join-Path $repoRoot 'scripts/Export-ToCSV.ps1')) -and $repoRoot -ne (Split-Path $repoRoot -Parent)) {
            $repoRoot = Split-Path $repoRoot -Parent
        }
        
        $scriptPath = Join-Path $repoRoot 'scripts/Export-ToCSV.ps1'
        if (Test-Path $scriptPath) {
            & $scriptPath -InputFile $jsonPath -OutputFile $csvPath 2>&1 | Write-Verbose
            Write-Verbose "Saved CSV: $csvPath"
        } else {
            Write-Warning "Export-ToCSV.ps1 not found at: $scriptPath"
        }
    }
    
    [void] GenerateMarkdownSummary([object]$result, [string]$path) {
        # Find script relative to repository root
        $repoRoot = $this.WorkspacePath
        while (-not (Test-Path (Join-Path $repoRoot 'scripts/Generate-SecurityReport.ps1')) -and $repoRoot -ne (Split-Path $repoRoot -Parent)) {
            $repoRoot = Split-Path $repoRoot -Parent
        }
        
        $scriptPath = Join-Path $repoRoot 'scripts/Generate-SecurityReport.ps1'
        $jsonTemp = [System.IO.Path]::GetTempFileName()
        
        try {
            $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonTemp -Encoding UTF8
            
            if (Test-Path $scriptPath) {
                & $scriptPath -InputFile $jsonTemp -OutputFile $path 2>&1 | Write-Verbose
                Write-Verbose "Saved markdown summary: $path"
            } else {
                Write-Warning "Generate-SecurityReport.ps1 not found at: $scriptPath"
            }
        } finally {
            if (Test-Path $jsonTemp) {
                Remove-Item $jsonTemp -Force
            }
        }
    }
    
    [void] GenerateMetrics([object]$result, [string]$path) {
        $metrics = @{
            version = '1.0'
            timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
            performance = @{
                analysisTimeMs = 0
                filesAnalyzed = 0
                linesOfCode = 0
                filesPerSecond = 0
                parallelMode = $false
            }
            counts = @{
                Critical = 0
                High = 0
                Medium = 0
                Low = 0
                Total = 0
            }
            rules = @{
                total = 0
                executed = 0
                triggered = 0
            }
            suppressions = @{
                active = 0
                expired = 0
            }
        }
        
        # Extract performance data if available
        if ($result.performance) {
            $metrics.performance = $result.performance
        }
        
        # Calculate counts from summary
        if ($result.Summary) {
            $metrics.counts.Critical = if ($result.Summary.TotalCritical) { $result.Summary.TotalCritical } else { 0 }
            $metrics.counts.High = if ($result.Summary.TotalHigh) { $result.Summary.TotalHigh } else { 0 }
            $metrics.counts.Medium = if ($result.Summary.TotalMedium) { $result.Summary.TotalMedium } else { 0 }
            $metrics.counts.Low = if ($result.Summary.TotalLow) { $result.Summary.TotalLow } else { 0 }
            $metrics.counts.Total = $result.TotalViolations
        }
        
        # Files analyzed
        if ($result.TotalFiles) {
            $metrics.performance.filesAnalyzed = $result.TotalFiles
        }
        
        # Suppression counts
        if ($result.SuppressedCount) {
            $metrics.suppressions.active = $result.SuppressedCount
        }
        
        $metrics | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8
        Write-Verbose "Saved metrics: $path"
    }
    
    [void] GenerateRunSummary([object]$result, [object]$config, [string]$path) {
        # Detect CI context
        $scriptRoot = Split-Path (Split-Path $this.ReportsDirectory -Parent) -Parent
        $ciAdapterPath = Join-Path $scriptRoot 'src/CIAdapter.psm1'
        
        $ciContext = $null
        if (Test-Path $ciAdapterPath) {
            Import-Module $ciAdapterPath -Force -ErrorAction SilentlyContinue
            # Use the function instead of class directly
            $adapter = New-CIAdapter
            if ($adapter) {
                $ciContext = $adapter.GetContext()
            }
        }
        
        $runSummary = @{
            version = '1.0'
            timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
            ci = @{}
            counts = @{
                Critical = 0
                High = 0
                Medium = 0
                Low = 0
            }
            gate = @{
                failOn = @()
                maxWarnings = 0
                result = 'pass'
            }
            performance = @{
                analysisTimeMs = 0
                filesAnalyzed = 0
                linesOfCode = 0
            }
        }
        
        # Add CI context if available
        if ($ciContext) {
            $runSummary.ci = @{
                provider = $ciContext.Provider
                repo = $ciContext.Repository
                branch = $ciContext.Branch
                sha = $ciContext.CommitSha
                pr = $ciContext.PullRequestId
                jobUrl = $ciContext.JobUrl
            }
        }
        
        # Add counts
        if ($result.Summary) {
            $runSummary.counts.Critical = if ($result.Summary.TotalCritical) { $result.Summary.TotalCritical } else { 0 }
            $runSummary.counts.High = if ($result.Summary.TotalHigh) { $result.Summary.TotalHigh } else { 0 }
            $runSummary.counts.Medium = if ($result.Summary.TotalMedium) { $result.Summary.TotalMedium } else { 0 }
            $runSummary.counts.Low = if ($result.Summary.TotalLow) { $result.Summary.TotalLow } else { 0 }
        }
        
        # Add gate information from config
        if ($config -and $config.CI) {
            if ($config.CI.fail_on) {
                $runSummary.gate.failOn = $config.CI.fail_on
            }
            if ($config.CI.max_warnings) {
                $runSummary.gate.maxWarnings = $config.CI.max_warnings
            }
            
            # Determine if gate passed
            $shouldFail = $false
            foreach ($severity in $runSummary.gate.failOn) {
                if ($runSummary.counts[$severity] -gt 0) {
                    $shouldFail = $true
                    break
                }
            }
            
            $runSummary.gate.result = if ($shouldFail) { 'fail' } else { 'pass' }
        }
        
        # Add performance
        if ($result.performance) {
            $runSummary.performance = $result.performance
        } elseif ($result.TotalFiles) {
            $runSummary.performance.filesAnalyzed = $result.TotalFiles
        }
        
        $runSummary | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8
        Write-Verbose "Saved run summary: $path"
    }
    
    [void] GenerateSuppressions([object]$result, [string]$path) {
        $suppressions = @{
            version = '1.0'
            timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
            active = @()
            expired = @()
            summary = @{
                totalActive = 0
                totalExpired = 0
            }
        }
        
        # Extract suppressions from results
        if ($result.Results) {
            foreach ($fileResult in $result.Results) {
                if ($fileResult.Suppressions) {
                    foreach ($suppression in $fileResult.Suppressions) {
                        if ($suppression.Expired) {
                            $suppressions.expired += $suppression
                        } else {
                            $suppressions.active += $suppression
                        }
                    }
                }
            }
        }
        
        $suppressions.summary.totalActive = $suppressions.active.Count
        $suppressions.summary.totalExpired = $suppressions.expired.Count
        
        $suppressions | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8
        Write-Verbose "Saved suppressions: $path"
    }
    
    [void] CleanupOldReports([int]$keepCount = 10) {
        # Could implement rotation of old reports if needed
        Write-Verbose "Report cleanup not yet implemented"
    }
}

# Helper function for external use
function New-ArtifactReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspacePath,
        
        [Parameter(Mandatory = $true)]
        [object]$AnalysisResult,
        
        [Parameter(Mandatory = $false)]
        [object]$Config
    )
    
    $manager = [ArtifactManager]::new($WorkspacePath)
    return $manager.GenerateAllArtifacts($AnalysisResult, $Config)
}

# Export the class
Export-ModuleMember -Function New-ArtifactReport
