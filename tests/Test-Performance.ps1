#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Performance benchmark test for PowerShield
.DESCRIPTION
    Tests and benchmarks PowerShield analysis performance with various optimizations
.EXAMPLE
    ./Test-Performance.ps1 -WorkspacePath ./tests/TestScripts
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$WorkspacePath = './tests/TestScripts',
    
    [Parameter(Mandatory=$false)]
    [switch]$CleanCache
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $PSScriptRoot

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       PowerShield Performance Benchmark Test              ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Import the analyzer module
Import-Module (Join-Path $scriptRoot "src/PowerShellSecurityAnalyzer.psm1") -Force

# Clean cache if requested
if ($CleanCache) {
    $cacheDir = Join-Path $WorkspacePath '.powershield-cache'
    if (Test-Path $cacheDir) {
        Write-Host "🗑️  Cleaning cache directory..." -ForegroundColor Yellow
        Remove-Item -Path $cacheDir -Recurse -Force
    }
}

Write-Host "📊 Testing workspace: $WorkspacePath`n" -ForegroundColor White

# Test 1: Baseline (no optimizations)
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "Test 1: Baseline Analysis (No Optimizations)" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════`n" -ForegroundColor DarkGray

$result1 = Invoke-WorkspaceAnalysis -WorkspacePath $WorkspacePath -WarningAction SilentlyContinue

Write-Host "  Files analyzed: $($result1.FilesAnalyzed)" -ForegroundColor White
Write-Host "  Total violations: $($result1.TotalViolations)" -ForegroundColor White
Write-Host "  Estimated time: Not tracked (baseline)`n" -ForegroundColor Gray

# Test 2: With metrics tracking
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "Test 2: Analysis with Performance Metrics" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════`n" -ForegroundColor DarkGray

$result2 = Invoke-WorkspaceAnalysis -WorkspacePath $WorkspacePath -TrackMetrics -WarningAction SilentlyContinue

Write-Host "  Files analyzed: $($result2.FilesAnalyzed)" -ForegroundColor White
Write-Host "  Total violations: $($result2.TotalViolations)" -ForegroundColor White
Write-Host "  Analysis time: $($result2.Metrics['total_analysis_time_seconds'])s" -ForegroundColor Cyan
Write-Host "  Files/second: $($result2.Metrics['files_per_second'])" -ForegroundColor Cyan
Write-Host "  Rules/second: $($result2.Metrics['rules_per_second'])" -ForegroundColor Cyan
Write-Host "  Memory peak: $($result2.Metrics['memory_peak_mb']) MB`n" -ForegroundColor Cyan

# Test 3: With caching (first run - cold cache)
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "Test 3: Analysis with Caching (Cold Cache)" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════`n" -ForegroundColor DarkGray

$result3 = Invoke-WorkspaceAnalysis -WorkspacePath $WorkspacePath -TrackMetrics -EnableCache -WarningAction SilentlyContinue

Write-Host "  Files analyzed: $($result3.FilesAnalyzed)" -ForegroundColor White
Write-Host "  Total violations: $($result3.TotalViolations)" -ForegroundColor White
Write-Host "  Analysis time: $($result3.Metrics['total_analysis_time_seconds'])s" -ForegroundColor Cyan
Write-Host "  Files/second: $($result3.Metrics['files_per_second'])" -ForegroundColor Cyan
Write-Host "  Cache hits: $($result3.Metrics['cache_hits'])" -ForegroundColor Green
Write-Host "  Cache misses: $($result3.Metrics['cache_misses'])" -ForegroundColor Red
Write-Host "  Cache hit rate: $($result3.Metrics['cache_hit_rate'])`n" -ForegroundColor Cyan

# Test 4: With caching (second run - warm cache)
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "Test 4: Analysis with Caching (Warm Cache)" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════`n" -ForegroundColor DarkGray

$result4 = Invoke-WorkspaceAnalysis -WorkspacePath $WorkspacePath -TrackMetrics -EnableCache -WarningAction SilentlyContinue

Write-Host "  Files analyzed: $($result4.FilesAnalyzed)" -ForegroundColor White
Write-Host "  Total violations: $($result4.TotalViolations)" -ForegroundColor White
Write-Host "  Analysis time: $($result4.Metrics['total_analysis_time_seconds'])s" -ForegroundColor Cyan
Write-Host "  Files/second: $($result4.Metrics['files_per_second'])" -ForegroundColor Cyan
Write-Host "  Cache hits: $($result4.Metrics['cache_hits'])" -ForegroundColor Green
Write-Host "  Cache misses: $($result4.Metrics['cache_misses'])" -ForegroundColor Red
Write-Host "  Cache hit rate: $($result4.Metrics['cache_hit_rate'])`n" -ForegroundColor Cyan

# Summary
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "Performance Summary" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════`n" -ForegroundColor DarkGray

$baselineTime = $result2.Metrics['total_analysis_time_seconds']
$cachedTime = $result4.Metrics['total_analysis_time_seconds']

if ($cachedTime -gt 0) {
    $speedup = [math]::Round($baselineTime / $cachedTime, 2)
    Write-Host "  🚀 Cache speedup: ${speedup}x faster" -ForegroundColor Green
    Write-Host "  ⏱️  Time saved: $([math]::Round($baselineTime - $cachedTime, 2))s" -ForegroundColor Green
}

Write-Host "  📁 Files processed: $($result2.FilesAnalyzed)" -ForegroundColor White
Write-Host "  🔍 Rules executed: $($result2.Metrics['rules_executed'])" -ForegroundColor White
Write-Host "  ⚠️  Violations found: $($result2.TotalViolations)" -ForegroundColor Yellow
Write-Host "  💾 Cache hit rate: $($result4.Metrics['cache_hit_rate'])" -ForegroundColor Cyan
Write-Host "  📊 Peak memory: $($result2.Metrics['memory_peak_mb']) MB`n" -ForegroundColor Cyan

Write-Host "✅ Performance testing complete!`n" -ForegroundColor Green
