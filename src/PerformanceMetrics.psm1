#Requires -Version 7.0

<#
.SYNOPSIS
    Performance metrics tracking for PowerShield
.DESCRIPTION
    Tracks and reports performance metrics for analysis operations including timing, throughput, and caching.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

class PerformanceMetrics {
    [datetime]$StartTime
    [datetime]$EndTime
    [int]$FilesAnalyzed
    [int]$FilesSkipped
    [int]$TotalViolations
    [int]$RulesExecuted
    [int]$CacheHits
    [int]$CacheMisses
    [double]$PeakMemoryMB
    [hashtable]$FileTimings
    [hashtable]$RuleTimings
    [bool]$ParallelMode
    [int]$WorkerThreads

    PerformanceMetrics() {
        $this.StartTime = Get-Date
        $this.FilesAnalyzed = 0
        $this.FilesSkipped = 0
        $this.TotalViolations = 0
        $this.RulesExecuted = 0
        $this.CacheHits = 0
        $this.CacheMisses = 0
        $this.PeakMemoryMB = 0
        $this.FileTimings = @{}
        $this.RuleTimings = @{}
        $this.ParallelMode = $false
        $this.WorkerThreads = 1
    }

    [void] RecordFileAnalysis([string]$FilePath, [double]$DurationMs, [int]$ViolationsFound) {
        $this.FilesAnalyzed++
        $this.TotalViolations += $ViolationsFound
        $this.FileTimings[$FilePath] = $DurationMs
        $this.UpdateMemoryUsage()
    }

    [void] RecordRuleExecution([string]$RuleName, [double]$DurationMs) {
        if (-not $this.RuleTimings.ContainsKey($RuleName)) {
            $this.RuleTimings[$RuleName] = @{
                Count = 0
                TotalMs = 0
                AvgMs = 0
            }
        }
        $this.RuleTimings[$RuleName].Count++
        $this.RuleTimings[$RuleName].TotalMs += $DurationMs
        $this.RuleTimings[$RuleName].AvgMs = $this.RuleTimings[$RuleName].TotalMs / $this.RuleTimings[$RuleName].Count
    }

    [void] RecordCacheHit() {
        $this.CacheHits++
    }

    [void] RecordCacheMiss() {
        $this.CacheMisses++
    }

    [void] RecordFileSkipped() {
        $this.FilesSkipped++
    }

    [void] UpdateMemoryUsage() {
        $currentMemoryMB = [System.GC]::GetTotalMemory($false) / 1MB
        if ($currentMemoryMB -gt $this.PeakMemoryMB) {
            $this.PeakMemoryMB = $currentMemoryMB
        }
    }

    [void] Complete() {
        $this.EndTime = Get-Date
        $this.UpdateMemoryUsage()
    }

    [double] GetTotalAnalysisTimeSeconds() {
        if ($this.EndTime -eq [datetime]::MinValue) {
            return ((Get-Date) - $this.StartTime).TotalSeconds
        }
        return ($this.EndTime - $this.StartTime).TotalSeconds
    }

    [double] GetFilesPerSecond() {
        $totalSeconds = $this.GetTotalAnalysisTimeSeconds()
        if ($totalSeconds -eq 0) { return 0 }
        return $this.FilesAnalyzed / $totalSeconds
    }

    [double] GetRulesPerSecond() {
        $totalSeconds = $this.GetTotalAnalysisTimeSeconds()
        if ($totalSeconds -eq 0) { return 0 }
        return $this.RulesExecuted / $totalSeconds
    }

    [double] GetCacheHitRate() {
        $total = $this.CacheHits + $this.CacheMisses
        if ($total -eq 0) { return 0 }
        return $this.CacheHits / $total
    }

    [hashtable] ToHashtable() {
        return @{
            total_analysis_time_seconds = [math]::Round($this.GetTotalAnalysisTimeSeconds(), 2)
            files_analyzed = $this.FilesAnalyzed
            files_skipped = $this.FilesSkipped
            files_per_second = [math]::Round($this.GetFilesPerSecond(), 2)
            total_violations = $this.TotalViolations
            rules_executed = $this.RulesExecuted
            rules_per_second = [math]::Round($this.GetRulesPerSecond(), 0)
            cache_hits = $this.CacheHits
            cache_misses = $this.CacheMisses
            cache_hit_rate = [math]::Round($this.GetCacheHitRate(), 3)
            memory_peak_mb = [math]::Round($this.PeakMemoryMB, 2)
            parallel_mode = $this.ParallelMode
            worker_threads = $this.WorkerThreads
            start_time = $this.StartTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            end_time = if ($this.EndTime -ne [datetime]::MinValue) { $this.EndTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { $null }
        }
    }

    [string] ToFormattedString() {
        $metrics = $this.ToHashtable()
        $sb = [System.Text.StringBuilder]::new()
        
        [void]$sb.AppendLine("Performance Metrics")
        [void]$sb.AppendLine("=" * 50)
        [void]$sb.AppendLine("Analysis Time: $($metrics.total_analysis_time_seconds)s")
        [void]$sb.AppendLine("Files Analyzed: $($metrics.files_analyzed)")
        [void]$sb.AppendLine("Files Skipped: $($metrics.files_skipped)")
        [void]$sb.AppendLine("Files/Second: $($metrics.files_per_second)")
        [void]$sb.AppendLine("Total Violations: $($metrics.total_violations)")
        [void]$sb.AppendLine("Rules Executed: $($metrics.rules_executed)")
        [void]$sb.AppendLine("Rules/Second: $($metrics.rules_per_second)")
        [void]$sb.AppendLine("Cache Hit Rate: $($metrics.cache_hit_rate)")
        [void]$sb.AppendLine("Peak Memory: $($metrics.memory_peak_mb) MB")
        [void]$sb.AppendLine("Parallel Mode: $($metrics.parallel_mode)")
        if ($metrics.parallel_mode) {
            [void]$sb.AppendLine("Worker Threads: $($metrics.worker_threads)")
        }
        
        return $sb.ToString()
    }
}

class AnalysisCache {
    [hashtable]$Cache
    [string]$CacheDir
    [bool]$Enabled
    [int]$MaxCacheAge

    AnalysisCache([bool]$enabled, [string]$cacheDir) {
        $this.Cache = @{}
        $this.Enabled = $enabled
        $this.CacheDir = $cacheDir
        $this.MaxCacheAge = 86400 # 24 hours in seconds
        
        if ($this.Enabled -and $this.CacheDir) {
            $this.InitializeCache()
        }
    }

    [void] InitializeCache() {
        if (-not (Test-Path $this.CacheDir)) {
            try {
                New-Item -Path $this.CacheDir -ItemType Directory -Force | Out-Null
            } catch {
                Write-Warning "Failed to create cache directory: $_"
                $this.Enabled = $false
            }
        }
    }

    [string] GetCacheKey([string]$FilePath, [string]$FileHash) {
        return "$FilePath|$FileHash"
    }

    [string] GetFileHash([string]$FilePath) {
        try {
            $fileInfo = Get-Item -Path $FilePath -ErrorAction Stop
            # Use file path + size + last write time for quick hash
            $hashInput = "$FilePath|$($fileInfo.Length)|$($fileInfo.LastWriteTimeUtc.Ticks)"
            $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($hashInput)
            )
            return [System.BitConverter]::ToString($hash).Replace('-', '')
        } catch {
            return $null
        }
    }

    [object] Get([string]$FilePath) {
        if (-not $this.Enabled) { return $null }

        $fileHash = $this.GetFileHash($FilePath)
        if (-not $fileHash) { return $null }

        $cacheKey = $this.GetCacheKey($FilePath, $fileHash)
        
        # Check in-memory cache first
        if ($this.Cache.ContainsKey($cacheKey)) {
            $cached = $this.Cache[$cacheKey]
            if ($this.IsCacheValid($cached)) {
                return $cached.Result
            } else {
                $this.Cache.Remove($cacheKey)
            }
        }

        # Check disk cache
        $cacheFile = Join-Path $this.CacheDir "$([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cacheKey))).json"
        if (Test-Path $cacheFile) {
            try {
                $cached = Get-Content -Path $cacheFile -Raw | ConvertFrom-Json
                if ($this.IsCacheValid($cached)) {
                    # Load back into memory
                    $this.Cache[$cacheKey] = $cached
                    return $cached.Result
                } else {
                    Remove-Item -Path $cacheFile -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Debug "Failed to read cache file: $_"
            }
        }

        return $null
    }

    [void] Set([string]$FilePath, [object]$Result) {
        if (-not $this.Enabled) { return }

        $fileHash = $this.GetFileHash($FilePath)
        if (-not $fileHash) { return }

        $cacheKey = $this.GetCacheKey($FilePath, $fileHash)
        
        $cacheEntry = @{
            FilePath = $FilePath
            FileHash = $fileHash
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Result = $Result
        }

        # Store in memory
        $this.Cache[$cacheKey] = $cacheEntry

        # Store on disk
        if ($this.CacheDir) {
            try {
                $cacheFile = Join-Path $this.CacheDir "$([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cacheKey))).json"
                $cacheEntry | ConvertTo-Json -Depth 10 | Out-File -FilePath $cacheFile -Encoding UTF8
            } catch {
                Write-Debug "Failed to write cache file: $_"
            }
        }
    }

    [bool] IsCacheValid([object]$CacheEntry) {
        if (-not $CacheEntry) { return $false }
        
        try {
            $timestamp = [datetime]::Parse($CacheEntry.Timestamp)
            $age = ((Get-Date).ToUniversalTime() - $timestamp).TotalSeconds
            return $age -lt $this.MaxCacheAge
        } catch {
            return $false
        }
    }

    [void] Clear() {
        $this.Cache.Clear()
        
        if ($this.CacheDir -and (Test-Path $this.CacheDir)) {
            try {
                Remove-Item -Path (Join-Path $this.CacheDir "*.json") -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Failed to clear cache directory: $_"
            }
        }
    }

    [int] GetCacheSize() {
        return $this.Cache.Count
    }
}

Export-ModuleMember -Function @()

# Export helper functions to create class instances
function New-PerformanceMetrics {
    return [PerformanceMetrics]::new()
}

function New-AnalysisCache {
    param(
        [bool]$Enabled = $true,
        [string]$CacheDir = '.powershield-cache'
    )
    return [AnalysisCache]::new($Enabled, $CacheDir)
}

Export-ModuleMember -Function New-PerformanceMetrics, New-AnalysisCache

