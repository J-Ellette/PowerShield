#Requires -Version 7.0

<#
.SYNOPSIS
    Performance profile management for PowerShield
.DESCRIPTION
    Provides performance optimization profiles (fast, balanced, thorough) to tune
    analysis speed vs comprehensiveness trade-offs.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

enum PerformanceProfile {
    Fast = 1
    Balanced = 2
    Thorough = 3
}

class ProfileConfiguration {
    [PerformanceProfile]$Profile
    [bool]$EnableParallel
    [int]$MaxThreads
    [int]$MaxFileSizeMB
    [bool]$EnableCaching
    [string[]]$SkipCategories
    [string[]]$SkipRules
    [bool]$DeepScan
    [int]$MaxDepth
    [double]$TimeoutPerFileSeconds
    
    ProfileConfiguration([PerformanceProfile]$profile) {
        $this.Profile = $profile
        $this.ApplyDefaults()
    }
    
    [void] ApplyDefaults() {
        switch ($this.Profile) {
            ([PerformanceProfile]::Fast) {
                $this.EnableParallel = $true
                $this.MaxThreads = [Environment]::ProcessorCount
                $this.MaxFileSizeMB = 5
                $this.EnableCaching = $true
                $this.DeepScan = $false
                $this.MaxDepth = 5
                $this.TimeoutPerFileSeconds = 10
                
                # Skip less critical categories in fast mode
                $this.SkipCategories = @('Low', 'Informational')
                
                # Skip computationally expensive rules
                $this.SkipRules = @(
                    'AdvancedDataFlowAnalysis',
                    'ComplexRegexAnalysis',
                    'DeepASTTraversal'
                )
            }
            
            ([PerformanceProfile]::Balanced) {
                $this.EnableParallel = $true
                $this.MaxThreads = [Math]::Max(1, [Environment]::ProcessorCount - 1)
                $this.MaxFileSizeMB = 10
                $this.EnableCaching = $true
                $this.DeepScan = $true
                $this.MaxDepth = 10
                $this.TimeoutPerFileSeconds = 30
                
                # No categories skipped in balanced mode
                $this.SkipCategories = @()
                
                # Only skip experimental rules
                $this.SkipRules = @('Experimental')
            }
            
            ([PerformanceProfile]::Thorough) {
                $this.EnableParallel = $true
                $this.MaxThreads = [Environment]::ProcessorCount
                $this.MaxFileSizeMB = 50
                $this.EnableCaching = $true
                $this.DeepScan = $true
                $this.MaxDepth = 20
                $this.TimeoutPerFileSeconds = 60
                
                # Include everything in thorough mode
                $this.SkipCategories = @()
                $this.SkipRules = @()
            }
        }
    }
    
    [bool] ShouldSkipRule([object]$rule) {
        # Check if rule category is skipped
        if ($rule.Category -and $this.SkipCategories -contains $rule.Category) {
            return $true
        }
        
        # Check if rule severity is skipped
        if ($rule.Severity -and $this.SkipCategories -contains $rule.Severity.ToString()) {
            return $true
        }
        
        # Check if specific rule is skipped
        if ($rule.Name -and $this.SkipRules -contains $rule.Name) {
            return $true
        }
        
        # Check if rule has experimental tag and we're not in thorough mode
        if ($rule.Tags -and $rule.Tags -contains 'Experimental' -and $this.Profile -ne [PerformanceProfile]::Thorough) {
            return $true
        }
        
        return $false
    }
    
    [string] ToString() {
        return "Profile: $($this.Profile), Parallel: $($this.EnableParallel), Threads: $($this.MaxThreads), Deep: $($this.DeepScan)"
    }
}

class ProfileManager {
    [ProfileConfiguration]$CurrentProfile
    [hashtable]$Metrics
    
    ProfileManager() {
        $this.CurrentProfile = [ProfileConfiguration]::new([PerformanceProfile]::Balanced)
        $this.Metrics = @{
            ProfileName = 'Balanced'
            RulesSkipped = 0
            FilesSkipped = 0
            TimesSaved = 0
        }
    }
    
    [void] SetProfile([string]$profileName) {
        $profile = switch ($profileName.ToLower()) {
            'fast' { [PerformanceProfile]::Fast }
            'balanced' { [PerformanceProfile]::Balanced }
            'thorough' { [PerformanceProfile]::Thorough }
            default {
                Write-Warning "Unknown profile '$profileName', using Balanced"
                [PerformanceProfile]::Balanced
            }
        }
        
        $this.CurrentProfile = [ProfileConfiguration]::new($profile)
        $this.Metrics.ProfileName = $profileName
        $this.Metrics.RulesSkipped = 0
        $this.Metrics.FilesSkipped = 0
        
        Write-Verbose "Performance profile set to: $($this.CurrentProfile.ToString())"
    }
    
    [ProfileConfiguration] GetProfile() {
        return $this.CurrentProfile
    }
    
    [bool] ShouldAnalyzeFile([string]$filePath) {
        # Check file size
        try {
            $fileInfo = Get-Item $filePath -ErrorAction Stop
            $fileSizeMB = $fileInfo.Length / 1MB
            
            if ($fileSizeMB -gt $this.CurrentProfile.MaxFileSizeMB) {
                Write-Verbose "Skipping large file ($([Math]::Round($fileSizeMB, 2)) MB): $filePath"
                $this.Metrics.FilesSkipped++
                return $false
            }
        } catch {
            Write-Warning "Could not check file size for: $filePath"
            return $true
        }
        
        return $true
    }
    
    [object[]] FilterRules([object[]]$rules) {
        $filteredRules = @()
        
        foreach ($rule in $rules) {
            if (-not $this.CurrentProfile.ShouldSkipRule($rule)) {
                $filteredRules += $rule
            } else {
                Write-Verbose "Skipping rule: $($rule.Name)"
                $this.Metrics.RulesSkipped++
            }
        }
        
        return $filteredRules
    }
    
    [hashtable] GetMetrics() {
        return $this.Metrics
    }
    
    [void] PrintSummary() {
        Write-Host "`nPerformance Profile Summary:" -ForegroundColor Cyan
        Write-Host "  Profile: $($this.Metrics.ProfileName)" -ForegroundColor White
        Write-Host "  Rules Skipped: $($this.Metrics.RulesSkipped)" -ForegroundColor Gray
        Write-Host "  Files Skipped: $($this.Metrics.FilesSkipped)" -ForegroundColor Gray
        
        if ($this.CurrentProfile.EnableParallel) {
            Write-Host "  Parallel Processing: Enabled ($($this.CurrentProfile.MaxThreads) threads)" -ForegroundColor Green
        } else {
            Write-Host "  Parallel Processing: Disabled" -ForegroundColor Gray
        }
    }
}

# Helper functions for easy access
function New-ProfileManager {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('fast', 'balanced', 'thorough')]
        [string]$Profile = 'balanced'
    )
    
    $manager = [ProfileManager]::new()
    $manager.SetProfile($Profile)
    return $manager
}

function Get-PerformanceProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('fast', 'balanced', 'thorough')]
        [string]$ProfileName = 'balanced'
    )
    
    $profile = switch ($ProfileName.ToLower()) {
        'fast' { [PerformanceProfile]::Fast }
        'balanced' { [PerformanceProfile]::Balanced }
        'thorough' { [PerformanceProfile]::Thorough }
        default { [PerformanceProfile]::Balanced }
    }
    
    return [ProfileConfiguration]::new($profile)
}

# Export members
Export-ModuleMember -Function New-ProfileManager, Get-PerformanceProfile
