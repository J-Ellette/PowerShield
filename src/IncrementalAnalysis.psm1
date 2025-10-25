#Requires -Version 7.0

<#
.SYNOPSIS
    Incremental analysis support for PowerShield
.DESCRIPTION
    Provides Git-aware change detection to analyze only modified files in CI/CD environments.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

class GitChangeDetector {
    [string]$WorkspacePath
    [bool]$IsGitRepository
    [string]$BaseBranch
    [string]$TargetBranch

    GitChangeDetector([string]$workspacePath) {
        $this.WorkspacePath = $workspacePath
        $this.IsGitRepository = $this.DetectGitRepository()
        $this.BaseBranch = 'main'
        $this.TargetBranch = 'HEAD'
    }

    [bool] DetectGitRepository() {
        $gitDir = Join-Path $this.WorkspacePath '.git'
        return Test-Path $gitDir
    }

    [string[]] GetChangedFiles() {
        if (-not $this.IsGitRepository) {
            Write-Verbose "Not a Git repository, cannot detect changed files"
            return @()
        }

        $changedFiles = @()

        try {
            # Try to detect base branch from environment variables (CI/CD)
            $ciBaseBranch = $this.DetectCIBaseBranch()
            if ($ciBaseBranch) {
                $this.BaseBranch = $ciBaseBranch
            }

            # Get changed files compared to base branch
            Push-Location $this.WorkspacePath
            try {
                # First, try to get merge base
                $mergeBase = git merge-base $this.BaseBranch $this.TargetBranch 2>$null
                
                if ($LASTEXITCODE -eq 0 -and $mergeBase) {
                    # Get files changed since merge base
                    $gitOutput = git diff --name-only $mergeBase...$this.TargetBranch 2>&1
                } else {
                    # Fallback: get uncommitted changes + last commit
                    $gitOutput = git diff --name-only HEAD 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        # Try staged files
                        $gitOutput = git diff --cached --name-only 2>&1
                    }
                }

                if ($LASTEXITCODE -eq 0) {
                    $changedFiles = $gitOutput | Where-Object { $_ -match '\.(ps1|psm1|psd1)$' }
                }
            } finally {
                Pop-Location
            }

            # Convert to full paths and filter for existing files
            $fullPaths = @()
            foreach ($file in $changedFiles) {
                $fullPath = Join-Path $this.WorkspacePath $file
                if (Test-Path $fullPath) {
                    $fullPaths += $fullPath
                }
            }

            Write-Verbose "Detected $($fullPaths.Count) changed PowerShell files"
            return $fullPaths

        } catch {
            Write-Warning "Failed to detect changed files: $_"
            return @()
        }
    }

    [string] DetectCIBaseBranch() {
        # GitHub Actions
        if ($env:GITHUB_BASE_REF) {
            return "origin/$env:GITHUB_BASE_REF"
        }
        
        # Azure DevOps
        if ($env:SYSTEM_PULLREQUEST_TARGETBRANCH) {
            return $env:SYSTEM_PULLREQUEST_TARGETBRANCH
        }
        
        # GitLab CI
        if ($env:CI_MERGE_REQUEST_TARGET_BRANCH_NAME) {
            return "origin/$env:CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
        }
        
        # Jenkins
        if ($env:CHANGE_TARGET) {
            return "origin/$env:CHANGE_TARGET"
        }
        
        return $null
    }

    [string[]] GetAllPowerShellFiles() {
        return Get-ChildItem -Path $this.WorkspacePath -Recurse -Include "*.ps1", "*.psm1", "*.psd1" -ErrorAction SilentlyContinue | 
               Select-Object -ExpandProperty FullName
    }
}

function Get-ChangedPowerShellFiles {
    <#
    .SYNOPSIS
        Gets PowerShell files that have changed in the current Git branch
    .DESCRIPTION
        Detects changed PowerShell files compared to the base branch using Git
    .PARAMETER WorkspacePath
        The workspace path (Git repository root)
    .PARAMETER BaseBranch
        The base branch to compare against (default: main)
    .EXAMPLE
        Get-ChangedPowerShellFiles -WorkspacePath . -BaseBranch main
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspacePath,
        
        [Parameter(Mandatory = $false)]
        [string]$BaseBranch = 'main'
    )

    $detector = [GitChangeDetector]::new($WorkspacePath)
    if ($BaseBranch) {
        $detector.BaseBranch = $BaseBranch
    }
    
    return $detector.GetChangedFiles()
}

function Test-GitRepository {
    <#
    .SYNOPSIS
        Tests if a directory is a Git repository
    .PARAMETER Path
        The path to test
    .EXAMPLE
        Test-GitRepository -Path .
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $gitDir = Join-Path $Path '.git'
    return Test-Path $gitDir
}

Export-ModuleMember -Function Get-ChangedPowerShellFiles, Test-GitRepository
