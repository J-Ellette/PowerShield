#Requires -Version 7.0

<#
.SYNOPSIS
    CI/CD platform adapter interface for PowerShield
.DESCRIPTION
    Provides platform-agnostic CI/CD integration with unified context detection,
    artifact publishing, and comment posting capabilities.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

#region CI Context Classes

class CIContext {
    [string]$Provider
    [string]$Repository
    [string]$Branch
    [string]$CommitSha
    [string]$PullRequestId
    [string]$JobUrl
    [string]$BuildId
    [string]$WorkflowName
    [hashtable]$RawEnvironment
    
    CIContext() {
        $this.RawEnvironment = @{}
    }
    
    [string] ToString() {
        return "CI: $($this.Provider) | Repo: $($this.Repository) | Branch: $($this.Branch) | PR: $($this.PullRequestId)"
    }
}

class AnalysisArtifacts {
    [string]$SarifPath
    [string]$JsonPath
    [string]$JunitPath
    [string]$TapPath
    [string]$CsvPath
    [string]$MarkdownPath
    [string]$MetricsPath
    [string]$RunSummaryPath
    [string]$SuppressionsPath
    
    AnalysisArtifacts() {}
}

#endregion

#region ICIAdapter Interface

class ICIAdapter {
    [string]$Name
    [CIContext]$Context
    
    ICIAdapter() {
        $this.Context = [CIContext]::new()
    }
    
    # Detect if running in this CI environment
    [bool] IsDetected() {
        throw "IsDetected() must be implemented by derived class"
    }
    
    # Get CI context information
    [CIContext] GetContext() {
        throw "GetContext() must be implemented by derived class"
    }
    
    # Discover changed files in the repository
    [string[]] DiscoverChangedFiles([string]$basePath) {
        # Default implementation using git
        return $this.DiscoverChangedFilesViaGit($basePath)
    }
    
    # Upload SARIF results to platform security features
    [void] UploadSarif([string]$sarifPath) {
        Write-Verbose "SARIF upload not implemented for $($this.Name)"
    }
    
    # Post comment to PR/MR
    [void] PostComment([string]$markdown) {
        Write-Verbose "Comment posting not implemented for $($this.Name)"
    }
    
    # Publish artifacts
    [void] PublishArtifacts([AnalysisArtifacts]$artifacts) {
        Write-Verbose "Artifact publishing not implemented for $($this.Name)"
    }
    
    # Check if platform supports inline annotations
    [bool] SupportsInlineAnnotations() {
        return $false
    }
    
    # Create inline annotation (if supported)
    [void] CreateAnnotation([string]$filePath, [int]$line, [string]$level, [string]$message) {
        Write-Verbose "Annotations not supported for $($this.Name)"
    }
    
    # Helper: Discover changed files via git
    [string[]] DiscoverChangedFilesViaGit([string]$basePath) {
        try {
            # Inline git change detection
            $changedFiles = @()
            
            # Check if it's a git repository
            $gitDir = Join-Path $basePath '.git'
            if (-not (Test-Path $gitDir)) {
                Write-Verbose "Not a Git repository, cannot detect changed files"
                return @()
            }
            
            $originalLocation = Get-Location
            try {
                Set-Location $basePath
                
                # Try to detect base branch from CI environment
                $baseBranch = 'main'
                $targetBranch = 'HEAD'
                
                # GitHub Actions
                if ($env:GITHUB_BASE_REF) {
                    $baseBranch = "origin/$env:GITHUB_BASE_REF"
                }
                # Azure DevOps
                elseif ($env:SYSTEM_PULLREQUEST_TARGETBRANCH) {
                    $baseBranch = $env:SYSTEM_PULLREQUEST_TARGETBRANCH
                }
                # GitLab CI
                elseif ($env:CI_MERGE_REQUEST_TARGET_BRANCH_NAME) {
                    $baseBranch = "origin/$env:CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
                }
                
                # Try to get merge base
                $mergeBase = git merge-base $baseBranch $targetBranch 2>$null
                
                if ($LASTEXITCODE -eq 0 -and $mergeBase) {
                    $gitOutput = git diff --name-only $mergeBase...$targetBranch 2>&1
                } else {
                    # Fallback: get uncommitted changes
                    $gitOutput = git diff --name-only HEAD 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        $gitOutput = git diff --cached --name-only 2>&1
                    }
                }
                
                if ($LASTEXITCODE -eq 0) {
                    $changedFiles = $gitOutput | Where-Object { $_ -match '\.(ps1|psm1|psd1)$' }
                }
                
                # Convert to full paths
                $fullPaths = @()
                foreach ($file in $changedFiles) {
                    $fullPath = Join-Path $basePath $file
                    if (Test-Path $fullPath) {
                        $fullPaths += $fullPath
                    }
                }
                
                Write-Verbose "Detected $($fullPaths.Count) changed PowerShell files"
                return $fullPaths
            } finally {
                Set-Location $originalLocation
            }
        } catch {
            Write-Warning "Failed to detect changed files via git: $_"
            return @()
        }
    }
}

#endregion

#region GitHub Actions Adapter

class GitHubActionsAdapter : ICIAdapter {
    
    GitHubActionsAdapter() : base() {
        $this.Name = 'GitHub Actions'
    }
    
    [bool] IsDetected() {
        return $null -ne $env:GITHUB_ACTIONS
    }
    
    [CIContext] GetContext() {
        $context = [CIContext]::new()
        $context.Provider = 'github'
        
        # Repository info
        $context.Repository = $env:GITHUB_REPOSITORY
        $context.Branch = $env:GITHUB_REF_NAME
        $context.CommitSha = $env:GITHUB_SHA
        
        # PR info
        if ($env:GITHUB_EVENT_NAME -eq 'pull_request') {
            $context.PullRequestId = $env:GITHUB_REF -replace 'refs/pull/(\d+)/.*', '$1'
            # Try to get PR number from event payload
            if (Test-Path $env:GITHUB_EVENT_PATH) {
                try {
                    $event = Get-Content $env:GITHUB_EVENT_PATH -Raw | ConvertFrom-Json
                    if ($event.pull_request -and $event.pull_request.number) {
                        $context.PullRequestId = $event.pull_request.number.ToString()
                    }
                } catch {
                    Write-Verbose "Could not parse GitHub event payload: $_"
                }
            }
        }
        
        # Build info
        $context.BuildId = $env:GITHUB_RUN_ID
        $context.WorkflowName = $env:GITHUB_WORKFLOW
        $context.JobUrl = "$($env:GITHUB_SERVER_URL)/$($env:GITHUB_REPOSITORY)/actions/runs/$($env:GITHUB_RUN_ID)"
        
        # Store raw environment
        $context.RawEnvironment = @{
            GITHUB_ACTIONS = $env:GITHUB_ACTIONS
            GITHUB_REPOSITORY = $env:GITHUB_REPOSITORY
            GITHUB_REF = $env:GITHUB_REF
            GITHUB_SHA = $env:GITHUB_SHA
            GITHUB_EVENT_NAME = $env:GITHUB_EVENT_NAME
            GITHUB_RUN_ID = $env:GITHUB_RUN_ID
            GITHUB_WORKFLOW = $env:GITHUB_WORKFLOW
        }
        
        $this.Context = $context
        return $context
    }
    
    [bool] SupportsInlineAnnotations() {
        return $true
    }
    
    [void] CreateAnnotation([string]$filePath, [int]$line, [string]$level, [string]$message) {
        # GitHub Actions workflow command format
        $relativePath = $filePath
        if ($env:GITHUB_WORKSPACE) {
            $relativePath = $filePath -replace [regex]::Escape($env:GITHUB_WORKSPACE), ''
            $relativePath = $relativePath.TrimStart('\', '/')
        }
        
        $escapedMessage = $message -replace '%', '%25' -replace '\r', '%0D' -replace '\n', '%0A'
        Write-Output "::$level file=$relativePath,line=$line::$escapedMessage"
    }
}

#endregion

#region Azure DevOps Adapter

class AzureDevOpsAdapter : ICIAdapter {
    
    AzureDevOpsAdapter() : base() {
        $this.Name = 'Azure DevOps'
    }
    
    [bool] IsDetected() {
        return $null -ne $env:TF_BUILD
    }
    
    [CIContext] GetContext() {
        $context = [CIContext]::new()
        $context.Provider = 'azuredevops'
        
        # Repository info
        $context.Repository = "$($env:SYSTEM_TEAMPROJECT)/$($env:BUILD_REPOSITORY_NAME)"
        $context.Branch = $env:BUILD_SOURCEBRANCHNAME
        $context.CommitSha = $env:BUILD_SOURCEVERSION
        
        # PR info
        if ($env:BUILD_REASON -eq 'PullRequest') {
            $context.PullRequestId = $env:SYSTEM_PULLREQUEST_PULLREQUESTID
        }
        
        # Build info
        $context.BuildId = $env:BUILD_BUILDID
        $context.WorkflowName = $env:BUILD_DEFINITIONNAME
        $context.JobUrl = "$($env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)$($env:SYSTEM_TEAMPROJECT)/_build/results?buildId=$($env:BUILD_BUILDID)"
        
        # Store raw environment
        $context.RawEnvironment = @{
            TF_BUILD = $env:TF_BUILD
            SYSTEM_TEAMPROJECT = $env:SYSTEM_TEAMPROJECT
            BUILD_REPOSITORY_NAME = $env:BUILD_REPOSITORY_NAME
            BUILD_SOURCEBRANCHNAME = $env:BUILD_SOURCEBRANCHNAME
            BUILD_SOURCEVERSION = $env:BUILD_SOURCEVERSION
            BUILD_REASON = $env:BUILD_REASON
            BUILD_BUILDID = $env:BUILD_BUILDID
        }
        
        $this.Context = $context
        return $context
    }
    
    [bool] SupportsInlineAnnotations() {
        return $true
    }
    
    [void] CreateAnnotation([string]$filePath, [int]$line, [string]$level, [string]$message) {
        # Azure DevOps logging command format
        $taskLevel = switch ($level) {
            'error' { 'error' }
            'warning' { 'warning' }
            default { 'warning' }
        }
        
        Write-Output "##vso[task.logissue type=$taskLevel;sourcepath=$filePath;linenumber=$line]$message"
    }
}

#endregion

#region GitLab CI Adapter

class GitLabCIAdapter : ICIAdapter {
    
    GitLabCIAdapter() : base() {
        $this.Name = 'GitLab CI'
    }
    
    [bool] IsDetected() {
        return $null -ne $env:GITLAB_CI
    }
    
    [CIContext] GetContext() {
        $context = [CIContext]::new()
        $context.Provider = 'gitlab'
        
        # Repository info
        $context.Repository = $env:CI_PROJECT_PATH
        $context.Branch = $env:CI_COMMIT_REF_NAME
        $context.CommitSha = $env:CI_COMMIT_SHA
        
        # MR (Merge Request) info
        if ($env:CI_MERGE_REQUEST_IID) {
            $context.PullRequestId = $env:CI_MERGE_REQUEST_IID
        }
        
        # Build info
        $context.BuildId = $env:CI_JOB_ID
        $context.WorkflowName = $env:CI_PIPELINE_NAME
        $context.JobUrl = $env:CI_JOB_URL
        
        # Store raw environment
        $context.RawEnvironment = @{
            GITLAB_CI = $env:GITLAB_CI
            CI_PROJECT_PATH = $env:CI_PROJECT_PATH
            CI_COMMIT_REF_NAME = $env:CI_COMMIT_REF_NAME
            CI_COMMIT_SHA = $env:CI_COMMIT_SHA
            CI_MERGE_REQUEST_IID = $env:CI_MERGE_REQUEST_IID
            CI_JOB_ID = $env:CI_JOB_ID
            CI_JOB_URL = $env:CI_JOB_URL
        }
        
        $this.Context = $context
        return $context
    }
}

#endregion

#region Jenkins Adapter

class JenkinsAdapter : ICIAdapter {
    
    JenkinsAdapter() : base() {
        $this.Name = 'Jenkins'
    }
    
    [bool] IsDetected() {
        return $null -ne $env:JENKINS_URL
    }
    
    [CIContext] GetContext() {
        $context = [CIContext]::new()
        $context.Provider = 'jenkins'
        
        # Repository info
        if ($env:GIT_URL) {
            $context.Repository = $env:GIT_URL -replace '.*[:/]([^/]+/[^/]+?)(?:\.git)?$', '$1'
        }
        $context.Branch = $env:GIT_BRANCH -replace '^origin/', ''
        $context.CommitSha = $env:GIT_COMMIT
        
        # PR info (requires GitHub or GitLab plugins)
        if ($env:CHANGE_ID) {
            $context.PullRequestId = $env:CHANGE_ID
        }
        
        # Build info
        $context.BuildId = $env:BUILD_NUMBER
        $context.WorkflowName = $env:JOB_NAME
        $context.JobUrl = $env:BUILD_URL
        
        # Store raw environment
        $context.RawEnvironment = @{
            JENKINS_URL = $env:JENKINS_URL
            GIT_URL = $env:GIT_URL
            GIT_BRANCH = $env:GIT_BRANCH
            GIT_COMMIT = $env:GIT_COMMIT
            BUILD_NUMBER = $env:BUILD_NUMBER
            JOB_NAME = $env:JOB_NAME
            BUILD_URL = $env:BUILD_URL
        }
        
        $this.Context = $context
        return $context
    }
}

#endregion

#region CircleCI Adapter

class CircleCIAdapter : ICIAdapter {
    
    CircleCIAdapter() : base() {
        $this.Name = 'CircleCI'
    }
    
    [bool] IsDetected() {
        return $null -ne $env:CIRCLECI
    }
    
    [CIContext] GetContext() {
        $context = [CIContext]::new()
        $context.Provider = 'circleci'
        
        # Repository info
        $context.Repository = "$($env:CIRCLE_PROJECT_USERNAME)/$($env:CIRCLE_PROJECT_REPONAME)"
        $context.Branch = $env:CIRCLE_BRANCH
        $context.CommitSha = $env:CIRCLE_SHA1
        
        # PR info
        if ($env:CIRCLE_PULL_REQUEST) {
            $context.PullRequestId = $env:CIRCLE_PULL_REQUEST -replace '.*pull/(\d+).*', '$1'
        }
        
        # Build info
        $context.BuildId = $env:CIRCLE_BUILD_NUM
        $context.WorkflowName = $env:CIRCLE_JOB
        $context.JobUrl = $env:CIRCLE_BUILD_URL
        
        # Store raw environment
        $context.RawEnvironment = @{
            CIRCLECI = $env:CIRCLECI
            CIRCLE_PROJECT_USERNAME = $env:CIRCLE_PROJECT_USERNAME
            CIRCLE_PROJECT_REPONAME = $env:CIRCLE_PROJECT_REPONAME
            CIRCLE_BRANCH = $env:CIRCLE_BRANCH
            CIRCLE_SHA1 = $env:CIRCLE_SHA1
            CIRCLE_BUILD_NUM = $env:CIRCLE_BUILD_NUM
            CIRCLE_JOB = $env:CIRCLE_JOB
        }
        
        $this.Context = $context
        return $context
    }
}

#endregion

#region TeamCity Adapter

class TeamCityAdapter : ICIAdapter {
    
    TeamCityAdapter() : base() {
        $this.Name = 'TeamCity'
    }
    
    [bool] IsDetected() {
        return $null -ne $env:TEAMCITY_VERSION
    }
    
    [CIContext] GetContext() {
        $context = [CIContext]::new()
        $context.Provider = 'teamcity'
        
        # Repository info
        if ($env:BUILD_VCS_URL) {
            $context.Repository = $env:BUILD_VCS_URL -replace '.*[:/]([^/]+/[^/]+?)(?:\.git)?$', '$1'
        }
        $context.Branch = $env:BUILD_VCS_BRANCH -replace '^refs/heads/', ''
        $context.CommitSha = $env:BUILD_VCS_NUMBER
        
        # Build info
        $context.BuildId = $env:BUILD_NUMBER
        $context.WorkflowName = $env:BUILD_TYPE
        
        # Construct job URL
        if ($env:SERVER_URL -and $env:BUILD_ID) {
            $context.JobUrl = "$($env:SERVER_URL)/viewLog.html?buildId=$($env:BUILD_ID)"
        }
        
        # Store raw environment
        $context.RawEnvironment = @{
            TEAMCITY_VERSION = $env:TEAMCITY_VERSION
            BUILD_VCS_URL = $env:BUILD_VCS_URL
            BUILD_VCS_BRANCH = $env:BUILD_VCS_BRANCH
            BUILD_VCS_NUMBER = $env:BUILD_VCS_NUMBER
            BUILD_NUMBER = $env:BUILD_NUMBER
            BUILD_TYPE = $env:BUILD_TYPE
            SERVER_URL = $env:SERVER_URL
        }
        
        $this.Context = $context
        return $context
    }
    
    [bool] SupportsInlineAnnotations() {
        return $true
    }
    
    [void] CreateAnnotation([string]$filePath, [int]$line, [string]$level, [string]$message) {
        # TeamCity service message format
        $status = switch ($level) {
            'error' { 'ERROR' }
            'warning' { 'WARNING' }
            default { 'WARNING' }
        }
        
        # Escape special characters for TeamCity service messages
        $escapedMessage = $message -replace '\|', '||' -replace "'", "|'" -replace '\n', '|n' -replace '\r', '|r' -replace '\[', '|[' -replace '\]', '|]'
        $escapedPath = $filePath -replace '\|', '||' -replace "'", "|'" -replace '\n', '|n' -replace '\r', '|r' -replace '\[', '|[' -replace '\]', '|]'
        
        Write-Output "##teamcity[message text='$escapedMessage' status='$status' file='$escapedPath' line='$line']"
    }
}

#endregion

#region CI Adapter Factory

class CIAdapterFactory {
    static [ICIAdapter] CreateAdapter() {
        # Try to detect CI environment
        $adapters = @(
            [GitHubActionsAdapter]::new(),
            [AzureDevOpsAdapter]::new(),
            [GitLabCIAdapter]::new(),
            [JenkinsAdapter]::new(),
            [CircleCIAdapter]::new(),
            [TeamCityAdapter]::new()
        )
        
        foreach ($adapter in $adapters) {
            if ($adapter.IsDetected()) {
                Write-Verbose "Detected CI environment: $($adapter.Name)"
                return $adapter
            }
        }
        
        Write-Verbose "No CI environment detected, using generic adapter"
        return [GenericCIAdapter]::new()
    }
}

# Helper function to create adapter (exported)
function New-CIAdapter {
    [CmdletBinding()]
    param()
    
    return [CIAdapterFactory]::CreateAdapter()
}

#endregion

#region Generic Adapter (Fallback)

class GenericCIAdapter : ICIAdapter {
    
    GenericCIAdapter() : base() {
        $this.Name = 'Generic'
    }
    
    [bool] IsDetected() {
        return $true  # Always available as fallback
    }
    
    [CIContext] GetContext() {
        $context = [CIContext]::new()
        $context.Provider = 'generic'
        
        # Try to get context from git
        try {
            $context.Repository = git config --get remote.origin.url 2>$null
            if ($context.Repository) {
                $context.Repository = $context.Repository -replace '.*[:/]([^/]+/[^/]+?)(?:\.git)?$', '$1'
            }
            
            $context.Branch = git rev-parse --abbrev-ref HEAD 2>$null
            $context.CommitSha = git rev-parse HEAD 2>$null
        } catch {
            Write-Verbose "Failed to get git context: $_"
        }
        
        $this.Context = $context
        return $context
    }
}

#endregion

# Export classes and factory
Export-ModuleMember -Function New-CIAdapter
