#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    PowerShield CLI - Comprehensive PowerShell Security Platform
.DESCRIPTION
    Command-line interface for PowerShield security analysis, hook management,
    and configuration operations.
.NOTES
    Version: 1.2.0
    Author: PowerShield Project
.EXAMPLE
    pwsh powershield.ps1 analyze ./scripts
    pwsh powershield.ps1 install-hooks
    pwsh powershield.ps1 config validate
#>

param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('analyze', 'install-hooks', 'uninstall-hooks', 'config', 'version', 'help')]
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

# Import modules
try {
    # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Controlled path within repository
    Import-Module "$scriptRoot/src/PowerShellSecurityAnalyzer.psm1" -Force -ErrorAction Stop
    # POWERSHIELD-SUPPRESS-NEXT: DangerousModules - Controlled path within repository
    Import-Module "$scriptRoot/src/ConfigLoader.psm1" -Force -ErrorAction Stop
} catch {
    Write-Error "Failed to load PowerShield modules: $_"
    exit 1
}

#region Command Functions

function Invoke-Analyze {
    <#
    .SYNOPSIS
        Analyze PowerShell scripts for security violations
    #>
    param(
        [string]$Path = ".",
        [ValidateSet('json', 'sarif', 'markdown', 'text')]
        [string]$Format = 'text',
        [string]$OutputFile,
        [switch]$Baseline,
        [switch]$EnableSuppressions
    )
    
    $targetPath = Resolve-Path $Path -ErrorAction SilentlyContinue
    if (-not $targetPath) {
        Write-Error "Path not found: $Path"
        exit 1
    }
    
    Write-Info "Analyzing: $targetPath"
    
    # Analyze
    if (Test-Path $targetPath -PathType Container) {
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
    
    # Display results
    if ($Format -eq 'text') {
        Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
        Write-Host "PowerShield Security Analysis Results" -ForegroundColor Cyan
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
        
        Write-Host "`nFiles Analyzed: $($result.TotalFiles)" -ForegroundColor White
        Write-Host "Total Violations: $($result.TotalViolations)" -ForegroundColor White
        
        if ($result.Summary) {
            Write-Host "`nSeverity Breakdown:" -ForegroundColor White
            foreach ($severity in @('Critical', 'High', 'Medium', 'Low')) {
                $count = $result.Summary["Total$severity"]
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
        if ($result.TotalViolations -gt 0) {
            $allViolations = @()
            foreach ($fileResult in $result.Results) {
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
    
    # Export results if requested
    if ($OutputFile) {
        switch ($Format) {
            'json' {
                $result | ConvertTo-Json -Depth 10 | Out-File $OutputFile
                Write-Success "Results exported to: $OutputFile"
            }
            'sarif' {
                # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Controlled path within repository
                . "$scriptRoot/scripts/Convert-ToSARIF.ps1"
                $jsonTemp = [System.IO.Path]::GetTempFileName()
                $result | ConvertTo-Json -Depth 10 | Out-File $jsonTemp
                Convert-ToSARIF -InputFile $jsonTemp -OutputFile $OutputFile
                Remove-Item $jsonTemp -Force
                Write-Success "SARIF results exported to: $OutputFile"
            }
            'markdown' {
                # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Controlled path within repository
                . "$scriptRoot/scripts/Generate-SecurityReport.ps1"
                $jsonTemp = [System.IO.Path]::GetTempFileName()
                $result | ConvertTo-Json -Depth 10 | Out-File $jsonTemp
                Generate-SecurityReport -InputFile $jsonTemp -OutputFile $OutputFile
                Remove-Item $jsonTemp -Force
                Write-Success "Markdown report exported to: $OutputFile"
            }
        }
    }
    
    # Exit with appropriate code
    if ($config.CI -and $config.CI.fail_on) {
        $shouldFail = $false
        foreach ($severity in $config.CI.fail_on) {
            $count = $result.Summary["Total$severity"]
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

function Install-Hooks {
    <#
    .SYNOPSIS
        Install PowerShield pre-commit hook
    #>
    param(
        [switch]$Force
    )
    
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
        Write-Info "Use -Force to overwrite"
        
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

function Uninstall-Hooks {
    <#
    .SYNOPSIS
        Uninstall PowerShield pre-commit hook
    #>
    
    $gitDir = git rev-parse --git-dir 2>$null
    if (-not $gitDir) {
        Write-Error "Not a git repository"
        exit 1
    }
    
    $gitDir = Resolve-Path $gitDir
    $targetHook = Join-Path $gitDir "hooks/pre-commit"
    
    if (-not (Test-Path $targetHook)) {
        Write-Warning "No pre-commit hook found"
        exit 0
    }
    
    # Check if it's a PowerShield hook
    $hookContent = Get-Content $targetHook -Raw
    if ($hookContent -notmatch 'PowerShield') {
        Write-Warning "The pre-commit hook does not appear to be a PowerShield hook"
        $response = Read-Host "Remove anyway? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Info "Uninstallation cancelled"
            exit 0
        }
    }
    
    try {
        Remove-Item $targetHook -Force
        Write-Success "Pre-commit hook uninstalled successfully"
    } catch {
        Write-Error "Failed to uninstall hook: $_"
        exit 1
    }
}

function Invoke-Config {
    <#
    .SYNOPSIS
        Configuration management commands
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
            $configPath = Join-Path $scriptRoot ".powershield.yml"
            if (Test-Path $configPath) {
                Write-Warning "Configuration already exists: $configPath"
                exit 0
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

function Show-Version {
    <#
    .SYNOPSIS
        Display PowerShield version information
    #>
    Write-Host "PowerShield - Comprehensive PowerShell Security Platform" -ForegroundColor Cyan
    Write-Host "Version: 1.2.0" -ForegroundColor White
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host "Platform: $($PSVersionTable.Platform)" -ForegroundColor Gray
}

function Show-Help {
    <#
    .SYNOPSIS
        Display help information
    #>
    Write-Host @"
PowerShield CLI - Comprehensive PowerShell Security Platform

USAGE:
    pwsh powershield.ps1 <command> [options]

COMMANDS:
    analyze [path]           Analyze PowerShell scripts for security violations
                            Options:
                              -Format <json|sarif|markdown|text>
                              -OutputFile <path>
                              -EnableSuppressions
                              
    install-hooks           Install pre-commit hook for local validation
                           Options:
                             -Force    Overwrite existing hook
                             
    uninstall-hooks        Remove pre-commit hook
    
    config <subcommand>    Configuration management
                          Subcommands:
                            validate   - Validate configuration file
                            show       - Display current configuration
                            init       - Create default configuration
    
    version                Display version information
    
    help                   Display this help message

EXAMPLES:
    # Analyze current directory
    pwsh powershield.ps1 analyze
    
    # Analyze specific path with JSON output
    pwsh powershield.ps1 analyze ./scripts -Format json -OutputFile results.json
    
    # Install pre-commit hook
    pwsh powershield.ps1 install-hooks
    
    # Validate configuration
    pwsh powershield.ps1 config validate

DOCUMENTATION:
    https://github.com/J-Ellette/PowerShield

"@ -ForegroundColor White
}

#endregion

#region Main Execution

switch ($Command) {
    'analyze' {
        $params = @{}
        for ($i = 0; $i -lt $Arguments.Count; $i++) {
            switch ($Arguments[$i]) {
                '-Format' {
                    $params['Format'] = $Arguments[++$i]
                }
                '-OutputFile' {
                    $params['OutputFile'] = $Arguments[++$i]
                }
                '-EnableSuppressions' {
                    $params['EnableSuppressions'] = $true
                }
                '-Baseline' {
                    $params['Baseline'] = $true
                }
                default {
                    if (-not $params.ContainsKey('Path')) {
                        $params['Path'] = $Arguments[$i]
                    }
                }
            }
        }
        Invoke-Analyze @params
    }
    
    'install-hooks' {
        $force = $Arguments -contains '-Force'
        Install-Hooks -Force:$force
    }
    
    'uninstall-hooks' {
        Uninstall-Hooks
    }
    
    'config' {
        if ($Arguments.Count -eq 0) {
            Write-Error "Config subcommand required"
            Show-Help
            exit 1
        }
        Invoke-Config -SubCommand $Arguments[0]
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
