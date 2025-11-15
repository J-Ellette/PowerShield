#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Webhook testing utility for PowerShield
.DESCRIPTION
    Tests webhook configurations by sending sample notifications to configured endpoints.
    Supports Slack, Microsoft Teams, and generic webhook formats.
.PARAMETER ConfigPath
    Path to PowerShield configuration file. Defaults to .powershield.yml
.PARAMETER Interactive
    Run in interactive mode with user prompts
.PARAMETER DryRun
    Generate payloads without sending them
.EXAMPLE
    ./Test-Webhooks.ps1
.EXAMPLE
    ./Test-Webhooks.ps1 -ConfigPath .powershield.yml -Interactive
.EXAMPLE
    ./Test-Webhooks.ps1 -DryRun
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = '.powershield.yml',
    
    [Parameter(Mandatory=$false)]
    [switch]$Interactive,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

# Import required modules
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptDir '../src/WebhookNotifier.psm1'
$configLoaderPath = Join-Path $scriptDir '../src/ConfigLoader.psm1'

if (-not (Test-Path $modulePath)) {
    Write-Error "WebhookNotifier module not found at: $modulePath"
    exit 1
}

if (-not (Test-Path $configLoaderPath)) {
    Write-Error "ConfigLoader module not found at: $configLoaderPath"
    exit 1
}

Import-Module $modulePath -Force
Import-Module $configLoaderPath -Force

Write-Host "╔════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   PowerShield Webhook Testing Utility                 ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Load configuration
if (Test-Path $ConfigPath) {
    Write-Host "Loading configuration from: $ConfigPath" -ForegroundColor Cyan
    $config = Import-PowerShieldConfiguration -WorkspacePath (Split-Path $ConfigPath -Parent)
    $webhookConfigs = $config.Webhooks
} else {
    Write-Warning "Configuration file not found: $ConfigPath"
    Write-Host "Using example webhook configuration..." -ForegroundColor Yellow
    
    # Example configurations
    $webhookConfigs = @(
        @{
            url = 'https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL'
            format = 'Slack'
            events = @('critical_found', 'analysis_complete')
            severity_filter = @('Critical', 'High')
        },
        @{
            url = 'https://outlook.office.com/webhook/EXAMPLE/TEAMS/WEBHOOK'
            format = 'Teams'
            events = @('critical_found')
            severity_filter = @('Critical')
        }
    )
}

if (-not $webhookConfigs -or $webhookConfigs.Count -eq 0) {
    Write-Host "No webhooks configured." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To configure webhooks, add the following to your .powershield.yml:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "webhooks:" -ForegroundColor Gray
    Write-Host "  - url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'" -ForegroundColor Gray
    Write-Host "    format: 'Slack'" -ForegroundColor Gray
    Write-Host "    events: ['critical_found', 'analysis_complete']" -ForegroundColor Gray
    Write-Host "    severity_filter: ['Critical', 'High']" -ForegroundColor Gray
    Write-Host ""
    exit 0
}

Write-Host "Found $($webhookConfigs.Count) webhook configuration(s)" -ForegroundColor Green
Write-Host ""

# Create sample analysis result
$sampleResult = @{
    TotalViolations = 8
    FilesAnalyzed = 15
    Summary = @{
        Critical = 2
        High = 3
        Medium = 2
        Low = 1
    }
    Results = @(
        @{
            FilePath = 'src/Example.ps1'
            Violations = @(
                @{
                    RuleId = 'CredentialExposure'
                    Severity = 'Critical'
                    Message = 'Plaintext password detected: ConvertTo-SecureString with -AsPlainText and -Force'
                    LineNumber = 15
                },
                @{
                    RuleId = 'InsecureHashAlgorithms'
                    Severity = 'High'
                    Message = 'Insecure hash algorithm MD5 detected'
                    LineNumber = 42
                }
            )
        },
        @{
            FilePath = 'scripts/Deploy.ps1'
            Violations = @(
                @{
                    RuleId = 'CommandInjection'
                    Severity = 'Critical'
                    Message = 'Unsafe Invoke-Expression detected with variable input'
                    LineNumber = 88
                }
            )
        }
    )
}

# Sample context
$sampleContext = @{
    repository = 'PowerShield/TestRepository'
    branch = 'main'
    commit = 'abc123def456789'
    build_url = 'https://github.com/PowerShield/TestRepository/actions/runs/12345678'
    platform = 'GitHub Actions'
}

# Test each webhook
$notifier = New-WebhookNotifier -WebhookConfigs $webhookConfigs

foreach ($i in 0..($webhookConfigs.Count - 1)) {
    $webhook = $webhookConfigs[$i]
    
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "Webhook #$($i + 1)" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "URL:              $($webhook.url)" -ForegroundColor White
    Write-Host "Format:           $($webhook.format)" -ForegroundColor White
    Write-Host "Events:           $($webhook.events -join ', ')" -ForegroundColor White
    Write-Host "Severity Filter:  $($webhook.severity_filter -join ', ')" -ForegroundColor White
    Write-Host ""
    
    # Generate payload
    try {
        Write-Host "Generating payload..." -ForegroundColor Cyan
        $webhookObj = $notifier.Webhooks[$i]
        $payload = $notifier.BuildPayload($webhook.format, 'analysis_complete', $sampleResult, $sampleContext)
        Write-Host "✓ Payload generated successfully" -ForegroundColor Green
        Write-Host ""
        
        # Display payload
        Write-Host "Payload Preview:" -ForegroundColor Cyan
        Write-Host "────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        $payload | ConvertTo-Json -Depth 10 | Write-Host -ForegroundColor Gray
        Write-Host "────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        
        if ($DryRun) {
            Write-Host "✓ Dry run mode - skipping actual webhook send" -ForegroundColor Yellow
            Write-Host ""
            continue
        }
        
        # Send webhook
        if ($Interactive) {
            $confirm = Read-Host "Send test webhook to this endpoint? (y/n)"
            if ($confirm -ne 'y') {
                Write-Host "Skipped" -ForegroundColor Yellow
                Write-Host ""
                continue
            }
        }
        
        Write-Host "Sending webhook..." -ForegroundColor Cyan
        $notifier.SendWebhook($webhook.url, $payload, $webhook.format)
        Write-Host "✓ Webhook sent successfully!" -ForegroundColor Green
        
    } catch {
        Write-Host "✗ Error: $_" -ForegroundColor Red
    }
    
    Write-Host ""
}

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Testing Complete" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

if ($DryRun) {
    Write-Host "This was a dry run. No webhooks were actually sent." -ForegroundColor Yellow
    Write-Host "Run without -DryRun to send test webhooks to the configured endpoints." -ForegroundColor Yellow
} else {
    Write-Host "Check your Slack/Teams channels for the test notifications." -ForegroundColor Cyan
}
