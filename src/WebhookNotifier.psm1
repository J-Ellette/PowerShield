#Requires -Version 7.0

<#
.SYNOPSIS
    Webhook notification system for PowerShield
.DESCRIPTION
    Sends security analysis notifications to Slack, Microsoft Teams, and other webhook endpoints
    with rich formatting and event filtering.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

class WebhookNotification {
    [string]$Url
    [string]$Format  # Slack, Teams, Generic
    [string[]]$Events
    [string[]]$SeverityFilter
    
    WebhookNotification([hashtable]$config) {
        $this.Url = $config.url
        $this.Format = if ($config.format) { $config.format } else { 'Generic' }
        $this.Events = if ($config.events) { $config.events } else { @('analysis_complete') }
        $this.SeverityFilter = if ($config.severity_filter) { $config.severity_filter } else { @('Critical', 'High', 'Medium', 'Low') }
    }
    
    [bool] ShouldNotify([string]$event, [hashtable]$summary) {
        # Check if event matches
        if ($event -notin $this.Events) {
            return $false
        }
        
        # Check if any violations match severity filter
        if ($event -eq 'critical_found') {
            foreach ($severity in $this.SeverityFilter) {
                $key = "$severity"
                if ($summary.ContainsKey($key) -and $summary[$key] -gt 0) {
                    return $true
                }
            }
            return $false
        }
        
        return $true
    }
}

class WebhookNotifier {
    [WebhookNotification[]]$Webhooks
    [bool]$Enabled
    
    WebhookNotifier([array]$webhookConfigs) {
        $this.Webhooks = @()
        $this.Enabled = $webhookConfigs.Count -gt 0
        
        foreach ($config in $webhookConfigs) {
            $this.Webhooks += [WebhookNotification]::new($config)
        }
    }
    
    [void] SendNotification([string]$event, [hashtable]$analysisResult, [hashtable]$context) {
        if (-not $this.Enabled) {
            return
        }
        
        foreach ($webhook in $this.Webhooks) {
            if ($webhook.ShouldNotify($event, $analysisResult.Summary)) {
                try {
                    $payload = $this.BuildPayload($webhook.Format, $event, $analysisResult, $context)
                    $this.SendWebhook($webhook.Url, $payload, $webhook.Format)
                    Write-Verbose "Webhook notification sent to $($webhook.Url) for event: $event"
                } catch {
                    Write-Verbose "Failed to send webhook notification: $_"
                }
            }
        }
        return
    }
    
    [hashtable] BuildPayload([string]$format, [string]$event, [hashtable]$result, [hashtable]$context) {
        switch ($format) {
            'Slack' { return $this.BuildSlackPayload($event, $result, $context) }
            'Teams' { return $this.BuildTeamsPayload($event, $result, $context) }
            default { return $this.BuildGenericPayload($event, $result, $context) }
        }
        return $this.BuildGenericPayload($event, $result, $context)
    }
    
    [hashtable] BuildSlackPayload([string]$event, [hashtable]$result, [hashtable]$context) {
        $summary = $result.Summary
        $critical = if ($summary.Critical) { $summary.Critical } else { 0 }
        $high = if ($summary.High) { $summary.High } else { 0 }
        $medium = if ($summary.Medium) { $summary.Medium } else { 0 }
        $low = if ($summary.Low) { $summary.Low } else { 0 }
        $total = if ($result.TotalViolations) { $result.TotalViolations } else { 0 }
        
        # Determine status color
        $color = if ($critical -gt 0) { '#FF0000' } elseif ($high -gt 0) { '#FF6600' } elseif ($medium -gt 0) { '#FFAA00' } else { '#00AA00' }
        
        # Build status text
        $statusEmoji = if ($total -eq 0) { '✅' } elseif ($critical -gt 0) { '🚨' } elseif ($high -gt 0) { '⚠️' } else { 'ℹ️' }
        $statusText = if ($total -eq 0) { 'No violations found' } else { "$total violation(s) detected" }
        
        # Build repository info
        $repoName = if ($context.repository) { $context.repository } else { 'Unknown Repository' }
        $branch = if ($context.branch) { $context.branch } else { 'unknown' }
        $commit = if ($context.commit) { $context.commit.Substring(0, 7) } else { 'unknown' }
        $buildUrl = if ($context.build_url) { $context.build_url } else { '#' }
        
        $blocks = @(
            @{
                type = 'header'
                text = @{
                    type = 'plain_text'
                    text = "$statusEmoji PowerShield Security Analysis"
                    emoji = $true
                }
            },
            @{
                type = 'section'
                fields = @(
                    @{
                        type = 'mrkdwn'
                        text = "*Repository:*`n$repoName"
                    },
                    @{
                        type = 'mrkdwn'
                        text = "*Branch:*`n$branch"
                    },
                    @{
                        type = 'mrkdwn'
                        text = "*Commit:*`n$commit"
                    },
                    @{
                        type = 'mrkdwn'
                        text = "*Status:*`n$statusText"
                    }
                )
            },
            @{
                type = 'section'
                fields = @(
                    @{
                        type = 'mrkdwn'
                        text = "*Critical:*`n$critical"
                    },
                    @{
                        type = 'mrkdwn'
                        text = "*High:*`n$high"
                    },
                    @{
                        type = 'mrkdwn'
                        text = "*Medium:*`n$medium"
                    },
                    @{
                        type = 'mrkdwn'
                        text = "*Low:*`n$low"
                    }
                )
            }
        )
        
        # Add action button
        if ($buildUrl -ne '#') {
            $blocks += @{
                type = 'actions'
                elements = @(
                    @{
                        type = 'button'
                        text = @{
                            type = 'plain_text'
                            text = 'View Build'
                            emoji = $true
                        }
                        url = $buildUrl
                        style = if ($critical -gt 0) { 'danger' } elseif ($high -gt 0) { 'primary' } else { $null }
                    }
                )
            }
        }
        
        # Add top violations if any
        if ($total -gt 0 -and $result.Results) {
            $topViolations = @()
            $violationCount = 0
            
            foreach ($fileResult in $result.Results) {
                if ($fileResult.Violations) {
                    foreach ($violation in $fileResult.Violations) {
                        if ($violation.Severity -in @('Critical', 'High') -and $violationCount -lt 3) {
                            $topViolations += "• *$($violation.RuleId)*: $($violation.Message.Split("`n")[0])"
                            $violationCount++
                        }
                    }
                }
                if ($violationCount -ge 3) { break }
            }
            
            if ($topViolations.Count -gt 0) {
                $blocks += @{
                    type = 'section'
                    text = @{
                        type = 'mrkdwn'
                        text = "*Top Issues:*`n" + ($topViolations -join "`n")
                    }
                }
            }
        }
        
        return @{
            blocks = $blocks
            attachments = @(
                @{
                    color = $color
                    fallback = "PowerShield Analysis: $statusText"
                }
            )
        }
    }
    
    [hashtable] BuildTeamsPayload([string]$event, [hashtable]$result, [hashtable]$context) {
        $summary = $result.Summary
        $critical = if ($summary.Critical) { $summary.Critical } else { 0 }
        $high = if ($summary.High) { $summary.High } else { 0 }
        $medium = if ($summary.Medium) { $summary.Medium } else { 0 }
        $low = if ($summary.Low) { $summary.Low } else { 0 }
        $total = if ($result.TotalViolations) { $result.TotalViolations } else { 0 }
        
        # Determine theme color (hex without #)
        $themeColor = if ($critical -gt 0) { 'FF0000' } elseif ($high -gt 0) { 'FF6600' } elseif ($medium -gt 0) { 'FFAA00' } else { '00AA00' }
        
        # Build status text
        $statusEmoji = if ($total -eq 0) { '✅' } elseif ($critical -gt 0) { '🚨' } elseif ($high -gt 0) { '⚠️' } else { 'ℹ️' }
        
        # Build repository info
        $repoName = if ($context.repository) { $context.repository } else { 'Unknown Repository' }
        $branch = if ($context.branch) { $context.branch } else { 'unknown' }
        $commit = if ($context.commit) { $context.commit.Substring(0, 7) } else { 'unknown' }
        $buildUrl = if ($context.build_url) { $context.build_url } else { $null }
        
        $facts = @(
            @{
                name = 'Repository'
                value = $repoName
            },
            @{
                name = 'Branch'
                value = $branch
            },
            @{
                name = 'Commit'
                value = $commit
            },
            @{
                name = 'Critical'
                value = $critical.ToString()
            },
            @{
                name = 'High'
                value = $high.ToString()
            },
            @{
                name = 'Medium'
                value = $medium.ToString()
            },
            @{
                name = 'Low'
                value = $low.ToString()
            },
            @{
                name = 'Total Violations'
                value = $total.ToString()
            },
            @{
                name = 'Platform'
                value = if ($context.platform) { $context.platform } else { 'GitHub Actions' }
            }
        )
        
        $payload = @{
            '@type' = 'MessageCard'
            '@context' = 'https://schema.org/extensions'
            themeColor = $themeColor
            summary = "PowerShield Security Analysis - $total violation(s)"
            sections = @(
                @{
                    activityTitle = "$statusEmoji PowerShield Security Analysis"
                    activitySubtitle = if ($total -eq 0) { 'No violations found' } else { "$total violation(s) detected" }
                    facts = $facts
                }
            )
        }
        
        # Add potential action button
        if ($buildUrl) {
            $payload['potentialAction'] = @(
                @{
                    '@type' = 'OpenUri'
                    name = 'View Build'
                    targets = @(
                        @{
                            os = 'default'
                            uri = $buildUrl
                        }
                    )
                }
            )
        }
        
        return $payload
    }
    
    [hashtable] BuildGenericPayload([string]$event, [hashtable]$result, [hashtable]$context) {
        $summary = $result.Summary
        
        return @{
            event = $event
            timestamp = (Get-Date -Format 'o')
            repository = if ($context.repository) { $context.repository } else { 'unknown' }
            branch = if ($context.branch) { $context.branch } else { 'unknown' }
            commit = if ($context.commit) { $context.commit } else { 'unknown' }
            total_violations = if ($result.TotalViolations) { $result.TotalViolations } else { 0 }
            files_analyzed = if ($result.FilesAnalyzed) { $result.FilesAnalyzed } else { 0 }
            summary = @{
                critical = if ($summary.Critical) { $summary.Critical } else { 0 }
                high = if ($summary.High) { $summary.High } else { 0 }
                medium = if ($summary.Medium) { $summary.Medium } else { 0 }
                low = if ($summary.Low) { $summary.Low } else { 0 }
            }
            build_url = if ($context.build_url) { $context.build_url } else { $null }
        }
    }
    
    [void] SendWebhook([string]$url, [hashtable]$payload, [string]$format) {
        $json = $payload | ConvertTo-Json -Depth 10 -Compress
        
        $headers = @{
            'Content-Type' = 'application/json'
        }
        
        # Add User-Agent
        $headers['User-Agent'] = 'PowerShield-Webhook/1.0'
        
        $params = @{
            Uri = $url
            Method = 'POST'
            Headers = $headers
            Body = $json
            TimeoutSec = 10
        }
        
        try {
            $null = Invoke-RestMethod @params
            Write-Verbose "Webhook sent successfully to $url"
        } catch {
            Write-Warning "Failed to send webhook to ${url}: $_"
            throw
        }
        return
    }
}

function New-WebhookNotifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [array]$WebhookConfigs = @()
    )
    
    return [WebhookNotifier]::new($WebhookConfigs)
}

function Send-WebhookNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [WebhookNotifier]$Notifier,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('critical_found', 'analysis_complete', 'fix_applied')]
        [string]$Event,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisResult,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Context = @{}
    )
    
    $Notifier.SendNotification($Event, $AnalysisResult, $Context)
}

function Test-WebhookConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$WebhookConfigs
    )
    
    Write-Host "Testing webhook configurations..."
    
    $testResult = @{
        TotalViolations = 5
        FilesAnalyzed = 10
        Summary = @{
            Critical = 2
            High = 3
            Medium = 0
            Low = 0
        }
        Results = @(
            @{
                FilePath = 'test/script.ps1'
                Violations = @(
                    @{
                        RuleId = 'TestRule'
                        Severity = 'Critical'
                        Message = 'This is a test violation'
                        LineNumber = 42
                    }
                )
            }
        )
    }
    
    $testContext = @{
        repository = 'PowerShield/Test'
        branch = 'main'
        commit = 'abc123def456'
        build_url = 'https://github.com/PowerShield/Test/actions/runs/123'
        platform = 'Test'
    }
    
    $notifier = New-WebhookNotifier -WebhookConfigs $WebhookConfigs
    
    foreach ($webhook in $notifier.Webhooks) {
        Write-Host "`nTesting webhook: $($webhook.Url)"
        Write-Host "  Format: $($webhook.Format)"
        Write-Host "  Events: $($webhook.Events -join ', ')"
        Write-Host "  Severity Filter: $($webhook.SeverityFilter -join ', ')"
        
        try {
            $payload = $notifier.BuildPayload($webhook.Format, 'analysis_complete', $testResult, $testContext)
            Write-Host "  ✓ Payload generated successfully"
            Write-Host "  Payload preview:"
            $payload | ConvertTo-Json -Depth 10 | Write-Host
            
            # Ask for confirmation before sending
            $confirm = Read-Host "`n  Send test webhook? (y/n)"
            if ($confirm -eq 'y') {
                $notifier.SendWebhook($webhook.Url, $payload, $webhook.Format)
                Write-Host "  ✓ Test webhook sent successfully" -ForegroundColor Green
            } else {
                Write-Host "  - Skipped sending test webhook" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        }
    }
}

Export-ModuleMember -Function @(
    'New-WebhookNotifier',
    'Send-WebhookNotification',
    'Test-WebhookConfiguration'
)
