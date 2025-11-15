#Requires -Version 7.0
#Requires -Module Pester

<#
.SYNOPSIS
    Integration tests for WebhookNotifier and PesterIntegration modules
.DESCRIPTION
    Tests the enterprise integration features including webhook notifications
    and Pester security test generation.
#>

Describe "WebhookNotifier Integration Tests" {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '../src/WebhookNotifier.psm1'
        Import-Module $modulePath -Force
        
        # Sample test data
        $script:testResult = @{
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
                            Message = 'Plaintext password detected'
                            LineNumber = 15
                        }
                    )
                }
            )
        }
        
        $script:testContext = @{
            repository = 'PowerShield/Test'
            branch = 'main'
            commit = 'abc123def456'
            build_url = 'https://github.com/PowerShield/Test/actions/runs/123'
            platform = 'GitHub Actions'
        }
    }
    
    Context "Webhook Configuration" {
        It "Should create webhook notifier with empty config" {
            $notifier = New-WebhookNotifier -WebhookConfigs @()
            $notifier | Should -Not -BeNullOrEmpty
            $notifier.Enabled | Should -Be $false
        }
        
        It "Should create webhook notifier with Slack config" {
            $config = @(
                @{
                    url = 'https://hooks.slack.com/test'
                    format = 'Slack'
                    events = @('analysis_complete')
                    severity_filter = @('Critical', 'High')
                }
            )
            
            $notifier = New-WebhookNotifier -WebhookConfigs $config
            $notifier | Should -Not -BeNullOrEmpty
            $notifier.Enabled | Should -Be $true
            $notifier.Webhooks.Count | Should -Be 1
            $notifier.Webhooks[0].Format | Should -Be 'Slack'
        }
        
        It "Should create webhook notifier with Teams config" {
            $config = @(
                @{
                    url = 'https://outlook.office.com/webhook/test'
                    format = 'Teams'
                    events = @('critical_found')
                    severity_filter = @('Critical')
                }
            )
            
            $notifier = New-WebhookNotifier -WebhookConfigs $config
            $notifier.Webhooks[0].Format | Should -Be 'Teams'
        }
        
        It "Should create webhook notifier with multiple configs" {
            $config = @(
                @{
                    url = 'https://hooks.slack.com/test1'
                    format = 'Slack'
                    events = @('analysis_complete')
                },
                @{
                    url = 'https://outlook.office.com/webhook/test2'
                    format = 'Teams'
                    events = @('critical_found')
                }
            )
            
            $notifier = New-WebhookNotifier -WebhookConfigs $config
            $notifier.Webhooks.Count | Should -Be 2
        }
    }
    
    Context "Payload Generation - Slack" {
        BeforeAll {
            $config = @(
                @{
                    url = 'https://hooks.slack.com/test'
                    format = 'Slack'
                    events = @('analysis_complete')
                    severity_filter = @('Critical', 'High')
                }
            )
            $script:notifier = New-WebhookNotifier -WebhookConfigs $config
        }
        
        It "Should generate valid Slack payload" {
            $payload = $script:notifier.BuildSlackPayload('analysis_complete', $script:testResult, $script:testContext)
            
            $payload | Should -Not -BeNullOrEmpty
            $payload.blocks | Should -Not -BeNullOrEmpty
            $payload.blocks.Count | Should -BeGreaterThan 0
        }
        
        It "Should include header block in Slack payload" {
            $payload = $script:notifier.BuildSlackPayload('analysis_complete', $script:testResult, $script:testContext)
            
            $headerBlock = $payload.blocks | Where-Object { $_.type -eq 'header' }
            $headerBlock | Should -Not -BeNullOrEmpty
            $headerBlock.text.text | Should -Match 'PowerShield'
        }
        
        It "Should include severity counts in Slack payload" {
            $payload = $script:notifier.BuildSlackPayload('analysis_complete', $script:testResult, $script:testContext)
            
            $json = $payload | ConvertTo-Json -Depth 10
            $json | Should -Match 'Critical'
            $json | Should -Match 'High'
        }
        
        It "Should include action button in Slack payload" {
            $payload = $script:notifier.BuildSlackPayload('analysis_complete', $script:testResult, $script:testContext)
            
            $actionsBlock = $payload.blocks | Where-Object { $_.type -eq 'actions' }
            $actionsBlock | Should -Not -BeNullOrEmpty
            $actionsBlock.elements[0].url | Should -Be $script:testContext.build_url
        }
    }
    
    Context "Payload Generation - Teams" {
        BeforeAll {
            $config = @(
                @{
                    url = 'https://outlook.office.com/webhook/test'
                    format = 'Teams'
                    events = @('analysis_complete')
                    severity_filter = @('Critical', 'High')
                }
            )
            $script:notifier = New-WebhookNotifier -WebhookConfigs $config
        }
        
        It "Should generate valid Teams payload" {
            $payload = $script:notifier.BuildTeamsPayload('analysis_complete', $script:testResult, $script:testContext)
            
            $payload | Should -Not -BeNullOrEmpty
            $payload.'@type' | Should -Be 'MessageCard'
            $payload.themeColor | Should -Not -BeNullOrEmpty
        }
        
        It "Should include facts in Teams payload" {
            $payload = $script:notifier.BuildTeamsPayload('analysis_complete', $script:testResult, $script:testContext)
            
            $payload.sections | Should -Not -BeNullOrEmpty
            $payload.sections[0].facts | Should -Not -BeNullOrEmpty
            $payload.sections[0].facts.Count | Should -BeGreaterThan 0
        }
        
        It "Should set theme color based on severity in Teams payload" {
            $payload = $script:notifier.BuildTeamsPayload('analysis_complete', $script:testResult, $script:testContext)
            
            # Should be red for critical violations
            $payload.themeColor | Should -Be 'FF0000'
        }
    }
    
    Context "Payload Generation - Generic" {
        BeforeAll {
            $config = @(
                @{
                    url = 'https://example.com/webhook'
                    format = 'Generic'
                    events = @('analysis_complete')
                }
            )
            $script:notifier = New-WebhookNotifier -WebhookConfigs $config
        }
        
        It "Should generate valid Generic payload" {
            $payload = $script:notifier.BuildGenericPayload('analysis_complete', $script:testResult, $script:testContext)
            
            $payload | Should -Not -BeNullOrEmpty
            $payload.event | Should -Be 'analysis_complete'
            $payload.total_violations | Should -Be 8
        }
        
        It "Should include summary in Generic payload" {
            $payload = $script:notifier.BuildGenericPayload('analysis_complete', $script:testResult, $script:testContext)
            
            $payload.summary | Should -Not -BeNullOrEmpty
            $payload.summary.critical | Should -Be 2
            $payload.summary.high | Should -Be 3
        }
    }
    
    Context "Event Filtering" {
        It "Should notify for matching event" {
            $config = @(
                @{
                    url = 'https://hooks.slack.com/test'
                    format = 'Slack'
                    events = @('analysis_complete')
                    severity_filter = @('Critical', 'High')
                }
            )
            
            $notifier = New-WebhookNotifier -WebhookConfigs $config
            $shouldNotify = $notifier.Webhooks[0].ShouldNotify('analysis_complete', $script:testResult.Summary)
            
            $shouldNotify | Should -Be $true
        }
        
        It "Should not notify for non-matching event" {
            $config = @(
                @{
                    url = 'https://hooks.slack.com/test'
                    format = 'Slack'
                    events = @('fix_applied')
                    severity_filter = @('Critical', 'High')
                }
            )
            
            $notifier = New-WebhookNotifier -WebhookConfigs $config
            $shouldNotify = $notifier.Webhooks[0].ShouldNotify('analysis_complete', $script:testResult.Summary)
            
            $shouldNotify | Should -Be $false
        }
        
        It "Should notify for critical_found when critical violations exist" {
            $config = @(
                @{
                    url = 'https://hooks.slack.com/test'
                    format = 'Slack'
                    events = @('critical_found')
                    severity_filter = @('Critical')
                }
            )
            
            $notifier = New-WebhookNotifier -WebhookConfigs $config
            $shouldNotify = $notifier.Webhooks[0].ShouldNotify('critical_found', $script:testResult.Summary)
            
            $shouldNotify | Should -Be $true
        }
    }
}

Describe "PesterIntegration Integration Tests" {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '../src/PesterIntegration.psm1'
        Import-Module $modulePath -Force
        
        # Sample test data
        $script:analysisResult = @{
            TotalViolations = 3
            FilesAnalyzed = 10
            Summary = @{
                Critical = 1
                High = 2
                Medium = 0
                Low = 0
            }
            Results = @(
                @{
                    FilePath = 'src/Example.ps1'
                    Violations = @(
                        @{
                            RuleId = 'InsecureHashAlgorithms'
                            Severity = 'High'
                            Message = 'MD5 detected'
                            LineNumber = 42
                        }
                    )
                }
            )
        }
        
        $script:appliedFixes = @(
            @{
                file = 'src/Example.ps1'
                rule_id = 'InsecureHashAlgorithms'
                line_number = 42
                original = 'MD5'
                fixed = 'SHA256'
            }
        )
    }
    
    Context "PesterIntegration Creation" {
        It "Should create Pester integration with defaults" {
            $config = @{
                enabled = $true
            }
            
            $integration = New-PesterIntegration -Configuration $config
            $integration | Should -Not -BeNullOrEmpty
            $integration.Enabled | Should -Be $true
            $integration.SecurityTestsPath | Should -Be './tests/Security.Tests.ps1'
        }
        
        It "Should create Pester integration with custom path" {
            $config = @{
                enabled = $true
                security_tests = './custom/path/Tests.ps1'
            }
            
            $integration = New-PesterIntegration -Configuration $config
            $integration.SecurityTestsPath | Should -Be './custom/path/Tests.ps1'
        }
        
        It "Should create Pester integration with all options" {
            $config = @{
                enabled = $true
                security_tests = './tests/Security.Tests.ps1'
                run_after_fixes = $true
                validate_fixes = $true
            }
            
            $integration = New-PesterIntegration -Configuration $config
            $integration.Enabled | Should -Be $true
            $integration.RunAfterFixes | Should -Be $true
            $integration.ValidateFixes | Should -Be $true
        }
    }
    
    Context "Security Test Generation" {
        It "Should generate security test script" {
            $config = @{
                enabled = $true
                security_tests = './tests/Security.Tests.ps1'
            }
            
            $integration = New-PesterIntegration -Configuration $config
            $testScript = $integration.GenerateSecurityTests($script:analysisResult, $script:appliedFixes)
            
            $testScript | Should -Not -BeNullOrEmpty
            $testScript | Should -Match 'Describe'
            $testScript | Should -Match 'PowerShield Security Validation'
        }
        
        It "Should include fix validation tests" {
            $config = @{
                enabled = $true
            }
            
            $integration = New-PesterIntegration -Configuration $config
            $testScript = $integration.GenerateSecurityTests($script:analysisResult, $script:appliedFixes)
            
            $testScript | Should -Match 'Security Fix Validation'
            $testScript | Should -Match 'InsecureHashAlgorithms'
            $testScript | Should -Match 'src/Example.ps1'
        }
        
        It "Should include rule-specific tests" {
            $config = @{
                enabled = $true
            }
            
            $integration = New-PesterIntegration -Configuration $config
            $testScript = $integration.GenerateSecurityTests($script:analysisResult, $script:appliedFixes)
            
            $testScript | Should -Match 'Rule-Specific Security Checks'
        }
        
        It "Should include file-level validation tests" {
            $config = @{
                enabled = $true
            }
            
            $integration = New-PesterIntegration -Configuration $config
            $testScript = $integration.GenerateSecurityTests($script:analysisResult, $script:appliedFixes)
            
            $testScript | Should -Match 'File-Level Security Validation'
        }
    }
    
    Context "Security Test Template" {
        It "Should create security test template" {
            $tempPath = Join-Path $TestDrive 'Template.Tests.ps1'
            
            $result = New-SecurityTestTemplate -OutputPath $tempPath
            
            $result | Should -Be $tempPath
            Test-Path $tempPath | Should -Be $true
        }
        
        It "Should generate valid Pester test structure" {
            $tempPath = Join-Path $TestDrive 'Template.Tests.ps1'
            New-SecurityTestTemplate -OutputPath $tempPath
            
            $content = Get-Content $tempPath -Raw
            $content | Should -Match '#Requires -Module Pester'
            $content | Should -Match 'Describe'
            $content | Should -Match 'Context'
            $content | Should -Match 'It'
        }
    }
}

Describe "ConfigLoader Integration Tests" {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '../src/ConfigLoader.psm1'
        Import-Module $modulePath -Force
    }
    
    Context "Configuration Loading" {
        It "Should load default configuration with integrations" {
            $config = Import-PowerShieldConfiguration
            
            $config | Should -Not -BeNullOrEmpty
            $config.Integrations | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Pester integration in default config" {
            $config = Import-PowerShieldConfiguration
            
            $config.Integrations.pester | Should -Not -BeNullOrEmpty
            $config.Integrations.pester.enabled | Should -Be $false
            $config.Integrations.pester.security_tests | Should -Be './tests/Security.Tests.ps1'
        }
    }
}
