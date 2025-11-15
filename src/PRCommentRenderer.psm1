#Requires -Version 7.0

<#
.SYNOPSIS
    Enhanced PR/MR comment renderer for PowerShield
.DESCRIPTION
    Generates rich, actionable markdown comments for pull requests and merge requests
    with severity summaries, top issues, code snippets, and compliance information.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

function New-EnhancedPRComment {
    <#
    .SYNOPSIS
        Generate an enhanced PR/MR comment from analysis results
    .PARAMETER Results
        PowerShield analysis results object
    .PARAMETER MaxTopIssues
        Maximum number of top issues to display (default: 5)
    .PARAMETER IncludeCodeSnippets
        Include code snippets in the comment
    .PARAMETER IncludeRemediation
        Include remediation suggestions
    .PARAMETER IncludeCompliance
        Include CWE and MITRE ATT&CK information
    .PARAMETER JobUrl
        CI/CD job URL for linking
    .PARAMETER ArtifactsUrl
        URL to full report artifacts
    .EXAMPLE
        $comment = New-EnhancedPRComment -Results $analysisResult -IncludeCodeSnippets
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Results,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxTopIssues = 5,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeCodeSnippets,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRemediation = $true,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeCompliance = $true,
        
        [Parameter(Mandatory = $false)]
        [string]$JobUrl,
        
        [Parameter(Mandatory = $false)]
        [string]$ArtifactsUrl,
        
        [Parameter(Mandatory = $false)]
        [string]$DocsUrl = 'https://github.com/J-Ellette/PowerShield/tree/main/docs'
    )
    
    $markdown = @()
    
    # Header
    $markdown += "## 🛡️ PowerShield Security Analysis"
    $markdown += ""
    
    # Extract violations
    $allViolations = @()
    if ($Results.Results) {
        foreach ($fileResult in $Results.Results) {
            if ($fileResult.Violations) {
                $allViolations += $fileResult.Violations
            }
        }
    } elseif ($Results.violations) {
        $allViolations = $Results.violations
    }
    
    # Calculate summary
    $summary = @{
        Critical = ($allViolations | Where-Object { $_.Severity -eq 'Critical' }).Count
        High = ($allViolations | Where-Object { $_.Severity -eq 'High' }).Count
        Medium = ($allViolations | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low = ($allViolations | Where-Object { $_.Severity -eq 'Low' }).Count
    }
    
    # Override with Results.Summary if available
    if ($Results.Summary) {
        if ($Results.Summary.TotalCritical) { $summary.Critical = $Results.Summary.TotalCritical }
        if ($Results.Summary.TotalHigh) { $summary.High = $Results.Summary.TotalHigh }
        if ($Results.Summary.TotalMedium) { $summary.Medium = $Results.Summary.TotalMedium }
        if ($Results.Summary.TotalLow) { $summary.Low = $Results.Summary.TotalLow }
    }
    
    $totalViolations = $summary.Critical + $summary.High + $summary.Medium + $summary.Low
    
    # Summary section with emojis
    $markdown += "### 📊 Summary"
    if ($totalViolations -eq 0) {
        $markdown += "✅ **No security violations found!** Great job! 🎉"
        $markdown += ""
        
        if ($Results.TotalFiles) {
            $markdown += "- **Files Analyzed**: $($Results.TotalFiles)"
        }
    } else {
        $markdown += "| Severity | Count | Status |"
        $markdown += "|----------|-------|--------|"
        
        if ($summary.Critical -gt 0) {
            $markdown += "| 🔴 **Critical** | **$($summary.Critical)** | ❌ Action Required |"
        } else {
            $markdown += "| 🔴 Critical | 0 | ✅ |"
        }
        
        if ($summary.High -gt 0) {
            $markdown += "| 🟠 **High** | **$($summary.High)** | ⚠️ Should Fix |"
        } else {
            $markdown += "| 🟠 High | 0 | ✅ |"
        }
        
        if ($summary.Medium -gt 0) {
            $markdown += "| 🟡 **Medium** | **$($summary.Medium)** | ⚡ Consider Fixing |"
        } else {
            $markdown += "| 🟡 Medium | 0 | ✅ |"
        }
        
        if ($summary.Low -gt 0) {
            $markdown += "| ⚪ Low | $($summary.Low) | 💡 Nice to Fix |"
        } else {
            $markdown += "| ⚪ Low | 0 | ✅ |"
        }
        
        $markdown += ""
        
        # Additional stats
        if ($Results.TotalFiles) {
            $markdown += "**Files Analyzed**: $($Results.TotalFiles) | **Total Issues**: $totalViolations"
            $markdown += ""
        }
    }
    
    # Top issues section
    if ($totalViolations -gt 0) {
        $markdown += "### 🔥 Top Issues"
        $markdown += ""
        
        # Sort by severity and take top N
        $severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
        $topViolations = $allViolations | Sort-Object { $severityOrder[$_.Severity] } | Select-Object -First $MaxTopIssues
        
        $issueNumber = 1
        foreach ($violation in $topViolations) {
            $severityEmoji = switch ($violation.Severity) {
                'Critical' { '🔴' }
                'High' { '🟠' }
                'Medium' { '🟡' }
                'Low' { '⚪' }
                default { '⚪' }
            }
            
            # Issue header
            $markdown += "#### $issueNumber. $severityEmoji **$($violation.RuleId)** ($($violation.Severity))"
            
            # Location
            $location = ""
            if ($violation.FilePath) {
                $location = "📄 ``$($violation.FilePath)``"
                if ($violation.LineNumber) {
                    $location += " (Line $($violation.LineNumber)"
                    if ($violation.Column) {
                        $location += ", Column $($violation.Column)"
                    }
                    $location += ")"
                }
                $markdown += $location
            }
            
            # Message
            if ($violation.Message) {
                $markdown += ""
                $markdown += "**Issue**: $($violation.Message)"
            }
            
            # Code snippet
            if ($IncludeCodeSnippets -and $violation.Code) {
                $markdown += ""
                $markdown += "``````powershell"
                $markdown += "# ❌ Current (Insecure)"
                $markdown += $violation.Code
                $markdown += "``````"
            }
            
            # Remediation
            if ($IncludeRemediation -and $violation.Remediation) {
                $markdown += ""
                if ($IncludeCodeSnippets) {
                    # Try to extract code from remediation
                    $remLines = $violation.Remediation -split "`n"
                    $hasCodeBlock = $false
                    $codeLines = @()
                    
                    foreach ($line in $remLines) {
                        if ($line -match '^``````') {
                            $hasCodeBlock = -not $hasCodeBlock
                        } elseif ($hasCodeBlock) {
                            $codeLines += $line
                        }
                    }
                    
                    if ($codeLines.Count -gt 0) {
                        $markdown += "``````powershell"
                        $markdown += "# ✅ Recommended (Secure)"
                        $markdown += ($codeLines -join "`n")
                        $markdown += "``````"
                    } else {
                        $markdown += "**Remediation**: $($violation.Remediation)"
                    }
                } else {
                    $markdown += "**Remediation**: $($violation.Remediation)"
                }
            }
            
            # CWE/MITRE if available
            if ($IncludeCompliance) {
                $complianceInfo = @()
                if ($violation.CWE) {
                    $complianceInfo += "CWE: $($violation.CWE)"
                }
                if ($violation.MitreAttack) {
                    if ($violation.MitreAttack -is [array]) {
                        $complianceInfo += "MITRE ATT&CK: $($violation.MitreAttack -join ', ')"
                    } else {
                        $complianceInfo += "MITRE ATT&CK: $($violation.MitreAttack)"
                    }
                }
                
                if ($complianceInfo.Count -gt 0) {
                    $markdown += ""
                    $markdown += "📋 " + ($complianceInfo -join ' | ')
                }
            }
            
            # Auto-fix availability
            if ($violation.AutoFixAvailable -or $violation.HasAutoFix) {
                $markdown += ""
                $markdown += "🔧 **Auto-fix available** - Run PowerShield auto-fix to apply this remediation automatically"
            }
            
            $markdown += ""
            $markdown += "---"
            $markdown += ""
            
            $issueNumber++
        }
        
        # Show count if there are more issues
        if ($allViolations.Count -gt $MaxTopIssues) {
            $remaining = $allViolations.Count - $MaxTopIssues
            $markdown += "_... and $remaining more issue(s). See full report for details._"
            $markdown += ""
        }
    }
    
    # Compliance section
    if ($IncludeCompliance -and $totalViolations -gt 0) {
        $markdown += "### 📈 Compliance & Coverage"
        $markdown += ""
        
        # Collect unique CWEs and MITRE techniques
        $uniqueCWEs = @()
        $uniqueMitre = @()
        
        foreach ($violation in $allViolations) {
            if ($violation.CWE -and $violation.CWE -notin $uniqueCWEs) {
                $uniqueCWEs += $violation.CWE
            }
            if ($violation.MitreAttack) {
                if ($violation.MitreAttack -is [array]) {
                    foreach ($technique in $violation.MitreAttack) {
                        if ($technique -notin $uniqueMitre) {
                            $uniqueMitre += $technique
                        }
                    }
                } elseif ($violation.MitreAttack -notin $uniqueMitre) {
                    $uniqueMitre += $violation.MitreAttack
                }
            }
        }
        
        if ($uniqueCWEs.Count -gt 0) {
            $markdown += "- **CWE Coverage**: $($uniqueCWEs.Count) weakness type(s) detected"
        }
        if ($uniqueMitre.Count -gt 0) {
            $markdown += "- **MITRE ATT&CK**: $($uniqueMitre.Count) technique mapping(s)"
        }
        
        # Suppressions
        if ($Results.SuppressedCount -gt 0) {
            $markdown += "- **Suppressions**: $($Results.SuppressedCount) active"
        }
        
        $markdown += ""
    }
    
    # Performance info
    if ($Results.performance) {
        $markdown += "### ⚡ Performance"
        $markdown += ""
        
        if ($Results.performance.analysisTimeMs) {
            $seconds = [math]::Round($Results.performance.analysisTimeMs / 1000.0, 2)
            $markdown += "- **Analysis Time**: $seconds seconds"
        }
        
        if ($Results.performance.filesAnalyzed) {
            $markdown += "- **Files Analyzed**: $($Results.performance.filesAnalyzed)"
        }
        
        if ($Results.performance.filesPerSecond) {
            $fps = [math]::Round($Results.performance.filesPerSecond, 2)
            $markdown += "- **Throughput**: $fps files/second"
        }
        
        $markdown += ""
    }
    
    # Footer with links
    $markdown += "---"
    $markdown += ""
    
    $links = @()
    if ($ArtifactsUrl) {
        $links += "📋 [Full Report]($ArtifactsUrl)"
    }
    if ($JobUrl) {
        $links += "🔗 [CI/CD Job]($JobUrl)"
    }
    $links += "📖 [Rule Documentation]($DocsUrl)"
    
    $markdown += ($links -join ' | ')
    
    $markdown += ""
    $markdown += "_Generated by [PowerShield](https://github.com/J-Ellette/PowerShield) - The comprehensive PowerShell security platform_"
    
    return ($markdown -join "`n")
}

# Export function
Export-ModuleMember -Function New-EnhancedPRComment
