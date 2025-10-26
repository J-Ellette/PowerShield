#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    PowerShield ROI Calculator for enterprise adoption
.DESCRIPTION
    Calculates Return on Investment for PowerShield adoption, including cost savings,
    time savings, and risk reduction. Provides business case justification.
.NOTES
    Version: 1.7.0
    Author: PowerShield Project
.EXAMPLE
    ./Calculate-PowerShieldROI.ps1 -Interactive
.EXAMPLE
    ./Calculate-PowerShieldROI.ps1 -TeamSize 10 -MonthlySecurityReviewHours 40
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Interactive,
    
    [Parameter(Mandatory = $false)]
    [int]$TeamSize = 5,
    
    [Parameter(Mandatory = $false)]
    [int]$MonthlySecurityReviewHours = 40,
    
    [Parameter(Mandatory = $false)]
    [int]$HourlyRate = 150,
    
    [Parameter(Mandatory = $false)]
    [int]$AnnualSecurityIncidents = 2,
    
    [Parameter(Mandatory = $false)]
    [int]$CostPerIncident = 50000,
    
    [Parameter(Mandatory = $false)]
    [int]$AnnualDelayedReleases = 3,
    
    [Parameter(Mandatory = $false)]
    [int]$CostPerDelayedRelease = 25000,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFormat = "text",  # text, markdown, json
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFile
)

# Color output helpers
function Write-ROIInfo { param([string]$Message) Write-Host "ℹ $Message" -ForegroundColor Cyan }
function Write-ROISuccess { param([string]$Message) Write-Host "✓ $Message" -ForegroundColor Green }
function Write-ROIHighlight { param([string]$Message) Write-Host "💰 $Message" -ForegroundColor Yellow }

<#
.SYNOPSIS
    Prompts user for input in interactive mode
#>
function Get-InteractiveInput {
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     PowerShield ROI Calculator - Enterprise Edition          ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
    
    Write-Host "Please provide information about your current security practices:`n"
    
    $script:TeamSize = Read-Host "Number of developers on team"
    $script:MonthlySecurityReviewHours = Read-Host "Hours spent on manual security reviews per month"
    $script:HourlyRate = Read-Host "Average hourly rate for security work (USD)"
    $script:AnnualSecurityIncidents = Read-Host "Security incidents per year (average)"
    $script:CostPerIncident = Read-Host "Average cost per security incident (USD)"
    $script:AnnualDelayedReleases = Read-Host "Releases delayed due to security issues per year"
    $script:CostPerDelayedRelease = Read-Host "Cost per delayed release (USD)"
    
    Write-Host ""
}

<#
.SYNOPSIS
    Calculates current costs without PowerShield
#>
function Get-CurrentCosts {
    $currentCosts = @{
        ManualReviewMonthlyCost = $MonthlySecurityReviewHours * $HourlyRate
        ManualReviewAnnualCost = ($MonthlySecurityReviewHours * $HourlyRate) * 12
        SecurityIncidentsAnnualCost = $AnnualSecurityIncidents * $CostPerIncident
        DelayedReleasesAnnualCost = $AnnualDelayedReleases * $CostPerDelayedRelease
    }
    
    $currentCosts.TotalAnnualCost = $currentCosts.ManualReviewAnnualCost + 
                                     $currentCosts.SecurityIncidentsAnnualCost + 
                                     $currentCosts.DelayedReleasesAnnualCost
    
    return $currentCosts
}

<#
.SYNOPSIS
    Estimates costs and benefits with PowerShield
#>
function Get-PowerShieldCosts {
    # PowerShield implementation and maintenance costs
    $powerShieldCosts = @{
        # One-time setup
        InitialSetupHours = 8
        InitialSetupCost = 8 * $HourlyRate
        
        # Monthly costs
        MonthlyAnalysisHours = 5  # Reduced from manual review
        MonthlyMaintenanceHours = 2  # Rule tuning, suppression review
        MonthlyTotalHours = 7
        MonthlyTotalCost = 7 * $HourlyRate
        AnnualToolCost = (7 * $HourlyRate) * 12
        
        # License cost (if applicable - PowerShield is open source)
        AnnualLicenseCost = 0
        
        # Training costs (one-time)
        TrainingHours = $TeamSize * 2  # 2 hours per developer
        TrainingCost = ($TeamSize * 2) * $HourlyRate
    }
    
    # First year includes setup and training
    $powerShieldCosts.FirstYearCost = $powerShieldCosts.InitialSetupCost + 
                                       $powerShieldCosts.AnnualToolCost + 
                                       $powerShieldCosts.TrainingCost + 
                                       $powerShieldCosts.AnnualLicenseCost
    
    # Ongoing annual cost
    $powerShieldCosts.OngoingAnnualCost = $powerShieldCosts.AnnualToolCost + 
                                           $powerShieldCosts.AnnualLicenseCost
    
    return $powerShieldCosts
}

<#
.SYNOPSIS
    Calculates benefits and savings from PowerShield
#>
function Get-PowerShieldBenefits {
    param(
        [hashtable]$CurrentCosts,
        [hashtable]$PowerShieldCosts
    )
    
    # Assumptions based on industry data and PowerShield capabilities
    $benefits = @{
        # Manual review time savings
        ManualReviewReduction = 0.875  # 87.5% reduction (40h → 5h)
        ManualReviewSavings = $CurrentCosts.ManualReviewAnnualCost * 0.875
        
        # Security incident reduction
        IncidentReductionRate = 0.90  # 90% of preventable incidents caught
        PreventedIncidents = $AnnualSecurityIncidents * 0.90
        IncidentSavings = ($AnnualSecurityIncidents * 0.90) * $CostPerIncident
        
        # Release delay reduction
        DelayReductionRate = 0.933  # 93.3% reduction (3 → 0.2 delays)
        PreventedDelays = $AnnualDelayedReleases * 0.933
        DelaySavings = ($AnnualDelayedReleases * 0.933) * $CostPerDelayedRelease
        
        # Additional benefits (harder to quantify)
        DeveloperProductivityGain = 0.15  # 15% productivity increase
        ComplianceValue = $TeamSize * $HourlyRate * 40  # Easier audit compliance
        ReputationProtection = "Reduced risk of data breaches and reputation damage"
    }
    
    $benefits.TotalAnnualSavings = $benefits.ManualReviewSavings + 
                                     $benefits.IncidentSavings + 
                                     $benefits.DelaySavings
    
    # Net benefit (savings minus costs)
    $benefits.FirstYearNetBenefit = $benefits.TotalAnnualSavings - $PowerShieldCosts.FirstYearCost
    $benefits.OngoingNetBenefit = $benefits.TotalAnnualSavings - $PowerShieldCosts.OngoingAnnualCost
    
    # ROI calculation
    $benefits.FirstYearROI = if ($PowerShieldCosts.FirstYearCost -gt 0) {
        (($benefits.FirstYearNetBenefit / $PowerShieldCosts.FirstYearCost) * 100)
    } else { 0 }
    
    $benefits.OngoingROI = if ($PowerShieldCosts.OngoingAnnualCost -gt 0) {
        (($benefits.OngoingNetBenefit / $PowerShieldCosts.OngoingAnnualCost) * 100)
    } else { 0 }
    
    # Payback period (in months)
    $benefits.PaybackPeriodMonths = if ($benefits.TotalAnnualSavings -gt 0) {
        ($PowerShieldCosts.FirstYearCost / ($benefits.TotalAnnualSavings / 12))
    } else { 999 }
    
    return $benefits
}

<#
.SYNOPSIS
    Formats ROI report as text
#>
function Format-ROIReportText {
    param(
        [hashtable]$CurrentCosts,
        [hashtable]$PowerShieldCosts,
        [hashtable]$Benefits
    )
    
    $report = @"

╔═══════════════════════════════════════════════════════════════════════╗
║                    PowerShield ROI Analysis                           ║
║                    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')                   ║
╚═══════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CURRENT STATE (Without PowerShield)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Team Size:                      $TeamSize developers
Manual Reviews:                 $MonthlySecurityReviewHours hours/month × `$$HourlyRate/hour

Monthly Costs:
  Manual Security Reviews:      `$$($CurrentCosts.ManualReviewMonthlyCost.ToString('N0'))

Annual Costs:
  Manual Security Reviews:      `$$($CurrentCosts.ManualReviewAnnualCost.ToString('N0'))
  Security Incidents:           $AnnualSecurityIncidents incidents × `$$($CostPerIncident.ToString('N0')) = `$$($CurrentCosts.SecurityIncidentsAnnualCost.ToString('N0'))
  Delayed Releases:             $AnnualDelayedReleases delays × `$$($CostPerDelayedRelease.ToString('N0')) = `$$($CurrentCosts.DelayedReleasesAnnualCost.ToString('N0'))
  
  TOTAL ANNUAL COST:            `$$($CurrentCosts.TotalAnnualCost.ToString('N0'))

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WITH POWERSHIELD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Implementation Costs (First Year):
  Initial Setup:                $($PowerShieldCosts.InitialSetupHours) hours × `$$HourlyRate = `$$($PowerShieldCosts.InitialSetupCost.ToString('N0'))
  Team Training:                $($PowerShieldCosts.TrainingHours) hours × `$$HourlyRate = `$$($PowerShieldCosts.TrainingCost.ToString('N0'))
  License Fee:                  `$$($PowerShieldCosts.AnnualLicenseCost.ToString('N0')) (Open Source!)
  Annual Tool Cost:             $($PowerShieldCosts.MonthlyTotalHours) hours/month × `$$HourlyRate × 12 = `$$($PowerShieldCosts.AnnualToolCost.ToString('N0'))
  
  FIRST YEAR TOTAL:             `$$($PowerShieldCosts.FirstYearCost.ToString('N0'))

Ongoing Annual Cost:            `$$($PowerShieldCosts.OngoingAnnualCost.ToString('N0'))

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SAVINGS & BENEFITS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Time Savings:
  Manual Review Reduction:      $($MonthlySecurityReviewHours)h → $($PowerShieldCosts.MonthlyAnalysisHours)h ($([math]::Round($Benefits.ManualReviewReduction * 100, 1))% reduction)
  Annual Time Savings:          `$$($Benefits.ManualReviewSavings.ToString('N0'))

Risk Reduction:
  Prevented Incidents:          $([math]::Round($Benefits.PreventedIncidents, 1)) incidents/year ($([math]::Round($Benefits.IncidentReductionRate * 100))% reduction)
  Annual Savings:               `$$($Benefits.IncidentSavings.ToString('N0'))

Release Velocity:
  Prevented Delays:             $([math]::Round($Benefits.PreventedDelays, 1)) delays/year ($([math]::Round($Benefits.DelayReductionRate * 100, 1))% reduction)
  Annual Savings:               `$$($Benefits.DelaySavings.ToString('N0'))

TOTAL ANNUAL SAVINGS:           `$$($Benefits.TotalAnnualSavings.ToString('N0'))

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ROI METRICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

First Year:
  Total Investment:             `$$($PowerShieldCosts.FirstYearCost.ToString('N0'))
  Total Savings:                `$$($Benefits.TotalAnnualSavings.ToString('N0'))
  Net Benefit:                  `$$($Benefits.FirstYearNetBenefit.ToString('N0'))
  ROI:                          $([math]::Round($Benefits.FirstYearROI, 1))%
  Payback Period:               $([math]::Round($Benefits.PaybackPeriodMonths, 1)) months

Ongoing (Year 2+):
  Annual Cost:                  `$$($PowerShieldCosts.OngoingAnnualCost.ToString('N0'))
  Annual Savings:               `$$($Benefits.TotalAnnualSavings.ToString('N0'))
  Net Benefit:                  `$$($Benefits.OngoingNetBenefit.ToString('N0'))
  ROI:                          $([math]::Round($Benefits.OngoingROI, 1))%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ADDITIONAL BENEFITS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Automated security analysis in CI/CD pipeline
✓ Real-time security feedback for developers
✓ Compliance reporting (NIST, CIS, OWASP, SOC 2, PCI-DSS, HIPAA)
✓ AI-powered auto-fix capabilities
✓ Advanced threat detection (MITRE ATT&CK coverage)
✓ Reduced audit preparation time (~`$$($Benefits.ComplianceValue.ToString('N0'))/year)
✓ Enhanced security posture and reputation protection
✓ Developer productivity improvement (~$([math]::Round($Benefits.DeveloperProductivityGain * 100))%)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RECOMMENDATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"@

    if ($Benefits.FirstYearROI -gt 100) {
        $report += @"
🎯 STRONG BUSINESS CASE: With an ROI of $([math]::Round($Benefits.FirstYearROI))% in the first
   year and payback in just $([math]::Round($Benefits.PaybackPeriodMonths, 1)) months, PowerShield delivers
   significant value.

💡 RECOMMENDATION: Proceed with PowerShield implementation.
   Start with a 30-day pilot program to validate these projections.

"@
    }
    elseif ($Benefits.FirstYearROI -gt 0) {
        $report += @"
✓ POSITIVE ROI: PowerShield delivers positive ROI of $([math]::Round($Benefits.FirstYearROI))%
  in the first year.

💡 RECOMMENDATION: Consider PowerShield adoption, especially given
   the ongoing benefits ($([math]::Round($Benefits.OngoingROI))% ROI in subsequent years).

"@
    }
    else {
        $report += @"
⚠ MARGINAL ROI: Based on current inputs, ROI is $([math]::Round($Benefits.FirstYearROI))%.
  
💡 RECOMMENDATION: Review assumptions. PowerShield may still provide
   value through risk reduction and compliance benefits not easily quantified.

"@
    }
    
    $report += @"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For enterprise trial and implementation support:
  Documentation: https://github.com/J-Ellette/PowerShield/docs
  Contact: Start with 30-day pilot program

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"@
    
    return $report
}

<#
.SYNOPSIS
    Formats ROI report as JSON
#>
function Format-ROIReportJSON {
    param(
        [hashtable]$CurrentCosts,
        [hashtable]$PowerShieldCosts,
        [hashtable]$Benefits
    )
    
    $roiData = @{
        generated = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
        inputs = @{
            teamSize = $TeamSize
            monthlySecurityReviewHours = $MonthlySecurityReviewHours
            hourlyRate = $HourlyRate
            annualSecurityIncidents = $AnnualSecurityIncidents
            costPerIncident = $CostPerIncident
            annualDelayedReleases = $AnnualDelayedReleases
            costPerDelayedRelease = $CostPerDelayedRelease
        }
        currentCosts = $CurrentCosts
        powerShieldCosts = $PowerShieldCosts
        benefits = $Benefits
    }
    
    return $roiData | ConvertTo-Json -Depth 10
}

# Main execution
function Invoke-ROICalculation {
    if ($Interactive) {
        Get-InteractiveInput
    }
    
    # Calculate costs and benefits
    $currentCosts = Get-CurrentCosts
    $powerShieldCosts = Get-PowerShieldCosts
    $benefits = Get-PowerShieldBenefits -CurrentCosts $currentCosts -PowerShieldCosts $powerShieldCosts
    
    # Generate report
    $report = switch ($OutputFormat.ToLower()) {
        'json' { Format-ROIReportJSON -CurrentCosts $currentCosts -PowerShieldCosts $powerShieldCosts -Benefits $benefits }
        'text' { Format-ROIReportText -CurrentCosts $currentCosts -PowerShieldCosts $powerShieldCosts -Benefits $benefits }
        default { Format-ROIReportText -CurrentCosts $currentCosts -PowerShieldCosts $powerShieldCosts -Benefits $benefits }
    }
    
    # Output report
    if ($OutputFile) {
        $report | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-ROISuccess "ROI report written to: $OutputFile"
    }
    else {
        Write-Host $report
    }
}

# Run calculation
Invoke-ROICalculation
