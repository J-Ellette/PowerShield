#Requires -Version 7.0

<#
.SYNOPSIS
    VS Code Language Server integration for PowerShield
.DESCRIPTION
    Provides diagnostic export, real-time analysis API, and quick fix formats for VS Code extension
#>

using namespace System.Collections.Generic

# VS Code Diagnostic Severity mapping
enum DiagnosticSeverity {
    Error = 1    # Critical/High
    Warning = 2  # Medium
    Information = 3  # Low
    Hint = 4     # Informational
}

# VS Code Diagnostic representation
class VSCodeDiagnostic {
    [string]$message
    [int]$severity
    [object]$range
    [string]$code
    [string]$source = "PowerShield"
    [object[]]$relatedInformation
    [object[]]$codeActions
    
    VSCodeDiagnostic([string]$msg, [int]$sev, [object]$rng, [string]$ruleId) {
        $this.message = $msg
        $this.severity = $sev
        $this.range = $rng
        $this.code = $ruleId
    }
}

# VS Code Position
class Position {
    [int]$line
    [int]$character
    
    Position([int]$ln, [int]$ch) {
        $this.line = $ln
        $this.character = $ch
    }
}

# VS Code Range
class Range {
    [Position]$start
    [Position]$end
    
    Range([int]$startLine, [int]$startChar, [int]$endLine, [int]$endChar) {
        $this.start = [Position]::new($startLine, $startChar)
        $this.end = [Position]::new($endLine, $endChar)
    }
}

# VS Code Code Action
class CodeAction {
    [string]$title
    [string]$kind
    [object]$edit
    [object[]]$diagnostics
    [bool]$isPreferred
    
    CodeAction([string]$title, [string]$kind) {
        $this.title = $title
        $this.kind = $kind
    }
}

# Quick Fix suggestion
class QuickFix {
    [string]$description
    [string]$fixedCode
    [double]$confidence
    [string]$category
    [Range]$range
    
    QuickFix([string]$desc, [string]$code, [double]$conf, [string]$cat, [Range]$rng) {
        $this.description = $desc
        $this.fixedCode = $code
        $this.confidence = $conf
        $this.category = $cat
        $this.range = $rng
    }
}

class VSCodeIntegration {
    [hashtable]$Configuration
    
    VSCodeIntegration() {
        $this.Configuration = @{
            enableRealTimeAnalysis = $true
            debounceMs = 500
            maxDiagnostics = 100
            showInformationalDiagnostics = $false
        }
    }
    
    <#
    .SYNOPSIS
        Convert PowerShield violations to VS Code diagnostics format
    #>
    [object[]] ConvertToDiagnostics([object[]]$violations, [string]$filePath) {
        [object[]]$diagnostics = @()
        
        foreach ($violation in $violations) {
            if (-not $violation) { continue }
            
            # Map PowerShield severity to VS Code severity
            [int]$severity = switch ($violation.Severity.ToString()) {
                'Critical' { [DiagnosticSeverity]::Error }
                'High' { [DiagnosticSeverity]::Error }
                'Medium' { [DiagnosticSeverity]::Warning }
                'Low' { [DiagnosticSeverity]::Information }
                default { [DiagnosticSeverity]::Warning }
            }
            
            # Create range (VS Code is 0-indexed, PowerShell is 1-indexed)
            [int]$startLine = [Math]::Max(0, $violation.LineNumber - 1)
            [int]$endLine = $startLine
            [int]$startChar = 0
            [int]$endChar = 100  # Default end of line
            
            [Range]$range = [Range]::new($startLine, $startChar, $endLine, $endChar)
            
            # Create diagnostic
            [VSCodeDiagnostic]$diagnostic = [VSCodeDiagnostic]::new(
                $violation.Message,
                [int]$severity,
                $range,
                $violation.RuleId
            )
            
            # Add code actions (quick fixes)
            if ($violation.Suggestion) {
                [CodeAction]$codeAction = [CodeAction]::new(
                    "Fix: $($violation.Suggestion)",
                    "quickfix"
                )
                $codeAction.isPreferred = $true
                $diagnostic.codeActions = @($codeAction)
            }
            
            $diagnostics += $diagnostic
        }
        
        return $diagnostics
    }
    
    <#
    .SYNOPSIS
        Export diagnostics to JSON format for Language Server Protocol
    #>
    [string] ExportDiagnosticsJSON([object[]]$violations, [string]$filePath) {
        [object[]]$diagnostics = $this.ConvertToDiagnostics($violations, $filePath)
        
        [hashtable]$output = @{
            jsonrpc = "2.0"
            method = "textDocument/publishDiagnostics"
            params = @{
                uri = "file:///$($filePath -replace '\\', '/')"
                diagnostics = $diagnostics
                version = 1
            }
        }
        
        return ($output | ConvertTo-Json -Depth 10)
    }
    
    <#
    .SYNOPSIS
        Generate quick fix suggestions in VS Code format
    #>
    [QuickFix[]] GenerateQuickFixes([object]$violation, [string]$fileContent) {
        [QuickFix[]]$fixes = @()
        
        # Extract the problematic line
        [string[]]$lines = $fileContent -split "`n"
        if ($violation.LineNumber -le $lines.Count) {
            [int]$lineIndex = $violation.LineNumber - 1
            [string]$originalLine = $lines[$lineIndex]
            
            # Generate fix based on rule
            [string]$fixedLine = $this.GenerateFixForRule($violation.RuleId, $originalLine, $violation)
            
            if ($fixedLine -and $fixedLine -ne $originalLine) {
                [Range]$range = [Range]::new(
                    $lineIndex, 0,
                    $lineIndex, $originalLine.Length
                )
                
                [QuickFix]$fix = [QuickFix]::new(
                    "Replace with secure alternative",
                    $fixedLine,
                    0.85,
                    "security",
                    $range
                )
                
                $fixes += $fix
            }
        }
        
        return $fixes
    }
    
    <#
    .SYNOPSIS
        Generate fix for specific rule
    #>
    [string] GenerateFixForRule([string]$ruleId, [string]$line, [object]$violation) {
        switch ($ruleId) {
            'InsecureHashAlgorithms' {
                if ($line -match 'MD5|SHA1') {
                    return $line -replace 'MD5', 'SHA256' -replace 'SHA1', 'SHA256'
                }
            }
            'CredentialExposure' {
                if ($line -match 'ConvertTo-SecureString.*-AsPlainText') {
                    return '# Use Read-Host -AsSecureString instead of plaintext'
                }
            }
            'CommandInjection' {
                if ($line -match 'Invoke-Expression') {
                    return '# Review: Consider using & or dot-sourcing instead of Invoke-Expression'
                }
            }
            'InsecureHTTP' {
                if ($line -match 'http://') {
                    return $line -replace 'http://', 'https://'
                }
            }
        }
        
        return $null
    }
    
    <#
    .SYNOPSIS
        Create command schema for VS Code extension
    #>
    [object] GetCommandSchema() {
        return @{
            commands = @(
                @{
                    command = "powershield.analyzeFile"
                    title = "PowerShield: Analyze Current File"
                    category = "PowerShield"
                    enablement = "editorLangId == 'powershell'"
                },
                @{
                    command = "powershield.analyzeWorkspace"
                    title = "PowerShield: Analyze Workspace"
                    category = "PowerShield"
                },
                @{
                    command = "powershield.applyFix"
                    title = "PowerShield: Apply Security Fix"
                    category = "PowerShield"
                    enablement = "editorLangId == 'powershell'"
                },
                @{
                    command = "powershield.suppressViolation"
                    title = "PowerShield: Suppress Violation"
                    category = "PowerShield"
                },
                @{
                    command = "powershield.showRuleDocumentation"
                    title = "PowerShield: Show Rule Documentation"
                    category = "PowerShield"
                },
                @{
                    command = "powershield.configureSettings"
                    title = "PowerShield: Configure Settings"
                    category = "PowerShield"
                },
                @{
                    command = "powershield.viewSecurityDashboard"
                    title = "PowerShield: View Security Dashboard"
                    category = "PowerShield"
                }
            )
            
            codeActions = @{
                kinds = @(
                    "quickfix",
                    "source.fixAll.powershield",
                    "refactor.rewrite.powershield"
                )
            }
            
            diagnostics = @{
                source = "PowerShield"
                codes = @(
                    "InsecureHashAlgorithms",
                    "CredentialExposure",
                    "CommandInjection",
                    "CertificateValidation",
                    "ExecutionPolicyBypass",
                    "UnsafePSRemoting",
                    "PowerShellVersionDowngrade"
                )
            }
        }
    }
    
    <#
    .SYNOPSIS
        Real-time analysis API endpoint structure
    #>
    [object] AnalyzeDocument([string]$uri, [string]$content, [int]$version) {
        # This would integrate with PowerShellSecurityAnalyzer
        # For now, return the structure
        
        return @{
            uri = $uri
            version = $version
            diagnostics = @()
            timestamp = (Get-Date).ToString('o')
            analysisTime = 0
        }
    }
    
    <#
    .SYNOPSIS
        Test-ScriptFileInfo integration for module security validation
    #>
    [object] ValidateModuleManifest([string]$manifestPath) {
        [hashtable]$results = @{
            isValid = $false
            errors = @()
            warnings = @()
            securityIssues = @()
        }
        
        try {
            # Test if file exists
            if (-not (Test-Path $manifestPath)) {
                $results.isValid = $false
                $results.errors += "Manifest file not found: $manifestPath"
                return $results
            }
            
            # Use Test-ModuleManifest for validation
            [string[]]$manifestWarnings = @()
            
            try {
                [object]$manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Continue -WarningVariable manifestWarnings
                $results.warnings = $manifestWarnings
                $results.isValid = $true  # Mark as valid if Test-ModuleManifest succeeds
                
                # Additional security checks only if manifest loaded successfully
                if ($manifest) {
                    # Check for required modules without versions
                    if ($manifest.RequiredModules) {
                        foreach ($reqModule in $manifest.RequiredModules) {
                            if (-not $reqModule.Version) {
                                $results.securityIssues += @{
                                    severity = "Medium"
                                    message = "Required module '$($reqModule.Name)' does not specify a version (security risk)"
                                    recommendation = "Always specify exact module versions to prevent supply chain attacks"
                                }
                            }
                        }
                    }
                    
                    # Check for script file info
                    if ($manifest.PrivateData.PSData.Tags -notcontains 'Security') {
                        $results.warnings += "Module does not have 'Security' tag"
                    }
                    
                    # Check for external module dependencies
                    if ($manifest.ExternalModuleDependencies) {
                        $results.securityIssues += @{
                            severity = "Low"
                            message = "Module has external dependencies that should be reviewed"
                            recommendation = "Review all external dependencies for security vulnerabilities"
                        }
                    }
                }
                
            } catch {
                # Manifest loading failed
                $results.warnings = if ($manifestWarnings) { $manifestWarnings } else { @() }
                $results.errors += "Failed to load manifest: $($_.Exception.Message)"
                $results.isValid = $false
                return $results
            }
            
        } catch {
            $results.errors += $_.Exception.Message
            $results.isValid = $false
            return $results
        }
        
        return $results
    }
}

# Export functions
function New-VSCodeIntegration {
    [CmdletBinding()]
    param()
    
    return [VSCodeIntegration]::new()
}

function Export-VSCodeDiagnostics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Violations,
        
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [Parameter()]
        [string]$OutputPath
    )
    
    $integration = [VSCodeIntegration]::new()
    $json = $integration.ExportDiagnosticsJSON($Violations, $FilePath)
    
    if ($OutputPath) {
        $json | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Verbose "Diagnostics exported to: $OutputPath"
    }
    
    return $json
}

function Get-VSCodeQuickFixes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Violation,
        
        [Parameter(Mandatory)]
        [string]$FileContent
    )
    
    $integration = [VSCodeIntegration]::new()
    return $integration.GenerateQuickFixes($Violation, $FileContent)
}

function Get-VSCodeCommandSchema {
    [CmdletBinding()]
    param()
    
    $integration = [VSCodeIntegration]::new()
    return $integration.GetCommandSchema()
}

function Test-ModuleSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ManifestPath
    )
    
    $integration = [VSCodeIntegration]::new()
    return $integration.ValidateModuleManifest($ManifestPath)
}

Export-ModuleMember -Function @(
    'New-VSCodeIntegration',
    'Export-VSCodeDiagnostics',
    'Get-VSCodeQuickFixes',
    'Get-VSCodeCommandSchema',
    'Test-ModuleSecurity'
)
