<#
.SYNOPSIS
    Converts PowerShield results to SARIF format for GitHub Security tab integration.
.DESCRIPTION
    Converts PowerShell Security Analyzer JSON results to SARIF 2.1.0 format.
.PARAMETER InputFile
    Path to the PowerShield JSON results file
.PARAMETER OutputFile
    Path where the SARIF file should be written
.EXAMPLE
    Convert-ToSARIF -InputFile results.json -OutputFile results.sarif
#>

function Get-MetadataValue {
    param(
        [object]$Metadata,
        [string]$Key
    )
    
    if (-not $Metadata) {
        return $null
    }
    
    # Handle hashtable
    if ($Metadata -is [hashtable]) {
        return $Metadata[$Key]
    }
    
    # Handle PSCustomObject (from JSON deserialization)
    if ($Metadata.PSObject.Properties.Name -contains $Key) {
        return $Metadata.$Key
    }
    
    return $null
}

function Convert-ToSARIF {
    param(
        [Parameter(Mandatory)]
        [string]$InputFile,
        
        [Parameter(Mandatory)]
        [string]$OutputFile
    )

    if (-not (Test-Path $InputFile)) {
        throw "Input file not found: $InputFile"
    }

    $results = Get-Content $InputFile -Raw | ConvertFrom-Json
    
    # Initialize SARIF structure
    $sarif = @{
        '$schema' = 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json'
        version = '2.1.0'
        runs = @(@{
            tool = @{
                driver = @{
                    name = 'PowerShield (Comprehensive PowerShell Security Platform)'
                    version = $results.metadata.version
                    informationUri = 'https://github.com/J-Ellette/PowerShellTestingSuite'
                    semanticVersion = $results.metadata.version
                    rules = @()
                }
            }
            results = @()
            originalUriBaseIds = @{
                SRCROOT = @{
                    uri = 'file:///'
                }
            }
        })
    }

    # Build rules dictionary with rich metadata
    $rulesMap = @{}
    foreach ($violation in $results.violations) {
        if ($violation -and $violation.RuleId -and -not $rulesMap.ContainsKey($violation.RuleId)) {
            $severityLevel = if ($violation.Severity) {
                switch ($violation.Severity) {
                    'Critical' { 'error' }
                    'High' { 'error' }
                    'Medium' { 'warning' }
                    'Low' { 'note' }
                    default { 'warning' }
                }
            } else {
                'warning'
            }
            
            # Build properties with metadata
            $properties = @{
                category = 'security'
                tags = @('security', 'powershell')
            }
            
            # Add CWE mappings
            $cweValue = Get-MetadataValue -Metadata $violation.Metadata -Key 'CWE'
            if ($cweValue) {
                $properties['cwe'] = $cweValue
            }
            
            # Add MITRE ATT&CK technique IDs
            $mitreValue = Get-MetadataValue -Metadata $violation.Metadata -Key 'MitreAttack'
            if ($mitreValue) {
                $properties['mitreAttack'] = $mitreValue
                # Also add as precision tag for GitHub
                $properties['precision'] = 'high'
            }
            
            # Add OWASP categories
            $owaspValue = Get-MetadataValue -Metadata $violation.Metadata -Key 'OWASP'
            if ($owaspValue) {
                $properties['owasp'] = $owaspValue
            }
            
            # Add security severity
            $securitySeverityValue = Get-MetadataValue -Metadata $violation.Metadata -Key 'SecuritySeverity'
            if ($securitySeverityValue) {
                $properties['securitySeverity'] = $securitySeverityValue
            }
            
            $ruleDefinition = @{
                id = $violation.RuleId
                name = if ($violation.Name) { $violation.Name } else { $violation.RuleId }
                shortDescription = @{ text = if ($violation.Message) { $violation.Message } else { "Security violation" } }
                fullDescription = @{ text = if ($violation.Message) { $violation.Message } else { "Security violation detected" } }
                defaultConfiguration = @{
                    level = $severityLevel
                }
                properties = $properties
            }
            
            # Add help URL if available
            $helpUriValue = Get-MetadataValue -Metadata $violation.Metadata -Key 'HelpUri'
            if ($helpUriValue) {
                $ruleDefinition['helpUri'] = $helpUriValue
            }
            
            $rulesMap[$violation.RuleId] = $ruleDefinition
        }
    }

    $sarif.runs[0].tool.driver.rules = @($rulesMap.Values)

    # Build results
    foreach ($violation in $results.violations) {
        if (-not $violation -or -not $violation.RuleId -or -not $violation.LineNumber) {
            continue
        }
        
        $severityLevel = if ($violation.Severity) {
            switch ($violation.Severity) {
                'Critical' { 'error' }
                'High' { 'error' }
                'Medium' { 'warning' }
                'Low' { 'note' }
                default { 'warning' }
            }
        } else {
            'warning'
        }
        
        # Convert file path to relative URI
        $relativeUri = 'unknown'
        if ($violation.FilePath) {
            $filePath = $violation.FilePath.Replace('\', '/')
            
            # If path is absolute, convert to relative to current directory
            if ([System.IO.Path]::IsPathRooted($violation.FilePath)) {
                try {
                    $currentDir = (Get-Location).Path.Replace('\', '/')
                    if ($filePath.StartsWith($currentDir)) {
                        $relativeUri = $filePath.Substring($currentDir.Length).TrimStart('/')
                    } else {
                        # Path is absolute but not under current directory, use as-is
                        $relativeUri = $filePath
                    }
                } catch {
                    # Fallback to original path
                    $relativeUri = $filePath
                }
            } else {
                # Already relative, just clean it up
                $relativeUri = $filePath.TrimStart('./')
            }
        }
        
        $result = @{
            ruleId = $violation.RuleId
            ruleIndex = [array]::IndexOf(@($rulesMap.Keys), $violation.RuleId)
            message = @{ text = if ($violation.Message) { $violation.Message } else { "Security violation" } }
            level = $severityLevel
            locations = @(@{
                physicalLocation = @{
                    artifactLocation = @{ 
                        uri = $relativeUri
                        uriBaseId = 'SRCROOT'
                    }
                    region = @{
                        startLine = $violation.LineNumber
                        startColumn = 1
                        snippet = @{ text = if ($violation.Code) { $violation.Code } else { '' } }
                    }
                }
            })
            partialFingerprints = @{
                primaryLocationLineHash = (Get-ContentBasedFingerprint -Violation $violation)
            }
        }
        
        # Add fix suggestions if available
        if ($violation.Fixes -and $violation.Fixes.Count -gt 0) {
            $result['fixes'] = @()
            foreach ($fix in $violation.Fixes) {
                $sarifFix = @{
                    description = @{
                        text = $fix.description
                    }
                    artifactChanges = @(@{
                        artifactLocation = @{
                            uri = $relativeUri
                            uriBaseId = 'SRCROOT'
                        }
                        replacements = @(@{
                            deletedRegion = @{
                                startLine = $violation.LineNumber
                                startColumn = 1
                            }
                            insertedContent = @{
                                text = $fix.replacement
                            }
                        })
                    })
                }
                $result['fixes'] += $sarifFix
            }
        }
        
        # Add code flows if available
        if ($violation.CodeFlows -and $violation.CodeFlows.Count -gt 0) {
            $result['codeFlows'] = @()
            foreach ($flow in $violation.CodeFlows) {
                $sarifFlow = @{
                    message = @{
                        text = if ($flow.message) { $flow.message } else { "Data flow" }
                    }
                    threadFlows = @(@{
                        locations = @()
                    })
                }
                
                foreach ($location in $flow.locations) {
                    $flowLocation = @{
                        location = @{
                            physicalLocation = @{
                                artifactLocation = @{
                                    uri = if ($location.filePath) { $location.filePath.Replace('\', '/').TrimStart('./') } else { $relativeUri }
                                    uriBaseId = 'SRCROOT'
                                }
                                region = @{
                                    startLine = if ($location.lineNumber) { $location.lineNumber } else { 1 }
                                }
                            }
                            message = @{
                                text = if ($location.message) { $location.message } else { "Flow step" }
                            }
                        }
                    }
                    $sarifFlow.threadFlows[0].locations += $flowLocation
                }
                
                $result['codeFlows'] += $sarifFlow
            }
        }
        
        # Add related locations if metadata contains them
        $relatedLocations = Get-MetadataValue -Metadata $violation.Metadata -Key 'RelatedLocations'
        if ($relatedLocations) {
            $result['relatedLocations'] = @()
            foreach ($relatedLoc in $relatedLocations) {
                $result['relatedLocations'] += @{
                    physicalLocation = @{
                        artifactLocation = @{
                            uri = if ($relatedLoc.filePath) { $relatedLoc.filePath.Replace('\', '/').TrimStart('./') } else { $relativeUri }
                            uriBaseId = 'SRCROOT'
                        }
                        region = @{
                            startLine = if ($relatedLoc.lineNumber) { $relatedLoc.lineNumber } else { 1 }
                        }
                    }
                    message = @{
                        text = if ($relatedLoc.message) { $relatedLoc.message } else { "Related location" }
                    }
                }
            }
        }
        
        $sarif.runs[0].results += $result
    }

    # Write SARIF output
    $sarif | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "SARIF output written to: $OutputFile"
}

function Get-StringHash {
    param([string]$String)
    
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))
    return [System.BitConverter]::ToString($hash).Replace('-', '').Substring(0, 16)
}

function Get-ContentBasedFingerprint {
    param([object]$Violation)
    
    # Build a stable fingerprint based on:
    # 1. Rule ID (what was detected)
    # 2. Code content (the actual issue)
    # 3. Normalized file path (to handle relative/absolute path differences)
    
    $components = @()
    
    # Add rule ID
    if ($Violation.RuleId) {
        $components += $Violation.RuleId
    }
    
    # Add normalized code snippet (trim and normalize whitespace)
    if ($Violation.Code) {
        $normalizedCode = $Violation.Code.Trim() -replace '\s+', ' '
        $components += $normalizedCode
    }
    
    # Add normalized file path (use just the filename or relative path from repo root)
    if ($Violation.FilePath) {
        $filePath = $Violation.FilePath.Replace('\', '/')
        # Extract just the relative path from the repo (remove any absolute prefix)
        if ($filePath -match '/(src/|scripts/|tests/)') {
            $filePath = $Matches[0] + ($filePath -split $Matches[0], 2)[1]
        } elseif ([System.IO.Path]::IsPathRooted($filePath)) {
            # If absolute, try to get just the filename
            $filePath = [System.IO.Path]::GetFileName($filePath)
        }
        $components += $filePath
    }
    
    # Combine all components and hash
    $fingerprintString = $components -join '|'
    return Get-StringHash $fingerprintString
}

if ($MyInvocation.PSScriptRoot -eq $null -or $MyInvocation.InvocationName -eq '.') {
    # Do not call Export-ModuleMember when dot-sourced
} else {
    Export-ModuleMember -Function Convert-ToSARIF  # or Generate-SecurityReport
}
