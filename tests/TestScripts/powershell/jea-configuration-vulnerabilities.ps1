# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for JEA (Just Enough Administration) configuration vulnerabilities
# These patterns represent JEA security misconfigurations

# Violation 1: Role capability file with excessive visible cmdlets (wildcard)
$roleCapabilityContent = @'
@{
    ModulesToImport = 'Microsoft.PowerShell.Management'
    VisibleCmdlets = @('*')
    VisibleFunctions = @('*')
}
'@
Set-Content -Path "C:\temp\DangerousRole.psrc" -Value $roleCapabilityContent

# Violation 2: Session configuration without transcript logging
$sessionConfigParams = @{
    Name = 'UnsafeJEAEndpoint'
    TranscriptDirectory = $null
    RunAsVirtualAccount = $true
}
Register-PSSessionConfiguration @sessionConfigParams -Force

# Violation 3: JEA endpoint with RunAsCredential instead of virtual account
$credential = Get-Credential
Register-PSSessionConfiguration -Name 'CredentialBasedJEA' -RunAsCredential $credential -Force

# Violation 4: Role capability allowing dangerous cmdlets
$dangerousRoleContent = @'
@{
    VisibleCmdlets = @(
        'Invoke-Expression',
        'Invoke-Command',
        'Enter-PSSession',
        'New-PSSession'
    )
    VisibleFunctions = @('*')
}
'@
Set-Content -Path "C:\temp\DangerousCmdlets.psrc" -Value $dangerousRoleContent

# Violation 5: Session configuration with full language mode
Register-PSSessionConfiguration -Name 'FullLanguageJEA' -SessionType Default -Force

# Violation 6: JEA role with script execution enabled
$scriptRoleContent = @'
@{
    VisibleCmdlets = @('Get-Process', 'Stop-Process')
    VisibleExternalCommands = @('C:\Windows\System32\*.exe')
    ScriptsToProcess = @('C:\scripts\startup.ps1')
}
'@
Set-Content -Path "C:\temp\ScriptRole.psrc" -Value $scriptRoleContent

# Violation 7: Role capability without required modules constraint
$unconstrainedRole = @'
@{
    VisibleCmdlets = @(
        @{Name = 'Get-Service'; Parameters = @{Name = '*'}}
    )
    # Missing: ModulesToImport = specific modules only
}
'@
Set-Content -Path "C:\temp\UnconstrainedRole.psrc" -Value $unconstrainedRole

# Violation 8: JEA endpoint without user drive
Register-PSSessionConfiguration -Name 'NoDriveJEA' -MountUserDrive:$false -Force

# Violation 9: Session configuration allowing arbitrary script blocks
$scriptBlockConfig = @{
    Name = 'ScriptBlockJEA'
    SessionType = 'Default'
    RunAsVirtualAccount = $true
}
Register-PSSessionConfiguration @scriptBlockConfig -Force

# Violation 10: Role capability with excessive alias visibility
$aliasRole = @'
@{
    VisibleAliases = @('*')
    VisibleCmdlets = @('Get-Service', 'Get-Process')
}
'@
Set-Content -Path "C:\temp\AliasRole.psrc" -Value $aliasRole

# Violation 11: JEA configuration without execution policy restriction
Register-PSSessionConfiguration -Name 'NoExecPolicyJEA' -ExecutionPolicy Bypass -Force

# Violation 12: Role capability allowing Add-Type (can load arbitrary code)
$addTypeRole = @'
@{
    VisibleCmdlets = @(
        'Get-Process',
        'Add-Type'
    )
}
'@
Set-Content -Path "C:\temp\AddTypeRole.psrc" -Value $addTypeRole

# Violation 13: Session configuration with no timeout
Register-PSSessionConfiguration -Name 'NoTimeoutJEA' -MaximumReceivedObjectSizeMB 1024 -MaximumReceivedDataSizePerCommandMB 512 -Force

# Violation 14: Role capability with visible providers (filesystem access)
$providerRole = @'
@{
    VisibleProviders = @('FileSystem', 'Registry', 'Certificate')
    VisibleCmdlets = @('Get-ChildItem', 'Set-Item')
}
'@
Set-Content -Path "C:\temp\ProviderRole.psrc" -Value $providerRole

# Correct usage examples (should not trigger violations)
# Properly constrained role capability
$secureRoleContent = @'
@{
    ModulesToImport = @('Microsoft.PowerShell.Management')
    VisibleCmdlets = @(
        @{Name = 'Get-Service'; Parameters = @{Name = 'Name'}},
        @{Name = 'Restart-Service'; Parameters = @{Name = 'Name'}; ValidatePattern = 'AppPool.*'}
    )
    VisibleFunctions = @()
    VisibleExternalCommands = @()
}
'@
Set-Content -Path "C:\temp\SecureRole.psrc" -Value $secureRoleContent

# Secure session configuration
$secureSessionParams = @{
    Name = 'SecureJEAEndpoint'
    SessionType = 'RestrictedRemoteServer'
    RunAsVirtualAccount = $true
    TranscriptDirectory = 'C:\Transcripts'
    LanguageMode = 'NoLanguage'
}
Register-PSSessionConfiguration @secureSessionParams -Force

# Role capability with specific cmdlet parameters
$constrainedRole = @'
@{
    ModulesToImport = @('ActiveDirectory')
    VisibleCmdlets = @(
        @{
            Name = 'Get-ADUser'
            Parameters = @(
                @{Name = 'Identity'},
                @{Name = 'Properties'; ValidateSet = 'DisplayName', 'EmailAddress'}
            )
        }
    )
}
'@
Set-Content -Path "C:\temp\ConstrainedRole.psrc" -Value $constrainedRole

# Session configuration with proper security settings
Register-PSSessionConfiguration -Name 'ProperJEA' `
    -SessionType RestrictedRemoteServer `
    -RunAsVirtualAccount `
    -TranscriptDirectory 'C:\JEATranscripts' `
    -SessionTypeOption (New-PSSessionOption -IdleTimeoutMs 300000) `
    -Force
