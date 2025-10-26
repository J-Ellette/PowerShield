# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for PowerShell Gallery security violations
# These patterns represent supply chain security risks

# Violation 1: Installing module without -Scope CurrentUser (requires admin/system-wide)
Install-Module -Name SomeModule -Force

# Violation 2: Installing module with -Scope AllUsers (system-wide installation)
Install-Module -Name AnotherModule -Scope AllUsers -Force

# Violation 3: Installing module without version pinning (supply chain risk)
Install-Module -Name UnpinnedModule -Force -Scope CurrentUser

# Violation 4: Installing module without verifying publisher/signature
Install-Module -Name UntrustedModule -SkipPublisherCheck -Force -Scope CurrentUser

# Violation 5: Bypassing signature validation
Install-Module -Name UnverifiedModule -AllowClobber -SkipPublisherCheck -Force

# Violation 6: Installing from untrusted repository
Register-PSRepository -Name "UntrustedRepo" -SourceLocation "https://untrusted-source.com/nuget" -InstallationPolicy Trusted
Install-Module -Name ModuleFromUntrustedSource -Repository UntrustedRepo -Force

# Violation 7: Disabling repository trust check
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name AnyModule -Force

# Violation 8: Using Find-Module without verifying results
$modules = Find-Module -Name "SomePattern*"
$modules | Install-Module -Force

# Violation 9: Installing pre-release modules without verification
Install-Module -Name PreReleaseModule -AllowPrerelease -Force -Scope CurrentUser

# Violation 10: Installing module with -AllowClobber (can overwrite existing commands)
Install-Module -Name ConflictingModule -AllowClobber -Force -Scope CurrentUser

# Violation 11: Importing module from arbitrary path without verification
$modulePath = "C:\Users\Downloads\SuspiciousModule.psm1"
Import-Module $modulePath -Force

# Violation 12: Installing module from network share
Install-Module -Name NetworkModule -Repository "\\fileserver\PSModules" -Force

# Correct usage examples (should not trigger violations)
# Installing module with proper scope
Install-Module -Name SafeModule -Scope CurrentUser -Force

# Installing with version pinning
Install-Module -Name PinnedModule -RequiredVersion 1.2.3 -Scope CurrentUser -Force

# Verifying module before installation
$module = Find-Module -Name VerifiedModule -Repository PSGallery
if ($module.CompanyName -eq "TrustedPublisher") {
    Install-Module -Name VerifiedModule -Scope CurrentUser -Force
}

# Checking module signature
$moduleInfo = Get-Module -Name InstalledModule -ListAvailable
$signature = Get-AuthenticodeSignature -FilePath $moduleInfo.Path
if ($signature.Status -eq "Valid") {
    Import-Module InstalledModule
}

# Using trusted repository only
Get-PSRepository -Name PSGallery | Where-Object { $_.InstallationPolicy -eq "Untrusted" }
