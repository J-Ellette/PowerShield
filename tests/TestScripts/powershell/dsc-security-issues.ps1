# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These credentials and patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for DSC (Desired State Configuration) security issues
# These patterns represent DSC security misconfigurations

# Violation 1: DSC configuration with plaintext password in ConfigurationData
$configData = @{
    AllNodes = @(
        @{
            NodeName = "Server01"
            PSDscAllowPlainTextPassword = $true
            Password = "MyPlainTextPassword123!"
        }
    )
}

Configuration InsecureDSC {
    param(
        [string]$NodeName
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node $NodeName {
        User LocalAdmin {
            UserName = "LocalAdmin"
            Password = (Get-Credential -UserName "LocalAdmin" -Message "Password").Password
        }
    }
}

# Violation 2: Configuration allowing plaintext passwords
Configuration AllowPlainText {
    param(
        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )
    
    Node "localhost" {
        User TestUser {
            UserName = "TestUser"
            Password = $Credential
            PSDscAllowPlainTextPassword = $true
        }
    }
}

# Violation 3: MOF file with exposed credentials
$mofContent = @'
instance of MSFT_Credential as $MSFT_Credential1ref
{
    Password = "SecretPassword123!";
    UserName = "Administrator";
};
'@
Set-Content -Path "C:\temp\InsecureConfig.mof" -Value $mofContent

# Violation 4: DSC resource downloading from untrusted source
Configuration DownloadUntrusted {
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "localhost" {
        Archive DownloadArchive {
            Path = "https://untrusted-site.com/package.zip"
            Destination = "C:\Program Files\App"
            Ensure = "Present"
        }
    }
}

# Violation 5: Script resource with Invoke-Expression
Configuration DangerousScript {
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "localhost" {
        Script ExecuteCode {
            GetScript = { @{ Result = "" } }
            SetScript = { 
                $userInput = $using:userProvidedCommand
                Invoke-Expression $userInput 
            }
            TestScript = { $false }
        }
    }
}

# Violation 6: Registry resource modifying security settings
Configuration WeakenSecurity {
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "localhost" {
        Registry DisableUAC {
            Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "EnableLUA"
            ValueData = "0"
            ValueType = "Dword"
            Ensure = "Present"
        }
    }
}

# Violation 7: DSC configuration with embedded certificate password
$certPassword = ConvertTo-SecureString "CertPassword123!" -AsPlainText -Force
$encryptionCert = @{
    CertificateFile = "C:\certs\dsc.cer"
    Password = $certPassword
}

# Violation 8: Package resource installing from arbitrary URL
Configuration InstallUntrusted {
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "localhost" {
        Package InstallSoftware {
            Name = "UntrustedApp"
            Path = "https://random-site.com/setup.exe"
            ProductId = "12345678-1234-1234-1234-123456789012"
            Arguments = "/quiet /norestart"
        }
    }
}

# Violation 9: Service resource with hardcoded credentials
Configuration ServiceWithCreds {
    param(
        [string]$ServiceUser = "DOMAIN\ServiceAccount",
        [string]$ServicePassword = "ServiceP@ssw0rd123!"
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "localhost" {
        $securePassword = ConvertTo-SecureString $ServicePassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($ServiceUser, $securePassword)
        
        Service AppService {
            Name = "MyAppService"
            Credential = $credential
            StartupType = "Automatic"
            State = "Running"
        }
    }
}

# Violation 10: WindowsFeature installing unnecessary features
Configuration InstallAllFeatures {
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "localhost" {
        WindowsFeature TelnetClient {
            Name = "Telnet-Client"
            Ensure = "Present"
        }
        
        WindowsFeature SMBv1 {
            Name = "FS-SMB1"
            Ensure = "Present"
        }
    }
}

# Violation 11: File resource with overly permissive access
Configuration PermissiveFiles {
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "localhost" {
        File SharedFolder {
            DestinationPath = "C:\SharedData"
            Type = "Directory"
            Ensure = "Present"
            Attributes = @("Archive")
            # Missing proper NTFS permissions
        }
    }
}

# Violation 12: Group resource adding users to Administrators
Configuration AddAdmins {
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "localhost" {
        Group AddToAdmins {
            GroupName = "Administrators"
            MembersToInclude = @("RegularUser", "TestAccount")
            Ensure = "Present"
        }
    }
}

# Violation 13: DSC without certificate encryption
$unencryptedConfigData = @{
    AllNodes = @(
        @{
            NodeName = "*"
            PSDscAllowPlainTextPassword = $true
            # Missing: CertificateFile and Thumbprint
        }
    )
}

# Correct usage examples (should not trigger violations)
# Using certificate-based credential encryption
$secureConfigData = @{
    AllNodes = @(
        @{
            NodeName = "*"
            CertificateFile = "C:\certs\dsc-public.cer"
            Thumbprint = "1234567890ABCDEF1234567890ABCDEF12345678"
        }
        @{
            NodeName = "Server01"
        }
    )
}

Configuration SecureDSC {
    param(
        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "Server01" {
        User SecureUser {
            UserName = "SecureUser"
            Password = $Credential
            Ensure = "Present"
        }
    }
}

# Generate MOF with encryption
SecureDSC -ConfigurationData $secureConfigData -Credential (Get-Credential) -OutputPath "C:\DSC\Secure"

# Using Script resource safely
Configuration SafeScript {
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "localhost" {
        Script SafeExecution {
            GetScript = { @{ Result = (Get-Service -Name "wuauserv").Status } }
            SetScript = { Start-Service -Name "wuauserv" }
            TestScript = { (Get-Service -Name "wuauserv").Status -eq "Running" }
        }
    }
}
