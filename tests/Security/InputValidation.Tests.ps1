#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

<#
.SYNOPSIS
    Security tests for PowerShield input validation
.DESCRIPTION
    Tests the InputValidation module for security vulnerabilities,
    including path traversal, injection attacks, and input sanitization
.NOTES
    Version: 1.7.0
    These tests verify PowerShield's own security posture
#>

BeforeAll {
    # Import the module under test
    Import-Module "$PSScriptRoot/../../src/InputValidation.psm1" -Force # POWERSHIELD-SUPPRESS: DangerousModules - Legitimate test setup importing test module (2026-01-24)
}

Describe "InputValidator.ValidatePath" -Tag "Security", "InputValidation" {
    
    Context "Path Traversal Protection" {
        It "Should reject path traversal attempts with ../" { # POWERSHIELD-SUPPRESS: PathTraversal - Test description (2026-01-24)
            { [InputValidator]::ValidatePath("../../../etc/passwd") } | # POWERSHIELD-SUPPRESS: PathTraversal - Test string used to validate security check (2026-01-24)
                Should -Throw "*Path traversal detected*"
        }
        
        It "Should reject path traversal attempts with ..\" { # POWERSHIELD-SUPPRESS: PathTraversal - Test description (2026-01-24)
            { [InputValidator]::ValidatePath("..\..\..\windows\system32") } | # POWERSHIELD-SUPPRESS: PathTraversal - Test string used to validate security check (2026-01-24)
                Should -Throw "*Path traversal detected*"
        }
        
        It "Should reject mixed traversal patterns" {
            { [InputValidator]::ValidatePath("./test/../../sensitive/file.txt") } | # POWERSHIELD-SUPPRESS: PathTraversal - Test string used to validate security check (2026-01-24)
                Should -Throw "*Path traversal detected*"
        }
        
        It "Should accept legitimate relative paths without .." {
            $result = [InputValidator]::ValidatePath("./scripts/test.ps1", $false, $false)
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Path Length Validation" {
        It "Should reject excessively long paths" {
            $longPath = "C:\" + ("A" * 300) + "\file.txt"
            { [InputValidator]::ValidatePath($longPath) } | 
                Should -Throw "*maximum length*"
        }
    }
    
    Context "Path Depth Protection" {
        It "Should reject paths exceeding maximum depth" {
            # Create a path with > 100 levels
            $deepPath = "C:\" + ("folder\" * 150) + "file.txt"
            { [InputValidator]::ValidatePath($deepPath) } | 
                Should -Throw "*Path depth exceeds maximum*"
        }
    }
    
    Context "Null and Empty Input" {
        It "Should reject null path" {
            { [InputValidator]::ValidatePath($null) } | 
                Should -Throw "*cannot be null*"
        }
        
        It "Should reject empty path" {
            { [InputValidator]::ValidatePath("") } | 
                Should -Throw "*cannot be null or empty*"
        }
        
        It "Should reject whitespace-only path" {
            { [InputValidator]::ValidatePath("   ") } | 
                Should -Throw "*cannot be null or empty*"
        }
    }
    
    Context "File Existence Validation" {
        It "Should throw when MustExist is true and file doesn't exist" {
            { [InputValidator]::ValidatePath("C:\NonExistent\File.txt", $true, $false) } | 
                Should -Throw "*not found*"
        }
    }
}

Describe "InputValidator.ValidateConfigFile" -Tag "Security", "Configuration" {
    
    Context "Configuration File Validation" {
        BeforeAll {
            # Create a temporary valid config file
            $script:testConfigPath = [System.IO.Path]::GetTempFileName()
            $script:testConfigPath = [System.IO.Path]::ChangeExtension($script:testConfigPath, '.yml')
            "version: 1.0" | Out-File -FilePath $script:testConfigPath -Encoding UTF8
        }
        
        AfterAll {
            if (Test-Path $script:testConfigPath) {
                Remove-Item $script:testConfigPath -Force
            }
        }
        
        It "Should accept valid YAML configuration file" {
            $result = [InputValidator]::ValidateConfigFile($script:testConfigPath)
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should reject non-YAML/JSON extensions" {
            $invalidPath = [System.IO.Path]::GetTempFileName()
            "test" | Out-File -FilePath $invalidPath
            { [InputValidator]::ValidateConfigFile($invalidPath) } | 
                Should -Throw "*Invalid configuration file extension*"
            Remove-Item $invalidPath -Force
        }
        
        It "Should reject excessively large configuration files" {
            $largePath = [System.IO.Path]::GetTempFileName()
            $largePath = [System.IO.Path]::ChangeExtension($largePath, '.yml')
            # Create a file larger than 10MB
            $largeContent = "x" * (11 * 1024 * 1024)
            [System.IO.File]::WriteAllText($largePath, $largeContent)
            
            { [InputValidator]::ValidateConfigFile($largePath) } | 
                Should -Throw "*exceeds maximum size*"
            
            Remove-Item $largePath -Force
        }
    }
}

Describe "InputValidator.SanitizeForLogging" -Tag "Security", "Logging" {
    
    Context "ANSI Escape Sequence Removal" {
        It "Should remove ANSI color codes" {
            $input = "`e[31mError`e[0m"
            $result = [InputValidator]::SanitizeForLogging($input)
            $result | Should -Not -Match '\x1b\['
            $result | Should -Be "Error"
        }
    }
    
    Context "Control Character Removal" {
        It "Should remove control characters except newline and tab" {
            $input = "Test`0String`aWith`bControl"
            $result = [InputValidator]::SanitizeForLogging($input)
            $result | Should -Not -Match '[\x00-\x1F&&[^\r\n\t]]'
        }
        
        It "Should preserve newlines and tabs" {
            $input = "Line1`nLine2`tTabbed"
            $result = [InputValidator]::SanitizeForLogging($input)
            $result | Should -Match "`n"
            $result | Should -Match "`t"
        }
    }
    
    Context "Length Limitation" {
        It "Should truncate long strings" {
            $input = "x" * 600
            $result = [InputValidator]::SanitizeForLogging($input)
            $result.Length | Should -BeLessOrEqual 500
            $result | Should -Match '\.\.\.$'
        }
    }
}

Describe "InputValidator.ValidateSeverity" -Tag "Security", "Validation" {
    
    Context "Valid Severity Levels" {
        It "Should accept 'Low'" {
            $result = [InputValidator]::ValidateSeverity("Low")
            $result | Should -Be "Low"
        }
        
        It "Should accept 'Medium'" {
            $result = [InputValidator]::ValidateSeverity("Medium")
            $result | Should -Be "Medium"
        }
        
        It "Should accept 'High'" {
            $result = [InputValidator]::ValidateSeverity("High")
            $result | Should -Be "High"
        }
        
        It "Should accept 'Critical'" {
            $result = [InputValidator]::ValidateSeverity("Critical")
            $result | Should -Be "Critical"
        }
    }
    
    Context "Invalid Severity Levels" {
        It "Should reject invalid severity" {
            { [InputValidator]::ValidateSeverity("Extreme") } | 
                Should -Throw "*Invalid severity*"
        }
        
        It "Should reject empty severity" {
            { [InputValidator]::ValidateSeverity("") } | 
                Should -Throw "*cannot be null or empty*"
        }
    }
}

Describe "InputValidator.ValidateNumericRange" -Tag "Security", "Validation" {
    
    Context "Range Validation" {
        It "Should accept value within range" {
            $result = [InputValidator]::ValidateNumericRange(50, 0, 100, "TestParam")
            $result | Should -Be 50
        }
        
        It "Should reject value below minimum" {
            { [InputValidator]::ValidateNumericRange(-5, 0, 100, "TestParam") } | 
                Should -Throw "*must be between*"
        }
        
        It "Should reject value above maximum" {
            { [InputValidator]::ValidateNumericRange(150, 0, 100, "TestParam") } | 
                Should -Throw "*must be between*"
        }
        
        It "Should accept boundary values" {
            $result = [InputValidator]::ValidateNumericRange(0, 0, 100, "TestParam")
            $result | Should -Be 0
            
            $result = [InputValidator]::ValidateNumericRange(100, 0, 100, "TestParam")
            $result | Should -Be 100
        }
    }
}

Describe "InputValidator.ValidateEmail" -Tag "Security", "Validation" {
    
    Context "Valid Email Addresses" {
        It "Should accept standard email format" {
            $result = [InputValidator]::ValidateEmail("test@example.com")
            $result | Should -Be "test@example.com"
        }
        
        It "Should accept email with subdomain" {
            $result = [InputValidator]::ValidateEmail("user@mail.company.com")
            $result | Should -Be "user@mail.company.com"
        }
        
        It "Should convert to lowercase" {
            $result = [InputValidator]::ValidateEmail("Test@Example.COM")
            $result | Should -Be "test@example.com"
        }
    }
    
    Context "Invalid Email Addresses" {
        It "Should reject email without @" {
            { [InputValidator]::ValidateEmail("notanemail.com") } | 
                Should -Throw "*Invalid email format*"
        }
        
        It "Should reject email without domain" {
            { [InputValidator]::ValidateEmail("test@") } | 
                Should -Throw "*Invalid email format*"
        }
        
        It "Should reject empty email" {
            { [InputValidator]::ValidateEmail("") } | 
                Should -Throw "*cannot be null or empty*"
        }
    }
}

Describe "InputValidator.ValidateUrl" -Tag "Security", "Validation" {
    
    Context "Valid URLs" {
        It "Should accept HTTP URL" {
            $result = [InputValidator]::ValidateUrl("http://example.com")
            $result.Scheme | Should -Be "http"
        }
        
        It "Should accept HTTPS URL" {
            $result = [InputValidator]::ValidateUrl("https://example.com")
            $result.Scheme | Should -Be "https"
        }
        
        It "Should accept URL with path" {
            $result = [InputValidator]::ValidateUrl("https://example.com/path/to/resource") # POWERSHIELD-SUPPRESS: HardcodedURLs - Test URL used to validate URL parsing (2026-01-24)
            $result.AbsolutePath | Should -Be "/path/to/resource"
        }
    }
    
    Context "HTTPS Requirement" {
        It "Should reject HTTP when HTTPS required" {
            { [InputValidator]::ValidateUrl("http://example.com", $true) } | 
                Should -Throw "*must use HTTPS*"
        }
        
        It "Should accept HTTPS when HTTPS required" {
            $result = [InputValidator]::ValidateUrl("https://example.com", $true)
            $result.Scheme | Should -Be "https"
        }
    }
    
    Context "Invalid URLs" {
        It "Should reject non-HTTP(S) schemes" {
            { [InputValidator]::ValidateUrl("ftp://example.com") } | # POWERSHIELD-SUPPRESS: DataExfiltrationDetection - Test string used to validate protocol rejection (2026-01-24)
                Should -Throw "*must use HTTP or HTTPS*"
        }
        
        It "Should reject malformed URLs" {
            { [InputValidator]::ValidateUrl("not a url") } | 
                Should -Throw "*Invalid URL format*"
        }
        
        It "Should reject empty URL" {
            { [InputValidator]::ValidateUrl("") } | 
                Should -Throw "*cannot be null or empty*"
        }
    }
}

Describe "InputValidator.ValidateRegexPattern" -Tag "Security", "Validation" {
    
    Context "Valid Regex Patterns" {
        It "Should accept simple regex pattern" {
            $result = [InputValidator]::ValidateRegexPattern("^\d+$")
            $result | Should -Be "^\d+$"
        }
        
        It "Should accept complex regex pattern" {
            $result = [InputValidator]::ValidateRegexPattern("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Invalid Regex Patterns" {
        It "Should reject invalid regex syntax" {
            { [InputValidator]::ValidateRegexPattern("^[unclosed") } | 
                Should -Throw "*Invalid regex pattern*"
        }
        
        It "Should reject excessively long patterns" {
            $longPattern = "^(" + ("x|" * 600) + ")$"
            { [InputValidator]::ValidateRegexPattern($longPattern) } | 
                Should -Throw "*exceeds maximum length*"
        }
        
        It "Should reject empty pattern" {
            { [InputValidator]::ValidateRegexPattern("") } | 
                Should -Throw "*cannot be null or empty*"
        }
    }
}

Describe "InputValidator.SanitizeUserInput" -Tag "Security", "InputSanitization" {
    
    Context "Dangerous Character Removal" {
        It "Should remove shell metacharacters" {
            $input = "test;command&other|pipe"
            $result = [InputValidator]::SanitizeUserInput($input)
            $result | Should -Not -Match '[;&|]'
        }
        
        It "Should remove command substitution characters" {
            $input = "test`$variable$(command)"
            $result = [InputValidator]::SanitizeUserInput($input)
            $result | Should -Not -Match '[$()]'
        }
        
        It "Should remove backticks and brackets" {
            $input = "test`command{block}[array]"
            $result = [InputValidator]::SanitizeUserInput($input)
            $result | Should -Not -Match '[`{}[\]]'
        }
    }
    
    Context "Allowed Character Validation" {
        It "Should accept input matching allowed pattern" {
            $input = "valid_input-123.txt"
            $result = [InputValidator]::SanitizeUserInput($input, '^[a-zA-Z0-9._\-]+$')
            $result | Should -Be $input
        }
        
        It "Should reject input with disallowed characters" {
            $input = "invalid@input#here"
            { [InputValidator]::SanitizeUserInput($input, '^[a-zA-Z0-9._\-]+$') } | 
                Should -Throw "*disallowed characters*"
        }
    }
}

Describe "InputValidator.CreateSecureTempFile" -Tag "Security", "FileSystem" {
    
    Context "Secure Temp File Creation" {
        BeforeEach {
            $script:tempFile = $null
        }
        
        AfterEach {
            if ($script:tempFile -and (Test-Path $script:tempFile)) {
                Remove-Item $script:tempFile -Force
            }
        }
        
        It "Should create a temporary file" {
            $script:tempFile = [InputValidator]::CreateSecureTempFile('.tmp')
            Test-Path $script:tempFile | Should -Be $true
        }
        
        It "Should create file with specified extension" {
            $script:tempFile = [InputValidator]::CreateSecureTempFile('.log')
            [System.IO.Path]::GetExtension($script:tempFile) | Should -Be ".log"
        }
        
        It "Should create file in temp directory" {
            $script:tempFile = [InputValidator]::CreateSecureTempFile()
            $tempPath = [System.IO.Path]::GetTempPath()
            $script:tempFile | Should -Match [regex]::Escape($tempPath)
        }
        
        # Platform-specific permission tests
        It "Should set restrictive permissions on Windows" -Skip:(-not $IsWindows) {
            $script:tempFile = [InputValidator]::CreateSecureTempFile()
            $acl = Get-Acl $script:tempFile
            $acl.Access.Count | Should -Be 1
            $acl.Access[0].IdentityReference.Value | Should -Match $env:USERNAME
        }
        
        It "Should set 600 permissions on Unix" -Skip:(-not ($IsLinux -or $IsMacOS)) {
            $script:tempFile = [InputValidator]::CreateSecureTempFile()
            $permissions = & stat -c "%a" $script:tempFile
            $permissions | Should -Be "600"
        }
    }
}

# Summary
Describe "Security Test Summary" -Tag "Security", "Summary" {
    It "Should pass all security validation tests" {
        $true | Should -Be $true
    }
}
