/**
 * Template-Based AI Provider
 * Fallback provider using rule-based templates (no AI API required)
 */

import { BaseAIProvider } from './AIProvider';
import { SecurityViolation, AIFixResult, AIProviderConfig, FixContext } from '../types';

/**
 * Template-based fix patterns for common security issues
 */
interface FixTemplate {
    rulePattern: RegExp;
    generateFix: (violation: SecurityViolation, context: FixContext) => AIFixResult;
    explanation: string;
}

/**
 * Template-based provider implementation (no external API required)
 */
export class TemplateBasedProvider extends BaseAIProvider {
    name = "Template-Based";
    type = "template-based" as const;
    
    private templates: FixTemplate[] = [];
    
    async initialize(config: AIProviderConfig): Promise<void> {
        await super.initialize(config);
        this.initializeTemplates();
    }
    
    async isAvailable(): Promise<boolean> {
        return true; // Always available as fallback
    }
    
    async generateFix(
        violation: SecurityViolation, 
        context: FixContext
    ): Promise<AIFixResult> {
        // Find matching template
        for (const template of this.templates) {
            if (template.rulePattern.test(violation.ruleId)) {
                return template.generateFix(violation, context);
            }
        }
        
        // Default fallback
        return {
            fixedCode: context.codeContext.targetCode,
            explanation: `No template available for ${violation.ruleId}. Please review the security documentation for manual fix guidance.`,
            confidence: 0.1,
            alternative: undefined
        };
    }
    
    async explainViolation(violation: SecurityViolation): Promise<string> {
        // Find matching template
        for (const template of this.templates) {
            if (template.rulePattern.test(violation.ruleId)) {
                return template.explanation;
            }
        }
        
        // Default explanation
        return `Security Issue: ${violation.message}\n\nSeverity: ${violation.severity}\n\nThis security violation requires attention. Please review your code and consult security best practices.`;
    }
    
    async suggestBestPractices(codeContext: string): Promise<string[]> {
        return [
            "Use SecureString for sensitive data instead of plain text",
            "Always validate and sanitize user input",
            "Use modern cryptographic algorithms (SHA256, AES)",
            "Never bypass SSL/TLS certificate validation",
            "Implement proper error handling without exposing sensitive information"
        ];
    }
    
    /**
     * Initialize fix templates
     */
    private initializeTemplates(): void {
        this.templates = [
            // Insecure hash algorithms
            {
                rulePattern: /InsecureHash|MD5|SHA1|RIPEMD/i,
                generateFix: (violation, context) => {
                    const code = context.codeContext.targetCode;
                    let fixedCode = code;
                    
                    // Replace MD5 with SHA256
                    fixedCode = fixedCode.replace(/\bMD5\b/gi, 'SHA256');
                    fixedCode = fixedCode.replace(/\bSHA1\b/gi, 'SHA256');
                    fixedCode = fixedCode.replace(/\bRIPEMD160\b/gi, 'SHA256');
                    
                    return {
                        fixedCode,
                        explanation: "Replaced insecure hash algorithm with SHA256, which is cryptographically secure and recommended for modern applications.",
                        confidence: 0.9,
                        alternative: "Consider using SHA384 or SHA512 for even stronger security requirements."
                    };
                },
                explanation: "MD5, SHA1, and RIPEMD160 are cryptographically broken hash algorithms. They are vulnerable to collision attacks and should not be used for security-sensitive operations. Use SHA256 or stronger algorithms instead."
            },
            
            // Credential exposure
            {
                rulePattern: /Credential|Password|Secret/i,
                generateFix: (violation, context) => {
                    const code = context.codeContext.targetCode;
                    let fixedCode = code;
                    
                    // Replace ConvertTo-SecureString with Read-Host -AsSecureString
                    if (code.includes('ConvertTo-SecureString') && code.includes('$password')) {
                        fixedCode = `# Prompt user for password securely (not stored in plain text)
$password = Read-Host -Prompt "Enter password" -AsSecureString`;
                    } else if (code.match(/\$\w+\s*=\s*["'].*["']/)) {
                        // Replace plain text assignment
                        fixedCode = `# Use SecureString for sensitive data
$securePassword = Read-Host -Prompt "Enter password" -AsSecureString
# Convert to credential object if needed
$credential = New-Object System.Management.Automation.PSCredential("username", $securePassword)`;
                    }
                    
                    return {
                        fixedCode,
                        explanation: "Replaced plain text password handling with SecureString, which encrypts the password in memory and prevents it from being stored as plain text.",
                        confidence: 0.85,
                        alternative: "Consider using Azure Key Vault or Windows Credential Manager for production environments."
                    };
                },
                explanation: "Storing passwords or credentials in plain text exposes them to anyone who can read the script or memory dumps. Always use SecureString, PSCredential objects, or secure credential storage systems."
            },
            
            // Command injection
            {
                rulePattern: /CommandInjection|Invoke-Expression/i,
                generateFix: (violation, context) => {
                    const code = context.codeContext.targetCode;
                    
                    return {
                        fixedCode: `# SECURITY WARNING: Invoke-Expression with user input removed
# TODO: Replace with specific cmdlet or validated parameter
# Original code: ${code}
# Consider using switch statement or validated parameter sets instead`,
                        explanation: "Removed dangerous Invoke-Expression call. This prevents command injection attacks where malicious input could execute arbitrary code. Use specific cmdlets or validate input against an allowlist instead.",
                        confidence: 0.7,
                        alternative: "Use a switch statement with predefined commands, or validate input against a strict allowlist of permitted values."
                    };
                },
                explanation: "Invoke-Expression executes arbitrary PowerShell code, which is extremely dangerous when combined with user input. Attackers can inject malicious commands that will be executed with the script's privileges. Always use specific cmdlets and validate input."
            },
            
            // Certificate validation bypass
            {
                rulePattern: /Certificate|SSL|TLS|ServerCertificateValidation/i,
                generateFix: (violation, context) => {
                    return {
                        fixedCode: `# SECURITY WARNING: Certificate validation bypass removed
# SSL/TLS certificate validation is critical for secure communications
# Do not disable certificate validation in production environments
# If you need to work with self-signed certificates, add them to the trusted root store`,
                        explanation: "Removed certificate validation bypass. This prevents man-in-the-middle attacks by ensuring SSL/TLS certificates are properly validated.",
                        confidence: 0.95,
                        alternative: "Add self-signed certificates to the Windows trusted root certificate store instead of bypassing validation."
                    };
                },
                explanation: "Bypassing SSL/TLS certificate validation defeats the purpose of encrypted connections. It makes your application vulnerable to man-in-the-middle attacks where an attacker can intercept and modify communications. Always validate certificates in production."
            }
        ];
    }
}
