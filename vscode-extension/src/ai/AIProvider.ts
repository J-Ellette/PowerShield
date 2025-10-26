/**
 * AI Provider Interface
 * Defines the contract for AI providers in PowerShield
 */

import { SecurityViolation, AIFixResult, AIProviderConfig, FixContext } from '../types';

/**
 * Base interface for all AI providers
 */
export interface AIProvider {
    /**
     * Provider name (e.g., "GitHub Models", "OpenAI")
     */
    name: string;
    
    /**
     * Provider type identifier
     */
    type: 'github-models' | 'openai' | 'anthropic' | 'azure-openai' | 'local-llm' | 'template-based';
    
    /**
     * Initialize the provider with configuration
     */
    initialize(config: AIProviderConfig): Promise<void>;
    
    /**
     * Generate a fix for a security violation
     */
    generateFix(violation: SecurityViolation, context: FixContext): Promise<AIFixResult>;
    
    /**
     * Explain a security violation in detail
     */
    explainViolation(violation: SecurityViolation): Promise<string>;
    
    /**
     * Suggest best practices for the given code context
     */
    suggestBestPractices(codeContext: string): Promise<string[]>;
    
    /**
     * Check if the provider is available and configured
     */
    isAvailable(): Promise<boolean>;
}

/**
 * System prompt for PowerShell security analysis
 */
export const POWERSHELL_SECURITY_SYSTEM_PROMPT = `You are a PowerShell security expert assistant. Your role is to help developers write secure PowerShell code by:

1. Identifying security vulnerabilities and weaknesses
2. Providing clear, actionable fixes that maintain functionality
3. Explaining security concepts in an educational manner
4. Following PowerShell best practices and conventions
5. Considering the broader context of the code

When generating fixes:
- Maintain the original code's functionality
- Use secure alternatives that are well-documented
- Provide comments explaining the security improvement
- Follow PowerShell naming conventions and style
- Consider performance implications
- Ensure compatibility with PowerShell 7+

Focus on these security areas:
- Cryptographic operations (use modern algorithms)
- Credential handling (use SecureString, never plaintext)
- Command injection prevention (validate and sanitize input)
- Certificate validation (never bypass SSL/TLS checks)
- Secure communications (use TLS 1.2+)
- Data protection (encrypt sensitive data)
- Input validation (always validate user input)
- Error handling (avoid exposing sensitive information)`;

/**
 * Abstract base class for AI providers
 */
export abstract class BaseAIProvider implements AIProvider {
    abstract name: string;
    abstract type: 'github-models' | 'openai' | 'anthropic' | 'azure-openai' | 'local-llm' | 'template-based';
    
    protected config: AIProviderConfig | null = null;
    protected initialized: boolean = false;
    
    async initialize(config: AIProviderConfig): Promise<void> {
        this.config = config;
        this.initialized = true;
    }
    
    abstract generateFix(violation: SecurityViolation, context: FixContext): Promise<AIFixResult>;
    abstract explainViolation(violation: SecurityViolation): Promise<string>;
    abstract suggestBestPractices(codeContext: string): Promise<string[]>;
    
    async isAvailable(): Promise<boolean> {
        return this.initialized && this.config !== null;
    }
    
    /**
     * Build a fix prompt from violation and context
     */
    protected buildFixPrompt(violation: SecurityViolation, context: FixContext): string {
        const lines = [
            `# Security Violation Fix Request`,
            ``,
            `## Violation Details`,
            `- Rule: ${violation.ruleId}`,
            `- Severity: ${violation.severity}`,
            `- Message: ${violation.message}`,
            `- Line: ${violation.lineNumber}`,
            ``,
            `## Code Context`,
            ``,
            `### Before (${context.codeContext.beforeLines.length} lines)`,
            `\`\`\`powershell`,
            ...context.codeContext.beforeLines,
            `\`\`\``,
            ``,
            `### Target Code (to be fixed)`,
            `\`\`\`powershell`,
            context.codeContext.targetCode,
            `\`\`\``,
            ``,
            `### After (${context.codeContext.afterLines.length} lines)`,
            `\`\`\`powershell`,
            ...context.codeContext.afterLines,
            `\`\`\``
        ];
        
        if (context.codeContext.functionContext) {
            lines.push(
                ``,
                `## Function Context`,
                `- Name: ${context.codeContext.functionContext.name}`,
                `- Parameters: ${context.codeContext.functionContext.parameters.join(', ')}`,
                context.codeContext.functionContext.purpose ? `- Purpose: ${context.codeContext.functionContext.purpose}` : ''
            );
        }
        
        lines.push(
            ``,
            `## Requirements`,
            `1. Provide a secure fix that addresses the violation`,
            `2. Maintain the original functionality`,
            `3. Add comments explaining the security improvement`,
            `4. Follow PowerShell best practices`,
            `5. Provide confidence score (0-1) for the fix`,
            ``,
            `## Response Format`,
            `Provide your response as JSON:`,
            `{`,
            `  "fixedCode": "// the corrected code",`,
            `  "explanation": "// why this fix is secure",`,
            `  "confidence": 0.95,`,
            `  "alternative": "// optional alternative approach"`,
            `}`
        );
        
        return lines.filter(line => line !== undefined).join('\n');
    }
    
    /**
     * Build an explanation prompt for a violation
     */
    protected buildExplanationPrompt(violation: SecurityViolation): string {
        return `Explain this PowerShell security violation in detail:

Rule: ${violation.ruleId}
Severity: ${violation.severity}
Message: ${violation.message}
Code: ${violation.code}

Provide:
1. What the security issue is
2. Why it's a problem
3. Potential attack scenarios
4. How to fix it properly
5. Best practices to avoid this in the future

Keep the explanation clear, educational, and actionable.`;
    }
    
    /**
     * Parse a fix response from AI provider
     */
    protected parseFixResponse(response: string): AIFixResult {
        try {
            // Try to extract JSON from response
            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                const parsed = JSON.parse(jsonMatch[0]);
                return {
                    fixedCode: parsed.fixedCode || '',
                    explanation: parsed.explanation || '',
                    confidence: parsed.confidence || 0.5,
                    alternative: parsed.alternative
                };
            }
            
            // Fallback: treat entire response as explanation
            return {
                fixedCode: '',
                explanation: response,
                confidence: 0.3,
                alternative: undefined
            };
        } catch (error) {
            console.error('Failed to parse AI response:', error);
            return {
                fixedCode: '',
                explanation: response,
                confidence: 0.1,
                alternative: undefined
            };
        }
    }
}
