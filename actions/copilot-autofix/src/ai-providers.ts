/**
 * AI Provider Abstraction Layer
 * Supports multiple AI providers for generating security fixes
 */

import * as core from '@actions/core';
import * as https from 'https';
import { AutoFixConfig } from './config';

export interface AIProviderMessage {
    role: 'system' | 'user' | 'assistant';
    content: string;
}

export interface AIProviderResponse {
    content: string;
    model: string;
    usage?: {
        prompt_tokens: number;
        completion_tokens: number;
        total_tokens: number;
    };
}

export interface FixRequest {
    code: string;
    ruleId: string;
    ruleName: string;
    ruleDescription: string;
    severity: string;
    filePath: string;
    lineNumber: number;
    context?: string;  // Surrounding code context
}

export interface FixResponse {
    fixedCode: string;
    explanation: string;
    confidence: number;
    alternatives?: Array<{
        code: string;
        explanation: string;
        confidence: number;
    }>;
}

/**
 * Base class for AI providers
 */
export abstract class AIProvider {
    protected config: AutoFixConfig;
    protected apiKey?: string;

    constructor(config: AutoFixConfig, apiKey?: string) {
        this.config = config;
        this.apiKey = apiKey;
    }

    /**
     * Generate a fix for a security violation
     */
    abstract generateFix(request: FixRequest): Promise<FixResponse>;

    /**
     * Validate the provider is properly configured
     */
    abstract validate(): Promise<boolean>;

    /**
     * Get provider name
     */
    abstract getName(): string;

    /**
     * Create the system prompt for fix generation
     */
    protected createSystemPrompt(): string {
        return `You are a PowerShell security expert. Your task is to fix security vulnerabilities in PowerShell code.

Rules:
1. Only modify the specific vulnerable code
2. Preserve the original functionality
3. Use secure PowerShell best practices
4. Provide clear explanations
5. Maintain code style and formatting
6. Rate your confidence (0.0-1.0) honestly

Output format (JSON):
{
    "fixedCode": "the corrected code",
    "explanation": "brief explanation of the fix",
    "confidence": 0.85,
    "alternatives": [
        {
            "code": "alternative fix",
            "explanation": "why this alternative works",
            "confidence": 0.75
        }
    ]
}`;
    }

    /**
     * Create the user prompt for a specific violation
     */
    protected createUserPrompt(request: FixRequest): string {
        const contextSection = request.context 
            ? `\n\nSurrounding context:\n\`\`\`powershell\n${request.context}\n\`\`\``
            : '';

        return `Fix this PowerShell security violation:

Rule: ${request.ruleName} (${request.ruleId})
Severity: ${request.severity}
Description: ${request.ruleDescription}
File: ${request.filePath}:${request.lineNumber}

Vulnerable code:
\`\`\`powershell
${request.code}
\`\`\`${contextSection}

Provide a secure fix that addresses the ${request.ruleName} violation while preserving functionality.`;
    }

    /**
     * Parse AI response into FixResponse
     */
    protected parseFixResponse(content: string, fallbackCode: string): FixResponse {
        try {
            // Try to parse as JSON first
            const jsonMatch = content.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                const parsed = JSON.parse(jsonMatch[0]);
                return {
                    fixedCode: parsed.fixedCode || fallbackCode,
                    explanation: parsed.explanation || 'AI-generated fix',
                    confidence: Math.max(0, Math.min(1, parsed.confidence || 0.7)),
                    alternatives: parsed.alternatives || []
                };
            }

            // Fallback: extract code blocks
            const codeMatch = content.match(/```(?:powershell)?\s*([\s\S]*?)```/);
            const extractedCode = codeMatch ? codeMatch[1].trim() : fallbackCode;

            return {
                fixedCode: extractedCode,
                explanation: 'AI-generated fix (parsed from response)',
                confidence: 0.6  // Lower confidence for parsed responses
            };
        } catch (error) {
            core.warning(`Failed to parse AI response: ${error}`);
            return {
                fixedCode: fallbackCode,
                explanation: 'Failed to parse AI response',
                confidence: 0.3
            };
        }
    }

    /**
     * Make HTTPS request
     */
    protected async makeHttpsRequest(
        hostname: string,
        path: string,
        method: string,
        headers: { [key: string]: string },
        body?: string
    ): Promise<string> {
        return new Promise((resolve, reject) => {
            const options = {
                hostname,
                path,
                method,
                headers: {
                    'Content-Type': 'application/json',
                    ...headers,
                    ...(body && { 'Content-Length': Buffer.byteLength(body) })
                }
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(data);
                    } else {
                        reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                    }
                });
            });

            req.on('error', reject);
            if (body) req.write(body);
            req.end();
        });
    }
}

/**
 * GitHub Models API Provider (using existing GITHUB_TOKEN)
 */
export class GitHubModelsProvider extends AIProvider {
    private endpoint = 'https://models.inference.ai.azure.com';

    async generateFix(request: FixRequest): Promise<FixResponse> {
        try {
            const messages: AIProviderMessage[] = [
                { role: 'system', content: this.createSystemPrompt() },
                { role: 'user', content: this.createUserPrompt(request) }
            ];

            const requestBody = {
                messages,
                model: this.config.model || 'gpt-4o-mini',
                temperature: 0.3,
                max_tokens: 1000
            };

            core.debug(`Calling GitHub Models API for ${request.ruleId}`);

            const response = await this.makeHttpsRequest(
                'models.inference.ai.azure.com',
                '/chat/completions',
                'POST',
                {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                JSON.stringify(requestBody)
            );

            const parsed = JSON.parse(response);
            const content = parsed.choices?.[0]?.message?.content || '';

            return this.parseFixResponse(content, request.code);
        } catch (error) {
            core.warning(`GitHub Models API error: ${error}`);
            throw error;
        }
    }

    async validate(): Promise<boolean> {
        if (!this.apiKey) {
            core.warning('GitHub token not provided for GitHub Models');
            return false;
        }
        return true;
    }

    getName(): string {
        return 'GitHub Models';
    }
}

/**
 * OpenAI Provider
 */
export class OpenAIProvider extends AIProvider {
    async generateFix(request: FixRequest): Promise<FixResponse> {
        try {
            const messages: AIProviderMessage[] = [
                { role: 'system', content: this.createSystemPrompt() },
                { role: 'user', content: this.createUserPrompt(request) }
            ];

            const requestBody = {
                model: this.config.model || 'gpt-4o-mini',
                messages,
                temperature: 0.3,
                max_tokens: 1000
            };

            core.debug(`Calling OpenAI API for ${request.ruleId}`);

            const response = await this.makeHttpsRequest(
                'api.openai.com',
                '/v1/chat/completions',
                'POST',
                {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                JSON.stringify(requestBody)
            );

            const parsed = JSON.parse(response);
            const content = parsed.choices?.[0]?.message?.content || '';

            return this.parseFixResponse(content, request.code);
        } catch (error) {
            core.warning(`OpenAI API error: ${error}`);
            throw error;
        }
    }

    async validate(): Promise<boolean> {
        if (!this.apiKey) {
            core.warning('OpenAI API key not provided');
            return false;
        }
        return true;
    }

    getName(): string {
        return 'OpenAI';
    }
}

/**
 * Azure OpenAI Provider
 */
export class AzureOpenAIProvider extends AIProvider {
    private endpoint: string;
    private deployment: string;

    constructor(config: AutoFixConfig, apiKey?: string, endpoint?: string, deployment?: string) {
        super(config, apiKey);
        this.endpoint = endpoint || process.env.AZURE_OPENAI_ENDPOINT || '';
        this.deployment = deployment || process.env.AZURE_OPENAI_DEPLOYMENT || config.model;
    }

    async generateFix(request: FixRequest): Promise<FixResponse> {
        try {
            const messages: AIProviderMessage[] = [
                { role: 'system', content: this.createSystemPrompt() },
                { role: 'user', content: this.createUserPrompt(request) }
            ];

            const requestBody = {
                messages,
                temperature: 0.3,
                max_tokens: 1000
            };

            const url = new URL(this.endpoint);
            const path = `/openai/deployments/${this.deployment}/chat/completions?api-version=2024-02-15-preview`;

            core.debug(`Calling Azure OpenAI for ${request.ruleId}`);

            const response = await this.makeHttpsRequest(
                url.hostname,
                path,
                'POST',
                {
                    'api-key': this.apiKey || '',
                    'Content-Type': 'application/json'
                },
                JSON.stringify(requestBody)
            );

            const parsed = JSON.parse(response);
            const content = parsed.choices?.[0]?.message?.content || '';

            return this.parseFixResponse(content, request.code);
        } catch (error) {
            core.warning(`Azure OpenAI error: ${error}`);
            throw error;
        }
    }

    async validate(): Promise<boolean> {
        if (!this.apiKey || !this.endpoint) {
            core.warning('Azure OpenAI configuration incomplete');
            return false;
        }
        return true;
    }

    getName(): string {
        return 'Azure OpenAI';
    }
}

/**
 * Anthropic Claude Provider
 */
export class ClaudeProvider extends AIProvider {
    async generateFix(request: FixRequest): Promise<FixResponse> {
        try {
            const systemPrompt = this.createSystemPrompt();
            const userPrompt = this.createUserPrompt(request);

            const requestBody = {
                model: this.config.model || 'claude-3-5-sonnet-20241022',
                max_tokens: 1000,
                system: systemPrompt,
                messages: [
                    { role: 'user', content: userPrompt }
                ]
            };

            core.debug(`Calling Claude API for ${request.ruleId}`);

            const response = await this.makeHttpsRequest(
                'api.anthropic.com',
                '/v1/messages',
                'POST',
                {
                    'x-api-key': this.apiKey || '',
                    'anthropic-version': '2023-06-01',
                    'Content-Type': 'application/json'
                },
                JSON.stringify(requestBody)
            );

            const parsed = JSON.parse(response);
            const content = parsed.content?.[0]?.text || '';

            return this.parseFixResponse(content, request.code);
        } catch (error) {
            core.warning(`Claude API error: ${error}`);
            throw error;
        }
    }

    async validate(): Promise<boolean> {
        if (!this.apiKey) {
            core.warning('Claude API key not provided');
            return false;
        }
        return true;
    }

    getName(): string {
        return 'Anthropic Claude';
    }
}

/**
 * Template-based provider (fallback, no AI)
 */
export class TemplateProvider extends AIProvider {
    async generateFix(request: FixRequest): Promise<FixResponse> {
        // Use rule-based templates
        const fix = this.getTemplateBasedFix(request);
        
        return {
            fixedCode: fix.fixedCode,
            explanation: fix.explanation,
            confidence: fix.confidence
        };
    }

    async validate(): Promise<boolean> {
        return true;  // Always valid, no external dependencies
    }

    getName(): string {
        return 'Template-based';
    }

    private getTemplateBasedFix(request: FixRequest): FixResponse {
        const templates: Record<string, any> = {
            'InsecureHashAlgorithms': {
                patterns: [
                    { from: /MD5/gi, to: 'SHA256' },
                    { from: /SHA1/gi, to: 'SHA256' },
                    { from: /RIPEMD160/gi, to: 'SHA256' }
                ],
                explanation: 'Replaced insecure hash algorithm with SHA256',
                confidence: 0.9
            },
            'CredentialExposure': {
                patterns: [
                    { 
                        from: /ConvertTo-SecureString\s+["'][^"']*["']\s+-AsPlainText\s+-Force/gi, 
                        to: 'Read-Host "Enter password" -AsSecureString'
                    }
                ],
                explanation: 'Replaced plaintext password with secure input',
                confidence: 0.85
            },
            'CommandInjection': {
                patterns: [
                    { 
                        from: /Invoke-Expression\s+/gi, 
                        to: '# SECURITY: Removed Invoke-Expression - validate input and use safer alternatives\n# '
                    }
                ],
                explanation: 'Removed command injection vulnerability',
                confidence: 0.8
            },
            'CertificateValidation': {
                patterns: [
                    { 
                        from: /\[System\.Net\.ServicePointManager\]::ServerCertificateValidationCallback\s*=\s*\{\s*\$true\s*\}/gi,
                        to: '# SECURITY: Implement proper certificate validation instead of bypassing'
                    }
                ],
                explanation: 'Removed certificate validation bypass',
                confidence: 0.85
            },
            'AzurePowerShellCredentialLeaks': {
                patterns: [
                    { 
                        from: /Connect-AzAccount\s+.*-Credential/gi, 
                        to: '# SECURITY: Use Managed Identity or certificate-based authentication\nConnect-AzAccount -Identity  # For managed identity\n# Connect-AzAccount -ServicePrincipal -TenantId $tenantId -CertificateThumbprint $thumbprint -ApplicationId $appId  # For certificate auth'
                    },
                    { 
                        from: /\$.*(?:StorageAccountKey|AccountKey)\s*=\s*["'][^"']*["']/gi, 
                        to: '# SECURITY: Retrieve storage key from Key Vault or use managed identity\n$storageKey = Get-AzKeyVaultSecret -VaultName "YourKeyVault" -Name "StorageAccountKey" -AsPlainText'
                    },
                    { 
                        from: /\$.*(?:ServicePrincipalKey|AppSecret|ClientSecret)\s*=\s*["'][^"']*["']/gi, 
                        to: '# SECURITY: Use certificate-based authentication or retrieve secret from Key Vault\n$clientSecret = Get-AzKeyVaultSecret -VaultName "YourKeyVault" -Name "ClientSecret" -AsPlainText'
                    },
                    { 
                        from: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+/gi, 
                        to: '# SECURITY: Use managed identity or retrieve connection string from Key Vault\n$connectionString = Get-AzKeyVaultSecret -VaultName "YourKeyVault" -Name "StorageConnectionString" -AsPlainText'
                    }
                ],
                explanation: 'Replaced hardcoded Azure credentials with secure alternatives',
                confidence: 0.8
            },
            'AzureResourceExposure': {
                patterns: [
                    { 
                        from: /-Permission\s+(Blob|Container)/gi, 
                        to: '-Permission Off  # Use private access and configure specific access via SAS tokens or RBAC'
                    },
                    { 
                        from: /-StartIpAddress\s+"0\.0\.0\.0"/gi, 
                        to: '-StartIpAddress "YOUR_SPECIFIC_IP_RANGE"  # Replace with specific IP ranges only'
                    },
                    { 
                        from: /-SourceAddressPrefix\s+(\*|Internet|"0\.0\.0\.0\/0")/gi, 
                        to: '-SourceAddressPrefix "SPECIFIC_SUBNET"  # Replace with specific subnet or IP range'
                    },
                    { 
                        from: /-PermissionsToSecrets\s+(all|\*)/gi, 
                        to: '-PermissionsToSecrets @("Get", "List")  # Use least privilege principle'
                    },
                    { 
                        from: /-PermissionsToKeys\s+(all|\*)/gi, 
                        to: '-PermissionsToKeys @("Get", "Decrypt")  # Use least privilege principle'
                    }
                ],
                explanation: 'Applied security best practices to Azure resource configurations',
                confidence: 0.85
            }
        };

        const template = templates[request.ruleId];
        if (!template) {
            return {
                fixedCode: request.code,
                explanation: 'No template available for this rule',
                confidence: 0.0
            };
        }

        let fixedCode = request.code;
        let matched = false;

        for (const pattern of template.patterns) {
            if (pattern.from.test(fixedCode)) {
                fixedCode = fixedCode.replace(pattern.from, pattern.to);
                matched = true;
                break;
            }
        }

        return {
            fixedCode: matched ? fixedCode : request.code,
            explanation: matched ? template.explanation : 'No matching pattern found',
            confidence: matched ? template.confidence : 0.0
        };
    }
}

/**
 * Factory for creating AI providers
 */
export class AIProviderFactory {
    static createProvider(config: AutoFixConfig, githubToken?: string): AIProvider {
        const provider = config.provider || 'github-models';

        switch (provider) {
            case 'github-models':
                return new GitHubModelsProvider(config, githubToken);
            
            case 'openai':
                const openaiKey = process.env.OPENAI_API_KEY;
                return new OpenAIProvider(config, openaiKey);
            
            case 'azure':
                const azureKey = process.env.AZURE_OPENAI_KEY;
                return new AzureOpenAIProvider(config, azureKey);
            
            case 'claude':
                const claudeKey = process.env.ANTHROPIC_API_KEY;
                return new ClaudeProvider(config, claudeKey);
            
            case 'template':
                return new TemplateProvider(config);
            
            default:
                core.warning(`Unknown provider: ${provider}, falling back to template-based`);
                return new TemplateProvider(config);
        }
    }
}
