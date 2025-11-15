/**
 * Anthropic AI Provider
 * Uses Anthropic Claude API for AI-powered security fixes
 */

import { BaseAIProvider, POWERSHELL_SECURITY_SYSTEM_PROMPT } from './AIProvider';
import { SecurityViolation, AIFixResult, AIProviderConfig, FixContext } from '../types';

/**
 * Anthropic provider implementation
 */
export class AnthropicProvider extends BaseAIProvider {
    name = "Anthropic Claude";
    type = "anthropic" as const;
    
    private apiKey: string | null = null;
    private endpoint: string = "https://api.anthropic.com/v1";
    private model: string = "claude-3-5-sonnet-20241022";
    
    async initialize(config: AIProviderConfig): Promise<void> {
        await super.initialize(config);
        
        this.apiKey = config.apiKey || process.env.ANTHROPIC_API_KEY || null;
        if (config.endpoint) {
            this.endpoint = config.endpoint;
        }
        if (config.model) {
            this.model = config.model;
        }
    }
    
    async isAvailable(): Promise<boolean> {
        return this.initialized && this.apiKey !== null;
    }
    
    async generateFix(
        violation: SecurityViolation, 
        context: FixContext
    ): Promise<AIFixResult> {
        if (!this.apiKey) {
            throw new Error('Anthropic API key not configured');
        }
        
        const prompt = this.buildFixPrompt(violation, context);
        
        try {
            const response = await this.callAPI({
                model: this.model,
                max_tokens: this.config?.maxTokens || 1000,
                system: POWERSHELL_SECURITY_SYSTEM_PROMPT,
                messages: [
                    {
                        role: "user",
                        content: prompt
                    }
                ],
                temperature: 0.1
            });
            
            const content = response.content?.[0]?.text || '';
            return this.parseFixResponse(content);
        } catch (error) {
            console.error('Anthropic API error:', error);
            throw new Error(`Failed to generate fix: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    
    async explainViolation(violation: SecurityViolation): Promise<string> {
        if (!this.apiKey) {
            throw new Error('Anthropic API key not configured');
        }
        
        const prompt = this.buildExplanationPrompt(violation);
        
        try {
            const response = await this.callAPI({
                model: this.model,
                max_tokens: 500,
                system: POWERSHELL_SECURITY_SYSTEM_PROMPT,
                messages: [
                    {
                        role: "user",
                        content: prompt
                    }
                ],
                temperature: 0.3
            });
            
            return response.content?.[0]?.text || 'Unable to generate explanation';
        } catch (error) {
            console.error('Anthropic API error:', error);
            throw new Error(`Failed to explain violation: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    
    async suggestBestPractices(codeContext: string): Promise<string[]> {
        if (!this.apiKey) {
            throw new Error('Anthropic API key not configured');
        }
        
        const prompt = `Analyze this PowerShell code and suggest security best practices:

\`\`\`powershell
${codeContext}
\`\`\`

Provide 3-5 specific, actionable security best practices that would improve this code.
Format as a JSON array of strings.`;
        
        try {
            const response = await this.callAPI({
                model: this.model,
                max_tokens: 300,
                system: POWERSHELL_SECURITY_SYSTEM_PROMPT,
                messages: [
                    {
                        role: "user",
                        content: prompt
                    }
                ],
                temperature: 0.3
            });
            
            const content = response.content?.[0]?.text || '[]';
            
            // Try to extract JSON array
            const jsonMatch = content.match(/\[[\s\S]*\]/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
            
            // Fallback: split by lines
            return content.split('\n').filter((line: string) => line.trim().length > 0).slice(0, 5);
        } catch (error) {
            console.error('Anthropic API error:', error);
            return [];
        }
    }
    
    /**
     * Call Anthropic API
     */
    private async callAPI(request: any): Promise<any> {
        const response = await fetch(`${this.endpoint}/messages`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': this.apiKey!,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify(request)
        });
        
        if (!response.ok) {
            const error = await response.text();
            throw new Error(`API request failed: ${response.status} ${error}`);
        }
        
        return await response.json();
    }
}
