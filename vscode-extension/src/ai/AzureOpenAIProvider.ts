/**
 * Azure OpenAI AI Provider
 * Uses Azure OpenAI Service for AI-powered security fixes
 */

import { BaseAIProvider, POWERSHELL_SECURITY_SYSTEM_PROMPT } from './AIProvider';
import { SecurityViolation, AIFixResult, AIProviderConfig, FixContext } from '../types';

/**
 * Azure OpenAI provider implementation
 */
export class AzureOpenAIProvider extends BaseAIProvider {
    name = "Azure OpenAI";
    type = "azure-openai" as const;
    
    private apiKey: string | null = null;
    private endpoint: string | null = null;
    private deploymentName: string = "gpt-4";
    private apiVersion: string = "2024-02-15-preview";
    
    async initialize(config: AIProviderConfig): Promise<void> {
        await super.initialize(config);
        
        this.apiKey = config.apiKey || process.env.AZURE_OPENAI_API_KEY || null;
        this.endpoint = config.endpoint || process.env.AZURE_OPENAI_ENDPOINT || null;
        
        if (config.model) {
            this.deploymentName = config.model;
        }
    }
    
    async isAvailable(): Promise<boolean> {
        return this.initialized && this.apiKey !== null && this.endpoint !== null;
    }
    
    async generateFix(
        violation: SecurityViolation, 
        context: FixContext
    ): Promise<AIFixResult> {
        if (!this.apiKey || !this.endpoint) {
            throw new Error('Azure OpenAI API key or endpoint not configured');
        }
        
        const prompt = this.buildFixPrompt(violation, context);
        
        try {
            const response = await this.callAPI({
                messages: [
                    {
                        role: "system",
                        content: POWERSHELL_SECURITY_SYSTEM_PROMPT
                    },
                    {
                        role: "user",
                        content: prompt
                    }
                ],
                temperature: 0.1,
                max_tokens: this.config?.maxTokens || 1000
            });
            
            const content = response.choices?.[0]?.message?.content || '';
            return this.parseFixResponse(content);
        } catch (error) {
            console.error('Azure OpenAI API error:', error);
            throw new Error(`Failed to generate fix: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    
    async explainViolation(violation: SecurityViolation): Promise<string> {
        if (!this.apiKey || !this.endpoint) {
            throw new Error('Azure OpenAI API key or endpoint not configured');
        }
        
        const prompt = this.buildExplanationPrompt(violation);
        
        try {
            const response = await this.callAPI({
                messages: [
                    {
                        role: "system",
                        content: POWERSHELL_SECURITY_SYSTEM_PROMPT
                    },
                    {
                        role: "user",
                        content: prompt
                    }
                ],
                temperature: 0.3,
                max_tokens: 500
            });
            
            return response.choices?.[0]?.message?.content || 'Unable to generate explanation';
        } catch (error) {
            console.error('Azure OpenAI API error:', error);
            throw new Error(`Failed to explain violation: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    
    async suggestBestPractices(codeContext: string): Promise<string[]> {
        if (!this.apiKey || !this.endpoint) {
            throw new Error('Azure OpenAI API key or endpoint not configured');
        }
        
        const prompt = `Analyze this PowerShell code and suggest security best practices:

\`\`\`powershell
${codeContext}
\`\`\`

Provide 3-5 specific, actionable security best practices that would improve this code.
Format as a JSON array of strings.`;
        
        try {
            const response = await this.callAPI({
                messages: [
                    {
                        role: "system",
                        content: POWERSHELL_SECURITY_SYSTEM_PROMPT
                    },
                    {
                        role: "user",
                        content: prompt
                    }
                ],
                temperature: 0.3,
                max_tokens: 300
            });
            
            const content = response.choices?.[0]?.message?.content || '[]';
            
            // Try to extract JSON array
            const jsonMatch = content.match(/\[[\s\S]*\]/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
            
            // Fallback: split by lines
            return content.split('\n').filter((line: string) => line.trim().length > 0).slice(0, 5);
        } catch (error) {
            console.error('Azure OpenAI API error:', error);
            return [];
        }
    }
    
    /**
     * Call Azure OpenAI API
     */
    private async callAPI(request: any): Promise<any> {
        const url = `${this.endpoint}/openai/deployments/${this.deploymentName}/chat/completions?api-version=${this.apiVersion}`;
        
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'api-key': this.apiKey!
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
