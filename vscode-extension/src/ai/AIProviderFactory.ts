/**
 * AI Provider Factory
 * Creates and manages AI provider instances
 */

import { AIProvider } from './AIProvider';
import { GitHubModelsProvider } from './GitHubModelsProvider';
import { OpenAIProvider } from './OpenAIProvider';
import { AnthropicProvider } from './AnthropicProvider';
import { AzureOpenAIProvider } from './AzureOpenAIProvider';
import { TemplateBasedProvider } from './TemplateBasedProvider';
import { AIProviderConfig } from '../types';

/**
 * Factory for creating AI provider instances
 */
export class AIProviderFactory {
    private static providers: Map<string, AIProvider> = new Map();
    
    /**
     * Create or get an AI provider instance
     */
    static async createProvider(
        type: 'github-models' | 'openai' | 'anthropic' | 'azure-openai' | 'template-based',
        config: AIProviderConfig
    ): Promise<AIProvider> {
        // Check if provider already exists
        const cacheKey = `${type}-${config.apiKey || 'default'}`;
        if (this.providers.has(cacheKey)) {
            return this.providers.get(cacheKey)!;
        }
        
        // Create new provider
        let provider: AIProvider;
        
        switch (type) {
            case 'github-models':
                provider = new GitHubModelsProvider();
                break;
            case 'openai':
                provider = new OpenAIProvider();
                break;
            case 'anthropic':
                provider = new AnthropicProvider();
                break;
            case 'azure-openai':
                provider = new AzureOpenAIProvider();
                break;
            case 'template-based':
                provider = new TemplateBasedProvider();
                break;
            default:
                throw new Error(`Unknown provider type: ${type}`);
        }
        
        // Initialize provider
        await provider.initialize(config);
        
        // Cache provider
        this.providers.set(cacheKey, provider);
        
        return provider;
    }
    
    /**
     * Get available providers based on configuration
     */
    static async getAvailableProviders(
        preferredTypes: string[],
        configs: Map<string, AIProviderConfig>
    ): Promise<AIProvider[]> {
        const providers: AIProvider[] = [];
        
        for (const type of preferredTypes) {
            try {
                const config = configs.get(type) || { 
                    name: type, 
                    type: type as any 
                };
                
                const provider = await this.createProvider(type as any, config);
                
                // Check if provider is available
                if (await provider.isAvailable()) {
                    providers.push(provider);
                }
            } catch (error) {
                console.warn(`Failed to initialize provider ${type}:`, error);
            }
        }
        
        // Always add template-based as final fallback
        const templateConfig: AIProviderConfig = {
            name: 'template-based',
            type: 'template-based'
        };
        const templateProvider = await this.createProvider('template-based', templateConfig);
        if (!providers.some(p => p.type === 'template-based')) {
            providers.push(templateProvider);
        }
        
        return providers;
    }
    
    /**
     * Clear all cached providers
     */
    static clearCache(): void {
        this.providers.clear();
    }
}
