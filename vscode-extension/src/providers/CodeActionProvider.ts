/**
 * AI Code Action Provider
 * Provides intelligent code actions for security violations
 */

import * as vscode from 'vscode';
import { SecurityViolation, AIFixResult } from '../types';
import { AIProvider } from '../ai/AIProvider';
import { AIProviderFactory } from '../ai/AIProviderFactory';
import { FixContextBuilder } from '../ai/FixContextBuilder';
import { TemplateBasedProvider } from '../ai/TemplateBasedProvider';

/**
 * Provides code actions for PowerShield security diagnostics
 */
export class AICodeActionProvider implements vscode.CodeActionProvider {
    private aiProviders: AIProvider[] = [];
    private fixContextBuilder: FixContextBuilder;
    private diagnosticMap: Map<string, SecurityViolation> = new Map();
    private templateProvider: TemplateBasedProvider;
    
    constructor() {
        this.fixContextBuilder = new FixContextBuilder();
        this.templateProvider = new TemplateBasedProvider();
        this.templateProvider.initialize({ name: 'template-based', type: 'template-based' });
        
        this.initializeProviders();
    }
    
    /**
     * Initialize AI providers based on configuration
     */
    private async initializeProviders(): Promise<void> {
        const config = vscode.workspace.getConfiguration('powershield');
        const primaryProvider = config.get<string>('aiProvider.primary', 'github-models');
        const fallbackProviders = config.get<string[]>('aiProvider.fallback', ['template-based']);
        
        // Build provider chain: primary -> fallbacks
        const providerTypes = [primaryProvider, ...fallbackProviders];
        
        // Get provider configs
        const providerConfigs = new Map<string, any>();
        for (const type of providerTypes) {
            providerConfigs.set(type, {
                name: type,
                type: type as any,
                apiKey: this.getAPIKey(type),
                endpoint: this.getEndpoint(type),
                model: this.getModel(type)
            });
        }
        
        this.aiProviders = await AIProviderFactory.getAvailableProviders(
            providerTypes,
            providerConfigs
        );
    }
    
    /**
     * Get API key for provider from environment or config
     */
    private getAPIKey(providerType: string): string | undefined {
        switch (providerType) {
            case 'github-models':
                return process.env.GITHUB_TOKEN;
            case 'openai':
                return process.env.OPENAI_API_KEY;
            case 'anthropic':
                return process.env.ANTHROPIC_API_KEY;
            case 'azure-openai':
                return process.env.AZURE_OPENAI_API_KEY;
            default:
                return undefined;
        }
    }
    
    /**
     * Get endpoint for provider
     */
    private getEndpoint(providerType: string): string | undefined {
        if (providerType === 'azure-openai') {
            return process.env.AZURE_OPENAI_ENDPOINT;
        }
        return undefined;
    }
    
    /**
     * Get model name for provider
     */
    private getModel(providerType: string): string | undefined {
        const config = vscode.workspace.getConfiguration('powershield');
        return config.get<string>(`aiProvider.${providerType}.model`);
    }
    
    /**
     * Provide code actions for diagnostics
     */
    async provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): Promise<vscode.CodeAction[]> {
        const actions: vscode.CodeAction[] = [];
        
        // Get PowerShield diagnostics in range
        const securityDiagnostics = context.diagnostics.filter(
            d => d.source === 'PowerShield' && d.range.intersection(range)
        );
        
        for (const diagnostic of securityDiagnostics) {
            const violation = this.getViolationFromDiagnostic(diagnostic);
            if (!violation) continue;
            
            // Store violation for later use
            const diagnosticKey = this.getDiagnosticKey(diagnostic);
            this.diagnosticMap.set(diagnosticKey, violation);
            
            // AI-powered fix action
            const aiFixAction = new vscode.CodeAction(
                `🤖 AI Fix: ${violation.ruleId}`,
                vscode.CodeActionKind.QuickFix
            );
            aiFixAction.command = {
                title: 'Generate AI Fix',
                command: 'powershield.generateAIFix',
                arguments: [document, violation, diagnostic.range]
            };
            aiFixAction.isPreferred = true;
            actions.push(aiFixAction);
            
            // Template-based fix (always available as fallback)
            if (this.hasTemplateFix(violation)) {
                const templateAction = new vscode.CodeAction(
                    `🔧 Quick Fix: ${violation.ruleId}`,
                    vscode.CodeActionKind.QuickFix
                );
                templateAction.command = {
                    title: 'Apply Template Fix',
                    command: 'powershield.applyTemplateFix',
                    arguments: [document, violation, diagnostic.range]
                };
                actions.push(templateAction);
            }
            
            // Explain violation action
            const explainAction = new vscode.CodeAction(
                `📖 Explain: ${violation.ruleId}`,
                vscode.CodeActionKind.Empty
            );
            explainAction.command = {
                title: 'Explain Security Issue',
                command: 'powershield.explainViolation',
                arguments: [violation]
            };
            actions.push(explainAction);
            
            // Suppress violation action (for false positives)
            const suppressAction = new vscode.CodeAction(
                `🙈 Suppress: ${violation.ruleId}`,
                vscode.CodeActionKind.QuickFix
            );
            suppressAction.command = {
                title: 'Suppress Violation',
                command: 'powershield.suppressViolation',
                arguments: [document, violation, diagnostic.range]
            };
            actions.push(suppressAction);
        }
        
        return actions;
    }
    
    /**
     * Get violation from diagnostic
     */
    private getViolationFromDiagnostic(diagnostic: vscode.Diagnostic): SecurityViolation | undefined {
        // Try to extract from diagnostic code
        const ruleId = typeof diagnostic.code === 'object' ? diagnostic.code.value.toString() : diagnostic.code?.toString() || '';
        
        // Create a basic violation object from diagnostic
        // In a real implementation, this would be stored during analysis
        return {
            name: ruleId,
            message: diagnostic.message,
            description: diagnostic.message,
            severity: this.mapDiagnosticSeverity(diagnostic.severity),
            lineNumber: diagnostic.range.start.line + 1,
            columnNumber: diagnostic.range.start.character,
            endColumn: diagnostic.range.end.character,
            code: '',
            filePath: '',
            ruleId: ruleId
        };
    }
    
    /**
     * Map VS Code diagnostic severity to PowerShield severity
     */
    private mapDiagnosticSeverity(severity: vscode.DiagnosticSeverity): any {
        switch (severity) {
            case vscode.DiagnosticSeverity.Error:
                return 4; // Critical
            case vscode.DiagnosticSeverity.Warning:
                return 3; // High
            case vscode.DiagnosticSeverity.Information:
                return 2; // Medium
            case vscode.DiagnosticSeverity.Hint:
                return 1; // Low
            default:
                return 2;
        }
    }
    
    /**
     * Get unique key for diagnostic
     */
    private getDiagnosticKey(diagnostic: vscode.Diagnostic): string {
        return `${diagnostic.range.start.line}-${diagnostic.range.start.character}-${diagnostic.code}`;
    }
    
    /**
     * Check if template fix is available for violation
     */
    private hasTemplateFix(violation: SecurityViolation): boolean {
        // Template provider has fixes for common patterns
        const commonPatterns = [
            /InsecureHash|MD5|SHA1/i,
            /Credential|Password/i,
            /CommandInjection|Invoke-Expression/i,
            /Certificate|SSL|TLS/i
        ];
        
        return commonPatterns.some(pattern => pattern.test(violation.ruleId));
    }
    
    /**
     * Generate AI fix for violation
     */
    async generateAIFix(
        document: vscode.TextDocument,
        violation: SecurityViolation,
        range: vscode.Range
    ): Promise<void> {
        const config = vscode.workspace.getConfiguration('powershield');
        const confidenceThreshold = config.get<number>('aiProvider.confidenceThreshold', 0.8);
        
        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: `PowerShield: Generating AI fix for ${violation.ruleId}...`,
                cancellable: false
            },
            async () => {
                // Build fix context
                const context = this.fixContextBuilder.buildFixContext(document, violation, range);
                
                // Try each provider in fallback chain
                let fixResult: AIFixResult | null = null;
                let usedProvider: AIProvider | null = null;
                
                for (const provider of this.aiProviders) {
                    try {
                        fixResult = await provider.generateFix(violation, context);
                        
                        // Check confidence threshold
                        if (fixResult.confidence >= confidenceThreshold) {
                            usedProvider = provider;
                            break;
                        }
                    } catch (error) {
                        console.warn(`Provider ${provider.name} failed:`, error);
                        continue;
                    }
                }
                
                if (!fixResult || !usedProvider) {
                    vscode.window.showErrorMessage('Failed to generate fix with all available providers');
                    return;
                }
                
                // Show fix preview and apply
                await this.showFixPreview(document, range, fixResult, usedProvider);
            }
        );
    }
    
    /**
     * Show fix preview and apply if accepted
     */
    private async showFixPreview(
        document: vscode.TextDocument,
        range: vscode.Range,
        fixResult: AIFixResult,
        provider: AIProvider
    ): Promise<void> {
        const panel = vscode.window.createWebviewPanel(
            'powershield-fix-preview',
            'PowerShield Fix Preview',
            vscode.ViewColumn.Beside,
            { enableScripts: true }
        );
        
        panel.webview.html = this.getFixPreviewHTML(fixResult, provider);
        
        // Handle accept/reject actions
        panel.webview.onDidReceiveMessage(async (message) => {
            switch (message.command) {
                case 'accept':
                    await this.applyFix(document, range, fixResult.fixedCode);
                    panel.dispose();
                    vscode.window.showInformationMessage('Fix applied successfully');
                    break;
                case 'reject':
                    panel.dispose();
                    break;
            }
        });
    }
    
    /**
     * Get HTML for fix preview
     */
    private getFixPreviewHTML(fixResult: AIFixResult, provider: AIProvider): string {
        return `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: var(--vscode-font-family); padding: 20px; }
        .header { margin-bottom: 20px; }
        .provider { color: var(--vscode-descriptionForeground); font-size: 0.9em; }
        .confidence { 
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            background: ${fixResult.confidence >= 0.8 ? 'var(--vscode-testing-iconPassed)' : 'var(--vscode-testing-iconQueued)'};
            color: white;
            font-weight: bold;
        }
        .code-block { 
            background: var(--vscode-textCodeBlock-background);
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            overflow-x: auto;
        }
        .explanation { 
            margin: 15px 0;
            line-height: 1.6;
        }
        .actions {
            margin-top: 20px;
            display: flex;
            gap: 10px;
        }
        button {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .accept { 
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
        }
        .reject {
            background: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }
    </style>
</head>
<body>
    <div class="header">
        <h2>🤖 AI-Generated Security Fix</h2>
        <div class="provider">Provider: ${provider.name}</div>
        <div><span class="confidence">Confidence: ${(fixResult.confidence * 100).toFixed(0)}%</span></div>
    </div>
    
    <div class="explanation">
        <h3>Explanation:</h3>
        <p>${fixResult.explanation}</p>
    </div>
    
    <div class="code-block">
        <h3>Fixed Code:</h3>
        <pre><code>${this.escapeHtml(fixResult.fixedCode)}</code></pre>
    </div>
    
    ${fixResult.alternative ? `
    <div class="explanation">
        <h3>Alternative Approach:</h3>
        <p>${fixResult.alternative}</p>
    </div>
    ` : ''}
    
    <div class="actions">
        <button class="accept" onclick="acceptFix()">✓ Accept Fix</button>
        <button class="reject" onclick="rejectFix()">✗ Reject</button>
    </div>
    
    <script>
        const vscode = acquireVsCodeApi();
        
        function acceptFix() {
            vscode.postMessage({ command: 'accept' });
        }
        
        function rejectFix() {
            vscode.postMessage({ command: 'reject' });
        }
    </script>
</body>
</html>`;
    }
    
    /**
     * Escape HTML
     */
    private escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
    
    /**
     * Apply fix to document
     */
    private async applyFix(
        document: vscode.TextDocument,
        range: vscode.Range,
        fixedCode: string
    ): Promise<void> {
        const edit = new vscode.WorkspaceEdit();
        edit.replace(document.uri, range, fixedCode);
        await vscode.workspace.applyEdit(edit);
    }
    
    /**
     * Apply template-based fix
     */
    async applyTemplateFix(
        document: vscode.TextDocument,
        violation: SecurityViolation,
        range: vscode.Range
    ): Promise<void> {
        const context = this.fixContextBuilder.buildFixContext(document, violation, range);
        const fixResult = await this.templateProvider.generateFix(violation, context);
        
        await this.applyFix(document, range, fixResult.fixedCode);
        vscode.window.showInformationMessage(`Template fix applied: ${fixResult.explanation}`);
    }
    
    /**
     * Explain violation
     */
    async explainViolation(violation: SecurityViolation): Promise<void> {
        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: `PowerShield: Explaining ${violation.ruleId}...`,
                cancellable: false
            },
            async () => {
                // Try AI providers first, fall back to template
                let explanation: string = '';
                
                for (const provider of this.aiProviders) {
                    try {
                        explanation = await provider.explainViolation(violation);
                        if (explanation) break;
                    } catch (error) {
                        continue;
                    }
                }
                
                if (!explanation) {
                    explanation = await this.templateProvider.explainViolation(violation);
                }
                
                // Show explanation in output or webview
                const panel = vscode.window.createWebviewPanel(
                    'powershield-explanation',
                    `Explain: ${violation.ruleId}`,
                    vscode.ViewColumn.Beside,
                    {}
                );
                
                panel.webview.html = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { 
            font-family: var(--vscode-font-family); 
            padding: 20px;
            line-height: 1.6;
        }
        h2 { color: var(--vscode-foreground); }
        .content { white-space: pre-wrap; }
    </style>
</head>
<body>
    <h2>📖 ${violation.ruleId}</h2>
    <div class="content">${this.escapeHtml(explanation)}</div>
</body>
</html>`;
            }
        );
    }
    
    /**
     * Suppress violation
     */
    async suppressViolation(
        document: vscode.TextDocument,
        violation: SecurityViolation,
        range: vscode.Range
    ): Promise<void> {
        const line = document.lineAt(range.start.line);
        const suppressComment = `# powershield-disable-line ${violation.ruleId}`;
        
        const edit = new vscode.WorkspaceEdit();
        const insertPosition = new vscode.Position(range.start.line, line.firstNonWhitespaceCharacterIndex);
        edit.insert(document.uri, insertPosition, `${suppressComment}\n${' '.repeat(line.firstNonWhitespaceCharacterIndex)}`);
        
        await vscode.workspace.applyEdit(edit);
        vscode.window.showInformationMessage(`Suppressed ${violation.ruleId} on line ${violation.lineNumber}`);
    }
}
