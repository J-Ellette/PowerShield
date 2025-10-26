/**
 * PowerShield Settings Panel
 * Interactive webview for configuration management
 */

import * as vscode from 'vscode';

interface ExtensionSettings {
    realTimeAnalysis: {
        enabled: boolean;
        debounceMs: number;
        backgroundAnalysis: boolean;
    };
    aiIntegration: {
        primaryProvider: string;
        fallbackProviders: string[];
        confidenceThreshold: number;
        maxTokens: number;
    };
    userInterface: {
        showInlineDecorations: boolean;
        showHoverExplanations: boolean;
        showCodeLens: boolean;
        themeIntegration: boolean;
    };
    performance: {
        enableCaching: boolean;
        maxCacheSize: string;
        enableIncrementalAnalysis: boolean;
    };
    security: {
        enabledRules: string[];
        disabledRules: string[];
        customRulesPath: string;
        suppressionComments: boolean;
    };
}

export class SettingsPanel {
    private panel: vscode.WebviewPanel | undefined;
    private context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    /**
     * Show the settings panel
     */
    async show(): Promise<void> {
        if (this.panel) {
            this.panel.reveal(vscode.ViewColumn.One);
            return;
        }

        this.panel = vscode.window.createWebviewPanel(
            'powershield-settings',
            'PowerShield Settings',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        this.panel.webview.html = this.getSettingsHTML();

        this.panel.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.type) {
                    case 'saveSettings':
                        await this.saveSettings(message.settings);
                        break;
                    case 'testAIProvider':
                        await this.testAIProvider(message.provider);
                        break;
                    case 'resetToDefaults':
                        await this.resetToDefaults();
                        break;
                    case 'openConfigFile':
                        await this.openConfigFile();
                        break;
                }
            },
            undefined,
            []
        );

        this.panel.onDidDispose(() => {
            this.panel = undefined;
        });

        // Load current settings
        const currentSettings = this.getCurrentSettings();
        this.panel.webview.postMessage({
            type: 'loadSettings',
            settings: currentSettings
        });
    }

    /**
     * Get current extension settings
     */
    private getCurrentSettings(): ExtensionSettings {
        const config = vscode.workspace.getConfiguration('powershield');

        return {
            realTimeAnalysis: {
                enabled: config.get('realTimeAnalysis.enabled', true),
                debounceMs: config.get('realTimeAnalysis.debounceMs', 1000),
                backgroundAnalysis: config.get('realTimeAnalysis.backgroundAnalysis', true)
            },
            aiIntegration: {
                primaryProvider: config.get('aiProvider.primary', 'github-models'),
                fallbackProviders: config.get('aiProvider.fallback', ['template-based']),
                confidenceThreshold: config.get('aiProvider.confidenceThreshold', 0.8),
                maxTokens: config.get('aiProvider.maxTokens', 1000)
            },
            userInterface: {
                showInlineDecorations: config.get('ui.showInlineDecorations', true),
                showHoverExplanations: config.get('ui.showHoverExplanations', true),
                showCodeLens: config.get('ui.showCodeLens', true),
                themeIntegration: config.get('ui.themeIntegration', true)
            },
            performance: {
                enableCaching: config.get('performance.enableCaching', true),
                maxCacheSize: config.get('performance.maxCacheSize', '100MB'),
                enableIncrementalAnalysis: config.get('performance.enableIncrementalAnalysis', true)
            },
            security: {
                enabledRules: config.get('rules.enabled', []),
                disabledRules: config.get('rules.disabled', []),
                customRulesPath: config.get('rules.customPath', ''),
                suppressionComments: config.get('suppressions.enabled', true)
            }
        };
    }

    /**
     * Save settings to workspace configuration
     */
    private async saveSettings(settings: ExtensionSettings): Promise<void> {
        try {
            const config = vscode.workspace.getConfiguration('powershield');

            // Real-time analysis settings
            await config.update('realTimeAnalysis.enabled', settings.realTimeAnalysis.enabled, true);
            await config.update('realTimeAnalysis.debounceMs', settings.realTimeAnalysis.debounceMs, true);
            await config.update('realTimeAnalysis.backgroundAnalysis', settings.realTimeAnalysis.backgroundAnalysis, true);

            // AI integration settings
            await config.update('aiProvider.primary', settings.aiIntegration.primaryProvider, true);
            await config.update('aiProvider.fallback', settings.aiIntegration.fallbackProviders, true);
            await config.update('aiProvider.confidenceThreshold', settings.aiIntegration.confidenceThreshold, true);
            await config.update('aiProvider.maxTokens', settings.aiIntegration.maxTokens, true);

            // UI settings
            await config.update('ui.showInlineDecorations', settings.userInterface.showInlineDecorations, true);
            await config.update('ui.showHoverExplanations', settings.userInterface.showHoverExplanations, true);
            await config.update('ui.showCodeLens', settings.userInterface.showCodeLens, true);
            await config.update('ui.themeIntegration', settings.userInterface.themeIntegration, true);

            // Performance settings
            await config.update('performance.enableCaching', settings.performance.enableCaching, true);
            await config.update('performance.maxCacheSize', settings.performance.maxCacheSize, true);
            await config.update('performance.enableIncrementalAnalysis', settings.performance.enableIncrementalAnalysis, true);

            // Security settings
            await config.update('rules.enabled', settings.security.enabledRules, true);
            await config.update('rules.disabled', settings.security.disabledRules, true);
            await config.update('rules.customPath', settings.security.customRulesPath, true);
            await config.update('suppressions.enabled', settings.security.suppressionComments, true);

            vscode.window.showInformationMessage('PowerShield settings saved successfully');
            
            if (this.panel) {
                this.panel.webview.postMessage({ type: 'saveSuccess' });
            }
        } catch (error) {
            console.error('Failed to save settings:', error);
            vscode.window.showErrorMessage('Failed to save settings');
            
            if (this.panel) {
                this.panel.webview.postMessage({ type: 'saveError', error: String(error) });
            }
        }
    }

    /**
     * Test AI provider connection
     */
    private async testAIProvider(provider: string): Promise<void> {
        try {
            if (this.panel) {
                this.panel.webview.postMessage({ 
                    type: 'testingProvider',
                    provider 
                });
            }

            // Simulate testing - in real implementation, this would call the AI provider
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            // Check if provider is configured
            const config = vscode.workspace.getConfiguration('powershield');
            const hasApiKey = this.checkProviderConfiguration(provider, config);

            if (this.panel) {
                this.panel.webview.postMessage({
                    type: 'testResult',
                    provider,
                    success: hasApiKey,
                    message: hasApiKey 
                        ? `${provider} is configured and ready` 
                        : `${provider} requires API key configuration`
                });
            }
        } catch (error) {
            console.error('Failed to test AI provider:', error);
            
            if (this.panel) {
                this.panel.webview.postMessage({
                    type: 'testResult',
                    provider,
                    success: false,
                    message: String(error)
                });
            }
        }
    }

    /**
     * Check if provider is properly configured
     */
    private checkProviderConfiguration(provider: string, config: vscode.WorkspaceConfiguration): boolean {
        switch (provider) {
            case 'github-models':
                return !!process.env.GITHUB_TOKEN;
            case 'openai':
                return !!process.env.OPENAI_API_KEY;
            case 'anthropic':
                return !!process.env.ANTHROPIC_API_KEY;
            case 'azure-openai':
                return !!process.env.AZURE_OPENAI_API_KEY && !!process.env.AZURE_OPENAI_ENDPOINT;
            case 'template-based':
                return true; // Always available
            default:
                return false;
        }
    }

    /**
     * Reset all settings to defaults
     */
    private async resetToDefaults(): Promise<void> {
        const confirm = await vscode.window.showWarningMessage(
            'Are you sure you want to reset all PowerShield settings to defaults?',
            { modal: true },
            'Reset'
        );

        if (confirm !== 'Reset') {
            return;
        }

        try {
            const config = vscode.workspace.getConfiguration('powershield');
            const keys = [
                'realTimeAnalysis.enabled',
                'realTimeAnalysis.debounceMs',
                'realTimeAnalysis.backgroundAnalysis',
                'aiProvider.primary',
                'aiProvider.fallback',
                'aiProvider.confidenceThreshold',
                'aiProvider.maxTokens',
                'ui.showInlineDecorations',
                'ui.showHoverExplanations',
                'ui.showCodeLens',
                'ui.themeIntegration',
                'performance.enableCaching',
                'performance.maxCacheSize',
                'performance.enableIncrementalAnalysis',
                'rules.enabled',
                'rules.disabled',
                'rules.customPath',
                'suppressions.enabled'
            ];

            for (const key of keys) {
                await config.update(key, undefined, true);
            }

            vscode.window.showInformationMessage('Settings reset to defaults');

            // Reload current settings
            const currentSettings = this.getCurrentSettings();
            if (this.panel) {
                this.panel.webview.postMessage({
                    type: 'loadSettings',
                    settings: currentSettings
                });
            }
        } catch (error) {
            console.error('Failed to reset settings:', error);
            vscode.window.showErrorMessage('Failed to reset settings');
        }
    }

    /**
     * Open PowerShield configuration file
     */
    private async openConfigFile(): Promise<void> {
        try {
            if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
                vscode.window.showWarningMessage('No workspace folder open');
                return;
            }

            const workspaceRoot = vscode.workspace.workspaceFolders[0].uri;
            const configPath = vscode.Uri.joinPath(workspaceRoot, '.powershield.yml');

            try {
                await vscode.workspace.fs.stat(configPath);
                const document = await vscode.workspace.openTextDocument(configPath);
                await vscode.window.showTextDocument(document);
            } catch {
                // File doesn't exist, offer to create it
                const create = await vscode.window.showInformationMessage(
                    'Configuration file .powershield.yml does not exist. Create it?',
                    'Create'
                );

                if (create === 'Create') {
                    const template = this.getConfigTemplate();
                    await vscode.workspace.fs.writeFile(configPath, Buffer.from(template, 'utf8'));
                    const document = await vscode.workspace.openTextDocument(configPath);
                    await vscode.window.showTextDocument(document);
                }
            }
        } catch (error) {
            console.error('Failed to open config file:', error);
            vscode.window.showErrorMessage('Failed to open configuration file');
        }
    }

    /**
     * Get configuration file template
     */
    private getConfigTemplate(): string {
        return `# PowerShield Configuration
version: "1.0"

# Security rules configuration
rules:
  enabled: []  # Leave empty to enable all rules
  disabled: []  # Specify rules to disable

# Suppression settings
suppressions:
  enabled: true
  inline: true

# Performance settings
performance:
  caching: true
  incrementalAnalysis: true
  maxCacheSize: "100MB"
`;
    }

    /**
     * Get settings HTML content
     */
    private getSettingsHTML(): string {
        const nonce = this.getNonce();

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
    <title>PowerShield Settings</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            padding: 20px;
            max-width: 800px;
            margin: 0 auto;
        }
        h1 {
            margin-top: 0;
            border-bottom: 1px solid var(--vscode-panel-border);
            padding-bottom: 10px;
        }
        h2 {
            margin-top: 30px;
            color: var(--vscode-textLink-foreground);
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: var(--vscode-editorWidget-background);
            border-radius: 4px;
        }
        .setting-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"],
        input[type="number"],
        select {
            width: 100%;
            padding: 8px;
            background-color: var(--vscode-input-background);
            color: var(--vscode-input-foreground);
            border: 1px solid var(--vscode-input-border);
            border-radius: 4px;
            box-sizing: border-box;
        }
        input[type="checkbox"] {
            margin-right: 8px;
        }
        .checkbox-label {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
            font-weight: normal;
        }
        button {
            padding: 8px 16px;
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
        }
        button:hover {
            background-color: var(--vscode-button-hoverBackground);
        }
        button.secondary {
            background-color: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }
        button.secondary:hover {
            background-color: var(--vscode-button-secondaryHoverBackground);
        }
        .description {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
            margin-top: 5px;
        }
        .actions {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid var(--vscode-panel-border);
        }
        .status-message {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .status-message.success {
            background-color: rgba(40, 167, 69, 0.2);
            border: 1px solid #28a745;
        }
        .status-message.error {
            background-color: rgba(220, 53, 69, 0.2);
            border: 1px solid #dc3545;
        }
        .test-result {
            padding: 10px;
            margin-top: 10px;
            border-radius: 4px;
            display: none;
        }
    </style>
</head>
<body>
    <h1>⚙️ PowerShield Settings</h1>
    
    <div id="status-container"></div>
    
    <div class="section">
        <h2>Real-Time Analysis</h2>
        
        <div class="setting-group">
            <label class="checkbox-label">
                <input type="checkbox" id="realtime-enabled" />
                Enable real-time security analysis
            </label>
            <div class="description">Analyze files as you type</div>
        </div>
        
        <div class="setting-group">
            <label for="debounce-ms">Analysis Delay (ms)</label>
            <input type="number" id="debounce-ms" min="100" max="5000" step="100" />
            <div class="description">Time to wait after typing stops before analysis runs</div>
        </div>
        
        <div class="setting-group">
            <label class="checkbox-label">
                <input type="checkbox" id="background-analysis" />
                Background analysis
            </label>
            <div class="description">Run analysis in background worker threads</div>
        </div>
    </div>
    
    <div class="section">
        <h2>AI Integration</h2>
        
        <div class="setting-group">
            <label for="primary-provider">Primary AI Provider</label>
            <select id="primary-provider">
                <option value="github-models">GitHub Models</option>
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic (Claude)</option>
                <option value="azure-openai">Azure OpenAI</option>
                <option value="template-based">Template-Based (No AI)</option>
            </select>
            <button class="secondary" id="test-provider-btn" style="margin-top: 10px;">Test Connection</button>
            <div id="test-result" class="test-result"></div>
        </div>
        
        <div class="setting-group">
            <label for="confidence-threshold">Confidence Threshold</label>
            <input type="number" id="confidence-threshold" min="0" max="1" step="0.1" />
            <div class="description">Minimum confidence (0-1) for applying AI fixes</div>
        </div>
        
        <div class="setting-group">
            <label for="max-tokens">Max Tokens</label>
            <input type="number" id="max-tokens" min="100" max="4000" step="100" />
            <div class="description">Maximum tokens for AI responses</div>
        </div>
    </div>
    
    <div class="section">
        <h2>User Interface</h2>
        
        <div class="setting-group">
            <label class="checkbox-label">
                <input type="checkbox" id="show-decorations" />
                Show inline decorations
            </label>
        </div>
        
        <div class="setting-group">
            <label class="checkbox-label">
                <input type="checkbox" id="show-hover" />
                Show hover explanations
            </label>
        </div>
        
        <div class="setting-group">
            <label class="checkbox-label">
                <input type="checkbox" id="show-codelens" />
                Show CodeLens
            </label>
        </div>
        
        <div class="setting-group">
            <label class="checkbox-label">
                <input type="checkbox" id="theme-integration" />
                Theme integration
            </label>
        </div>
    </div>
    
    <div class="section">
        <h2>Performance</h2>
        
        <div class="setting-group">
            <label class="checkbox-label">
                <input type="checkbox" id="enable-caching" />
                Enable caching
            </label>
        </div>
        
        <div class="setting-group">
            <label for="max-cache-size">Max Cache Size</label>
            <input type="text" id="max-cache-size" placeholder="100MB" />
            <div class="description">Maximum memory for caching analysis results</div>
        </div>
        
        <div class="setting-group">
            <label class="checkbox-label">
                <input type="checkbox" id="incremental-analysis" />
                Enable incremental analysis
            </label>
        </div>
    </div>
    
    <div class="section">
        <h2>Security Rules</h2>
        
        <div class="setting-group">
            <label for="custom-rules-path">Custom Rules Path</label>
            <input type="text" id="custom-rules-path" placeholder="path/to/custom/rules" />
            <div class="description">Path to custom security rules</div>
        </div>
        
        <div class="setting-group">
            <label class="checkbox-label">
                <input type="checkbox" id="suppression-comments" />
                Enable suppression comments
            </label>
            <div class="description">Allow inline comments to suppress violations</div>
        </div>
        
        <button class="secondary" id="open-config-btn">Open .powershield.yml</button>
    </div>
    
    <div class="actions">
        <button id="save-btn">💾 Save Settings</button>
        <button class="secondary" id="reset-btn">🔄 Reset to Defaults</button>
    </div>
    
    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();
        let currentSettings = null;
        
        // Event listeners
        document.getElementById('save-btn').addEventListener('click', saveSettings);
        document.getElementById('reset-btn').addEventListener('click', resetToDefaults);
        document.getElementById('test-provider-btn').addEventListener('click', testProvider);
        document.getElementById('open-config-btn').addEventListener('click', openConfigFile);
        
        // Handle messages from extension
        window.addEventListener('message', event => {
            const message = event.data;
            
            switch (message.type) {
                case 'loadSettings':
                    currentSettings = message.settings;
                    loadSettings(message.settings);
                    break;
                case 'saveSuccess':
                    showStatus('Settings saved successfully', 'success');
                    break;
                case 'saveError':
                    showStatus('Failed to save settings: ' + message.error, 'error');
                    break;
                case 'testingProvider':
                    showTestResult('Testing ' + message.provider + '...', 'info');
                    break;
                case 'testResult':
                    showTestResult(
                        message.message,
                        message.success ? 'success' : 'error'
                    );
                    break;
            }
        });
        
        function loadSettings(settings) {
            // Real-time analysis
            document.getElementById('realtime-enabled').checked = settings.realTimeAnalysis.enabled;
            document.getElementById('debounce-ms').value = settings.realTimeAnalysis.debounceMs;
            document.getElementById('background-analysis').checked = settings.realTimeAnalysis.backgroundAnalysis;
            
            // AI integration
            document.getElementById('primary-provider').value = settings.aiIntegration.primaryProvider;
            document.getElementById('confidence-threshold').value = settings.aiIntegration.confidenceThreshold;
            document.getElementById('max-tokens').value = settings.aiIntegration.maxTokens;
            
            // UI
            document.getElementById('show-decorations').checked = settings.userInterface.showInlineDecorations;
            document.getElementById('show-hover').checked = settings.userInterface.showHoverExplanations;
            document.getElementById('show-codelens').checked = settings.userInterface.showCodeLens;
            document.getElementById('theme-integration').checked = settings.userInterface.themeIntegration;
            
            // Performance
            document.getElementById('enable-caching').checked = settings.performance.enableCaching;
            document.getElementById('max-cache-size').value = settings.performance.maxCacheSize;
            document.getElementById('incremental-analysis').checked = settings.performance.enableIncrementalAnalysis;
            
            // Security
            document.getElementById('custom-rules-path').value = settings.security.customRulesPath;
            document.getElementById('suppression-comments').checked = settings.security.suppressionComments;
        }
        
        function saveSettings() {
            const settings = {
                realTimeAnalysis: {
                    enabled: document.getElementById('realtime-enabled').checked,
                    debounceMs: parseInt(document.getElementById('debounce-ms').value),
                    backgroundAnalysis: document.getElementById('background-analysis').checked
                },
                aiIntegration: {
                    primaryProvider: document.getElementById('primary-provider').value,
                    fallbackProviders: ['template-based'],
                    confidenceThreshold: parseFloat(document.getElementById('confidence-threshold').value),
                    maxTokens: parseInt(document.getElementById('max-tokens').value)
                },
                userInterface: {
                    showInlineDecorations: document.getElementById('show-decorations').checked,
                    showHoverExplanations: document.getElementById('show-hover').checked,
                    showCodeLens: document.getElementById('show-codelens').checked,
                    themeIntegration: document.getElementById('theme-integration').checked
                },
                performance: {
                    enableCaching: document.getElementById('enable-caching').checked,
                    maxCacheSize: document.getElementById('max-cache-size').value,
                    enableIncrementalAnalysis: document.getElementById('incremental-analysis').checked
                },
                security: {
                    enabledRules: [],
                    disabledRules: [],
                    customRulesPath: document.getElementById('custom-rules-path').value,
                    suppressionComments: document.getElementById('suppression-comments').checked
                }
            };
            
            vscode.postMessage({
                type: 'saveSettings',
                settings: settings
            });
        }
        
        function resetToDefaults() {
            vscode.postMessage({ type: 'resetToDefaults' });
        }
        
        function testProvider() {
            const provider = document.getElementById('primary-provider').value;
            vscode.postMessage({
                type: 'testAIProvider',
                provider: provider
            });
        }
        
        function openConfigFile() {
            vscode.postMessage({ type: 'openConfigFile' });
        }
        
        function showStatus(message, type) {
            const container = document.getElementById('status-container');
            container.innerHTML = '<div class="status-message ' + type + '">' + message + '</div>';
            setTimeout(() => {
                container.innerHTML = '';
            }, 5000);
        }
        
        function showTestResult(message, type) {
            const result = document.getElementById('test-result');
            result.className = 'test-result status-message ' + type;
            result.textContent = message;
            result.style.display = 'block';
            
            if (type !== 'info') {
                setTimeout(() => {
                    result.style.display = 'none';
                }, 5000);
            }
        }
    </script>
</body>
</html>`;
    }

    /**
     * Generate a nonce for CSP
     */
    private getNonce(): string {
        let text = '';
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        for (let i = 0; i < 32; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }

    /**
     * Dispose of resources
     */
    public dispose(): void {
        if (this.panel) {
            this.panel.dispose();
        }
    }
}
