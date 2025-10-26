/**
 * PowerShield VS Code Extension
 * Main entry point for the extension
 */

import * as vscode from 'vscode';
import { PowerShieldEngine } from './core/PowerShieldEngine';
import { PSSecurityProvider } from './providers/SecurityProvider';
import { RealTimeAnalysisProvider } from './providers/RealTimeAnalysisProvider';

let powerShieldEngine: PowerShieldEngine;
let securityProvider: PSSecurityProvider;
let realTimeAnalysisProvider: RealTimeAnalysisProvider;
let diagnosticCollection: vscode.DiagnosticCollection;

/**
 * Activate the extension
 */
export async function activate(context: vscode.ExtensionContext) {
    console.log('PowerShield VS Code Extension activating...');

    try {
        // Initialize PowerShield core engine
        powerShieldEngine = new PowerShieldEngine();
        await powerShieldEngine.initialize(context);

        // Create diagnostic collection
        diagnosticCollection = vscode.languages.createDiagnosticCollection('powershield');
        context.subscriptions.push(diagnosticCollection);

        // Register providers
        registerSecurityProviders(context, powerShieldEngine);
        
        // Setup real-time analysis
        setupRealTimeAnalysis(context, powerShieldEngine);
        
        // Register commands
        registerCommands(context, powerShieldEngine);

        // Show welcome message
        vscode.window.showInformationMessage(
            'PowerShield: Security analysis activated for PowerShell files'
        );

        console.log('PowerShield VS Code Extension activated successfully');
    } catch (error) {
        console.error('Failed to activate PowerShield extension:', error);
        vscode.window.showErrorMessage(
            `PowerShield activation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
    }
}

/**
 * Register security providers
 */
function registerSecurityProviders(
    context: vscode.ExtensionContext,
    engine: PowerShieldEngine
): void {
    // Initialize security provider
    securityProvider = new PSSecurityProvider(engine);
    
    console.log('Security providers registered');
}

/**
 * Setup real-time analysis
 */
function setupRealTimeAnalysis(
    context: vscode.ExtensionContext,
    engine: PowerShieldEngine
): void {
    // Initialize real-time analysis provider
    realTimeAnalysisProvider = new RealTimeAnalysisProvider(
        engine,
        securityProvider,
        diagnosticCollection
    );

    // Setup document watchers
    realTimeAnalysisProvider.setupDocumentWatchers(context);

    // Analyze all currently open PowerShell documents
    realTimeAnalysisProvider.analyzeAllOpenDocuments().catch(err => {
        console.error('Error analyzing open documents:', err);
    });

    console.log('Real-time analysis setup complete');
}

/**
 * Register commands
 */
function registerCommands(
    context: vscode.ExtensionContext,
    engine: PowerShieldEngine
): void {
    // Analyze current file
    const analyzeFileCommand = vscode.commands.registerCommand(
        'powershield.analyzeFile',
        async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('No active editor');
                return;
            }

            if (editor.document.languageId !== 'powershell') {
                vscode.window.showWarningMessage('Current file is not a PowerShell file');
                return;
            }

            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'PowerShield: Analyzing file...',
                    cancellable: false
                },
                async () => {
                    try {
                        const violations = await securityProvider.analyzeDocument(editor.document);
                        
                        vscode.window.showInformationMessage(
                            `PowerShield: Found ${violations.length} security issue(s)`
                        );
                    } catch (error) {
                        vscode.window.showErrorMessage(
                            `Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                        );
                    }
                }
            );
        }
    );

    // Analyze workspace
    const analyzeWorkspaceCommand = vscode.commands.registerCommand(
        'powershield.analyzeWorkspace',
        async () => {
            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'PowerShield: Analyzing workspace...',
                    cancellable: false
                },
                async () => {
                    try {
                        // Find all PowerShell files in workspace
                        const files = await vscode.workspace.findFiles(
                            '**/*.{ps1,psm1,psd1}',
                            '**/node_modules/**'
                        );

                        let totalViolations = 0;
                        for (const fileUri of files) {
                            const document = await vscode.workspace.openTextDocument(fileUri);
                            const violations = await securityProvider.analyzeDocument(document);
                            totalViolations += violations.length;
                        }

                        vscode.window.showInformationMessage(
                            `PowerShield: Analyzed ${files.length} file(s), found ${totalViolations} security issue(s)`
                        );
                    } catch (error) {
                        vscode.window.showErrorMessage(
                            `Workspace analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                        );
                    }
                }
            );
        }
    );

    // Show output
    const showOutputCommand = vscode.commands.registerCommand(
        'powershield.showOutput',
        () => {
            powerShieldEngine.showOutput();
        }
    );

    // Configure settings
    const configureSettingsCommand = vscode.commands.registerCommand(
        'powershield.configureSettings',
        () => {
            vscode.commands.executeCommand(
                'workbench.action.openSettings',
                'powershield'
            );
        }
    );

    // Clear cache
    const clearCacheCommand = vscode.commands.registerCommand(
        'powershield.clearCache',
        () => {
            securityProvider.clearCache();
            vscode.window.showInformationMessage('PowerShield: Cache cleared');
        }
    );

    // Reload configuration
    const reloadConfigCommand = vscode.commands.registerCommand(
        'powershield.reloadConfig',
        () => {
            powerShieldEngine.reloadConfiguration();
            securityProvider.updateCacheSettings();
            realTimeAnalysisProvider.updateSettings();
            vscode.window.showInformationMessage('PowerShield: Configuration reloaded');
        }
    );

    // Placeholder commands for Phase 2.2+
    const generateAIFixCommand = vscode.commands.registerCommand(
        'powershield.generateAIFix',
        () => {
            vscode.window.showInformationMessage(
                'AI Fix generation coming in Phase 2.2'
            );
        }
    );

    const explainViolationCommand = vscode.commands.registerCommand(
        'powershield.explainViolation',
        () => {
            vscode.window.showInformationMessage(
                'Violation explanations coming in Phase 2.3'
            );
        }
    );

    const suppressViolationCommand = vscode.commands.registerCommand(
        'powershield.suppressViolation',
        () => {
            vscode.window.showInformationMessage(
                'Violation suppression coming in Phase 2.3'
            );
        }
    );

    const showDashboardCommand = vscode.commands.registerCommand(
        'powershield.showSecurityDashboard',
        () => {
            vscode.window.showInformationMessage(
                'Security Dashboard coming in Phase 2.5'
            );
        }
    );

    // Register all commands
    context.subscriptions.push(
        analyzeFileCommand,
        analyzeWorkspaceCommand,
        showOutputCommand,
        configureSettingsCommand,
        clearCacheCommand,
        reloadConfigCommand,
        generateAIFixCommand,
        explainViolationCommand,
        suppressViolationCommand,
        showDashboardCommand
    );

    console.log('Commands registered');
}

/**
 * Deactivate the extension
 */
export function deactivate() {
    console.log('PowerShield VS Code Extension deactivating...');
    
    if (realTimeAnalysisProvider) {
        realTimeAnalysisProvider.dispose();
    }
    
    if (powerShieldEngine) {
        powerShieldEngine.dispose();
    }
    
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
    
    console.log('PowerShield VS Code Extension deactivated');
}
