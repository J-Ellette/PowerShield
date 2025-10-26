/**
 * PowerShield VS Code Extension
 * Main entry point for the extension
 */

import * as vscode from 'vscode';
import { PowerShieldEngine } from './core/PowerShieldEngine';
import { PSSecurityProvider } from './providers/SecurityProvider';
import { RealTimeAnalysisProvider } from './providers/RealTimeAnalysisProvider';
import { AICodeActionProvider } from './providers/CodeActionProvider';

let powerShieldEngine: PowerShieldEngine;
let securityProvider: PSSecurityProvider;
let realTimeAnalysisProvider: RealTimeAnalysisProvider;
let codeActionProvider: AICodeActionProvider;
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
        
        // Register AI code actions
        registerCodeActions(context);
        
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
 * Register AI code actions
 */
function registerCodeActions(context: vscode.ExtensionContext): void {
    // Initialize code action provider
    codeActionProvider = new AICodeActionProvider();
    
    // Register for PowerShell files
    const codeActionDisposable = vscode.languages.registerCodeActionsProvider(
        { language: 'powershell', scheme: 'file' },
        codeActionProvider,
        {
            providedCodeActionKinds: [
                vscode.CodeActionKind.QuickFix,
                vscode.CodeActionKind.Empty
            ]
        }
    );
    
    context.subscriptions.push(codeActionDisposable);
    console.log('AI code actions registered');
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
        async (document: vscode.TextDocument, violation: any, range: vscode.Range) => {
            if (codeActionProvider) {
                await codeActionProvider.generateAIFix(document, violation, range);
            } else {
                vscode.window.showWarningMessage('Code action provider not initialized');
            }
        }
    );

    const explainViolationCommand = vscode.commands.registerCommand(
        'powershield.explainViolation',
        async (violation: any) => {
            if (codeActionProvider) {
                await codeActionProvider.explainViolation(violation);
            } else {
                vscode.window.showWarningMessage('Code action provider not initialized');
            }
        }
    );

    const suppressViolationCommand = vscode.commands.registerCommand(
        'powershield.suppressViolation',
        async (document: vscode.TextDocument, violation: any, range: vscode.Range) => {
            if (codeActionProvider) {
                await codeActionProvider.suppressViolation(document, violation, range);
            } else {
                vscode.window.showWarningMessage('Code action provider not initialized');
            }
        }
    );
    
    const applyTemplateFixCommand = vscode.commands.registerCommand(
        'powershield.applyTemplateFix',
        async (document: vscode.TextDocument, violation: any, range: vscode.Range) => {
            if (codeActionProvider) {
                await codeActionProvider.applyTemplateFix(document, violation, range);
            } else {
                vscode.window.showWarningMessage('Code action provider not initialized');
            }
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
        applyTemplateFixCommand,
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
