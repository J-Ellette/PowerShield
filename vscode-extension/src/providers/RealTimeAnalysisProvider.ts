/**
 * Real-Time Analysis Provider
 * Handles document change events with debouncing and scheduling
 */

import * as vscode from 'vscode';
import { PSSecurityProvider } from './SecurityProvider';
import { PowerShieldEngine } from '../core/PowerShieldEngine';
import { SecurityViolation } from '../types';
import { SecurityDiagnosticsProvider } from './DiagnosticsProvider';
import { SecurityHoverProvider } from './HoverProvider';

export class RealTimeAnalysisProvider {
    private analysisTimeouts: Map<string, NodeJS.Timeout> = new Map();
    private debounceMs: number = 1000;
    private enabled: boolean = true;
    private securityProvider: PSSecurityProvider;
    private powerShieldEngine: PowerShieldEngine;
    private diagnosticCollection: vscode.DiagnosticCollection;
    private diagnosticsProvider: SecurityDiagnosticsProvider;
    private hoverProvider: SecurityHoverProvider;

    constructor(
        engine: PowerShieldEngine,
        securityProvider: PSSecurityProvider,
        diagnosticCollection: vscode.DiagnosticCollection,
        hoverProvider: SecurityHoverProvider
    ) {
        this.powerShieldEngine = engine;
        this.securityProvider = securityProvider;
        this.diagnosticCollection = diagnosticCollection;
        this.diagnosticsProvider = new SecurityDiagnosticsProvider(diagnosticCollection);
        this.hoverProvider = hoverProvider;
        this.updateSettings();
    }

    /**
     * Update settings from configuration
     */
    updateSettings(): void {
        const config = this.powerShieldEngine.getConfiguration();
        this.enabled = config.realTimeAnalysis.enabled;
        this.debounceMs = config.realTimeAnalysis.debounceMs;
    }

    /**
     * Setup document watchers for real-time analysis
     */
    setupDocumentWatchers(context: vscode.ExtensionContext): void {
        // Real-time analysis on document changes
        const documentChangeListener = vscode.workspace.onDidChangeTextDocument(
            async (event) => {
                if (!this.enabled) {
                    return;
                }
                
                if (this.isPowerShellDocument(event.document)) {
                    await this.scheduleAnalysis(event.document);
                }
            }
        );

        // Immediate analysis on save
        const documentSaveListener = vscode.workspace.onDidSaveTextDocument(
            async (document) => {
                if (!this.enabled) {
                    return;
                }
                
                if (this.isPowerShellDocument(document)) {
                    await this.immediateAnalysis(document);
                }
            }
        );

        // Analysis when document is opened
        const documentOpenListener = vscode.workspace.onDidOpenTextDocument(
            async (document) => {
                if (!this.enabled) {
                    return;
                }
                
                if (this.isPowerShellDocument(document)) {
                    await this.immediateAnalysis(document);
                }
            }
        );

        // Clear diagnostics when document is closed
        const documentCloseListener = vscode.workspace.onDidCloseTextDocument(
            (document) => {
                if (this.isPowerShellDocument(document)) {
                    this.diagnosticCollection.delete(document.uri);
                    this.clearScheduledAnalysis(document.uri.toString());
                }
            }
        );

        context.subscriptions.push(
            documentChangeListener,
            documentSaveListener,
            documentOpenListener,
            documentCloseListener
        );
    }

    /**
     * Check if document is a PowerShell file
     */
    private isPowerShellDocument(document: vscode.TextDocument): boolean {
        return document.languageId === 'powershell' && 
               document.uri.scheme === 'file';
    }

    /**
     * Schedule analysis with debouncing
     */
    private async scheduleAnalysis(document: vscode.TextDocument): Promise<void> {
        const uri = document.uri.toString();

        // Clear existing timeout
        this.clearScheduledAnalysis(uri);

        // Schedule new analysis
        const timeout = setTimeout(async () => {
            await this.performAnalysis(document);
            this.analysisTimeouts.delete(uri);
        }, this.debounceMs);

        this.analysisTimeouts.set(uri, timeout);
    }

    /**
     * Clear scheduled analysis for a URI
     */
    private clearScheduledAnalysis(uri: string): void {
        const existingTimeout = this.analysisTimeouts.get(uri);
        if (existingTimeout) {
            clearTimeout(existingTimeout);
            this.analysisTimeouts.delete(uri);
        }
    }

    /**
     * Perform immediate analysis (no debounce)
     */
    private async immediateAnalysis(document: vscode.TextDocument): Promise<void> {
        // Clear any scheduled analysis
        this.clearScheduledAnalysis(document.uri.toString());
        
        // Perform analysis immediately
        await this.performAnalysis(document);
    }

    /**
     * Perform the actual analysis
     */
    private async performAnalysis(document: vscode.TextDocument): Promise<void> {
        try {
            // Show progress for long-running analysis
            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Window,
                    title: `PowerShield: Analyzing ${document.fileName.split(/[\\/]/).pop()}...`,
                    cancellable: false
                },
                async (progress) => {
                    // Analyze the document
                    const violations = await this.securityProvider.analyzeDocument(document);

                    // Update diagnostics
                    this.updateDiagnostics(document, violations);

                    // Show notification if critical issues found
                    const criticalCount = violations.filter(v => v.severity === 4).length;
                    if (criticalCount > 0) {
                        vscode.window.showWarningMessage(
                            `PowerShield found ${criticalCount} critical security issue(s) in ${document.fileName.split(/[\\/]/).pop()}`
                        );
                    }
                }
            );
        } catch (error) {
            // Log error but don't show to user for every analysis
            console.error('PowerShield analysis error:', error);
            
            // Clear diagnostics on error
            this.diagnosticCollection.delete(document.uri);
        }
    }

    /**
     * Update VS Code diagnostics from violations
     */
    private updateDiagnostics(
        document: vscode.TextDocument,
        violations: SecurityViolation[]
    ): void {
        // Use the new DiagnosticsProvider
        this.diagnosticsProvider.updateDiagnostics(document, violations);
        
        // Update hover provider with violations
        this.hoverProvider.updateViolations(document, violations);
    }

    /**
     * Trigger analysis for all open PowerShell documents
     */
    async analyzeAllOpenDocuments(): Promise<void> {
        const documents = vscode.workspace.textDocuments.filter(
            doc => this.isPowerShellDocument(doc)
        );

        for (const document of documents) {
            await this.immediateAnalysis(document);
        }
    }

    /**
     * Dispose resources
     */
    dispose(): void {
        // Clear all pending timeouts
        for (const timeout of this.analysisTimeouts.values()) {
            clearTimeout(timeout);
        }
        this.analysisTimeouts.clear();
    }
}
