/**
 * PowerShield Security CodeLens Provider
 * Provides inline security actions and summaries
 */

import * as vscode from 'vscode';
import { SecurityViolation, SecuritySeverity } from '../types';
import { PSSecurityProvider } from './SecurityProvider';

interface ViolationScope {
    range: vscode.Range;
    name: string;
    type: 'function' | 'document';
}

export class SecurityCodeLensProvider implements vscode.CodeLensProvider {
    private securityProvider: PSSecurityProvider;
    private documentViolations: Map<string, SecurityViolation[]> = new Map();
    
    private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
    public readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

    constructor(securityProvider: PSSecurityProvider) {
        this.securityProvider = securityProvider;
    }

    /**
     * Update violations for a document
     */
    public updateViolations(documentUri: string, violations: SecurityViolation[]): void {
        this.documentViolations.set(documentUri, violations);
        this._onDidChangeCodeLenses.fire();
    }

    /**
     * Clear violations for a document
     */
    public clearViolations(documentUri: string): void {
        this.documentViolations.delete(documentUri);
        this._onDidChangeCodeLenses.fire();
    }

    /**
     * Provide CodeLens for a document
     */
    async provideCodeLenses(
        document: vscode.TextDocument,
        token: vscode.CancellationToken
    ): Promise<vscode.CodeLens[]> {
        const config = vscode.workspace.getConfiguration('powershield');
        const showCodeLens = config.get<boolean>('ui.showCodeLens', true);
        
        if (!showCodeLens) {
            return [];
        }

        const codeLenses: vscode.CodeLens[] = [];
        const violations = this.documentViolations.get(document.uri.toString()) || [];
        
        if (violations.length === 0) {
            return [];
        }

        // Group violations by function/scope
        const violationGroups = this.groupViolationsByScope(document, violations);
        
        // Add scope-level CodeLens
        for (const [scope, scopeViolations] of violationGroups) {
            if (scope.type === 'function') {
                // Summary CodeLens for functions
                if (scopeViolations.length > 0) {
                    const summaryLens = new vscode.CodeLens(scope.range, {
                        title: `🛡️ ${scopeViolations.length} security issue${scopeViolations.length > 1 ? 's' : ''}`,
                        command: 'powershield.showScopeViolations',
                        arguments: [document.uri, scope, scopeViolations]
                    });
                    codeLenses.push(summaryLens);
                }
                
                // Quick fix CodeLens for high-confidence fixes
                const fixableViolations = scopeViolations.filter(v => 
                    v.hasQuickFix && (v.confidence || 0) > 0.8
                );
                
                if (fixableViolations.length > 0) {
                    const fixLens = new vscode.CodeLens(scope.range, {
                        title: `🔧 Fix ${fixableViolations.length} issue${fixableViolations.length > 1 ? 's' : ''}`,
                        command: 'powershield.applyAllScopeFixes',
                        arguments: [document.uri, scope, fixableViolations]
                    });
                    codeLenses.push(fixLens);
                }
            }
        }
        
        // Document-level summary at top of file
        if (violations.length > 0) {
            const documentRange = new vscode.Range(0, 0, 0, 0);
            const documentSummaryLens = new vscode.CodeLens(documentRange, {
                title: `📊 Security Summary: ${this.formatSecuritySummary(violations)}`,
                command: 'powershield.showDocumentSummary',
                arguments: [document.uri, violations]
            });
            codeLenses.push(documentSummaryLens);
        }
        
        return codeLenses;
    }

    /**
     * Group violations by their containing scope (function or document)
     */
    private groupViolationsByScope(
        document: vscode.TextDocument,
        violations: SecurityViolation[]
    ): Map<ViolationScope, SecurityViolation[]> {
        const groups = new Map<ViolationScope, SecurityViolation[]>();
        
        // Get function definitions from document
        const functionScopes = this.extractFunctionScopes(document);
        
        // Group violations
        for (const violation of violations) {
            const line = violation.lineNumber - 1; // Convert to 0-based
            
            // Find containing function
            let containingScope: ViolationScope | null = null;
            for (const scope of functionScopes) {
                if (scope.range.contains(new vscode.Position(line, 0))) {
                    containingScope = scope;
                    break;
                }
            }
            
            // Use function scope or document scope
            if (containingScope) {
                if (!groups.has(containingScope)) {
                    groups.set(containingScope, []);
                }
                groups.get(containingScope)!.push(violation);
            }
        }
        
        return groups;
    }

    /**
     * Extract function scopes from document
     */
    private extractFunctionScopes(document: vscode.TextDocument): ViolationScope[] {
        const scopes: ViolationScope[] = [];
        const text = document.getText();
        
        // Match PowerShell function definitions
        // Supports: function Name {}, Function Name {}, function Name() {}
        const functionRegex = /^[\s]*(?:function|filter|workflow)\s+([a-zA-Z_][\w-]*)/gim;
        let match;
        
        while ((match = functionRegex.exec(text)) !== null) {
            const functionName = match[1];
            const startPos = document.positionAt(match.index);
            
            // Find the closing brace for this function
            const endPos = this.findFunctionEnd(document, startPos);
            
            if (endPos) {
                scopes.push({
                    range: new vscode.Range(startPos, endPos),
                    name: functionName,
                    type: 'function'
                });
            }
        }
        
        return scopes;
    }

    /**
     * Find the end position of a function by matching braces
     */
    private findFunctionEnd(
        document: vscode.TextDocument,
        startPos: vscode.Position
    ): vscode.Position | null {
        const text = document.getText();
        const startOffset = document.offsetAt(startPos);
        
        // Find opening brace
        let braceCount = 0;
        let foundOpen = false;
        
        for (let i = startOffset; i < text.length; i++) {
            const char = text[i];
            
            if (char === '{') {
                foundOpen = true;
                braceCount++;
            } else if (char === '}') {
                braceCount--;
                
                if (foundOpen && braceCount === 0) {
                    return document.positionAt(i + 1);
                }
            }
        }
        
        // If we couldn't find the end, use end of document
        return new vscode.Position(document.lineCount - 1, 0);
    }

    /**
     * Format security summary for display
     */
    private formatSecuritySummary(violations: SecurityViolation[]): string {
        const counts: Record<string, number> = {};
        
        for (const violation of violations) {
            const severityName = SecuritySeverity[violation.severity];
            counts[severityName] = (counts[severityName] || 0) + 1;
        }
        
        const parts: string[] = [];
        if (counts.Critical) parts.push(`${counts.Critical} Critical`);
        if (counts.High) parts.push(`${counts.High} High`);
        if (counts.Medium) parts.push(`${counts.Medium} Medium`);
        if (counts.Low) parts.push(`${counts.Low} Low`);
        
        return parts.join(', ') || 'No issues';
    }

    /**
     * Dispose of resources
     */
    public dispose(): void {
        this._onDidChangeCodeLenses.dispose();
    }
}
