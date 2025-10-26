/**
 * Fix Context Builder
 * Builds rich context for AI-powered fix generation
 */

import * as vscode from 'vscode';
import { SecurityViolation, FixContext, FunctionContext } from '../types';

/**
 * Builds context information for fix generation
 */
export class FixContextBuilder {
    /**
     * Build complete fix context from document and violation
     */
    buildFixContext(
        document: vscode.TextDocument,
        violation: SecurityViolation,
        range: vscode.Range
    ): FixContext {
        const lineNumber = violation.lineNumber - 1; // Convert to 0-indexed
        const targetRange = range || new vscode.Range(lineNumber, 0, lineNumber, Number.MAX_VALUE);
        
        return {
            violation,
            codeContext: {
                beforeLines: this.getContextLines(document, Math.max(0, lineNumber - 5), lineNumber),
                targetCode: document.getText(targetRange),
                afterLines: this.getContextLines(document, lineNumber + 1, Math.min(document.lineCount, lineNumber + 6)),
                functionContext: this.getFunctionContext(document, targetRange),
                moduleContext: this.getModuleContext(document)
            },
            projectContext: {
                workspaceType: this.detectWorkspaceType(),
                dependencies: this.getProjectDependencies(),
                conventions: this.detectCodingConventions(document)
            }
        };
    }
    
    /**
     * Get context lines from document
     */
    private getContextLines(
        document: vscode.TextDocument,
        startLine: number,
        endLine: number
    ): string[] {
        const lines: string[] = [];
        
        for (let i = startLine; i < endLine && i < document.lineCount; i++) {
            lines.push(document.lineAt(i).text);
        }
        
        return lines;
    }
    
    /**
     * Get function context containing the violation
     */
    private getFunctionContext(
        document: vscode.TextDocument,
        range: vscode.Range
    ): FunctionContext | undefined {
        const text = document.getText();
        const lineNumber = range.start.line;
        
        // Simple PowerShell function detection
        // Look backwards for function declaration
        for (let i = lineNumber; i >= 0; i--) {
            const line = document.lineAt(i).text;
            const functionMatch = line.match(/^\s*(?:function|filter)\s+([A-Za-z][\w-]*)\s*(?:\(([^)]*)\))?/);
            
            if (functionMatch) {
                const functionName = functionMatch[1];
                const paramsStr = functionMatch[2] || '';
                
                // Extract parameters
                const parameters: string[] = [];
                if (paramsStr) {
                    parameters.push(...paramsStr.split(',').map(p => p.trim()).filter(p => p));
                }
                
                // Look for param block
                const paramBlockMatch = text.match(new RegExp(
                    `function\\s+${functionName}[^{]*\\{\\s*param\\s*\\(([^)]+)\\)`,
                    'i'
                ));
                
                if (paramBlockMatch && parameters.length === 0) {
                    const paramBlock = paramBlockMatch[1];
                    const paramMatches = paramBlock.match(/\[\w+\]\s*\$\w+/g);
                    if (paramMatches) {
                        parameters.push(...paramMatches.map(p => p.trim()));
                    }
                }
                
                return {
                    name: functionName,
                    parameters,
                    purpose: this.inferFunctionPurpose(functionName),
                    scope: this.determineFunctionScope(line)
                };
            }
        }
        
        return undefined;
    }
    
    /**
     * Infer function purpose from name
     */
    private inferFunctionPurpose(functionName: string): string | undefined {
        const verbMatch = functionName.match(/^([A-Z][a-z]+)-/);
        if (verbMatch) {
            const verb = verbMatch[1].toLowerCase();
            const commonVerbs: Record<string, string> = {
                'get': 'retrieves data or information',
                'set': 'modifies or configures settings',
                'new': 'creates new objects or resources',
                'remove': 'deletes objects or resources',
                'invoke': 'executes an operation or command',
                'test': 'validates or checks conditions',
                'start': 'initiates a process or service',
                'stop': 'terminates a process or service',
                'enable': 'activates a feature or capability',
                'disable': 'deactivates a feature or capability',
                'add': 'adds items to a collection',
                'clear': 'removes all items from a collection',
                'copy': 'duplicates data or files',
                'move': 'relocates data or files',
                'export': 'saves data to external format',
                'import': 'loads data from external source'
            };
            
            return commonVerbs[verb];
        }
        
        return undefined;
    }
    
    /**
     * Determine function scope
     */
    private determineFunctionScope(line: string): string {
        if (line.includes('private')) return 'private';
        if (line.includes('public')) return 'public';
        return 'public'; // Default in PowerShell
    }
    
    /**
     * Get module context
     */
    private getModuleContext(document: vscode.TextDocument): string | undefined {
        const text = document.getText();
        
        // Check if this is a module file
        if (document.fileName.endsWith('.psm1')) {
            // Extract module name from file name
            const fileName = document.fileName.split(/[/\\]/).pop();
            return fileName?.replace('.psm1', '');
        }
        
        // Look for module manifest or import
        const moduleMatch = text.match(/#\s*Module:\s*(\S+)/i);
        if (moduleMatch) {
            return moduleMatch[1];
        }
        
        return undefined;
    }
    
    /**
     * Detect workspace type
     */
    private detectWorkspaceType(): string | undefined {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            return undefined;
        }
        
        // Check for common project indicators
        const rootPath = workspaceFolders[0].uri.fsPath;
        
        // Check for Azure DevOps or GitHub
        if (rootPath.includes('.git')) return 'git';
        if (rootPath.includes('azure-pipelines')) return 'azure-devops';
        if (rootPath.includes('.github')) return 'github';
        
        return 'generic';
    }
    
    /**
     * Get project dependencies
     */
    private getProjectDependencies(): string[] | undefined {
        // In future, could parse .psd1 manifest files
        // For now, return undefined
        return undefined;
    }
    
    /**
     * Detect coding conventions
     */
    private detectCodingConventions(document: vscode.TextDocument): string | undefined {
        const text = document.getText();
        
        // Detect indentation style
        const spaceMatch = text.match(/^\s{4}/m);
        const tabMatch = text.match(/^\t/m);
        
        if (spaceMatch && !tabMatch) return 'spaces-4';
        if (tabMatch && !spaceMatch) return 'tabs';
        if (spaceMatch) return 'spaces-4';
        
        return 'spaces-4'; // Default
    }
}
