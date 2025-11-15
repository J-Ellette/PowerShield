/**
 * PowerShield Core Engine
 * Bridges TypeScript extension with PowerShell analysis engine
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { spawn } from 'child_process';
import {
    AnalysisResult,
    SecurityViolation,
    PowerShellResult,
    PowerShieldConfig,
    SecuritySeverity
} from '../types';

export class PowerShieldEngine {
    private context: vscode.ExtensionContext | undefined;
    private config: PowerShieldConfig | undefined;
    private outputChannel: vscode.OutputChannel;
    private analyzerModulePath: string;
    private vscodeIntegrationPath: string;

    constructor() {
        this.outputChannel = vscode.window.createOutputChannel('PowerShield');
        
        // Paths to PowerShell modules (relative to repository root)
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
        const extensionRoot = path.dirname(path.dirname(__dirname)); // Go up from out/core to vscode-extension
        const repoRoot = path.dirname(extensionRoot); // Go up to repository root
        
        this.analyzerModulePath = path.join(repoRoot, 'src', 'PowerShellSecurityAnalyzer.psm1');
        this.vscodeIntegrationPath = path.join(repoRoot, 'src', 'VSCodeIntegration.psm1');
        
        this.log(`Analyzer module path: ${this.analyzerModulePath}`);
        this.log(`VS Code integration path: ${this.vscodeIntegrationPath}`);
    }

    /**
     * Initialize the PowerShield engine
     */
    async initialize(context: vscode.ExtensionContext): Promise<void> {
        this.context = context;
        this.config = this.loadConfiguration();
        
        this.log('PowerShield Engine initializing...');
        
        // Verify PowerShell is available
        const psAvailable = await this.verifyPowerShellAvailable();
        if (!psAvailable) {
            vscode.window.showErrorMessage(
                'PowerShell 7+ is required for PowerShield. Please install PowerShell Core.'
            );
            throw new Error('PowerShell 7+ not available');
        }
        
        // Verify analyzer module exists
        const fs = await import('fs');
        if (!fs.existsSync(this.analyzerModulePath)) {
            vscode.window.showErrorMessage(
                `PowerShield analyzer module not found at: ${this.analyzerModulePath}`
            );
            throw new Error('Analyzer module not found');
        }
        
        this.log('PowerShield Engine initialized successfully');
    }

    /**
     * Load configuration from VS Code settings
     */
    private loadConfiguration(): PowerShieldConfig {
        const config = vscode.workspace.getConfiguration('powershield');
        
        return {
            realTimeAnalysis: {
                enabled: config.get('realTimeAnalysis.enabled', true),
                debounceMs: config.get('realTimeAnalysis.debounceMs', 1000),
                backgroundAnalysis: config.get('realTimeAnalysis.backgroundAnalysis', true)
            },
            aiProvider: {
                primary: config.get('aiProvider.primary', 'github-models'),
                fallback: config.get('aiProvider.fallback', ['template-based']),
                confidenceThreshold: config.get('aiProvider.confidenceThreshold', 0.8)
            },
            ui: {
                showInlineDecorations: config.get('ui.showInlineDecorations', true),
                showHoverExplanations: config.get('ui.showHoverExplanations', true),
                showCodeLens: config.get('ui.showCodeLens', true)
            },
            performance: {
                enableCaching: config.get('performance.enableCaching', true),
                maxCacheSize: config.get('performance.maxCacheSize', '100MB'),
                enableIncrementalAnalysis: config.get('performance.enableIncrementalAnalysis', true)
            },
            rules: {
                enabled: config.get('rules.enabled', []),
                disabled: config.get('rules.disabled', [])
            },
            suppressions: {
                enabled: config.get('suppressions.enabled', true)
            }
        };
    }

    /**
     * Get current configuration
     */
    getConfiguration(): PowerShieldConfig {
        if (!this.config) {
            this.config = this.loadConfiguration();
        }
        return this.config;
    }

    /**
     * Reload configuration from settings
     */
    reloadConfiguration(): void {
        this.config = this.loadConfiguration();
        this.log('Configuration reloaded');
    }

    /**
     * Verify PowerShell 7+ is available
     */
    private async verifyPowerShellAvailable(): Promise<boolean> {
        try {
            const result = await this.executePowerShell('$PSVersionTable.PSVersion.Major');
            const version = parseInt(result.stdout.trim());
            this.log(`PowerShell version detected: ${version}`);
            return version >= 7;
        } catch (error) {
            this.log(`PowerShell verification failed: ${error}`);
            return false;
        }
    }

    /**
     * Analyze a PowerShell script file
     */
    async analyzeScript(filePath: string, content?: string): Promise<AnalysisResult> {
        const startTime = Date.now();
        
        try {
            this.log(`Analyzing script: ${filePath}`);
            
            // Build PowerShell command to analyze the script
            const script = content 
                ? this.buildAnalyzeContentScript(filePath, content)
                : this.buildAnalyzeFileScript(filePath);
            
            const result = await this.executePowerShell(script);
            
            if (result.exitCode !== 0) {
                this.log(`Analysis failed: ${result.stderr}`);
                throw new Error(`Analysis failed: ${result.stderr}`);
            }
            
            // Parse the JSON output from PowerShell
            const violations = this.parseAnalysisResult(result.stdout);
            
            const analysisTime = Date.now() - startTime;
            this.log(`Analysis completed in ${analysisTime}ms, found ${violations.length} violations`);
            
            return {
                filePath,
                violations,
                timestamp: new Date(),
                analysisTime
            };
        } catch (error) {
            this.log(`Analysis error: ${error}`);
            throw error;
        }
    }

    /**
     * Build PowerShell script to analyze file
     */
    private buildAnalyzeFileScript(filePath: string): string {
        // Escape path for PowerShell
        const escapedPath = filePath.replace(/\\/g, '\\\\').replace(/'/g, "''");
        
        return `
            Import-Module '${this.analyzerModulePath}' -Force -ErrorAction Stop
            Import-Module '${this.vscodeIntegrationPath}' -Force -ErrorAction Stop
            
            $analyzer = New-SecurityAnalyzer
            $result = Invoke-SecurityAnalysis -ScriptPath '${escapedPath}'
            
            if ($result.Violations) {
                $integration = New-VSCodeIntegration
                $diagnostics = $integration.ConvertToDiagnostics($result.Violations, '${escapedPath}')
                $diagnostics | ConvertTo-Json -Depth 10 -Compress
            } else {
                Write-Output '[]'
            }
        `;
    }

    /**
     * Build PowerShell script to analyze content
     */
    private buildAnalyzeContentScript(filePath: string, content: string): string {
        // Escape content for PowerShell
        const escapedContent = content.replace(/`/g, '``').replace(/\$/g, '`$').replace(/"/g, '`"');
        const escapedPath = filePath.replace(/\\/g, '\\\\').replace(/'/g, "''");
        
        return `
            Import-Module '${this.analyzerModulePath}' -Force -ErrorAction Stop
            Import-Module '${this.vscodeIntegrationPath}' -Force -ErrorAction Stop
            
            $content = @"
${escapedContent}
"@
            
            # Write content to temp file for analysis
            # POWERSHIELD-SUPPRESS-NEXT: UnsafeFileInclusion - Legitimate temporary file usage for VS Code extension analysis (2026-12-31)
            $tempFile = [System.IO.Path]::GetTempFileName() + '.ps1'
            $content | Out-File -FilePath $tempFile -Encoding utf8
            
            try {
                $analyzer = New-SecurityAnalyzer
                $result = Invoke-SecurityAnalysis -ScriptPath $tempFile
                
                if ($result.Violations) {
                    # Update violations to reference original file
                    foreach ($v in $result.Violations) {
                        $v.FilePath = '${escapedPath}'
                    }
                    
                    $integration = New-VSCodeIntegration
                    $diagnostics = $integration.ConvertToDiagnostics($result.Violations, '${escapedPath}')
                    $diagnostics | ConvertTo-Json -Depth 10 -Compress
                } else {
                    Write-Output '[]'
                }
            } finally {
                Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
            }
        `;
    }

    /**
     * Parse analysis result from PowerShell output
     */
    private parseAnalysisResult(output: string): SecurityViolation[] {
        try {
            if (!output || output.trim() === '[]' || output.trim() === '') {
                return [];
            }
            
            const diagnostics = JSON.parse(output);
            
            // Convert VS Code diagnostics back to SecurityViolation format
            return diagnostics.map((d: any) => this.convertDiagnosticToViolation(d));
        } catch (error) {
            this.log(`Failed to parse analysis result: ${error}`);
            this.log(`Raw output: ${output}`);
            return [];
        }
    }

    /**
     * Convert VS Code diagnostic to SecurityViolation
     */
    private convertDiagnosticToViolation(diagnostic: any): SecurityViolation {
        // Map VS Code severity back to PowerShield severity
        const severity = this.mapVSCodeSeverity(diagnostic.severity);
        
        return {
            name: diagnostic.code || 'Unknown',
            message: diagnostic.message,
            description: diagnostic.message,
            severity,
            lineNumber: (diagnostic.range?.start?.line || 0) + 1, // Convert back to 1-indexed
            columnNumber: diagnostic.range?.start?.character || 0,
            endColumn: diagnostic.range?.end?.character,
            code: diagnostic.code || '',
            filePath: '',
            ruleId: diagnostic.code || '',
            metadata: {},
            fixes: diagnostic.codeActions ? this.parseCodeActions(diagnostic.codeActions) : []
        };
    }

    /**
     * Map VS Code severity to PowerShield severity
     */
    private mapVSCodeSeverity(vsSeverity: number): SecuritySeverity {
        switch (vsSeverity) {
            case 1: return SecuritySeverity.Critical; // Error
            case 2: return SecuritySeverity.Medium;   // Warning
            case 3: return SecuritySeverity.Low;      // Information
            case 4: return SecuritySeverity.Low;      // Hint
            default: return SecuritySeverity.Medium;
        }
    }

    /**
     * Parse code actions from diagnostic
     */
    private parseCodeActions(codeActions: any[]): any[] {
        return codeActions.map(action => ({
            description: action.title,
            fixedCode: '',
            confidence: action.isPreferred ? 0.9 : 0.7,
            category: action.kind || 'quickfix'
        }));
    }

    /**
     * Execute PowerShell command
     */
    private async executePowerShell(script: string): Promise<PowerShellResult> {
        return new Promise((resolve, reject) => {
            let stdout = '';
            let stderr = '';
            
            // Use pwsh (PowerShell Core) or powershell
            const psCommand = process.platform === 'win32' ? 'pwsh.exe' : 'pwsh';
            
            const ps = spawn(psCommand, [
                '-NoProfile',
                '-NonInteractive',
                '-NoLogo',
                '-Command',
                script
            ]);
            
            ps.stdout.on('data', (data) => {
                stdout += data.toString();
            });
            
            ps.stderr.on('data', (data) => {
                stderr += data.toString();
            });
            
            ps.on('close', (code) => {
                resolve({
                    stdout,
                    stderr,
                    exitCode: code || 0
                });
            });
            
            ps.on('error', (err) => {
                reject(new Error(`Failed to start PowerShell: ${err.message}`));
            });
            
            // Timeout after 30 seconds
            setTimeout(() => {
                ps.kill();
                reject(new Error('PowerShell execution timed out'));
            }, 30000);
        });
    }

    /**
     * Log message to output channel
     */
    private log(message: string): void {
        const timestamp = new Date().toISOString();
        this.outputChannel.appendLine(`[${timestamp}] ${message}`);
    }

    /**
     * Show output channel
     */
    showOutput(): void {
        this.outputChannel.show();
    }

    /**
     * Dispose resources
     */
    dispose(): void {
        this.outputChannel.dispose();
    }
}
