/**
 * PowerShield Security Dashboard
 * Interactive webview for security analysis overview
 */

import * as vscode from 'vscode';
import { SecurityViolation, SecuritySeverity } from '../types';
import { PSSecurityProvider } from '../providers/SecurityProvider';

interface DashboardData {
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        total: number;
    };
    violations: SecurityViolation[];
    topIssues: Array<{
        ruleId: string;
        count: number;
        severity: SecuritySeverity;
    }>;
    fileStats: Array<{
        filePath: string;
        violations: number;
        criticalCount: number;
    }>;
    compliance: {
        cwe: string[];
        owasp: string[];
        mitre: string[];
    };
}

export class SecurityDashboard {
    private panel: vscode.WebviewPanel | undefined;
    private securityProvider: PSSecurityProvider;
    private context: vscode.ExtensionContext;

    constructor(
        context: vscode.ExtensionContext,
        securityProvider: PSSecurityProvider
    ) {
        this.context = context;
        this.securityProvider = securityProvider;
    }

    /**
     * Show the security dashboard
     */
    async show(): Promise<void> {
        if (this.panel) {
            this.panel.reveal(vscode.ViewColumn.Two);
            await this.updateDashboardData();
            return;
        }

        this.panel = vscode.window.createWebviewPanel(
            'powershield-dashboard',
            'PowerShield Security Dashboard',
            vscode.ViewColumn.Two,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [
                    vscode.Uri.joinPath(this.context.extensionUri, 'media')
                ]
            }
        );

        this.panel.webview.html = this.getWebviewContent();
        this.setupWebviewMessageHandling();

        this.panel.onDidDispose(() => {
            this.panel = undefined;
        });

        // Initial data load
        await this.updateDashboardData();
    }

    /**
     * Setup message handling from webview
     */
    private setupWebviewMessageHandling(): void {
        if (!this.panel) return;

        this.panel.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.type) {
                    case 'refresh':
                        await this.updateDashboardData();
                        break;
                    case 'exportReport':
                        await this.exportReport(message.format);
                        break;
                    case 'jumpToViolation':
                        await this.jumpToViolation(message.violation);
                        break;
                    case 'openSettings':
                        await vscode.commands.executeCommand('powershield.configureSettings');
                        break;
                }
            },
            undefined,
            []
        );
    }

    /**
     * Update dashboard with current analysis data
     */
    private async updateDashboardData(): Promise<void> {
        if (!this.panel) return;

        try {
            const data = await this.collectDashboardData();
            this.panel.webview.postMessage({
                type: 'updateData',
                data
            });
        } catch (error) {
            console.error('Failed to update dashboard data:', error);
            vscode.window.showErrorMessage('Failed to update dashboard data');
        }
    }

    /**
     * Collect all security data for the dashboard
     */
    private async collectDashboardData(): Promise<DashboardData> {
        const allViolations: SecurityViolation[] = [];
        const fileViolations = new Map<string, SecurityViolation[]>();

        // Collect violations from all PowerShell files in workspace
        if (vscode.workspace.workspaceFolders) {
            const psFiles = await vscode.workspace.findFiles(
                '**/*.{ps1,psm1,psd1}',
                '**/node_modules/**'
            );

            for (const fileUri of psFiles) {
                try {
                    const document = await vscode.workspace.openTextDocument(fileUri);
                    const violations = await this.securityProvider.analyzeDocument(document);
                    
                    if (violations.length > 0) {
                        allViolations.push(...violations);
                        fileViolations.set(fileUri.fsPath, violations);
                    }
                } catch (error) {
                    console.error(`Failed to analyze ${fileUri.fsPath}:`, error);
                }
            }
        }

        // Calculate summary
        const summary = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            total: allViolations.length
        };

        for (const violation of allViolations) {
            switch (violation.severity) {
                case SecuritySeverity.Critical:
                    summary.critical++;
                    break;
                case SecuritySeverity.High:
                    summary.high++;
                    break;
                case SecuritySeverity.Medium:
                    summary.medium++;
                    break;
                case SecuritySeverity.Low:
                    summary.low++;
                    break;
            }
        }

        // Calculate top issues
        const ruleCounts = new Map<string, { count: number; severity: SecuritySeverity }>();
        for (const violation of allViolations) {
            const existing = ruleCounts.get(violation.ruleId);
            if (existing) {
                existing.count++;
            } else {
                ruleCounts.set(violation.ruleId, {
                    count: 1,
                    severity: violation.severity
                });
            }
        }

        const topIssues = Array.from(ruleCounts.entries())
            .map(([ruleId, data]) => ({
                ruleId,
                count: data.count,
                severity: data.severity
            }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10);

        // Calculate file stats
        const fileStats = Array.from(fileViolations.entries())
            .map(([filePath, violations]) => ({
                filePath,
                violations: violations.length,
                criticalCount: violations.filter(v => v.severity === SecuritySeverity.Critical).length
            }))
            .sort((a, b) => b.violations - a.violations)
            .slice(0, 10);

        // Extract compliance data
        const compliance = {
            cwe: new Set<string>(),
            owasp: new Set<string>(),
            mitre: new Set<string>()
        };

        for (const violation of allViolations) {
            if (violation.metadata?.CWE) {
                violation.metadata.CWE.forEach(cwe => compliance.cwe.add(cwe));
            }
            if (violation.metadata?.OWASP) {
                violation.metadata.OWASP.forEach(owasp => compliance.owasp.add(owasp));
            }
            if (violation.metadata?.MitreAttack) {
                violation.metadata.MitreAttack.forEach(mitre => compliance.mitre.add(mitre));
            }
        }

        return {
            summary,
            violations: allViolations,
            topIssues,
            fileStats,
            compliance: {
                cwe: Array.from(compliance.cwe),
                owasp: Array.from(compliance.owasp),
                mitre: Array.from(compliance.mitre)
            }
        };
    }

    /**
     * Export security report
     */
    private async exportReport(format: 'markdown' | 'json' | 'html'): Promise<void> {
        try {
            const data = await this.collectDashboardData();
            let content: string;
            let fileName: string;

            switch (format) {
                case 'markdown':
                    content = this.generateMarkdownReport(data);
                    fileName = 'powershield-report.md';
                    break;
                case 'json':
                    content = JSON.stringify(data, null, 2);
                    fileName = 'powershield-report.json';
                    break;
                case 'html':
                    content = this.generateHtmlReport(data);
                    fileName = 'powershield-report.html';
                    break;
                default:
                    throw new Error(`Unsupported format: ${format}`);
            }

            const saveUri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(fileName),
                filters: {
                    'Report Files': [format]
                }
            });

            if (saveUri) {
                await vscode.workspace.fs.writeFile(
                    saveUri,
                    Buffer.from(content, 'utf8')
                );
                vscode.window.showInformationMessage(`Report exported to ${saveUri.fsPath}`);
            }
        } catch (error) {
            console.error('Failed to export report:', error);
            vscode.window.showErrorMessage('Failed to export report');
        }
    }

    /**
     * Generate markdown report
     */
    private generateMarkdownReport(data: DashboardData): string {
        let report = '# PowerShield Security Report\n\n';
        report += `Generated: ${new Date().toLocaleString()}\n\n`;
        
        report += '## Summary\n\n';
        report += `- **Total Issues**: ${data.summary.total}\n`;
        report += `- **Critical**: ${data.summary.critical}\n`;
        report += `- **High**: ${data.summary.high}\n`;
        report += `- **Medium**: ${data.summary.medium}\n`;
        report += `- **Low**: ${data.summary.low}\n\n`;
        
        if (data.topIssues.length > 0) {
            report += '## Top Security Issues\n\n';
            for (const issue of data.topIssues) {
                const severity = SecuritySeverity[issue.severity];
                report += `- **${issue.ruleId}** (${severity}): ${issue.count} occurrence${issue.count > 1 ? 's' : ''}\n`;
            }
            report += '\n';
        }
        
        if (data.fileStats.length > 0) {
            report += '## Most Affected Files\n\n';
            for (const file of data.fileStats) {
                report += `- **${file.filePath}**: ${file.violations} issue${file.violations > 1 ? 's' : ''} (${file.criticalCount} critical)\n`;
            }
            report += '\n';
        }
        
        return report;
    }

    /**
     * Generate HTML report
     */
    private generateHtmlReport(data: DashboardData): string {
        return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PowerShield Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .metric { padding: 20px; border-radius: 8px; color: white; }
        .critical { background-color: #dc3545; }
        .high { background-color: #fd7e14; }
        .medium { background-color: #ffc107; color: #333; }
        .low { background-color: #28a745; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #007bff; color: white; }
    </style>
</head>
<body>
    <h1>PowerShield Security Report</h1>
    <p>Generated: ${new Date().toLocaleString()}</p>
    
    <div class="summary">
        <div class="metric critical"><h3>Critical</h3><p>${data.summary.critical}</p></div>
        <div class="metric high"><h3>High</h3><p>${data.summary.high}</p></div>
        <div class="metric medium"><h3>Medium</h3><p>${data.summary.medium}</p></div>
        <div class="metric low"><h3>Low</h3><p>${data.summary.low}</p></div>
    </div>
    
    <h2>Top Security Issues</h2>
    <table>
        <tr><th>Rule ID</th><th>Severity</th><th>Count</th></tr>
        ${data.topIssues.map(issue => `
            <tr>
                <td>${issue.ruleId}</td>
                <td>${SecuritySeverity[issue.severity]}</td>
                <td>${issue.count}</td>
            </tr>
        `).join('')}
    </table>
</body>
</html>`;
    }

    /**
     * Jump to a specific violation in the editor
     */
    private async jumpToViolation(violation: SecurityViolation): Promise<void> {
        try {
            const fileUri = vscode.Uri.file(violation.filePath);
            const document = await vscode.workspace.openTextDocument(fileUri);
            const editor = await vscode.window.showTextDocument(document);
            
            const line = violation.lineNumber - 1;
            const position = new vscode.Position(line, 0);
            
            editor.selection = new vscode.Selection(position, position);
            editor.revealRange(
                new vscode.Range(position, position),
                vscode.TextEditorRevealType.InCenter
            );
        } catch (error) {
            console.error('Failed to jump to violation:', error);
            vscode.window.showErrorMessage('Failed to open file');
        }
    }

    /**
     * Get webview HTML content
     */
    private getWebviewContent(): string {
        const nonce = this.getNonce();

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
    <title>PowerShield Security Dashboard</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            padding: 0;
            margin: 0;
        }
        .dashboard-header {
            padding: 20px;
            background-color: var(--vscode-editorGroupHeader-tabsBackground);
            border-bottom: 1px solid var(--vscode-panel-border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .dashboard-header h1 {
            margin: 0;
            font-size: 24px;
        }
        .dashboard-actions button {
            margin-left: 10px;
            padding: 8px 16px;
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .dashboard-actions button:hover {
            background-color: var(--vscode-button-hoverBackground);
        }
        .dashboard-content {
            padding: 20px;
        }
        .metric-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .metric-card.critical {
            background-color: rgba(220, 53, 69, 0.2);
            border: 2px solid #dc3545;
        }
        .metric-card.high {
            background-color: rgba(253, 126, 20, 0.2);
            border: 2px solid #fd7e14;
        }
        .metric-card.medium {
            background-color: rgba(255, 193, 7, 0.2);
            border: 2px solid #ffc107;
        }
        .metric-card.low {
            background-color: rgba(40, 167, 69, 0.2);
            border: 2px solid #28a745;
        }
        .metric-card h3 {
            margin: 0 0 10px 0;
            font-size: 16px;
        }
        .metric-value {
            font-size: 36px;
            font-weight: bold;
        }
        .section {
            margin-bottom: 30px;
        }
        .section h2 {
            margin-top: 0;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        .violation-item {
            padding: 10px;
            margin: 10px 0;
            background-color: var(--vscode-list-hoverBackground);
            border-radius: 4px;
            cursor: pointer;
        }
        .violation-item:hover {
            background-color: var(--vscode-list-activeSelectionBackground);
        }
        .loading {
            text-align: center;
            padding: 40px;
            color: var(--vscode-descriptionForeground);
        }
    </style>
</head>
<body>
    <div id="app">
        <header class="dashboard-header">
            <h1>🛡️ PowerShield Security Dashboard</h1>
            <div class="dashboard-actions">
                <button id="refresh-btn">🔄 Refresh</button>
                <button id="export-md-btn">📄 Export Markdown</button>
                <button id="export-json-btn">📊 Export JSON</button>
                <button id="settings-btn">⚙️ Settings</button>
            </div>
        </header>
        
        <main class="dashboard-content">
            <section class="security-overview">
                <div class="metric-cards">
                    <div class="metric-card critical">
                        <h3>Critical Issues</h3>
                        <span class="metric-value" id="critical-count">0</span>
                    </div>
                    <div class="metric-card high">
                        <h3>High Issues</h3>
                        <span class="metric-value" id="high-count">0</span>
                    </div>
                    <div class="metric-card medium">
                        <h3>Medium Issues</h3>
                        <span class="metric-value" id="medium-count">0</span>
                    </div>
                    <div class="metric-card low">
                        <h3>Low Issues</h3>
                        <span class="metric-value" id="low-count">0</span>
                    </div>
                </div>
            </section>
            
            <section class="section top-violations">
                <h2>Top Security Issues</h2>
                <div id="violations-list" class="loading">Loading...</div>
            </section>
            
            <section class="section file-stats">
                <h2>Most Affected Files</h2>
                <div id="file-stats-list" class="loading">Loading...</div>
            </section>
        </main>
    </div>
    
    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();
        
        // Event listeners
        document.getElementById('refresh-btn').addEventListener('click', () => {
            vscode.postMessage({ type: 'refresh' });
        });
        
        document.getElementById('export-md-btn').addEventListener('click', () => {
            vscode.postMessage({ type: 'exportReport', format: 'markdown' });
        });
        
        document.getElementById('export-json-btn').addEventListener('click', () => {
            vscode.postMessage({ type: 'exportReport', format: 'json' });
        });
        
        document.getElementById('settings-btn').addEventListener('click', () => {
            vscode.postMessage({ type: 'openSettings' });
        });
        
        // Handle messages from extension
        window.addEventListener('message', event => {
            const message = event.data;
            
            if (message.type === 'updateData') {
                updateDashboard(message.data);
            }
        });
        
        function updateDashboard(data) {
            // Update metrics
            document.getElementById('critical-count').textContent = data.summary.critical;
            document.getElementById('high-count').textContent = data.summary.high;
            document.getElementById('medium-count').textContent = data.summary.medium;
            document.getElementById('low-count').textContent = data.summary.low;
            
            // Update top issues
            const violationsList = document.getElementById('violations-list');
            if (data.topIssues.length === 0) {
                violationsList.innerHTML = '<p>No security issues detected</p>';
            } else {
                violationsList.innerHTML = data.topIssues.map(issue => 
                    '<div class="violation-item">' +
                    '<strong>' + issue.ruleId + '</strong>: ' +
                    issue.count + ' occurrence' + (issue.count > 1 ? 's' : '') +
                    '</div>'
                ).join('');
            }
            
            // Update file stats
            const fileStatsList = document.getElementById('file-stats-list');
            if (data.fileStats.length === 0) {
                fileStatsList.innerHTML = '<p>No files analyzed</p>';
            } else {
                fileStatsList.innerHTML = data.fileStats.map(file => 
                    '<div class="violation-item">' +
                    '<strong>' + file.filePath + '</strong>: ' +
                    file.violations + ' issue' + (file.violations > 1 ? 's' : '') +
                    ' (' + file.criticalCount + ' critical)' +
                    '</div>'
                ).join('');
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
