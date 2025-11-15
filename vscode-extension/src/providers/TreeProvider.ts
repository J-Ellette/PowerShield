/**
 * Security Tree Provider
 * Provides a tree view for workspace security overview in the sidebar
 */

import * as vscode from 'vscode';
import { SecurityViolation, SecuritySeverity, WorkspaceSecurityState, SecuritySummary } from '../types';

/**
 * Base class for security tree items
 */
export class SecurityTreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue?: string
    ) {
        super(label, collapsibleState);
    }
}

/**
 * Security summary tree item
 */
export class SecuritySummaryItem extends SecurityTreeItem {
    constructor(public readonly summary: SecuritySummary) {
        super(
            `📊 Security Overview`,
            vscode.TreeItemCollapsibleState.Collapsed,
            'summary'
        );

        const totalViolations = summary.totalViolations || 0;
        const totalFiles = summary.totalFiles || 0;
        
        this.description = `${totalViolations} issue${totalViolations !== 1 ? 's' : ''} in ${totalFiles} file${totalFiles !== 1 ? 's' : ''}`;
        this.tooltip = this.createTooltip();
    }

    private createTooltip(): string {
        const s = this.summary;
        return [
            `Total Files: ${s.totalFiles || 0}`,
            `Total Issues: ${s.totalViolations || 0}`,
            `Critical: ${s.criticalCount || 0}`,
            `High: ${s.highCount || 0}`,
            `Medium: ${s.mediumCount || 0}`,
            `Low: ${s.lowCount || 0}`,
            s.lastAnalysis ? `Last Analysis: ${s.lastAnalysis.toLocaleString()}` : ''
        ].filter(Boolean).join('\n');
    }
}

/**
 * Security category tree item
 */
export class SecurityCategoryItem extends SecurityTreeItem {
    constructor(
        public readonly categoryLabel: string,
        public readonly severity: string,
        public readonly violations: SecurityViolation[]
    ) {
        const icon = SecurityCategoryItem.getIcon(severity);
        super(
            `${icon} ${categoryLabel}`,
            violations.length > 0 
                ? vscode.TreeItemCollapsibleState.Collapsed 
                : vscode.TreeItemCollapsibleState.None,
            'category'
        );

        this.description = `${violations.length}`;
        this.tooltip = `${violations.length} ${severity} severity issue${violations.length !== 1 ? 's' : ''}`;
        
        // Set icon color based on severity
        this.iconPath = new vscode.ThemeIcon(
            'warning',
            this.getThemeColor(severity)
        );
    }

    private static getIcon(severity: string): string {
        switch (severity) {
            case 'critical': return '🔴';
            case 'high': return '🟠';
            case 'medium': return '🟡';
            case 'low': return '🔵';
            case 'info': return '⚪';
            default: return '⚪';
        }
    }

    private getThemeColor(severity: string): vscode.ThemeColor | undefined {
        switch (severity) {
            case 'critical':
            case 'high':
                return new vscode.ThemeColor('errorForeground');
            case 'medium':
                return new vscode.ThemeColor('warningForeground');
            case 'low':
            case 'info':
                return new vscode.ThemeColor('infoForeground');
            default:
                return undefined;
        }
    }
}

/**
 * Security violation tree item
 */
export class SecurityViolationItem extends SecurityTreeItem {
    constructor(public readonly violation: SecurityViolation) {
        const fileName = SecurityViolationItem.extractFileName(violation.filePath);
        super(
            `${fileName}:${violation.lineNumber}`,
            vscode.TreeItemCollapsibleState.None,
            'violation'
        );

        this.description = violation.description || violation.message;
        this.tooltip = this.createTooltip();
        
        // Set icon based on severity
        this.iconPath = new vscode.ThemeIcon(
            'warning',
            this.getThemeColor(violation.severity)
        );

        // Set command to jump to violation
        this.command = {
            command: 'powershield.jumpToViolation',
            title: 'Jump to Violation',
            arguments: [violation]
        };
    }

    private static extractFileName(filePath: string): string {
        const parts = filePath.split(/[\\/]/);
        return parts[parts.length - 1] || filePath;
    }

    private createTooltip(): vscode.MarkdownString {
        const tooltip = new vscode.MarkdownString();
        tooltip.appendMarkdown(`**${this.violation.name || this.violation.ruleId}**\n\n`);
        tooltip.appendMarkdown(`${this.violation.description || this.violation.message}\n\n`);
        tooltip.appendMarkdown(`File: ${this.violation.filePath}\n`);
        tooltip.appendMarkdown(`Line: ${this.violation.lineNumber}\n`);
        
        const cweId = this.extractCWEId();
        if (cweId) {
            tooltip.appendMarkdown(`CWE: ${cweId}\n`);
        }
        
        return tooltip;
    }

    private extractCWEId(): string | null {
        if (this.violation.cweId) {
            return this.violation.cweId;
        }
        if (this.violation.metadata?.CWE && this.violation.metadata.CWE.length > 0) {
            return this.violation.metadata.CWE[0];
        }
        return null;
    }

    private getThemeColor(severity: SecuritySeverity): vscode.ThemeColor {
        switch (severity) {
            case SecuritySeverity.Critical:
            case SecuritySeverity.High:
                return new vscode.ThemeColor('errorForeground');
            case SecuritySeverity.Medium:
                return new vscode.ThemeColor('warningForeground');
            case SecuritySeverity.Low:
                return new vscode.ThemeColor('infoForeground');
            default:
                return new vscode.ThemeColor('foreground');
        }
    }
}

/**
 * Security Tree Data Provider
 */
export class SecurityTreeProvider implements vscode.TreeDataProvider<SecurityTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<SecurityTreeItem | undefined | null>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private workspaceSecurity: WorkspaceSecurityState;

    constructor() {
        // Initialize with empty state
        this.workspaceSecurity = {
            summary: {
                totalFiles: 0,
                totalViolations: 0,
                criticalCount: 0,
                highCount: 0,
                mediumCount: 0,
                lowCount: 0,
                infoCount: 0
            },
            critical: [],
            high: [],
            medium: [],
            low: [],
            info: []
        };
    }

    /**
     * Get tree item
     */
    getTreeItem(element: SecurityTreeItem): vscode.TreeItem {
        return element;
    }

    /**
     * Get children elements
     */
    async getChildren(element?: SecurityTreeItem): Promise<SecurityTreeItem[]> {
        if (!element) {
            // Root level - show summary and categories
            return [
                new SecuritySummaryItem(this.workspaceSecurity.summary),
                new SecurityCategoryItem('Critical Issues', 'critical', this.workspaceSecurity.critical),
                new SecurityCategoryItem('High Issues', 'high', this.workspaceSecurity.high),
                new SecurityCategoryItem('Medium Issues', 'medium', this.workspaceSecurity.medium),
                new SecurityCategoryItem('Low Issues', 'low', this.workspaceSecurity.low),
                new SecurityCategoryItem('Informational', 'info', this.workspaceSecurity.info)
            ];
        }

        if (element instanceof SecurityCategoryItem) {
            // Category level - show violations
            return element.violations.map(v => new SecurityViolationItem(v));
        }

        if (element instanceof SecuritySummaryItem) {
            // Summary breakdown
            const s = element.summary;
            return [
                this.createStatItem('Critical', s.criticalCount || 0, '🔴'),
                this.createStatItem('High', s.highCount || 0, '🟠'),
                this.createStatItem('Medium', s.mediumCount || 0, '🟡'),
                this.createStatItem('Low', s.lowCount || 0, '🔵'),
                this.createStatItem('Info', s.infoCount || 0, '⚪')
            ];
        }

        return [];
    }

    /**
     * Create a statistic item
     */
    private createStatItem(label: string, count: number, icon: string): SecurityTreeItem {
        const item = new SecurityTreeItem(
            `${icon} ${label}`,
            vscode.TreeItemCollapsibleState.None,
            'stat'
        );
        item.description = `${count}`;
        return item;
    }

    /**
     * Refresh the tree view
     */
    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }

    /**
     * Update workspace security state
     */
    updateWorkspaceSecurity(violations: SecurityViolation[]): void {
        // Categorize violations by severity
        const critical = violations.filter(v => v.severity === SecuritySeverity.Critical);
        const high = violations.filter(v => v.severity === SecuritySeverity.High);
        const medium = violations.filter(v => v.severity === SecuritySeverity.Medium);
        const low = violations.filter(v => v.severity === SecuritySeverity.Low);
        const info = violations.filter(v => 
            v.severity !== SecuritySeverity.Critical && 
            v.severity !== SecuritySeverity.High && 
            v.severity !== SecuritySeverity.Medium && 
            v.severity !== SecuritySeverity.Low
        );

        // Get unique file count
        const uniqueFiles = new Set(violations.map(v => v.filePath));

        // Update workspace security state
        this.workspaceSecurity = {
            summary: {
                totalFiles: uniqueFiles.size,
                totalViolations: violations.length,
                criticalCount: critical.length,
                highCount: high.length,
                mediumCount: medium.length,
                lowCount: low.length,
                infoCount: info.length,
                lastAnalysis: new Date()
            },
            critical,
            high,
            medium,
            low,
            info
        };

        // Refresh the tree
        this.refresh();
    }

    /**
     * Clear all violations
     */
    clearViolations(): void {
        this.workspaceSecurity = {
            summary: {
                totalFiles: 0,
                totalViolations: 0,
                criticalCount: 0,
                highCount: 0,
                mediumCount: 0,
                lowCount: 0,
                infoCount: 0
            },
            critical: [],
            high: [],
            medium: [],
            low: [],
            info: []
        };
        this.refresh();
    }
}
