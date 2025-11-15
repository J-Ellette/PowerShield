/**
 * Security Hover Provider
 * Provides rich hover information with educational content
 */

import * as vscode from 'vscode';
import { SecurityViolation, SecuritySeverity } from '../types';

export class SecurityHoverProvider implements vscode.HoverProvider {
    private violations: Map<string, SecurityViolation[]> = new Map();

    /**
     * Update violations for a document
     */
    updateViolations(document: vscode.TextDocument, violations: SecurityViolation[]): void {
        this.violations.set(document.uri.toString(), violations);
    }

    /**
     * Clear violations for a document
     */
    clearViolations(uri: vscode.Uri): void {
        this.violations.delete(uri.toString());
    }

    /**
     * Provide hover information
     */
    async provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): Promise<vscode.Hover | undefined> {
        const violation = await this.getViolationAtPosition(document, position);

        if (!violation) {
            return undefined;
        }

        const hoverContent = this.createHoverContent(violation, document);
        return new vscode.Hover(hoverContent);
    }

    /**
     * Get violation at a specific position
     */
    private async getViolationAtPosition(
        document: vscode.TextDocument,
        position: vscode.Position
    ): Promise<SecurityViolation | undefined> {
        const violations = this.violations.get(document.uri.toString());
        if (!violations) {
            return undefined;
        }

        // Find violation at the current position
        return violations.find(v => {
            const line = Math.max(0, v.lineNumber - 1);
            return line === position.line;
        });
    }

    /**
     * Create hover content for a violation
     */
    private createHoverContent(
        violation: SecurityViolation,
        document: vscode.TextDocument
    ): vscode.MarkdownString {
        const hoverContent = new vscode.MarkdownString();
        hoverContent.isTrusted = true;
        hoverContent.supportHtml = true;

        // Security issue header
        const title = violation.ruleTitle || violation.name || violation.ruleId;
        hoverContent.appendMarkdown(`## 🛡️ ${title}\n\n`);

        // Severity badge
        const severityBadge = this.getSeverityBadge(violation.severity);
        const severityName = SecuritySeverity[violation.severity] || 'Unknown';
        hoverContent.appendMarkdown(`${severityBadge} **Severity:** ${severityName}\n\n`);

        // Description and explanation
        const description = violation.description || violation.message;
        hoverContent.appendMarkdown(`**Issue:** ${description}\n\n`);

        if (violation.explanation) {
            hoverContent.appendMarkdown(`**Why this matters:** ${violation.explanation}\n\n`);
        }

        // CWE and compliance information
        const cweId = this.extractCWEId(violation);
        if (cweId) {
            hoverContent.appendMarkdown(
                `**CWE:** [CWE-${cweId}](https://cwe.mitre.org/data/definitions/${cweId}.html)\n`
            );
        }

        if (violation.compliance && violation.compliance.length > 0) {
            hoverContent.appendMarkdown(`**Compliance:** ${violation.compliance.join(', ')}\n\n`);
        }

        // MITRE ATT&CK information
        if (violation.metadata?.MitreAttack && violation.metadata.MitreAttack.length > 0) {
            hoverContent.appendMarkdown(`**MITRE ATT&CK:** ${violation.metadata.MitreAttack.join(', ')}\n\n`);
        }

        // OWASP information
        if (violation.metadata?.OWASP && violation.metadata.OWASP.length > 0) {
            hoverContent.appendMarkdown(`**OWASP:** ${violation.metadata.OWASP.join(', ')}\n\n`);
        }

        // Quick fix preview
        if (violation.hasQuickFix || violation.fixes?.length) {
            hoverContent.appendMarkdown(`### 🔧 Quick Fix Available\n`);
            const fixPreview = violation.fixPreview || (violation.fixes?.[0]?.fixedCode) || "// Fix will be generated...";
            hoverContent.appendCodeblock(fixPreview, 'powershell');
            hoverContent.appendMarkdown('\n');
        }

        // Best practices and learning resources
        if (violation.bestPractices && violation.bestPractices.length > 0) {
            hoverContent.appendMarkdown(`### 📚 Best Practices\n`);
            for (const practice of violation.bestPractices) {
                hoverContent.appendMarkdown(`- ${practice}\n`);
            }
            hoverContent.appendMarkdown('\n');
        }

        // Action commands
        hoverContent.appendMarkdown(`---\n`);
        
        // Encode arguments for commands
        const fixArgs = JSON.stringify([document.uri.toString(), violation]);
        const docArgs = JSON.stringify([violation.ruleId]);
        const suppressArgs = JSON.stringify([document.uri.toString(), violation]);

        hoverContent.appendMarkdown(
            `[🤖 Generate AI Fix](command:powershield.generateAIFix?${encodeURIComponent(fixArgs)}) | `
        );
        hoverContent.appendMarkdown(
            `[📖 Learn More](command:powershield.openDocumentation?${encodeURIComponent(docArgs)}) | `
        );
        hoverContent.appendMarkdown(
            `[🙈 Suppress](command:powershield.suppressViolation?${encodeURIComponent(suppressArgs)})`
        );

        return hoverContent;
    }

    /**
     * Get severity badge emoji
     */
    private getSeverityBadge(severity: SecuritySeverity): string {
        switch (severity) {
            case SecuritySeverity.Critical:
                return '🔴';
            case SecuritySeverity.High:
                return '🟠';
            case SecuritySeverity.Medium:
                return '🟡';
            case SecuritySeverity.Low:
                return '🔵';
            default:
                return '⚪';
        }
    }

    /**
     * Extract CWE ID from violation
     */
    private extractCWEId(violation: SecurityViolation): string | null {
        // Check direct cweId property
        if (violation.cweId) {
            return violation.cweId.replace('CWE-', '');
        }

        // Check metadata.CWE array
        if (violation.metadata?.CWE && violation.metadata.CWE.length > 0) {
            return violation.metadata.CWE[0].replace('CWE-', '');
        }

        return null;
    }
}
