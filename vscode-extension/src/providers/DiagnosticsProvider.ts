/**
 * Security Diagnostics Provider
 * Provides rich VS Code diagnostics with CWE links and compliance information
 */

import * as vscode from 'vscode';
import { SecurityViolation, SecuritySeverity } from '../types';

export class SecurityDiagnosticsProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor(diagnosticCollection: vscode.DiagnosticCollection) {
        this.diagnosticCollection = diagnosticCollection;
    }

    /**
     * Update diagnostics for a document
     */
    updateDiagnostics(
        document: vscode.TextDocument,
        violations: SecurityViolation[]
    ): void {
        const diagnostics: vscode.Diagnostic[] = [];

        for (const violation of violations) {
            const diagnostic = this.createDiagnostic(violation);
            diagnostics.push(diagnostic);
        }

        this.diagnosticCollection.set(document.uri, diagnostics);
    }

    /**
     * Create a diagnostic from a security violation
     */
    private createDiagnostic(violation: SecurityViolation): vscode.Diagnostic {
        // Create range (convert from 1-indexed to 0-indexed)
        const line = Math.max(0, violation.lineNumber - 1);
        const startChar = violation.columnNumber || 0;
        const endChar = violation.endColumn || 100;

        const range = new vscode.Range(
            new vscode.Position(line, startChar),
            new vscode.Position(line, endChar)
        );

        // Format diagnostic message
        const message = this.formatDiagnosticMessage(violation);

        // Map severity
        const severity = this.mapSeverity(violation.severity);

        // Create diagnostic
        const diagnostic = new vscode.Diagnostic(range, message, severity);

        // Enhanced diagnostic properties
        diagnostic.source = 'PowerShield';
        
        // Add CWE link if available
        const cweId = this.extractCWEId(violation);
        if (cweId) {
            diagnostic.code = {
                value: violation.ruleId,
                target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${cweId}.html`)
            };
        } else {
            diagnostic.code = violation.ruleId;
        }

        // Add diagnostic tags
        diagnostic.tags = this.getDiagnosticTags(violation);

        // Add related information
        diagnostic.relatedInformation = this.getRelatedInformation(violation);

        return diagnostic;
    }

    /**
     * Format diagnostic message with severity and CWE info
     */
    private formatDiagnosticMessage(violation: SecurityViolation): string {
        const severityName = SecuritySeverity[violation.severity]?.toUpperCase() || 'UNKNOWN';
        const cweInfo = this.extractCWEId(violation) ? ` (CWE-${this.extractCWEId(violation)})` : '';
        
        return `[${severityName}] ${violation.description || violation.message}${cweInfo}`;
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

    /**
     * Get diagnostic tags for a violation
     */
    private getDiagnosticTags(violation: SecurityViolation): vscode.DiagnosticTag[] {
        const tags: vscode.DiagnosticTag[] = [];

        if (violation.deprecated) {
            tags.push(vscode.DiagnosticTag.Deprecated);
        }

        if (violation.confidence !== undefined && violation.confidence < 0.8) {
            tags.push(vscode.DiagnosticTag.Unnecessary);
        }

        return tags;
    }

    /**
     * Get related information for a violation
     */
    private getRelatedInformation(violation: SecurityViolation): vscode.DiagnosticRelatedInformation[] | undefined {
        const relatedInfo: vscode.DiagnosticRelatedInformation[] = [];

        // Add compliance information
        if (violation.compliance && violation.compliance.length > 0) {
            const complianceText = `Compliance standards: ${violation.compliance.join(', ')}`;
            const location = new vscode.Location(
                vscode.Uri.file(violation.filePath),
                new vscode.Position(Math.max(0, violation.lineNumber - 1), 0)
            );
            relatedInfo.push(
                new vscode.DiagnosticRelatedInformation(location, complianceText)
            );
        }

        // Add MITRE ATT&CK information
        if (violation.metadata?.MitreAttack && violation.metadata.MitreAttack.length > 0) {
            const mitreText = `MITRE ATT&CK: ${violation.metadata.MitreAttack.join(', ')}`;
            const location = new vscode.Location(
                vscode.Uri.file(violation.filePath),
                new vscode.Position(Math.max(0, violation.lineNumber - 1), 0)
            );
            relatedInfo.push(
                new vscode.DiagnosticRelatedInformation(location, mitreText)
            );
        }

        // Add OWASP information
        if (violation.metadata?.OWASP && violation.metadata.OWASP.length > 0) {
            const owaspText = `OWASP: ${violation.metadata.OWASP.join(', ')}`;
            const location = new vscode.Location(
                vscode.Uri.file(violation.filePath),
                new vscode.Position(Math.max(0, violation.lineNumber - 1), 0)
            );
            relatedInfo.push(
                new vscode.DiagnosticRelatedInformation(location, owaspText)
            );
        }

        return relatedInfo.length > 0 ? relatedInfo : undefined;
    }

    /**
     * Map PowerShield severity to VS Code severity
     */
    private mapSeverity(severity: SecuritySeverity): vscode.DiagnosticSeverity {
        switch (severity) {
            case SecuritySeverity.Critical:
                return vscode.DiagnosticSeverity.Error;
            case SecuritySeverity.High:
                return vscode.DiagnosticSeverity.Error;
            case SecuritySeverity.Medium:
                return vscode.DiagnosticSeverity.Warning;
            case SecuritySeverity.Low:
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    /**
     * Clear diagnostics for a document
     */
    clearDiagnostics(uri: vscode.Uri): void {
        this.diagnosticCollection.delete(uri);
    }

    /**
     * Clear all diagnostics
     */
    clearAll(): void {
        this.diagnosticCollection.clear();
    }
}
