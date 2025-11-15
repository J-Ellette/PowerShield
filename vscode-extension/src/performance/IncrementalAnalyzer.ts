/**
 * Incremental Analysis System
 * Provides high-performance analysis by caching and analyzing only changed ranges
 */

import * as vscode from 'vscode';
import { SecurityViolation } from '../types';
import { PSSecurityProvider } from '../providers/SecurityProvider';

/**
 * Cache entry for document analysis
 */
export interface DocumentAnalysisCache {
    violations: SecurityViolation[];
    timestamp: number;
    documentVersion: number;
    contentHash: string;
}

/**
 * Parsed AST cache entry (placeholder for future PowerShell AST integration)
 */
export interface ParsedAST {
    documentVersion: number;
    timestamp: number;
    // Future: Add actual AST structure when PowerShell AST parsing is integrated
}

/**
 * Incremental analyzer that optimizes performance by analyzing only changed ranges
 */
export class IncrementalAnalyzer {
    private documentCache: Map<string, DocumentAnalysisCache> = new Map();
    private astCache: Map<string, ParsedAST> = new Map();
    private securityProvider: PSSecurityProvider;
    private enabled: boolean = true;

    constructor(securityProvider: PSSecurityProvider) {
        this.securityProvider = securityProvider;
    }

    /**
     * Enable or disable incremental analysis
     */
    setEnabled(enabled: boolean): void {
        this.enabled = enabled;
    }

    /**
     * Analyze document incrementally based on changes
     */
    async analyzeIncremental(
        document: vscode.TextDocument,
        changes: vscode.TextDocumentContentChangeEvent[]
    ): Promise<SecurityViolation[]> {
        if (!this.enabled) {
            return this.performFullAnalysis(document);
        }

        const documentKey = document.uri.toString();
        const cached = this.documentCache.get(documentKey);

        // If no cache or significant changes, perform full analysis
        if (!cached || this.hasSignificantChanges(changes)) {
            return this.performFullAnalysis(document);
        }

        // Check if document version changed significantly
        if (Math.abs(document.version - cached.documentVersion) > 1) {
            return this.performFullAnalysis(document);
        }

        // Incremental analysis - analyze affected ranges
        const affectedRanges = this.getAffectedRanges(changes, document);
        const newViolations: SecurityViolation[] = [];

        for (const range of affectedRanges) {
            const rangeViolations = await this.analyzeRange(document, range);
            newViolations.push(...rangeViolations);
        }

        // Merge with cached violations
        const mergedViolations = this.mergeViolations(
            cached.violations,
            newViolations,
            affectedRanges
        );

        // Update cache
        this.updateCache(document, mergedViolations);

        return mergedViolations;
    }

    /**
     * Perform full document analysis
     */
    private async performFullAnalysis(document: vscode.TextDocument): Promise<SecurityViolation[]> {
        const violations = await this.securityProvider.analyzeDocument(document);
        this.updateCache(document, violations);
        return violations;
    }

    /**
     * Analyze a specific range in the document
     */
    private async analyzeRange(
        document: vscode.TextDocument,
        range: vscode.Range
    ): Promise<SecurityViolation[]> {
        // Use security provider's range analysis
        return await this.securityProvider.analyzeRange(document, range);
    }

    /**
     * Detect if changes are significant enough to require full re-analysis
     */
    private hasSignificantChanges(changes: vscode.TextDocumentContentChangeEvent[]): boolean {
        return changes.some(change => {
            const text = change.text;
            
            // Keywords that indicate structural changes
            if (text.includes('function') ||
                text.includes('param') ||
                text.includes('Import-Module') ||
                text.includes('class') ||
                text.includes('workflow')) {
                return true;
            }

            // Large deletions
            if (change.rangeLength > 100) {
                return true;
            }

            // Multiple line changes
            const lineCount = (text.match(/\n/g) || []).length;
            if (lineCount > 10) {
                return true;
            }

            return false;
        });
    }

    /**
     * Get affected ranges from document changes
     */
    private getAffectedRanges(
        changes: vscode.TextDocumentContentChangeEvent[],
        document: vscode.TextDocument
    ): vscode.Range[] {
        const ranges: vscode.Range[] = [];

        for (const change of changes) {
            if (change.range) {
                // Expand range to include context (5 lines before and after)
                const startLine = Math.max(0, change.range.start.line - 5);
                const endLine = Math.min(
                    document.lineCount - 1,
                    change.range.end.line + 5
                );

                const expandedRange = new vscode.Range(
                    new vscode.Position(startLine, 0),
                    new vscode.Position(endLine, document.lineAt(endLine).text.length)
                );

                ranges.push(expandedRange);
            }
        }

        // Merge overlapping ranges
        return this.mergeOverlappingRanges(ranges);
    }

    /**
     * Merge overlapping ranges
     */
    private mergeOverlappingRanges(ranges: vscode.Range[]): vscode.Range[] {
        if (ranges.length === 0) {
            return [];
        }

        // Sort ranges by start position
        const sortedRanges = ranges.sort((a, b) => {
            return a.start.line - b.start.line;
        });

        const merged: vscode.Range[] = [sortedRanges[0]];

        for (let i = 1; i < sortedRanges.length; i++) {
            const current = sortedRanges[i];
            const last = merged[merged.length - 1];

            // Check if ranges overlap
            if (current.start.line <= last.end.line + 1) {
                // Merge ranges
                merged[merged.length - 1] = new vscode.Range(
                    last.start,
                    current.end.line > last.end.line ? current.end : last.end
                );
            } else {
                merged.push(current);
            }
        }

        return merged;
    }

    /**
     * Merge new violations with cached violations, removing outdated ones
     */
    private mergeViolations(
        cachedViolations: SecurityViolation[],
        newViolations: SecurityViolation[],
        affectedRanges: vscode.Range[]
    ): SecurityViolation[] {
        // Remove violations in affected ranges
        const unaffectedViolations = cachedViolations.filter(violation => {
            const violationLine = violation.lineNumber - 1; // Convert to 0-indexed
            
            return !affectedRanges.some(range => {
                return violationLine >= range.start.line &&
                       violationLine <= range.end.line;
            });
        });

        // Combine with new violations
        return [...unaffectedViolations, ...newViolations];
    }

    /**
     * Update cache with latest analysis results
     */
    private updateCache(document: vscode.TextDocument, violations: SecurityViolation[]): void {
        const documentKey = document.uri.toString();
        const content = document.getText();
        
        // Generate content hash (simple hash for now)
        const contentHash = this.simpleHash(content);

        const cache: DocumentAnalysisCache = {
            violations,
            timestamp: Date.now(),
            documentVersion: document.version,
            contentHash
        };

        this.documentCache.set(documentKey, cache);
    }

    /**
     * Simple hash function for content
     */
    private simpleHash(text: string): string {
        let hash = 0;
        for (let i = 0; i < text.length; i++) {
            const char = text.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString(36);
    }

    /**
     * Invalidate cache for a document
     */
    invalidateCache(document: vscode.TextDocument): void {
        const documentKey = document.uri.toString();
        this.documentCache.delete(documentKey);
        this.astCache.delete(documentKey);
    }

    /**
     * Clear all caches
     */
    clearAllCaches(): void {
        this.documentCache.clear();
        this.astCache.clear();
    }

    /**
     * Get cache statistics
     */
    getCacheStats(): { documentCacheSize: number; astCacheSize: number } {
        return {
            documentCacheSize: this.documentCache.size,
            astCacheSize: this.astCache.size
        };
    }
}
