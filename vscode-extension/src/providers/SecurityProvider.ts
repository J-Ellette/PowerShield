/**
 * PowerShell Security Provider
 * Provides document analysis with caching
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { PowerShieldEngine } from '../core/PowerShieldEngine';
import {
    SecurityViolation,
    AnalysisResult,
    CacheEntry
} from '../types';

export class PSSecurityProvider {
    private analysisCache: Map<string, CacheEntry> = new Map();
    private powerShieldEngine: PowerShieldEngine;
    private maxCacheSize: number = 100; // Max number of cached results
    private cacheEnabled: boolean = true;

    constructor(engine: PowerShieldEngine) {
        this.powerShieldEngine = engine;
        this.updateCacheSettings();
    }

    /**
     * Update cache settings from configuration
     */
    updateCacheSettings(): void {
        const config = this.powerShieldEngine.getConfiguration();
        this.cacheEnabled = config.performance.enableCaching;
        
        // Parse max cache size (e.g., "100MB")
        const maxSize = config.performance.maxCacheSize;
        const match = maxSize.match(/(\d+)\s*(MB|GB)?/i);
        if (match) {
            const size = parseInt(match[1]);
            const unit = match[2]?.toUpperCase() || 'MB';
            // Estimate ~1KB per cached entry, so 100MB = 100,000 entries
            this.maxCacheSize = unit === 'GB' ? size * 1000000 : size * 1000;
        }
    }

    /**
     * Analyze a document
     */
    async analyzeDocument(document: vscode.TextDocument): Promise<SecurityViolation[]> {
        const content = document.getText();
        const cacheKey = this.generateCacheKey(content);
        
        // Check cache if enabled
        if (this.cacheEnabled && this.analysisCache.has(cacheKey)) {
            const cached = this.analysisCache.get(cacheKey)!;
            cached.lastAccessed = Date.now();
            return cached.violations;
        }
        
        // Perform analysis using PowerShield engine
        const result = await this.powerShieldEngine.analyzeScript(
            document.fileName,
            content
        );
        
        // Cache results
        if (this.cacheEnabled) {
            this.cacheResult(cacheKey, result.violations, content);
        }
        
        return result.violations;
    }

    /**
     * Analyze a specific range in a document (for incremental analysis)
     */
    async analyzeRange(
        document: vscode.TextDocument,
        range: vscode.Range
    ): Promise<SecurityViolation[]> {
        // For now, analyze the entire document
        // Future: Implement true incremental analysis
        const violations = await this.analyzeDocument(document);
        
        // Filter violations to only those in the specified range
        return violations.filter(v => {
            const violationLine = v.lineNumber - 1; // Convert to 0-indexed
            return violationLine >= range.start.line && violationLine <= range.end.line;
        });
    }

    /**
     * Generate cache key from content
     */
    private generateCacheKey(content: string): string {
        return crypto.createHash('sha256').update(content).digest('hex');
    }

    /**
     * Cache analysis result
     */
    private cacheResult(cacheKey: string, violations: SecurityViolation[], content: string): void {
        // Enforce cache size limit
        if (this.analysisCache.size >= this.maxCacheSize) {
            this.evictLeastRecentlyUsed();
        }
        
        const entry: CacheEntry = {
            violations,
            timestamp: Date.now(),
            lastAccessed: Date.now(),
            contentHash: cacheKey
        };
        
        this.analysisCache.set(cacheKey, entry);
    }

    /**
     * Evict least recently used cache entries
     */
    private evictLeastRecentlyUsed(): void {
        // Find the entry with oldest lastAccessed time
        let oldestKey: string | null = null;
        let oldestTime = Date.now();
        
        for (const [key, entry] of this.analysisCache.entries()) {
            if (entry.lastAccessed < oldestTime) {
                oldestTime = entry.lastAccessed;
                oldestKey = key;
            }
        }
        
        if (oldestKey) {
            this.analysisCache.delete(oldestKey);
        }
    }

    /**
     * Clear the cache
     */
    clearCache(): void {
        this.analysisCache.clear();
    }

    /**
     * Get cache statistics
     */
    getCacheStats(): { size: number; maxSize: number; hitRate?: number } {
        return {
            size: this.analysisCache.size,
            maxSize: this.maxCacheSize
        };
    }

    /**
     * Invalidate cache for a specific document
     */
    invalidateDocument(document: vscode.TextDocument): void {
        const content = document.getText();
        const cacheKey = this.generateCacheKey(content);
        this.analysisCache.delete(cacheKey);
    }
}
