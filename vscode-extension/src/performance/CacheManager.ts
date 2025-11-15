/**
 * Multi-Level Cache Manager
 * Provides memory and disk caching for analysis results
 */

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { SecurityViolation } from '../types';

/**
 * Cache entry with metadata
 */
export interface CacheEntry {
    violations: SecurityViolation[];
    timestamp: number;
    lastAccessed: number;
    size: number; // Approximate size in bytes
}

/**
 * Cache configuration
 */
export interface CacheConfig {
    maxMemorySize: number; // In bytes
    diskCachePath: string;
    ttl: number; // Time to live in milliseconds
    enableDiskCache: boolean;
}

/**
 * Cache statistics
 */
export interface CacheStats {
    memorySize: number;
    memoryEntries: number;
    diskEntries: number;
    hitRate: number;
    missRate: number;
    totalHits: number;
    totalMisses: number;
}

/**
 * Multi-level cache manager
 */
export class CacheManager {
    private memoryCache: Map<string, CacheEntry> = new Map();
    private diskCache: DiskCache;
    private readonly maxMemorySize: number;
    private currentMemorySize: number = 0;
    private config: CacheConfig;
    private stats = {
        hits: 0,
        misses: 0
    };

    constructor(config: CacheConfig) {
        this.config = config;
        this.maxMemorySize = config.maxMemorySize;
        this.diskCache = new DiskCache(config.diskCachePath, config.enableDiskCache);
    }

    /**
     * Get cached violations
     */
    async get(key: string): Promise<SecurityViolation[] | null> {
        // Try memory cache first
        const memoryEntry = this.memoryCache.get(key);
        if (memoryEntry && !this.isExpired(memoryEntry)) {
            memoryEntry.lastAccessed = Date.now();
            this.stats.hits++;
            return memoryEntry.violations;
        }

        // Try disk cache
        if (this.config.enableDiskCache) {
            const diskEntry = await this.diskCache.get(key);
            if (diskEntry && !this.isExpired(diskEntry)) {
                // Promote to memory cache
                this.setMemoryCache(key, diskEntry.violations);
                this.stats.hits++;
                return diskEntry.violations;
            }
        }

        this.stats.misses++;
        return null;
    }

    /**
     * Set cache entry
     */
    async set(key: string, violations: SecurityViolation[]): Promise<void> {
        // Always update memory cache
        this.setMemoryCache(key, violations);

        // Asynchronously update disk cache
        if (this.config.enableDiskCache) {
            setImmediate(async () => {
                await this.diskCache.set(key, violations);
            });
        }
    }

    /**
     * Set memory cache entry
     */
    private setMemoryCache(key: string, violations: SecurityViolation[]): void {
        // Calculate approximate size
        const size = this.estimateSize(violations);

        // Implement LRU eviction if needed
        while (this.currentMemorySize + size > this.maxMemorySize && this.memoryCache.size > 0) {
            this.evictLeastRecentlyUsed();
        }

        const entry: CacheEntry = {
            violations,
            timestamp: Date.now(),
            lastAccessed: Date.now(),
            size
        };

        // Remove old entry if exists
        const oldEntry = this.memoryCache.get(key);
        if (oldEntry) {
            this.currentMemorySize -= oldEntry.size;
        }

        this.memoryCache.set(key, entry);
        this.currentMemorySize += size;
    }

    /**
     * Check if cache entry is expired
     */
    private isExpired(entry: CacheEntry): boolean {
        const now = Date.now();
        return (now - entry.timestamp) > this.config.ttl;
    }

    /**
     * Evict least recently used entry
     */
    private evictLeastRecentlyUsed(): void {
        let oldestKey: string | null = null;
        let oldestTime = Date.now();

        for (const [key, entry] of this.memoryCache.entries()) {
            if (entry.lastAccessed < oldestTime) {
                oldestTime = entry.lastAccessed;
                oldestKey = key;
            }
        }

        if (oldestKey) {
            const entry = this.memoryCache.get(oldestKey);
            if (entry) {
                this.currentMemorySize -= entry.size;
            }
            this.memoryCache.delete(oldestKey);
        }
    }

    /**
     * Estimate size of violations in bytes
     */
    private estimateSize(violations: SecurityViolation[]): number {
        // Rough estimate: ~500 bytes per violation
        return violations.length * 500;
    }

    /**
     * Get current memory usage
     */
    private getMemoryUsage(): number {
        return this.currentMemorySize;
    }

    /**
     * Clear all caches
     */
    async clear(): Promise<void> {
        this.memoryCache.clear();
        this.currentMemorySize = 0;
        await this.diskCache.clear();
    }

    /**
     * Invalidate cache entry
     */
    async invalidate(key: string): Promise<void> {
        const entry = this.memoryCache.get(key);
        if (entry) {
            this.currentMemorySize -= entry.size;
        }
        this.memoryCache.delete(key);
        await this.diskCache.invalidate(key);
    }

    /**
     * Get cache statistics
     */
    async getStats(): Promise<CacheStats> {
        const diskEntries = await this.diskCache.getEntryCount();
        const total = this.stats.hits + this.stats.misses;
        
        return {
            memorySize: this.currentMemorySize,
            memoryEntries: this.memoryCache.size,
            diskEntries,
            hitRate: total > 0 ? this.stats.hits / total : 0,
            missRate: total > 0 ? this.stats.misses / total : 0,
            totalHits: this.stats.hits,
            totalMisses: this.stats.misses
        };
    }

    /**
     * Reset statistics
     */
    resetStats(): void {
        this.stats.hits = 0;
        this.stats.misses = 0;
    }

    /**
     * Dispose resources
     */
    async dispose(): Promise<void> {
        await this.clear();
    }
}

/**
 * Disk cache implementation
 */
class DiskCache {
    private cachePath: string;
    private enabled: boolean;
    private cacheIndex: Map<string, string> = new Map(); // key -> filename

    constructor(cachePath: string, enabled: boolean) {
        this.cachePath = cachePath;
        this.enabled = enabled;

        if (this.enabled) {
            this.initializeCacheDirectory();
            this.loadCacheIndex();
        }
    }

    /**
     * Initialize cache directory
     */
    private initializeCacheDirectory(): void {
        try {
            if (!fs.existsSync(this.cachePath)) {
                fs.mkdirSync(this.cachePath, { recursive: true });
            }
        } catch (error) {
            console.error('Failed to initialize disk cache:', error);
            this.enabled = false;
        }
    }

    /**
     * Load cache index from disk
     */
    private loadCacheIndex(): void {
        try {
            const indexPath = path.join(this.cachePath, 'index.json');
            if (fs.existsSync(indexPath)) {
                const indexData = fs.readFileSync(indexPath, 'utf-8');
                const index = JSON.parse(indexData);
                this.cacheIndex = new Map(Object.entries(index));
            }
        } catch (error) {
            console.error('Failed to load cache index:', error);
            this.cacheIndex = new Map();
        }
    }

    /**
     * Save cache index to disk
     */
    private saveCacheIndex(): void {
        try {
            const indexPath = path.join(this.cachePath, 'index.json');
            const indexData = Object.fromEntries(this.cacheIndex);
            fs.writeFileSync(indexPath, JSON.stringify(indexData, null, 2));
        } catch (error) {
            console.error('Failed to save cache index:', error);
        }
    }

    /**
     * Get cache entry from disk
     */
    async get(key: string): Promise<CacheEntry | null> {
        if (!this.enabled) {
            return null;
        }

        try {
            const filename = this.cacheIndex.get(key);
            if (!filename) {
                return null;
            }

            const filePath = path.join(this.cachePath, filename);
            if (!fs.existsSync(filePath)) {
                this.cacheIndex.delete(key);
                return null;
            }

            const data = fs.readFileSync(filePath, 'utf-8');
            const entry = JSON.parse(data);
            return entry;
        } catch (error) {
            console.error('Failed to read disk cache:', error);
            return null;
        }
    }

    /**
     * Set cache entry on disk
     */
    async set(key: string, violations: SecurityViolation[]): Promise<void> {
        if (!this.enabled) {
            return;
        }

        try {
            const filename = this.generateFilename(key);
            const filePath = path.join(this.cachePath, filename);

            const entry: CacheEntry = {
                violations,
                timestamp: Date.now(),
                lastAccessed: Date.now(),
                size: violations.length * 500
            };

            fs.writeFileSync(filePath, JSON.stringify(entry, null, 2));
            
            this.cacheIndex.set(key, filename);
            this.saveCacheIndex();
        } catch (error) {
            console.error('Failed to write disk cache:', error);
        }
    }

    /**
     * Generate filename from cache key
     */
    private generateFilename(key: string): string {
        const hash = crypto.createHash('md5').update(key).digest('hex');
        return `${hash}.json`;
    }

    /**
     * Invalidate cache entry
     */
    async invalidate(key: string): Promise<void> {
        if (!this.enabled) {
            return;
        }

        try {
            const filename = this.cacheIndex.get(key);
            if (filename) {
                const filePath = path.join(this.cachePath, filename);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
                this.cacheIndex.delete(key);
                this.saveCacheIndex();
            }
        } catch (error) {
            console.error('Failed to invalidate disk cache:', error);
        }
    }

    /**
     * Clear all disk cache
     */
    async clear(): Promise<void> {
        if (!this.enabled) {
            return;
        }

        try {
            const files = fs.readdirSync(this.cachePath);
            for (const file of files) {
                if (file !== 'index.json') {
                    const filePath = path.join(this.cachePath, file);
                    fs.unlinkSync(filePath);
                }
            }
            this.cacheIndex.clear();
            this.saveCacheIndex();
        } catch (error) {
            console.error('Failed to clear disk cache:', error);
        }
    }

    /**
     * Get number of entries in disk cache
     */
    async getEntryCount(): Promise<number> {
        return this.cacheIndex.size;
    }
}
