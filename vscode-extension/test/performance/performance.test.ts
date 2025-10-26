/**
 * Basic tests for performance components
 * These are manual verification tests to ensure the components integrate correctly
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { IncrementalAnalyzer } from '../../src/performance/IncrementalAnalyzer';
import { CacheManager, CacheConfig } from '../../src/performance/CacheManager';
import { BackgroundAnalyzer } from '../../src/performance/BackgroundAnalyzer';
import { SecurityViolation } from '../../src/types';
import * as path from 'path';
import * as os from 'os';

suite('Performance Module Tests', () => {
    
    suite('IncrementalAnalyzer', () => {
        test('detects significant changes with function keyword', () => {
            const mockProvider: any = {
                analyzeDocument: async () => [],
                analyzeRange: async () => []
            };
            
            const analyzer = new IncrementalAnalyzer(mockProvider);
            
            const changes: vscode.TextDocumentContentChangeEvent[] = [
                {
                    range: new vscode.Range(0, 0, 0, 0),
                    rangeOffset: 0,
                    rangeLength: 0,
                    text: 'function Test-Function {'
                }
            ];
            
            const hasSignificant = (analyzer as any).hasSignificantChanges(changes);
            assert.strictEqual(hasSignificant, true, 'Should detect function as significant change');
        });
        
        test('detects insignificant changes for minor edits', () => {
            const mockProvider: any = {
                analyzeDocument: async () => [],
                analyzeRange: async () => []
            };
            
            const analyzer = new IncrementalAnalyzer(mockProvider);
            
            const changes: vscode.TextDocumentContentChangeEvent[] = [
                {
                    range: new vscode.Range(5, 0, 5, 10),
                    rangeOffset: 50,
                    rangeLength: 10,
                    text: 'Write-Host'
                }
            ];
            
            const hasSignificant = (analyzer as any).hasSignificantChanges(changes);
            assert.strictEqual(hasSignificant, false, 'Should not detect minor edit as significant');
        });
        
        test('merges overlapping ranges correctly', () => {
            const mockProvider: any = {
                analyzeDocument: async () => [],
                analyzeRange: async () => []
            };
            
            const analyzer = new IncrementalAnalyzer(mockProvider);
            
            const ranges = [
                new vscode.Range(5, 0, 10, 0),
                new vscode.Range(8, 0, 15, 0),
                new vscode.Range(20, 0, 25, 0)
            ];
            
            const merged = (analyzer as any).mergeOverlappingRanges(ranges);
            
            assert.strictEqual(merged.length, 2, 'Should merge overlapping ranges into 2 ranges');
            assert.strictEqual(merged[0].start.line, 5, 'First merged range should start at line 5');
            assert.strictEqual(merged[0].end.line, 15, 'First merged range should end at line 15');
            assert.strictEqual(merged[1].start.line, 20, 'Second range should start at line 20');
        });
        
        test('cache stats are tracked', () => {
            const mockProvider: any = {
                analyzeDocument: async () => [],
                analyzeRange: async () => []
            };
            
            const analyzer = new IncrementalAnalyzer(mockProvider);
            const stats = analyzer.getCacheStats();
            
            assert.strictEqual(typeof stats.documentCacheSize, 'number', 'Should have documentCacheSize');
            assert.strictEqual(typeof stats.astCacheSize, 'number', 'Should have astCacheSize');
        });
    });
    
    suite('CacheManager', () => {
        test('can be instantiated with config', () => {
            const config: CacheConfig = {
                maxMemorySize: 10 * 1024 * 1024, // 10MB
                diskCachePath: path.join(os.tmpdir(), 'test-cache'),
                ttl: 60 * 60 * 1000, // 1 hour
                enableDiskCache: true
            };
            
            const cacheManager = new CacheManager(config);
            assert.ok(cacheManager, 'CacheManager should be instantiated');
        });
        
        test('get returns null for non-existent key', async () => {
            const config: CacheConfig = {
                maxMemorySize: 10 * 1024 * 1024,
                diskCachePath: path.join(os.tmpdir(), 'test-cache-2'),
                ttl: 60 * 60 * 1000,
                enableDiskCache: false
            };
            
            const cacheManager = new CacheManager(config);
            const result = await cacheManager.get('non-existent-key');
            
            assert.strictEqual(result, null, 'Should return null for non-existent key');
        });
        
        test('set and get work correctly', async () => {
            const config: CacheConfig = {
                maxMemorySize: 10 * 1024 * 1024,
                diskCachePath: path.join(os.tmpdir(), 'test-cache-3'),
                ttl: 60 * 60 * 1000,
                enableDiskCache: false
            };
            
            const cacheManager = new CacheManager(config);
            
            const testViolations: SecurityViolation[] = [{
                name: 'TestRule',
                message: 'Test message',
                description: 'Test description',
                severity: 3,
                lineNumber: 10,
                code: 'test code',
                filePath: 'test.ps1',
                ruleId: 'TEST001'
            }];
            
            await cacheManager.set('test-key', testViolations);
            const result = await cacheManager.get('test-key');
            
            assert.ok(result, 'Should retrieve cached violations');
            assert.strictEqual(result!.length, 1, 'Should have 1 violation');
            assert.strictEqual(result![0].ruleId, 'TEST001', 'Should have correct rule ID');
        });
        
        test('cache statistics are tracked', async () => {
            const config: CacheConfig = {
                maxMemorySize: 10 * 1024 * 1024,
                diskCachePath: path.join(os.tmpdir(), 'test-cache-4'),
                ttl: 60 * 60 * 1000,
                enableDiskCache: false
            };
            
            const cacheManager = new CacheManager(config);
            
            // Perform some cache operations
            await cacheManager.get('test-key-1'); // Miss
            
            const stats = await cacheManager.getStats();
            
            assert.ok(stats, 'Should have statistics');
            assert.strictEqual(typeof stats.hitRate, 'number', 'Should have hit rate');
            assert.strictEqual(typeof stats.missRate, 'number', 'Should have miss rate');
            assert.strictEqual(stats.totalMisses, 1, 'Should have 1 miss');
        });
    });
    
    suite('BackgroundAnalyzer', () => {
        test('can be instantiated', () => {
            const analyzer = new BackgroundAnalyzer();
            assert.ok(analyzer, 'BackgroundAnalyzer should be instantiated');
        });
        
        test('queue stats are available', () => {
            const analyzer = new BackgroundAnalyzer();
            const stats = analyzer.getQueueStats();
            
            assert.strictEqual(typeof stats.queueSize, 'number', 'Should have queueSize');
            assert.strictEqual(typeof stats.pendingRequests, 'number', 'Should have pendingRequests');
            assert.strictEqual(typeof stats.isProcessing, 'boolean', 'Should have isProcessing flag');
            assert.strictEqual(stats.queueSize, 0, 'Initial queue should be empty');
        });
        
        test('can be disabled and enabled', () => {
            const analyzer = new BackgroundAnalyzer();
            
            analyzer.setEnabled(false);
            const stats1 = analyzer.getQueueStats();
            // After disabling, it should not break
            
            analyzer.setEnabled(true);
            const stats2 = analyzer.getQueueStats();
            
            assert.ok(true, 'Enable/disable should not throw errors');
        });
    });
});
