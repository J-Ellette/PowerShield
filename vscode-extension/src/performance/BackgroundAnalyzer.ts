/**
 * Background Analysis System
 * Uses worker threads for non-blocking analysis
 */

import * as vscode from 'vscode';
import { Worker } from 'worker_threads';
import * as path from 'path';
import { SecurityViolation } from '../types';

/**
 * Analysis request for background processing
 */
export interface AnalysisRequest {
    id: string;
    content: string;
    fileName: string;
    enabledRules: string[];
    resolve?: (violations: SecurityViolation[]) => void;
    reject?: (error: Error) => void;
}

/**
 * Worker message types
 */
interface WorkerMessage {
    type: 'analyze' | 'complete' | 'error' | 'ready';
    requestId?: string;
    data?: any;
    error?: string;
}

/**
 * Background analyzer using worker threads
 */
export class BackgroundAnalyzer {
    private worker: Worker | null = null;
    private analysisQueue: AnalysisRequest[] = [];
    private isProcessing: boolean = false;
    private pendingRequests: Map<string, AnalysisRequest> = new Map();
    private workerReady: boolean = false;
    private enabled: boolean = true;
    private maxQueueSize: number = 50;

    constructor() {
        // Worker will be initialized lazily
    }

    /**
     * Initialize the worker thread
     */
    private async initializeWorker(): Promise<void> {
        if (this.worker) {
            return;
        }

        try {
            // Path to the worker script
            const workerPath = path.join(__dirname, 'analysis-worker.js');
            
            this.worker = new Worker(workerPath);
            this.setupWorkerMessageHandling();
            
            // Wait for worker to be ready
            await this.waitForWorkerReady();
        } catch (error) {
            console.error('Failed to initialize worker:', error);
            // Fallback: disable background processing
            this.enabled = false;
            this.worker = null;
        }
    }

    /**
     * Setup worker message handling
     */
    private setupWorkerMessageHandling(): void {
        if (!this.worker) {
            return;
        }

        this.worker.on('message', (message: WorkerMessage) => {
            this.handleWorkerMessage(message);
        });

        this.worker.on('error', (error: Error) => {
            console.error('Worker error:', error);
            
            // Reject all pending requests
            for (const [requestId, request] of this.pendingRequests) {
                if (request.reject) {
                    request.reject(error);
                }
            }
            this.pendingRequests.clear();
            
            // Try to reinitialize worker
            this.worker = null;
            this.workerReady = false;
        });

        this.worker.on('exit', (code: number) => {
            if (code !== 0) {
                console.error(`Worker stopped with exit code ${code}`);
            }
            this.worker = null;
            this.workerReady = false;
        });
    }

    /**
     * Wait for worker to be ready
     */
    private waitForWorkerReady(): Promise<void> {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Error('Worker initialization timeout'));
            }, 5000);

            const checkReady = (message: WorkerMessage) => {
                if (message.type === 'ready') {
                    clearTimeout(timeout);
                    this.workerReady = true;
                    this.worker?.off('message', checkReady);
                    resolve();
                }
            };

            this.worker?.on('message', checkReady);
        });
    }

    /**
     * Handle messages from worker
     */
    private handleWorkerMessage(message: WorkerMessage): void {
        switch (message.type) {
            case 'ready':
                this.workerReady = true;
                break;

            case 'complete':
                if (message.requestId) {
                    const request = this.pendingRequests.get(message.requestId);
                    if (request && request.resolve) {
                        request.resolve(message.data || []);
                    }
                    this.pendingRequests.delete(message.requestId);
                }
                break;

            case 'error':
                if (message.requestId) {
                    const request = this.pendingRequests.get(message.requestId);
                    if (request && request.reject) {
                        request.reject(new Error(message.error || 'Analysis failed'));
                    }
                    this.pendingRequests.delete(message.requestId);
                }
                break;
        }
    }

    /**
     * Enable or disable background processing
     */
    setEnabled(enabled: boolean): void {
        this.enabled = enabled;
        if (!enabled) {
            this.dispose();
        }
    }

    /**
     * Queue an analysis request
     */
    async queueAnalysis(request: AnalysisRequest): Promise<SecurityViolation[]> {
        // If background processing is disabled, return empty result
        // (caller should use synchronous analysis)
        if (!this.enabled) {
            throw new Error('Background processing is disabled');
        }

        // Initialize worker if needed
        if (!this.worker) {
            await this.initializeWorker();
        }

        // If worker failed to initialize, throw error
        if (!this.worker || !this.workerReady) {
            throw new Error('Worker not available');
        }

        return new Promise((resolve, reject) => {
            // Check queue size limit
            if (this.analysisQueue.length >= this.maxQueueSize) {
                reject(new Error('Analysis queue is full'));
                return;
            }

            request.resolve = resolve;
            request.reject = reject;

            this.analysisQueue.push(request);
            this.processQueue();
        });
    }

    /**
     * Process the analysis queue
     */
    private async processQueue(): Promise<void> {
        if (this.isProcessing || this.analysisQueue.length === 0 || !this.worker || !this.workerReady) {
            return;
        }

        this.isProcessing = true;

        while (this.analysisQueue.length > 0 && this.worker && this.workerReady) {
            const request = this.analysisQueue.shift();
            if (!request) {
                break;
            }

            try {
                // Store pending request
                this.pendingRequests.set(request.id, request);

                // Send to worker
                this.worker.postMessage({
                    type: 'analyze',
                    requestId: request.id,
                    data: {
                        content: request.content,
                        fileName: request.fileName,
                        rules: request.enabledRules
                    }
                });

                // Don't wait for response here - it will be handled by message handler
                // This allows multiple requests to be in flight
            } catch (error) {
                // Remove from pending and reject
                this.pendingRequests.delete(request.id);
                if (request.reject) {
                    request.reject(error as Error);
                }
            }
        }

        this.isProcessing = false;
    }

    /**
     * Wait for a worker response (used internally)
     */
    private async waitForWorkerResponse(request: AnalysisRequest): Promise<void> {
        // Response handling is done via message handler
        // This method exists for compatibility but doesn't block
        return Promise.resolve();
    }

    /**
     * Get queue statistics
     */
    getQueueStats(): {
        queueSize: number;
        pendingRequests: number;
        maxQueueSize: number;
        isProcessing: boolean;
        workerReady: boolean;
    } {
        return {
            queueSize: this.analysisQueue.length,
            pendingRequests: this.pendingRequests.size,
            maxQueueSize: this.maxQueueSize,
            isProcessing: this.isProcessing,
            workerReady: this.workerReady
        };
    }

    /**
     * Clear the queue
     */
    clearQueue(): void {
        // Reject all queued requests
        for (const request of this.analysisQueue) {
            if (request.reject) {
                request.reject(new Error('Queue cleared'));
            }
        }
        this.analysisQueue = [];

        // Reject all pending requests
        for (const [requestId, request] of this.pendingRequests) {
            if (request.reject) {
                request.reject(new Error('Queue cleared'));
            }
        }
        this.pendingRequests.clear();
    }

    /**
     * Dispose of resources
     */
    dispose(): void {
        this.clearQueue();
        
        if (this.worker) {
            this.worker.terminate();
            this.worker = null;
        }
        
        this.workerReady = false;
        this.isProcessing = false;
    }
}
