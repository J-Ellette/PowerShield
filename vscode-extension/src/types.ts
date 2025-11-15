/**
 * Core types and interfaces for PowerShield VS Code Extension
 */

/**
 * Security severity levels matching PowerShell module
 */
export enum SecuritySeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/**
 * Security violation from analysis
 */
export interface SecurityViolation {
    name: string;
    message: string;
    description: string;
    severity: SecuritySeverity;
    lineNumber: number;
    columnNumber?: number;
    endColumn?: number;
    code: string;
    filePath: string;
    ruleId: string;
    ruleTitle?: string;
    explanation?: string;
    cweId?: string;
    compliance?: string[];
    hasQuickFix?: boolean;
    fixPreview?: string;
    bestPractices?: string[];
    deprecated?: boolean;
    confidence?: number;
    metadata?: {
        CWE?: string[];
        MitreAttack?: string[];
        OWASP?: string[];
        HelpUri?: string;
        [key: string]: any;
    };
    fixes?: FixSuggestion[];
    codeFlows?: CodeFlow[];
}

/**
 * Fix suggestion for a violation
 */
export interface FixSuggestion {
    description: string;
    fixedCode: string;
    confidence: number;
    category: string;
}

/**
 * Code flow for data flow analysis
 */
export interface CodeFlow {
    locations: CodeLocation[];
    message?: string;
}

/**
 * Code location in a flow
 */
export interface CodeLocation {
    filePath: string;
    lineNumber: number;
    columnNumber?: number;
    message?: string;
}

/**
 * Analysis result for a document
 */
export interface AnalysisResult {
    filePath: string;
    violations: SecurityViolation[];
    timestamp: Date;
    analysisTime: number;
    cacheHit?: boolean;
}

/**
 * Cached analysis entry
 */
export interface CacheEntry {
    violations: SecurityViolation[];
    timestamp: number;
    lastAccessed: number;
    contentHash: string;
}

/**
 * PowerShield engine configuration
 */
export interface PowerShieldConfig {
    realTimeAnalysis: {
        enabled: boolean;
        debounceMs: number;
        backgroundAnalysis: boolean;
    };
    aiProvider: {
        primary: string;
        fallback: string[];
        confidenceThreshold: number;
    };
    ui: {
        showInlineDecorations: boolean;
        showHoverExplanations: boolean;
        showCodeLens: boolean;
    };
    performance: {
        enableCaching: boolean;
        maxCacheSize: string;
        enableIncrementalAnalysis: boolean;
    };
    rules: {
        enabled: string[];
        disabled: string[];
    };
    suppressions: {
        enabled: boolean;
    };
}

/**
 * PowerShell execution result
 */
export interface PowerShellResult {
    stdout: string;
    stderr: string;
    exitCode: number;
    data?: any;
}

/**
 * Workspace security state
 */
export interface WorkspaceSecurityState {
    summary: SecuritySummary;
    critical: SecurityViolation[];
    high: SecurityViolation[];
    medium: SecurityViolation[];
    low: SecurityViolation[];
    info: SecurityViolation[];
}

/**
 * Security summary statistics
 */
export interface SecuritySummary {
    totalFiles: number;
    totalViolations: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    lastAnalysis?: Date;
}

/**
 * AI provider configuration
 */
export interface AIProviderConfig {
    name: string;
    type: 'github-models' | 'openai' | 'anthropic' | 'azure-openai' | 'template-based';
    apiKey?: string;
    endpoint?: string;
    model?: string;
    maxTokens?: number;
    temperature?: number;
}

/**
 * AI fix result
 */
export interface AIFixResult {
    fixedCode: string;
    explanation: string;
    confidence: number;
    alternative?: string;
}

/**
 * Fix context for AI generation
 */
export interface FixContext {
    violation: SecurityViolation;
    codeContext: {
        beforeLines: string[];
        targetCode: string;
        afterLines: string[];
        functionContext?: FunctionContext;
        moduleContext?: string;
    };
    projectContext?: {
        workspaceType?: string;
        dependencies?: string[];
        conventions?: string;
    };
}

/**
 * Function context
 */
export interface FunctionContext {
    name: string;
    parameters: string[];
    purpose?: string;
    scope?: string;
}
