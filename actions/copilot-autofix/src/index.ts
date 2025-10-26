import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';
import { ConfigLoader, PowerShieldConfig } from './config';
import { AIProviderFactory, AIProvider, FixRequest } from './ai-providers';

interface PSViolation {
    Name: string;
    Message: string;
    Severity: string;
    LineNumber: number;
    Code: string;
    FilePath: string;
    RuleId: string;
}

interface FixSuggestion {
    originalCode: string;
    fixedCode: string;
    explanation: string;
    confidence: number;
    ruleId: string;
    filePath: string;
    lineNumber: number;
}

class AutoFixer {
    private config: PowerShieldConfig;
    private aiProvider: AIProvider;
    private templateProvider: AIProvider;

    constructor(config: PowerShieldConfig, githubToken?: string) {
        this.config = config;
        
        // Create primary AI provider
        this.aiProvider = AIProviderFactory.createProvider(config.autofix, githubToken);
        
        // Create template provider as fallback
        const templateConfig = { ...config.autofix, provider: 'template' as const };
        this.templateProvider = AIProviderFactory.createProvider(templateConfig);
    }

    async generateFixes(violations: PSViolation[]): Promise<Map<string, FixSuggestion[]>> {
        const fixes = new Map<string, FixSuggestion[]>();
        let processedCount = 0;

        core.info(`Processing ${violations.length} violations with ${this.aiProvider.getName()}...`);

        // Validate AI provider
        const isValid = await this.aiProvider.validate();
        if (!isValid && !this.config.autofix.fallback_to_templates) {
            core.warning('AI provider validation failed and fallback is disabled');
            return fixes;
        }

        for (const violation of violations) {
            if (processedCount >= this.config.autofix.max_fixes) {
                core.info(`Reached maximum fixes limit (${this.config.autofix.max_fixes})`);
                break;
            }

            // Check if this rule is enabled for auto-fix
            if (!this.isRuleFixEnabled(violation.RuleId)) {
                core.debug(`Auto-fix disabled for rule: ${violation.RuleId}`);
                continue;
            }

            try {
                const fix = await this.generateSingleFix(violation);
                
                if (fix && fix.confidence >= this.config.autofix.confidence_threshold) {
                    if (!fixes.has(violation.FilePath)) {
                        fixes.set(violation.FilePath, []);
                    }
                    fixes.get(violation.FilePath)!.push(fix);
                    processedCount++;
                    
                    core.info(`Generated fix for ${violation.RuleId} in ${violation.FilePath} (confidence: ${fix.confidence})`);
                } else if (fix) {
                    core.warning(`Fix for ${violation.RuleId} has low confidence (${fix.confidence}), skipping`);
                }
            } catch (error) {
                core.error(`Failed to generate fix for ${violation.RuleId}: ${error}`);
            }
        }

        return fixes;
    }

    private async generateSingleFix(violation: PSViolation): Promise<FixSuggestion | null> {
        try {
            // Get rule configuration
            const ruleConfig = this.config.rules[violation.RuleId];
            const ruleDescription = ruleConfig?.enabled !== false 
                ? `Security rule: ${violation.Name}`
                : `Rule: ${violation.Name}`;

            // Read surrounding context from file
            const context = this.getCodeContext(violation.FilePath, violation.LineNumber);

            const request: FixRequest = {
                code: violation.Code,
                ruleId: violation.RuleId,
                ruleName: violation.Name,
                ruleDescription: ruleDescription,
                severity: violation.Severity,
                filePath: violation.FilePath,
                lineNumber: violation.LineNumber,
                context: context
            };

            // Try AI provider first
            let fixResponse = null;
            const useAI = await this.aiProvider.validate();
            
            if (useAI) {
                try {
                    core.debug(`Attempting AI fix with ${this.aiProvider.getName()}`);
                    fixResponse = await this.aiProvider.generateFix(request);
                } catch (error) {
                    core.warning(`AI provider failed: ${error}`);
                    fixResponse = null;
                }
            }

            // Fallback to templates if AI failed or disabled
            if (!fixResponse && this.config.autofix.fallback_to_templates) {
                core.debug('Falling back to template-based fix');
                fixResponse = await this.templateProvider.generateFix(request);
            }

            if (!fixResponse || fixResponse.confidence < 0.5) {
                return null;
            }

            return {
                originalCode: violation.Code,
                fixedCode: fixResponse.fixedCode,
                explanation: fixResponse.explanation,
                confidence: fixResponse.confidence,
                ruleId: violation.RuleId,
                filePath: violation.FilePath,
                lineNumber: violation.LineNumber
            };
        } catch (error) {
            core.error(`Error generating fix for ${violation.RuleId}: ${error}`);
            return null;
        }
    }

    private getCodeContext(filePath: string, lineNumber: number, contextLines: number = 3): string {
        try {
            if (!fs.existsSync(filePath)) {
                return '';
            }

            const lines = fs.readFileSync(filePath, 'utf8').split('\n');
            const startLine = Math.max(0, lineNumber - contextLines - 1);
            const endLine = Math.min(lines.length, lineNumber + contextLines);
            
            return lines.slice(startLine, endLine).join('\n');
        } catch (error) {
            core.debug(`Failed to read context from ${filePath}: ${error}`);
            return '';
        }
    }

    private isRuleFixEnabled(ruleId: string): boolean {
        // Check global autofix enabled
        if (!this.config.autofix.enabled) {
            return false;
        }

        // Check rule-specific fix configuration
        if (this.config.autofix.rule_fixes.hasOwnProperty(ruleId)) {
            return this.config.autofix.rule_fixes[ruleId];
        }

        // Check if rule itself is enabled
        if (this.config.rules[ruleId]?.enabled === false) {
            return false;
        }

        // Default to enabled
        return true;
    }

    async applyFixes(fixes: Map<string, FixSuggestion[]>): Promise<{count: number, details: string[], rules: string[]}> {
        let totalFixes = 0;
        const details: string[] = [];
        const rules = new Set<string>();

        for (const [filePath, fileFixes] of fixes) {
            try {
                if (!fs.existsSync(filePath)) {
                    core.warning(`File not found: ${filePath}`);
                    continue;
                }

                let fileContent = fs.readFileSync(filePath, 'utf8');
                
                // Sort fixes by line number (descending) to maintain line positions
                const sortedFixes = fileFixes.sort((a, b) => b.lineNumber - a.lineNumber);

                let appliedCount = 0;
                for (const fix of sortedFixes) {
                    const originalContent = fileContent;
                    fileContent = fileContent.replace(fix.originalCode, fix.fixedCode);
                    
                    if (fileContent !== originalContent) {
                        appliedCount++;
                        totalFixes++;
                        rules.add(fix.ruleId);
                        
                        const fileName = path.basename(filePath);
                        details.push(`${fileName}:${fix.lineNumber} - ${fix.explanation} (confidence: ${fix.confidence})`);
                        core.info(`Applied fix in ${filePath}:${fix.lineNumber} - ${fix.explanation}`);
                    }
                }

                if (appliedCount > 0) {
                    fs.writeFileSync(filePath, fileContent, 'utf8');
                    core.info(`Applied ${appliedCount} fixes to ${filePath}`);
                }
            } catch (error) {
                core.error(`Failed to apply fixes to ${filePath}: ${error}`);
            }
        }

        return {
            count: totalFixes,
            details: details,
            rules: Array.from(rules)
        };
    }

    async reAnalyze(violations: PSViolation[], workspacePath: string): Promise<boolean> {
        core.info('Re-analyzing to verify fixes...');
        
        // This would call the PowerShell analyzer again
        // For now, we'll just return true as a placeholder
        // In practice, this should shell out to pwsh and run the analyzer
        
        return true;
    }
}

async function run(): Promise<void> {
    try {
        // Load configuration
        const workspacePath = process.env.GITHUB_WORKSPACE || '.';
        core.info('Loading PowerShield configuration...');
        const config = ConfigLoader.loadConfig(workspacePath);

        // Validate configuration
        const validation = ConfigLoader.validateConfig(config);
        if (!validation.valid) {
            core.warning('Configuration validation failed:');
            validation.errors.forEach(err => core.warning(`  - ${err}`));
        }

        // Log configuration
        core.info(`Auto-fix provider: ${config.autofix.provider}`);
        core.info(`Model: ${config.autofix.model}`);
        core.info(`Max fixes: ${config.autofix.max_fixes}`);
        core.info(`Confidence threshold: ${config.autofix.confidence_threshold}`);
        core.info(`Fallback to templates: ${config.autofix.fallback_to_templates}`);

        // Get inputs (can override config)
        const violationsFile = core.getInput('violations-file', { required: true });
        const maxFixes = parseInt(core.getInput('max-fixes') || config.autofix.max_fixes.toString());
        const confidenceThreshold = parseFloat(core.getInput('confidence-threshold') || config.autofix.confidence_threshold.toString());
        const applyFixes = core.getBooleanInput('apply-fixes');
        const githubToken = core.getInput('github-token', { required: true });

        // Override config with inputs
        config.autofix.max_fixes = maxFixes;
        config.autofix.confidence_threshold = confidenceThreshold;

        core.info(`PowerShield Auto-Fix Action`);
        core.info(`Violations file: ${violationsFile}`);
        core.info(`Apply fixes: ${applyFixes}`);

        // Read violations
        if (!fs.existsSync(violationsFile)) {
            core.setFailed(`Violations file not found: ${violationsFile}`);
            return;
        }

        const violationsData = JSON.parse(fs.readFileSync(violationsFile, 'utf8'));
        const violations: PSViolation[] = violationsData.violations || [];

        if (violations.length === 0) {
            core.info('No violations to fix');
            core.setOutput('fixes-applied', 'false');
            core.setOutput('fixes-count', '0');
            core.setOutput('fixed-rules', '');
            core.setOutput('fix-details', '');
            return;
        }

        core.info(`Processing ${violations.length} violations...`);

        // Initialize fixer
        const fixer = new AutoFixer(config, githubToken);

        // Generate fixes
        const fixes = await fixer.generateFixes(violations);
        const totalFixes = Array.from(fixes.values()).reduce((sum, fileFixes) => sum + fileFixes.length, 0);

        core.info(`Generated ${totalFixes} potential fixes`);

        if (totalFixes === 0) {
            core.info('No fixes could be generated with sufficient confidence');
            core.setOutput('fixes-applied', 'false');
            core.setOutput('fixes-count', '0');
            core.setOutput('fixed-rules', '');
            core.setOutput('fix-details', '');
            return;
        }

        if (applyFixes) {
            // Apply the fixes
            const result = await fixer.applyFixes(fixes);
            
            core.setOutput('fixes-applied', result.count > 0 ? 'true' : 'false');
            core.setOutput('fixes-count', result.count.toString());
            core.setOutput('fixed-rules', result.rules.join(', '));
            core.setOutput('fix-details', result.details.join('\n'));
            
            if (result.count > 0) {
                core.info(`✅ Applied ${result.count} fixes successfully`);
                
                // Create summary
                core.summary
                    .addHeading('🤖 PowerShield Auto-Fix Results')
                    .addTable([
                        [{ data: 'Metric', header: true }, { data: 'Value', header: true }],
                        ['Provider', config.autofix.provider],
                        ['Model', config.autofix.model],
                        ['Fixes Applied', result.count.toString()],
                        ['Rules Fixed', result.rules.join(', ')],
                    ])
                    .addHeading('Details', 3)
                    .addList(result.details)
                    .write();

                // Re-analyze if enabled
                if (config.ci && result.count > 0) {
                    core.info('Fixes applied, re-analysis recommended');
                }
            } else {
                core.warning('No fixes were applied');
            }
        } else {
            // Just preview the fixes
            core.info('Preview mode - fixes not applied');
            core.setOutput('fixes-applied', 'false');
            core.setOutput('fixes-count', totalFixes.toString());
            
            // Output fix preview
            for (const [filePath, fileFixes] of fixes) {
                core.info(`\nPotential fixes for ${filePath}:`);
                fileFixes.forEach((fix, index) => {
                    core.info(`  ${index + 1}. ${fix.explanation} (confidence: ${fix.confidence})`);
                    core.info(`     Line ${fix.lineNumber}`);
                    core.info(`     Before: ${fix.originalCode.substring(0, 100)}${fix.originalCode.length > 100 ? '...' : ''}`);
                    core.info(`     After:  ${fix.fixedCode.substring(0, 100)}${fix.fixedCode.length > 100 ? '...' : ''}`);
                });
            }

            // Create preview summary
            core.summary
                .addHeading('🤖 PowerShield Auto-Fix Preview')
                .addTable([
                    [{ data: 'Metric', header: true }, { data: 'Value', header: true }],
                    ['Provider', config.autofix.provider],
                    ['Model', config.autofix.model],
                    ['Potential Fixes', totalFixes.toString()],
                ])
                .addRaw('\n> Set `apply-fixes: true` to apply these fixes')
                .write();
        }

    } catch (error) {
        if (error instanceof Error) {
            core.setFailed(`Action failed: ${error.message}`);
        } else {
            core.setFailed(`Action failed: ${error}`);
        }
    }
}

run();
