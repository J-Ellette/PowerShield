import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';

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

class AIFixer {
    private maxFixes: number;
    private confidenceThreshold: number;

    constructor(maxFixes: number = 10, confidenceThreshold: number = 0.8) {
        this.maxFixes = maxFixes;
        this.confidenceThreshold = confidenceThreshold;
    }

    async generateFixes(violations: PSViolation[]): Promise<Map<string, FixSuggestion[]>> {
        const fixes = new Map<string, FixSuggestion[]>();
        let processedCount = 0;

        core.info(`Processing ${violations.length} violations...`);

        for (const violation of violations) {
            if (processedCount >= this.maxFixes) {
                core.info(`Reached maximum fixes limit (${this.maxFixes})`);
                break;
            }

            try {
                const fix = await this.generateSingleFix(violation);
                
                if (fix && fix.confidence >= this.confidenceThreshold) {
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
            // Use rule-based fixes (simulating AI for now)
            const fix = this.getRuleBasedFix(violation);
            
            if (!fix) {
                return null;
            }

            const confidence = this.calculateConfidence(fix.fixedCode, violation);
            
            if (confidence < 0.5) {
                return null;
            }

            return {
                originalCode: violation.Code,
                fixedCode: fix.fixedCode,
                explanation: fix.explanation,
                confidence: confidence,
                ruleId: violation.RuleId,
                filePath: violation.FilePath,
                lineNumber: violation.LineNumber
            };
        } catch (error) {
            core.error(`Error generating fix for ${violation.RuleId}: ${error}`);
            return null;
        }
    }

    private getRuleBasedFix(violation: PSViolation): { fixedCode: string; explanation: string } | null {
        const ruleFixes: Record<string, any> = {
            'InsecureHashAlgorithms': {
                patterns: [
                    { 
                        from: /Get-FileHash\s+.*-Algorithm\s+MD5/gi, 
                        to: (match: string) => match.replace(/MD5/gi, 'SHA256')
                    },
                    { 
                        from: /Get-FileHash\s+.*-Algorithm\s+SHA1/gi, 
                        to: (match: string) => match.replace(/SHA1/gi, 'SHA256')
                    },
                    {
                        from: /\[System\.Security\.Cryptography\.MD5\]/gi,
                        to: () => '[System.Security.Cryptography.SHA256]'
                    },
                    {
                        from: /System\.Security\.Cryptography\.SHA1CryptoServiceProvider/gi,
                        to: () => 'System.Security.Cryptography.SHA256CryptoServiceProvider'
                    }
                ],
                explanation: 'Replaced insecure hash algorithm with SHA256'
            },
            'CredentialExposure': {
                patterns: [
                    { 
                        from: /ConvertTo-SecureString\s+"[^"]*"\s+-AsPlainText\s+-Force/gi, 
                        to: () => 'Read-Host "Enter password" -AsSecureString' 
                    },
                    {
                        from: /ConvertTo-SecureString\s+'[^']*'\s+-AsPlainText\s+-Force/gi,
                        to: () => 'Read-Host "Enter password" -AsSecureString'
                    }
                ],
                explanation: 'Replaced plaintext password with secure input'
            },
            'CommandInjection': {
                patterns: [
                    { 
                        from: /Invoke-Expression\s+\$\w+/gi, 
                        to: () => '# SECURITY: Removed Invoke-Expression - validate input and use safer alternatives' 
                    },
                    {
                        from: /iex\s+\$\w+/gi,
                        to: () => '# SECURITY: Removed iex - validate input and use safer alternatives'
                    }
                ],
                explanation: 'Removed command injection vulnerability'
            },
            'CertificateValidation': {
                patterns: [
                    { 
                        from: /\[System\.Net\.ServicePointManager\]::ServerCertificateValidationCallback\s*=\s*\{\s*\$true\s*\}/gi, 
                        to: () => '# SECURITY: Implement proper certificate validation instead of bypassing' 
                    },
                    {
                        from: /ServerCertificateValidationCallback\s*=\s*\{\s*return\s+\$true\s*\}/gi,
                        to: () => '# SECURITY: Implement proper certificate validation instead of bypassing'
                    }
                ],
                explanation: 'Removed certificate validation bypass'
            }
        };

        const ruleFix = ruleFixes[violation.RuleId];
        if (!ruleFix) {
            core.debug(`No fix pattern for rule: ${violation.RuleId}`);
            return null;
        }

        let fixedCode = violation.Code;
        let matched = false;

        for (const pattern of ruleFix.patterns) {
            if (pattern.from.test(fixedCode)) {
                if (typeof pattern.to === 'function') {
                    fixedCode = fixedCode.replace(pattern.from, pattern.to);
                } else {
                    fixedCode = fixedCode.replace(pattern.from, pattern.to);
                }
                matched = true;
                break;
            }
        }

        if (!matched) {
            return null;
        }

        return { fixedCode, explanation: ruleFix.explanation };
    }

    private calculateConfidence(fixedCode: string, violation: PSViolation): number {
        let confidence = 0.8; // Base confidence for rule-based fixes
        
        // Rule-specific confidence adjustments
        switch (violation.RuleId) {
            case 'InsecureHashAlgorithms':
                if (fixedCode.includes('SHA256') || fixedCode.includes('SHA384') || fixedCode.includes('SHA512')) {
                    confidence += 0.15;
                }
                if (fixedCode.includes('MD5') || fixedCode.includes('SHA1')) {
                    confidence -= 0.4;
                }
                break;
                
            case 'CredentialExposure':
                if (fixedCode.includes('-AsSecureString') || fixedCode.includes('Read-Host')) {
                    confidence += 0.15;
                }
                if (fixedCode.includes('-AsPlainText')) {
                    confidence -= 0.4;
                }
                break;
                
            case 'CommandInjection':
                if (!fixedCode.includes('Invoke-Expression') && !fixedCode.includes('iex')) {
                    confidence += 0.15;
                }
                break;

            case 'CertificateValidation':
                if (!fixedCode.includes('{ $true }') && !fixedCode.includes('return $true')) {
                    confidence += 0.15;
                }
                break;
        }

        // Ensure the fix actually changes something
        if (fixedCode.trim() === violation.Code.trim()) {
            confidence -= 0.5;
        }

        return Math.max(0, Math.min(1, confidence));
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
                        details.push(`${fileName}:${fix.lineNumber} - ${fix.explanation}`);
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
}

async function run(): Promise<void> {
    try {
        // Get inputs
        const violationsFile = core.getInput('violations-file', { required: true });
        const maxFixes = parseInt(core.getInput('max-fixes') || '10');
        const confidenceThreshold = parseFloat(core.getInput('confidence-threshold') || '0.8');
        const applyFixes = core.getBooleanInput('apply-fixes');

        core.info(`PowerShield Auto-Fix Action`);
        core.info(`Violations file: ${violationsFile}`);
        core.info(`Max fixes: ${maxFixes}`);
        core.info(`Confidence threshold: ${confidenceThreshold}`);
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
        const fixer = new AIFixer(maxFixes, confidenceThreshold);

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
                core.summary
                    .addHeading('🤖 PowerShield Auto-Fix Results')
                    .addTable([
                        [{ data: 'Metric', header: true }, { data: 'Value', header: true }],
                        ['Fixes Applied', result.count.toString()],
                        ['Rules Fixed', result.rules.join(', ')],
                    ])
                    .addHeading('Details', 3)
                    .addList(result.details)
                    .write();
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
                    core.info(`     Before: ${fix.originalCode}`);
                    core.info(`     After:  ${fix.fixedCode}`);
                });
            }
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
