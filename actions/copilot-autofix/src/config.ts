/**
 * PowerShield Configuration System
 * Provides hierarchical configuration loading and validation
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export interface AnalysisConfig {
    severity_threshold: 'Low' | 'Medium' | 'High' | 'Critical';
    max_file_size: number;
    timeout_seconds: number;
    parallel_analysis: boolean;
    exclude_paths: string[];
    exclude_files: string[];
}

export interface RuleConfig {
    enabled: boolean;
    severity?: 'Low' | 'Medium' | 'High' | 'Critical';
    [key: string]: any;
}

export interface AutoFixConfig {
    enabled: boolean;
    provider: 'github-models' | 'openai' | 'azure' | 'claude' | 'template';
    model: string;
    max_fixes: number;
    confidence_threshold: number;
    apply_automatically: boolean;
    fallback_to_templates: boolean;
    rule_fixes: { [ruleId: string]: boolean };
}

export interface SuppressionConfig {
    require_justification: boolean;
    max_duration_days: number;
    allow_permanent: boolean;
}

export interface ReportingConfig {
    formats: ('sarif' | 'json' | 'markdown')[];
    output_dir: string;
    sarif?: {
        include_code_flows: boolean;
        include_fixes: boolean;
    };
    markdown?: {
        include_severity_summary: boolean;
        include_top_issues: number;
    };
}

export interface CIConfig {
    fail_on: ('Critical' | 'High' | 'Medium' | 'Low')[];
    max_warnings: number;
    baseline_mode: boolean;
    baseline_file: string;
}

export interface WebhookConfig {
    url: string;
    events: string[];
    severity_filter: ('Critical' | 'High' | 'Medium' | 'Low')[];
}

export interface EnterpriseConfig {
    audit_log: boolean;
    compliance_reporting: boolean;
    policy_enforcement: boolean;
}

export interface PowerShieldConfig {
    version: string;
    analysis: AnalysisConfig;
    rules: { [ruleId: string]: RuleConfig };
    autofix: AutoFixConfig;
    suppressions: SuppressionConfig;
    reporting: ReportingConfig;
    ci: CIConfig;
    webhooks?: WebhookConfig[];
    enterprise?: EnterpriseConfig;
}

/**
 * Default configuration
 */
export const DEFAULT_CONFIG: PowerShieldConfig = {
    version: '1.0',
    analysis: {
        severity_threshold: 'Medium',
        max_file_size: 10485760, // 10MB
        timeout_seconds: 30,
        parallel_analysis: true,
        exclude_paths: [
            '**/node_modules/**',
            '**/dist/**',
            '**/*.min.ps1',
            '.github/**',
            'scripts/**',
            'src/PowerShellSecurityAnalyzer.psm1'
        ],
        exclude_files: ['*.tests.ps1']
    },
    rules: {
        InsecureHashAlgorithms: {
            enabled: true,
            severity: 'High'
        },
        CredentialExposure: {
            enabled: true,
            severity: 'Critical',
            check_comments: true,
            min_password_length: 8
        },
        CommandInjection: {
            enabled: true,
            severity: 'Critical'
        },
        CertificateValidation: {
            enabled: true,
            severity: 'High'
        },
        AzurePowerShellCredentialLeaks: {
            enabled: true,
            severity: 'Critical'
        },
        AzureResourceExposure: {
            enabled: true,
            severity: 'High'
        }
    },
    autofix: {
        enabled: true,
        provider: 'github-models',
        model: 'gpt-4o-mini',
        max_fixes: 10,
        confidence_threshold: 0.8,
        apply_automatically: false,
        fallback_to_templates: true,
        rule_fixes: {
            InsecureHashAlgorithms: true,
            CredentialExposure: true,
            CommandInjection: false,
            CertificateValidation: false,
            AzurePowerShellCredentialLeaks: true,
            AzureResourceExposure: true
        }
    },
    suppressions: {
        require_justification: true,
        max_duration_days: 90,
        allow_permanent: false
    },
    reporting: {
        formats: ['sarif', 'json', 'markdown'],
        output_dir: '.powershield-reports',
        sarif: {
            include_code_flows: true,
            include_fixes: true
        },
        markdown: {
            include_severity_summary: true,
            include_top_issues: 5
        }
    },
    ci: {
        fail_on: ['Critical', 'High'],
        max_warnings: 50,
        baseline_mode: false,
        baseline_file: '.powershield-baseline.sarif'
    }
};

/**
 * Configuration loader with hierarchical support
 */
export class ConfigLoader {
    private static CONFIG_FILENAMES = ['.powershield.yml', '.powershield.yaml', 'powershield.yml', 'powershield.yaml'];

    /**
     * Load configuration from file system with hierarchical merging
     */
    static loadConfig(workspacePath: string = '.'): PowerShieldConfig {
        const configs: Partial<PowerShieldConfig>[] = [];

        // 1. Start with default config
        configs.push(DEFAULT_CONFIG);

        // 2. Look for global config (~/.powershield.yml)
        const globalConfig = this.loadGlobalConfig();
        if (globalConfig) {
            configs.push(globalConfig);
        }

        // 3. Look for project config
        const projectConfig = this.loadProjectConfig(workspacePath);
        if (projectConfig) {
            configs.push(projectConfig);
        }

        // 4. Look for local config (takes highest precedence)
        const localConfig = this.loadLocalConfig(workspacePath);
        if (localConfig) {
            configs.push(localConfig);
        }

        // Merge all configs (later configs override earlier ones)
        return this.mergeConfigs(configs);
    }

    /**
     * Load global configuration from user home directory
     */
    private static loadGlobalConfig(): Partial<PowerShieldConfig> | null {
        const homeDir = process.env.HOME || process.env.USERPROFILE;
        if (!homeDir) return null;

        for (const filename of this.CONFIG_FILENAMES) {
            const configPath = path.join(homeDir, filename);
            const config = this.loadConfigFile(configPath);
            if (config) return config;
        }

        return null;
    }

    /**
     * Load project configuration from workspace root
     */
    private static loadProjectConfig(workspacePath: string): Partial<PowerShieldConfig> | null {
        for (const filename of this.CONFIG_FILENAMES) {
            const configPath = path.join(workspacePath, filename);
            const config = this.loadConfigFile(configPath);
            if (config) return config;
        }

        return null;
    }

    /**
     * Load local configuration (e.g., .powershield.local.yml)
     */
    private static loadLocalConfig(workspacePath: string): Partial<PowerShieldConfig> | null {
        const localFilenames = ['.powershield.local.yml', '.powershield.local.yaml'];
        
        for (const filename of localFilenames) {
            const configPath = path.join(workspacePath, filename);
            const config = this.loadConfigFile(configPath);
            if (config) return config;
        }

        return null;
    }

    /**
     * Load a single configuration file
     */
    private static loadConfigFile(filePath: string): Partial<PowerShieldConfig> | null {
        try {
            if (!fs.existsSync(filePath)) {
                return null;
            }

            const content = fs.readFileSync(filePath, 'utf8');
            const config = yaml.load(content) as Partial<PowerShieldConfig>;

            console.log(`Loaded configuration from: ${filePath}`);
            return config;
        } catch (error) {
            console.warn(`Failed to load config from ${filePath}:`, error);
            return null;
        }
    }

    /**
     * Deep merge multiple configuration objects
     */
    private static mergeConfigs(configs: Partial<PowerShieldConfig>[]): PowerShieldConfig {
        const result = { ...DEFAULT_CONFIG };

        for (const config of configs) {
            if (!config) continue;

            // Merge top-level properties
            Object.assign(result, {
                version: config.version || result.version,
                analysis: config.analysis ? { ...result.analysis, ...config.analysis } : result.analysis,
                autofix: config.autofix ? { ...result.autofix, ...config.autofix } : result.autofix,
                suppressions: config.suppressions ? { ...result.suppressions, ...config.suppressions } : result.suppressions,
                reporting: config.reporting ? this.deepMerge(result.reporting, config.reporting) : result.reporting,
                ci: config.ci ? { ...result.ci, ...config.ci } : result.ci,
                webhooks: config.webhooks || result.webhooks,
                enterprise: config.enterprise ? { ...result.enterprise, ...config.enterprise } : result.enterprise
            });

            // Merge rules (special handling to preserve per-rule config)
            if (config.rules) {
                result.rules = { ...result.rules };
                for (const [ruleId, ruleConfig] of Object.entries(config.rules)) {
                    result.rules[ruleId] = { ...result.rules[ruleId], ...ruleConfig };
                }
            }

            // Merge autofix rule_fixes
            if (config.autofix?.rule_fixes) {
                result.autofix.rule_fixes = { ...result.autofix.rule_fixes, ...config.autofix.rule_fixes };
            }
        }

        return result;
    }

    /**
     * Deep merge two objects
     */
    private static deepMerge<T>(target: T, source: Partial<T>): T {
        const result = { ...target } as any;
        
        for (const key in source) {
            const sourceValue = source[key];
            const targetValue = result[key];

            if (sourceValue && typeof sourceValue === 'object' && !Array.isArray(sourceValue)) {
                result[key] = this.deepMerge(targetValue || {}, sourceValue);
            } else {
                result[key] = sourceValue;
            }
        }

        return result as T;
    }

    /**
     * Validate configuration
     */
    static validateConfig(config: PowerShieldConfig): { valid: boolean; errors: string[] } {
        const errors: string[] = [];

        // Validate version
        if (!config.version || config.version !== '1.0') {
            errors.push('Invalid or missing config version (expected "1.0")');
        }

        // Validate analysis settings
        if (config.analysis.max_file_size <= 0) {
            errors.push('analysis.max_file_size must be positive');
        }
        if (config.analysis.timeout_seconds <= 0) {
            errors.push('analysis.timeout_seconds must be positive');
        }

        // Validate autofix settings
        if (config.autofix.confidence_threshold < 0 || config.autofix.confidence_threshold > 1) {
            errors.push('autofix.confidence_threshold must be between 0 and 1');
        }
        if (config.autofix.max_fixes < 0) {
            errors.push('autofix.max_fixes must be non-negative');
        }

        const validProviders = ['github-models', 'openai', 'azure', 'claude', 'template'];
        if (!validProviders.includes(config.autofix.provider)) {
            errors.push(`autofix.provider must be one of: ${validProviders.join(', ')}`);
        }

        // Validate suppression settings
        if (config.suppressions.max_duration_days < 0) {
            errors.push('suppressions.max_duration_days must be non-negative');
        }

        // Validate CI settings
        if (config.ci.max_warnings < 0) {
            errors.push('ci.max_warnings must be non-negative');
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }

    /**
     * Save configuration to file
     */
    static saveConfig(config: PowerShieldConfig, filePath: string): void {
        const yamlContent = yaml.dump(config, {
            indent: 2,
            lineWidth: 120,
            noRefs: true
        });

        fs.writeFileSync(filePath, yamlContent, 'utf8');
        console.log(`Configuration saved to: ${filePath}`);
    }

    /**
     * Create example configuration file
     */
    static createExampleConfig(outputPath: string): void {
        const exampleConfig: PowerShieldConfig = {
            ...DEFAULT_CONFIG,
            // Add comments via custom formatting
        };

        const yamlContent = this.generateExampleYaml();
        fs.writeFileSync(outputPath, yamlContent, 'utf8');
        console.log(`Example configuration created at: ${outputPath}`);
    }

    /**
     * Generate example YAML with comments
     */
    private static generateExampleYaml(): string {
        return `# PowerShield Configuration
# Complete configuration reference for PowerShield

version: "1.0"

# Analysis Settings
analysis:
  severity_threshold: "Medium"  # Low, Medium, High, Critical
  max_file_size: 10485760  # 10MB
  timeout_seconds: 30
  parallel_analysis: true
  
  # Path exclusions (glob patterns)
  exclude_paths:
    - "**/node_modules/**"
    - "**/dist/**"
    - "**/*.min.ps1"
    - ".github/**"
  
  # File exclusions
  exclude_files:
    - "*.tests.ps1"

# Rule Configuration
rules:
  # Enable/disable rules and override severity
  InsecureHashAlgorithms:
    enabled: true
    severity: "High"
  
  CredentialExposure:
    enabled: true
    severity: "Critical"
    check_comments: true
    min_password_length: 8
  
  CommandInjection:
    enabled: true
    severity: "Critical"
  
  CertificateValidation:
    enabled: true
    severity: "High"

# Auto-Fix Configuration
autofix:
  enabled: true
  provider: "github-models"  # github-models, openai, azure, claude, template
  model: "gpt-4o-mini"
  max_fixes: 10
  confidence_threshold: 0.8
  apply_automatically: false
  fallback_to_templates: true
  
  # Per-rule auto-fix control
  rule_fixes:
    InsecureHashAlgorithms: true
    CredentialExposure: true
    CommandInjection: false  # Too risky for auto-fix
    CertificateValidation: false

# Suppression Settings
suppressions:
  require_justification: true
  max_duration_days: 90
  allow_permanent: false

# Reporting
reporting:
  formats: ["sarif", "json", "markdown"]
  output_dir: ".powershield-reports"
  
  sarif:
    include_code_flows: true
    include_fixes: true
  
  markdown:
    include_severity_summary: true
    include_top_issues: 5

# CI/CD Integration
ci:
  fail_on: ["Critical", "High"]
  max_warnings: 50
  baseline_mode: false
  baseline_file: ".powershield-baseline.sarif"

# Webhooks (optional)
# webhooks:
#   - url: "https://hooks.slack.com/..."
#     events: ["critical_found", "analysis_complete"]
#     severity_filter: ["Critical", "High"]

# Enterprise Settings (optional)
# enterprise:
#   audit_log: true
#   compliance_reporting: true
#   policy_enforcement: true
`;
    }
}
