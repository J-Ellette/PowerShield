# Phase 3.3: Local AI Integration

## Ollama and Model Management Implementation

> **Timeline**: Months 9-10  
> **Prerequisites**: Phase 3.1 & 3.2 Complete  
> **Goal**: Implement offline AI capabilities for air-gapped environments

---

## 🧠 **AI Architecture Overview**

### **Local AI Stack**

The local AI integration provides enterprise-grade offline capabilities:

- **Ollama Runtime**: Local model hosting and inference
- **Model Management**: Automated download and lifecycle management  
- **Task Specialization**: Optimized models for different analysis tasks
- **Performance Optimization**: Model caching and resource management
- **Enterprise Security**: Complete air-gap compatibility

### **Supported Models**

| Model | Size | Purpose | Priority |
|-------|------|---------|----------|
| **CodeLlama 7B Code** | 3.8GB | Code generation and fixes | High |
| **CodeLlama 13B Instruct** | 7.3GB | Complex explanations | Medium |
| **Mistral 7B Instruct** | 4.1GB | General analysis | Medium |
| **Phi3 Mini** | 2.3GB | Fast responses | High |
| **CodeGemma 7B** | 4.8GB | Alternative code model | Low |

---

## 🔧 **Ollama Integration**

### **Local AI Orchestrator**

```typescript
// src/main/ai/LocalAIOrchestrator.ts
import { OllamaApi, ChatRequest, ChatResponse } from 'ollama';
import { EventEmitter } from 'events';

export interface ModelInfo {
    name: string;
    size: number;
    modified: Date;
    digest: string;
    status: 'available' | 'downloading' | 'error' | 'loading';
    purpose: string;
    priority: 'high' | 'medium' | 'low';
    parameters?: ModelParameters;
}

export interface ModelParameters {
    contextLength: number;
    temperature: number;
    topP: number;
    repeatPenalty: number;
    stopSequences: string[];
}

export interface LocalAIOptions {
    model?: string;
    temperature?: number;
    maxTokens?: number;
    timeout?: number;
    stream?: boolean;
}

export interface AIFixResult {
    success: boolean;
    fixedCode: string;
    confidence: number;
    explanation: string;
    changes: CodeChange[];
    alternatives?: string[];
}

export interface SecurityExplanation {
    violation: SecurityViolation;
    explanation: string;
    severity: string;
    mitigation: string[];
    references: string[];
    confidence: number;
    educationalContent?: EducationalContent;
}

export interface EducationalContent {
    concept: string;
    definition: string;
    examples: CodeExample[];
    bestPractices: string[];
    commonMistakes: string[];
}

export class LocalAIOrchestrator extends EventEmitter {
    private ollama: OllamaApi;
    private availableModels: Map<string, ModelInfo> = new Map();
    private modelCache: Map<string, CachedModel> = new Map();
    private isInitialized = false;
    private healthCheckInterval: NodeJS.Timeout | null = null;

    constructor() {
        super();
        this.ollama = new OllamaApi({
            host: 'http://localhost:11434'
        });
    }

    async initialize(): Promise<void> {
        console.log('Initializing Local AI Orchestrator...');

        try {
            // Check Ollama availability
            await this.verifyOllamaAvailability();

            // Load existing models
            await this.loadAvailableModels();

            // Setup recommended models
            await this.setupRecommendedModels();

            // Initialize model cache
            await this.initializeModelCache();

            // Setup health monitoring
            this.setupHealthMonitoring();

            this.isInitialized = true;
            this.emit('initialized');

            console.log('Local AI Orchestrator initialized successfully');

        } catch (error) {
            console.error('Failed to initialize Local AI Orchestrator:', error);
            this.emit('error', error);
            throw error;
        }
    }

    private async verifyOllamaAvailability(): Promise<void> {
        try {
            const response = await fetch('http://localhost:11434/api/version', {
                method: 'GET',
                timeout: 5000
            });

            if (!response.ok) {
                throw new Error(`Ollama server responded with status: ${response.status}`);
            }

            const version = await response.json();
            console.log(`Ollama version: ${version.version}`);

        } catch (error) {
            if (error.code === 'ECONNREFUSED') {
                throw new Error('Ollama is not running. Please start Ollama service.');
            }
            throw new Error(`Failed to connect to Ollama: ${error.message}`);
        }
    }

    private async loadAvailableModels(): Promise<void> {
        try {
            const models = await this.ollama.list();
            
            for (const model of models.models) {
                const modelInfo: ModelInfo = {
                    name: model.name,
                    size: model.size,
                    modified: new Date(model.modified_at),
                    digest: model.digest,
                    status: 'available',
                    purpose: this.getModelPurpose(model.name),
                    priority: this.getModelPriority(model.name)
                };

                this.availableModels.set(model.name, modelInfo);
            }

            console.log(`Loaded ${this.availableModels.size} available models`);

        } catch (error) {
            console.warn('Failed to load available models:', error.message);
        }
    }

    private async setupRecommendedModels(): Promise<void> {
        const recommendedModels = [
            {
                name: 'codellama:7b-code',
                purpose: 'Code analysis and fix generation',
                priority: 'high' as const,
                autoDownload: true
            },
            {
                name: 'phi3:mini',
                purpose: 'Fast analysis and suggestions',
                priority: 'high' as const,
                autoDownload: true
            },
            {
                name: 'codellama:13b-instruct',
                purpose: 'Complex security explanations',
                priority: 'medium' as const,
                autoDownload: false
            },
            {
                name: 'mistral:7b-instruct',
                purpose: 'General purpose analysis',
                priority: 'medium' as const,
                autoDownload: false
            }
        ];

        for (const model of recommendedModels) {
            if (!this.availableModels.has(model.name)) {
                // Add to available models as "not downloaded"
                this.availableModels.set(model.name, {
                    name: model.name,
                    size: 0,
                    modified: new Date(),
                    digest: '',
                    status: 'error', // Will be updated when downloaded
                    purpose: model.purpose,
                    priority: model.priority
                });

                // Auto-download high priority models
                if (model.autoDownload) {
                    console.log(`Auto-downloading recommended model: ${model.name}`);
                    this.downloadModel(model.name).catch(error => {
                        console.warn(`Failed to auto-download ${model.name}:`, error.message);
                    });
                }
            }
        }
    }

    private async initializeModelCache(): Promise<void> {
        // Pre-warm high priority models
        const highPriorityModels = Array.from(this.availableModels.values())
            .filter(model => model.priority === 'high' && model.status === 'available')
            .slice(0, 2); // Limit to 2 models to avoid memory issues

        for (const model of highPriorityModels) {
            try {
                await this.warmupModel(model.name);
            } catch (error) {
                console.warn(`Failed to warm up model ${model.name}:`, error.message);
            }
        }
    }

    async generateSecurityFix(
        violation: SecurityViolation,
        context: FixContext,
        options: LocalAIOptions = {}
    ): Promise<AIFixResult> {
        this.ensureInitialized();

        const model = options.model || this.selectBestModel('code-generation');
        console.log(`Generating security fix using model: ${model}`);

        try {
            const prompt = this.buildSecurityFixPrompt(violation, context);
            
            const response = await this.ollama.chat({
                model,
                messages: [
                    {
                        role: 'system',
                        content: POWERSHELL_SECURITY_SYSTEM_PROMPT
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                options: {
                    temperature: options.temperature || 0.1,
                    top_p: 0.9,
                    num_predict: options.maxTokens || 1000,
                    stop: ['```\n\n', '---', '\n\n## ']
                },
                stream: false
            });

            return this.parseFixResponse(response.message.content, violation);

        } catch (error) {
            console.error(`Failed to generate fix with model ${model}:`, error);
            
            // Try fallback model
            const fallbackModel = this.selectFallbackModel('code-generation', model);
            if (fallbackModel) {
                console.log(`Retrying with fallback model: ${fallbackModel}`);
                return this.generateSecurityFix(violation, context, { ...options, model: fallbackModel });
            }

            throw new Error(`AI fix generation failed: ${error.message}`);
        }
    }

    async explainViolation(
        violation: SecurityViolation,
        options: LocalAIOptions = {}
    ): Promise<SecurityExplanation> {
        this.ensureInitialized();

        const model = options.model || this.selectBestModel('explanation');
        console.log(`Explaining violation using model: ${model}`);

        try {
            const prompt = this.buildExplanationPrompt(violation);
            
            const response = await this.ollama.chat({
                model,
                messages: [
                    {
                        role: 'system',
                        content: POWERSHELL_SECURITY_EXPLANATION_PROMPT
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                options: {
                    temperature: options.temperature || 0.3,
                    top_p: 0.9,
                    num_predict: options.maxTokens || 800
                },
                stream: false
            });

            return this.parseExplanationResponse(response.message.content, violation);

        } catch (error) {
            console.error(`Failed to explain violation with model ${model}:`, error);
            
            // Try fallback model
            const fallbackModel = this.selectFallbackModel('explanation', model);
            if (fallbackModel) {
                console.log(`Retrying with fallback model: ${fallbackModel}`);
                return this.explainViolation(violation, { ...options, model: fallbackModel });
            }

            throw new Error(`AI explanation failed: ${error.message}`);
        }
    }

    private buildSecurityFixPrompt(violation: SecurityViolation, context: FixContext): string {
        return `# PowerShell Security Fix Request

## Violation Details
- **Rule**: ${violation.ruleId}
- **Severity**: ${violation.severity}
- **Description**: ${violation.description}
- **Line**: ${violation.lineNumber}
- **File**: ${violation.filePath}

## Code Context
\`\`\`powershell
${context.beforeLines.join('\n')}
>>> ${context.targetCode} <<<  # This line needs fixing
${context.afterLines.join('\n')}
\`\`\`

## Function Context
${context.functionContext ? `
- **Function Name**: ${context.functionContext.name}
- **Purpose**: ${context.functionContext.purpose}
- **Parameters**: ${context.functionContext.parameters.join(', ')}
- **Return Type**: ${context.functionContext.returnType || 'Unknown'}
` : 'No function context available'}

## Fix Requirements
1. **Security**: Fix the security violation while preserving functionality
2. **Compatibility**: Maintain PowerShell version compatibility
3. **Best Practices**: Follow PowerShell coding best practices
4. **Comments**: Add explanatory comments for the fix
5. **Testing**: Ensure the fix doesn't break existing functionality

## Response Format
Please provide ONLY the fixed PowerShell code in this format:

\`\`\`powershell
# Fixed code with explanatory comments
# Explain what was changed and why
\`\`\`

Generate the secure fix now:`;
    }

    private buildExplanationPrompt(violation: SecurityViolation): string {
        return `# PowerShell Security Violation Explanation

## Violation Details
- **Rule ID**: ${violation.ruleId}
- **Severity**: ${violation.severity}
- **Description**: ${violation.description}
- **File**: ${violation.filePath}
- **Line**: ${violation.lineNumber}

## Code Context
\`\`\`powershell
${violation.codeContext || 'No code context available'}
\`\`\`

## Explanation Request
Please provide a comprehensive explanation of this security violation that includes:

1. **What the violation is**: Clear explanation of the security issue
2. **Why it's dangerous**: Potential risks and attack vectors
3. **How to fix it**: Step-by-step remediation guidance
4. **Best practices**: General recommendations to prevent similar issues
5. **Examples**: If applicable, show secure alternatives

Make the explanation educational and accessible to developers of all skill levels.

Provide your explanation now:`;
    }

    private parseFixResponse(response: string, violation: SecurityViolation): AIFixResult {
        // Extract code blocks from response
        const codeBlockRegex = /```powershell\n([\s\S]*?)\n```/g;
        const matches = Array.from(response.matchAll(codeBlockRegex));
        
        if (matches.length === 0) {
            return {
                success: false,
                fixedCode: '',
                confidence: 0,
                explanation: 'No valid PowerShell code found in AI response',
                changes: []
            };
        }

        const fixedCode = matches[0][1].trim();
        
        // Calculate confidence based on response quality
        const confidence = this.calculateFixConfidence(response, fixedCode, violation);
        
        // Extract explanation from response
        const explanation = this.extractExplanation(response);
        
        // Analyze changes
        const changes = this.analyzeCodeChanges(violation.codeContext || '', fixedCode);

        return {
            success: true,
            fixedCode,
            confidence,
            explanation,
            changes
        };
    }

    private parseExplanationResponse(response: string, violation: SecurityViolation): SecurityExplanation {
        // Extract structured information from the response
        const sections = this.parseResponseSections(response);
        
        return {
            violation,
            explanation: sections.explanation || response,
            severity: violation.severity,
            mitigation: sections.mitigation || [],
            references: sections.references || [],
            confidence: this.calculateExplanationConfidence(response),
            educationalContent: sections.educational
        };
    }

    private selectBestModel(task: 'code-generation' | 'explanation' | 'analysis'): string {
        const taskModelMap = {
            'code-generation': ['codellama:7b-code', 'codellama:13b-instruct', 'phi3:mini'],
            'explanation': ['codellama:13b-instruct', 'mistral:7b-instruct', 'phi3:mini'],
            'analysis': ['phi3:mini', 'mistral:7b-instruct', 'codellama:7b-code']
        };

        const preferredModels = taskModelMap[task];

        // Find first available model
        for (const modelName of preferredModels) {
            const model = this.availableModels.get(modelName);
            if (model && model.status === 'available') {
                return modelName;
            }
        }

        // Fallback to any available model
        const anyAvailable = Array.from(this.availableModels.values())
            .find(m => m.status === 'available');

        if (!anyAvailable) {
            throw new Error('No local AI models available. Please download a model first.');
        }

        return anyAvailable.name;
    }

    async downloadModel(
        modelName: string,
        onProgress?: (progress: DownloadProgress) => void
    ): Promise<void> {
        console.log(`Starting download of model: ${modelName}`);

        // Update model status
        const model = this.availableModels.get(modelName);
        if (model) {
            model.status = 'downloading';
            this.availableModels.set(modelName, model);
        }

        try {
            const pullStream = await this.ollama.pull({
                model: modelName,
                stream: true
            });

            let totalSize = 0;
            let downloadedSize = 0;

            for await (const chunk of pullStream) {
                if (chunk.total) {
                    totalSize = chunk.total;
                }
                if (chunk.completed) {
                    downloadedSize = chunk.completed;
                }

                const progress: DownloadProgress = {
                    modelName,
                    status: 'downloading',
                    progress: totalSize > 0 ? (downloadedSize / totalSize) * 100 : 0,
                    totalSize,
                    downloadedSize,
                    stage: chunk.status || 'downloading'
                };

                if (onProgress) {
                    onProgress(progress);
                }

                this.emit('download-progress', progress);

                if (chunk.status === 'success') {
                    // Update model status
                    if (model) {
                        model.status = 'available';
                        model.size = totalSize;
                        this.availableModels.set(modelName, model);
                    }

                    console.log(`Model download completed: ${modelName}`);
                    
                    const finalProgress: DownloadProgress = {
                        modelName,
                        status: 'completed',
                        progress: 100,
                        totalSize,
                        downloadedSize: totalSize,
                        stage: 'completed'
                    };

                    if (onProgress) {
                        onProgress(finalProgress);
                    }

                    this.emit('download-complete', finalProgress);
                    break;
                }
            }

        } catch (error) {
            console.error(`Model download failed: ${modelName}`, error);

            // Update model status
            if (model) {
                model.status = 'error';
                this.availableModels.set(modelName, model);
            }

            const errorProgress: DownloadProgress = {
                modelName,
                status: 'error',
                progress: 0,
                totalSize: 0,
                downloadedSize: 0,
                stage: 'error',
                error: error.message
            };

            if (onProgress) {
                onProgress(errorProgress);
            }

            this.emit('download-error', errorProgress);
            throw error;
        }
    }

    async deleteModel(modelName: string): Promise<void> {
        console.log(`Deleting model: ${modelName}`);

        try {
            await this.ollama.delete({ model: modelName });
            
            // Remove from available models
            this.availableModels.delete(modelName);
            
            // Clear from cache
            this.modelCache.delete(modelName);
            
            console.log(`Model deleted successfully: ${modelName}`);
            this.emit('model-deleted', modelName);

        } catch (error) {
            console.error(`Failed to delete model ${modelName}:`, error);
            throw error;
        }
    }

    async getModelInfo(modelName: string): Promise<ModelInfo | null> {
        return this.availableModels.get(modelName) || null;
    }

    async getAvailableModels(): Promise<ModelInfo[]> {
        return Array.from(this.availableModels.values());
    }

    async checkOllamaStatus(): Promise<boolean> {
        try {
            await this.verifyOllamaAvailability();
            return true;
        } catch (error) {
            return false;
        }
    }

    private setupHealthMonitoring(): void {
        // Check Ollama health every 30 seconds
        this.healthCheckInterval = setInterval(async () => {
            const isHealthy = await this.checkOllamaStatus();
            
            if (!isHealthy) {
                this.emit('health-check-failed');
            }
        }, 30000);
    }

    private ensureInitialized(): void {
        if (!this.isInitialized) {
            throw new Error('LocalAIOrchestrator not initialized. Call initialize() first.');
        }
    }

    async shutdown(): Promise<void> {
        console.log('Shutting down Local AI Orchestrator...');

        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
        }

        // Clear caches
        this.modelCache.clear();
        
        this.isInitialized = false;
        this.emit('shutdown');

        console.log('Local AI Orchestrator shutdown completed');
    }

    // Additional utility methods for implementation...
}

// System prompts for AI models
const POWERSHELL_SECURITY_SYSTEM_PROMPT = `You are a PowerShell security expert. Your task is to analyze PowerShell code and provide secure fixes for security violations. Always prioritize security while maintaining functionality. Provide clear, well-commented code that follows PowerShell best practices.

Key principles:
1. Never execute or run potentially malicious code
2. Always validate inputs and sanitize outputs
3. Use secure PowerShell cmdlets and methods
4. Follow principle of least privilege
5. Add clear comments explaining security improvements

Respond only with the fixed PowerShell code in a code block, preceded by comments explaining the changes.`;

const POWERSHELL_SECURITY_EXPLANATION_PROMPT = `You are a PowerShell security educator. Your task is to explain security violations in PowerShell code in a clear, educational manner. Help developers understand not just what is wrong, but why it's dangerous and how to fix it.

Structure your explanations:
1. What: Clear description of the security issue
2. Why: Potential risks and attack vectors
3. How: Step-by-step remediation guidance
4. Best practices: Prevention strategies
5. Examples: Secure alternatives when applicable

Make explanations accessible to developers of all skill levels while being technically accurate.`;
```

---

## 📋 **Implementation Checklist**

### **Phase 3.3.1: Ollama Setup (Week 1)**

- [ ] Install and configure Ollama service
- [ ] Test basic model download and inference
- [ ] Implement health checking and monitoring
- [ ] Create model configuration management
- [ ] Set up development environment

### **Phase 3.3.2: AI Orchestrator (Week 2)**

- [ ] Implement LocalAIOrchestrator class
- [ ] Add model selection and fallback logic
- [ ] Create prompt engineering templates
- [ ] Implement response parsing and validation
- [ ] Add error handling and retry mechanisms

### **Phase 3.3.3: Model Management (Week 3)**

- [ ] Implement model download with progress tracking
- [ ] Add model caching and preloading
- [ ] Create model deletion and cleanup
- [ ] Implement model validation and verification
- [ ] Add storage optimization

### **Phase 3.3.4: UI Integration (Week 4)**

- [ ] Create AI configuration panel
- [ ] Add model download progress indicators
- [ ] Implement model selection interface
- [ ] Add AI status monitoring
- [ ] Create troubleshooting guides

### **Phase 3.3.5: Performance Optimization (Week 5)**

- [ ] Optimize model loading and inference
- [ ] Implement response caching
- [ ] Add concurrent request handling
- [ ] Optimize memory usage
- [ ] Performance testing and tuning

### **Phase 3.3.6: Security & Testing (Week 6)**

- [ ] Security audit of AI integration
- [ ] Test AI response quality and accuracy
- [ ] Validate prompt injection protection
- [ ] Test offline functionality
- [ ] Cross-platform compatibility testing

### **Phase 3.3.7: Documentation & Deployment (Week 7-8)**

- [ ] Create AI setup and configuration guides
- [ ] Document model recommendations
- [ ] Add troubleshooting documentation
- [ ] Create deployment scripts
- [ ] User training materials

---

## 🔒 **Security Considerations**

### **Prompt Security**

1. **Injection Protection**: Validate and sanitize all user inputs
2. **Context Isolation**: Separate analysis context from system prompts
3. **Output Validation**: Verify AI responses before execution
4. **Rate Limiting**: Prevent abuse of AI services

### **Model Security**

1. **Model Verification**: Validate model integrity and authenticity
2. **Access Control**: Restrict model download and deletion
3. **Resource Limits**: Prevent resource exhaustion attacks
4. **Audit Logging**: Log all AI operations for security review

### **Data Protection**

1. **Local Processing**: All AI processing happens locally
2. **No Data Transmission**: No code sent to external services
3. **Temporary Storage**: Secure cleanup of temporary data
4. **Memory Protection**: Clear sensitive data from memory

---

## 📊 **Performance Metrics**

### **AI Performance**

- **Model Loading**: < 30 seconds for 7B models
- **Inference Time**: < 10 seconds for typical fixes
- **Memory Usage**: < 8GB for 13B models
- **CPU Usage**: < 80% during inference

### **Quality Metrics**

- **Fix Accuracy**: > 90% for common violations
- **Explanation Quality**: > 95% user satisfaction
- **Response Relevance**: > 95% contextually appropriate
- **Code Correctness**: > 98% syntactically valid

### **System Metrics**

- **Model Storage**: < 50GB for recommended models
- **Download Speed**: Limited by network bandwidth
- **Concurrent Users**: Support up to 10 simultaneous requests
- **Uptime**: > 99.9% availability when models loaded

---

**Next Phase**: [Phase 3.4: Enterprise Governance](phase-3-4-enterprise-governance.md)

---

*This local AI integration provides enterprise-grade offline capabilities while maintaining the highest standards of security and performance.*
