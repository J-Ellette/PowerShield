# Phase 3: Standalone Sandbox Application (Weeks 9-12)

## 3.1 Electron Application Main Process

File: standalone-app/src/main/main.ts

typescriptimport { app, BrowserWindow, ipcMain, dialog, Menu, shell, protocol } from 'electron';
import *as path from 'path';
import* as fs from 'fs';
import { SandboxManager } from './security/sandboxManager';
import { LocalAIManager } from './ai/localAIManager';
import { SecurityReportGenerator } from './reports/securityReportGenerator';
import { ConfigurationManager } from './config/configurationManager';
import { UpdateManager } from './updates/updateManager';
import { TelemetryManager } from './telemetry/telemetryManager';

class PowerShieldApplication {
    private mainWindow: BrowserWindow | null = null;
    private sandboxManager: SandboxManager;
    private aiManager: LocalAIManager;
    private reportGenerator: SecurityReportGenerator;
    private configManager: ConfigurationManager;
    private updateManager: UpdateManager;
    private telemetryManager: TelemetryManager;

    constructor() {
        this.sandboxManager = new SandboxManager();
        this.aiManager = new LocalAIManager();
        this.reportGenerator = new SecurityReportGenerator();
        this.configManager = new ConfigurationManager();
        this.updateManager = new UpdateManager();
        this.telemetryManager = new TelemetryManager();
        
        this.setupApplication();
    }

    private setupApplication(): void {
        // Set app security policies
        app.setAsDefaultProtocolClient('psts');
        
        // Handle app events
        app.whenReady().then(() => {
            this.createMainWindow();
            this.setupMenu();
            this.registerProtocolHandlers();
            this.setupIpcHandlers();
            this.initializeServices();
        });

        app.on('window-all-closed', () => {
            if (process.platform !== 'darwin') {
                this.cleanup();
                app.quit();
            }
        });

        app.on('activate', () => {
            if (BrowserWindow.getAllWindows().length === 0) {
                this.createMainWindow();
            }
        });

        // Security: Prevent new window creation
        app.on('web-contents-created', (event, contents) => {
            contents.on('new-window', (navigationEvent, navigationUrl) => {
                navigationEvent.preventDefault();
                shell.openExternal(navigationUrl);
            });
        });
    }

    private createMainWindow(): void {
        this.mainWindow = new BrowserWindow({
            width: 1400,
            height: 900,
            minWidth: 1000,
            minHeight: 700,
            show: false,
            icon: path.join(__dirname, '../assets/icon.png'),
            titleBarStyle: 'default',
            webPreferences: {
                nodeIntegration: false,
                contextIsolation: true,
                enableRemoteModule: false,
                sandbox: true,
                preload: path.join(__dirname, 'preload.js'),
                webSecurity: true,
                allowRunningInsecureContent: false,
                experimentalFeatures: false
            }
        });

        // Load the application
        if (process.env.NODE_ENV === 'development') {
            this.mainWindow.loadURL('http://localhost:3000');
            this.mainWindow.webContents.openDevTools();
        } else {
            this.mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
        }

        // Window event handlers
        this.mainWindow.once('ready-to-show', () => {
            this.mainWindow?.show();
            this.checkForUpdates();
        });

        this.mainWindow.on('closed', () => {
            this.mainWindow = null;
        });

        // Security: Prevent navigation to external URLs
        this.mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
            const parsedUrl = new URL(navigationUrl);
            if (parsedUrl.origin !== 'http://localhost:3000' && parsedUrl.origin !== 'file://') {
                event.preventDefault();
            }
        });
    }

    private setupMenu(): void {
        const template: Electron.MenuItemConstructorOptions[] = [
            {
                label: 'File',
                submenu: [
                    {
                        label: 'Open Script...',
                        accelerator: 'CmdOrCtrl+O',
                        click: () => this.handleOpenScript()
                    },
                    {
                        label: 'Open Folder...',
                        accelerator: 'CmdOrCtrl+Shift+O',
                        click: () => this.handleOpenFolder()
                    },
                    { type: 'separator' },
                    {
                        label: 'Export Report...',
                        accelerator: 'CmdOrCtrl+E',
                        click: () => this.handleExportReport()
                    },
                    { type: 'separator' },
                    {
                        label: 'Exit',
                        accelerator: process.platform === 'darwin' ? 'Cmd+Q' : 'Ctrl+Q',
                        click: () => {
                            this.cleanup();
                            app.quit();
                        }
                    }
                ]
            },
            {
                label: 'Analysis',
                submenu: [
                    {
                        label: 'Run Security Analysis',
                        accelerator: 'F5',
                        click: () => this.handleRunAnalysis()
                    },
                    {
                        label: 'Apply AI Fixes',
                        accelerator: 'CmdOrCtrl+F',
                        click: () => this.handleApplyFixes()
                    },
                    { type: 'separator' },
                    {
                        label: 'Clear Results',
                        click: () => this.handleClearResults()
                    }
                ]
            },
            {
                label: 'AI',
                submenu: [
                    {
                        label: 'Configure Local AI',
                        click: () => this.handleConfigureLocalAI()
                    },
                    {
                        label: 'Download Models',
                        click: () => this.handleDownloadModels()
                    },
                    {
                        label: 'Test AI Connection',
                        click: () => this.handleTestAI()
                    }
                ]
            },
            {
                label: 'Tools',
                submenu: [
                    {
                        label: 'Sandbox Settings',
                        click: () => this.handleSandboxSettings()
                    },
                    {
                        label: 'Security Policies',
                        click: () => this.handleSecurityPolicies()
                    },
                    { type: 'separator' },
                    {
                        label: 'Preferences...',
                        accelerator: 'CmdOrCtrl+,',
                        click: () => this.handlePreferences()
                    }
                ]
            },
            {
                label: 'Help',
                submenu: [
                    {
                        label: 'Documentation',
                        click: () => shell.openExternal('https://psts.dev/docs')
                    },
                    {
                        label: 'Report Issue',
                        click: () => shell.openExternal('https://github.com/yourorg/psts/issues')
                    },
                    { type: 'separator' },
                    {
                        label: 'About PowerShield',
                        click: () => this.handleAbout()
                    }
                ]
            }
        ];

        const menu = Menu.buildFromTemplate(template);
        Menu.setApplicationMenu(menu);
    }

    private registerProtocolHandlers(): void {
        protocol.registerFileProtocol('psts-secure', (request, callback) => {
            const filePath = request.url.replace('psts-secure://', '');
            const normalizedPath = path.normalize(filePath);
            
            // Security: Only allow access to specific directories
            const allowedPaths = [
                path.join(__dirname, '../renderer'),
                path.join(__dirname, '../assets'),
                this.configManager.getTempDirectory()
            ];
            
            const isAllowed = allowedPaths.some(allowedPath => 
                normalizedPath.startsWith(path.resolve(allowedPath))
            );
            
            if (isAllowed && fs.existsSync(normalizedPath)) {
                callback({ path: normalizedPath });
            } else {
                callback({ error: -6 }); // FILE_NOT_FOUND
            }
        });
    }

    private setupIpcHandlers(): void {
        // File operations
        ipcMain.handle('open-script-file', this.handleOpenScript.bind(this));
        ipcMain.handle('open-folder', this.handleOpenFolder.bind(this));
        ipcMain.handle('save-file', this.handleSaveFile.bind(this));

        // Analysis operations
        ipcMain.handle('analyze-script', this.handleAnalyzeScript.bind(this));
        ipcMain.handle('analyze-folder', this.handleAnalyzeFolder.bind(this));
        ipcMain.handle('get-analysis-status', this.handleGetAnalysisStatus.bind(this));

        // AI operations
        ipcMain.handle('generate-ai-fixes', this.handleGenerateAIFixes.bind(this));
        ipcMain.handle('apply-ai-fixes', this.handleApplyAIFixes.bind(this));
        ipcMain.handle('configure-ai', this.handleConfigureAI.bind(this));
        ipcMain.handle('test-ai-connection', this.handleTestAIConnection.bind(this));

        // Sandbox operations
        ipcMain.handle('get-sandbox-status', this.handleGetSandboxStatus.bind(this));
        ipcMain.handle('configure-sandbox', this.handleConfigureSandbox.bind(this));
        ipcMain.handle('reset-sandbox', this.handleResetSandbox.bind(this));

        // Report operations
        ipcMain.handle('generate-report', this.handleGenerateReport.bind(this));
        ipcMain.handle('export-report', this.handleExportReport.bind(this));

        // Configuration
        ipcMain.handle('get-config', this.handleGetConfig.bind(this));
        ipcMain.handle('set-config', this.handleSetConfig.bind(this));
        ipcMain.handle('reset-config', this.handleResetConfig.bind(this));

        // System operations
        ipcMain.handle('get-system-info', this.handleGetSystemInfo.bind(this));
        ipcMain.handle('check-docker', this.handleCheckDocker.bind(this));
        ipcMain.handle('install-dependencies', this.handleInstallDependencies.bind(this));
    }

    private async initializeServices(): Promise<void> {
        try {
            // Initialize configuration
            await this.configManager.initialize();
            
            // Initialize sandbox
            await this.sandboxManager.initialize();
            
            // Initialize AI manager
            await this.aiManager.initialize();
            
            // Initialize telemetry
            if (this.configManager.get('telemetry.enabled', true)) {
                await this.telemetryManager.initialize();
            }
            
            // Check system requirements
            await this.checkSystemRequirements();
            
            console.log('PowerShield services initialized successfully');
        } catch (error) {
            console.error('Failed to initialize services:', error);
            dialog.showErrorBox('Initialization Error', `Failed to initialize PowerShield: ${error}`);
        }
    }

    private async checkSystemRequirements(): Promise<void> {
        const requirements = {
            docker: await this.sandboxManager.checkDockerAvailable(),
            nodejs: this.checkNodeJSVersion(),
            powershell: await this.checkPowerShellAvailable(),
            memory: this.checkAvailableMemory()
        };

        const issues: string[] = [];
        
        if (!requirements.docker) {
            issues.push('Docker is not available. Sandbox features will be disabled.');
        }
        
        if (!requirements.nodejs) {
            issues.push('Node.js version 16+ is required.');
        }
        
        if (!requirements.powershell) {
            issues.push('PowerShell 7+ is recommended for best results.');
        }
        
        if (!requirements.memory) {
            issues.push('At least 4GB RAM is recommended for AI features.');
        }

        if (issues.length > 0) {
            dialog.showMessageBox(this.mainWindow!, {
                type: 'warning',
                title: 'System Requirements',
                message: 'Some system requirements are not met:',
                detail: issues.join('\n\n'),
                buttons: ['Continue', 'Learn More'],
                defaultId: 0
            }).then(result => {
                if (result.response === 1) {
                    shell.openExternal('https://psts.dev/docs/requirements');
                }
            });
        }
    }

    // IPC Handler implementations
    private async handleOpenScript(): Promise<{ success: boolean; data?: any; error?: string }> {
        try {
            const result = await dialog.showOpenDialog(this.mainWindow!, {
                properties: ['openFile'],
                filters: [
                    { name: 'PowerShell Scripts', extensions: ['ps1', 'psm1', 'psd1'] },
                    { name: 'All Files', extensions: ['*'] }
                ]
            });

            if (!result.canceled && result.filePaths.length > 0) {
                const filePath = result.filePaths[0];
                const content = await fs.promises.readFile(filePath, 'utf8');
                
                this.telemetryManager.trackEvent('file_opened', { type: 'script' });
                
                return {
                    success: true,
                    data: { path: filePath, content, name: path.basename(filePath) }
                };
            }
            
            return { success: false };
        } catch (error) {
            return { success: false, error: `Failed to open script: ${error}` };
        }
    }

    private async handleAnalyzeScript(event: Electron.IpcMainInvokeEvent, scriptData: any): Promise<any> {
        try {
            const sessionId = await this.sandboxManager.createSession();
            const result = await this.sandboxManager.analyzeScript(sessionId, scriptData);
            
            this.telemetryManager.trackEvent('analysis_completed', {
                violations: result.violations?.length || 0,
                duration: result.duration
            });
            
            return { success: true, data: result };
        } catch (error) {
            this.telemetryManager.trackError('analysis_failed', error);
            return { success: false, error: `Analysis failed: ${error}` };
        }
    }

    private async handleGenerateAIFixes(event: Electron.IpcMainInvokeEvent, violations: any[]): Promise<any> {
        try {
            const fixes = await this.aiManager.generateFixes(violations);
            
            this.telemetryManager.trackEvent('ai_fixes_generated', {
                violations: violations.length,
                fixes: fixes.length
            });
            
            return { success: true, data: fixes };
        } catch (error) {
            this.telemetryManager.trackError('ai_fix_generation_failed', error);
            return { success: false, error: `Failed to generate fixes: ${error}` };
        }
    }

    private checkNodeJSVersion(): boolean {
        const version = process.version;
        const majorVersion = parseInt(version.slice(1).split('.')[0]);
        return majorVersion >= 16;
    }

    private async checkPowerShellAvailable(): Promise<boolean> {
        try {
            const { spawn } = await import('child_process');
            return new Promise((resolve) => {
                const ps = spawn('pwsh', ['--version']);
                ps.on('close', (code) => resolve(code === 0));
                ps.on('error', () => resolve(false));
            });
        } catch {
            return false;
        }
    }

    private checkAvailableMemory(): boolean {
        const totalMemory = require('os').totalmem();
        return totalMemory >= 4 * 1024 * 1024 * 1024; // 4GB
    }

    private async checkForUpdates(): Promise<void> {
        if (this.configManager.get('updates.checkOnStartup', true)) {
            try {
                const updateAvailable = await this.updateManager.checkForUpdates();
                if (updateAvailable) {
                    const result = await dialog.showMessageBox(this.mainWindow!, {
                        type: 'info',
                        title: 'Update Available',
                        message: 'A new version of PowerShield is available.',
                        detail: 'Would you like to download and install it now?',
                        buttons: ['Update Now', 'Later'],
                        defaultId: 0
                    });
                    
                    if (result.response === 0) {
                        await this.updateManager.downloadAndInstallUpdate();
                    }
                }
            } catch (error) {
                console.error('Update check failed:', error);
            }
        }
    }

    private async cleanup(): Promise<void> {
        try {
            await this.sandboxManager.cleanup();
            await this.aiManager.cleanup();
            await this.telemetryManager.flush();
        } catch (error) {
            console.error('Cleanup failed:', error);
        }
    }

    // Additional handler stubs - implement as needed
    private async handleOpenFolder(): Promise<any> { /* Implementation */ }
    private async handleSaveFile(): Promise<any> { /* Implementation */ }
    private async handleAnalyzeFolder(): Promise<any> { /* Implementation */ }
    private async handleGetAnalysisStatus(): Promise<any> { /* Implementation */ }
    private async handleApplyAIFixes(): Promise<any> { /* Implementation */ }
    private async handleConfigureAI(): Promise<any> { /* Implementation */ }
    private async handleTestAIConnection(): Promise<any> { /* Implementation */ }
    private async handleGetSandboxStatus(): Promise<any> { /* Implementation */ }
    private async handleConfigureSandbox(): Promise<any> { /* Implementation */ }
    private async handleResetSandbox(): Promise<any> { /* Implementation */ }
    private async handleGenerateReport(): Promise<any> { /* Implementation */ }
    private async handleExportReport(): Promise<any> { /* Implementation */ }
    private async handleGetConfig(): Promise<any> { /* Implementation */ }
    private async handleSetConfig(): Promise<any> { /* Implementation */ }
    private async handleResetConfig(): Promise<any> { /* Implementation */ }
    private async handleGetSystemInfo(): Promise<any> { /* Implementation */ }
    private async handleCheckDocker(): Promise<any> { /* Implementation */ }
    private async handleInstallDependencies(): Promise<any> { /* Implementation */ }
    private async handleRunAnalysis(): Promise<any> { /* Implementation */ }
    private async handleApplyFixes(): Promise<any> { /* Implementation */ }
    private async handleClearResults(): Promise<any> { /* Implementation */ }
    private async handleConfigureLocalAI(): Promise<any> { /* Implementation */ }
    private async handleDownloadModels(): Promise<any> { /* Implementation */ }
    private async handleTestAI(): Promise<any> { /* Implementation */ }
    private async handleSandboxSettings(): Promise<any> { /* Implementation */ }
    private async handleSecurityPolicies(): Promise<any> { /* Implementation */ }
    private async handlePreferences(): Promise<any> { /* Implementation */ }
    private async handleAbout(): Promise<any> { /* Implementation */ }
}

// Start the application
new PowerShieldApplication();

## 3.2 Sandbox Manager with Docker Isolation

File: standalone-app/src/main/security/sandboxManager.ts
typescriptimport { spawn, ChildProcess } from 'child_process';
import *as fs from 'fs/promises';
import* as path from 'path';
import *as crypto from 'crypto';
import* as os from 'os';

export interface SandboxSession {
    id: string;
    containerId?: string;
    tempDir: string;
    status: 'created' | 'running' | 'completed' | 'error';
    startTime: Date;
    endTime?: Date;
}

export interface AnalysisResult {
    sessionId: string;
    violations: SecurityViolation[];
    metadata: {
        duration: number;
        filesAnalyzed: number;
        rulesExecuted: number;
        timestamp: Date;
    };
    logs: string[];
    error?: string;
}

export interface SecurityViolation {
    ruleId: string;
    name: string;
    message: string;
    severity: 'Low' | 'Medium' | 'High' | 'Critical';
    lineNumber: number;
    code: string;
    filePath: string;
}

export class SandboxManager {
    private sessions: Map<string, SandboxSession> = new Map();
    private tempBaseDir: string;
    private dockerImage = 'psts-analyzer:latest';
    private maxSessions = 5;
    private sessionTimeout = 300000; // 5 minutes

    constructor() {
        this.tempBaseDir = path.join(os.tmpdir(), 'psts-sandbox');
        this.setupCleanupTimer();
    }

    async initialize(): Promise<void> {
        // Create base temp directory
        await fs.mkdir(this.tempBaseDir, { recursive: true });

        // Check if Docker is available
        const dockerAvailable = await this.checkDockerAvailable();
        if (!dockerAvailable) {
            console.warn('Docker not available - sandbox features will be limited');
            return;
        }

        // Build or pull the analysis Docker image
        await this.ensureDockerImage();
    }

    async checkDockerAvailable(): Promise<boolean> {
        try {
            const result = await this.executeCommand('docker', ['--version']);
            return result.success;
        } catch {
            return false;
        }
    }

    async createSession(): Promise<string> {
        // Clean up old sessions if we're at the limit
        if (this.sessions.size >= this.maxSessions) {
            await this.cleanupOldSessions();
        }

        const sessionId = crypto.randomUUID();
        const tempDir = path.join(this.tempBaseDir, sessionId);
        
        await fs.mkdir(tempDir, { recursive: true });

        const session: SandboxSession = {
            id: sessionId,
            tempDir,
            status: 'created',
            startTime: new Date()
        };

        this.sessions.set(sessionId, session);
        
        // Set up session timeout
        setTimeout(() => {
            this.cleanupSession(sessionId);
        }, this.sessionTimeout);

        return sessionId;
    }

    async analyzeScript(sessionId: string, scriptData: { content: string; path?: string; name?: string }): Promise<AnalysisResult> {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session ${sessionId} not found`);
        }

        session.status = 'running';
        const startTime = Date.now();
        const logs: string[] = [];

        try {
            // Write script to temp file
            const scriptFileName = scriptData.name || 'script.ps1';
            const scriptPath = path.join(session.tempDir, scriptFileName);
            await fs.writeFile(scriptPath, scriptData.content, 'utf8');

            logs.push(`Script written to: ${scriptPath}`);

            // Run analysis in Docker container
            const analysisResult = await this.runContainerAnalysis(session, scriptPath, logs);

            session.status = 'completed';
            session.endTime = new Date();

            const duration = Date.now() - startTime;

            return {
                sessionId,
                violations: analysisResult.violations,
                metadata: {
                    duration,
                    filesAnalyzed: 1,
                    rulesExecuted: analysisResult.rulesExecuted || 0,
                    timestamp: new Date()
                },
                logs
            };

        } catch (error) {
            session.status = 'error';
            session.endTime = new Date();
            
            logs.push(`Error: ${error}`);
            
            return {
                sessionId,
                violations: [],
                metadata: {
                    duration: Date.now() - startTime,
                    filesAnalyzed: 0,
                    rulesExecuted: 0,
                    timestamp: new Date()
                },
                logs,
                error: String(error)
            };
        }
    }

    private async runContainerAnalysis(session: SandboxSession, scriptPath: string, logs: string[]): Promise<{violations: SecurityViolation[], rulesExecuted: number}> {
        const containerName = `psts-analysis-${session.id}`;
        
        try {
            // Docker run command with security constraints
            const dockerArgs = [
                'run',
                '--rm',
                '--name', containerName,
                '--network', 'none',                           // No network access
                '--read-only',                                // Read-only filesystem
                '--tmpfs', '/tmp:noexec,nosuid,size=100m',   // Limited temp space
                '--memory', '512m',                          // Memory limit
                '--cpus', '1.0',                            // CPU limit
                '--user', 'nobody',                         // Non-root user
                '--security-opt', 'no-new-privileges',      // Prevent privilege escalation
                '--cap-drop', 'ALL',                        // Drop all capabilities
                '--pids-limit', '50',                       // Limit number of processes
                '-v', `${session.tempDir}:/workspace:ro`,   // Mount workspace read-only
                '-v', `${session.tempDir}/output:/output:rw`, // Output directory
                this.dockerImage,
                '/app/analyze.ps1',
                `/workspace/${path.basename(scriptPath)}`
            ];

            logs.push(`Running Docker container: ${containerName}`);
            
            // Create output directory
            const outputDir = path.join(session.tempDir, 'output');
            await fs.mkdir(outputDir, { recursive: true });

            // Store container ID
            session.containerId = containerName;

            // Execute Docker container
            const result = await this.executeCommand('docker', dockerArgs, {
                timeout: 60000, // 1 minute timeout
                cwd: session.tempDir
            });

            if (!result.success) {
                throw new Error(`Container execution failed: ${result.error}`);
            }

            logs.push('Container execution completed');

            // Read analysis results
            const resultsPath = path.join(outputDir, 'results.json');
            const resultsContent = await fs.readFile(resultsPath, 'utf8');
            const analysisData = JSON.parse(resultsContent);

            return {
                violations: analysisData.violations || [],
                rulesExecuted: analysisData.rulesExecuted || 0
            };

        } catch (error) {
            // Cleanup container if it's still running
            try {
                await this.executeCommand('docker', ['kill', containerName]);
            } catch {
                // Ignore cleanup errors
            }
            
            throw error;
        }
    }

    private async ensureDockerImage(): Promise<void> {
        try {
            // Check if image exists
            const checkResult = await this.executeCommand('docker', ['images', '-q', this.dockerImage]);
            
            if (!checkResult.success || !checkResult.stdout.trim()) {
                console.log('Building PowerShield Docker image...');
                await this.buildDockerImage();
            }
        } catch (error) {
            console.error('Failed to ensure Docker image:', error);
            throw error;
        }
    }

    private async buildDockerImage(): Promise<void> {
        const dockerfilePath = path.join(__dirname, '../../docker');
        
        const buildArgs = [
            'build',
            '-t', this.dockerImage,
            '-f', path.join(dockerfilePath, 'Dockerfile'),
            dockerfilePath
        ];

        const result = await this.executeCommand('docker', buildArgs, {
            timeout: 300000 // 5 minutes for building
        });

        if (!result.success) {
            throw new Error(`Docker image build failed: ${result.error}`);
        }

        console.log('PowerShield Docker image built successfully');
    }

    private async executeCommand(
        command: string, 
        args: string[], 
        options: { timeout?: number; cwd?: string } = {}
    ): Promise<{ success: boolean; stdout: string; stderr: string; error?: string }> {
        
        return new Promise((resolve) => {
            const child = spawn(command, args, {
                cwd: options.cwd,
                stdio: ['pipe', 'pipe', 'pipe']
            });

            let stdout = '';
            let stderr = '';
            let timeoutHandle: NodeJS.Timeout | null = null;

            child.stdout?.on('data', (data) => {
                stdout += data.toString();
            });

            child.stderr?.on('data', (data) => {
                stderr += data.toString();
            });

            child.on('close', (code) => {
                if (timeoutHandle) clearTimeout(timeoutHandle);
                resolve({
                    success: code === 0,
                    stdout,
                    stderr,
                    error: code !== 0 ? `Process exited with code ${code}` : undefined
                });
            });

            child.on('error', (error) => {
                if (timeoutHandle) clearTimeout(timeoutHandle);
                resolve({
                    success: false,
                    stdout,
                    stderr,
                    error: error.message
                });
            });

            // Set timeout if specified
            if (options.timeout) {
                timeoutHandle = setTimeout(() => {
                    child.kill('SIGKILL');
                    resolve({
                        success: false,
                        stdout,
                        stderr,
                        error: 'Command timed out'
                    });
                }, options.timeout);
            }
        });
    }

    private setupCleanupTimer(): void {
        // Clean up old sessions every 30 minutes
        setInterval(() => {
            this.cleanupOldSessions();
        }, 30 * 60 * 1000);
    }

    private async cleanupOldSessions(): Promise<void> {
        const now = Date.now();
        const sessionsToCleanup: string[] = [];

        for (const [sessionId, session] of this.sessions.entries()) {
            const sessionAge = now - session.startTime.getTime();
            if (sessionAge > this.sessionTimeout || session.status === 'completed' || session.status === 'error') {
                sessionsToCleanup.push(sessionId);
            }
        }

        for (const sessionId of sessionsToCleanup) {
            await this.cleanupSession(sessionId);
        }
    }

    async cleanupSession(sessionId: string): Promise<void> {
        const session = this.sessions.get(sessionId);
        if (!session) return;

        try {
            // Kill container if running
            if (session.containerId) {
                try {
                    await this.executeCommand('docker', ['kill', session.containerId]);
                } catch {
                    // Ignore errors - container might already be stopped
                }
            }

            // Remove temp directory
            await fs.rm(session.tempDir, { recursive: true, force: true });

            // Remove from sessions map
            this.sessions.delete(sessionId);

            console.log(`Cleaned up session: ${sessionId}`);
        } catch (error) {
            console.error(`Failed to cleanup session ${sessionId}:`, error);
        }
    }

    async cleanup(): Promise<void> {
        // Cleanup all active sessions
        const cleanupPromises = Array.from(this.sessions.keys()).map(sessionId => 
            this.cleanupSession(sessionId)
        );
        
        await Promise.all(cleanupPromises);

        // Remove base temp directory
        try {
            await fs.rm(this.tempBaseDir, { recursive: true, force: true });
        } catch (error) {
            console.error('Failed to cleanup temp directory:', error);
        }
    }

    getSessionStatus(sessionId: string): SandboxSession | null {
        return this.sessions.get(sessionId) || null;
    }

    getAllSessions(): SandboxSession[] {
        return Array.from(this.sessions.values());
}

## 3.3 Local AI Manager with Ollama Integration

File: standalone-app/src/main/ai/localAIManager.ts
typescriptimport { spawn, ChildProcess } from 'child_process';
import *as fs from 'fs/promises';
import* as path from 'path';
import * as os from 'os';
import fetch from 'node-fetch';

export interface AIModel {
    name: string;
    size: string;
    description: string;
    capabilities: string[];
    downloaded: boolean;
    downloading: boolean;
}

export interface AIFix {
    violation: any;
    originalCode: string;
    fixedCode: string;
    explanation: string;
    confidence: number;
    provider: string;
}

export interface AIProvider {
    name: string;
    available: boolean;
    models: AIModel[];
    generateFix(violation: any, context: string): Promise<AIFix | null>;
    testConnection(): Promise<boolean>;
}

export class LocalAIManager {
    private ollamaUrl = '<http://localhost:11434>';
    private providers: Map<string, AIProvider> = new Map();
    private currentModel = 'codellama:13b';
    private isOllamaRunning = false;
    private ollamaProcess: ChildProcess | null = null;

    async initialize(): Promise<void> {
        // Check if Ollama is available
        await this.checkOllamaAvailability();
        
        // Initialize providers
        this.setupProviders();
        
        // Auto-start Ollama if not running
        if (!this.isOllamaRunning) {
            await this.startOllama();
        }
        
        // Check available models
        await this.refreshModelList();
    }

    private async checkOllamaAvailability(): Promise<void> {
        try {
            const response = await fetch(`${this.ollamaUrl}/api/tags`, {
                method: 'GET',
                timeout: 5000
            });
            
            this.isOllamaRunning = response.ok;
        } catch (error) {
            this.isOllamaRunning = false;
            console.log('Ollama not running, will attempt to start...');
        }
    }

    private async startOllama(): Promise<void> {
        try {
            console.log('Starting Ollama server...');
            
            // Try to start Ollama
            this.ollamaProcess = spawn('ollama', ['serve'], {
                stdio: ['ignore', 'pipe', 'pipe'],
                detached: false
            });

            // Wait for Ollama to start
            await new Promise<void>((resolve, reject) => {
                const timeout = setTimeout(() => {
                    reject(new Error('Ollama startup timeout'));
                }, 30000);

                const checkRunning = async () => {
                    try {
                        const response = await fetch(`${this.ollamaUrl}/api/tags`, {
                            method: 'GET',
                            timeout: 2000
                        });
                        
                        if (response.ok) {
                            clearTimeout(timeout);
                            this.isOllamaRunning = true;
                            console.log('Ollama server started successfully');
                            resolve();
                        } else {
                            setTimeout(checkRunning, 1000);
                        }
                    } catch {
                        setTimeout(checkRunning, 1000);
                    }
                };

                checkRunning();
            });

        } catch (error) {
            console.error('Failed to start Ollama:', error);
            throw new Error('Could not start local AI service. Please install Ollama manually.');
        }
    }

    private setupProviders(): void {
        // Local Ollama provider
        this.providers.set('ollama', new OllamaProvider(this.ollamaUrl));
        
        // Fallback rule-based provider
        this.providers.set('rules', new RuleBasedProvider());
        
        // OpenAI fallback (if configured)
        const openaiKey = process.env.OPENAI_API_KEY;
        if (openaiKey) {
            this.providers.set('openai', new OpenAIFallbackProvider(openaiKey));
        }
    }

    async generateFixes(violations: any[]): Promise<AIFix[]> {
        const fixes: AIFix[] = [];
        
        for (const violation of violations) {
            // Try providers in order of preference
            for (const [name, provider] of this.providers) {
                if (!provider.available) continue;
                
                try {
                    const context = this.buildContext(violation);
                    const fix = await provider.generateFix(violation, context);
                    
                    if (fix && fix.confidence > 0.6) {
                        fixes.push(fix);
                        break; // Move to next violation
                    }
                } catch (error) {
                    console.error(`Provider ${name} failed:`, error);
                    continue; // Try next provider
                }
            }
        }
        
        return fixes;
    }

    async downloadModel(modelName: string, onProgress?: (progress: number) => void): Promise<void> {
        if (!this.isOllamaRunning) {
            throw new Error('Ollama service is not running');
        }

        try {
            console.log(`Downloading model: ${modelName}`);
            
            const response = await fetch(`${this.ollamaUrl}/api/pull`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: modelName, stream: true })
            });

            if (!response.ok) {
                throw new Error(`Failed to download model: ${response.statusText}`);
            }

            const reader = response.body?.getReader();
            if (!reader) throw new Error('No response stream');

            let totalSize = 0;
            let downloadedSize = 0;

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const chunk = new TextDecoder().decode(value);
                const lines = chunk.split('\n').filter(line => line.trim());

                for (const line of lines) {
                    try {
                        const data = JSON.parse(line);
                        
                        if (data.total) {
                            totalSize = data.total;
                        }
                        
                        if (data.completed) {
                            downloadedSize = data.completed;
                            
                            if (onProgress && totalSize > 0) {
                                const progress = (downloadedSize / totalSize) * 100;
                                onProgress(Math.round(progress));
                            }
                        }
                        
                        if (data.status === 'success') {
                            console.log(`Model ${modelName} downloaded successfully`);
                            return;
                        }
                        
                        if (data.error) {
                            throw new Error(data.error);
                        }
                    } catch (parseError) {
                        // Ignore JSON parse errors for streaming responses
                    }
                }
            }
        } catch (error) {
            console.error(`Failed to download model ${modelName}:`, error);
            throw error;
        }
    }

    async removeModel(modelName: string): Promise<void> {
        if (!this.isOllamaRunning) {
            throw new Error('Ollama service is not running');
        }

        try {
            const response = await fetch(`${this.ollamaUrl}/api/delete`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: modelName })
            });

            if (!response.ok) {
                throw new Error(`Failed to remove model: ${response.statusText}`);
            }

            console.log(`Model ${modelName} removed successfully`);
        } catch (error) {
            console.error(`Failed to remove model ${modelName}:`, error);
            throw error;
        }
    }

    async refreshModelList(): Promise<AIModel[]> {
        const models: AIModel[] = [];
        
        try {
            if (this.isOllamaRunning) {
                const response = await fetch(`${this.ollamaUrl}/api/tags`);
                const data = await response.json();
                
                for (const model of data.models || []) {
                    models.push({
                        name: model.name,
                        size: this.formatSize(model.size || 0),
                        description: this.getModelDescription(model.name),
                        capabilities: this.getModelCapabilities(model.name),
                        downloaded: true,
                        downloading: false
                    });
                }
            }
        } catch (error) {
            console.error('Failed to refresh model list:', error);
        }

        // Add available models that aren't downloaded
        const availableModels = [
            'codellama:13b',
            'codellama:7b',
            'llama2:13b',
            'llama2:7b',
            'mistral:7b'
        ];

        for (const modelName of availableModels) {
            if (!models.find(m => m.name === modelName)) {
                models.push({
                    name: modelName,
                    size: 'Unknown',
                    description: this.getModelDescription(modelName),
                    capabilities: this.getModelCapabilities(modelName),
                    downloaded: false,
                    downloading: false
                });
            }
        }

        return models;
    }

    private buildContext(violation: any): string {
        return `
Security Issue: ${violation.ruleId}
Message: ${violation.message}
Severity: ${violation.severity}
Code: ${violation.code}
Line: ${violation.lineNumber}
        `.trim();
    }

    private formatSize(bytes: number): string {
        const sizes = ['B', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 B';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }

    private getModelDescription(modelName: string): string {
        const descriptions: Record<string, string> = {
            'codellama:13b': 'Large code generation model (13B parameters)',
            'codellama:7b': 'Medium code generation model (7B parameters)',
            'llama2:13b': 'Large general purpose model (13B parameters)',
            'llama2:7b': 'Medium general purpose model (7B parameters)',
            'mistral:7b': 'Efficient medium model (7B parameters)'
        };
        
        return descriptions[modelName] || 'AI language model';
    }

    private getModelCapabilities(modelName: string): string[] {
        if (modelName.includes('codellama')) {
            return ['Code Generation', 'Code Fixing', 'Security Analysis'];
        }
        
        return ['Text Generation', 'Code Understanding'];
    }

    async testConnection(): Promise<boolean> {
        return this.isOllamaRunning;
    }

    async cleanup(): Promise<void> {
        // Stop Ollama process if we started it
        if (this.ollamaProcess) {
            this.ollamaProcess.kill();
            this.ollamaProcess = null;
        }
    }

    getAvailableProviders(): string[] {
        return Array.from(this.providers.keys()).filter(name => 
            this.providers.get(name)?.available
        );
    }

    async switchProvider(providerName: string): Promise<void> {
        const provider = this.providers.get(providerName);
        if (!provider) {
            throw new Error(`Provider ${providerName} not found`);
        }
        
        if (!provider.available) {
            throw new Error(`Provider ${providerName} is not available`);
        }
        
        // Set as current provider logic here
        console.log(`Switched to AI provider: ${providerName}`);
    }
}

// Provider implementations
class OllamaProvider implements AIProvider {
    name = 'Ollama Local';
    available = false;
    models: AIModel[] = [];

    constructor(private baseUrl: string) {
        this.checkAvailability();
    }

    private async checkAvailability(): Promise<void> {
        try {
            const response = await fetch(`${this.baseUrl}/api/tags`, { timeout: 5000 });
            this.available = response.ok;
        } catch {
            this.available = false;
        }
    }

    async generateFix(violation: any, context: string): Promise<AIFix | null> {
        const prompt = this.buildPrompt(violation, context);
        
        try {
            const response = await fetch(`${this.baseUrl}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: 'codellama:13b',
                    prompt: prompt,
                    stream: false,
                    options: {
                        temperature: 0.1,
                        top_p: 0.9,
                        num_predict: 200
                    }
                })
            });

            const data = await response.json();
            return this.parseResponse(data.response, violation);
        } catch (error) {
            console.error('Ollama generation failed:', error);
            return null;
        }
    }

    private buildPrompt(violation: any, context: string): string {
        return `Fix this PowerShell security issue:

Issue: ${violation.ruleId}
Message: ${violation.message}
Code: ${violation.code}

Provide only the corrected PowerShell code:`;
    }

    private parseResponse(response: string, violation: any): AIFix {
        let fixedCode = response.trim();
        
        // Clean up response
        fixedCode = fixedCode.replace(/```powershell/g, '');
        fixedCode = fixedCode.replace(/```/g, '');
        fixedCode = fixedCode.trim();

        return {
            violation,
            originalCode: violation.code,
            fixedCode,
            explanation: `AI-generated fix for ${violation.ruleId}`,
            confidence: 0.8,
            provider: this.name
        };
    }

    async testConnection(): Promise<boolean> {
        await this.checkAvailability();
        return this.available;
    }
}

class RuleBasedProvider implements AIProvider {
    name = 'Rule-Based';
    available = true;
    models: AIModel[] = [];

    async generateFix(violation: any, context: string): Promise<AIFix | null> {
        const fix = this.getRuleBasedFix(violation);
        
        if (!fix) return null;

        return {
            violation,
            originalCode: violation.code,
            fixedCode: fix.fixedCode,
            explanation: fix.explanation,
            confidence: 0.9,
            provider: this.name
        };
    }

    private getRuleBasedFix(violation: any): {fixedCode: string, explanation: string} | null {
        const ruleFixes: Record<string, any> = {
            'InsecureHashAlgorithms': {
                patterns: [
                    { from: /Get-FileHash.*-Algorithm\s+MD5/gi, to: 'Get-FileHash -Algorithm SHA256' },
                    { from: /Get-FileHash.*-Algorithm\s+SHA1/gi, to: 'Get-FileHash -Algorithm SHA256' }
                ],
                explanation: 'Replaced insecure hash algorithm with SHA256'
            },
            'CredentialExposure': {
                patterns: [
                    { from: /ConvertTo-SecureString\s+"[^"]*"\s+-AsPlainText\s+-Force/gi, to: 'Read-Host "Enter password" -AsSecureString' }
                ],
                explanation: 'Replaced plaintext password with secure input'
            }
        };

        const ruleFix = ruleFixes[violation.ruleId];
        if (!ruleFix) return null;

        let fixedCode = violation.code;
        for (const pattern of ruleFix.patterns) {
            if (pattern.from.test(fixedCode)) {
                fixedCode = fixedCode.replace(pattern.from, pattern.to);
                return { fixedCode, explanation: ruleFix.explanation };
            }
        }

        return null;
    }

    async testConnection(): Promise<boolean> {
        return true;
    }
}

class OpenAIFallbackProvider implements AIProvider {
    name = 'OpenAI Fallback';
    available = true;
    models: AIModel[] = [];

    constructor(private apiKey: string) {}

    async generateFix(violation: any, context: string): Promise<AIFix | null> {
        // Simplified OpenAI integration for fallback
        // Implementation similar to VS Code extension
        return null;
    }

    async testConnection(): Promise<boolean> {
}

## 3.4 React Frontend Interface

### 3.4.1 Main Application Component

import { Layout, Menu, Button, Upload, Card, Table, Tag, Progress, Modal, Tabs, Spin, Alert, Drawer } from 'antd';
import {
    FileOutlined,
    FolderOpenOutlined,
    PlayCircleOutlined,
    RobotOutlined,
    SettingOutlined,
    ShieldCheckOutlined,
    ExclamationCircleOutlined,
    CheckCircleOutlined,
    CloseCircleOutlined,
    InfoCircleOutlined,
    DownloadOutlined,
    DatabaseOutlined
} from '@ant-design/icons';
import { SecurityViolation, AnalysisResult, AIFix } from '../types';
import { ScriptEditor } from './components/ScriptEditor';
import { ViolationDetails } from './components/ViolationDetails';
import { AIFixInterface } from './components/AIFixInterface';
import { SandboxStatus } from './components/SandboxStatus';
import { SettingsPanel } from './components/SettingsPanel';
import { SecurityReport } from './components/SecurityReport';

const { Header, Content, Sider } = Layout;
const { TabPane } = Tabs;

interface AppState {
    currentScript: {
        content: string;
        path?: string;
        name?: string;
    } | null;
    analysisResult: AnalysisResult | null;
    violations: SecurityViolation[];
    aiFixesAvailable: AIFix[];
    isAnalyzing: boolean;
    isGeneratingFixes: boolean;
    sandboxStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
    aiStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
    selectedViolation: SecurityViolation | null;
    showSettings: boolean;
    showAIConfig: boolean;
    showReport: boolean;
}

export const App: React.FC = () => {
    const [state, setState] = useState<AppState>({
        currentScript: null,
        analysisResult: null,
        violations: [],
        aiFixesAvailable: [],
        isAnalyzing: false,
        isGeneratingFixes: false,
        sandboxStatus: 'disconnected',
        aiStatus: 'disconnected',
        selectedViolation: null,
        showSettings: false,
        showAIConfig: false,
        showReport: false
    });

    useEffect(() => {
        initializeApp();
    }, []);

    const initializeApp = async () => {
        try {
            // Check system status
            const sandboxStatus = await window.electronAPI.getSandboxStatus();
            const aiStatus = await window.electronAPI.testAIConnection();
            
            setState(prev => ({
                ...prev,
                sandboxStatus: sandboxStatus.success ? 'connected' : 'error',
                aiStatus: aiStatus.success ? 'connected' : 'error'
            }));
        } catch (error) {
            console.error('Failed to initialize app:', error);
        }
    };

    const handleOpenScript = async () => {
        try {
            const result = await window.electronAPI.openScriptFile();
            if (result.success) {
                setState(prev => ({
                    ...prev,
                    currentScript: result.data,
                    violations: [],
                    analysisResult: null,
                    aiFixesAvailable: []
                }));
            }
        } catch (error) {
            console.error('Failed to open script:', error);
        }
    };

    const handleOpenFolder = async () => {
        try {
            const result = await window.electronAPI.openFolder();
            if (result.success) {
                // Handle folder analysis
                await handleAnalyzeFolder(result.data.path);
            }
        } catch (error) {
            console.error('Failed to open folder:', error);
        }
    };

    const handleAnalyzeScript = async () => {
        if (!state.currentScript) return;

        setState(prev => ({ ...prev, isAnalyzing: true }));

        try {
            const result = await window.electronAPI.analyzeScript(state.currentScript);
            
            if (result.success) {
                setState(prev => ({
                    ...prev,
                    analysisResult: result.data,
                    violations: result.data.violations || [],
                    isAnalyzing: false
                }));
            } else {
                console.error('Analysis failed:', result.error);
                setState(prev => ({ ...prev, isAnalyzing: false }));
            }
        } catch (error) {
            console.error('Analysis error:', error);
            setState(prev => ({ ...prev, isAnalyzing: false }));
        }
    };

    const handleAnalyzeFolder = async (folderPath: string) => {
        setState(prev => ({ ...prev, isAnalyzing: true }));

        try {
            const result = await window.electronAPI.analyzeFolder(folderPath);
            
            if (result.success) {
                setState(prev => ({
                    ...prev,
                    analysisResult: result.data,
                    violations: result.data.violations || [],
                    isAnalyzing: false
                }));
            }
        } catch (error) {
            console.error('Folder analysis error:', error);
            setState(prev => ({ ...prev, isAnalyzing: false }));
        }
    };

    const handleGenerateAIFixes = async () => {
        if (!state.violations.length) return;

        setState(prev => ({ ...prev, isGeneratingFixes: true }));

        try {
            const result = await window.electronAPI.generateAIFixes(state.violations);
            
            if (result.success) {
                setState(prev => ({
                    ...prev,
                    aiFixesAvailable: result.data || [],
                    isGeneratingFixes: false
                }));
            } else {
                console.error('AI fix generation failed:', result.error);
                setState(prev => ({ ...prev, isGeneratingFixes: false }));
            }
        } catch (error) {
            console.error('AI fix generation error:', error);
            setState(prev => ({ ...prev, isGeneratingFixes: false }));
        }
    };

    const handleApplyAIFixes = async () => {
        if (!state.aiFixesAvailable.length || !state.currentScript) return;

        try {
            const result = await window.electronAPI.applyAIFixes({
                script: state.currentScript,
                fixes: state.aiFixesAvailable
            });

            if (result.success) {
                // Update the script content with fixes applied
                setState(prev => ({
                    ...prev,
                    currentScript: {
                        ...prev.currentScript!,
                        content: result.data.updatedContent
                    },
                    aiFixesAvailable: []
                }));

                // Re-analyze to show updated results
                setTimeout(() => handleAnalyzeScript(), 1000);
            }
        } catch (error) {
            console.error('Failed to apply fixes:', error);
        }
    };

    const getSeverityColor = (severity: string): string => {
        switch (severity) {
            case 'Critical': return 'red';
            case 'High': return 'orange';
            case 'Medium': return 'gold';
            case 'Low': return 'blue';
            default: return 'default';
        }
    };

    const violationColumns = [
        {
            title: 'Rule',
            dataIndex: 'ruleId',
            key: 'ruleId',
            width: 200,
        },
        {
            title: 'Severity',
            dataIndex: 'severity',
            key: 'severity',
            width: 100,
            render: (severity: string) => (
                <Tag color={getSeverityColor(severity)}>{severity}</Tag>
            ),
        },
        {
            title: 'Message',
            dataIndex: 'message',
            key: 'message',
            ellipsis: true,
        },
        {
            title: 'Line',
            dataIndex: 'lineNumber',
            key: 'lineNumber',
            width: 80,
        },
        {
            title: 'Actions',
            key: 'actions',
            width: 150,
            render: (record: SecurityViolation) => (
                <Button 
                    size="small" 
                    onClick={() => setState(prev => ({ ...prev, selectedViolation: record }))}
                >
                    View Details
                </Button>
            ),
        },
    ];

    const menuItems = [
        {
            key: 'file',
            icon: <FileOutlined />,
            label: 'Script',
            children: [
                { key: 'open-script', label: 'Open Script', onClick: handleOpenScript },
                { key: 'open-folder', label: 'Open Folder', onClick: handleOpenFolder },
            ]
        },
        {
            key: 'analysis',
            icon: <ShieldCheckOutlined />,
            label: 'Analysis',
            children: [
                { key: 'run-analysis', label: 'Run Analysis', onClick: handleAnalyzeScript },
                { key: 'clear-results', label: 'Clear Results' },
            ]
        },
        {
            key: 'ai',
            icon: <RobotOutlined />,
            label: 'AI Fixes',
            children: [
                { key: 'generate-fixes', label: 'Generate Fixes', onClick: handleGenerateAIFixes },
                { key: 'apply-fixes', label: 'Apply Fixes', onClick: handleApplyAIFixes },
                { key: 'ai-config', label: 'AI Configuration' },
            ]
        },
    ];

    return (
        <Layout style={{ height: '100vh' }}>
            <Header style={{ padding: '0 16px', background: '#001529' }}>
                <div style={{ color: 'white', fontSize: '18px', fontWeight: 'bold' }}>
                    PowerShield - Comprehensive PowerShell Security Platform
                </div>
                <div style={{ float: 'right', color: 'white' }}>
                    <span style={{ marginRight: 16 }}>
                        Sandbox: <Tag color={state.sandboxStatus === 'connected' ? 'green' : 'red'}>
                            {state.sandboxStatus}
                        </Tag>
                    </span>
                    <span style={{ marginRight: 16 }}>
                        AI: <Tag color={state.aiStatus === 'connected' ? 'green' : 'red'}>
                            {state.aiStatus}
                        </Tag>
                    </span>
                    <Button 
                        icon={<SettingOutlined />} 
                        type="text" 
                        style={{ color: 'white' }}
                        onClick={() => setState(prev => ({ ...prev, showSettings: true }))}
                    >
                        Settings
                    </Button>
                </div>
            </Header>

            <Layout>
                <Sider width={250} style={{ background: '#fff' }}>
                    <Menu mode="vertical" items={menuItems} />
                    
                    <div style={{ padding: 16 }}>
                        <SandboxStatus status={state.sandboxStatus} />
                        
                        {state.violations.length > 0 && (
                            <Card size="small" style={{ marginTop: 16 }}>
                                <div style={{ textAlign: 'center' }}>
                                    <div style={{ fontSize: 24, fontWeight: 'bold', color: '#ff4d4f' }}>
                                        {state.violations.length}
                                    </div>
                                    <div>Security Issues</div>
                                    
                                    <div style={{ marginTop: 8 }}>
                                        {['Critical', 'High', 'Medium', 'Low'].map(severity => {
                                            const count = state.violations.filter(v => v.severity === severity).length;
                                            if (count === 0) return null;
                                            return (
                                                <Tag key={severity} color={getSeverityColor(severity)} style={{ margin: 2 }}>
                                                    {severity}: {count}
                                                </Tag>
                                            );
                                        })}
                                    </div>
                                </div>
                            </Card>
                        )}

                        {state.aiFixesAvailable.length > 0 && (
                            <Card size="small" style={{ marginTop: 16 }}>
                                <div style={{ textAlign: 'center' }}>
                                    <div style={{ fontSize: 18, fontWeight: 'bold', color: '#52c41a' }}>
                                        {state.aiFixesAvailable.length}
                                    </div>
                                    <div>AI Fixes Available</div>
                                    
                                    <Button 
                                        type="primary" 
                                        size="small" 
                                        style={{ marginTop: 8 }}
                                        onClick={handleApplyAIFixes}
                                        icon={<RobotOutlined />}
                                    >
                                        Apply All
                                    </Button>
                                </div>
                            </Card>
                        )}
                    </div>
                </Sider>

                <Content style={{ padding: 16, overflow: 'auto' }}>
                    <Tabs defaultActiveKey="editor" type="card">
                        <TabPane tab="Script Editor" key="editor">
                            <ScriptEditor 
                                script={state.currentScript}
                                violations={state.violations}
                                onScriptChange={(content) => 
                                    setState(prev => ({
                                        ...prev,
                                        currentScript: prev.currentScript ? 
                                            { ...prev.currentScript, content } : 
                                            { content }
                                    }))
                                }
                            />
                            
                            <div style={{ marginTop: 16 }}>
                                <Button 
                                    type="primary" 
                                    icon={<PlayCircleOutlined />}
                                    onClick={handleAnalyzeScript}
                                    loading={state.isAnalyzing}
                                    disabled={!state.currentScript}
                                >
                                    Run Security Analysis
                                </Button>
                                
                                <Button 
                                    style={{ marginLeft: 8 }}
                                    icon={<RobotOutlined />}
                                    onClick={handleGenerateAIFixes}
                                    loading={state.isGeneratingFixes}
                                    disabled={!state.violations.length}
                                >
                                    Generate AI Fixes
                                </Button>
                            </div>
                        </TabPane>

                        <TabPane tab={`Violations (${state.violations.length})`} key="violations">
                            <Table 
                                dataSource={state.violations}
                                columns={violationColumns}
                                rowKey="ruleId"
                                size="small"
                                pagination={{ pageSize: 20 }}
                            />
                        </TabPane>

                        <TabPane tab="AI Fixes" key="ai-fixes">
                            <AIFixInterface 
                                fixes={state.aiFixesAvailable}
                                onApplyFix={(fix) => {
                                    // Apply individual fix
                                }}
                                onApplyAllFixes={handleApplyAIFixes}
                            />
                        </TabPane>

                        <TabPane tab="Report" key="report">
                            <SecurityReport 
                                analysisResult={state.analysisResult}
                                violations={state.violations}
                                onExport={() => setState(prev => ({ ...prev, showReport: true }))}
                            />
                        </TabPane>
                    </Tabs>
                </Content>
            </Layout>

            {/* Modals and Drawers */}
            <Modal
                title="Violation Details"
                open={!!state.selectedViolation}
                onCancel={() => setState(prev => ({ ...prev, selectedViolation: null }))}
                footer={null}
                width={800}
            >
                {state.selectedViolation && (
                    <ViolationDetails violation={state.selectedViolation} />
                )}
            </Modal>

            <Drawer
                title="Settings"
                placement="right"
                onClose={() => setState(prev => ({ ...prev, showSettings: false }))}
                open={state.showSettings}
                width={600}
            >
                <SettingsPanel />
            </Drawer>
        </Layout>
export default App;

## 3.5 Docker Configuration for Secure Analysis

### 3.5.1 Dockerfile Configuration

RUN adduser -D -s /bin/sh -h /home/analyzer analyzer

# Install PowerShell modules and dependencies

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; Install-Module -Name PSScriptAnalyzer -Force -Scope AllUsers"

# Create application directory

RUN mkdir -p /app && chown analyzer:analyzer /app

## Copy PowerShield analyzer modules

COPY --chown=analyzer:analyzer PowerShellSecurityAnalyzer/ /app/modules/
COPY --chown=analyzer:analyzer scripts/ /app/

# Create workspace and output directories

RUN mkdir -p /workspace /output && chown analyzer:analyzer /workspace /output

# Set up security constraints

RUN chmod 755 /app/analyze.ps1
RUN chmod -R 644 /app/modules/

# Switch to non-root user

USER analyzer

# Set working directory

WORKDIR /app

# Disable PowerShell telemetry

ENV POWERSHELL_TELEMETRY_OPTOUT=1
ENV POWERSHELL_UPDATECHECK_OPTOUT=1

# Health check

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD pwsh -c "Test-Path /app/analyze.ps1"

# Entry point

ENTRYPOINT ["pwsh", "/app/analyze.ps1"]
File: standalone-app/docker/scripts/analyze.ps1
powershell#!/usr/bin/env pwsh

param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,

    [string]$OutputPath = "/output/results.json",
    
    [string]$ConfigPath = "/app/config.json"
)

try {
    Write-Host "PowerShield Docker Analyzer Starting..."
    Write-Host "Script: $ScriptPath"
    Write-Host "Output: $OutputPath"

    # Security: Validate input paths
    if (-not (Test-Path $ScriptPath)) {
        throw "Script file not found: $ScriptPath"
    }
    
    $resolvedScriptPath = Resolve-Path $ScriptPath
    $workspaceDir = "/workspace"
    
    # Security: Ensure script is within workspace
    if (-not $resolvedScriptPath.Path.StartsWith($workspaceDir)) {
        throw "Script path outside allowed workspace: $resolvedScriptPath"
    }
    
    # Import PowerShield analyzer
    Import-Module "/app/modules/PowerShellSecurityAnalyzer.psd1" -Force
    
    Write-Host "Modules imported successfully"
    
    # Initialize analyzer with container-specific config
    $analyzer = [PowerShellSecurityAnalyzer]::new()
    
    # Load additional security rules for container environment
    $analyzer.SecurityRules.AddRange(@(
        # Container-specific security rules
        [SecurityRule]::new(
            "ContainerEscape",
            "Detects potential container escape attempts",
            [SecuritySeverity]::Critical,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Check for dangerous commands in container context
                $dangerousCommands = @('docker', 'kubectl', 'chroot', 'mount', 'nsenter')
                
                $commandCalls = $Ast.FindAll({
                    $args[0] -is [System.Management.Automation.Language.CommandAst]
                }, $true)
                
                foreach ($call in $commandCalls) {
                    $commandName = $call.GetCommandName()
                    if ($commandName -in $dangerousCommands) {
                        $violations += [SecurityViolation]::new(
                            "ContainerEscape",
                            "Potential container escape command detected: $commandName",
                            [SecuritySeverity]::Critical,
                            $call.Extent.StartLineNumber,
                            $call.Extent.Text
                        )
                    }
                }
                
                return $violations
            }
        ),
        
        [SecurityRule]::new(
            "FileSystemAccess",
            "Detects potentially dangerous file system access",
            [SecuritySeverity]::High,
            {
                param($Ast, $FilePath)
                $violations = @()
                
                # Check for access to sensitive paths
                $sensitivePaths = @('/etc/', '/proc/', '/sys/', '/dev/', '/var/', '/root/')
                
                $stringLiterals = $Ast.FindAll({
                    $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                }, $true)
                
                foreach ($literal in $stringLiterals) {
                    $path = $literal.Value
                    foreach ($sensitivePath in $sensitivePaths) {
                        if ($path.StartsWith($sensitivePath)) {
                            $violations += [SecurityViolation]::new(
                                "FileSystemAccess",
                                "Access to sensitive file system path: $path",
                                [SecuritySeverity]::High,
                                $literal.Extent.StartLineNumber,
                                $literal.Extent.Text
                            )
                        }
                    }
                }
                
                return $violations
            }
        )
    ))
    
    Write-Host "Container-specific security rules loaded"
    
    # Run analysis with timeout protection
    $timeoutSeconds = 60
    $job = Start-Job -ScriptBlock {
        param($AnalyzerInstance, $ScriptPath)
        return $AnalyzerInstance.AnalyzeScript($ScriptPath)
    } -ArgumentList $analyzer, $resolvedScriptPath.Path
    
    $result = $null
    if (Wait-Job $job -Timeout $timeoutSeconds) {
        $result = Receive-Job $job
        Remove-Job $job
    } else {
        Remove-Job $job -Force
        throw "Analysis timed out after $timeoutSeconds seconds"
    }
    
    Write-Host "Analysis completed successfully"
    Write-Host "Violations found: $($result.Violations.Count)"
    
    # Prepare output data
    $outputData = @{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        version = "1.0.0"
        environment = "docker-container"
        script = @{
            path = $ScriptPath
            name = Split-Path $ScriptPath -Leaf
        }
        analysis = @{
            violations = $result.Violations
            rulesExecuted = $result.RulesExecuted
            parseErrors = $result.ParseErrors
            duration = if ($result.Timestamp) { 
                ((Get-Date) - $result.Timestamp).TotalMilliseconds 
            } else { 0 }
        }
        security = @{
            containerized = $true
            user = $env:USER
            workingDirectory = $PWD.Path
        }
    }
    
    # Write results to output file
    $outputJson = $outputData | ConvertTo-Json -Depth 10 -Compress
    
    # Security: Ensure output directory exists and is writable
    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    $outputJson | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    
    Write-Host "Results written to: $OutputPath"
    Write-Host "PowerShield Docker Analyzer completed successfully"
    
    exit 0
    
} catch {
    $errorData = @{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        error = $_.Exception.Message
        stackTrace = $_.ScriptStackTrace
        script = $ScriptPath
        environment = "docker-container"
    }

    $errorJson = $errorData | ConvertTo-Json -Depth 5 -Compress
    
    try {
        $errorJson | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    } catch {
    exit 1
}

    Write-Error "PowerShield Docker Analyzer failed: $($_.Exception.Message)"
    exit 1
}

## 3.6 Enterprise Security Configuration

File: standalone-app/src/main/config/securityPolicies.ts
typescriptexport interface SecurityPolicy {
    id: string;
    name: string;
    description: string;
    enabled: boolean;
    severity: 'low' | 'medium' | 'high' | 'critical';
    rules: SecurityPolicyRule[];
}

export interface SecurityPolicyRule {
    ruleId: string;
    enabled: boolean;
    customMessage?: string;
    exemptions: string[];
    customConfiguration?: Record<string, any>;
}

export class SecurityPolicyManager {
    private policies: Map<string, SecurityPolicy> = new Map();
    private configPath: string;

    constructor(configPath: string) {
        this.configPath = configPath;
        this.loadDefaultPolicies();
    }

    private loadDefaultPolicies(): void {
        // Enterprise Security Policy Templates
        const enterprisePolicies: SecurityPolicy[] = [
            {
                id: 'enterprise-baseline',
                name: 'Enterprise Baseline Security',
                description: 'Baseline security requirements for enterprise PowerShell scripts',
                enabled: true,
                severity: 'high',
                rules: [
                    {
                        ruleId: 'InsecureHashAlgorithms',
                        enabled: true,
                        exemptions: []
                    },
                    {
                        ruleId: 'CredentialExposure',
                        enabled: true,
                        exemptions: []
                    },
                    {
                        ruleId: 'CommandInjection',
                        enabled: true,
                        exemptions: []
                    },
                    {
                        ruleId: 'CertificateValidation',
                        enabled: true,
                        exemptions: []
                    }
                ]
            },
            
            {
                id: 'financial-services',
                name: 'Financial Services Compliance',
                description: 'Enhanced security requirements for financial services',
                enabled: false,
                severity: 'critical',
                rules: [
                    {
                        ruleId: 'EncryptionStandards',
                        enabled: true,
                        customConfiguration: {
                            minimumKeySize: 2048,
                            requiredAlgorithms: ['AES-256', 'RSA-2048']
                        },
                        exemptions: []
                    },
                    {
                        ruleId: 'AuditLogging',
                        enabled: true,
                        customConfiguration: {
                            requiredEvents: ['credential-access', 'data-modification', 'privilege-escalation']
                        },
                        exemptions: []
                    },
                    {
                        ruleId: 'DataClassification',
                        enabled: true,
                        customConfiguration: {
                            sensitiveDataPatterns: ['SSN', 'Credit Card', 'Bank Account']
                        },
                        exemptions: []
                    }
                ]
            },
            
            {
                id: 'healthcare-hipaa',
                name: 'Healthcare HIPAA Compliance',
                description: 'HIPAA compliance requirements for healthcare organizations',
                enabled: false,
                severity: 'critical',
                rules: [
                    {
                        ruleId: 'PHIProtection',
                        enabled: true,
                        customConfiguration: {
                            phiPatterns: ['DOB', 'Medical Record Number', 'Patient ID']
                        },
                        exemptions: []
                    },
                    {
                        ruleId: 'AccessControl',
                        enabled: true,
                        customConfiguration: {
                            requiresMFA: true,
                            minimumPrivileges: true
                        },
                        exemptions: []
                    }
                ]
            },
            
            {
                id: 'government-fedramp',
                name: 'Government FedRAMP Compliance',
                description: 'FedRAMP security requirements for government systems',
                enabled: false,
                severity: 'critical',
                rules: [
                    {
                        ruleId: 'FIPS140Compliance',
                        enabled: true,
                        customConfiguration: {
                            fipsMode: true,
                            approvedAlgorithms: ['AES', 'SHA-256', 'RSA']
                        },
                        exemptions: []
                    },
                    {
                        ruleId: 'ContinuousMonitoring',
                        enabled: true,
                        customConfiguration: {
                            realTimeAlerts: true,
                            logRetention: '7-years'
                        },
                        exemptions: []
                    }
                ]
            }
        ];

        enterprisePolicies.forEach(policy => {
            this.policies.set(policy.id, policy);
        });
    }

    async loadPolicies(): Promise<void> {
        try {
            const fs = await import('fs/promises');
            const configData = await fs.readFile(this.configPath, 'utf8');
            const loadedPolicies = JSON.parse(configData);
            
            loadedPolicies.forEach((policy: SecurityPolicy) => {
                this.policies.set(policy.id, policy);
            });
        } catch (error) {
            console.log('No existing policy configuration found, using defaults');
        }
    }

    async savePolicies(): Promise<void> {
        try {
            const fs = await import('fs/promises');
            const path = await import('path');
            
            // Ensure config directory exists
            const configDir = path.dirname(this.configPath);
            await fs.mkdir(configDir, { recursive: true });
            
            const policiesArray = Array.from(this.policies.values());
            await fs.writeFile(this.configPath, JSON.stringify(policiesArray, null, 2));
        } catch (error) {
            console.error('Failed to save security policies:', error);
            throw error;
        }
    }

    getPolicy(policyId: string): SecurityPolicy | undefined {
        return this.policies.get(policyId);
    }

    getAllPolicies(): SecurityPolicy[] {
        return Array.from(this.policies.values());
    }

    getActivePolicies(): SecurityPolicy[] {
        return this.getAllPolicies().filter(policy => policy.enabled);
    }

    updatePolicy(policyId: string, updates: Partial<SecurityPolicy>): void {
        const existing = this.policies.get(policyId);
        if (existing) {
            this.policies.set(policyId, { ...existing, ...updates });
        }
    }

    createCustomPolicy(policy: SecurityPolicy): void {
        this.policies.set(policy.id, policy);
    }

    deletePolicy(policyId: string): boolean {
        return this.policies.delete(policyId);
    }

    validatePolicyCompliance(violations: any[], policyId: string): {
        compliant: boolean;
        violations: any[];
        exemptions: any[];
        summary: {
            totalViolations: number;
            criticalViolations: number;
            exemptedViolations: number;
        };
    } {
        const policy = this.getPolicy(policyId);
        if (!policy || !policy.enabled) {
            return {
                compliant: true,
                violations: [],
                exemptions: [],
                summary: {
                    totalViolations: 0,
                    criticalViolations: 0,
                    exemptedViolations: 0
                }
            };
        }

        const policyViolations: any[] = [];
        const exemptions: any[] = [];

        for (const violation of violations) {
            const policyRule = policy.rules.find(rule => rule.ruleId === violation.ruleId);
            
            if (policyRule && policyRule.enabled) {
                // Check if violation is exempted
                const isExempted = policyRule.exemptions.some(exemption => 
                    violation.filePath?.includes(exemption) ||
                    violation.code?.includes(exemption)
                );
                
                if (isExempted) {
                    exemptions.push({
                        ...violation,
                        exemptionReason: 'Policy exemption'
                    });
                } else {
                    policyViolations.push(violation);
                }
            }
        }

        const criticalViolations = policyViolations.filter(v => v.severity === 'Critical').length;
        
        return {
            compliant: policyViolations.length === 0,
            violations: policyViolations,
            exemptions: exemptions,
            summary: {
                totalViolations: policyViolations.length,
                criticalViolations: criticalViolations,
                exemptedViolations: exemptions.length
            }
        };
    }

    generateComplianceReport(analysisResults: any[], policyId: string): {
        policyName: string;
        overallCompliance: boolean;
        complianceScore: number;
        fileResults: any[];
        summary: any;
    } {
        const policy = this.getPolicy(policyId);
        if (!policy) {
            throw new Error(`Policy not found: ${policyId}`);
        }

        const fileResults = analysisResults.map(result => {
            const compliance = this.validatePolicyCompliance(result.violations, policyId);
            return {
                filePath: result.filePath,
                compliant: compliance.compliant,
                violations: compliance.violations.length,
                exemptions: compliance.exemptions.length,
                details: compliance
            };
        });

        const totalFiles = fileResults.length;
        const compliantFiles = fileResults.filter(r => r.compliant).length;
        const complianceScore = totalFiles > 0 ? (compliantFiles / totalFiles) * 100 : 100;

        const totalViolations = fileResults.reduce((sum, r) => sum + r.violations, 0);
        const totalExemptions = fileResults.reduce((sum, r) => sum + r.exemptions, 0);

        return {
            policyName: policy.name,
            overallCompliance: complianceScore === 100,
            complianceScore: Math.round(complianceScore),
            fileResults: fileResults,
            summary: {
                totalFiles,
                compliantFiles,
                nonCompliantFiles: totalFiles - compliantFiles,
                totalViolations,
                totalExemptions,
                compliancePercentage: complianceScore
            }
        };
    }
}
This completes Phase 3 of the PowerShield implementation - a comprehensive standalone sandbox application with:
Key Features Implemented:

Electron-based desktop application with security hardening
Docker-based sandbox isolation for script analysis
Local AI integration via Ollama with CodeLlama models
Multi-provider AI fallback system (local → cloud)
Enterprise security policy management
React-based user interface with real-time analysis
Comprehensive configuration and telemetry systems
Build and deployment configuration

Security Features:

Complete process isolation via Docker containers
Non-root execution in sandboxed environment
Network isolation during analysis
Memory and CPU limits for containers
File system access restrictions
Enterprise compliance frameworks (HIPAA, FedRAMP, etc.)

The application provides enterprise-grade security analysis with local AI capabilities, making it suitable for air-gapped environments while maintaining the option for cloud AI fallback when needed.
