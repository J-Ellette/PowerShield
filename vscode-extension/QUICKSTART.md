# PowerShield VS Code Extension - Quick Start Guide

This guide will help you get started with developing and testing the PowerShield VS Code extension.

## Prerequisites

- **Visual Studio Code**: Version 1.85.0 or higher
- **Node.js**: Version 20.x or higher
- **PowerShell Core**: Version 7.0 or higher
- **Git**: For cloning the repository

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/J-Ellette/PowerShield.git
cd PowerShield/vscode-extension
```

### 2. Install Dependencies

```bash
npm install
```

This installs all required dependencies including TypeScript, VS Code types, and ESLint.

### 3. Compile the Extension

```bash
npm run compile
```

This compiles TypeScript source files in `src/` to JavaScript in `out/`.

## Running the Extension

### Method 1: Debug in VS Code (Recommended)

1. Open the `vscode-extension` folder in VS Code:
   ```bash
   code .
   ```

2. Press `F5` or go to `Run > Start Debugging`

3. This opens a new VS Code window titled "[Extension Development Host]"

4. In the new window, open a PowerShell file (.ps1, .psm1, or .psd1)

5. The extension should automatically activate and analyze the file

### Method 2: Install as VSIX

1. Package the extension:
   ```bash
   npm run package
   ```

2. This creates a `.vsix` file in the current directory

3. Install the VSIX:
   - Open VS Code
   - Go to Extensions view (`Ctrl+Shift+X`)
   - Click the `...` menu → "Install from VSIX..."
   - Select the `.vsix` file

## Testing

### Integration Test

Run the PowerShell integration test:

```bash
pwsh ./test-integration.ps1
```

This verifies:
- PowerShell modules are accessible
- Security analysis works correctly
- VS Code diagnostic conversion is functional
- JSON export format is valid

Expected output: All tests pass ✅

### Manual Testing

1. **Open a PowerShell file** with security issues:
   ```powershell
   # test.ps1
   $hash = [System.Security.Cryptography.MD5]::Create()
   $password = ConvertTo-SecureString "MyPassword123" -AsPlainText -Force
   ```

2. **Check diagnostics**:
   - Look for red/yellow squiggles in the editor
   - Open Problems panel (`Ctrl+Shift+M`)
   - You should see violations listed

3. **Test commands**:
   - Open Command Palette (`Ctrl+Shift+P`)
   - Type "PowerShield"
   - Try commands like "Analyze Current File"

4. **Check output**:
   - Run "PowerShield: Show Output"
   - View logs in the Output panel

## Development Workflow

### Watch Mode

For active development, use watch mode to automatically recompile on changes:

```bash
npm run watch
```

Keep this running in a terminal. When you save a TypeScript file, it will automatically recompile.

### Making Changes

1. Edit source files in `src/`
2. Save the file (watch mode recompiles automatically)
3. Reload the Extension Development Host:
   - Press `Ctrl+R` in the Extension Development Host window
   - Or use Command Palette → "Developer: Reload Window"
4. Test your changes

## Project Structure

```
vscode-extension/
├── src/
│   ├── extension.ts              # Main entry point
│   ├── types.ts                  # TypeScript type definitions
│   ├── core/
│   │   └── PowerShieldEngine.ts  # PowerShell integration
│   └── providers/
│       ├── SecurityProvider.ts   # Document analysis with caching
│       └── RealTimeAnalysisProvider.ts  # Real-time analysis
├── out/                          # Compiled JavaScript (git-ignored)
├── node_modules/                 # Dependencies (git-ignored)
├── package.json                  # Extension manifest
├── tsconfig.json                 # TypeScript config
├── README.md                     # User documentation
├── CHANGELOG.md                  # Version history
└── QUICKSTART.md                 # This file
```

## Configuration

### Extension Settings

Open settings and search for "powershield" to configure:

- **Real-time analysis**: Enable/disable, set debounce delay
- **Performance**: Cache settings, incremental analysis
- **UI**: Toggle decorations, hover explanations, CodeLens

### Development Settings

Create a `.vscode/launch.json` for debugging (auto-generated):

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Extension",
      "type": "extensionHost",
      "request": "launch",
      "args": ["--extensionDevelopmentPath=${workspaceFolder}"],
      "outFiles": ["${workspaceFolder}/out/**/*.js"],
      "preLaunchTask": "npm: compile"
    }
  ]
}
```

## Common Issues

### "PowerShell 7+ is required"

**Problem**: Extension shows error on activation.

**Solution**: Install PowerShell Core:
- Windows: `winget install Microsoft.PowerShell`
- macOS: `brew install powershell`
- Linux: See [PowerShell docs](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell)

### "Module not found" errors

**Problem**: Can't find PowerShellSecurityAnalyzer.psm1

**Solution**: Make sure you're running the extension from within the PowerShield repository. The extension looks for modules in `../src/` relative to the extension folder.

### No violations detected

**Problem**: Opening a file with security issues but no diagnostics show.

**Solution**:
1. Check the PowerShield output channel for errors
2. Verify the file is recognized as PowerShell (check status bar)
3. Try running "PowerShield: Analyze Current File" manually
4. Check if real-time analysis is enabled in settings

### Compilation errors

**Problem**: TypeScript compilation fails.

**Solution**:
1. Delete `node_modules` and `out` directories
2. Run `npm install` again
3. Run `npm run compile`
4. Check for TypeScript version compatibility

## Debugging

### Console Logs

The extension logs to the Developer Console and Output channel:

1. **Developer Console**: `Help > Toggle Developer Tools`
2. **Output Channel**: "PowerShield" in the Output panel

### Breakpoints

1. Set breakpoints in TypeScript source files
2. Press `F5` to start debugging
3. Breakpoints hit in the Extension Development Host

### PowerShell Debugging

To debug PowerShell module issues:

1. Open PowerShell terminal
2. Import modules manually:
   ```powershell
   Import-Module ../src/PowerShellSecurityAnalyzer.psm1
   Import-Module ../src/VSCodeIntegration.psm1
   ```
3. Test analysis:
   ```powershell
   $analyzer = New-SecurityAnalyzer
   $result = Invoke-SecurityAnalysis -ScriptPath "test.ps1"
   ```

## Next Steps

### Phase 2.2: AI Integration

Next phase will add:
- AI-powered fix generation
- Multi-provider support (GitHub Models, OpenAI, Anthropic)
- Context-aware suggestions

### Phase 2.3: Enhanced UX

Following phases include:
- Hover provider with rich explanations
- Security overview sidebar
- Interactive learning

## Resources

- [VS Code Extension API](https://code.visualstudio.com/api)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [PowerShield Documentation](https://github.com/J-Ellette/PowerShield/tree/main/docs)
- [Phase 2 Master Plan](https://github.com/J-Ellette/PowerShield/blob/main/buildplans/phase-2-master-plan.md)

## Support

- **Issues**: [GitHub Issues](https://github.com/J-Ellette/PowerShield/issues)
- **Discussions**: [GitHub Discussions](https://github.com/J-Ellette/PowerShield/discussions)

---

Happy coding! 🛡️
