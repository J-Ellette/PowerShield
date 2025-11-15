# Phase 2.5 Quick Start Guide

Get started with PowerShield's new advanced features in 5 minutes!

## 🚀 Quick Start

### 1. Enable CodeLens (30 seconds)

CodeLens shows security summaries directly in your code.

**Steps:**
1. Open any PowerShell file (`.ps1`, `.psm1`, or `.psd1`)
2. Look for icons at the top of the file and above functions:
   - `📊 Security Summary: ...` at the top
   - `🛡️ N security issues` above functions with problems
   - `🔧 Fix N issues` for fixable problems

**Try it:**
```powershell
function Test-Security {
    # You should see CodeLens above this function
    $password = "hardcoded"
    Invoke-Expression $input
}
```

**Disable if needed:**
- Settings Panel → User Interface → Uncheck "Show CodeLens"
- Or: `"powershield.ui.showCodeLens": false` in settings.json

---

### 2. Explore the Dashboard (2 minutes)

See all security issues across your entire workspace.

**How to open:**
- Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`)
- Type: `PowerShield: Show Security Dashboard`
- Or: Click any `📊 Security Summary` CodeLens

**What you'll see:**
- 📊 Metric cards showing Critical, High, Medium, Low issues
- 📋 List of most common security issues
- 📁 Most affected files
- 🔄 Refresh button to re-analyze
- 📤 Export buttons for reports

**Try these actions:**
- Click "Refresh" to update the data
- Click "Export Markdown" to save a report
- Click a file name to jump to that file

---

### 3. Configure Settings (2 minutes)

Customize PowerShield to work your way.

**How to open:**
- Command Palette → `PowerShield: Configure Settings`
- Or: Dashboard → Click "⚙️ Settings"

**Quick tweaks:**

**For faster analysis:**
```
Real-Time Analysis → Analysis Delay → Change to 500ms
```

**To use different AI:**
```
AI Integration → Primary Provider → Choose from dropdown
AI Integration → Click "Test Connection"
```

**To disable features:**
```
User Interface → Uncheck features you don't want
```

**Save your changes:**
- Click "💾 Save Settings" at the bottom
- See confirmation message

---

## 💡 Common Use Cases

### Use Case 1: Quick Security Check

**Scenario:** You want to check if your script has security issues.

**Steps:**
1. Open your PowerShell file
2. Look at the top of the file for `📊 Security Summary`
3. If it shows issues, click it to see the Dashboard
4. Review the issues and click file names to jump to problems

**Time:** 10 seconds

---

### Use Case 2: Fix Multiple Issues in a Function

**Scenario:** A function has several security issues you want to fix quickly.

**Steps:**
1. Find the function with issues (look for `🛡️ N security issues` CodeLens)
2. Click the `🔧 Fix N issues` button next to it
3. Confirm the action
4. Review the applied fixes

**Time:** 30 seconds

---

### Use Case 3: Generate Security Report for Team

**Scenario:** You need to share security status with your team.

**Steps:**
1. Open Dashboard (`Ctrl+Shift+P` → `PowerShield: Show Security Dashboard`)
2. Click "Export Markdown"
3. Choose save location
4. Share the generated report file

**Time:** 1 minute

---

### Use Case 4: Customize for Your Workflow

**Scenario:** You want PowerShield to work differently.

**Steps:**
1. Open Settings Panel (`Ctrl+Shift+P` → `PowerShield: Configure Settings`)
2. Adjust settings in each section
3. Test AI provider if using AI features
4. Click "Save Settings"

**Time:** 2-3 minutes

---

### Use Case 5: Disable Distracting Features

**Scenario:** CodeLens is too distracting while you're writing code.

**Quick fix:**
1. Settings Panel → User Interface → Uncheck "Show CodeLens"
2. Save Settings

**Alternative:**
- Toggle via command: Settings → Search "showCodeLens" → Uncheck

**Time:** 15 seconds

---

## 🎯 Power User Tips

### Tip 1: Keyboard Shortcuts

Assign shortcuts to frequently used commands:

1. File → Preferences → Keyboard Shortcuts
2. Search for "PowerShield"
3. Assign shortcuts to:
   - `PowerShield: Show Security Dashboard`
   - `PowerShield: Configure Settings`
   - `PowerShield: Analyze Workspace`

### Tip 2: Workspace-Specific Settings

Different settings per project:

1. Create `.vscode/settings.json` in your workspace
2. Add PowerShield settings there
3. They override global settings

Example:
```json
{
  "powershield.aiProvider.primary": "template-based",
  "powershield.realTimeAnalysis.debounceMs": 2000,
  "powershield.ui.showCodeLens": false
}
```

### Tip 3: Export Reports Automatically

Create a task to export reports:

`.vscode/tasks.json`:
```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "PowerShield Report",
      "type": "shell",
      "command": "code --command powershield.showSecurityDashboard"
    }
  ]
}
```

### Tip 4: Custom Rules Path

Use your own security rules:

1. Settings Panel → Security Rules → Custom Rules Path
2. Enter path to your rules directory
3. Save Settings

### Tip 5: Quick Toggle

Quickly enable/disable features:

```json
// Disable everything temporarily
{
  "powershield.realTimeAnalysis.enabled": false,
  "powershield.ui.showCodeLens": false,
  "powershield.ui.showInlineDecorations": false
}

// Re-enable when needed
{
  "powershield.realTimeAnalysis.enabled": true,
  "powershield.ui.showCodeLens": true,
  "powershield.ui.showInlineDecorations": true
}
```

---

## 🐛 Troubleshooting

### CodeLens Not Showing

**Check:**
1. Is the file a PowerShell file? (`.ps1`, `.psm1`, `.psd1`)
2. Are there any security issues? (CodeLens only shows when issues exist)
3. Is CodeLens enabled? (Settings → `powershield.ui.showCodeLens`)

**Fix:**
- Reload window: `Ctrl+Shift+P` → `Developer: Reload Window`
- Re-analyze: `Ctrl+Shift+P` → `PowerShield: Analyze File`

---

### Dashboard Shows No Data

**Check:**
1. Are there PowerShell files in the workspace?
2. Have files been analyzed?

**Fix:**
- Click "Refresh" in the dashboard
- Or: `PowerShield: Analyze Workspace` from command palette

---

### Settings Not Saving

**Check:**
1. Do you have write permissions?
2. Is the workspace writable?

**Fix:**
- Check VS Code notifications for error messages
- Try saving to User settings instead of Workspace
- Restart VS Code

---

### AI Provider Test Fails

**Check:**
1. Is the API key set in environment variables?
   - GitHub Models: `GITHUB_TOKEN`
   - OpenAI: `OPENAI_API_KEY`
   - Anthropic: `ANTHROPIC_API_KEY`
   - Azure: `AZURE_OPENAI_API_KEY` and `AZURE_OPENAI_ENDPOINT`

**Fix:**
- Set environment variable
- Restart VS Code
- Test again

---

## 📚 Learn More

### Documentation
- **Full Guide:** See `PHASE_2.5_SUMMARY.md`
- **Features Demo:** See `PHASE_2.5_FEATURES.md`
- **Main README:** See repository README

### Command Reference

| Command | Description |
|---------|-------------|
| `PowerShield: Show Security Dashboard` | Open the dashboard |
| `PowerShield: Configure Settings` | Open settings panel |
| `PowerShield: Analyze File` | Analyze current file |
| `PowerShield: Analyze Workspace` | Analyze all files |
| `PowerShield: Refresh Security Overview` | Update tree view |

### Settings Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `powershield.ui.showCodeLens` | `true` | Show CodeLens |
| `powershield.realTimeAnalysis.enabled` | `true` | Enable real-time analysis |
| `powershield.realTimeAnalysis.debounceMs` | `1000` | Analysis delay (ms) |
| `powershield.aiProvider.primary` | `"github-models"` | AI provider |
| `powershield.aiProvider.confidenceThreshold` | `0.8` | Min confidence for fixes |
| `powershield.performance.enableCaching` | `true` | Enable caching |
| `powershield.performance.maxCacheSize` | `"100MB"` | Max cache size |

---

## ✅ Next Steps

1. ✅ **Try CodeLens** on your PowerShell files
2. ✅ **Open Dashboard** to see workspace overview
3. ✅ **Configure Settings** to match your workflow
4. ✅ **Export a Report** to share with your team
5. ✅ **Customize** keyboard shortcuts and settings

---

## 🎉 You're Ready!

You now know how to use all Phase 2.5 features:
- ✅ CodeLens for inline security awareness
- ✅ Dashboard for workspace overview
- ✅ Settings Panel for easy configuration

Happy secure coding! 🛡️

---

**Need Help?**
- GitHub Issues: https://github.com/J-Ellette/PowerShield/issues
- Documentation: See repository docs folder
