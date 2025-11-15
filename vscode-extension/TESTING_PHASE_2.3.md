# Phase 2.3 Testing Guide

This guide explains how to test the new Phase 2.3 features: DiagnosticsProvider, HoverProvider, and TreeProvider.

## Prerequisites

1. Build the extension:
```bash
cd vscode-extension
npm install
npm run compile
```

2. Open the extension in VS Code for development:
   - Open VS Code
   - File > Open Folder > Select `vscode-extension` folder
   - Press F5 to launch Extension Development Host

## Testing Features

### 1. Testing DiagnosticsProvider

The DiagnosticsProvider provides rich diagnostics in the Problems panel.

**Steps:**
1. In the Extension Development Host, open `test-sample.ps1`
2. Open the Problems panel (View > Problems or Ctrl+Shift+M)
3. Verify the following:
   - Multiple security issues are listed
   - Each diagnostic shows `[SEVERITY] Description (CWE-xxx)` format
   - Click on a CWE link code - it should open the CWE website
   - Hover over the code reference to see full details

**Expected Results:**
- Line 5: `[CRITICAL] Insecure Hash Algorithm (CWE-327)` - MD5 usage
- Line 11: `[CRITICAL] Credential Exposure` - Plaintext password
- Line 16: `[CRITICAL] Command Injection (CWE-94)` - Invoke-Expression
- Line 22: `[HIGH] Certificate Validation Bypass` - Certificate bypass
- Multiple other warnings

### 2. Testing HoverProvider

The HoverProvider shows rich educational content when hovering over security issues.

**Steps:**
1. Open `test-sample.ps1` in the Extension Development Host
2. Hover over a line with a security violation (e.g., line 5 with MD5)
3. Verify the hover content includes:
   - 🛡️ Security issue title
   - Severity badge with emoji (🔴 for Critical, 🟠 for High, etc.)
   - Issue description
   - "Why this matters" explanation (if available)
   - CWE link (clickable)
   - Compliance information (if available)
   - Quick fix preview (if available)
   - Best practices section (if available)
   - Action commands: "🤖 Generate AI Fix", "📖 Learn More", "🙈 Suppress"

**Expected Results:**
- Hover shows rich markdown content with all sections
- Links are clickable
- Commands are executable (some may show "coming soon" messages)

### 3. Testing TreeProvider (Security Overview Sidebar)

The TreeProvider shows a hierarchical view of all security issues in the workspace.

**Steps:**
1. In the Extension Development Host, open the Explorer view
2. Look for the "PowerShield Security" section in the sidebar
3. If not visible, click on the "..." menu in Explorer and enable it
4. Run Command: `PowerShield: Refresh Security Overview` (Ctrl+Shift+P)
5. Verify the tree structure:
   - 📊 Security Overview (expandable)
     - Shows total issues and files
     - Expands to show breakdown by severity
   - 🔴 Critical Issues (expandable)
   - 🟠 High Issues (expandable)
   - 🟡 Medium Issues (expandable)
   - 🔵 Low Issues (expandable)
   - ⚪ Informational (expandable)
6. Expand a category (e.g., Critical Issues)
7. Click on a violation - it should jump to that line in the file

**Expected Results:**
- Tree view shows all security issues grouped by severity
- Summary shows correct counts
- Clicking on a violation opens the file and jumps to the correct line
- Refresh button in the tree view title bar works

### 4. Testing Integration

Test that all features work together:

**Steps:**
1. Open `test-sample.ps1`
2. Make a change (e.g., add a new line with `$md5 = [MD5]::Create()`)
3. Wait 1 second (debounce delay)
4. Verify:
   - Problems panel updates with new diagnostic
   - Hover over new line shows hover content
   - Tree view updates with new violation (may need refresh)

**Expected Results:**
- All three providers update in sync
- New violations are detected and displayed
- All providers show consistent information

## Manual Testing Workflow

1. **Open Extension Development Host** (F5 in vscode-extension folder)
2. **Open test file** (`test-sample.ps1`)
3. **Check Problems panel** - Should show ~8-10 security issues
4. **Hover over violations** - Should show rich educational content
5. **Open PowerShield Security sidebar** - Should show hierarchical view
6. **Click on violations in tree** - Should jump to code
7. **Click on CWE links** - Should open browser
8. **Run workspace analysis** - Should populate tree view with all issues

## Known Limitations

1. Some hover commands may not be fully implemented yet:
   - "Learn More" opens GitHub rules directory (dedicated docs site coming soon)
   - "Generate AI Fix" requires AI provider configuration
   - "Suppress" may show placeholder behavior

2. Tree view updates require manual refresh after file changes (automatic updates planned for Phase 2.4)

3. CWE links work and open the official MITRE CWE database

## Troubleshooting

**No diagnostics showing:**
- Ensure PowerShield core engine is working
- Check Output panel (View > Output) and select "PowerShield" from dropdown
- Verify file is a .ps1, .psm1, or .psd1 file
- Try running "PowerShield: Analyze Current File" command

**Tree view not updating:**
- Click the refresh button in tree view title
- Run "PowerShield: Refresh Security Overview" command
- Ensure real-time analysis is enabled in settings

**Hover not showing:**
- Ensure hover is on a line with a security violation
- Check that problems panel shows diagnostics for that line
- Try saving the file first

## Testing Checklist

- [ ] DiagnosticsProvider: Problems panel shows violations with CWE info
- [ ] DiagnosticsProvider: CWE links are clickable
- [ ] DiagnosticsProvider: Severity levels are correct (Error/Warning/Info)
- [ ] HoverProvider: Hover shows rich markdown content
- [ ] HoverProvider: Severity badges display correctly
- [ ] HoverProvider: CWE links work
- [ ] HoverProvider: Commands are present (even if not fully functional)
- [ ] TreeProvider: Tree view shows in Explorer sidebar
- [ ] TreeProvider: Categories group violations by severity
- [ ] TreeProvider: Summary shows correct counts
- [ ] TreeProvider: Clicking violation jumps to code
- [ ] TreeProvider: Refresh button works
- [ ] Integration: All providers update on file save
- [ ] Integration: Real-time analysis updates diagnostics after typing
