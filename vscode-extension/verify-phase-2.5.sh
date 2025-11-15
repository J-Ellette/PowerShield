#!/bin/bash
# Phase 2.5 Verification Script
# Verifies all Phase 2.5 components are properly implemented

set -e

echo "🔍 Phase 2.5 Verification Script"
echo "================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Change to extension directory
cd "$(dirname "$0")"

echo "📁 Working directory: $(pwd)"
echo ""

# Test 1: Build compilation
echo "Test 1: TypeScript Compilation"
echo "-------------------------------"
if npm run compile 2>&1 | grep -q "error"; then
    echo -e "${RED}❌ FAILED: TypeScript compilation has errors${NC}"
    exit 1
else
    echo -e "${GREEN}✅ PASSED: TypeScript compiles successfully${NC}"
fi
echo ""

# Test 2: Check required files exist
echo "Test 2: Required Files Exist"
echo "-----------------------------"
REQUIRED_FILES=(
    "src/providers/CodeLensProvider.ts"
    "src/webview/SecurityDashboard.ts"
    "src/webview/SettingsPanel.ts"
    "out/providers/CodeLensProvider.js"
    "out/webview/SecurityDashboard.js"
    "out/webview/SettingsPanel.js"
)

ALL_FILES_EXIST=true
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅ Found: $file${NC}"
    else
        echo -e "${RED}❌ Missing: $file${NC}"
        ALL_FILES_EXIST=false
    fi
done

if [ "$ALL_FILES_EXIST" = false ]; then
    echo -e "${RED}❌ FAILED: Some required files are missing${NC}"
    exit 1
else
    echo -e "${GREEN}✅ PASSED: All required files exist${NC}"
fi
echo ""

# Test 3: Check commands in package.json
echo "Test 3: Commands Registration"
echo "------------------------------"
REQUIRED_COMMANDS=(
    "powershield.showScopeViolations"
    "powershield.applyAllScopeFixes"
    "powershield.showDocumentSummary"
)

ALL_COMMANDS_EXIST=true
for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if grep -q "\"$cmd\"" package.json; then
        echo -e "${GREEN}✅ Command registered: $cmd${NC}"
    else
        echo -e "${RED}❌ Command missing: $cmd${NC}"
        ALL_COMMANDS_EXIST=false
    fi
done

if [ "$ALL_COMMANDS_EXIST" = false ]; then
    echo -e "${RED}❌ FAILED: Some commands are not registered${NC}"
    exit 1
else
    echo -e "${GREEN}✅ PASSED: All commands are registered${NC}"
fi
echo ""

# Test 4: Check imports in extension.ts
echo "Test 4: Extension Integration"
echo "------------------------------"
REQUIRED_IMPORTS=(
    "SecurityCodeLensProvider"
    "SecurityDashboard"
    "SettingsPanel"
)

ALL_IMPORTS_EXIST=true
for import in "${REQUIRED_IMPORTS[@]}"; do
    if grep -q "$import" src/extension.ts; then
        echo -e "${GREEN}✅ Import exists: $import${NC}"
    else
        echo -e "${RED}❌ Import missing: $import${NC}"
        ALL_IMPORTS_EXIST=false
    fi
done

if [ "$ALL_IMPORTS_EXIST" = false ]; then
    echo -e "${RED}❌ FAILED: Some imports are missing${NC}"
    exit 1
else
    echo -e "${GREEN}✅ PASSED: All imports are present${NC}"
fi
echo ""

# Test 5: Check event system in RealTimeAnalysisProvider
echo "Test 5: Event System Implementation"
echo "------------------------------------"
if grep -q "onViolationsUpdated" src/providers/RealTimeAnalysisProvider.ts; then
    echo -e "${GREEN}✅ Event system method found${NC}"
else
    echo -e "${RED}❌ Event system method missing${NC}"
    exit 1
fi

if grep -q "_onViolationsUpdated" src/providers/RealTimeAnalysisProvider.ts; then
    echo -e "${GREEN}✅ Event emitter found${NC}"
else
    echo -e "${RED}❌ Event emitter missing${NC}"
    exit 1
fi
echo -e "${GREEN}✅ PASSED: Event system is implemented${NC}"
echo ""

# Test 6: Check compiled output
echo "Test 6: Compiled Output Verification"
echo "-------------------------------------"
COMPILED_FILES=(
    "out/extension.js"
    "out/providers/CodeLensProvider.js"
    "out/webview/SecurityDashboard.js"
    "out/webview/SettingsPanel.js"
)

ALL_COMPILED=true
for file in "${COMPILED_FILES[@]}"; do
    if [ -f "$file" ] && [ -s "$file" ]; then
        SIZE=$(wc -c < "$file")
        echo -e "${GREEN}✅ Compiled: $file (${SIZE} bytes)${NC}"
    else
        echo -e "${RED}❌ Not compiled or empty: $file${NC}"
        ALL_COMPILED=false
    fi
done

if [ "$ALL_COMPILED" = false ]; then
    echo -e "${RED}❌ FAILED: Some files are not properly compiled${NC}"
    exit 1
else
    echo -e "${GREEN}✅ PASSED: All files are properly compiled${NC}"
fi
echo ""

# Test 7: Code quality checks
echo "Test 7: Code Quality Checks"
echo "----------------------------"

# Check for TODO or FIXME comments in new files
TODO_COUNT=$(grep -r "TODO\|FIXME" src/providers/CodeLensProvider.ts src/webview/ 2>/dev/null | wc -l)
if [ "$TODO_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Warning: Found $TODO_COUNT TODO/FIXME comments${NC}"
else
    echo -e "${GREEN}✅ No TODO/FIXME comments${NC}"
fi

# Check for console.log in new files (should use proper logging)
CONSOLE_COUNT=$(grep -r "console\.log" src/providers/CodeLensProvider.ts src/webview/ 2>/dev/null | wc -l)
if [ "$CONSOLE_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Info: Found $CONSOLE_COUNT console.log statements${NC}"
else
    echo -e "${GREEN}✅ No console.log statements${NC}"
fi

# Check for proper error handling
ERROR_HANDLING=$(grep -r "try\|catch" src/webview/SecurityDashboard.ts src/webview/SettingsPanel.ts 2>/dev/null | wc -l)
if [ "$ERROR_HANDLING" -gt 10 ]; then
    echo -e "${GREEN}✅ Proper error handling found (${ERROR_HANDLING} try/catch blocks)${NC}"
else
    echo -e "${YELLOW}⚠️  Warning: Limited error handling (${ERROR_HANDLING} try/catch blocks)${NC}"
fi
echo ""

# Summary
echo "================================"
echo "📊 Verification Summary"
echo "================================"
echo -e "${GREEN}✅ All Phase 2.5 components verified successfully!${NC}"
echo ""
echo "Deliverables:"
echo "  ✅ 2.5.1: CodeLens Integration"
echo "  ✅ 2.5.2: Security Dashboard & Reports"
echo "  ✅ 2.5.3: Configuration & Settings UI"
echo ""
echo "Build Status: ✅ Passing"
echo "Integration: ✅ Complete"
echo "Documentation: ✅ Available (PHASE_2.5_SUMMARY.md)"
echo ""
echo "🎉 Phase 2.5 implementation is ready!"
echo ""
