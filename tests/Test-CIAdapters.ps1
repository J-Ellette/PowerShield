#Requires -Version 7.0

<#
.SYNOPSIS
    Test script for CI/CD platform adapters
.DESCRIPTION
    Tests all CI adapter implementations to ensure they load and function correctly
#>

Write-Host "Testing PowerShield CI/CD Adapters..." -ForegroundColor Cyan
Write-Host ""

# Import the CIAdapter module
Import-Module ./src/CIAdapter.psm1 -Force

# Test 1: Module imports successfully
Write-Host "✓ CIAdapter module imported successfully" -ForegroundColor Green

# Test 2: Factory creates an adapter
$adapter = New-CIAdapter
if ($adapter) {
    Write-Host "✓ CI Adapter factory works: Created $($adapter.Name) adapter" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to create CI adapter" -ForegroundColor Red
    exit 1
}

# Test 3: Get context
try {
    $context = $adapter.GetContext()
    Write-Host "✓ Successfully retrieved CI context" -ForegroundColor Green
    Write-Host "  Provider: $($context.Provider)" -ForegroundColor Gray
    Write-Host "  Repository: $($context.Repository)" -ForegroundColor Gray
    Write-Host "  Branch: $($context.Branch)" -ForegroundColor Gray
} catch {
    Write-Host "✗ Failed to get context: $_" -ForegroundColor Red
    exit 1
}

# Test 4: Test all adapter types
Write-Host ""
Write-Host "Testing individual adapter types..." -ForegroundColor Cyan

$adapterTypes = @(
    [GitHubActionsAdapter],
    [AzureDevOpsAdapter],
    [GitLabCIAdapter],
    [JenkinsAdapter],
    [CircleCIAdapter],
    [TeamCityAdapter],
    [GenericCIAdapter]
)

$allPassed = $true

foreach ($adapterType in $adapterTypes) {
    try {
        $testAdapter = $adapterType::new()
        $testContext = $testAdapter.GetContext()
        Write-Host "✓ $($testAdapter.Name) adapter works" -ForegroundColor Green
    } catch {
        Write-Host "✗ $($testAdapter.Name) adapter failed: $_" -ForegroundColor Red
        $allPassed = $false
    }
}

# Test 5: Test changed file discovery
Write-Host ""
Write-Host "Testing changed file discovery..." -ForegroundColor Cyan
try {
    $changedFiles = $adapter.DiscoverChangedFiles(".")
    Write-Host "✓ Changed file discovery works (found $($changedFiles.Count) files)" -ForegroundColor Green
} catch {
    Write-Host "⚠ Changed file discovery failed (expected in some environments): $_" -ForegroundColor Yellow
}

# Test 6: Test inline annotations support
Write-Host ""
Write-Host "Testing inline annotations..." -ForegroundColor Cyan
$supportsAnnotations = $adapter.SupportsInlineAnnotations()
if ($supportsAnnotations) {
    Write-Host "✓ $($adapter.Name) supports inline annotations" -ForegroundColor Green
    try {
        $adapter.CreateAnnotation("test.ps1", 10, "warning", "Test annotation")
        Write-Host "✓ Annotation creation works" -ForegroundColor Green
    } catch {
        Write-Host "✗ Annotation creation failed: $_" -ForegroundColor Red
        $allPassed = $false
    }
} else {
    Write-Host "ℹ $($adapter.Name) does not support inline annotations" -ForegroundColor Gray
}

# Summary
Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
if ($allPassed) {
    Write-Host "All CI Adapter tests passed! ✓" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some tests failed ✗" -ForegroundColor Red
    exit 1
}
