# Test script for script block logging detection

# Violation 1: Disabling module auto-loading
$PSModuleAutoLoadingPreference = 'None'

# Violation 2: Disabling script block logging via registry
$enableScriptBlockLogging = $false

# Violation 3: Another logging disable pattern
$ScriptBlockLogging = 0

# Correct usage (should not trigger violations)
$PSModuleAutoLoadingPreference = 'All'
