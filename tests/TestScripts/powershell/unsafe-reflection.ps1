# Test script for unsafe reflection detection

# Violation 1: Assembly::LoadFrom
$assembly = [System.Reflection.Assembly]::LoadFrom("C:\temp\untrusted.dll")

# Violation 2: Assembly::Load
$asm = [System.Reflection.Assembly]::Load("UntrustedAssembly")

# Violation 3: Assembly::LoadFile
$file = [System.Reflection.Assembly]::LoadFile("C:\malicious.dll")

# Violation 4: Direct assembly access
$type = (Get-Process).GetType().Assembly

# Correct usage (these still trigger but are documented patterns)
# Use trusted assemblies only
$trustedAsm = [System.Reflection.Assembly]::Load("System.Management.Automation")
