# Test script for XMLSecurity rule (XXE vulnerabilities)
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Loading XML without disabling external entities
$xmlContent = @"
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
"@
$xml = New-Object System.Xml.XmlDocument
$xml.LoadXml($xmlContent)

# ❌ VIOLATION: XmlReader without secure settings
$xmlFile = "C:\Data\untrusted.xml"
$reader = [System.Xml.XmlReader]::Create($xmlFile)
while ($reader.Read()) {
    Write-Host $reader.Value
}

# ❌ VIOLATION: XmlDocument.Load from untrusted source
$untrustedUrl = "http://malicious.example.com/data.xml"
$xmlDoc = New-Object System.Xml.XmlDocument
$xmlDoc.Load($untrustedUrl)

# ❌ VIOLATION: Using XmlTextReader without DTD processing disabled
$xmlReader = New-Object System.Xml.XmlTextReader("C:\Temp\external.xml")
$xmlData = New-Object System.Xml.XmlDocument
$xmlData.Load($xmlReader)

# ✅ SAFE: XML loading with secure settings (should not be flagged)
$settings = New-Object System.Xml.XmlReaderSettings
$settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
$settings.XmlResolver = $null
$secureReader = [System.Xml.XmlReader]::Create("C:\Data\safe.xml", $settings)
$safeXml = New-Object System.Xml.XmlDocument
$safeXml.Load($secureReader)
