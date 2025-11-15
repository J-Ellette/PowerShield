# =====================================================================
# WARNING: This is a TEST FILE containing INTENTIONAL security violations
# These patterns are FAKE examples for testing purposes
# This file should be EXCLUDED from security scanning
# =====================================================================
# Test script for certificate store manipulation violations
# These patterns represent PKI security risks

# Violation 1: Exporting certificate with private key without protection
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object -First 1
Export-PfxCertificate -Cert $cert -FilePath "C:\temp\exported-cert.pfx" -Password (ConvertTo-SecureString "weak" -AsPlainText -Force)

# Violation 2: Accessing private keys directly
$certWithKey = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey }
$privateKey = $certWithKey.PrivateKey
$privateKeyXml = $privateKey.ToXmlString($true)

# Violation 3: Exporting certificate to insecure location
Get-ChildItem -Path Cert:\LocalMachine\Root | Export-Certificate -FilePath "C:\Users\Public\root-cert.cer"

# Violation 4: Installing certificate without validation
$certBytes = [System.IO.File]::ReadAllBytes("C:\temp\untrusted.cer")
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$certificate.Import($certBytes)
Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root -FilePath "C:\temp\untrusted.cer"

# Violation 5: Adding certificate to trusted root without verification
$newCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\temp\suspicious.cer")
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($newCert)
$store.Close()

# Violation 6: Exporting all certificates including private keys
Get-ChildItem -Path Cert:\CurrentUser\My | ForEach-Object {
    if ($_.HasPrivateKey) {
        Export-PfxCertificate -Cert $_ -FilePath "C:\temp\$($_.Thumbprint).pfx" -Password (ConvertTo-SecureString "backup" -AsPlainText -Force)
    }
}

# Violation 7: Weakening certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Violation 8: Extracting certificate private key bytes
$certPath = "Cert:\CurrentUser\My\1234567890ABCDEF1234567890ABCDEF12345678"
$cert = Get-Item $certPath
if ($cert.HasPrivateKey) {
    $rsaKey = $cert.PrivateKey
    $keyParameters = $rsaKey.ExportParameters($true)
    $modulusBytes = $keyParameters.Modulus
    $exponentBytes = $keyParameters.Exponent
}

# Violation 9: Creating self-signed certificate without proper constraints
$selfSignedCert = New-SelfSignedCertificate -DnsName "test.local" -CertStoreLocation Cert:\CurrentUser\My

# Violation 10: Moving certificate between stores without validation
$sourceCert = Get-ChildItem Cert:\CurrentUser\My | Select-Object -First 1
$destStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
$destStore.Open("ReadWrite")
$destStore.Add($sourceCert)
$destStore.Close()

# Violation 11: Exporting certificate chain
$cert = Get-ChildItem Cert:\LocalMachine\My | Select-Object -First 1
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.Build($cert)
foreach ($element in $chain.ChainElements) {
    Export-Certificate -Cert $element.Certificate -FilePath "C:\temp\chain-$($element.Certificate.Thumbprint).cer"
}

# Violation 12: Importing certificate from web without validation
$webCertUrl = "https://untrusted-site.com/certificate.cer"
$webCert = Invoke-WebRequest -Uri $webCertUrl -UseBasicParsing
[System.IO.File]::WriteAllBytes("C:\temp\web-cert.cer", $webCert.Content)
Import-Certificate -CertStoreLocation Cert:\CurrentUser\My -FilePath "C:\temp\web-cert.cer"

# Correct usage examples (should not trigger violations)
# Viewing certificate information without accessing private key
$safeCert = Get-ChildItem Cert:\CurrentUser\My | Select-Object Thumbprint, Subject, NotAfter

# Exporting public certificate only (no private key)
$publicCert = Get-ChildItem Cert:\CurrentUser\My | Select-Object -First 1
Export-Certificate -Cert $publicCert -FilePath "C:\temp\public-only.cer"

# Validating certificate before use
$testCert = Get-ChildItem Cert:\CurrentUser\My | Select-Object -First 1
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chainBuilt = $chain.Build($testCert)
if ($chainBuilt -and $chain.ChainStatus.Count -eq 0) {
    Write-Host "Certificate is valid"
}

# Using certificate for signing (appropriate use of private key)
$codeSigningCert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
if ($codeSigningCert) {
    Set-AuthenticodeSignature -FilePath "C:\scripts\myscript.ps1" -Certificate $codeSigningCert
}
