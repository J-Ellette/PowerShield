# Test script with certificate validation bypass violations

# Violation 1: Certificate callback that always returns true
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Violation 2: Disabling certificate revocation check
[System.Net.ServicePointManager]::CheckCertificateRevocationList = $false

# Violation 3: Certificate validation bypass in function
function Skip-CertificateValidation {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
}

# Correct usage (should not trigger violation)
# Proper certificate validation would implement actual checks
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $certificate, $chain, $sslPolicyErrors)
    
    # Implement proper validation logic here
    if ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
        return $true
    }
    
    # Additional validation logic
    return $false
}
