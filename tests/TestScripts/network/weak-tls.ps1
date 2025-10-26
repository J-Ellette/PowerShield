# Test script for WeakTLS rule
# This script contains intentional security violations for testing purposes

# ❌ VIOLATION: Forcing weak TLS 1.0
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls

# ❌ VIOLATION: Enabling SSL3 (deprecated and insecure)
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Ssl3

# ❌ VIOLATION: Using TLS 1.1 (weak)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11

# ❌ VIOLATION: Downgrading from TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = "Tls"

# ✅ SAFE: Using TLS 1.2 or higher (should not be flagged)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
