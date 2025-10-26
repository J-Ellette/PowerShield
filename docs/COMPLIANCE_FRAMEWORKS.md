# PowerShield Compliance Framework Mappings

This document describes how PowerShield security rules map to various compliance frameworks and standards.

## Supported Frameworks

PowerShield provides comprehensive compliance reporting for the following frameworks:

1. **NIST Cybersecurity Framework 1.1** - 7 controls
2. **CIS PowerShell Security Benchmark 1.0** - 6 controls
3. **OWASP Top 10 2021** - 6 categories
4. **SOC 2 Type II** - 5 controls
5. **PCI-DSS 4.0** - 4 controls
6. **HIPAA Security Rule 2023** - 5 controls

**Total**: 33 controls across 6 frameworks

## NIST Cybersecurity Framework 1.1

### PR.AC-4 - Access Control
**Category**: Protect - Access Control  
**Description**: Access permissions and authorizations are managed  
**Mapped Rules**:
- `CredentialExposure` - Detects plaintext credentials
- `AzurePowerShellCredentialLeaks` - Azure credential exposure
- `CredentialHarvesting` - Credential theft attempts

### PR.AC-7 - Authentication
**Category**: Protect - Access Control  
**Description**: Users, devices, and other assets are authenticated  
**Mapped Rules**:
- `CertificateValidation` - SSL/TLS certificate validation bypass
- `CertificateStoreManipulation` - Certificate store tampering
- `AzureEntraIDPrivilegedOperations` - Privileged identity operations

### PR.DS-1 - Data at Rest Protection
**Category**: Protect - Data Security  
**Description**: Data-at-rest is protected  
**Mapped Rules**:
- `InsecureHashAlgorithms` - Weak cryptographic hashes (MD5, SHA1)
- `AzureEncryptionBypass` - Disabled encryption in Azure

### PR.DS-2 - Data in Transit Protection
**Category**: Protect - Data Security  
**Description**: Data-in-transit is protected  
**Mapped Rules**:
- `UnsafeHTTPUsage` - HTTP instead of HTTPS
- `TLSVersionDowngrade` - Outdated TLS versions

### DE.CM-4 - Malicious Code Detection
**Category**: Detect - Continuous Monitoring  
**Description**: Malicious code is detected  
**Mapped Rules**:
- `PowerShellObfuscation` - Code obfuscation techniques
- `DownloadCradle` - Download-and-execute patterns
- `AMSIEvasion` - Anti-Malware Scan Interface evasion
- `ETWEvasion` - Event Tracing for Windows evasion

### DE.CM-7 - Unauthorized Access Monitoring
**Category**: Detect - Continuous Monitoring  
**Description**: Monitoring for unauthorized personnel, connections, devices  
**Mapped Rules**:
- `LateralMovement` - Network lateral movement
- `PSRemotingUnsafe` - Unsafe PowerShell remoting
- `RemoteExecution` - Remote code execution

### RS.AN-3 - Forensics
**Category**: Respond - Analysis  
**Description**: Forensics are performed  
**Mapped Rules**:
- `ScriptBlockLoggingDisabled` - Disabled PowerShell logging
- `AzureLoggingDisabled` - Disabled Azure diagnostic logs

## CIS PowerShell Security Benchmark 1.0

### 1.1 - Execution Policy
**Description**: Ensure PowerShell execution policy is configured  
**Mapped Rules**:
- `ExecutionPolicyBypass` - Execution policy bypass attempts

### 2.1 - Script Block Logging
**Description**: Enable PowerShell script block logging  
**Mapped Rules**:
- `ScriptBlockLoggingDisabled` - Disabled script block logging

### 2.2 - Transcription
**Description**: Enable PowerShell transcription logging  
**Mapped Rules**:
- `TranscriptionLoggingDisabled` - Disabled transcription

### 3.1 - Remoting Security
**Description**: Configure PowerShell remoting securely  
**Mapped Rules**:
- `PSRemotingUnsafe` - Unsafe remoting configurations
- `RemoteExecution` - Unsafe remote execution

### 4.1 - Version Control
**Description**: Disable PowerShell v2  
**Mapped Rules**:
- `PowerShellVersion2` - PowerShell v2 usage

### 5.1 - Credential Management
**Description**: Protect credentials in scripts  
**Mapped Rules**:
- `CredentialExposure` - Plaintext credential storage
- `ConvertToSecureStringPlainText` - Insecure SecureString usage

## OWASP Top 10 2021

### A01 - Broken Access Control
**Description**: Restrictions on authenticated users not properly enforced  
**Mapped Rules**:
- `UnsafeFilePermissions` - Inadequate file permissions
- `RegistryPermissionsBypass` - Registry permission issues

### A02 - Cryptographic Failures
**Description**: Failures related to cryptography leading to sensitive data exposure  
**Mapped Rules**:
- `InsecureHashAlgorithms` - Weak cryptographic algorithms
- `AzureEncryptionBypass` - Disabled encryption

### A03 - Injection
**Description**: Injection flaws such as SQL, command, LDAP injection  
**Mapped Rules**:
- `CommandInjection` - Command injection vulnerabilities
- `SQLInjection` - SQL injection patterns
- `LDAPInjection` - LDAP injection patterns

### A05 - Security Misconfiguration
**Description**: Missing or insecure configurations  
**Mapped Rules**:
- `CertificateValidation` - SSL/TLS validation bypass
- `ExecutionPolicyBypass` - Execution policy bypass
- `AzurePolicyAndCompliance` - Azure policy violations

### A07 - Identification and Authentication Failures
**Description**: Failures in authentication mechanisms  
**Mapped Rules**:
- `CredentialExposure` - Credential exposure
- `AzurePowerShellCredentialLeaks` - Azure credential leaks

### A09 - Security Logging and Monitoring Failures
**Description**: Insufficient logging and monitoring  
**Mapped Rules**:
- `ScriptBlockLoggingDisabled` - Disabled logging
- `AzureLoggingDisabled` - Disabled Azure logging

## SOC 2 Type II

### CC6.1 - Logical Access Controls
**Category**: Common Criteria - Logical and Physical Access Controls  
**Description**: Restrict logical access to system resources  
**Mapped Rules**:
- `CredentialExposure` - Credential management
- `UnsafeFilePermissions` - File access control

### CC6.6 - Data Protection
**Category**: Common Criteria - Logical and Physical Access Controls  
**Description**: Protect data in transit and at rest  
**Mapped Rules**:
- `InsecureHashAlgorithms` - Cryptographic protection
- `UnsafeHTTPUsage` - Data transmission security
- `AzureEncryptionBypass` - Encryption controls

### CC6.7 - Confidential Information Access
**Category**: Common Criteria - Logical and Physical Access Controls  
**Description**: Restrict access to confidential information  
**Mapped Rules**:
- `CredentialExposure` - Sensitive data protection
- `AzurePowerShellCredentialLeaks` - Cloud credential security

### CC7.2 - Security Event Detection
**Category**: Common Criteria - System Operations  
**Description**: Detect security events and incidents  
**Mapped Rules**:
- `PowerShellObfuscation` - Malicious activity detection
- `DownloadCradle` - Threat detection
- `CredentialHarvesting` - Attack detection

### CC7.3 - Security Event Evaluation
**Category**: Common Criteria - System Operations  
**Description**: Evaluate security events to determine if incidents occurred  
**Mapped Rules**:
- `ScriptBlockLoggingDisabled` - Logging capabilities
- `AzureLoggingDisabled` - Monitoring capabilities

## PCI-DSS 4.0

### 3.5 - Protect Encryption Keys
**Category**: Protect Stored Cardholder Data  
**Description**: Protect encryption keys  
**Mapped Rules**:
- `CredentialExposure` - Key management
- `CertificateStoreManipulation` - Certificate key protection

### 4.1 - Strong Cryptography for Transmission
**Category**: Protect Cardholder Data with Strong Cryptography  
**Description**: Use strong cryptography for transmission  
**Mapped Rules**:
- `UnsafeHTTPUsage` - Secure transmission
- `TLSVersionDowngrade` - Strong encryption protocols
- `InsecureHashAlgorithms` - Cryptographic strength

### 8.2 - User Authentication
**Category**: Identify Users and Authenticate Access  
**Description**: Ensure proper user authentication  
**Mapped Rules**:
- `CredentialExposure` - Authentication security
- `ConvertToSecureStringPlainText` - Credential handling

### 10.2 - Audit Trails
**Category**: Log and Monitor All Access  
**Description**: Implement automated audit trails  
**Mapped Rules**:
- `ScriptBlockLoggingDisabled` - Audit logging
- `AzureLoggingDisabled` - Access logging

## HIPAA Security Rule 2023

### 164.308(a)(3) - Workforce Security
**Category**: Administrative Safeguards  
**Description**: Implement procedures to authorize access to ePHI  
**Mapped Rules**:
- `CredentialExposure` - Access authorization
- `UnsafeFilePermissions` - File access controls

### 164.308(a)(5)(ii)(C) - Login Monitoring
**Category**: Security Awareness and Training  
**Description**: Implement procedures for login monitoring  
**Mapped Rules**:
- `ScriptBlockLoggingDisabled` - Activity logging

### 164.312(a)(2)(iv) - Encryption and Decryption
**Category**: Technical Safeguards - Access Control  
**Description**: Implement encryption and decryption  
**Mapped Rules**:
- `InsecureHashAlgorithms` - Cryptographic controls
- `AzureEncryptionBypass` - Encryption implementation

### 164.312(e)(1) - Transmission Security
**Category**: Technical Safeguards - Transmission Security  
**Description**: Implement technical security measures for electronic communications  
**Mapped Rules**:
- `UnsafeHTTPUsage` - Secure communication
- `TLSVersionDowngrade` - Transmission protocols

### 164.312(e)(2)(II) - Encryption of ePHI
**Category**: Technical Safeguards - Transmission Security  
**Description**: Implement encryption of ePHI in transit  
**Mapped Rules**:
- `UnsafeHTTPUsage` - Data encryption in transit
- `InsecureHashAlgorithms` - Cryptographic methods

## Using Compliance Features

### Generate Compliance Dashboard

```powershell
# Show compliance status for all frameworks
psts compliance dashboard

# Export dashboard as HTML
psts compliance dashboard --output compliance-dashboard.html --format html

# Export as JSON for processing
psts compliance dashboard --output compliance-status.json --format json
```

### Assess Specific Framework

```powershell
# Assess NIST compliance
psts compliance assess --framework NIST

# Assess PCI-DSS compliance with detailed output
psts compliance assess --framework PCI-DSS --output pci-dss-assessment.md
```

### Generate Gap Analysis

```powershell
# Generate gap analysis for SOC 2
psts compliance gap-analysis --framework SOC2

# All frameworks
psts compliance gap-analysis --framework All --output gap-analysis.md
```

### Export Audit Evidence

```powershell
# Create audit evidence package
psts compliance audit

# Custom output location
psts compliance audit --output audit-evidence-2025.json
```

## Configuration

Enable compliance reporting in `.powershield.yml`:

```yaml
compliance:
  enabled: true
  frameworks:
    - NIST
    - CIS
    - OWASP
    - SOC2
    - PCI-DSS
    - HIPAA
  minimum_compliance: 80
  generate_reports: true
  report_format: "markdown"
```

## Interpreting Results

### Compliance Status

- **Compliant**: No violations found for mapped rules (0 violations)
- **Partially Compliant**: Few violations found (1-2 violations)
- **Non-Compliant**: Multiple violations found (3+ violations)

### Compliance Percentage

Calculated as: `(Compliant Controls / Total Controls) × 100`

### Gap Analysis

Gap analysis reports include:
- Control ID and description
- Current compliance status
- Number of violations
- Specific affected rules
- Detailed remediation steps

### Audit Evidence

Audit evidence packages contain:
- Analysis summary
- Compliance status for all frameworks
- Violation details with file locations
- Audit trail metadata
- Tool version and date

## Best Practices

1. **Regular Assessment**: Run compliance assessments regularly (weekly/monthly)
2. **Baseline Tracking**: Create baselines to track compliance improvements over time
3. **Framework Selection**: Focus on frameworks relevant to your industry
4. **Remediation Priority**: Address non-compliant controls first
5. **Documentation**: Keep audit evidence for compliance verification
6. **Team Sharing**: Share compliance reports with security and compliance teams

## Framework Updates

PowerShield's compliance mappings are maintained to align with:
- NIST Cybersecurity Framework updates
- CIS Benchmark releases
- OWASP Top 10 revisions
- Industry standard changes

Check the [PowerShield releases](https://github.com/J-Ellette/PowerShield/releases) for mapping updates.

## Questions or Issues?

- **Documentation**: See main README.md
- **Issues**: [GitHub Issues](https://github.com/J-Ellette/PowerShield/issues)
- **Discussions**: [GitHub Discussions](https://github.com/J-Ellette/PowerShield/discussions)
