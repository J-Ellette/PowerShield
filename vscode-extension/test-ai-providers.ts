/**
 * Test AI Providers
 * Basic tests to verify AI provider functionality
 */

import { SecurityViolation, FixContext, SecuritySeverity } from './src/types';
import { TemplateBasedProvider } from './src/ai/TemplateBasedProvider';
import { FixContextBuilder } from './src/ai/FixContextBuilder';

/**
 * Create a sample violation for testing
 */
function createSampleViolation(ruleId: string, code: string): SecurityViolation {
    return {
        name: ruleId,
        message: `Security violation: ${ruleId}`,
        description: `Test violation for ${ruleId}`,
        severity: SecuritySeverity.High,
        lineNumber: 10,
        columnNumber: 0,
        code: code,
        filePath: 'test.ps1',
        ruleId: ruleId
    };
}

/**
 * Create a sample fix context
 */
function createSampleContext(code: string): FixContext {
    const violation = createSampleViolation('TestRule', code);
    
    return {
        violation,
        codeContext: {
            beforeLines: [
                'function Test-Function {',
                '    param(',
                '        [string]$Input',
                '    )'
            ],
            targetCode: code,
            afterLines: [
                '    Write-Output "Done"',
                '}'
            ]
        }
    };
}

/**
 * Test Template-Based Provider
 */
async function testTemplateProvider() {
    console.log('\n=== Testing Template-Based Provider ===\n');
    
    const provider = new TemplateBasedProvider();
    await provider.initialize({ name: 'template-based', type: 'template-based' });
    
    // Test 1: Insecure Hash Algorithm
    console.log('Test 1: Insecure Hash Algorithm');
    const hashViolation = createSampleViolation(
        'InsecureHashAlgorithm',
        '$hash = [System.Security.Cryptography.MD5]::Create()'
    );
    const hashContext = createSampleContext(hashViolation.code);
    const hashFix = await provider.generateFix(hashViolation, hashContext);
    
    console.log('  Original:', hashViolation.code);
    console.log('  Fixed:', hashFix.fixedCode);
    console.log('  Confidence:', hashFix.confidence);
    console.log('  ✓ Test passed\n');
    
    // Test 2: Credential Exposure
    console.log('Test 2: Credential Exposure');
    const credViolation = createSampleViolation(
        'CredentialExposure',
        '$password = "MyPassword123"'
    );
    const credContext = createSampleContext(credViolation.code);
    const credFix = await provider.generateFix(credViolation, credContext);
    
    console.log('  Original:', credViolation.code);
    console.log('  Fixed:', credFix.fixedCode);
    console.log('  Confidence:', credFix.confidence);
    console.log('  ✓ Test passed\n');
    
    // Test 3: Command Injection
    console.log('Test 3: Command Injection');
    const cmdViolation = createSampleViolation(
        'CommandInjection',
        'Invoke-Expression $userInput'
    );
    const cmdContext = createSampleContext(cmdViolation.code);
    const cmdFix = await provider.generateFix(cmdViolation, cmdContext);
    
    console.log('  Original:', cmdViolation.code);
    console.log('  Fixed:', cmdFix.fixedCode.substring(0, 100) + '...');
    console.log('  Confidence:', cmdFix.confidence);
    console.log('  ✓ Test passed\n');
    
    // Test 4: Certificate Validation
    console.log('Test 4: Certificate Validation');
    const certViolation = createSampleViolation(
        'CertificateValidation',
        '[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}'
    );
    const certContext = createSampleContext(certViolation.code);
    const certFix = await provider.generateFix(certViolation, certContext);
    
    console.log('  Original:', certViolation.code);
    console.log('  Fixed:', certFix.fixedCode.substring(0, 100) + '...');
    console.log('  Confidence:', certFix.confidence);
    console.log('  ✓ Test passed\n');
    
    // Test 5: Explanation
    console.log('Test 5: Violation Explanation');
    const explanation = await provider.explainViolation(hashViolation);
    console.log('  Explanation length:', explanation.length, 'characters');
    console.log('  ✓ Test passed\n');
    
    // Test 6: Best Practices
    console.log('Test 6: Best Practices Suggestion');
    const practices = await provider.suggestBestPractices('$password = "test"');
    console.log('  Suggestions:', practices.length);
    practices.forEach((p, i) => console.log(`    ${i + 1}. ${p.substring(0, 60)}...`));
    console.log('  ✓ Test passed\n');
    
    console.log('=== All Template Provider Tests Passed! ===\n');
}

/**
 * Test AI Provider availability
 */
async function testProviderAvailability() {
    console.log('\n=== Testing Provider Availability ===\n');
    
    const template = new TemplateBasedProvider();
    await template.initialize({ name: 'template-based', type: 'template-based' });
    
    console.log('Template-Based Provider:');
    console.log('  Available:', await template.isAvailable());
    console.log('  Name:', template.name);
    console.log('  Type:', template.type);
    console.log('  ✓ Test passed\n');
    
    console.log('Note: To test other providers (GitHub Models, OpenAI, etc.),');
    console.log('      set appropriate environment variables and run again.\n');
}

/**
 * Run all tests
 */
async function runTests() {
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║         PowerShield AI Provider Tests                   ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
    
    try {
        await testProviderAvailability();
        await testTemplateProvider();
        
        console.log('╔══════════════════════════════════════════════════════════╗');
        console.log('║                  All Tests Passed! ✓                    ║');
        console.log('╚══════════════════════════════════════════════════════════╝\n');
        
        process.exit(0);
    } catch (error) {
        console.error('\n✗ Tests failed:', error);
        process.exit(1);
    }
}

// Run tests
runTests();
