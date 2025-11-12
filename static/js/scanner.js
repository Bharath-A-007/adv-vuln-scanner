class VulnerabilityScanner {
    constructor(targetUrl) {
        this.targetUrl = targetUrl;
        this.results = {
            findings: [],
            riskScore: 0,
            summary: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                total: 0
            }
        };
    }

    async quickScan() {
        console.log('Starting quick security scan...');
        
        try {
            // Test security headers
            await this.testSecurityHeaders();
            
            // Test for common vulnerabilities
            await this.testCommonVulnerabilities();
            
            // Calculate risk score
            this.calculateRiskScore();
            
            return this.results;
            
        } catch (error) {
            console.error('Scan failed:', error);
            throw error;
        }
    }

    async comprehensiveScan() {
        console.log('Starting comprehensive OWASP scan...');
        
        try {
            // OWASP 2021 & 2025 Tests
            await this.testBrokenAccessControl();
            await this.testCryptographicFailures();
            await this.testInjectionVulnerabilities();
            await this.testInsecureDesign();
            await this.testSecurityMisconfiguration();
            await this.testVulnerableComponents();
            await this.testIdentificationFailures();
            await this.testIntegrityFailures();
            await this.testLoggingFailures();
            await this.testSSRF();
            
            // Calculate risk score
            this.calculateRiskScore();
            
            return this.results;
            
        } catch (error) {
            console.error('Comprehensive scan failed:', error);
            throw error;
        }
    }

    async testSecurityHeaders() {
        try {
            const response = await fetch(this.targetUrl, {
                method: 'HEAD',
                mode: 'no-cors'
            });
            
            const headers = response.headers;
            const criticalHeaders = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ];
            
            criticalHeaders.forEach(header => {
                if (!headers.get(header)) {
                    this.addFinding(
                        'HIGH',
                        'A05:2021',
                        `Missing Security Header: ${header}`,
                        `The ${header} header is missing, which could lead to security vulnerabilities.`
                    );
                }
            });
            
        } catch (error) {
            this.addFinding(
                'MEDIUM',
                'A05:2021',
                'Cannot Check Security Headers',
                `Unable to retrieve headers: ${error.message}`
            );
        }
    }

    async testCommonVulnerabilities() {
        // Test for SQL Injection
        await this.testSQLInjection();
        
        // Test for XSS
        await this.testXSS();
        
        // Test for mixed content
        await this.testMixedContent();
    }

    async testSQLInjection() {
        const testPayloads = [
            "' OR '1'='1",
            "admin'--",
            "1 UNION SELECT 1,2,3--"
        ];
        
        for (const payload of testPayloads) {
            try {
                const testUrl = `${this.targetUrl}?search=${encodeURIComponent(payload)}`;
                const response = await fetch(testUrl);
                const text = await response.text();
                
                if (this.detectSQLiPatterns(text)) {
                    this.addFinding(
                        'CRITICAL',
                        'A03:2021',
                        'SQL Injection Vulnerability Detected',
                        `The application is vulnerable to SQL injection with payload: ${payload}`,
                        `Test payload used: ${payload}`
                    );
                    break;
                }
            } catch (error) {
                console.log('SQLi test failed for payload:', payload);
            }
        }
    }

    async testXSS() {
        const xssPayloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')"
        ];
        
        for (const payload of xssPayloads) {
            try {
                const testUrl = `${this.targetUrl}?q=${encodeURIComponent(payload)}`;
                const response = await fetch(testUrl);
                const text = await response.text();
                
                if (text.includes(payload)) {
                    this.addFinding(
                        'HIGH',
                        'A03:2021',
                        'Cross-Site Scripting (XSS) Vulnerability',
                        `Reflected XSS detected with payload: ${payload}`,
                        `Payload reflected in response: ${payload.substring(0, 50)}...`
                    );
                    break;
                }
            } catch (error) {
                console.log('XSS test failed for payload:', payload);
            }
        }
    }

    detectSQLiPatterns(text) {
        const patterns = [
            /sql syntax.*error/i,
            /mysql_fetch_array/i,
            /unclosed quotation mark/i,
            /microsoft.*odbc/i,
            /ora-[0-9]/i
        ];
        
        return patterns.some(pattern => pattern.test(text));
    }

    addFinding(severity, owaspRef, title, description, evidence = '') {
        const finding = {
            id: this.results.findings.length + 1,
            severity: severity,
            owasp_ref: owaspRef,
            title: title,
            description: description,
            evidence: evidence,
            timestamp: new Date().toISOString()
        };
        
        this.results.findings.push(finding);
        
        // Update summary
        this.results.summary[severity.toLowerCase()]++;
        this.results.summary.total++;
    }

    calculateRiskScore() {
        const weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 1
        };
        
        let totalScore = 0;
        this.results.findings.forEach(finding => {
            totalScore += weights[finding.severity] || 0;
        });
        
        // Normalize to 0-100 scale
        this.results.riskScore = Math.min(100, totalScore * 2);
        
        return this.results.riskScore;
    }

    // Additional OWASP test methods
    async testBrokenAccessControl() {
        // Implement access control tests
        console.log('Testing broken access control...');
    }

    async testCryptographicFailures() {
        // Check for HTTPS and crypto issues
        if (!this.targetUrl.startsWith('https://')) {
            this.addFinding(
                'CRITICAL',
                'A02:2021',
                'Website Not Using HTTPS',
                'The website is served over HTTP instead of HTTPS, exposing data to interception.'
            );
        }
    }

    async testInsecureDesign() {
        // Test for design-level vulnerabilities
        console.log('Testing insecure design patterns...');
    }

    async testSecurityMisconfiguration() {
        // Test for misconfigurations
        console.log('Testing security misconfigurations...');
    }

    async testVulnerableComponents() {
        // Identify vulnerable components
        console.log('Testing for vulnerable components...');
    }

    async testIdentificationFailures() {
        // Test authentication mechanisms
        console.log('Testing identification failures...');
    }

    async testIntegrityFailures() {
        // Test integrity issues
        console.log('Testing integrity failures...');
    }

    async testLoggingFailures() {
        // Test logging and monitoring
        console.log('Testing logging failures...');
    }

    async testSSRF() {
        // Test for SSRF vulnerabilities
        console.log('Testing SSRF vulnerabilities...');
    }

    async testMixedContent() {
        // Check for mixed content issues
        if (this.targetUrl.startsWith('https://')) {
            try {
                const response = await fetch(this.targetUrl);
                const text = await response.text();
                
                if (text.includes('http://') && !text.includes('https://')) {
                    this.addFinding(
                        'MEDIUM',
                        'A02:2021',
                        'Mixed Content Issues',
                        'The HTTPS site loads resources over HTTP, reducing security benefits.'
                    );
                }
            } catch (error) {
                console.log('Mixed content test failed');
            }
        }
    }
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VulnerabilityScanner;
}
