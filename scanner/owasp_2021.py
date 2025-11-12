"""
OWASP Top 10 2021 Vulnerability Checks
"""

class OWASP2021Scanner:
    def __init__(self, target_url, session):
        self.target_url = target_url
        self.session = session
        self.findings = []
    
    def check_broken_access_control(self):
        """A01:2021 - Broken Access Control"""
        tests = [
            self._test_insecure_direct_object_references,
            self._test_missing_function_level_access_control,
            self._test_elevation_of_privilege
        ]
        for test in tests:
            test()
    
    def check_cryptographic_failures(self):
        """A02:2021 - Cryptographic Failures"""
        if not self.target_url.startswith('https://'):
            self._add_finding('CRITICAL', 'A02:2021', 
                            'Website not using HTTPS', 
                            'Sensitive data exposed over unencrypted connection')
        
        self._check_weak_crypto_implementation()
        self._check_sensitive_data_exposure()
    
    def check_injection(self):
        """A03:2021 - Injection"""
        self._test_sql_injection()
        self._test_command_injection()
        self._test_ldap_injection()
    
    def check_insecure_design(self):
        """A04:2021 - Insecure Design"""
        self._test_business_logic_flaws()
        self._check_missing_security_controls()
    
    def check_security_misconfiguration(self):
        """A05:2021 - Security Misconfiguration"""
        self._check_default_credentials()
        self._check_unnecessary_features()
        self._check_insecure_configurations()
    
    def check_vulnerable_components(self):
        """A06:2021 - Vulnerable and Outdated Components"""
        self._identify_technologies()
        self._check_known_vulnerabilities()
    
    def check_identification_failures(self):
        """A07:2021 - Identification and Authentication Failures"""
        self._test_weak_authentication()
        self._check_session_management()
        self._test_credential_stuffing()
    
    def check_software_data_integrity(self):
        """A08:2021 - Software and Data Integrity Failures"""
        self._check_insecure_deserialization()
        self._test_integrity_verification()
    
    def check_security_logging(self):
        """A09:2021 - Security Logging and Monitoring Failures"""
        self._check_audit_logs()
        self._test_logging_mechanisms()
    
    def check_ssrf(self):
        """A10:2021 - Server-Side Request Forgery"""
        self._test_ssrf_vulnerabilities()
    
    # Implementation methods
    def _test_insecure_direct_object_references(self):
        """Test for IDOR vulnerabilities"""
        try:
            test_urls = [
                f"{self.target_url}/user/1/profile",
                f"{self.target_url}/admin/1/settings",
                f"{self.target_url}/api/user/1"
            ]
            
            for test_url in test_urls:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    self._add_finding('HIGH', 'A01:2021',
                                    'Insecure Direct Object Reference (IDOR)',
                                    f'Accessible without authorization: {test_url}')
                    break
        except:
            pass
    
    def _test_sql_injection(self):
        """Comprehensive SQL injection testing"""
        payloads = [
            "' OR '1'='1",
            "admin'--",
            "1' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "'; DROP TABLE users--"
        ]
        
        forms = self._extract_forms()
        for form in forms:
            for payload in payloads:
                if self._is_sql_injection_vulnerable(form, payload):
                    self._add_finding('CRITICAL', 'A03:2021',
                                    'SQL Injection vulnerability',
                                    f'Vulnerable to {payload} in {form["action"]}')
                    return
    
    def _check_weak_crypto_implementation(self):
        """Check for weak cryptographic implementations"""
        try:
            response = self.session.get(self.target_url, timeout=5)
            headers = response.headers
            
            # Check for weak cookies
            if 'set-cookie' in headers:
                cookie_header = headers['set-cookie'].lower()
                if 'httponly' not in cookie_header:
                    self._add_finding('MEDIUM', 'A02:2021',
                                    'Cookie without HttpOnly flag',
                                    'Cookies accessible via JavaScript')
                
                if 'secure' not in cookie_header and self.target_url.startswith('https://'):
                    self._add_finding('MEDIUM', 'A02:2021',
                                    'Cookie without Secure flag',
                                    'Cookies transmitted over insecure connection')
        except:
            pass
    
    def _extract_forms(self):
        """Extract all forms from the target page"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all('input'):
                    if input_tag.get('name'):
                        form_data['inputs'].append({
                            'name': input_tag.get('name'),
                            'type': input_tag.get('type', 'text')
                        })
                
                forms.append(form_data)
            return forms
        except:
            return []
    
    def _is_sql_injection_vulnerable(self, form, payload):
        """Check if form is vulnerable to SQL injection"""
        try:
            from urllib.parse import urljoin
            target_url = urljoin(self.target_url, form['action'])
            data = {input_tag['name']: payload for input_tag in form['inputs']}
            
            error_indicators = [
                'sql syntax', 'mysql_fetch', 'ora-', 'postgresql',
                'unclosed quotation', 'syntax error'
            ]
            
            if form['method'] == 'post':
                response = self.session.post(target_url, data=data, timeout=8)
            else:
                response = self.session.get(target_url, params=data, timeout=8)
            
            content_lower = response.text.lower()
            return any(error in content_lower for error in error_indicators)
        except:
            return False
    
    def _add_finding(self, severity, category, title, description):
        """Add a vulnerability finding"""
        self.findings.append({
            'severity': severity,
            'category': category,
            'title': title,
            'description': description,
            'owasp_ref': category
        })
