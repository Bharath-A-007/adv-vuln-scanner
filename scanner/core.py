import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import ssl
import socket
from datetime import datetime
import re

class AdvancedVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []
        
    def quick_scan(self):
        """Perform quick security assessment"""
        self._scan_security_headers()
        self._scan_injection_vulnerabilities()
        self._scan_authentication_issues()
        return self._compile_results()
    
    def comprehensive_scan(self):
        """Comprehensive OWASP Top 10 scan"""
        # OWASP 2021 & 2025 Coverage
        self._scan_broken_access_control()
        self._scan_cryptographic_failures()
        self._scan_injection_vulnerabilities()
        self._scan_insecure_design()
        self._scan_security_misconfiguration()
        self._scan_vulnerable_components()
        self._scan_identification_failures()
        self._scan_integrity_failures()
        self._scan_logging_failures()
        self._scan_ssrf()
        
        return self._compile_results()
    
    def _scan_broken_access_control(self):
        """A01: Broken Access Control"""
        tests = [
            self._test_directory_traversal,
            self._test_insecure_direct_object_references,
            self._test_missing_authorization
        ]
        for test in tests:
            test()
    
    def _scan_cryptographic_failures(self):
        """A02: Cryptographic Failures & A04:2025"""
        if not self.target_url.startswith('https://'):
            self._add_finding('CRITICAL', 'A02:2021', 'Website not using HTTPS', 'Data transmitted over unencrypted connection')
        
        self._check_ssl_tls_configuration()
        self._scan_for_sensitive_data()
    
    def _scan_injection_vulnerabilities(self):
        """A03:2021 Injection & A05:2025 Injection"""
        self._test_sql_injection()
        self._test_xss()
        self._test_command_injection()
    
    def _scan_insecure_design(self):
        """A04:2021 Insecure Design & A06:2025 Insecure Design"""
        self._test_business_logic_flaws()
        self._check_default_credentials()
    
    def _scan_security_misconfiguration(self):
        """A05:2021 Security Misconfiguration & A02:2025"""
        self._check_security_headers()
        self._check_debug_mode()
        self._check_directory_listing()
        self._check_error_messages()
    
    def _scan_vulnerable_components(self):
        """A06:2021 Vulnerable Components & A03:2025 Supply Chain"""
        self._identify_technologies()
        self._check_known_vulnerabilities()
    
    def _scan_identification_failures(self):
        """A07:2021 Identification Failures & A07:2025 Authentication"""
        self._test_authentication_mechanisms()
        self._check_session_management()
    
    def _scan_integrity_failures(self):
        """A08:2021 Integrity Failures & A08:2025"""
        self._check_code_integrity()
        self._test_deserialization()
    
    def _scan_logging_failures(self):
        """A09:2021 Logging Failures & A09:2025"""
        self._check_audit_logs()
    
    def _scan_ssrf(self):
        """A10:2021 SSRF"""
        self._test_ssrf_vulnerabilities()
    
    # Implementation of individual test methods
    def _check_security_headers(self):
        headers = self._get_headers()
        critical_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'XSS protection',
            'X-XSS-Protection': 'XSS filter'
        }
        
        for header, purpose in critical_headers.items():
            if header not in headers:
                self._add_finding('HIGH', 'A05:2021', f'Missing security header: {header}', purpose)
    
    def _test_sql_injection(self):
        forms = self._extract_forms()
        payloads = ["' OR '1'='1", "admin'--", "1 UNION SELECT 1,2,3--"]
        
        for form in forms:
            for payload in payloads:
                if self._submit_payload(form, payload):
                    self._add_finding('CRITICAL', 'A03:2021', 'SQL Injection vulnerability', f'Vulnerable parameter in {form["action"]}')
                    return
    
    def _test_xss(self):
        forms = self._extract_forms()
        payload = "<script>alert('XSS')</script>"
        
        for form in forms:
            if self._submit_payload(form, payload) and payload in self._get_response(form, payload).text:
                self._add_finding('HIGH', 'A03:2021', 'XSS vulnerability', 'Reflected XSS detected')
                return
    
    def _check_ssl_tls_configuration(self):
        if self.target_url.startswith('https://'):
            try:
                hostname = urlparse(self.target_url).hostname
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        
                        # Check certificate expiry
                        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if (expiry - datetime.now()).days < 30:
                            self._add_finding('HIGH', 'A02:2021', 'SSL certificate expiring soon', 'Renew SSL certificate')
                        
                        # Check protocol
                        if ssock.version() in ['TLSv1', 'TLSv1.1']:
                            self._add_finding('MEDIUM', 'A02:2021', 'Weak TLS protocol', 'Upgrade to TLS 1.2 or higher')
            except Exception as e:
                self._add_finding('MEDIUM', 'A02:2021', 'SSL/TLS configuration issue', str(e))
    
    # Utility methods
    def _get_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=10)
            return response.headers
        except:
            return {}
    
    def _extract_forms(self):
        try:
            response = self.session.get(self.target_url, timeout=10)
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
    
    def _submit_payload(self, form, payload):
        try:
            target_url = urljoin(self.target_url, form['action'])
            data = {input_tag['name']: payload for input_tag in form['inputs']}
            
            if form['method'] == 'post':
                response = self.session.post(target_url, data=data, timeout=8)
            else:
                response = self.session.get(target_url, params=data, timeout=8)
            
            return response
        except:
            return None
    
    def _add_finding(self, severity, category, title, description):
        self.findings.append({
            'severity': severity,
            'category': category,
            'title': title,
            'description': description,
            'owasp_ref': category
        })
    
    def _compile_results(self):
        # Calculate risk score
        risk_score = self._calculate_risk_score()
        
        return {
            'target_url': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'findings': self.findings,
            'summary': self._generate_summary()
        }
    
    def _calculate_risk_score(self):
        severity_weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
        total_score = sum(severity_weights.get(finding['severity'], 0) for finding in self.findings)
        return min(100, total_score * 2)  # Normalize to 100
    
    def _get_risk_level(self, score):
        if score >= 70: return 'HIGH'
        if score >= 40: return 'MEDIUM'
        return 'LOW'
    
    def _generate_summary(self):
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            counts[finding['severity']] += 1
        
        return {
            'total_findings': len(self.findings),
            'critical': counts['CRITICAL'],
            'high': counts['HIGH'],
            'medium': counts['MEDIUM'],
            'low': counts['LOW']
        }

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
