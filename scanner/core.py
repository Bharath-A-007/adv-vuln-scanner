import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import ssl
import socket
from datetime import datetime
import re
import time
import uuid

class AdvancedVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []
        
    def quick_scan(self):
        """Perform quick security assessment"""
        print(f"🔍 Starting quick scan for {self.target_url}")
        self.check_security_headers()  # FIXED: Changed from _scan_security_headers
        self.test_sql_injection()      # FIXED: Changed from _scan_sql_injection
        self.test_xss()                # FIXED: Changed from _scan_xss
        self.check_ssl_tls()           # FIXED: Changed from _check_ssl_tls
        return self.compile_results()  # FIXED: Changed from _compile_results
    
    def comprehensive_scan(self):
        """Comprehensive OWASP Top 10 scan"""
        print(f"🔍 Starting comprehensive scan for {self.target_url}")
        
        # OWASP 2021 & 2025 Coverage
        self.check_security_headers()
        self.test_sql_injection()
        self.test_xss()
        self.check_ssl_tls()
        self.check_security_misconfiguration()
        self.scan_for_sensitive_data()
        
        return self.compile_results()
    
    def check_security_headers(self):
        """Check for missing security headers"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            critical_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection', 
                'Content-Security-Policy': 'XSS protection',
                'Strict-Transport-Security': 'HTTPS enforcement'
            }
            
            for header, purpose in critical_headers.items():
                if header not in headers:
                    self.add_finding('HIGH', 'A05:2021', 
                                    f'Missing Security Header: {header}', 
                                    f'{header} is missing. {purpose}')
                else:
                    self.add_finding('LOW', 'A05:2021',
                                    f'Security Header Present: {header}',
                                    f'{header}: {headers[header]}')
                    
        except Exception as e:
            self.add_finding('MEDIUM', 'A05:2021',
                            'Cannot Check Security Headers',
                            f'Unable to retrieve headers: {str(e)}')
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                self.add_finding('LOW', 'A03:2021',
                                'No Forms Found for Testing',
                                'No input forms detected for SQLi testing')
                return
            
            payloads = ["' OR '1'='1", "admin'--", "1 UNION SELECT 1,2,3--"]
            
            for form in forms[:2]:  # Test first 2 forms only for demo
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Extract form inputs
                inputs = {}
                for input_tag in form.find_all('input'):
                    if input_tag.get('name') and input_tag.get('type') in ['text', 'password', 'search', 'email']:
                        inputs[input_tag['name']] = input_tag.get('value', 'test')
                
                for payload in payloads:
                    test_data = {k: payload for k, v in inputs.items()}
                    target_url = urljoin(self.target_url, form_action)
                    
                    try:
                        if form_method == 'post':
                            response = self.session.post(target_url, data=test_data, timeout=8)
                        else:
                            response = self.session.get(target_url, params=test_data, timeout=8)
                        
                        content_lower = response.text.lower()
                        
                        # Check for SQL error patterns
                        error_patterns = [
                            'sql syntax', 'mysql_fetch', 'unclosed quotation',
                            'ora-', 'microsoft.*odbc', 'syntax error'
                        ]
                        
                        if any(error in content_lower for error in error_patterns):
                            self.add_finding('CRITICAL', 'A03:2021',
                                            'SQL Injection Vulnerability Detected',
                                            f'SQLi detected with payload: {payload}',
                                            f'Form: {form_action}, Payload: {payload}')
                            return
                            
                    except requests.exceptions.Timeout:
                        self.add_finding('MEDIUM', 'A03:2021',
                                        'Possible Blind SQL Injection',
                                        f'Request timeout with payload: {payload}')
                    except Exception:
                        continue
                        
        except Exception as e:
            self.add_finding('MEDIUM', 'A03:2021',
                            'SQL Injection Test Failed',
                            f'SQLi testing failed: {str(e)}')
    
    def test_xss(self):
        """Test for XSS vulnerabilities"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert('XSS')</script>"
            ]
            
            for form in forms[:2]:  # Test first 2 forms
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Extract form inputs
                inputs = {}
                for input_tag in form.find_all('input'):
                    if input_tag.get('name') and input_tag.get('type') in ['text', 'password', 'search', 'email', 'url']:
                        inputs[input_tag['name']] = input_tag.get('value', 'test')
                
                for payload in payloads:
                    test_data = {k: payload for k, v in inputs.items()}
                    target_url = urljoin(self.target_url, form_action)
                    
                    try:
                        if form_method == 'post':
                            response = self.session.post(target_url, data=test_data, timeout=8)
                        else:
                            response = self.session.get(target_url, params=test_data, timeout=8)
                        
                        if payload in response.text:
                            self.add_finding('HIGH', 'A03:2021',
                                            'XSS Vulnerability Detected',
                                            f'Reflected XSS with payload: {payload}',
                                            f'Form: {form_action}, Payload: {payload}')
                            return
                            
                    except Exception:
                        continue
                        
        except Exception as e:
            self.add_finding('MEDIUM', 'A03:2021',
                            'XSS Test Failed',
                            f'XSS testing failed: {str(e)}')
    
    def check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        if not self.target_url.startswith('https://'):
            self.add_finding('CRITICAL', 'A02:2021',
                            'Website Not Using HTTPS',
                            'The website is served over HTTP instead of HTTPS')
            return
            
        try:
            domain = urlparse(self.target_url).hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate expiration
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        self.add_finding('HIGH', 'A02:2021',
                                        'SSL Certificate Expiring Soon',
                                        f'Certificate expires in {days_until_expiry} days')
                    else:
                        self.add_finding('LOW', 'A02:2021',
                                        'SSL Certificate Valid',
                                        f'Certificate valid for {days_until_expiry} days')
                    
                    # Check protocol
                    protocol = ssock.version()
                    if protocol in ['TLSv1', 'TLSv1.1']:
                        self.add_finding('MEDIUM', 'A02:2021',
                                        'Weak TLS Protocol',
                                        f'Using {protocol}, upgrade to TLS 1.2 or higher')
                    else:
                        self.add_finding('LOW', 'A02:2021',
                                        'Secure TLS Protocol',
                                        f'Using {protocol}')
                        
        except Exception as e:
            self.add_finding('MEDIUM', 'A02:2021',
                            'SSL/TLS Check Failed',
                            f'SSL/TLS verification failed: {str(e)}')
    
    def check_security_misconfiguration(self):
        """Check for security misconfigurations"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Check for directory listing
            if "index of /" in response.text.lower():
                self.add_finding('HIGH', 'A05:2021',
                                'Directory Listing Enabled',
                                'Directory listing exposes sensitive files')
            
            # Check for error messages
            error_indicators = ['stack trace', 'error in', 'exception', 'at line']
            for indicator in error_indicators:
                if indicator in response.text.lower():
                    self.add_finding('MEDIUM', 'A05:2021',
                                    'Error Messages Exposed',
                                    'Detailed error messages visible to users')
                    break
                    
        except Exception as e:
            self.add_finding('MEDIUM', 'A05:2021',
                            'Security Misconfiguration Check Failed',
                            f'Configuration check failed: {str(e)}')
    
    def scan_for_sensitive_data(self):
        """Scan for sensitive information exposure"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            content_lower = response.text.lower()
            
            sensitive_patterns = [
                'password', 'secret', 'api_key', 'token',
                'aws_access_key', 'database_password'
            ]
            
            for pattern in sensitive_patterns:
                if re.search(rf'\b{pattern}\b.*=.*[\'\"][^\'\"]+[\'\"]', content_lower):
                    self.add_finding('HIGH', 'A02:2021',
                                    'Sensitive Information Exposure',
                                    f'Possible {pattern} exposure in source code')
                    
        except Exception as e:
            self.add_finding('MEDIUM', 'A02:2021',
                            'Sensitive Data Scan Failed',
                            f'Sensitive data check failed: {str(e)}')
    
    def add_finding(self, severity, owasp_ref, title, description, evidence=''):
        """Add a vulnerability finding"""
        finding = {
            'severity': severity,
            'owasp_ref': owasp_ref,
            'title': title,
            'description': description,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat()
        }
        
        self.findings.append(finding)
        print(f"📝 Found: {severity} - {title}")
    
    def compile_results(self):
        """Compile scan results with risk scoring"""
        risk_score = self.calculate_risk_score()
        
        return {
            'target_url': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'risk_score': risk_score,
            'risk_level': self.get_risk_level(risk_score),
            'findings': self.findings,
            'summary': self.generate_summary(),
            'scan_id': str(uuid.uuid4())
        }
    
    def calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        severity_weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
        total_score = sum(severity_weights.get(finding['severity'], 0) for finding in self.findings)
        return min(100, total_score * 2)  # Normalize to 100
    
    def get_risk_level(self, score):
        """Convert score to risk level"""
        if score >= 70: return 'HIGH'
        if score >= 40: return 'MEDIUM'
        return 'LOW'
    
    def generate_summary(self):
        """Generate findings summary"""
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
