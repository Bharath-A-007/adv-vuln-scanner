"""
Utility functions for the vulnerability scanner
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import socket
import ssl
from datetime import datetime
import time

class ScannerUtils:
    @staticmethod
    def normalize_url(url):
        """Normalize URL by ensuring proper scheme"""
        if not url:
            return url
            
        url = url.strip()
        url = re.sub(r'^https?://', '', url)
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        return url
    
    @staticmethod
    def extract_forms(session, url):
        """Extract all forms from a webpage"""
        try:
            response = session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                # Get all input fields
                for input_tag in form.find_all('input'):
                    if input_tag.get('name'):
                        form_data['inputs'].append({
                            'name': input_tag.get('name'),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        })
                
                # Get textarea fields
                for textarea in form.find_all('textarea'):
                    if textarea.get('name'):
                        form_data['inputs'].append({
                            'name': textarea.get('name'),
                            'type': 'textarea',
                            'value': textarea.get_text()
                        })
                
                # Get select fields
                for select in form.find_all('select'):
                    if select.get('name'):
                        form_data['inputs'].append({
                            'name': select.get('name'),
                            'type': 'select',
                            'value': ''
                        })
                
                forms.append(form_data)
            return forms
        except Exception as e:
            return []
    
    @staticmethod
    def check_ssl_certificate(url):
        """Check SSL certificate validity and configuration"""
        if not url.startswith('https://'):
            return {'valid': False, 'error': 'Not HTTPS'}
        
        try:
            hostname = urlparse(url).hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate expiration
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    # Check protocol
                    protocol = ssock.version()
                    
                    return {
                        'valid': True,
                        'expiry_days': days_until_expiry,
                        'protocol': protocol,
                        'cipher': cipher[0] if cipher else None,
                        'issuer': dict(x[0] for x in cert['issuer'])
                    }
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    @staticmethod
    def check_security_headers(session, url):
        """Check for security headers in HTTP response"""
        try:
            response = session.get(url, timeout=10, verify=False)
            headers = response.headers
            findings = []
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'XSS protection',
                'X-XSS-Protection': 'XSS filter',
                'Referrer-Policy': 'Referrer information control',
                'Permissions-Policy': 'Browser features control'
            }
            
            for header, purpose in security_headers.items():
                if header not in headers:
                    findings.append({
                        'severity': 'HIGH',
                        'title': f'Missing security header: {header}',
                        'description': purpose
                    })
                else:
                    findings.append({
                        'severity': 'INFO',
                        'title': f'Security header present: {header}',
                        'description': f'{header}: {headers[header]}'
                    })
            
            return findings
        except Exception as e:
            return [{
                'severity': 'INFO',
                'title': 'Failed to check security headers',
                'description': str(e)
            }]
    
    @staticmethod
    def test_sql_injection(session, form, target_url):
        """Test a form for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "admin'--",
            "1' UNION SELECT 1,2,3--",
            "' AND 1=1--"
        ]
        
        error_patterns = [
            'sql syntax', 'mysql_fetch', 'ora-', 'postgresql',
            'unclosed quotation', 'syntax error', 'mysql.*result'
        ]
        
        for payload in payloads:
            try:
                test_data = {}
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'password', 'search', 'email']:
                        test_data[input_field['name']] = payload
                    else:
                        test_data[input_field['name']] = input_field.get('value', '')
                
                full_url = urljoin(target_url, form['action'])
                
                if form['method'] == 'post':
                    response = session.post(full_url, data=test_data, timeout=8, verify=False)
                else:
                    response = session.get(full_url, params=test_data, timeout=8, verify=False)
                
                content_lower = response.text.lower()
                
                # Check for SQL errors in response
                if any(error in content_lower for error in error_patterns):
                    return True, payload
                    
                # Check for time-based blind SQLi
                if "' AND SLEEP" in payload.upper():
                    start_time = time.time()
                    if form['method'] == 'post':
                        session.post(full_url, data=test_data, timeout=15, verify=False)
                    else:
                        session.get(full_url, params=test_data, timeout=15, verify=False)
                    response_time = time.time() - start_time
                    
                    if response_time > 5:
                        return True, payload
                        
            except requests.exceptions.Timeout:
                return True, payload
            except:
                continue
        
        return False, None
    
    @staticmethod
    def test_xss(session, form, target_url):
        """Test a form for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>"
        ]
        
        for payload in payloads:
            try:
                test_data = {}
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'password', 'search', 'email', 'url']:
                        test_data[input_field['name']] = payload
                    else:
                        test_data[input_field['name']] = input_field.get('value', '')
                
                full_url = urljoin(target_url, form['action'])
                
                if form['method'] == 'post':
                    response = session.post(full_url, data=test_data, timeout=8, verify=False)
                else:
                    response = session.get(full_url, params=test_data, timeout=8, verify=False)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    return True, payload
                    
            except:
                continue
        
        return False, None
    
    @staticmethod
    def calculate_risk_score(findings):
        """Calculate overall risk score based on findings"""
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7, 
            'MEDIUM': 4,
            'LOW': 1,
            'INFO': 0
        }
        
        total_score = sum(severity_weights.get(finding['severity'], 0) for finding in findings)
        normalized_score = min(100, total_score * 2)  # Scale to 100
        
        return normalized_score
    
    @staticmethod
    def get_risk_level(score):
        """Convert risk score to risk level"""
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
