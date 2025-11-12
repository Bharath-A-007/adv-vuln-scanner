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
