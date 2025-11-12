from flask import Flask, render_template, request, send_file, jsonify
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
from datetime import datetime
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'web-doc-secret-key-2024'

# Store scan results temporarily
scan_results_store = {}

class SimpleVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
    
    def quick_scan(self):
        """Perform quick security assessment"""
        print(f"🔍 Starting quick scan for {self.target_url}")
        
        try:
            # Test 1: Check security headers
            self.check_security_headers()
            
            # Test 2: Check if HTTPS
            self.check_https()
            
            # Test 3: Look for common vulnerabilities
            self.check_common_issues()
            
            return self.compile_results()
            
        except Exception as e:
            self.add_finding('MEDIUM', 'Scan Error', f'Scan failed: {str(e)}', '')
            return self.compile_results()
    
    def comprehensive_scan(self):
        """Comprehensive scan - same as quick for now"""
        return self.quick_scan()
    
    def check_security_headers(self):
        """Check for missing security headers"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            headers = response.headers
            
            critical_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection', 
                'Content-Security-Policy': 'XSS protection',
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
    
    def check_https(self):
        """Check if website uses HTTPS"""
        if not self.target_url.startswith('https://'):
            self.add_finding('HIGH', 'A02:2021',
                            'Website Not Using HTTPS',
                            'The website is served over HTTP instead of HTTPS')
        else:
            self.add_finding('LOW', 'A02:2021',
                            'Website Using HTTPS',
                            'Good: Website uses secure HTTPS protocol')
    
    def check_common_issues(self):
        """Check for common web vulnerabilities"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            content = response.text.lower()
            
            # Check for directory listing
            if "index of /" in content:
                self.add_finding('HIGH', 'A05:2021',
                                'Directory Listing Enabled',
                                'Directory listing exposes sensitive files')
            
            # Check for error messages
            if "error" in content or "exception" in content:
                self.add_finding('MEDIUM', 'A05:2021',
                                'Error Messages May Be Exposed',
                                'Error messages visible to users')
            
            # Check for common admin paths
            admin_paths = ['/admin', '/wp-admin', '/administrator']
            for path in admin_paths:
                test_url = urljoin(self.target_url, path)
                try:
                    admin_response = requests.get(test_url, timeout=5, verify=False)
                    if admin_response.status_code == 200:
                        self.add_finding('MEDIUM', 'A01:2021',
                                        f'Admin Panel Accessible: {path}',
                                        f'Admin panel found at {path}')
                except:
                    pass
                    
        except Exception as e:
            self.add_finding('MEDIUM', 'Scan Error',
                            'Common Issues Check Failed',
                            f'Common vulnerability check failed: {str(e)}')
    
    def add_finding(self, severity, category, title, description):
        """Add a vulnerability finding"""
        finding = {
            'severity': severity,
            'owasp_ref': category,
            'title': title,
            'description': description,
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
        if not self.findings:
            return 10  # Low risk if no findings
        
        severity_weights = {'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
        total_score = sum(severity_weights.get(finding['severity'], 0) for finding in self.findings)
        return min(100, total_score * 3)
    
    def get_risk_level(self, score):
        """Convert score to risk level"""
        if score >= 60: return 'HIGH'
        if score >= 30: return 'MEDIUM'
        return 'LOW'
    
    def generate_summary(self):
        """Generate findings summary"""
        counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            counts[finding['severity']] += 1
        
        return {
            'total_findings': len(self.findings),
            'high': counts['HIGH'],
            'medium': counts['MEDIUM'],
            'low': counts['LOW']
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_website():
    target_url = request.json.get('url')
    scan_type = request.json.get('scan_type', 'quick')
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    print(f"🎯 Scanning: {target_url} ({scan_type} scan)")
    
    # Initialize scanner
    scanner = SimpleVulnerabilityScanner(target_url)
    
    # Perform scan
    try:
        if scan_type == 'comprehensive':
            results = scanner.comprehensive_scan()
        else:
            results = scanner.quick_scan()
        
        # Store results with unique ID
        scan_id = results['scan_id']
        scan_results_store[scan_id] = results
        
        print(f"✅ Scan completed. Found {len(results['findings'])} vulnerabilities")
        return jsonify(results)
        
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/results')
def show_results():
    return render_template('results.html')

@app.route('/download-report')
def download_report():
    scan_id = request.args.get('scan_id')
    if not scan_id or scan_id not in scan_results_store:
        return jsonify({'error': 'Scan results not found'}), 404
    
    results = scan_results_store[scan_id]
    
    # Simple PDF generation (you can enhance this later)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from datetime import datetime
        
        filename = f"web_doc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join('reports', filename)
        
        # Create reports directory if it doesn't exist
        if not os.path.exists('reports'):
            os.makedirs('reports')
        
        # Create simple PDF
        c = canvas.Canvas(filepath, pagesize=letter)
        c.drawString(100, 750, "Web Doc Security Scan Report")
        c.drawString(100, 730, f"Target: {results['target_url']}")
        c.drawString(100, 710, f"Scan Date: {results['scan_date']}")
        c.drawString(100, 690, f"Risk Score: {results['risk_score']}/100 ({results['risk_level']})")
        
        y_position = 650
        for i, finding in enumerate(results['findings']):
            if y_position < 100:  # New page if needed
                c.showPage()
                y_position = 750
            
            c.drawString(100, y_position, f"{i+1}. {finding['severity']}: {finding['title']}")
            y_position -= 20
        
        c.save()
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({'error': f'PDF generation failed: {str(e)}'}), 500

@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    if scan_id in scan_results_store:
        return jsonify(scan_results_store[scan_id])
    return jsonify({'error': 'Results not found'}), 404

if __name__ == '__main__':
    if not os.path.exists('reports'):
        os.makedirs('reports')
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
