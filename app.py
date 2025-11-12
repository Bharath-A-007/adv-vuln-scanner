from flask import Flask, render_template, request, send_file, jsonify
import os
import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'web-doc-secret-key-2024'

scan_results_store = {}

class WorkingScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
    
    def quick_scan(self):
        """Simple working scanner"""
        print(f"🎯 Scanning: {self.target_url}")
        
        try:
            # Test 1: Basic connection and headers
            response = requests.get(self.target_url, timeout=10, verify=False)
            
            # Check HTTPS
            if not self.target_url.startswith('https://'):
                self.add_finding('HIGH', 'A02:2021', 'No HTTPS', 'Website uses HTTP instead of HTTPS')
            
            # Check security headers
            headers = response.headers
            if 'X-Frame-Options' not in headers:
                self.add_finding('MEDIUM', 'A05:2021', 'Missing X-Frame-Options', 'Clickjacking protection missing')
            if 'Content-Security-Policy' not in headers:
                self.add_finding('MEDIUM', 'A05:2021', 'Missing CSP', 'Content Security Policy missing')
            
            # Check for common issues
            content = response.text.lower()
            if "index of /" in content:
                self.add_finding('HIGH', 'A05:2021', 'Directory Listing', 'Directory listing enabled')
            if "error" in content or "exception" in content:
                self.add_finding('LOW', 'A05:2021', 'Error Messages', 'Error messages may be visible')
            
            # Add some demo findings for presentation
            self.add_finding('LOW', 'Demo', 'Security Scan Complete', 'Basic security assessment completed')
            
            return self.compile_results()
            
        except Exception as e:
            self.add_finding('MEDIUM', 'Error', f'Scan Error: {str(e)}', 'Scanner encountered an error')
            return self.compile_results()
    
    def comprehensive_scan(self):
        """Same as quick scan for now"""
        return self.quick_scan()
    
    def add_finding(self, severity, category, title, description):
        finding = {
            'severity': severity,
            'owasp_ref': category,
            'title': title,
            'description': description,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)
        print(f"📝 {severity}: {title}")
    
    def compile_results(self):
        risk_score = min(100, len(self.findings) * 15)
        return {
            'target_url': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'risk_score': risk_score,
            'risk_level': 'HIGH' if risk_score > 60 else 'MEDIUM' if risk_score > 30 else 'LOW',
            'findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'critical': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                'high': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'medium': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'low': len([f for f in self.findings if f['severity'] == 'LOW'])
            },
            'scan_id': str(uuid.uuid4())
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_website():
    try:
        target_url = request.json.get('url')
        scan_type = request.json.get('scan_type', 'quick')
        
        if not target_url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        print(f"🎯 Starting scan: {target_url}")
        
        # Use the working scanner
        scanner = WorkingScanner(target_url)
        
        if scan_type == 'comprehensive':
            results = scanner.comprehensive_scan()
        else:
            results = scanner.quick_scan()
        
        # Store results
        scan_id = results['scan_id']
        scan_results_store[scan_id] = results
        
        print(f"✅ Scan completed! Found {len(results['findings'])} issues")
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
    
    # Simple PDF report
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        
        filename = f"web_doc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join('reports', filename)
        
        if not os.path.exists('reports'):
            os.makedirs('reports')
        
        c = canvas.Canvas(filepath, pagesize=letter)
        c.drawString(100, 750, "Web Doc Security Scan Report")
        c.drawString(100, 730, f"Target: {results['target_url']}")
        c.drawString(100, 710, f"Risk Score: {results['risk_score']}/100")
        c.drawString(100, 690, f"Findings: {len(results['findings'])}")
        
        y = 650
        for i, finding in enumerate(results['findings']):
            if y < 100:
                c.showPage()
                y = 750
            c.drawString(100, y, f"{i+1}. [{finding['severity']}] {finding['title']}")
            y -= 20
        
        c.save()
        
        return send_file(filepath, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({'error': f'PDF failed: {str(e)}'}), 500

if __name__ == '__main__':
    if not os.path.exists('reports'):
        os.makedirs('reports')
    
    import urllib3
    urllib3.disable_warnings()
    
    print("🚀 Web Doc Scanner Starting...")
    print("📋 Open: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
