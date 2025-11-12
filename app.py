from flask import Flask, render_template, request, send_file, jsonify
import os
from scanner.core import AdvancedVulnerabilityScanner
from report_generator import PDFReportGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'web-doc-secret-key-2024'

# Store scan results temporarily
scan_results_store = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_website():
    target_url = request.json.get('url')
    scan_type = request.json.get('scan_type', 'quick')
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Initialize scanner
    scanner = AdvancedVulnerabilityScanner(target_url)
    
    # Perform scan
    if scan_type == 'comprehensive':
        results = scanner.comprehensive_scan()
    else:
        results = scanner.quick_scan()
    
    # Store results with unique ID
    import uuid
    scan_id = str(uuid.uuid4())
    scan_results_store[scan_id] = results
    
    results['scan_id'] = scan_id
    return jsonify(results)

@app.route('/results')
def show_results():
    return render_template('results.html')

@app.route('/download-report')
def download_report():
    scan_id = request.args.get('scan_id')
    if not scan_id or scan_id not in scan_results_store:
        return jsonify({'error': 'Scan results not found'}), 404
    
    results = scan_results_store[scan_id]
    
    # Generate PDF report
    pdf_generator = PDFReportGenerator()
    pdf_path = pdf_generator.generate_report(results)
    
    # Return PDF file
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f'web_doc_security_report_{results["target_url"].replace("://", "_")}.pdf',
        mimetype='application/pdf'
    )

@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    if scan_id in scan_results_store:
        return jsonify(scan_results_store[scan_id])
    return jsonify({'error': 'Results not found'}), 404

if __name__ == '__main__':
    if not os.path.exists('reports'):
        os.makedirs('reports')
    app.run(debug=True)
