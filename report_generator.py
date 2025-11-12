from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import inch
from datetime import datetime
import os

class PDFReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
    
    def _create_custom_styles(self):
        # Title style
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            textColor=colors.HexColor('#2563eb'),
            alignment=1
        )
        
        # Heading styles
        self.heading1_style = ParagraphStyle(
            'Heading1',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.HexColor('#1e293b')
        )
        
        self.heading2_style = ParagraphStyle(
            'Heading2',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceAfter=8,
            textColor=colors.HexColor('#374151')
        )
        
        # Severity styles
        self.critical_style = ParagraphStyle(
            'Critical',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#dc2626'),
            backColor=colors.HexColor('#fef2f2'),
            borderPadding=5,
            borderColor=colors.HexColor('#fca5a5'),
            borderWidth=1
        )
        
        self.high_style = ParagraphStyle(
            'High',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#ea580c'),
            backColor=colors.HexColor('#fff7ed'),
            borderPadding=5,
            borderColor=colors.HexColor('#fdba74'),
            borderWidth=1
        )
        
        self.medium_style = ParagraphStyle(
            'Medium',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#d97706'),
            backColor=colors.HexColor('#fffbeb'),
            borderPadding=5,
            borderColor=colors.HexColor('#fcd34d'),
            borderWidth=1
        )
        
        self.low_style = ParagraphStyle(
            'Low',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#059669'),
            backColor=colors.HexColor('#f0fdf4'),
            borderPadding=5,
            borderColor=colors.HexColor('#86efac'),
            borderWidth=1
        )
    
    def generate_report(self, scan_results):
        """Generate comprehensive PDF security report"""
        filename = f"security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join('reports', filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=0.5*inch)
        story = []
        
        # Cover Page
        story.extend(self._create_cover_page(scan_results))
        story.append(PageBreak())
        
        # Executive Summary
        story.extend(self._create_executive_summary(scan_results))
        story.append(PageBreak())
        
        # Detailed Findings
        story.extend(self._create_detailed_findings(scan_results))
        story.append(PageBreak())
        
        # Remediation Guidance
        story.extend(self._create_remediation_guide(scan_results))
        
        # Build PDF
        doc.build(story)
        return filepath
    
    def _create_cover_page(self, results):
        elements = []
        
        # Title
        title = Paragraph("SECURITY ASSESSMENT REPORT", self.title_style)
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))
        
        # Scan Details Table
        scan_data = [
            ['Target URL:', results['target_url']],
            ['Scan Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Risk Level:', f"{results['risk_level']} ({results['risk_score']}/100)"],
            ['Total Findings:', str(len(results['findings']))],
            ['Scan Duration:', 'Quick Scan' if len(results['findings']) < 15 else 'Comprehensive Scan']
        ]
        
        scan_table = Table(scan_data, colWidths=[2*inch, 4*inch])
        scan_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#374151')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
        ]))
        elements.append(scan_table)
        elements.append(Spacer(1, 0.5*inch))
        
        # Risk Meter Visualization
        risk_text = f"Overall Risk Score: {results['risk_score']}/100 - {results['risk_level'].upper()} RISK"
        risk_para = Paragraph(risk_text, self.heading1_style)
        elements.append(risk_para)
        
        return elements
    
    def _create_executive_summary(self, results):
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.title_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Severity Breakdown
        severity_counts = self._count_severities(results['findings'])
        
        summary_data = [
            ['Severity Level', 'Count', 'Percentage'],
            ['CRITICAL', str(severity_counts['CRITICAL']), f"{(severity_counts['CRITICAL']/len(results['findings']))*100:.1f}%"],
            ['HIGH', str(severity_counts['HIGH']), f"{(severity_counts['HIGH']/len(results['findings']))*100:.1f}%"],
            ['MEDIUM', str(severity_counts['MEDIUM']), f"{(severity_counts['MEDIUM']/len(results['findings']))*100:.1f}%"],
            ['LOW', str(severity_counts['LOW']), f"{(severity_counts['LOW']/len(results['findings']))*100:.1f}%"],
            ['TOTAL', str(len(results['findings'])), '100%']
        ]
        
        summary_table = Table(summary_data, colWidths=[1.5*inch, 1*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#fef2f2')),  # Critical row
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#fff7ed')),  # High row
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#fffbeb')),  # Medium row
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#f0fdf4')),  # Low row
            ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#f8fafc')),  # Total row
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
        ]))
        elements.append(summary_table)
        
        return elements
    
    def _create_detailed_findings(self, results):
        elements = []
        
        elements.append(Paragraph("Detailed Vulnerability Findings", self.title_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Group findings by severity
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for finding in results['findings']:
            by_severity[finding['severity']].append(finding)
        
        # Display findings by severity level
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if by_severity[severity]:
                elements.append(Paragraph(f"{severity} Severity Findings", self.heading1_style))
                
                for i, finding in enumerate(by_severity[severity], 1):
                    # Vulnerability card
                    vuln_text = f"""
                    <b>{i}. {finding['title']}</b><br/>
                    <b>OWASP Reference:</b> {finding['owasp_ref']}<br/>
                    <b>Description:</b> {finding['description']}
                    """
                    
                    style = getattr(self, f'{severity.lower()}_style')
                    vuln_para = Paragraph(vuln_text, style)
                    elements.append(vuln_para)
                    elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _create_remediation_guide(self, results):
        elements = []
        
        elements.append(Paragraph("Remediation Guidance", self.title_style))
        elements.append(Spacer(1, 0.2*inch))
        
        remediation_advice = [
            ["1. Critical & High Severity Issues", "Address within 24-48 hours"],
            ["2. Medium Severity Issues", "Address within 1-2 weeks"],
            ["3. Low Severity Issues", "Address in next development cycle"],
            ["4. Security Headers", "Implement missing security headers immediately"],
            ["5. SSL/TLS Configuration", "Ensure proper encryption configuration"],
            ["6. Input Validation", "Implement comprehensive input sanitization"]
        ]
        
        remediation_table = Table(remediation_advice, colWidths=[3.5*inch, 2.5*inch])
        remediation_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#ea580c')),
            ('TEXTCOLOR', (0, 1), (-1, 1), colors.white),
            ('BACKGROUND', (0, 2), (-1, 3), colors.HexColor('#f8fafc')),
            ('TEXTCOLOR', (0, 2), (-1, -1), colors.HexColor('#374151')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
        ]))
        elements.append(remediation_table)
        
        return elements
    
    def _count_severities(self, findings):
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            counts[finding['severity']] += 1
        return counts
