import unittest
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.core import AdvancedVulnerabilityScanner

class TestVulnerabilityScanner(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = AdvancedVulnerabilityScanner("https://example.com")
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.target_url, "https://example.com")
        self.assertEqual(len(self.scanner.findings), 0)
    
    def test_add_finding(self):
        """Test adding vulnerability findings"""
        initial_count = len(self.scanner.findings)
        
        self.scanner._add_finding(
            "HIGH", 
            "A03:2021", 
            "Test Vulnerability", 
            "This is a test vulnerability"
        )
        
        self.assertEqual(len(self.scanner.findings), initial_count + 1)
        
        finding = self.scanner.findings[-1]
        self.assertEqual(finding['severity'], "HIGH")
        self.assertEqual(finding['category'], "A03:2021")
        self.assertEqual(finding['title'], "Test Vulnerability")
    
    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        # Add test findings
        self.scanner._add_finding("CRITICAL", "A01:2021", "Test1", "Desc1")
        self.scanner._add_finding("HIGH", "A02:2021", "Test2", "Desc2")
        self.scanner._add_finding("MEDIUM", "A03:2021", "Test3", "Desc3")
        
        results = self.scanner._compile_results()
        
        # Risk score should be between 0 and 100
        self.assertGreaterEqual(results['risk_score'], 0)
        self.assertLessEqual(results['risk_score'], 100)
        
        # With 3 findings, score should be > 0
        self.assertGreater(results['risk_score'], 0)
    
    def test_severity_counting(self):
        """Test severity level counting"""
        self.scanner._add_finding("CRITICAL", "A01:2021", "Test1", "Desc1")
        self.scanner._add_finding("CRITICAL", "A01:2021", "Test2", "Desc2")
        self.scanner._add_finding("HIGH", "A02:2021", "Test3", "Desc3")
        self.scanner._add_finding("MEDIUM", "A03:2021", "Test4", "Desc4")
        self.scanner._add_finding("LOW", "A04:2021", "Test5", "Desc5")
        
        results = self.scanner._compile_results()
        summary = results['summary']
        
        self.assertEqual(summary['critical'], 2)
        self.assertEqual(summary['high'], 1)
        self.assertEqual(summary['medium'], 1)
        self.assertEqual(summary['low'], 1)
        self.assertEqual(summary['total'], 5)
    
    def test_risk_level_classification(self):
        """Test risk level classification"""
        # Test critical risk
        self.scanner._add_finding("CRITICAL", "A01:2021", "Test", "Desc")
        self.scanner._add_finding("CRITICAL", "A01:2021", "Test", "Desc")
        results = self.scanner._compile_results()
        self.assertEqual(results['risk_level'], 'HIGH')
        
        # Reset and test low risk
        self.scanner.findings = []
        self.scanner._add_finding("LOW", "A01:2021", "Test", "Desc")
        results = self.scanner._compile_results()
        self.assertEqual(results['risk_level'], 'LOW')

if __name__ == '__main__':
    unittest.main()
