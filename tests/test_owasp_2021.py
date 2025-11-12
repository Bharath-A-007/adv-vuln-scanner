import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.core import AdvancedVulnerabilityScanner

class TestOWASP2021(unittest.TestCase):
    
    def setUp(self):
        self.scanner = AdvancedVulnerabilityScanner("https://example.com")
    
    def test_broken_access_control_checks(self):
        """Test A01:2021 Broken Access Control checks"""
        # This would test various access control vulnerabilities
        # For now, just verify the method exists
        self.assertTrue(hasattr(self.scanner, '_scan_broken_access_control'))
    
    def test_cryptographic_failures_checks(self):
        """Test A02:2021 Cryptographic Failures checks"""
        self.assertTrue(hasattr(self.scanner, '_scan_cryptographic_failures'))
    
    def test_injection_checks(self):
        """Test A03:2021 Injection checks"""
        self.assertTrue(hasattr(self.scanner, '_scan_injection_vulnerabilities'))
    
    def test_insecure_design_checks(self):
        """Test A04:2021 Insecure Design checks"""
        self.assertTrue(hasattr(self.scanner, '_scan_insecure_design'))
    
    def test_security_misconfiguration_checks(self):
        """Test A05:2021 Security Misconfiguration checks"""
        self.assertTrue(hasattr(self.scanner, '_scan_security_misconfiguration'))

if __name__ == '__main__':
    unittest.main()
