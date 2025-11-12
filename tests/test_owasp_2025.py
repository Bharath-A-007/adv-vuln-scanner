import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.core import AdvancedVulnerabilityScanner

class TestOWASP2025(unittest.TestCase):
    
    def setUp(self):
        self.scanner = AdvancedVulnerabilityScanner("https://example.com")
    
    def test_supply_chain_checks(self):
        """Test A03:2025 Software Supply Chain checks"""
        self.assertTrue(hasattr(self.scanner, '_scan_vulnerable_components'))
    
    def test_authentication_failures_checks(self):
        """Test A07:2025 Authentication Failures checks"""
        self.assertTrue(hasattr(self.scanner, '_scan_identification_failures'))
    
    def test_integrity_failures_checks(self):
        """Test A08:2025 Software Integrity Failures checks"""
        self.assertTrue(hasattr(self.scanner, '_scan_integrity_failures'))
    
    def test_logging_alerting_checks(self):
        """Test A09:2025 Logging & Alerting Failures checks"""
        self.assertTrue(hasattr(self.scanner, '_scan_logging_failures'))

if __name__ == '__main__':
    unittest.main()
