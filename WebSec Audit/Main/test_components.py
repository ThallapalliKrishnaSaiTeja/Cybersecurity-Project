def test_imports():
    """Test if all modules can be imported successfully"""
    print("Testing component imports...")
    
    try:
        from web_crawler import WebCrawler
        print("✓ Web Crawler module imported successfully")
    except ImportError as e:
        print(f"✗ Web Crawler import failed: {e}")
        return False
    
    try:
        from vulnerability_scanner import VulnerabilityScanner, Vulnerability, VulnerabilityType, Severity
        print("✓ Vulnerability Scanner module imported successfully")
    except ImportError as e:
        print(f"✗ Vulnerability Scanner import failed: {e}")
        return False
    
    try:
        from auth_manager import AuthenticationManager
        print("✓ Authentication Manager module imported successfully")
    except ImportError as e:
        print(f"✗ Authentication Manager import failed: {e}")
        return False
    
    try:
        from report_generator import ReportGenerator
        print("✓ Report Generator module imported successfully")
    except ImportError as e:
        print(f"✗ Report Generator import failed: {e}")
        return False
    
    return True

def test_basic_functionality():
    """Test basic functionality of components"""
    print("\nTesting basic functionality...")
    
    try:
        # Test WebCrawler initialization
        from web_crawler import WebCrawler
        crawler = WebCrawler("http://example.com", max_depth=1)
        print("✓ Web Crawler initialization successful")
        
        # Test VulnerabilityScanner initialization
        from vulnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner()
        print("✓ Vulnerability Scanner initialization successful")
        
        # Test AuthenticationManager initialization
        from auth_manager import AuthenticationManager
        auth_manager = AuthenticationManager()
        print("✓ Authentication Manager initialization successful")
        
        # Test ReportGenerator initialization
        from report_generator import ReportGenerator
        report_gen = ReportGenerator()
        print("✓ Report Generator initialization successful")
        
        return True
        
    except Exception as e:
        print(f"✗ Component initialization failed: {e}")
        return False

def test_vulnerability_creation():
    """Test vulnerability object creation"""
    print("\nTesting vulnerability object creation...")
    
    try:
        from vulnerability_scanner import Vulnerability, VulnerabilityType, Severity
        
        # Create a test vulnerability
        test_vuln = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.HIGH,
            url="http://example.com/test",
            parameter="id",
            payload="' OR 1=1--",
            evidence="SQL error detected",
            description="Test SQL injection vulnerability",
            remediation="Use parameterized queries"
        )
        
        print("✓ Vulnerability object created successfully")
        print(f"  Type: {test_vuln.type.value}")
        print(f"  Severity: {test_vuln.severity.value}")
        print(f"  URL: {test_vuln.url}")
        
        return True
        
    except Exception as e:
        print(f"✗ Vulnerability creation failed: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("Web Application Security Audit Tool - Component Tests")
    print("=" * 60)
    
    all_passed = True
    
    # Test imports
    if not test_imports():
        all_passed = False
    
    # Test basic functionality
    if not test_basic_functionality():
        all_passed = False
    
    # Test vulnerability creation
    if not test_vulnerability_creation():
        all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All tests passed! The security audit tool is ready to use.")
    else:
        print("✗ Some tests failed. Please check the error messages above.")
    print("=" * 60)

if __name__ == "__main__":
    main()
