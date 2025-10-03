import os
import json
from datetime import datetime

def create_demo_auth_config():
    """Create demonstration authentication configurations"""
    
    # Form-based authentication example
    form_auth = {
        "type": "form",
        "username": "demo_user",
        "password": "demo_password",
        "comment": "Example form-based authentication for login forms"
    }
    
    # Basic authentication example
    basic_auth = {
        "type": "basic",
        "username": "admin",
        "password": "admin123",
        "comment": "Example HTTP Basic authentication"
    }
    
    # Bearer token authentication example
    bearer_auth = {
        "type": "bearer",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "comment": "Example Bearer token authentication for APIs"
    }
    
    # Save configuration files
    with open("demo_form_auth.json", "w") as f:
        json.dump(form_auth, f, indent=2)
    
    with open("demo_basic_auth.json", "w") as f:
        json.dump(basic_auth, f, indent=2)
    
    with open("demo_bearer_auth.json", "w") as f:
        json.dump(bearer_auth, f, indent=2)
    
    print("✓ Demo authentication configurations created:")
    print("  • demo_form_auth.json")
    print("  • demo_basic_auth.json")
    print("  • demo_bearer_auth.json")

def show_usage_examples():
    """Display comprehensive usage examples"""
    
    print("\n" + "="*80)
    print("WEB APPLICATION SECURITY AUDIT TOOL - USAGE EXAMPLES")
    print("="*80)
    
    print("\n1. BASIC SCAN")
    print("-" * 40)
    print("python main.py http://example.com")
    print("• Performs standard security scan")
    print("• Crawls up to 3 levels deep")
    print("• Generates HTML and console reports")
    
    print("\n2. AUTHENTICATED SCAN")
    print("-" * 40)
    print("# First create auth config:")
    print("python main.py --create-auth-sample")
    print("# Edit auth_config_sample.json, then:")
    print("python main.py http://example.com --auth-config auth_config_sample.json")
    print("• Performs authenticated security testing")
    print("• Access protected areas of the application")
    
    print("\n3. FAST CI/CD SCAN")
    print("-" * 40)
    print("python main.py http://example.com --fast-scan --output-format json --exclude-low")
    print("• Optimized for continuous integration")
    print("• Faster execution with essential checks")
    print("• JSON output for automated processing")
    
    print("\n4. COMPREHENSIVE DEEP SCAN")
    print("-" * 40)
    print("python main.py http://example.com --max-depth 5 --output-format all --log-level DEBUG")
    print("• Thorough security assessment")
    print("• Deep crawling and detailed logging")
    print("• All report formats generated")
    
    print("\n5. CUSTOM CONFIGURATION")
    print("-" * 40)
    print("python main.py http://example.com \\")
    print("  --max-depth 2 \\")
    print("  --delay 0.5 \\")
    print("  --output-dir custom_reports \\")
    print("  --auth-config my_auth.json")
    print("• Customized scan parameters")
    print("• Custom output directory")
    print("• Reduced delay for faster scanning")

def show_command_options():
    """Display all command line options"""
    
    print("\n" + "="*80)
    print("COMMAND LINE OPTIONS REFERENCE")
    print("="*80)
    
    options = [
        ("target", "Target URL to scan (required)", "http://example.com"),
        ("--max-depth N", "Maximum crawling depth", "3"),
        ("--delay N", "Delay between requests (seconds)", "1.0"),
        ("--output-format", "Report formats: html, json, console, all", "html console"),
        ("--output-dir DIR", "Output directory for reports", "reports"),
        ("--auth-config FILE", "Authentication configuration file", "None"),
        ("--exclude-low", "Exclude low severity vulnerabilities", "False"),
        ("--fast-scan", "Faster scan with reduced payloads", "False"),
        ("--log-level LEVEL", "Logging level: DEBUG, INFO, WARNING, ERROR", "INFO"),
        ("--create-auth-sample", "Create sample auth configuration", "N/A")
    ]
    
    print(f"{'Option':<25} {'Description':<40} {'Default':<15}")
    print("-" * 80)
    for option, desc, default in options:
        print(f"{option:<25} {desc:<40} {default:<15}")

def show_vulnerability_types():
    """Display supported vulnerability types"""
    
    print("\n" + "="*80)
    print("SUPPORTED VULNERABILITY TYPES (OWASP TOP 10)")
    print("="*80)
    
    vulnerabilities = [
        ("SQL Injection", "Detects SQL injection vulnerabilities in parameters and forms"),
        ("Cross-Site Scripting (XSS)", "Identifies reflected and stored XSS vulnerabilities"),
        ("Cross-Site Request Forgery", "Checks for missing CSRF protection in forms"),
        ("Broken Authentication", "Analyzes authentication mechanisms and session management"),
        ("Sensitive Data Exposure", "Identifies potential data exposure issues"),
        ("Security Misconfiguration", "Checks for missing security headers and configurations"),
        ("Broken Access Control", "Tests for access control vulnerabilities"),
        ("XML External Entities", "Detects XXE vulnerabilities in XML processing"),
        ("Insecure Deserialization", "Identifies unsafe deserialization patterns"),
        ("Vulnerable Components", "Checks for known vulnerable components")
    ]
    
    for i, (vuln_type, description) in enumerate(vulnerabilities, 1):
        print(f"{i:2}. {vuln_type}")
        print(f"    {description}")

def show_report_formats():
    """Display available report formats"""
    
    print("\n" + "="*80)
    print("REPORT FORMATS")
    print("="*80)
    
    print("\n📄 HTML REPORT")
    print("• Interactive dashboard with charts and graphs")
    print("• Detailed vulnerability information with evidence")
    print("• Executive summary and risk assessment")
    print("• Remediation guidance for each finding")
    print("• Professional presentation for stakeholders")
    
    print("\n📊 JSON REPORT")
    print("• Machine-readable format for API integration")
    print("• Complete vulnerability data with metadata")
    print("• Easy integration with other security tools")
    print("• Suitable for automated processing and CI/CD")
    
    print("\n💻 CONSOLE REPORT")
    print("• Terminal-friendly output with color coding")
    print("• Quick overview of findings and statistics")
    print("• Ideal for command-line workflows")
    print("• CI/CD pipeline compatible")

def create_sample_scan_script():
    """Create a sample scanning script"""
    
    script_content = '''#!/usr/bin/env python3
"""
Sample automated security scan script
Demonstrates programmatic usage of the Web Application Security Audit Tool
"""

import sys
import os
from main import WebSecurityAuditTool

def run_automated_scan(target_url):
    """Run an automated security scan"""
    
    print(f"Starting automated security scan for: {target_url}")
    
    # Create mock command line arguments
    class Args:
        def __init__(self):
            self.target = target_url
            self.max_depth = 2
            self.delay = 1.0
            self.output_format = ['html', 'json']
            self.output_dir = 'automated_reports'
            self.auth_config = None
            self.exclude_low = True
            self.fast_scan = True
            self.log_level = 'INFO'
    
    try:
        # Initialize and run the audit tool
        audit_tool = WebSecurityAuditTool()
        audit_tool.setup_logging('INFO')
        
        args = Args()
        audit_tool.run_scan(args)
        
        print("✓ Automated scan completed successfully")
        return True
        
    except Exception as e:
        print(f"✗ Scan failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sample_scan.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    success = run_automated_scan(target)
    sys.exit(0 if success else 1)
'''
    
    with open("sample_scan.py", "w") as f:
        f.write(script_content)
    
    print("✓ Sample scanning script created: sample_scan.py")

def main():
    """Main demonstration function"""
    
    print("🔒 WEB APPLICATION SECURITY AUDIT TOOL")
    print("📅 Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    # Create demo files
    create_demo_auth_config()
    create_sample_scan_script()
    
    # Show usage information
    show_usage_examples()
    show_command_options()
    show_vulnerability_types()
    show_report_formats()
    
    print("\n" + "="*80)
    print("GETTING STARTED")
    print("="*80)
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Run basic scan: python main.py http://example.com")
    print("3. Check generated reports in the 'reports' directory")
    print("4. For authenticated scans, create auth config with --create-auth-sample")
    print("5. Customize scan parameters as needed for your use case")
    
    print("\n⚠️  IMPORTANT SECURITY NOTES:")
    print("• Only scan applications you own or have permission to test")
    print("• Follow responsible disclosure practices")
    print("• Verify findings manually before reporting")
    print("• Ensure compliance with local laws and regulations")
    
    print("\n✅ Demo setup completed! All files are ready for use.")

if __name__ == "__main__":
    main()