import argparse
import sys
import time
import os
from datetime import datetime
from typing import List, Dict, Optional
import logging
from colorama import init, Fore, Back, Style
import json

# Import our modules
from web_crawler import WebCrawler
from vulnerability_scanner import VulnerabilityScanner, Vulnerability
from auth_manager import AuthenticationManager
from report_generator import ReportGenerator

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class WebSecurityAuditTool:
    def __init__(self):
        self.crawler = None
        self.scanner = None
        self.auth_manager = None
        self.report_generator = None
        self.vulnerabilities: List[Vulnerability] = []
        self.scan_start_time = None
        self.scan_info = {}
        
        # Setup logging
        self.setup_logging()
        self.logger = logging.getLogger(__name__)

    def setup_logging(self, log_level: str = "INFO"):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format=log_format,
            handlers=[
                logging.FileHandler('audit_tool.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                    Web Application Security Audit Tool                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Features: Web Crawling | OWASP Top 10 Scanning | Authentication Support    ║
║           Comprehensive Reporting | DevSecOps Integration                    ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def print_status(self, message: str, status_type: str = "info"):
        """Print colored status messages"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if status_type == "success":
            print(f"{Fore.GREEN}[{timestamp}] ✓ {message}{Style.RESET_ALL}")
        elif status_type == "error":
            print(f"{Fore.RED}[{timestamp}] ✗ {message}{Style.RESET_ALL}")
        elif status_type == "warning":
            print(f"{Fore.YELLOW}[{timestamp}] ⚠ {message}{Style.RESET_ALL}")
        elif status_type == "info":
            print(f"{Fore.BLUE}[{timestamp}] ℹ {message}{Style.RESET_ALL}")
        else:
            print(f"[{timestamp}] {message}")

    def initialize_components(self, target_url: str, config: Dict):
        """Initialize all components"""
        self.print_status("Initializing security audit components...")
        
        # Initialize crawler
        self.crawler = WebCrawler(
            base_url=target_url,
            max_depth=config.get('max_depth', 3),
            delay=config.get('crawl_delay', 1.0)
        )
        
        # Initialize scanner
        self.scanner = VulnerabilityScanner()
        
        # Initialize authentication manager
        self.auth_manager = AuthenticationManager(self.scanner.session)
        
        # Initialize report generator
        self.report_generator = ReportGenerator(config.get('output_dir', 'reports'))
        
        self.print_status("Components initialized successfully", "success")

    def perform_authentication(self, auth_config: Dict) -> bool:
        """Handle authentication if configured"""
        if not auth_config:
            return False
        
        self.print_status("Attempting authentication...")
        
        auth_type = auth_config.get('type', '').lower()
        
        if auth_type == 'form':
            # Find login forms
            login_forms = self.auth_manager.find_login_forms(self.crawler.base_url)
            
            if not login_forms:
                self.print_status("No login forms found", "warning")
                return False
            
            # Use the first login form found
            success = self.auth_manager.authenticate_form_based(
                login_forms[0],
                auth_config.get('username', ''),
                auth_config.get('password', '')
            )
            
            if success:
                self.print_status("Form-based authentication successful", "success")
                return True
            else:
                self.print_status("Form-based authentication failed", "error")
                return False
        
        elif auth_type == 'basic':
            success = self.auth_manager.authenticate_basic_auth(
                self.crawler.base_url,
                auth_config.get('username', ''),
                auth_config.get('password', '')
            )
            
            if success:
                self.print_status("Basic authentication successful", "success")
                return True
            else:
                self.print_status("Basic authentication failed", "error")
                return False
        
        elif auth_type == 'bearer':
            success = self.auth_manager.authenticate_bearer_token(
                auth_config.get('token', '')
            )
            
            if success:
                self.print_status("Bearer token authentication set", "success")
                return True
            else:
                self.print_status("Bearer token authentication failed", "error")
                return False
        
        return False

    def crawl_target(self, authenticated: bool = False) -> Dict:
        """Perform web crawling"""
        self.print_status("Starting web crawling phase...")
        
        auth_cookies = self.auth_manager.auth_cookies if authenticated else None
        
        crawl_results = self.crawler.crawl(
            authenticated=authenticated,
            auth_cookies=auth_cookies
        )
        
        self.print_status(f"Crawling completed. Found {len(crawl_results['endpoints'])} endpoints", "success")
        self.print_status(f"Discovered {len(crawl_results['forms'])} forms")
        
        return crawl_results

    def scan_vulnerabilities(self, crawl_results: Dict, scan_config: Dict):
        """Perform vulnerability scanning"""
        self.print_status("Starting vulnerability scanning phase...")
        
        total_endpoints = len(crawl_results['endpoints'])
        total_forms = len(crawl_results['forms'])
        
        # Scan endpoints
        for i, endpoint in enumerate(crawl_results['endpoints'], 1):
            self.print_status(f"Scanning endpoint {i}/{total_endpoints}: {endpoint}")
            
            # Get parameters for this endpoint
            params = crawl_results['parameters'].get(endpoint, {})
            if params:
                params_dict = {param: 'test_value' for param in params}
                endpoint_vulns = self.scanner.scan_endpoint(endpoint, params_dict)
                self.vulnerabilities.extend(endpoint_vulns)
        
        # Scan forms
        if crawl_results['forms']:
            self.print_status(f"Scanning {total_forms} forms...")
            form_vulns = self.scanner.scan_forms(crawl_results['forms'])
            self.vulnerabilities.extend(form_vulns)
        
        # Update scanner's vulnerability list
        self.scanner.vulnerabilities = self.vulnerabilities
        
        self.print_status(f"Vulnerability scanning completed. Found {len(self.vulnerabilities)} vulnerabilities", "success")

    def generate_reports(self, output_formats: List[str]):
        """Generate security reports"""
        self.print_status("Generating security reports...")
        
        scan_duration = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        self.scan_info.update({
            'duration': f"{scan_duration:.1f} seconds",
            'vulnerabilities_found': len(self.vulnerabilities)
        })
        
        generated_reports = []
        
        if 'html' in output_formats:
            html_report = self.report_generator.generate_html_report(
                self.vulnerabilities, self.scan_info
            )
            generated_reports.append(html_report)
            self.print_status(f"HTML report generated: {html_report}", "success")
        
        if 'json' in output_formats:
            json_report = self.report_generator.generate_json_report(
                self.vulnerabilities, self.scan_info
            )
            generated_reports.append(json_report)
            self.print_status(f"JSON report generated: {json_report}", "success")
        
        if 'console' in output_formats:
            console_report = self.report_generator.generate_console_report(
                self.vulnerabilities, self.scan_info
            )
            print("\n" + "="*80)
            print(console_report)
            print("="*80 + "\n")
        
        return generated_reports

    def print_vulnerability_summary(self):
        """Print a summary of found vulnerabilities"""
        if not self.vulnerabilities:
            self.print_status("No vulnerabilities found", "success")
            return
        
        summary = self.scanner.get_vulnerability_summary()
        
        print(f"\n{Fore.YELLOW}VULNERABILITY SUMMARY{Style.RESET_ALL}")
        print("-" * 40)
        print(f"Total Vulnerabilities: {summary['total']}")
        
        print("\nBy Severity:")
        severity_colors = {
            'Critical': Fore.RED,
            'High': Fore.MAGENTA,
            'Medium': Fore.YELLOW,
            'Low': Fore.GREEN,
            'Informational': Fore.CYAN
        }
        
        for severity, count in summary['by_severity'].items():
            color = severity_colors.get(severity, Fore.WHITE)
            print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
        
        print("\nBy Type:")
        for vuln_type, count in summary['by_type'].items():
            print(f"  {vuln_type}: {count}")

    def run_scan(self, args):
        """Main scan execution function"""
        self.scan_start_time = time.time()
        
        # Print banner
        self.print_banner()
        
        # Prepare scan configuration
        config = {
            'max_depth': args.max_depth,
            'crawl_delay': args.delay,
            'output_dir': args.output_dir
        }
        
        # Initialize components
        self.initialize_components(args.target, config)
        
        # Store scan information
        self.scan_info = {
            'target_url': args.target,
            'scan_type': 'Authenticated' if args.auth_config else 'Unauthenticated',
            'timestamp': datetime.now().isoformat(),
            'max_depth': args.max_depth
        }
        
        # Handle authentication
        authenticated = False
        if args.auth_config:
            try:
                with open(args.auth_config, 'r') as f:
                    auth_config = json.load(f)
                authenticated = self.perform_authentication(auth_config)
            except Exception as e:
                self.print_status(f"Error loading authentication config: {e}", "error")
        
        # Perform crawling
        crawl_results = self.crawl_target(authenticated)
        
        # Update scan info with crawl results
        self.scan_info.update({
            'pages_scanned': crawl_results['total_pages'],
            'forms_analyzed': len(crawl_results['forms']),
            'endpoints_discovered': len(crawl_results['endpoints'])
        })
        
        # Perform vulnerability scanning
        scan_config = {
            'include_low_severity': not args.exclude_low,
            'fast_scan': args.fast_scan
        }
        
        self.scan_vulnerabilities(crawl_results, scan_config)
        
        # Print summary
        self.print_vulnerability_summary()
        
        # Generate reports
        output_formats = args.output_format
        if 'all' in output_formats:
            output_formats = ['html', 'json', 'console']
        
        generated_reports = self.generate_reports(output_formats)
        
        # Print completion message
        scan_duration = time.time() - self.scan_start_time
        self.print_status(f"Security audit completed in {scan_duration:.1f} seconds", "success")
        
        if generated_reports:
            self.print_status("Reports generated:")
            for report in generated_reports:
                print(f"  • {report}")

def create_sample_auth_config():
    """Create a sample authentication configuration file"""
    sample_config = {
        "type": "form",
        "username": "your_username",
        "password": "your_password",
        "comment": "Supported types: form, basic, bearer"
    }
    
    with open("auth_config_sample.json", "w") as f:
        json.dump(sample_config, f, indent=2)
    
    print("Sample authentication config created: auth_config_sample.json")

def main():
    parser = argparse.ArgumentParser(
        description="Web Application Security Audit Tool - EDP Batch 6 Project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py http://example.com
  python main.py http://example.com --max-depth 2 --output-format html json
  python main.py http://example.com --auth-config auth.json --authenticated
  python main.py --create-auth-sample

Team: Ishan Ali Mohammed, Thallapalli Krishna Sai Teja, Gadiraju Krishnahaitanya Varma
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('--max-depth', type=int, default=3, 
                       help='Maximum crawling depth (default: 3)')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--output-format', nargs='+', 
                       choices=['html', 'json', 'console', 'all'],
                       default=['html', 'console'],
                       help='Output format(s) for reports (default: html console)')
    parser.add_argument('--output-dir', default='reports',
                       help='Output directory for reports (default: reports)')
    parser.add_argument('--auth-config', 
                       help='JSON file containing authentication configuration')
    parser.add_argument('--exclude-low', action='store_true',
                       help='Exclude low severity vulnerabilities from reports')
    parser.add_argument('--fast-scan', action='store_true',
                       help='Perform faster scan with reduced payload sets')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Set logging level (default: INFO)')
    parser.add_argument('--create-auth-sample', action='store_true',
                       help='Create a sample authentication configuration file')
    
    args = parser.parse_args()
    
    # Handle special commands
    if args.create_auth_sample:
        create_sample_auth_config()
        return
    
    # Validate required arguments
    if not args.target:
        parser.error("Target URL is required unless using --create-auth-sample")
    
    # Validate URL format
    if not args.target.startswith(('http://', 'https://')):
        print(f"{Fore.RED}Error: Target URL must start with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)
    
    # Create and run the audit tool
    try:
        audit_tool = WebSecurityAuditTool()
        audit_tool.setup_logging(args.log_level)
        audit_tool.run_scan(args)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
