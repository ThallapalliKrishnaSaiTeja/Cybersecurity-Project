 Web Application Security Audit Tool

 Overview

A comprehensive web application security audit tool that implements automated vulnerability scanning based on OWASP Top 10 guidelines. The tool features modular architecture with web crawling, vulnerability detection, authentication support, and detailed reporting capabilities.
 Features

 🔍 Web Crawling & Discovery
- Intelligent web crawling with configurable depth
- Automatic endpoint and API discovery
- Form detection and analysis
- Parameter extraction from URLs and forms

 🛡️ Vulnerability Scanning
- OWASP Top 10 Coverage:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Broken Authentication
  - Sensitive Data Exposure
  - Security Misconfiguration
  - And more...

 🔐 Authentication Support
- Form-based authentication
- HTTP Basic Authentication
- Bearer token authentication
- Session management and persistence

 📊 Comprehensive Reporting
- HTML reports with visualizations
- JSON reports for API integration
- Console output for CI/CD pipelines
- Risk-based vulnerability prioritization
- Detailed remediation guidance

 ⚙️ DevSecOps Integration
- Command-line interface for automation
- Configurable scan policies
- Multiple output formats
- CI/CD pipeline compatibility

 Installation

1. Clone or download the project files

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Verify installation:
```bash
python main.py --help
```

 Quick Start

 Basic Scan
```bash
python main.py http://example.com
```

 Advanced Scan with Authentication
```bash
 Create authentication config
python main.py --create-auth-sample

 Edit auth_config_sample.json with your credentials
 Then run authenticated scan
python main.py http://example.com --auth-config auth_config_sample.json
```

 Customized Scan
```bash
python main.py http://example.com \
  --max-depth 2 \
  --output-format html json \
  --output-dir my_reports \
  --exclude-low
```

 Usage Examples

 1. Standard Security Audit
```bash
python main.py https://target-website.com
```
- Crawls the website up to 3 levels deep
- Scans for OWASP Top 10 vulnerabilities
- Generates HTML and console reports

 2. Authenticated Scan
```bash
 First, create authentication configuration
python main.py --create-auth-sample

 Edit the generated auth_config_sample.json:
{
  "type": "form",
  "username": "your_username",
  "password": "your_password"
}

 Run authenticated scan
python main.py https://target-website.com --auth-config auth_config_sample.json
```

 3. Fast Scan for CI/CD
```bash
python main.py https://target-website.com \
  --fast-scan \
  --output-format json \
  --exclude-low \
  --max-depth 1
```

 4. Comprehensive Deep Scan
```bash
python main.py https://target-website.com \
  --max-depth 5 \
  --delay 0.5 \
  --output-format all \
  --log-level DEBUG
```

 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target URL to scan | Required |
| `--max-depth` | Maximum crawling depth | 3 |
| `--delay` | Delay between requests (seconds) | 1.0 |
| `--output-format` | Report formats: html, json, console, all | html console |
| `--output-dir` | Output directory for reports | reports |
| `--auth-config` | JSON file with authentication config | None |
| `--exclude-low` | Exclude low severity vulnerabilities | False |
| `--fast-scan` | Faster scan with reduced payloads | False |
| `--log-level` | Logging level: DEBUG, INFO, WARNING, ERROR | INFO |

 Authentication Configuration

The tool supports multiple authentication methods:

 Form-Based Authentication
```json
{
  "type": "form",
  "username": "your_username",
  "password": "your_password"
}
```

 HTTP Basic Authentication
```json
{
  "type": "basic",
  "username": "your_username",
  "password": "your_password"
}
```

 Bearer Token Authentication
```json
{
  "type": "bearer",
  "token": "your_bearer_token"
}
```

 Report Formats

 HTML Report
- Interactive dashboard with charts
- Vulnerability details with evidence
- Risk-based prioritization
- Remediation guidance
- Executive summary

 JSON Report
- Machine-readable format
- API integration friendly
- Complete vulnerability data
- Scan metadata

 Console Report
- Terminal-friendly output
- CI/CD pipeline compatible
- Summary statistics
- Color-coded severity levels

 Architecture

The tool follows a modular architecture:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Crawler   │───▶│ Vulnerability    │───▶│ Report          │
│                 │    │ Scanner          │    │ Generator       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Authentication  │    │ OWASP Top 10     │    │ HTML/JSON/      │
│ Manager         │    │ Detection        │    │ Console Output  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

 Vulnerability Detection

 SQL Injection
- Error-based detection
- Time-based blind SQLi
- Union-based injection
- Boolean-based blind SQLi

 Cross-Site Scripting (XSS)
- Reflected XSS
- Stored XSS (basic detection)
- DOM-based XSS patterns

 Security Headers
- Missing security headers
- HSTS, CSP, X-Frame-Options
- Content type validation

 CSRF Protection
- Token validation
- SameSite cookie analysis
- Referer header checks

 Sample Output

```

[10:30:15] ℹ Initializing security audit components...
[10:30:16] ✓ Components initialized successfully
[10:30:16] ℹ Starting web crawling phase...
[10:30:25] ✓ Crawling completed. Found 15 endpoints
[10:30:25] ℹ Discovered 3 forms
[10:30:25] ℹ Starting vulnerability scanning phase...
[10:30:45] ✓ Vulnerability scanning completed. Found 5 vulnerabilities

VULNERABILITY SUMMARY
----------------------------------------
Total Vulnerabilities: 5

By Severity:
  High: 2
  Medium: 2
  Low: 1

By Type:
  SQL Injection: 1
  Cross-Site Scripting (XSS): 2
  Security Misconfiguration: 2
```

 File Structure

```
EDP Batch6/
├── main.py                  Main application entry point
├── web_crawler.py           Web crawling module
├── vulnerability_scanner.py  Vulnerability detection engine
├── auth_manager.py          Authentication handling
├── report_generator.py      Report generation
├── requirements.txt         Python dependencies
├── README.md               This file
└── reports/                Generated reports directory
```

 Dependencies

- requests: HTTP library for web requests
- beautifulsoup4: HTML parsing and analysis
- selenium: Browser automation (optional)
- flask: Web framework for dashboard
- matplotlib: Chart generation
- reportlab: PDF report generation
- colorama: Cross-platform colored terminal output

 Security Considerations

⚠️ Important Security Notes:

1. Authorized Testing Only: Only use this tool on applications you own or have explicit permission to test
2. Rate Limiting: The tool includes delays to avoid overwhelming target servers
3. Responsible Disclosure: Report found vulnerabilities responsibly to application owners
4. Legal Compliance: Ensure compliance with local laws and regulations

 Limitations

- JavaScript-Heavy Applications: Limited support for complex JavaScript applications
- Authentication Complexity: May not handle complex multi-step authentication flows
- False Positives: Manual verification of findings is recommended
- Coverage: Not all vulnerability types are covered (focus on OWASP Top 10)

 Contributing

This is an academic project for EDP Batch 6. For improvements or bug reports:

1. Document the issue clearly
2. Provide reproduction steps
3. Include relevant logs and outputs
4. Suggest potential solutions

 License

This project is developed for educational purposes as part of the Engineering Design Project (EDP) curriculum.

 Acknowledgments

- OWASP Foundation for security guidelines and vulnerability classifications
- Python Security Community for tools and libraries
- Academic Supervisors for guidance and support

---

Developed by EDP Batch 6 Team  
Engineering Design Project - Web Application Security
