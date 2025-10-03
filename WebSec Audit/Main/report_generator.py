import json
import os
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import asdict
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from tabulate import tabulate
import logging

from vulnerability_scanner import Vulnerability, VulnerabilityType, Severity

class ReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Report styles
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkred
        )

    def generate_executive_summary(self, vulnerabilities: List[Vulnerability], 
                                 scan_info: Dict) -> Dict:
        """Generate executive summary of the security audit"""
        total_vulns = len(vulnerabilities)
        
        # Count by severity
        severity_counts = {}
        for severity in Severity:
            count = sum(1 for v in vulnerabilities if v.severity == severity)
            severity_counts[severity.value] = count
        
        # Count by type
        type_counts = {}
        for vuln_type in VulnerabilityType:
            count = sum(1 for v in vulnerabilities if v.type == vuln_type)
            if count > 0:
                type_counts[vuln_type.value] = count
        
        # Calculate risk score (weighted by severity)
        risk_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
        
        risk_score = sum(risk_weights.get(v.severity, 0) for v in vulnerabilities)
        max_possible_score = len(vulnerabilities) * 10 if vulnerabilities else 1
        risk_percentage = (risk_score / max_possible_score) * 100
        
        # Determine overall security posture
        if risk_percentage >= 70:
            security_posture = "Poor"
        elif risk_percentage >= 40:
            security_posture = "Fair"
        elif risk_percentage >= 20:
            security_posture = "Good"
        else:
            security_posture = "Excellent"
        
        return {
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts,
            'vulnerability_types': type_counts,
            'risk_score': risk_score,
            'risk_percentage': risk_percentage,
            'security_posture': security_posture,
            'scan_info': scan_info
        }

    def create_vulnerability_chart(self, vulnerabilities: List[Vulnerability], 
                                 filename: str) -> str:
        """Create vulnerability distribution chart"""
        severity_counts = {}
        for severity in Severity:
            count = sum(1 for v in vulnerabilities if v.severity == severity)
            if count > 0:
                severity_counts[severity.value] = count
        
        if not severity_counts:
            return None
        
        # Create pie chart
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Severity distribution pie chart
        colors_map = {
            'Critical': '#d32f2f',
            'High': '#f57c00',
            'Medium': '#fbc02d',
            'Low': '#388e3c',
            'Informational': '#1976d2'
        }
        
        labels = list(severity_counts.keys())
        sizes = list(severity_counts.values())
        colors_list = [colors_map.get(label, '#gray') for label in labels]
        
        ax1.pie(sizes, labels=labels, colors=colors_list, autopct='%1.1f%%', startangle=90)
        ax1.set_title('Vulnerabilities by Severity', fontsize=14, fontweight='bold')
        
        # Vulnerability types bar chart
        type_counts = {}
        for vuln_type in VulnerabilityType:
            count = sum(1 for v in vulnerabilities if v.type == vuln_type)
            if count > 0:
                type_counts[vuln_type.value] = count
        
        if type_counts:
            types = list(type_counts.keys())
            counts = list(type_counts.values())
            
            # Truncate long type names for display
            display_types = [t[:20] + '...' if len(t) > 20 else t for t in types]
            
            bars = ax2.bar(range(len(types)), counts, color='#1976d2', alpha=0.7)
            ax2.set_xlabel('Vulnerability Types')
            ax2.set_ylabel('Count')
            ax2.set_title('Vulnerabilities by Type', fontsize=14, fontweight='bold')
            ax2.set_xticks(range(len(types)))
            ax2.set_xticklabels(display_types, rotation=45, ha='right')
            
            # Add value labels on bars
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                        str(count), ha='center', va='bottom')
        
        plt.tight_layout()
        chart_path = os.path.join(self.output_dir, filename)
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return chart_path

    def generate_html_report(self, vulnerabilities: List[Vulnerability], 
                           scan_info: Dict, filename: str = None) -> str:
        """Generate HTML report"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_audit_report_{timestamp}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Generate executive summary
        summary = self.generate_executive_summary(vulnerabilities, scan_info)
        
        # Create chart
        chart_filename = f"vulnerability_chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        chart_path = self.create_vulnerability_chart(vulnerabilities, chart_filename)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Application Security Audit Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #1976d2;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #1976d2;
            margin: 0;
            font-size: 2.5em;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 1.2em;
        }}
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
        }}
        .severity-critical {{ background: linear-gradient(135deg, #d32f2f, #f44336); }}
        .severity-high {{ background: linear-gradient(135deg, #f57c00, #ff9800); }}
        .severity-medium {{ background: linear-gradient(135deg, #fbc02d, #ffeb3b); color: #333; }}
        .severity-low {{ background: linear-gradient(135deg, #388e3c, #4caf50); }}
        .chart-container {{
            text-align: center;
            margin: 30px 0;
        }}
        .vulnerabilities-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .vulnerabilities-table th,
        .vulnerabilities-table td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        .vulnerabilities-table th {{
            background-color: #1976d2;
            color: white;
            font-weight: bold;
        }}
        .vulnerabilities-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .severity-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 0.8em;
        }}
        .badge-critical {{ background-color: #d32f2f; }}
        .badge-high {{ background-color: #f57c00; }}
        .badge-medium {{ background-color: #fbc02d; color: #333; }}
        .badge-low {{ background-color: #388e3c; }}
        .badge-info {{ background-color: #1976d2; }}
        .section {{
            margin: 30px 0;
        }}
        .section h2 {{
            color: #1976d2;
            border-bottom: 2px solid #1976d2;
            padding-bottom: 10px;
        }}
        .remediation {{
            background-color: #e8f5e8;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin: 10px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Web Application Security Audit Report</h1>
            <p>Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
            <p><strong>Target:</strong> {scan_info.get('target_url', 'N/A')}</p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p><strong>Security Posture:</strong> {summary['security_posture']}</p>
            <p><strong>Risk Score:</strong> {summary['risk_score']} ({summary['risk_percentage']:.1f}%)</p>
            
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Vulnerabilities</h3>
                    <div class="value">{summary['total_vulnerabilities']}</div>
                </div>
                <div class="summary-card severity-critical">
                    <h3>Critical</h3>
                    <div class="value">{summary['severity_breakdown'].get('Critical', 0)}</div>
                </div>
                <div class="summary-card severity-high">
                    <h3>High</h3>
                    <div class="value">{summary['severity_breakdown'].get('High', 0)}</div>
                </div>
                <div class="summary-card severity-medium">
                    <h3>Medium</h3>
                    <div class="value">{summary['severity_breakdown'].get('Medium', 0)}</div>
                </div>
                <div class="summary-card severity-low">
                    <h3>Low</h3>
                    <div class="value">{summary['severity_breakdown'].get('Low', 0)}</div>
                </div>
            </div>
        </div>
"""

        # Add chart if available
        if chart_path and os.path.exists(chart_path):
            html_content += f"""
        <div class="section">
            <h2>Vulnerability Distribution</h2>
            <div class="chart-container">
                <img src="{chart_filename}" alt="Vulnerability Distribution Chart" style="max-width: 100%; height: auto;">
            </div>
        </div>
"""

        # Add detailed vulnerabilities table
        if vulnerabilities:
            html_content += """
        <div class="section">
            <h2>Detailed Vulnerability Findings</h2>
            <table class="vulnerabilities-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>URL</th>
                        <th>Parameter</th>
                        <th>Evidence</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            for vuln in vulnerabilities:
                severity_class = f"badge-{vuln.severity.value.lower()}"
                html_content += f"""
                    <tr>
                        <td>{vuln.type.value}</td>
                        <td><span class="severity-badge {severity_class}">{vuln.severity.value}</span></td>
                        <td style="word-break: break-all;">{vuln.url}</td>
                        <td>{vuln.parameter}</td>
                        <td>{vuln.evidence}</td>
                        <td>
                            <div class="remediation">
                                {vuln.remediation}
                            </div>
                        </td>
                    </tr>
"""
            
            html_content += """
                </tbody>
            </table>
        </div>
"""

        # Add scan information
        html_content += f"""
        <div class="section">
            <h2>Scan Information</h2>
            <p><strong>Scan Duration:</strong> {scan_info.get('duration', 'N/A')}</p>
            <p><strong>Pages Scanned:</strong> {scan_info.get('pages_scanned', 'N/A')}</p>
            <p><strong>Forms Analyzed:</strong> {scan_info.get('forms_analyzed', 'N/A')}</p>
            <p><strong>Scan Type:</strong> {scan_info.get('scan_type', 'Standard')}</p>
        </div>

        <div class="footer">
            <p>Report generated by Web Application Security Audit Tool</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {filepath}")
        return filepath

    def generate_json_report(self, vulnerabilities: List[Vulnerability], 
                           scan_info: Dict, filename: str = None) -> str:
        """Generate JSON report for API integration"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_audit_report_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Convert vulnerabilities to dictionaries
        vulns_data = []
        for vuln in vulnerabilities:
            vuln_dict = asdict(vuln)
            # Convert enums to strings
            vuln_dict['type'] = vuln.type.value
            vuln_dict['severity'] = vuln.severity.value
            vulns_data.append(vuln_dict)
        
        # Generate summary
        summary = self.generate_executive_summary(vulnerabilities, scan_info)
        
        report_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool_version': '1.0',
                'report_format': 'json'
            },
            'scan_info': scan_info,
            'executive_summary': summary,
            'vulnerabilities': vulns_data
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"JSON report generated: {filepath}")
        return filepath

    def generate_console_report(self, vulnerabilities: List[Vulnerability], 
                              scan_info: Dict) -> str:
        """Generate console-friendly report"""
        summary = self.generate_executive_summary(vulnerabilities, scan_info)
        
        report = []
        report.append("=" * 80)
        report.append("WEB APPLICATION SECURITY AUDIT REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target: {scan_info.get('target_url', 'N/A')}")
        report.append("")
        
        # Executive Summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 40)
        report.append(f"Security Posture: {summary['security_posture']}")
        report.append(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        report.append(f"Risk Score: {summary['risk_score']} ({summary['risk_percentage']:.1f}%)")
        report.append("")
        
        # Severity Breakdown
        report.append("SEVERITY BREAKDOWN")
        report.append("-" * 40)
        for severity, count in summary['severity_breakdown'].items():
            if count > 0:
                report.append(f"{severity}: {count}")
        report.append("")
        
        # Detailed Findings
        if vulnerabilities:
            report.append("DETAILED FINDINGS")
            report.append("-" * 40)
            
            # Group by severity
            by_severity = {}
            for vuln in vulnerabilities:
                severity = vuln.severity.value
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(vuln)
            
            # Display in severity order
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
            for severity in severity_order:
                if severity in by_severity:
                    report.append(f"\n{severity.upper()} SEVERITY:")
                    for i, vuln in enumerate(by_severity[severity], 1):
                        report.append(f"  {i}. {vuln.type.value}")
                        report.append(f"     URL: {vuln.url}")
                        report.append(f"     Parameter: {vuln.parameter}")
                        report.append(f"     Evidence: {vuln.evidence}")
                        report.append(f"     Remediation: {vuln.remediation}")
                        if vuln.cwe_id:
                            report.append(f"     CWE ID: {vuln.cwe_id}")
                        report.append("")
        
        report.append("=" * 80)
        
        return "\n".join(report)

if __name__ == "__main__":
    # Example usage
    from vulnerability_scanner import Vulnerability, VulnerabilityType, Severity
    
    # Create sample vulnerabilities for testing
    sample_vulns = [
        Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.HIGH,
            url="http://example.com/search",
            parameter="q",
            payload="' OR 1=1--",
            evidence="SQL error detected",
            description="SQL injection vulnerability",
            remediation="Use parameterized queries"
        )
    ]
    
    sample_scan_info = {
        'target_url': 'http://example.com',
        'duration': '5 minutes',
        'pages_scanned': 25,
        'forms_analyzed': 3
    }
    
    generator = ReportGenerator()
    html_report = generator.generate_html_report(sample_vulns, sample_scan_info)
    print(f"Sample report generated: {html_report}")
