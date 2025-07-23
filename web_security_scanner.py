#!/usr/bin/env python3
"""
Web Application Security Scanner - Advanced Web Vulnerability Assessment Tool
Features: SQL Injection, XSS, Directory Traversal, Security Headers Analysis
Author: Cybersecurity Student Tool Enhancement
"""

import requests
import urllib.parse
import argparse
import time
import random
import json
import threading
from datetime import datetime
import re
import sys
from bs4 import BeautifulSoup

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class WebSecurityScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.scan_start_time = None
        self.session = requests.Session()
        
        # SQL Injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND 1=1",
            "' AND 1=2",
            "admin'--",
            "admin' #",
            "' OR 'a'='a",
            "' OR 'x'='x",
            "') OR ('1'='1",
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<script>document.write('XSS')</script>",
            "<div onclick=alert('XSS')>Click me</div>",
            "<input onfocus=alert('XSS') autofocus>",
        ]
        
        # Directory traversal payloads
        self.dir_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "../../../../boot.ini",
            "..\\..\\..\\..\\boot.ini",
        ]
        
        # Security headers to check
        self.security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-XSS-Protection': 'XSS filtering',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content injection protection',
            'X-Permitted-Cross-Domain-Policies': 'Cross-domain policy',
            'Referrer-Policy': 'Referrer information control',
            'Feature-Policy': 'Feature restrictions',
            'X-Powered-By': 'Server information disclosure (should not be present)',
            'Server': 'Server information disclosure'
        }

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════╗
║    Web Application Security Scanner       ║
║       Advanced Vulnerability Tool        ║
╚═══════════════════════════════════════════╝
{Colors.ENDC}
        """
        print(banner)

    def get_arguments(self):
        parser = argparse.ArgumentParser(
            description="Web Application Security Scanner",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Vulnerability Types:
  sql    : SQL Injection testing
  xss    : Cross-Site Scripting testing
  dir    : Directory traversal testing
  headers: Security headers analysis
  all    : All vulnerability types

Examples:
  python3 web_security_scanner.py -u http://example.com --vuln-types sql,xss
  python3 web_security_scanner.py -u http://example.com --vuln-types all
  python3 web_security_scanner.py -u http://example.com --crawl --depth 2
  python3 web_security_scanner.py -u http://example.com --custom-headers "Authorization: Bearer token"
            """)
        
        parser.add_argument("-u", "--url", required=True,
                          help="Target URL to scan")
        parser.add_argument("--vuln-types", default="all",
                          help="Vulnerability types to test (sql,xss,dir,headers,all)")
        parser.add_argument("--crawl", action="store_true",
                          help="Crawl website for additional URLs")
        parser.add_argument("--depth", type=int, default=1,
                          help="Crawling depth (default: 1)")
        parser.add_argument("--threads", type=int, default=10,
                          help="Number of threads (default: 10)")
        parser.add_argument("--delay", type=float, default=0.5,
                          help="Delay between requests (default: 0.5)")
        parser.add_argument("--timeout", type=int, default=10,
                          help="Request timeout (default: 10)")
        parser.add_argument("--custom-headers", type=str,
                          help="Custom headers (format: 'Header1: Value1, Header2: Value2')")
        parser.add_argument("--user-agent", type=str,
                          default="WebSecScanner/1.0 (Security Testing)",
                          help="Custom User-Agent")
        parser.add_argument("--output", choices=['table', 'json', 'html'], default='table',
                          help="Output format")
        parser.add_argument("--save", type=str,
                          help="Save results to file")
        parser.add_argument("--verbose", "-v", action="store_true",
                          help="Verbose output")
        parser.add_argument("--silent", action="store_true",
                          help="Silent mode")
        
        return parser.parse_args()

    def setup_session(self, user_agent, custom_headers=None, timeout=10):
        """Setup HTTP session with custom settings"""
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        if custom_headers:
            for header in custom_headers.split(','):
                if ':' in header:
                    key, value = header.split(':', 1)
                    self.session.headers[key.strip()] = value.strip()
        
        self.session.timeout = timeout

    def crawl_website(self, base_url, depth=1, visited=None):
        """Crawl website to discover additional URLs"""
        if visited is None:
            visited = set()
        
        urls = set()
        urls.add(base_url)
        
        if depth <= 0:
            return urls
        
        try:
            response = self.session.get(base_url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urllib.parse.urljoin(base_url, href)
                
                # Only include URLs from the same domain
                if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(base_url).netloc:
                    if full_url not in visited:
                        visited.add(full_url)
                        urls.add(full_url)
                        
                        # Recursive crawling
                        if depth > 1:
                            sub_urls = self.crawl_website(full_url, depth-1, visited)
                            urls.update(sub_urls)
            
            # Find forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    form_url = urllib.parse.urljoin(base_url, action)
                    if urllib.parse.urlparse(form_url).netloc == urllib.parse.urlparse(base_url).netloc:
                        urls.add(form_url)
                        
        except Exception as e:
            if not self.silent:
                print(f"{Colors.YELLOW}[!] Error crawling {base_url}: {e}{Colors.ENDC}")
        
        return urls

    def test_sql_injection(self, url, verbose=False):
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Parse URL to get parameters
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            if not params:
                return vulnerabilities
            
            for param_name in params:
                for payload in self.sql_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    if verbose:
                        print(f"{Colors.BLUE}[*] Testing SQL injection: {param_name} = {payload[:20]}...{Colors.ENDC}")
                    
                    try:
                        response = self.session.get(test_url, params=test_params, timeout=10)
                        
                        # Check for SQL error indicators
                        sql_errors = [
                            'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB Provider',
                            'Unclosed quotation mark', 'SQLSTATE', 'PostgreSQL query failed',
                            'Warning: mysql_', 'MySQLSyntaxErrorException', 'valid MySQL result',
                            'Warning: pg_', 'valid PostgreSQL result', 'Npgsql.',
                            'Dynamic SQL Error', 'Warning: mssql_', 'Microsoft SQL Native Client',
                            'ORA-00933', 'ORA-00921', 'sqlite3.OperationalError'
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                vuln = {
                                    'type': 'SQL Injection',
                                    'severity': 'High',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': error,
                                    'timestamp': datetime.now().isoformat()
                                }
                                vulnerabilities.append(vuln)
                                
                                if not self.silent:
                                    print(f"{Colors.RED}[!] SQL Injection found: {param_name} - {error}{Colors.ENDC}")
                                break
                    
                    except Exception as e:
                        if verbose:
                            print(f"{Colors.YELLOW}[!] Error testing {param_name}: {e}{Colors.ENDC}")
                    
                    time.sleep(0.1)  # Small delay between requests
                    
        except Exception as e:
            if verbose:
                print(f"{Colors.RED}[!] Error in SQL injection test: {e}{Colors.ENDC}")
        
        return vulnerabilities

    def test_xss(self, url, verbose=False):
        """Test for Cross-Site Scripting vulnerabilities"""
        vulnerabilities = []
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            if not params:
                return vulnerabilities
            
            for param_name in params:
                for payload in self.xss_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    if verbose:
                        print(f"{Colors.BLUE}[*] Testing XSS: {param_name} = {payload[:20]}...{Colors.ENDC}")
                    
                    try:
                        response = self.session.get(test_url, params=test_params, timeout=10)
                        
                        # Check if payload is reflected in response
                        if payload in response.text:
                            vuln = {
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'Medium',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': 'Payload reflected in response',
                                'timestamp': datetime.now().isoformat()
                            }
                            vulnerabilities.append(vuln)
                            
                            if not self.silent:
                                print(f"{Colors.RED}[!] XSS found: {param_name} - Payload reflected{Colors.ENDC}")
                    
                    except Exception as e:
                        if verbose:
                            print(f"{Colors.YELLOW}[!] Error testing XSS {param_name}: {e}{Colors.ENDC}")
                    
                    time.sleep(0.1)
                    
        except Exception as e:
            if verbose:
                print(f"{Colors.RED}[!] Error in XSS test: {e}{Colors.ENDC}")
        
        return vulnerabilities

    def test_directory_traversal(self, url, verbose=False):
        """Test for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            if not params:
                return vulnerabilities
            
            for param_name in params:
                for payload in self.dir_traversal_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    if verbose:
                        print(f"{Colors.BLUE}[*] Testing Directory Traversal: {param_name} = {payload[:20]}...{Colors.ENDC}")
                    
                    try:
                        response = self.session.get(test_url, params=test_params, timeout=10)
                        
                        # Check for file content indicators
                        file_indicators = [
                            'root:x:', 'daemon:x:', 'bin:x:',  # /etc/passwd
                            '[boot loader]', '[operating systems]',  # boot.ini
                            '# Copyright', '127.0.0.1'  # hosts file
                        ]
                        
                        for indicator in file_indicators:
                            if indicator in response.text:
                                vuln = {
                                    'type': 'Directory Traversal',
                                    'severity': 'High',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': f'File content detected: {indicator}',
                                    'timestamp': datetime.now().isoformat()
                                }
                                vulnerabilities.append(vuln)
                                
                                if not self.silent:
                                    print(f"{Colors.RED}[!] Directory Traversal found: {param_name} - {indicator}{Colors.ENDC}")
                                break
                    
                    except Exception as e:
                        if verbose:
                            print(f"{Colors.YELLOW}[!] Error testing directory traversal {param_name}: {e}{Colors.ENDC}")
                    
                    time.sleep(0.1)
                    
        except Exception as e:
            if verbose:
                print(f"{Colors.RED}[!] Error in directory traversal test: {e}{Colors.ENDC}")
        
        return vulnerabilities

    def analyze_security_headers(self, url, verbose=False):
        """Analyze security headers"""
        vulnerabilities = []
        
        try:
            if verbose:
                print(f"{Colors.BLUE}[*] Analyzing security headers for {url}{Colors.ENDC}")
            
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            for header, description in self.security_headers.items():
                if header.lower() not in [h.lower() for h in headers]:
                    if header not in ['X-Powered-By', 'Server']:  # These should NOT be present
                        severity = 'Low' if header in ['X-Permitted-Cross-Domain-Policies', 'Feature-Policy'] else 'Medium'
                        vuln = {
                            'type': 'Missing Security Header',
                            'severity': severity,
                            'url': url,
                            'parameter': header,
                            'payload': 'N/A',
                            'evidence': f'Missing {header} header - {description}',
                            'timestamp': datetime.now().isoformat()
                        }
                        vulnerabilities.append(vuln)
                        
                        if not self.silent:
                            print(f"{Colors.YELLOW}[!] Missing header: {header} - {description}{Colors.ENDC}")
                else:
                    if header in ['X-Powered-By', 'Server']:  # Information disclosure
                        vuln = {
                            'type': 'Information Disclosure',
                            'severity': 'Low',
                            'url': url,
                            'parameter': header,
                            'payload': 'N/A',
                            'evidence': f'{header}: {headers.get(header, "")}',
                            'timestamp': datetime.now().isoformat()
                        }
                        vulnerabilities.append(vuln)
                        
                        if not self.silent:
                            print(f"{Colors.YELLOW}[!] Information disclosure: {header}: {headers.get(header, '')}{Colors.ENDC}")
                            
        except Exception as e:
            if verbose:
                print(f"{Colors.RED}[!] Error analyzing headers: {e}{Colors.ENDC}")
        
        return vulnerabilities

    def scan_url(self, url, vuln_types, verbose=False, delay=0.5):
        """Scan a single URL for vulnerabilities"""
        url_vulnerabilities = []
        
        if 'sql' in vuln_types or 'all' in vuln_types:
            sql_vulns = self.test_sql_injection(url, verbose)
            url_vulnerabilities.extend(sql_vulns)
        
        time.sleep(delay)
        
        if 'xss' in vuln_types or 'all' in vuln_types:
            xss_vulns = self.test_xss(url, verbose)
            url_vulnerabilities.extend(xss_vulns)
        
        time.sleep(delay)
        
        if 'dir' in vuln_types or 'all' in vuln_types:
            dir_vulns = self.test_directory_traversal(url, verbose)
            url_vulnerabilities.extend(dir_vulns)
        
        time.sleep(delay)
        
        if 'headers' in vuln_types or 'all' in vuln_types:
            header_vulns = self.analyze_security_headers(url, verbose)
            url_vulnerabilities.extend(header_vulns)
        
        return url_vulnerabilities

    def display_results(self, output_format='table', silent=False):
        """Display scan results"""
        if not self.vulnerabilities:
            if not silent:
                print(f"{Colors.GREEN}[✓] No vulnerabilities found{Colors.ENDC}")
            return
        
        scan_time = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        if output_format == 'table':
            if not silent:
                print(f"\n{Colors.RED}{'='*100}{Colors.ENDC}")
                print(f"{Colors.BOLD}Vulnerability Scan Results:{Colors.ENDC}")
                print(f"{Colors.RED}{'='*100}{Colors.ENDC}")
                
                # Group by severity
                high_vulns = [v for v in self.vulnerabilities if v['severity'] == 'High']
                medium_vulns = [v for v in self.vulnerabilities if v['severity'] == 'Medium']
                low_vulns = [v for v in self.vulnerabilities if v['severity'] == 'Low']
                
                for severity, vulns in [('High', high_vulns), ('Medium', medium_vulns), ('Low', low_vulns)]:
                    if vulns:
                        color = Colors.RED if severity == 'High' else Colors.YELLOW if severity == 'Medium' else Colors.BLUE
                        print(f"\n{color}{Colors.BOLD}{severity} Severity Vulnerabilities:{Colors.ENDC}")
                        print("-" * 80)
                        
                        for vuln in vulns:
                            print(f"{color}[!] {vuln['type']}{Colors.ENDC}")
                            print(f"    URL: {vuln['url']}")
                            if vuln['parameter'] != 'N/A':
                                print(f"    Parameter: {vuln['parameter']}")
                            if vuln['payload'] != 'N/A':
                                print(f"    Payload: {vuln['payload'][:50]}...")
                            print(f"    Evidence: {vuln['evidence']}")
                            print()
                
                print(f"{Colors.GREEN}[✓] Scan completed in {scan_time:.2f} seconds{Colors.ENDC}")
                print(f"{Colors.RED}[!] Found {len(self.vulnerabilities)} vulnerability(ies){Colors.ENDC}")
                
        elif output_format == 'json':
            scan_info = {
                "scan_time": scan_time,
                "vulnerabilities_count": len(self.vulnerabilities),
                "timestamp": datetime.now().isoformat(),
                "vulnerabilities": self.vulnerabilities
            }
            print(json.dumps(scan_info, indent=2))
            
        elif output_format == 'html':
            html_output = self.generate_html_report()
            print(html_output)

    def generate_html_report(self):
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Web Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f44336; color: white; padding: 20px; text-align: center; }}
        .summary {{ background: #f9f9f9; padding: 15px; margin: 20px 0; }}
        .vulnerability {{ border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; background: #ffeaea; }}
        .high {{ border-color: #f44336; }}
        .medium {{ border-color: #ff9800; background: #fff3e0; }}
        .low {{ border-color: #2196f3; background: #e3f2fd; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Web Security Scan Report</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> {len(self.vulnerabilities)}</p>
        <p><strong>High Severity:</strong> {len([v for v in self.vulnerabilities if v['severity'] == 'High'])}</p>
        <p><strong>Medium Severity:</strong> {len([v for v in self.vulnerabilities if v['severity'] == 'Medium'])}</p>
        <p><strong>Low Severity:</strong> {len([v for v in self.vulnerabilities if v['severity'] == 'Low'])}</p>
    </div>
    
    <h2>Vulnerabilities</h2>
"""
        
        for vuln in self.vulnerabilities:
            severity_class = vuln['severity'].lower()
            html += f"""
    <div class="vulnerability {severity_class}">
        <h3>{vuln['type']} - {vuln['severity']} Severity</h3>
        <p><strong>URL:</strong> {vuln['url']}</p>
        <p><strong>Parameter:</strong> {vuln['parameter']}</p>
        <p><strong>Evidence:</strong> {vuln['evidence']}</p>
        <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html

    def save_results(self, filename, output_format='json'):
        """Save results to file"""
        try:
            with open(filename, 'w') as f:
                if output_format == 'json':
                    scan_info = {
                        "scan_time": time.time() - self.scan_start_time if self.scan_start_time else 0,
                        "vulnerabilities_count": len(self.vulnerabilities),
                        "timestamp": datetime.now().isoformat(),
                        "vulnerabilities": self.vulnerabilities
                    }
                    json.dump(scan_info, f, indent=2)
                elif output_format == 'html':
                    f.write(self.generate_html_report())
            
            print(f"{Colors.GREEN}[✓] Results saved to {filename}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving results: {e}{Colors.ENDC}")

def main():
    scanner = WebSecurityScanner()
    
    try:
        args = scanner.get_arguments()
        scanner.silent = args.silent
        
        if not args.silent:
            scanner.print_banner()
        
        # Setup session
        scanner.setup_session(args.user_agent, args.custom_headers, args.timeout)
        
        # Parse vulnerability types
        vuln_types = [v.strip() for v in args.vuln_types.split(',')]
        
        # Get URLs to scan
        urls_to_scan = set()
        urls_to_scan.add(args.url)
        
        if args.crawl:
            if not args.silent:
                print(f"{Colors.CYAN}[*] Crawling website (depth: {args.depth})...{Colors.ENDC}")
            
            crawled_urls = scanner.crawl_website(args.url, args.depth)
            urls_to_scan.update(crawled_urls)
            
            if not args.silent:
                print(f"{Colors.GREEN}[✓] Found {len(urls_to_scan)} URLs to scan{Colors.ENDC}")
        
        if not args.silent:
            print(f"{Colors.CYAN}[*] Starting vulnerability scan...{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Testing for: {', '.join(vuln_types)}{Colors.ENDC}")
        
        scanner.scan_start_time = time.time()
        
        # Scan URLs
        for url in urls_to_scan:
            if not args.silent:
                print(f"{Colors.BLUE}[*] Scanning: {url}{Colors.ENDC}")
            
            url_vulns = scanner.scan_url(url, vuln_types, args.verbose, args.delay)
            scanner.vulnerabilities.extend(url_vulns)
        
        # Display results
        scanner.display_results(args.output, args.silent)
        
        # Save results if requested
        if args.save:
            scanner.save_results(args.save, args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Fatal error: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()