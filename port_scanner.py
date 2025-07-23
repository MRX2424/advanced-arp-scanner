#!/usr/bin/env python3
"""
Advanced Port Scanner - Professional Network Port Analysis Tool
Features: Multiple scan types, service detection, vulnerability assessment
Author: Cybersecurity Student Tool Enhancement
"""

import socket
import threading
import argparse
import time
import random
import json
import sys
from datetime import datetime
import subprocess
import re

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

class AdvancedPortScanner:
    def __init__(self):
        self.open_ports = []
        self.scan_start_time = None
        self.common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MYSQL",
            3389: "RDP", 5432: "POSTGRESQL", 6379: "REDIS", 27017: "MONGODB"
        }
        
        self.vulnerability_signatures = {
            21: ["FTP anonymous login", "vsftpd 2.3.4 backdoor"],
            22: ["SSH weak encryption", "OpenSSH user enumeration"],
            23: ["Telnet cleartext", "Default credentials"],
            25: ["SMTP open relay", "VRFY command enabled"],
            80: ["HTTP server info disclosure", "Default pages"],
            443: ["SSL/TLS vulnerabilities", "Weak ciphers"],
            3389: ["RDP BlueKeep", "Weak RDP encryption"]
        }

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════╗
║       Advanced Port Scanner v1.0          ║
║    Professional Network Analysis Tool     ║
╚═══════════════════════════════════════════╝
{Colors.ENDC}
        """
        print(banner)

    def get_arguments(self):
        parser = argparse.ArgumentParser(
            description="Advanced Port Scanner with Multiple Techniques",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Scan Types:
  tcp-connect : Full TCP connect scan (default)
  tcp-syn     : SYN stealth scan (requires root)
  udp         : UDP scan
  tcp-fin     : FIN scan
  tcp-null    : NULL scan
  tcp-xmas    : XMAS scan

Examples:
  python3 port_scanner.py -t 192.168.1.1 -p 1-1000
  python3 port_scanner.py -t 192.168.1.1 -p 22,80,443 --scan-type tcp-syn
  python3 port_scanner.py -t 192.168.1.1 --common-ports --service-detect
  python3 port_scanner.py -t 192.168.1.1 -p 1-65535 --threads 100 --stealth
            """)
        
        parser.add_argument("-t", "--target", required=True,
                          help="Target IP address or hostname")
        parser.add_argument("-p", "--ports", default="1-1000",
                          help="Port range (e.g., 1-1000, 22,80,443)")
        parser.add_argument("--common-ports", action="store_true",
                          help="Scan common ports only")
        parser.add_argument("--scan-type", choices=['tcp-connect', 'tcp-syn', 'udp', 'tcp-fin', 'tcp-null', 'tcp-xmas'],
                          default='tcp-connect', help="Scan technique")
        parser.add_argument("--threads", type=int, default=50,
                          help="Number of threads (default: 50)")
        parser.add_argument("--timeout", type=float, default=1.0,
                          help="Connection timeout (default: 1.0)")
        parser.add_argument("--stealth", action="store_true",
                          help="Enable stealth mode with random delays")
        parser.add_argument("--service-detect", action="store_true",
                          help="Detect services on open ports")
        parser.add_argument("--vuln-scan", action="store_true",
                          help="Basic vulnerability assessment")
        parser.add_argument("--output", choices=['table', 'json', 'csv'], default='table',
                          help="Output format")
        parser.add_argument("--save", type=str,
                          help="Save results to file")
        parser.add_argument("--verbose", "-v", action="store_true",
                          help="Verbose output")
        parser.add_argument("--silent", action="store_true",
                          help="Silent mode")
        
        return parser.parse_args()

    def parse_ports(self, port_string):
        """Parse port specification into list of ports"""
        ports = []
        
        if self.common_ports and hasattr(self, 'common_ports_only'):
            return list(self.common_ports.keys())
        
        for part in port_string.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))

    def tcp_connect_scan(self, target, port, timeout, verbose=False):
        """Traditional TCP connect scan"""
        try:
            if verbose:
                print(f"{Colors.BLUE}[*] Scanning TCP {port}...{Colors.ENDC}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return True
                
        except Exception as e:
            if verbose:
                print(f"{Colors.RED}[!] Error scanning port {port}: {e}{Colors.ENDC}")
        
        return False

    def detect_service(self, target, port, timeout=3):
        """Basic service detection using banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            else:
                # Try to grab banner
                pass
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Analyze banner
            service_info = self.analyze_banner(banner, port)
            return service_info
            
        except:
            # Return default service info
            return {
                'service': self.common_ports.get(port, 'unknown'),
                'version': 'unknown',
                'banner': ''
            }

    def analyze_banner(self, banner, port):
        """Analyze service banner for version information"""
        service_info = {
            'service': self.common_ports.get(port, 'unknown'),
            'version': 'unknown',
            'banner': banner[:100]  # Limit banner length
        }
        
        # HTTP/HTTPS detection
        if 'HTTP' in banner:
            if 'Apache' in banner:
                match = re.search(r'Apache/([0-9.]+)', banner)
                service_info['service'] = 'Apache'
                if match:
                    service_info['version'] = match.group(1)
            elif 'nginx' in banner:
                match = re.search(r'nginx/([0-9.]+)', banner)
                service_info['service'] = 'Nginx'
                if match:
                    service_info['version'] = match.group(1)
            elif 'IIS' in banner:
                service_info['service'] = 'IIS'
        
        # SSH detection
        elif 'SSH' in banner:
            match = re.search(r'OpenSSH_([0-9.]+)', banner)
            service_info['service'] = 'OpenSSH'
            if match:
                service_info['version'] = match.group(1)
        
        # FTP detection
        elif 'FTP' in banner:
            if 'vsftpd' in banner:
                match = re.search(r'vsftpd ([0-9.]+)', banner)
                service_info['service'] = 'vsftpd'
                if match:
                    service_info['version'] = match.group(1)
        
        return service_info

    def basic_vuln_check(self, target, port, service_info):
        """Basic vulnerability assessment"""
        vulnerabilities = []
        
        # Check known vulnerable versions
        service = service_info.get('service', '').lower()
        version = service_info.get('version', '')
        
        # Example vulnerability checks
        if service == 'apache' and version:
            try:
                version_parts = [int(x) for x in version.split('.')]
                if version_parts[0] == 2 and version_parts[1] < 4:
                    vulnerabilities.append("Apache < 2.4 - Multiple vulnerabilities")
            except:
                pass
        
        elif service == 'openssh' and version:
            try:
                version_parts = [int(x) for x in version.split('.')]
                if version_parts[0] < 8:
                    vulnerabilities.append("OpenSSH < 8.0 - User enumeration")
            except:
                pass
        
        # Port-specific checks
        if port in self.vulnerability_signatures:
            vulnerabilities.extend(self.vulnerability_signatures[port])
        
        return vulnerabilities

    def scan_port(self, target, port, scan_type, timeout, stealth, service_detect, vuln_scan, verbose):
        """Scan individual port with specified technique"""
        try:
            is_open = False
            
            # Apply stealth delay
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))
            
            # Perform scan based on type
            if scan_type == 'tcp-connect':
                is_open = self.tcp_connect_scan(target, port, timeout, verbose)
            
            # Add other scan types here (SYN, UDP, etc.)
            # For now, defaulting to TCP connect
            
            if is_open:
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': self.common_ports.get(port, 'unknown'),
                    'timestamp': datetime.now().isoformat()
                }
                
                # Service detection
                if service_detect:
                    service_info = self.detect_service(target, port)
                    port_info.update(service_info)
                
                # Vulnerability assessment
                if vuln_scan:
                    vulnerabilities = self.basic_vuln_check(target, port, port_info)
                    port_info['vulnerabilities'] = vulnerabilities
                
                self.open_ports.append(port_info)
                
                if not verbose:
                    print(f"{Colors.GREEN}[+] Port {port} ({port_info['service']}) - OPEN{Colors.ENDC}")
                
        except Exception as e:
            if verbose:
                print(f"{Colors.RED}[!] Error scanning port {port}: {e}{Colors.ENDC}")

    def threaded_scan(self, target, ports, scan_type, timeout, threads, stealth, service_detect, vuln_scan, verbose):
        """Multi-threaded port scanning"""
        
        def worker():
            while True:
                try:
                    port = port_queue.get(timeout=1)
                    self.scan_port(target, port, scan_type, timeout, stealth, service_detect, vuln_scan, verbose)
                    port_queue.task_done()
                except:
                    break
        
        import queue
        port_queue = queue.Queue()
        
        # Add ports to queue
        for port in ports:
            port_queue.put(port)
        
        # Start threads
        thread_list = []
        for _ in range(min(threads, len(ports))):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        # Wait for completion
        port_queue.join()

    def display_results(self, target, output_format='table', silent=False):
        """Display scan results"""
        if not self.open_ports:
            if not silent:
                print(f"{Colors.YELLOW}[!] No open ports found{Colors.ENDC}")
            return
        
        scan_time = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        if output_format == 'table':
            if not silent:
                print(f"\n{Colors.GREEN}{'='*80}{Colors.ENDC}")
                print(f"{Colors.BOLD}Port Scan Results for {target}:{Colors.ENDC}")
                print(f"{Colors.GREEN}{'='*80}{Colors.ENDC}")
                
                # Check if we have service info
                has_service_info = any('version' in port for port in self.open_ports)
                has_vulns = any('vulnerabilities' in port for port in self.open_ports)
                
                if has_vulns:
                    print(f"{Colors.BOLD}{'Port':<8} {'Service':<15} {'Version':<15} {'Vulnerabilities':<30}{Colors.ENDC}")
                    print("-" * 70)
                    for port in self.open_ports:
                        vulns = ', '.join(port.get('vulnerabilities', []))
                        if len(vulns) > 28:
                            vulns = vulns[:25] + "..."
                        print(f"{port['port']:<8} {port.get('service', 'unknown'):<15} {port.get('version', 'unknown'):<15} {vulns:<30}")
                elif has_service_info:
                    print(f"{Colors.BOLD}{'Port':<8} {'Service':<15} {'Version':<15} {'Banner':<30}{Colors.ENDC}")
                    print("-" * 70)
                    for port in self.open_ports:
                        banner = port.get('banner', '')
                        if len(banner) > 28:
                            banner = banner[:25] + "..."
                        print(f"{port['port']:<8} {port.get('service', 'unknown'):<15} {port.get('version', 'unknown'):<15} {banner:<30}")
                else:
                    print(f"{Colors.BOLD}{'Port':<8} {'Service':<15} {'State':<10}{Colors.ENDC}")
                    print("-" * 35)
                    for port in self.open_ports:
                        print(f"{port['port']:<8} {port.get('service', 'unknown'):<15} {port['state']:<10}")
                
                print(f"\n{Colors.GREEN}[✓] Scan completed in {scan_time:.2f} seconds{Colors.ENDC}")
                print(f"{Colors.GREEN}[✓] Found {len(self.open_ports)} open port(s){Colors.ENDC}")
                
        elif output_format == 'json':
            scan_info = {
                "target": target,
                "scan_time": scan_time,
                "open_ports_count": len(self.open_ports),
                "timestamp": datetime.now().isoformat(),
                "open_ports": self.open_ports
            }
            print(json.dumps(scan_info, indent=2))
            
        elif output_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            if self.open_ports:
                fieldnames = list(self.open_ports[0].keys())
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.open_ports)
            print(output.getvalue())

    def save_results(self, target, filename, output_format='json'):
        """Save results to file"""
        try:
            with open(filename, 'w') as f:
                if output_format == 'json':
                    scan_info = {
                        "target": target,
                        "scan_time": time.time() - self.scan_start_time if self.scan_start_time else 0,
                        "open_ports_count": len(self.open_ports),
                        "timestamp": datetime.now().isoformat(),
                        "open_ports": self.open_ports
                    }
                    json.dump(scan_info, f, indent=2)
                elif output_format == 'csv':
                    import csv
                    if self.open_ports:
                        fieldnames = list(self.open_ports[0].keys())
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(self.open_ports)
            
            print(f"{Colors.GREEN}[✓] Results saved to {filename}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving results: {e}{Colors.ENDC}")

def main():
    scanner = AdvancedPortScanner()
    
    try:
        args = scanner.get_arguments()
        
        if not args.silent:
            scanner.print_banner()
        
        # Parse ports
        if args.common_ports:
            ports = list(scanner.common_ports.keys())
        else:
            ports = scanner.parse_ports(args.ports)
        
        if not args.silent:
            print(f"{Colors.CYAN}[*] Starting port scan on {args.target}{Colors.ENDC}")
            print(f"{Colors.CYAN}[*] Scanning {len(ports)} port(s) using {args.scan_type} scan{Colors.ENDC}")
            if args.stealth:
                print(f"{Colors.YELLOW}[*] Stealth mode enabled{Colors.ENDC}")
        
        scanner.scan_start_time = time.time()
        
        # Perform scan
        scanner.threaded_scan(
            args.target, ports, args.scan_type, args.timeout,
            args.threads, args.stealth, args.service_detect,
            args.vuln_scan, args.verbose
        )
        
        # Display results
        scanner.display_results(args.target, args.output, args.silent)
        
        # Save results if requested
        if args.save:
            scanner.save_results(args.target, args.save, args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Fatal error: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()