#!/usr/bin/env python3
"""
Enhanced ARP Scanner - Advanced Network Discovery Tool
Features: Stealth scanning, MAC spoofing, OS detection, vulnerability scanning integration
Author: Cybersecurity Student Tool Enhancement
"""

import scapy.all as scapy
import argparse
import time
import random
import subprocess
import threading
import json
import ipaddress
from datetime import datetime
import os
import sys

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

class EnhancedARPScanner:
    def __init__(self):
        self.results = []
        self.scan_start_time = None
        self.total_hosts = 0
        
    def get_arguments(self):
        parser = argparse.ArgumentParser(
            description="Enhanced ARP Network Scanner with Advanced Features",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python3 enhanced_arp_scanner.py -r 192.168.1.1/24
  python3 enhanced_arp_scanner.py -r 192.168.1.1/24 -s -d random --os-detect
  python3 enhanced_arp_scanner.py -r 192.168.1.1/24 -m -i eth0 --output json
  python3 enhanced_arp_scanner.py -r 192.168.1.1/24 --threads 50 --timeout 3
            """)
        
        parser.add_argument("-r", "--range", dest="network_ip", required=True, 
                          help="Target IP range (e.g., 192.168.1.1/24)")
        parser.add_argument("-s", "--stealth", action="store_true", 
                          help="Enable stealth mode (adds delay between packets)")
        parser.add_argument("-d", "--delay", type=str, default="1.0",
                          help="Delay between packets (e.g., 1.5 or 'random')")
        parser.add_argument("-i", "--interface", type=str, 
                          help="Network interface (e.g., eth0 or wlan0)")
        parser.add_argument("-m", "--mac-spoof", action="store_true", 
                          help="Spoof MAC address before scan")
        parser.add_argument("--timeout", type=int, default=2,
                          help="Timeout for ARP requests (default: 2)")
        parser.add_argument("--threads", type=int, default=20,
                          help="Number of threads for scanning (default: 20)")
        parser.add_argument("--os-detect", action="store_true",
                          help="Attempt basic OS detection")
        parser.add_argument("--vendor-lookup", action="store_true",
                          help="Lookup MAC vendor information")
        parser.add_argument("--output", choices=['table', 'json', 'csv'], default='table',
                          help="Output format (default: table)")
        parser.add_argument("--save", type=str,
                          help="Save results to file")
        parser.add_argument("--verbose", "-v", action="store_true",
                          help="Verbose output")
        parser.add_argument("--silent", action="store_true",
                          help="Silent mode (minimal output)")
        
        return parser.parse_args()

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════╗
║        Enhanced ARP Scanner v2.0          ║
║     Advanced Network Discovery Tool       ║
╚═══════════════════════════════════════════╝
{Colors.ENDC}
        """
        print(banner)

    def generate_random_mac(self):
        """Generate a random MAC address with valid OUI"""
        # Use common vendor OUIs for better stealth
        ouis = [
            "00:50:56",  # VMware
            "08:00:27",  # VirtualBox
            "00:0C:29",  # VMware
            "00:1B:21",  # Intel
            "00:23:AE",  # LiteOn
        ]
        oui = random.choice(ouis)
        mac = f"{oui}:%02x:%02x:%02x" % tuple(random.randint(0x00, 0xFF) for _ in range(3))
        return mac

    def change_mac(self, interface, new_mac):
        """Change MAC address with better error handling"""
        try:
            print(f"{Colors.YELLOW}[+] Changing MAC address of {interface} to {new_mac}{Colors.ENDC}")
            
            # Bring interface down
            result = subprocess.run(["sudo", "ip", "link", "set", interface, "down"], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Failed to bring interface down: {result.stderr}")
            
            # Change MAC
            result = subprocess.run(["sudo", "ip", "link", "set", interface, "address", new_mac],
                                  capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Failed to change MAC: {result.stderr}")
            
            # Bring interface up
            result = subprocess.run(["sudo", "ip", "link", "set", interface, "up"],
                                  capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Failed to bring interface up: {result.stderr}")
                
            print(f"{Colors.GREEN}[✓] MAC address changed successfully{Colors.ENDC}")
            time.sleep(2)  # Wait for interface to stabilize
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error changing MAC address: {e}{Colors.ENDC}")
            return False
        return True

    def get_vendor_info(self, mac):
        """Get vendor information from MAC address"""
        try:
            # Simple vendor lookup based on OUI
            oui = mac[:8].upper().replace(":", "")
            vendor_db = {
                "005056": "VMware",
                "080027": "VirtualBox", 
                "000C29": "VMware",
                "001B21": "Intel",
                "0023AE": "LiteOn",
                "001C42": "Parallels",
                "0050C2": "IEEE Registration Authority",
                "00A0C9": "Intel",
                "000D87": "Cisco-Linksys",
                "001839": "Cisco-Linksys",
            }
            return vendor_db.get(oui, "Unknown")
        except:
            return "Unknown"

    def detect_os_hints(self, ip):
        """Basic OS detection through TTL and other indicators"""
        try:
            # Send ICMP ping to get TTL
            response = scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=1, verbose=False)
            if response:
                ttl = response.ttl
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Network Device"
        except:
            pass
        return "Unknown"

    def threaded_arp_scan(self, ip_list, results_list, stealth=False, delay=None, timeout=2, verbose=False):
        """Threaded ARP scanning for better performance"""
        for ip in ip_list:
            try:
                if verbose and not stealth:
                    print(f"{Colors.BLUE}[*] Scanning {ip}...{Colors.ENDC}")
                
                arp_request = scapy.ARP(pdst=ip)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                request_broadcast = broadcast / arp_request
                
                answered, _ = scapy.srp(request_broadcast, timeout=timeout, verbose=False)
                
                for element in answered:
                    client_info = {
                        "ip": element[1].psrc,
                        "mac": element[1].hwsrc,
                        "timestamp": datetime.now().isoformat()
                    }
                    results_list.append(client_info)
                
                if stealth:
                    if delay == "random":
                        sleep_time = round(random.uniform(0.1, 1.0), 2)
                    else:
                        try:
                            sleep_time = float(delay)
                        except:
                            sleep_time = 0.5
                    time.sleep(sleep_time)
                    
            except Exception as e:
                if verbose:
                    print(f"{Colors.RED}[!] Error scanning {ip}: {e}{Colors.ENDC}")

    def scan_network(self, network_ip, stealth=False, delay=None, timeout=2, threads=20, verbose=False):
        """Enhanced network scanning with threading"""
        try:
            # Parse network range
            network = ipaddress.ip_network(network_ip, strict=False)
            host_list = [str(ip) for ip in network.hosts()]
            self.total_hosts = len(host_list)
            
            if not verbose:
                print(f"{Colors.CYAN}[*] Scanning {self.total_hosts} hosts in {network_ip}...{Colors.ENDC}")
            
            self.scan_start_time = time.time()
            
            # Split hosts into chunks for threading
            chunk_size = max(1, len(host_list) // threads)
            chunks = [host_list[i:i + chunk_size] for i in range(0, len(host_list), chunk_size)]
            
            # Create threads
            thread_list = []
            for chunk in chunks:
                thread = threading.Thread(
                    target=self.threaded_arp_scan,
                    args=(chunk, self.results, stealth, delay, timeout, verbose)
                )
                thread_list.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in thread_list:
                thread.join()
                
            return self.results
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error during scan: {e}{Colors.ENDC}")
            return []

    def enhance_results(self, results, os_detect=False, vendor_lookup=False):
        """Enhance results with additional information"""
        enhanced_results = []
        
        for result in results:
            enhanced = result.copy()
            
            if vendor_lookup:
                enhanced['vendor'] = self.get_vendor_info(result['mac'])
            
            if os_detect:
                enhanced['os_hint'] = self.detect_os_hints(result['ip'])
                
            enhanced_results.append(enhanced)
            
        return enhanced_results

    def display_results(self, results, output_format='table', silent=False):
        """Display results in various formats"""
        if not results:
            if not silent:
                print(f"{Colors.YELLOW}[!] No devices found{Colors.ENDC}")
            return
            
        scan_time = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        if output_format == 'table':
            if not silent:
                print(f"\n{Colors.GREEN}{'='*80}{Colors.ENDC}")
                print(f"{Colors.BOLD}Scan Results:{Colors.ENDC}")
                print(f"{Colors.GREEN}{'='*80}{Colors.ENDC}")
                
                # Determine columns based on available data
                has_vendor = any('vendor' in r for r in results)
                has_os = any('os_hint' in r for r in results)
                
                if has_vendor and has_os:
                    print(f"{Colors.BOLD}{'IP Address':<15} {'MAC Address':<18} {'Vendor':<15} {'OS Hint':<12} {'Timestamp':<20}{Colors.ENDC}")
                    print("-" * 80)
                    for result in results:
                        print(f"{result['ip']:<15} {result['mac']:<18} {result.get('vendor', 'N/A'):<15} {result.get('os_hint', 'N/A'):<12} {result.get('timestamp', 'N/A'):<20}")
                elif has_vendor:
                    print(f"{Colors.BOLD}{'IP Address':<15} {'MAC Address':<18} {'Vendor':<20} {'Timestamp':<20}{Colors.ENDC}")
                    print("-" * 73)
                    for result in results:
                        print(f"{result['ip']:<15} {result['mac']:<18} {result.get('vendor', 'N/A'):<20} {result.get('timestamp', 'N/A'):<20}")
                else:
                    print(f"{Colors.BOLD}{'IP Address':<15} {'MAC Address':<18} {'Timestamp':<20}{Colors.ENDC}")
                    print("-" * 53)
                    for result in results:
                        print(f"{result['ip']:<15} {result['mac']:<18} {result.get('timestamp', 'N/A'):<20}")
                
                print(f"\n{Colors.GREEN}[✓] Scan completed in {scan_time:.2f} seconds{Colors.ENDC}")
                print(f"{Colors.GREEN}[✓] Found {len(results)} device(s) out of {self.total_hosts} hosts scanned{Colors.ENDC}")
                
        elif output_format == 'json':
            scan_info = {
                "scan_time": scan_time,
                "total_hosts_scanned": self.total_hosts,
                "devices_found": len(results),
                "timestamp": datetime.now().isoformat(),
                "results": results
            }
            print(json.dumps(scan_info, indent=2))
            
        elif output_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            
            if results:
                fieldnames = list(results[0].keys())
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
                
            print(output.getvalue())

    def save_results(self, results, filename, output_format='json'):
        """Save results to file"""
        try:
            with open(filename, 'w') as f:
                if output_format == 'json':
                    scan_info = {
                        "scan_time": time.time() - self.scan_start_time if self.scan_start_time else 0,
                        "total_hosts_scanned": self.total_hosts,
                        "devices_found": len(results),
                        "timestamp": datetime.now().isoformat(),
                        "results": results
                    }
                    json.dump(scan_info, f, indent=2)
                elif output_format == 'csv':
                    import csv
                    if results:
                        fieldnames = list(results[0].keys())
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(results)
                        
            print(f"{Colors.GREEN}[✓] Results saved to {filename}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving results: {e}{Colors.ENDC}")

def main():
    # Check if running as root for certain features
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}[!] Some features require root privileges (MAC spoofing, OS detection){Colors.ENDC}")
    
    scanner = EnhancedARPScanner()
    
    try:
        args = scanner.get_arguments()
        
        if not args.silent:
            scanner.print_banner()
        
        # MAC spoofing
        if args.mac_spoof:
            if not args.interface:
                print(f"{Colors.RED}[-] You must specify --interface or -i when using --mac-spoof{Colors.ENDC}")
                sys.exit(1)
            
            if os.geteuid() != 0:
                print(f"{Colors.RED}[-] MAC spoofing requires root privileges{Colors.ENDC}")
                sys.exit(1)
                
            new_mac = scanner.generate_random_mac()
            if not scanner.change_mac(args.interface, new_mac):
                sys.exit(1)
        
        # Perform scan
        if not args.silent:
            print(f"{Colors.CYAN}[*] Starting enhanced ARP scan...{Colors.ENDC}")
            
        results = scanner.scan_network(
            args.network_ip,
            stealth=args.stealth,
            delay=args.delay,
            timeout=args.timeout,
            threads=args.threads,
            verbose=args.verbose
        )
        
        # Enhance results with additional information
        enhanced_results = scanner.enhance_results(
            results,
            os_detect=args.os_detect,
            vendor_lookup=args.vendor_lookup
        )
        
        # Display results
        scanner.display_results(enhanced_results, args.output, args.silent)
        
        # Save results if requested
        if args.save:
            scanner.save_results(enhanced_results, args.save, args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Fatal error: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()