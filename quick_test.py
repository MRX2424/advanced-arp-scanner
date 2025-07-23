#!/usr/bin/env python3
"""
Quick Test Script for Cybersecurity Toolkit
This script demonstrates the functionality of all tools
"""

import subprocess
import sys
import time

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════╗
║     Cybersecurity Toolkit Quick Test     ║
║            Tool Demonstration             ║
╚═══════════════════════════════════════════╝
{Colors.ENDC}
    """
    print(banner)

def run_test(command, description):
    """Run a test command and display results"""
    print(f"\n{Colors.BLUE}{'='*60}{Colors.ENDC}")
    print(f"{Colors.YELLOW}🧪 Testing: {description}{Colors.ENDC}")
    print(f"{Colors.BLUE}Command: {command}{Colors.ENDC}")
    print(f"{Colors.BLUE}{'='*60}{Colors.ENDC}")
    
    try:
        # Run the command
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}✅ Test completed successfully{Colors.ENDC}")
            if result.stdout:
                print(f"\nOutput preview (first 500 chars):")
                print(result.stdout[:500])
                if len(result.stdout) > 500:
                    print("... (output truncated)")
        else:
            print(f"{Colors.RED}❌ Test failed with return code: {result.returncode}{Colors.ENDC}")
            if result.stderr:
                print(f"Error: {result.stderr}")
                
    except subprocess.TimeoutExpired:
        print(f"{Colors.YELLOW}⏰ Test timed out (30 seconds limit){Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}❌ Test failed with exception: {e}{Colors.ENDC}")
    
    time.sleep(2)

def main():
    print_banner()
    
    print(f"{Colors.CYAN}This script will run quick tests on all cybersecurity tools{Colors.ENDC}")
    print(f"{Colors.YELLOW}Note: Some tests may require specific network conditions or permissions{Colors.ENDC}")
    
    input(f"\n{Colors.GREEN}Press Enter to start testing...{Colors.ENDC}")
    
    # Test 1: Enhanced ARP Scanner (help)
    run_test(
        "python3 enhanced_arp_scanner.py --help",
        "Enhanced ARP Scanner - Help Output"
    )
    
    # Test 2: Enhanced ARP Scanner (localhost scan)
    run_test(
        "python3 enhanced_arp_scanner.py -r 127.0.0.1/32 --timeout 1",
        "Enhanced ARP Scanner - Localhost Test"
    )
    
    # Test 3: Port Scanner (help)
    run_test(
        "python3 port_scanner.py --help",
        "Advanced Port Scanner - Help Output"
    )
    
    # Test 4: Port Scanner (localhost common ports)
    run_test(
        "python3 port_scanner.py -t 127.0.0.1 -p 80,443,22 --timeout 1",
        "Advanced Port Scanner - Localhost Common Ports"
    )
    
    # Test 5: Web Security Scanner (help)
    run_test(
        "python3 web_security_scanner.py --help", 
        "Web Security Scanner - Help Output"
    )
    
    # Test 6: Check if all required modules are installed
    print(f"\n{Colors.BLUE}{'='*60}{Colors.ENDC}")
    print(f"{Colors.YELLOW}🔍 Checking Python Dependencies{Colors.ENDC}")
    print(f"{Colors.BLUE}{'='*60}{Colors.ENDC}")
    
    required_modules = ['scapy', 'requests', 'beautifulsoup4', 'argparse']
    
    for module in required_modules:
        try:
            if module == 'beautifulsoup4':
                import bs4
            else:
                __import__(module)
            print(f"{Colors.GREEN}✅ {module} - Available{Colors.ENDC}")
        except ImportError:
            print(f"{Colors.RED}❌ {module} - Missing (install with: pip install {module}){Colors.ENDC}")
    
    # Test 7: Create test output files
    print(f"\n{Colors.BLUE}{'='*60}{Colors.ENDC}")
    print(f"{Colors.YELLOW}📄 Testing Output File Generation{Colors.ENDC}")
    print(f"{Colors.BLUE}{'='*60}{Colors.ENDC}")
    
    # Test JSON output
    run_test(
        "python3 enhanced_arp_scanner.py -r 127.0.0.1/32 --output json --save test_output.json --silent",
        "JSON Output Test"
    )
    
    # Test CSV output  
    run_test(
        "python3 enhanced_arp_scanner.py -r 127.0.0.1/32 --output csv --save test_output.csv --silent",
        "CSV Output Test"
    )
    
    # Summary
    print(f"\n{Colors.GREEN}{'='*60}{Colors.ENDC}")
    print(f"{Colors.GREEN}{Colors.BOLD}🎉 Testing Complete!{Colors.ENDC}")
    print(f"{Colors.GREEN}{'='*60}{Colors.ENDC}")
    
    print(f"""
{Colors.CYAN}Next Steps:{Colors.ENDC}
1. Review any failed tests above
2. Install missing dependencies if needed
3. Run individual tools with your target networks
4. Read the CYBERSECURITY_TOOLKIT_GUIDE.md for detailed usage

{Colors.YELLOW}Remember: Only test on networks you own or have permission to test!{Colors.ENDC}

{Colors.GREEN}Tool Usage Examples:{Colors.ENDC}
• Enhanced ARP Scanner: python3 enhanced_arp_scanner.py -r 192.168.1.1/24
• Port Scanner: python3 port_scanner.py -t 192.168.1.1 --common-ports
• Web Scanner: python3 web_security_scanner.py -u http://example.com --vuln-types headers
    """)

if __name__ == "__main__":
    main()