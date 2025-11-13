#!/usr/bin/env python3
"""
Smart Vulnerability Scanner
===========================
An intelligent vulnerability scanner for authorized security testing.

LEGAL WARNING:
--------------
This tool is designed ONLY for:
- Authorized bug bounty programs (Google VRP, Apple Security Bounty, etc.)
- Penetration testing with written permission
- Security research on systems you own or have explicit authorization to test

Unauthorized scanning is ILLEGAL and may result in criminal prosecution.
Always ensure you have written permission before scanning any target.

Usage:
    python3 scanner.py --target https://example.com --scope bug-bounty
"""

import requests
import argparse
import json
import sys
import time
import urllib.parse
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class Colors:
    """Terminal colors for output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class VulnerabilityScanner:
    """Main vulnerability scanner class"""

    def __init__(self, target: str, config: Dict):
        self.target = target.rstrip('/')
        self.config = config
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.get('user_agent', 'SecurityScanner/1.0 (Authorized Testing)')
        })

    def banner(self):
        """Display tool banner"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}")
        print("=" * 70)
        print("         Smart Vulnerability Scanner v1.0")
        print("         For Authorized Security Testing Only")
        print("=" * 70)
        print(f"{Colors.END}")
        print(f"{Colors.YELLOW}Target: {self.target}{Colors.END}")
        print(f"{Colors.YELLOW}Scope: {self.config.get('scope', 'Not specified')}{Colors.END}\n")

    def confirm_authorization(self) -> bool:
        """Confirm user has authorization to scan"""
        print(f"\n{Colors.RED}{Colors.BOLD}AUTHORIZATION CHECK{Colors.END}")
        print(f"{Colors.RED}Do you have WRITTEN AUTHORIZATION to test {self.target}?{Colors.END}")
        print("This includes:")
        print("  - Bug bounty program participation")
        print("  - Written penetration testing agreement")
        print("  - System ownership documentation")

        response = input(f"\n{Colors.BOLD}Type 'YES I AM AUTHORIZED' to continue: {Colors.END}")
        return response == "YES I AM AUTHORIZED"

    def smart_request(self, url: str, method: str = 'GET', data: Dict = None,
                     params: Dict = None, timeout: int = 10) -> Optional[requests.Response]:
        """Make a smart HTTP request with error handling"""
        try:
            if method.upper() == 'GET':
                resp = self.session.get(url, params=params, timeout=timeout,
                                       verify=False, allow_redirects=True)
            elif method.upper() == 'POST':
                resp = self.session.post(url, data=data, params=params,
                                        timeout=timeout, verify=False)
            else:
                resp = self.session.request(method, url, data=data, params=params,
                                           timeout=timeout, verify=False)
            return resp
        except requests.exceptions.Timeout:
            print(f"{Colors.YELLOW}[!] Timeout for {url}{Colors.END}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] Request error: {str(e)}{Colors.END}")
            return None

    def scan(self):
        """Main scanning function"""
        self.banner()

        if not self.confirm_authorization():
            print(f"\n{Colors.RED}[!] Authorization not confirmed. Exiting.{Colors.END}")
            sys.exit(1)

        print(f"\n{Colors.GREEN}[+] Starting vulnerability scan...{Colors.END}\n")

        # Import scanner modules
        from modules.sql_injection import SQLInjectionScanner
        from modules.xss_scanner import XSSScanner
        from modules.ssrf_scanner import SSRFScanner
        from modules.open_redirect import OpenRedirectScanner
        from modules.header_injection import HeaderInjectionScanner
        from modules.info_disclosure import InfoDisclosureScanner

        # Initialize scanners
        scanners = [
            InfoDisclosureScanner(self),
            SQLInjectionScanner(self),
            XSSScanner(self),
            SSRFScanner(self),
            OpenRedirectScanner(self),
            HeaderInjectionScanner(self)
        ]

        # Run each scanner
        for scanner in scanners:
            print(f"\n{Colors.CYAN}[*] Running {scanner.name}...{Colors.END}")
            results = scanner.scan()
            if results:
                self.vulnerabilities.extend(results)
                print(f"{Colors.GREEN}[+] Found {len(results)} potential issues{Colors.END}")

        # Generate report
        self.generate_report()

    def generate_report(self):
        """Generate vulnerability report"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}")
        print("=" * 70)
        print("                    SCAN RESULTS")
        print("=" * 70)
        print(f"{Colors.END}")

        if not self.vulnerabilities:
            print(f"{Colors.GREEN}[+] No vulnerabilities found!{Colors.END}")
            return

        # Group by severity
        critical = [v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']
        high = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
        medium = [v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']
        low = [v for v in self.vulnerabilities if v['severity'] == 'LOW']
        info = [v for v in self.vulnerabilities if v['severity'] == 'INFO']

        print(f"{Colors.RED}Critical: {len(critical)}{Colors.END}")
        print(f"{Colors.RED}High: {len(high)}{Colors.END}")
        print(f"{Colors.YELLOW}Medium: {len(medium)}{Colors.END}")
        print(f"{Colors.YELLOW}Low: {len(low)}{Colors.END}")
        print(f"{Colors.CYAN}Info: {len(info)}{Colors.END}")

        print(f"\n{Colors.BOLD}Detailed Findings:{Colors.END}\n")

        for vuln in self.vulnerabilities:
            color = Colors.RED if vuln['severity'] in ['CRITICAL', 'HIGH'] else Colors.YELLOW
            print(f"{color}[{vuln['severity']}] {vuln['type']}{Colors.END}")
            print(f"  URL: {vuln['url']}")
            print(f"  Description: {vuln['description']}")
            if 'payload' in vuln:
                print(f"  Payload: {vuln['payload'][:100]}...")
            if 'evidence' in vuln:
                print(f"  Evidence: {vuln['evidence'][:100]}...")
            print()

        # Save JSON report
        report_file = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'target': self.target,
                'scan_date': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities
            }, f, indent=2)

        print(f"{Colors.GREEN}[+] Report saved to {report_file}{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description='Smart Vulnerability Scanner for Authorized Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py --target https://example.com --scope bug-bounty
  python3 scanner.py --target https://testsite.com --scope pentest --threads 10

Bug Bounty Programs:
  Google VRP: https://bughunters.google.com/
  Apple Security Bounty: https://security.apple.com/bounty/

Remember: ALWAYS get authorization before scanning!
        """
    )

    parser.add_argument('--target', required=True, help='Target URL (e.g., https://example.com)')
    parser.add_argument('--scope', required=True,
                       choices=['bug-bounty', 'pentest', 'owned-system'],
                       help='Authorization scope')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive scanning')

    args = parser.parse_args()

    # Configuration
    config = {
        'scope': args.scope,
        'threads': args.threads,
        'timeout': args.timeout,
        'aggressive': args.aggressive,
        'user_agent': 'SecurityScanner/1.0 (Authorized Bug Bounty Testing)'
    }

    # Initialize and run scanner
    scanner = VulnerabilityScanner(args.target, config)
    scanner.scan()

if __name__ == '__main__':
    main()
