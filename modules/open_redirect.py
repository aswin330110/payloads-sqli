"""
Open Redirect Scanner Module
Tests for open redirect vulnerabilities
"""

import re
from typing import List, Dict
from urllib.parse import urlparse

class OpenRedirectScanner:
    """Smart Open Redirect vulnerability scanner"""

    def __init__(self, parent_scanner):
        self.scanner = parent_scanner
        self.name = "Open Redirect Scanner"
        self.test_domains = [
            'evil.com',
            'attacker.com',
            'https://evil.com',
            'http://attacker.com',
            '//evil.com',
        ]

    def generate_redirect_payloads(self, test_domain: str) -> List[str]:
        """Generate open redirect test payloads"""
        payloads = [
            test_domain,
            f'https://{test_domain}',
            f'http://{test_domain}',
            f'//{test_domain}',
            f'/{test_domain}',
            f'@{test_domain}',
            f'javascript:window.location="http://{test_domain}"',
            f'data:text/html,<script>window.location="http://{test_domain}"</script>',
            f'\x00http://{test_domain}',
            f'http://{test_domain}%00',
            f'http://www.{test_domain}/',
            f'//www.{test_domain}/',
        ]

        # URL encoding variations
        encoded_payloads = [
            test_domain.replace('.', '%2e'),
            test_domain.replace('.', '%252e'),
            f'%2f%2f{test_domain}',
        ]

        return payloads + encoded_payloads

    def check_redirect(self, response, test_domain: str) -> bool:
        """Check if redirect is vulnerable"""
        if not response:
            return False

        # Check Location header
        if 'Location' in response.headers:
            location = response.headers['Location']
            parsed = urlparse(location)

            # Check if redirecting to test domain
            if test_domain.lower() in location.lower():
                return True

            # Check for external redirect
            if parsed.netloc and test_domain.lower() in parsed.netloc.lower():
                return True

        # Check meta refresh
        meta_refresh = re.search(
            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\']+)',
            response.text,
            re.IGNORECASE
        )
        if meta_refresh:
            url = meta_refresh.group(1)
            if test_domain.lower() in url.lower():
                return True

        # Check JavaScript redirects
        js_redirect = re.search(
            r'(window\.location|document\.location|location\.href)\s*=\s*["\']([^"\']+)',
            response.text,
            re.IGNORECASE
        )
        if js_redirect:
            url = js_redirect.group(2)
            if test_domain.lower() in url.lower():
                return True

        return False

    def test_parameter(self, url: str, param: str, value: str) -> List[Dict]:
        """Test a single parameter for open redirect"""
        vulnerabilities = []

        test_domain = 'evil-redirect-test.com'

        for payload in self.generate_redirect_payloads(test_domain)[:15]:
            test_resp = self.scanner.smart_request(
                url,
                params={param: payload},
                timeout=10
            )

            if self.check_redirect(test_resp, test_domain):
                evidence = ""
                if 'Location' in test_resp.headers:
                    evidence = f"Location header: {test_resp.headers['Location']}"
                else:
                    evidence = "Redirect detected in HTML/JavaScript"

                vulnerabilities.append({
                    'type': 'Open Redirect',
                    'severity': 'MEDIUM',
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'description': f'Open redirect vulnerability in parameter "{param}"',
                    'evidence': evidence
                })
                break

        return vulnerabilities

    def scan(self) -> List[Dict]:
        """Scan for open redirect vulnerabilities"""
        vulnerabilities = []

        from urllib.parse import parse_qs

        parsed = urlparse(self.scanner.target)
        params = parse_qs(parsed.query)

        if not params:
            # Try common redirect parameters
            test_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'return_url',
                          'goto', 'continue', 'dest', 'destination', 'redir', 'redirect_uri']
            for param in test_params:
                test_url = f"{self.scanner.target}?{param}=/home"
                resp = self.scanner.smart_request(test_url)
                if resp:
                    vulns = self.test_parameter(self.scanner.target, param, '/home')
                    vulnerabilities.extend(vulns)
        else:
            # Test existing parameters
            for param, values in params.items():
                value = values[0] if values else '/home'
                vulns = self.test_parameter(self.scanner.target, param, value)
                vulnerabilities.extend(vulns)

        return vulnerabilities
