"""
Header Injection Scanner Module
Tests for HTTP header injection vulnerabilities including CRLF injection
"""

import re
from typing import List, Dict

class HeaderInjectionScanner:
    """Smart Header Injection vulnerability scanner"""

    def __init__(self, parent_scanner):
        self.scanner = parent_scanner
        self.name = "Header Injection Scanner"

    def generate_header_payloads(self) -> List[Dict]:
        """Generate header injection test payloads"""
        payloads = [
            # CRLF injection
            {
                'payload': '%0d%0aX-Injected-Header: test',
                'type': 'CRLF Injection (URL encoded)',
                'detection': 'X-Injected-Header'
            },
            {
                'payload': '\r\nX-Injected-Header: test',
                'type': 'CRLF Injection',
                'detection': 'X-Injected-Header'
            },
            {
                'payload': '%0aX-Injected-Header: test',
                'type': 'LF Injection',
                'detection': 'X-Injected-Header'
            },

            # Response splitting
            {
                'payload': '%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>Injected</html>',
                'type': 'HTTP Response Splitting',
                'detection': 'Injected'
            },

            # Cookie injection
            {
                'payload': '%0d%0aSet-Cookie: admin=true',
                'type': 'Cookie Injection',
                'detection': 'Set-Cookie'
            },

            # Header concatenation
            {
                'payload': '\nX-Test: injected',
                'type': 'Header Concatenation',
                'detection': 'X-Test'
            },
        ]

        return payloads

    def check_header_injection(self, response, payload_dict: Dict) -> bool:
        """Check if header injection was successful"""
        if not response:
            return False

        detection = payload_dict['detection']

        # Check in response headers
        for header, value in response.headers.items():
            if detection.lower() in header.lower() or detection.lower() in value.lower():
                return True

        # Check in response body for response splitting
        if detection.lower() in response.text.lower():
            return True

        return False

    def test_parameter(self, url: str, param: str, value: str) -> List[Dict]:
        """Test a single parameter for header injection"""
        vulnerabilities = []

        for payload_dict in self.generate_header_payloads():
            test_resp = self.scanner.smart_request(
                url,
                params={param: payload_dict['payload']},
                timeout=10
            )

            if self.check_header_injection(test_resp, payload_dict):
                vulnerabilities.append({
                    'type': f'Header Injection - {payload_dict["type"]}',
                    'severity': 'HIGH',
                    'url': url,
                    'parameter': param,
                    'payload': payload_dict['payload'],
                    'description': f'Header injection vulnerability ({payload_dict["type"]}) in parameter "{param}"',
                    'evidence': f'Injected header detected: {payload_dict["detection"]}'
                })
                break

        return vulnerabilities

    def scan(self) -> List[Dict]:
        """Scan for header injection vulnerabilities"""
        vulnerabilities = []

        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.scanner.target)
        params = parse_qs(parsed.query)

        if params:
            # Test existing parameters
            for param, values in params.items():
                value = values[0] if values else 'test'
                vulns = self.test_parameter(self.scanner.target, param, value)
                vulnerabilities.extend(vulns)

        return vulnerabilities
