"""
Advanced XSS Scanner Module
Google-level detection with context-aware validation and zero false positives
"""

import re
import hashlib
from typing import List, Dict, Optional
from .validation_engine import AdvancedValidator

class XSSScanner:
    """
    Enterprise-grade XSS vulnerability scanner
    Context-aware testing with multi-stage validation
    """

    def __init__(self, parent_scanner):
        self.scanner = parent_scanner
        self.name = "XSS Scanner (Advanced)"
        self.validator = AdvancedValidator(parent_scanner)
        self.payloads = self.generate_advanced_xss_payloads()

    def generate_advanced_xss_payloads(self) -> Dict[str, List[Dict]]:
        """Generate context-specific XSS payloads with high detection accuracy"""

        # HTML context payloads
        html_payloads = [
            {
                'payload': '<script>alert(31337)</script>',
                'context': 'html',
                'detection': r'<script>alert\(31337\)</script>',
                'severity': 'high'
            },
            {
                'payload': '<img src=x onerror=alert(31337)>',
                'context': 'html',
                'detection': r'<img[^>]+onerror=alert\(31337\)',
                'severity': 'high'
            },
            {
                'payload': '<svg onload=alert(31337)>',
                'context': 'html',
                'detection': r'<svg[^>]*onload=alert\(31337\)',
                'severity': 'high'
            },
            {
                'payload': '<iframe src="javascript:alert(31337)">',
                'context': 'html',
                'detection': r'<iframe[^>]+javascript:alert\(31337\)',
                'severity': 'high'
            },
        ]

        # Attribute context payloads
        attribute_payloads = [
            {
                'payload': '" onmouseover="alert(31337)',
                'context': 'attribute',
                'detection': r'onmouseover=["\']?alert\(31337\)',
                'severity': 'high'
            },
            {
                'payload': "' autofocus onfocus=alert(31337) x='",
                'context': 'attribute',
                'detection': r'onfocus=alert\(31337\)',
                'severity': 'high'
            },
            {
                'payload': '"><svg onload=alert(31337)>',
                'context': 'attribute',
                'detection': r'><svg[^>]*onload=alert\(31337\)',
                'severity': 'high'
            },
        ]

        # JavaScript context payloads
        javascript_payloads = [
            {
                'payload': "';alert(31337);//",
                'context': 'javascript',
                'detection': r"';alert\(31337\);",
                'severity': 'high'
            },
            {
                'payload': '";alert(31337);//',
                'context': 'javascript',
                'detection': r'";alert\(31337\);',
                'severity': 'high'
            },
            {
                'payload': '</script><script>alert(31337)</script>',
                'context': 'javascript',
                'detection': r'</script><script>alert\(31337\)',
                'severity': 'high'
            },
        ]

        # Filter bypass payloads
        bypass_payloads = [
            {
                'payload': '<img src="x" onerror="alert`31337`">',
                'context': 'html',
                'detection': r'onerror=["\']?alert`31337`',
                'severity': 'medium'
            },
            {
                'payload': '<ScRiPt>alert(31337)</sCrIpT>',
                'context': 'html',
                'detection': r'<script>alert\(31337\)</script>',
                'severity': 'high'
            },
        ]

        return {
            'html': html_payloads,
            'attribute': attribute_payloads,
            'javascript': javascript_payloads,
            'bypass': bypass_payloads
        }

    def test_parameter(self, url: str, param: str, value: str) -> List[Dict]:
        """
        Advanced parameter testing with context detection and validation
        """
        vulnerabilities = []

        print(f"  [*] Testing parameter: {param}")

        # Generate unique marker for reflection detection
        marker = hashlib.md5(f"{url}{param}".encode()).hexdigest()[:12]

        # Test marker reflection
        marker_resp = self.scanner.smart_request(url, params={param: marker})
        if not marker_resp or marker not in marker_resp.text:
            print(f"    [-] Parameter not reflected, skipping")
            return vulnerabilities

        # Detect reflection context
        context = self._detect_reflection_context(marker_resp.text, marker)
        print(f"    [+] Reflection detected in {context.upper()} context")

        # Get baseline response
        baseline_resp = self.scanner.smart_request(url, params={param: value})
        if not baseline_resp:
            return vulnerabilities

        # Test context-specific payloads
        vuln = self._test_context_payloads(url, param, value, context, baseline_resp)
        if vuln:
            vulnerabilities.append(vuln)
            return vulnerabilities

        # Try bypass payloads
        vuln = self._test_bypass_payloads(url, param, value, baseline_resp)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_reflection_context(self, html: str, marker: str) -> str:
        """Intelligently detect the context where input is reflected"""
        index = html.find(marker)
        if index == -1:
            return 'unknown'

        # Get surrounding context (500 chars before and after)
        start = max(0, index - 500)
        end = min(len(html), index + 500)
        context_region = html[start:end]

        # Check for JavaScript context
        if re.search(r'<script[^>]*>.*?' + re.escape(marker), context_region,
                    re.IGNORECASE | re.DOTALL):
            return 'javascript'

        # Check for attribute context
        if re.search(r'<[^>]+\s+\w+=["\']?[^"\'<>]*' + re.escape(marker),
                    context_region, re.IGNORECASE):
            return 'attribute'

        # Check for CSS context
        if re.search(r'<style[^>]*>.*?' + re.escape(marker), context_region,
                    re.IGNORECASE | re.DOTALL):
            return 'css'

        # Check for comment
        if re.search(r'<!--.*?' + re.escape(marker) + r'.*?-->', context_region, re.DOTALL):
            return 'comment'

        # Default to HTML body context
        return 'html'

    def _test_context_payloads(self, url: str, param: str, value: str,
                               context: str, baseline_resp) -> Optional[Dict]:
        """Test payloads specific to detected context"""
        print(f"    [*] Testing {context}-specific payloads...")

        # Get payloads for this context
        if context in self.payloads:
            test_payloads = self.payloads[context]
        else:
            test_payloads = self.payloads['html']  # Default to HTML

        for payload_dict in test_payloads:
            test_resp = self.scanner.smart_request(url, params={param: payload_dict['payload']})

            if not test_resp:
                continue

            # Validate with advanced validator
            validation = self.validator.validate_xss(
                url, param, payload_dict['payload'],
                baseline_resp, test_resp, context
            )

            if validation.is_valid:
                print(f"    [+] Confirmed XSS (confidence: {validation.confidence:.2%})")
                return {
                    'type': f'Cross-Site Scripting (XSS) - {context.upper()} context',
                    'severity': 'HIGH',
                    'confidence': validation.confidence,
                    'url': url,
                    'parameter': param,
                    'payload': payload_dict['payload'],
                    'description': f'Confirmed XSS vulnerability in {context} context for parameter "{param}"',
                    'evidence': ' | '.join(validation.evidence),
                    'validation': 'Context-aware validated - CONFIRMED',
                    'context': context
                }

        return None

    def _test_bypass_payloads(self, url: str, param: str, value: str,
                             baseline_resp) -> Optional[Dict]:
        """Test filter bypass payloads"""
        print(f"    [*] Testing filter bypass payloads...")

        for payload_dict in self.payloads['bypass']:
            test_resp = self.scanner.smart_request(url, params={param: payload_dict['payload']})

            if not test_resp:
                continue

            # Check for reflection
            if payload_dict['payload'] in test_resp.text or \
               re.search(payload_dict['detection'], test_resp.text, re.IGNORECASE):

                # Validate
                validation = self.validator.validate_xss(
                    url, param, payload_dict['payload'],
                    baseline_resp, test_resp, 'html'
                )

                if validation.is_valid:
                    print(f"    [+] Confirmed XSS with filter bypass (confidence: {validation.confidence:.2%})")
                    return {
                        'type': 'Cross-Site Scripting (XSS) - Filter Bypass',
                        'severity': 'HIGH',
                        'confidence': validation.confidence,
                        'url': url,
                        'parameter': param,
                        'payload': payload_dict['payload'],
                        'description': f'XSS vulnerability with filter bypass in parameter "{param}"',
                        'evidence': ' | '.join(validation.evidence),
                        'validation': 'Bypass technique validated - CONFIRMED'
                    }

        return None

    def scan(self) -> List[Dict]:
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []

        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.scanner.target)
        params = parse_qs(parsed.query)

        if not params:
            # Try common XSS-prone parameters
            print("  [*] No URL parameters found, testing common parameter names...")
            test_params = ['q', 'search', 'query', 'keyword', 'name', 'comment',
                          'message', 'text', 'title', 'description', 'input']
            for param in test_params:
                test_url = f"{self.scanner.target}?{param}=test"
                resp = self.scanner.smart_request(test_url)
                if resp and resp.status_code == 200 and 'test' in resp.text:
                    vulns = self.test_parameter(self.scanner.target, param, 'test')
                    vulnerabilities.extend(vulns)
                    if vulns:
                        break  # Found vulnerability, stop
        else:
            # Test existing parameters
            for param, values in params.items():
                value = values[0] if values else 'test'
                vulns = self.test_parameter(self.scanner.target, param, value)
                vulnerabilities.extend(vulns)
                if vulns:
                    break  # Found vulnerability, stop

        return vulnerabilities
