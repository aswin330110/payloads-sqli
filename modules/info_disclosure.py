"""
Information Disclosure Scanner Module
Tests for sensitive information leakage
"""

import re
from typing import List, Dict

class InfoDisclosureScanner:
    """Smart Information Disclosure vulnerability scanner"""

    def __init__(self, parent_scanner):
        self.scanner = parent_scanner
        self.name = "Information Disclosure Scanner"

    def get_sensitive_patterns(self) -> List[Dict]:
        """Define patterns for sensitive information"""
        patterns = [
            {
                'name': 'AWS Access Key',
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': 'CRITICAL'
            },
            {
                'name': 'AWS Secret Key',
                'pattern': r'aws_secret_access_key\s*=\s*[\'\"]?([a-zA-Z0-9/+=]{40})[\'\"]?',
                'severity': 'CRITICAL'
            },
            {
                'name': 'Google API Key',
                'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
                'severity': 'HIGH'
            },
            {
                'name': 'Google OAuth Token',
                'pattern': r'ya29\.[0-9A-Za-z\-_]+',
                'severity': 'HIGH'
            },
            {
                'name': 'GitHub Token',
                'pattern': r'ghp_[0-9a-zA-Z]{36}',
                'severity': 'CRITICAL'
            },
            {
                'name': 'Private Key',
                'pattern': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
                'severity': 'CRITICAL'
            },
            {
                'name': 'Email Address',
                'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                'severity': 'LOW'
            },
            {
                'name': 'Internal IP Address',
                'pattern': r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
                'severity': 'MEDIUM'
            },
            {
                'name': 'JWT Token',
                'pattern': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
                'severity': 'HIGH'
            },
            {
                'name': 'Database Connection String',
                'pattern': r'(mongodb|mysql|postgres|mssql)://[^\s]+',
                'severity': 'HIGH'
            },
            {
                'name': 'Password in Code',
                'pattern': r'(password|passwd|pwd)\s*[:=]\s*[\'"]([^\'"]{3,})[\'"]',
                'severity': 'HIGH'
            },
        ]

        return patterns

    def check_error_disclosure(self, response) -> List[Dict]:
        """Check for error message disclosure"""
        if not response:
            return []

        vulnerabilities = []

        error_patterns = [
            {
                'name': 'Stack Trace',
                'patterns': [
                    r'at\s+[\w\.$]+\([\w\.]+:\d+\)',  # Java/JavaScript
                    r'File\s+"[^"]+",\s+line\s+\d+',  # Python
                    r'in\s+[/\w]+\.php\s+on\s+line\s+\d+',  # PHP
                ],
                'severity': 'MEDIUM'
            },
            {
                'name': 'Database Error',
                'patterns': [
                    r'(SQL|MySQL|PostgreSQL|Oracle|MSSQL)\s+(syntax|error)',
                    r'mysqli?_',
                    r'pg_query',
                ],
                'severity': 'MEDIUM'
            },
            {
                'name': 'Framework Debug Info',
                'patterns': [
                    r'(Laravel|Django|Rails|Express)\s+(Error|Debug)',
                    r'DEBUG\s*=\s*True',
                    r'Whoops,?\s+looks\s+like\s+something\s+went\s+wrong',
                ],
                'severity': 'MEDIUM'
            },
        ]

        for error_type in error_patterns:
            for pattern in error_type['patterns']:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    vulnerabilities.append({
                        'type': f'Information Disclosure - {error_type["name"]}',
                        'severity': error_type['severity'],
                        'url': response.url,
                        'description': f'{error_type["name"]} exposed in response',
                        'evidence': str(matches[0])[:200]
                    })
                    break

        return vulnerabilities

    def check_sensitive_files(self) -> List[Dict]:
        """Check for common sensitive files"""
        vulnerabilities = []

        sensitive_paths = [
            ('.git/config', 'Git Configuration', 'MEDIUM'),
            ('.env', 'Environment Variables', 'HIGH'),
            ('config.php', 'PHP Configuration', 'MEDIUM'),
            ('web.config', 'IIS Configuration', 'MEDIUM'),
            ('.htaccess', 'Apache Configuration', 'LOW'),
            ('phpinfo.php', 'PHP Info Page', 'MEDIUM'),
            ('server-status', 'Apache Server Status', 'LOW'),
            ('admin', 'Admin Panel', 'INFO'),
            ('backup.sql', 'SQL Backup', 'HIGH'),
            ('database.sql', 'Database Backup', 'HIGH'),
            ('.DS_Store', 'macOS Metadata', 'LOW'),
        ]

        base_url = self.scanner.target.rstrip('/')

        for path, name, severity in sensitive_paths:
            url = f"{base_url}/{path}"
            resp = self.scanner.smart_request(url, timeout=5)

            if resp and resp.status_code == 200 and len(resp.text) > 0:
                # Additional validation
                if path == '.git/config' and '[core]' not in resp.text:
                    continue
                if path == 'phpinfo.php' and 'phpinfo()' not in resp.text.lower():
                    continue

                vulnerabilities.append({
                    'type': f'Information Disclosure - {name}',
                    'severity': severity,
                    'url': url,
                    'description': f'Sensitive file "{path}" is publicly accessible',
                    'evidence': resp.text[:200]
                })

        return vulnerabilities

    def check_security_headers(self) -> List[Dict]:
        """Check for missing security headers"""
        vulnerabilities = []

        resp = self.scanner.smart_request(self.scanner.target)
        if not resp:
            return vulnerabilities

        security_headers = [
            ('X-Frame-Options', 'Clickjacking protection missing', 'LOW'),
            ('X-Content-Type-Options', 'MIME-sniffing protection missing', 'LOW'),
            ('Strict-Transport-Security', 'HSTS not enforced', 'MEDIUM'),
            ('Content-Security-Policy', 'CSP not implemented', 'MEDIUM'),
            ('X-XSS-Protection', 'XSS protection header missing', 'LOW'),
        ]

        for header, description, severity in security_headers:
            if header not in resp.headers:
                vulnerabilities.append({
                    'type': 'Information Disclosure - Missing Security Header',
                    'severity': severity,
                    'url': self.scanner.target,
                    'description': description,
                    'evidence': f'Missing header: {header}'
                })

        return vulnerabilities

    def scan(self) -> List[Dict]:
        """Scan for information disclosure vulnerabilities"""
        vulnerabilities = []

        # Check main page
        resp = self.scanner.smart_request(self.scanner.target)
        if resp:
            # Check for sensitive data patterns
            for pattern_dict in self.get_sensitive_patterns():
                matches = re.findall(pattern_dict['pattern'], resp.text)
                if matches:
                    vulnerabilities.append({
                        'type': f'Information Disclosure - {pattern_dict["name"]}',
                        'severity': pattern_dict['severity'],
                        'url': self.scanner.target,
                        'description': f'{pattern_dict["name"]} found in response',
                        'evidence': str(matches[0])[:100]
                    })

            # Check error disclosure
            error_vulns = self.check_error_disclosure(resp)
            vulnerabilities.extend(error_vulns)

        # Check sensitive files
        file_vulns = self.check_sensitive_files()
        vulnerabilities.extend(file_vulns)

        # Check security headers
        header_vulns = self.check_security_headers()
        vulnerabilities.extend(header_vulns)

        return vulnerabilities
