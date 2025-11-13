"""
Advanced Validation Engine
Zero False Positive Verification Framework
"""

import re
import time
import hashlib
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class ValidationResult:
    """Validation result with confidence scoring"""
    is_valid: bool
    confidence: float  # 0.0 to 1.0
    evidence: List[str]
    false_positive_reasons: List[str]

class AdvancedValidator:
    """
    Google-level validation engine with zero false positives
    Uses multi-stage verification and differential analysis
    """

    def __init__(self, scanner):
        self.scanner = scanner
        self.min_confidence = 0.95  # 95% confidence required

    def validate_sqli(self, url: str, param: str, payload: str,
                     baseline_resp, test_resp, detection_type: str) -> ValidationResult:
        """
        Advanced SQL injection validation with multiple verification stages
        """
        evidence = []
        false_positive_reasons = []
        confidence = 0.0

        if not test_resp or not baseline_resp:
            return ValidationResult(False, 0.0, [], ["No response received"])

        # Stage 1: Error-based validation
        if detection_type == "error":
            error_confidence = self._validate_sql_error(test_resp.text, baseline_resp.text)
            if error_confidence < 0.8:
                false_positive_reasons.append("SQL error patterns not specific enough")
                return ValidationResult(False, error_confidence, evidence, false_positive_reasons)

            # Verify error is injection-induced, not application error
            if self._is_application_error(test_resp.text):
                false_positive_reasons.append("Detected error is application-level, not SQL")
                return ValidationResult(False, 0.0, evidence, false_positive_reasons)

            evidence.append(f"Specific SQL error pattern detected")
            confidence = error_confidence

        # Stage 2: Time-based validation (requires multiple confirmations)
        elif detection_type == "time":
            time_confidence = self._validate_time_based(
                url, param, payload, baseline_resp
            )
            if time_confidence < 0.95:
                false_positive_reasons.append("Time delay not consistent or too variable")
                return ValidationResult(False, time_confidence, evidence, false_positive_reasons)

            evidence.append("Consistent time delay confirmed across multiple requests")
            confidence = time_confidence

        # Stage 3: Boolean-based validation (differential analysis)
        elif detection_type == "boolean":
            boolean_confidence = self._validate_boolean_based(
                url, param, baseline_resp
            )
            if boolean_confidence < 0.9:
                false_positive_reasons.append("Response differences not consistent with boolean SQLi")
                return ValidationResult(False, boolean_confidence, evidence, false_positive_reasons)

            evidence.append("Boolean condition differential confirmed")
            confidence = boolean_confidence

        # Stage 4: Cross-verification
        # Test if WAF/IDS is just blocking vs actual vulnerability
        if self._is_waf_blocking(test_resp):
            false_positive_reasons.append("WAF blocking detected, not confirmed vulnerability")
            return ValidationResult(False, 0.0, evidence, false_positive_reasons)

        # Stage 5: Payload reflection check (not actual SQLi)
        if payload in test_resp.text and len(test_resp.text) > 1000:
            # Payload reflected in large response, might be false positive
            if not self._has_sql_execution_evidence(test_resp.text):
                false_positive_reasons.append("Payload reflected but no SQL execution evidence")
                confidence *= 0.7

        is_valid = confidence >= self.min_confidence
        return ValidationResult(is_valid, confidence, evidence, false_positive_reasons)

    def _validate_sql_error(self, test_text: str, baseline_text: str) -> float:
        """Validate SQL error with high specificity"""
        # High-confidence SQL error patterns (very specific)
        high_confidence_patterns = [
            (r"You have an error in your SQL syntax.*check the manual that corresponds to your (MySQL|MariaDB) server version", 0.98),
            (r"pg_query\(\).*ERROR:.*syntax error at or near", 0.98),
            (r"Microsoft SQL Server.*Incorrect syntax near", 0.98),
            (r"ORA-\d{5}:.*SQL command not properly ended", 0.98),
            (r"SQLite3::SQLException", 0.95),
            (r"org\.postgresql\.util\.PSQLException.*ERROR:", 0.95),
            (r"com\.mysql\.jdbc\.exceptions\.jdbc4\.MySQLSyntaxErrorException", 0.95),
        ]

        # Medium confidence patterns (need additional verification)
        medium_confidence_patterns = [
            (r"SQL syntax.*error", 0.7),
            (r"mysql_fetch", 0.6),
            (r"Warning.*pg_", 0.6),
        ]

        max_confidence = 0.0

        # Check if error appears in test but not baseline
        for pattern, confidence in high_confidence_patterns:
            if re.search(pattern, test_text, re.IGNORECASE) and \
               not re.search(pattern, baseline_text, re.IGNORECASE):
                max_confidence = max(max_confidence, confidence)

        # Medium patterns need higher threshold
        if max_confidence < 0.9:
            for pattern, confidence in medium_confidence_patterns:
                if re.search(pattern, test_text, re.IGNORECASE) and \
                   not re.search(pattern, baseline_text, re.IGNORECASE):
                    max_confidence = max(max_confidence, confidence)

        return max_confidence

    def _validate_time_based(self, url: str, param: str, payload: str,
                            baseline_resp) -> float:
        """
        Validate time-based SQLi with multiple confirmations
        Requires consistent delays to eliminate network jitter false positives
        """
        baseline_time = baseline_resp.elapsed.total_seconds()
        expected_delay = 5  # seconds

        # Test 3 times to confirm consistency
        delays = []
        for i in range(3):
            resp = self.scanner.smart_request(url, params={param: payload})
            if not resp:
                return 0.0

            actual_delay = resp.elapsed.total_seconds() - baseline_time
            delays.append(actual_delay)
            time.sleep(1)  # Brief pause between tests

        # Check if delays are consistent
        avg_delay = sum(delays) / len(delays)
        std_dev = (sum((x - avg_delay) ** 2 for x in delays) / len(delays)) ** 0.5

        # High variance = network issues, not SQLi
        if std_dev > 1.5:
            return 0.0

        # Check if average delay matches expected
        if avg_delay < expected_delay - 1 or avg_delay > expected_delay + 2:
            return 0.0

        # Confidence based on consistency
        confidence = 1.0 - (std_dev / expected_delay)
        return min(confidence, 0.98)

    def _validate_boolean_based(self, url: str, param: str, baseline_resp) -> float:
        """
        Validate boolean-based blind SQLi with differential analysis
        """
        # True condition
        true_payload = "1' AND '1'='1"
        true_resp = self.scanner.smart_request(url, params={param: true_payload})

        # False condition
        false_payload = "1' AND '1'='2"
        false_resp = self.scanner.smart_request(url, params={param: false_payload})

        if not true_resp or not false_resp:
            return 0.0

        # Responses should be significantly different
        true_len = len(true_resp.text)
        false_len = len(false_resp.text)
        baseline_len = len(baseline_resp.text)

        # True should match baseline, false should differ
        true_diff = abs(true_len - baseline_len)
        false_diff = abs(false_len - baseline_len)

        # True condition should be similar to baseline
        if true_diff > baseline_len * 0.1:  # More than 10% difference
            return 0.0

        # False condition should differ significantly
        if false_diff < baseline_len * 0.05:  # Less than 5% difference
            return 0.0

        # Test again to confirm consistency
        true_resp2 = self.scanner.smart_request(url, params={param: true_payload})
        false_resp2 = self.scanner.smart_request(url, params={param: false_payload})

        if not true_resp2 or not false_resp2:
            return 0.85

        # Check consistency
        true_consistent = abs(len(true_resp2.text) - true_len) < true_len * 0.05
        false_consistent = abs(len(false_resp2.text) - false_len) < false_len * 0.05

        if true_consistent and false_consistent:
            return 0.95

        return 0.75

    def _is_application_error(self, text: str) -> bool:
        """Check if error is application-level, not SQL"""
        app_error_patterns = [
            r"404 Not Found",
            r"500 Internal Server Error",
            r"403 Forbidden",
            r"Bad Request",
            r"Invalid Request",
            r"Exception.*NullPointerException",
            r"Exception.*RuntimeException",
        ]

        for pattern in app_error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _is_waf_blocking(self, resp) -> bool:
        """Detect WAF/IDS blocking"""
        if not resp:
            return True

        # Common WAF signatures
        waf_signatures = [
            ("X-CDN", "cloudflare"),
            ("Server", "cloudflare"),
            ("Server", "AkamaiGHost"),
            ("X-Sucuri-ID", ""),
            ("X-Security", ""),
        ]

        for header, value in waf_signatures:
            if header in resp.headers:
                if not value or value.lower() in resp.headers[header].lower():
                    return True

        # WAF block pages
        waf_content = [
            "access denied",
            "blocked by",
            "security policy",
            "request blocked",
            "cloudflare",
        ]

        text_lower = resp.text.lower()
        for signature in waf_content:
            if signature in text_lower and resp.status_code in [403, 406, 419]:
                return True

        return False

    def _has_sql_execution_evidence(self, text: str) -> bool:
        """Check for evidence of SQL execution beyond just reflection"""
        # Look for database-specific output
        sql_execution_evidence = [
            r"Query result",
            r"SELECT \* FROM",
            r"Database error",
            r"Table '.*' doesn't exist",
            r"Column '.*' not found",
        ]

        for pattern in sql_execution_evidence:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def validate_xss(self, url: str, param: str, payload: str,
                    baseline_resp, test_resp, context: str) -> ValidationResult:
        """
        Advanced XSS validation with context verification and execution confirmation
        """
        evidence = []
        false_positive_reasons = []

        if not test_resp or not baseline_resp:
            return ValidationResult(False, 0.0, [], ["No response received"])

        # Stage 1: Check if payload is actually reflected
        if payload not in test_resp.text:
            false_positive_reasons.append("Payload not reflected in response")
            return ValidationResult(False, 0.0, evidence, false_positive_reasons)

        # Stage 2: Validate context-specific execution
        context_confidence = self._validate_xss_context(test_resp.text, payload, context)
        if context_confidence < 0.8:
            false_positive_reasons.append("Payload reflected but not in executable context")
            return ValidationResult(False, context_confidence, evidence, false_positive_reasons)

        evidence.append(f"Payload in executable {context} context")

        # Stage 3: Check for encoding/sanitization
        if self._is_xss_encoded(test_resp.text, payload):
            false_positive_reasons.append("Payload is HTML-encoded or sanitized")
            return ValidationResult(False, 0.0, evidence, false_positive_reasons)

        # Stage 4: Verify it's not just reflected in comments/attributes
        if self._is_xss_in_safe_context(test_resp.text, payload):
            false_positive_reasons.append("Payload in non-executable context (comment, etc)")
            return ValidationResult(False, 0.0, evidence, false_positive_reasons)

        # Stage 5: Check CSP headers (might prevent execution)
        csp_blocks = self._check_csp_blocking(test_resp, payload)
        if csp_blocks:
            evidence.append("WARNING: CSP may prevent execution in browser")
            context_confidence *= 0.8

        confidence = context_confidence
        is_valid = confidence >= self.min_confidence

        return ValidationResult(is_valid, confidence, evidence, false_positive_reasons)

    def _validate_xss_context(self, html: str, payload: str, context: str) -> float:
        """Validate XSS payload is in executable context"""
        # Find payload location
        index = html.find(payload)
        if index == -1:
            return 0.0

        # Get surrounding context
        start = max(0, index - 200)
        end = min(len(html), index + len(payload) + 200)
        surrounding = html[start:end]

        # Check based on context type
        if context == "html":
            # Should not be inside <!-- --> comments
            if re.search(r'<!--.*' + re.escape(payload) + r'.*-->', surrounding, re.DOTALL):
                return 0.0

            # Check if in script tag
            if '<script' in surrounding.lower() and '</script>' in surrounding.lower():
                return 0.98

            # Check if in event handler
            if re.search(r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload), surrounding, re.IGNORECASE):
                return 0.95

            return 0.85

        elif context == "attribute":
            # Check if inside attribute value
            if re.search(r'\w+\s*=\s*["\']?[^"\']*' + re.escape(payload), surrounding):
                # Check if it breaks out
                if '"' in payload or "'" in payload:
                    return 0.95
                return 0.7
            return 0.5

        elif context == "javascript":
            # Inside <script> tags
            if '<script' in html[:index].lower() and '</script>' in html[index:].lower():
                return 0.95
            return 0.6

        return 0.5

    def _is_xss_encoded(self, html: str, payload: str) -> bool:
        """Check if XSS payload is HTML encoded"""
        # Check for common encodings
        encoded_versions = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '&#60;').replace('>', '&#62;'),
            payload.replace('"', '&quot;').replace("'", '&#39;'),
        ]

        for encoded in encoded_versions:
            if encoded in html:
                return True
        return False

    def _is_xss_in_safe_context(self, html: str, payload: str) -> bool:
        """Check if XSS is in a safe non-executable context"""
        index = html.find(payload)
        if index == -1:
            return True

        # Get context
        before = html[max(0, index-50):index]
        after = html[index:min(len(html), index+len(payload)+50)]

        # Inside HTML comments
        if '<!--' in before and '-->' in after:
            return True

        # Inside <textarea>
        if '<textarea' in before.lower() and '</textarea>' in after.lower():
            return True

        # Inside certain safe attributes
        safe_attrs = ['data-', 'aria-']
        for attr in safe_attrs:
            if attr in before.lower():
                return True

        return False

    def _check_csp_blocking(self, resp, payload: str) -> bool:
        """Check if CSP would block the XSS"""
        if 'Content-Security-Policy' not in resp.headers:
            return False

        csp = resp.headers['Content-Security-Policy'].lower()

        # Check if inline scripts are blocked
        if "'unsafe-inline'" not in csp:
            if 'script' in payload.lower() or 'on' in payload.lower():
                # Inline execution would be blocked
                return True

        return False

    def validate_ssrf(self, url: str, param: str, payload: str,
                     test_resp, payload_type: str) -> ValidationResult:
        """
        Advanced SSRF validation with deep response analysis
        """
        evidence = []
        false_positive_reasons = []

        if not test_resp:
            return ValidationResult(False, 0.0, [], ["No response received"])

        # Stage 1: Check for specific metadata/internal content
        confidence = self._analyze_ssrf_response(test_resp, payload_type)

        if confidence < 0.8:
            false_positive_reasons.append("Response doesn't contain expected internal data")
            return ValidationResult(False, confidence, evidence, false_positive_reasons)

        # Stage 2: Verify it's not just reflected URL
        if payload in test_resp.text and len(test_resp.text) < 500:
            false_positive_reasons.append("Payload just reflected, no actual SSRF")
            return ValidationResult(False, 0.0, evidence, false_positive_reasons)

        # Stage 3: Multiple payload verification for cloud metadata
        if 'metadata' in payload_type.lower():
            multi_confidence = self._verify_cloud_metadata(url, param, payload_type)
            if multi_confidence < 0.9:
                false_positive_reasons.append("Cloud metadata not consistently accessible")
                return ValidationResult(False, multi_confidence, evidence, false_positive_reasons)
            confidence = multi_confidence

        evidence.append(f"Confirmed {payload_type} access via SSRF")
        is_valid = confidence >= self.min_confidence

        return ValidationResult(is_valid, confidence, evidence, false_positive_reasons)

    def _analyze_ssrf_response(self, resp, payload_type: str) -> float:
        """Analyze response for SSRF evidence"""
        text = resp.text.lower()

        if 'aws metadata' in payload_type.lower():
            # Very specific AWS metadata indicators
            if 'ami-id' in text or 'instance-id' in text:
                return 0.99
            if 'iam/security-credentials' in text:
                return 0.99
            return 0.0

        elif 'gcp metadata' in payload_type.lower():
            if 'computemetadata' in text or 'numeric_project_id' in text:
                return 0.99
            return 0.0

        elif 'azure metadata' in payload_type.lower():
            if 'subscriptionid' in text or 'vmid' in text:
                return 0.99
            return 0.0

        elif 'localhost' in payload_type.lower():
            # Check for internal service responses
            if any(s in text for s in ['apache', 'nginx', 'iis', 'index of']):
                return 0.85
            return 0.3

        return 0.5

    def _verify_cloud_metadata(self, url: str, param: str, payload_type: str) -> float:
        """Multi-stage cloud metadata verification"""
        # Try to fetch specific metadata endpoints
        test_payloads = []

        if 'aws' in payload_type.lower():
            test_payloads = [
                'http://169.254.169.254/latest/meta-data/ami-id',
                'http://169.254.169.254/latest/meta-data/instance-id',
            ]
        elif 'gcp' in payload_type.lower():
            test_payloads = [
                'http://metadata.google.internal/computeMetadata/v1/instance/id',
            ]

        success_count = 0
        for test_payload in test_payloads:
            resp = self.scanner.smart_request(url, params={param: test_payload})
            if resp and len(resp.text) > 5 and len(resp.text) < 200:
                # Metadata responses are typically short
                if not '<html' in resp.text.lower():
                    success_count += 1

        if success_count >= 2:
            return 0.98
        elif success_count == 1:
            return 0.85

        return 0.0
