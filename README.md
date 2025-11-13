# Smart Vulnerability Scanner

A comprehensive, intelligent vulnerability scanner designed for **authorized security testing only**. This tool is specifically built for bug bounty hunters and penetration testers working with proper authorization.

## ⚠️ LEGAL WARNING

**THIS TOOL IS FOR AUTHORIZED USE ONLY**

Only use this tool on systems where you have:
- Written permission from the system owner
- Active participation in a bug bounty program
- A signed penetration testing agreement
- Explicit authorization to conduct security testing

**Unauthorized scanning is illegal and may result in criminal prosecution.**

## 🎯 Features

### Comprehensive Vulnerability Detection

1. **SQL Injection (SQLi)**
   - Error-based detection
   - Time-based blind SQLi
   - Boolean-based blind SQLi
   - Intelligent payload selection from database-specific payloads
   - Support for MySQL, PostgreSQL, MSSQL, Oracle

2. **Cross-Site Scripting (XSS)**
   - Reflected XSS detection
   - Context-aware testing (HTML, JavaScript, attribute contexts)
   - Polyglot payload support
   - Filter bypass techniques
   - DOM-based XSS detection

3. **Server-Side Request Forgery (SSRF)**
   - Cloud metadata endpoint testing (AWS, GCP, Azure)
   - Internal network probing
   - Protocol bypass detection (file://, gopher://)
   - Internal service discovery

4. **Open Redirect**
   - URL redirect detection
   - Meta refresh detection
   - JavaScript redirect detection
   - Multiple encoding bypass techniques

5. **Header Injection**
   - CRLF injection detection
   - HTTP response splitting
   - Cookie injection
   - Header concatenation attacks

6. **Information Disclosure**
   - Sensitive data pattern detection (API keys, tokens, credentials)
   - Stack trace exposure
   - Database error disclosure
   - Sensitive file discovery (.git, .env, config files)
   - Security header analysis

## 📋 Requirements

- Python 3.7+
- Required packages (see requirements.txt)

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/payloads-sqli.git
cd payloads-sqli

# Install dependencies
pip3 install -r requirements.txt

# Make scanner executable
chmod +x scanner.py
```

## 📖 Usage

### Basic Usage

```bash
python3 scanner.py --target https://example.com --scope bug-bounty
```

### Advanced Options

```bash
# Specify number of threads
python3 scanner.py --target https://example.com --scope bug-bounty --threads 10

# Set custom timeout
python3 scanner.py --target https://example.com --scope pentest --timeout 15

# Enable aggressive scanning (more payloads)
python3 scanner.py --target https://example.com --scope owned-system --aggressive
```

### Command Line Options

- `--target URL` - Target URL to scan (required)
- `--scope {bug-bounty,pentest,owned-system}` - Authorization scope (required)
- `--threads N` - Number of concurrent threads (default: 5)
- `--timeout N` - Request timeout in seconds (default: 10)
- `--aggressive` - Enable aggressive scanning mode

## 🎯 Bug Bounty Programs

This tool is designed to work with major bug bounty platforms:

### Recommended Programs

- **Google Vulnerability Reward Program (VRP)**
  - https://bughunters.google.com/
  - In-scope: Most Google services
  - Rewards: Up to $31,337

- **Apple Security Bounty**
  - https://security.apple.com/bounty/
  - In-scope: iOS, macOS, iCloud, Safari
  - Rewards: Up to $1,000,000

- **Microsoft Bug Bounty**
  - https://www.microsoft.com/en-us/msrc/bounty
  - In-scope: Azure, Office 365, Edge
  - Rewards: Varies by product

- **HackerOne Platform**
  - https://hackerone.com/
  - Thousands of programs
  - Various reward structures

- **Bugcrowd Platform**
  - https://www.bugcrowd.com/
  - Hundreds of programs
  - Competitive rewards

## 📊 Output and Reporting

### Terminal Output

The scanner provides color-coded real-time output:
- 🔴 **RED** - Critical/High severity findings
- 🟡 **YELLOW** - Medium/Low severity findings
- 🔵 **CYAN** - Informational findings
- 🟢 **GREEN** - Success messages

### JSON Report

Detailed reports are automatically saved as:
```
scan_report_YYYYMMDD_HHMMSS.json
```

Report includes:
- All discovered vulnerabilities
- Severity ratings
- Evidence and payloads
- Affected URLs and parameters
- Scan metadata

## 🔧 Architecture

```
payloads-sqli/
├── scanner.py              # Main scanner engine
├── modules/                # Vulnerability detection modules
│   ├── __init__.py
│   ├── sql_injection.py    # SQLi detection
│   ├── xss_scanner.py      # XSS detection
│   ├── ssrf_scanner.py     # SSRF detection
│   ├── open_redirect.py    # Open redirect detection
│   ├── header_injection.py # Header injection detection
│   └── info_disclosure.py  # Information disclosure
├── payloads/               # Payload databases
│   ├── generic.txt
│   ├── mysql.txt
│   ├── postgresql.txt
│   ├── mssql.txt
│   └── oracle.txt
└── requirements.txt
```

## 🛡️ Ethical Usage Guidelines

### Before Scanning

1. ✅ **Verify Authorization**
   - Ensure you have written permission
   - Review program scope and rules
   - Check for excluded domains/IPs

2. ✅ **Understand the Scope**
   - Read bug bounty program policies
   - Note out-of-scope targets
   - Understand prohibited testing methods

3. ✅ **Configure Appropriately**
   - Use reasonable thread counts
   - Set appropriate timeouts
   - Avoid aggressive scanning on production systems

### During Scanning

- Monitor your testing impact
- Stop if you detect service degradation
- Respect rate limits
- Keep detailed notes

### After Scanning

- Report findings responsibly
- Follow disclosure timelines
- Don't exploit vulnerabilities
- Provide clear reproduction steps

## 🔍 Example Workflow

```bash
# 1. Identify target from bug bounty program
TARGET="https://example.com"

# 2. Verify authorization
# Read program scope at hackerone.com/example

# 3. Run initial scan
python3 scanner.py --target $TARGET --scope bug-bounty

# 4. Review findings in JSON report
cat scan_report_*.json

# 5. Verify vulnerabilities manually
# Test each finding to confirm

# 6. Submit report to bug bounty platform
# Include evidence from scanner + manual verification
```

## 📝 Sample Output

```
======================================================================
         Smart Vulnerability Scanner v1.0
         For Authorized Security Testing Only
======================================================================
Target: https://example.com
Scope: bug-bounty

AUTHORIZATION CHECK
Do you have WRITTEN AUTHORIZATION to test https://example.com?
Type 'YES I AM AUTHORIZED' to continue: YES I AM AUTHORIZED

[+] Starting vulnerability scan...

[*] Running Information Disclosure Scanner...
[+] Found 3 potential issues

[*] Running SQL Injection Scanner...
[+] Found 1 potential issues

[*] Running XSS Scanner...
[+] Found 2 potential issues

======================================================================
                    SCAN RESULTS
======================================================================
Critical: 0
High: 3
Medium: 2
Low: 1
Info: 0

[HIGH] SQL Injection (Error-based)
  URL: https://example.com?id=1
  Description: SQL error detected in parameter "id"
  Payload: ' OR '1'='1
  Evidence: MySQL syntax error near '1'='1'

[+] Report saved to scan_report_20250113_142530.json
```

## 🤝 Contributing

Contributions are welcome! Please ensure any additions:
- Follow ethical security testing principles
- Include clear documentation
- Add appropriate test cases
- Don't include malicious code

## ⚖️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by this tool. Users are solely responsible for ensuring they have proper authorization before conducting any security testing.

**USE AT YOUR OWN RISK**

## 📚 Resources

### Learning Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacker101](https://www.hacker101.com/)

### Bug Bounty Platforms
- [HackerOne](https://hackerone.com/)
- [Bugcrowd](https://bugcrowd.com/)
- [Intigriti](https://www.intigriti.com/)
- [YesWeHack](https://www.yeswehack.com/)

### Tools and Resources
- [OWASP ZAP](https://www.zaproxy.org/)
- [Burp Suite](https://portswigger.net/burp)
- [Nuclei](https://github.com/projectdiscovery/nuclei)

## 📄 License

MIT License - See LICENSE file for details

## ✨ Author

Created for ethical security testing and bug bounty hunting.

---

**Remember: Always get authorization before testing!** 🔒
