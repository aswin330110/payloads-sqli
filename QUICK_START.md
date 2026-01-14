# Quick Start Guide - Smart Vulnerability Scanner

## 🚀 Get Started in 5 Minutes

### Step 1: Install Dependencies

```bash
pip3 install -r requirements.txt
```

### Step 2: Verify Installation

```bash
python3 scanner.py --help
```

### Step 3: Choose Your Target

**⚠️ CRITICAL: Only test targets where you have authorization!**

#### Option A: Bug Bounty Program
1. Visit a bug bounty platform (HackerOne, Bugcrowd, etc.)
2. Choose a program you want to participate in
3. Read the program rules and scope carefully
4. Note the in-scope domains

#### Option B: Your Own System
- Use a test environment you control
- Set up a vulnerable app like DVWA or WebGoat

### Step 4: Run Your First Scan

```bash
# Example: Scanning a bug bounty target
python3 scanner.py --target https://example.com --scope bug-bounty

# Example: Scanning your own test system
python3 scanner.py --target http://localhost:8080 --scope owned-system
```

### Step 5: Review Results

The scanner will:
1. Ask you to confirm authorization (type `YES I AM AUTHORIZED`)
2. Run all vulnerability checks
3. Display findings in real-time
4. Save a detailed JSON report

```bash
# View the JSON report
cat scan_report_*.json
```

## 🎯 Common Use Cases

### Bug Bounty Hunting

```bash
# Start with a specific target from a program
TARGET="https://subdomain.example.com"
python3 scanner.py --target $TARGET --scope bug-bounty --threads 5

# Review findings
cat scan_report_*.json | grep -A 5 "HIGH"

# Manually verify each finding
# Submit valid findings to the bug bounty platform
```

### Penetration Testing

```bash
# With authorization document
python3 scanner.py --target https://client-site.com --scope pentest --aggressive

# Generate report for client
cat scan_report_*.json
```

### Learning and Practice

```bash
# Set up DVWA (Damn Vulnerable Web Application)
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Scan it
python3 scanner.py --target http://localhost --scope owned-system --aggressive
```

## 📊 Understanding Results

### Severity Levels

- **CRITICAL** 🔴 - Immediate attention required (e.g., credential exposure, cloud metadata access)
- **HIGH** 🔴 - Severe vulnerability (e.g., SQL injection, XSS, SSRF)
- **MEDIUM** 🟡 - Notable security issue (e.g., open redirect, missing headers)
- **LOW** 🟡 - Minor security concern
- **INFO** 🔵 - Informational finding

### What to Report

✅ **DO Report:**
- Findings with clear security impact
- Reproducible vulnerabilities
- Issues within program scope
- Findings with proof-of-concept

❌ **DON'T Report:**
- False positives (verify first!)
- Out-of-scope findings
- Known issues
- Low-quality duplicate reports

## 🔍 Example Workflow

### Complete Bug Bounty Workflow

```bash
# 1. Research target company
COMPANY="Example Corp"
PROGRAM="https://hackerone.com/example"

# 2. Read program scope
# - In scope: *.example.com
# - Out of scope: status.example.com
# - Rewards: $100 - $10,000

# 3. Subdomain enumeration (use other tools)
# Find: api.example.com, admin.example.com

# 4. Scan each subdomain
python3 scanner.py --target https://api.example.com --scope bug-bounty
python3 scanner.py --target https://admin.example.com --scope bug-bounty

# 5. Review all findings
ls -lt scan_report_*.json

# 6. Manual verification
# Test each finding manually
# Take screenshots
# Document steps to reproduce

# 7. Submit report
# Use HackerOne/Bugcrowd template
# Include scanner output + manual verification
# Wait for triage
```

## 💡 Pro Tips

### 1. Start Small
- Begin with one target
- Learn to verify findings manually
- Understand false positives

### 2. Verify Everything
- Scanner output is a starting point
- Always manually verify vulnerabilities
- Understand the security impact

### 3. Read Program Rules
- Know what's in scope
- Understand prohibited actions
- Follow disclosure guidelines

### 4. Be Patient
- Don't rush to submit findings
- Quality over quantity
- Build reputation with good reports

### 5. Keep Learning
- Study OWASP Top 10
- Complete Web Security Academy courses
- Read disclosed bug bounty reports

## 🛠️ Troubleshooting

### "Authorization not confirmed"
- You must type exactly: `YES I AM AUTHORIZED`
- Ensure you actually have permission!

### "Connection timeout"
- Increase timeout: `--timeout 20`
- Check if target is accessible
- Verify firewall/WAF isn't blocking

### "No vulnerabilities found"
- Target might be well-secured
- Try different parameters
- Check if WAF is blocking payloads

### Too many false positives
- Manually verify each finding
- Adjust detection rules if needed
- Report false positives as issues

## 📚 Next Steps

1. **Learn More**
   - [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
   - [Bug Bounty Bootcamp Book](https://nostarch.com/bug-bounty-bootcamp)
   - [Web Security Academy](https://portswigger.net/web-security)

2. **Practice**
   - [HackTheBox](https://www.hackthebox.com/)
   - [TryHackMe](https://tryhackme.com/)
   - [PentesterLab](https://pentesterlab.com/)

3. **Join Communities**
   - [Bug Bounty Forum](https://bugbountyforum.com/)
   - Reddit: r/bugbounty
   - Twitter: Follow #bugbounty

4. **Start Hunting**
   - Sign up for HackerOne/Bugcrowd
   - Choose beginner-friendly programs
   - Submit your first report!

## 🎓 Learning Path

### Week 1: Basics
- Understand web vulnerabilities
- Learn HTTP basics
- Practice on DVWA

### Week 2: Tools
- Master this scanner
- Learn Burp Suite basics
- Understand proxying

### Week 3: Manual Testing
- Practice manual SQLi
- Test for XSS manually
- Learn SSRF exploitation

### Week 4: Bug Bounty
- Choose a program
- Read all rules
- Submit first report

---

**Happy (Ethical) Hunting! 🎯**

Remember: Authorization first, scanning second! 🔒
