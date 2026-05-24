# 🔐 Task 3: Secure Coding Review

**CodeAlpha Cybersecurity Internship | May–June 2026**  
**Student:** BAGATHEESHWAR A | **ID:** CA/DF1/82983  

---

## 📌 Overview

This task demonstrates secure coding practices by identifying and fixing **four major vulnerability categories** in a Python application:

| Vulnerability | CWE | Severity |
|--------------|-----|----------|
| SQL Injection | CWE-89 | 🔴 CRITICAL |
| Command Injection | CWE-78 | 🔴 CRITICAL |
| Hardcoded Credentials | CWE-798 | 🔴 CRITICAL |
| Insecure File Handling | CWE-22, CWE-732 | 🟠 HIGH |

---

## 📁 File Structure

```
task3_secure_coding_review/
├── vulnerable_code.py    ← Intentionally vulnerable Python code (educational)
├── secure_code.py        ← Fixed, hardened version with all vulnerabilities patched
├── analyzer.py           ← Automated static security scanner (CLI tool)
├── review_report.md      ← Full audit report with attack scenarios & fixes
└── README.md             ← This file
```

---

## 🚀 Quick Start

### 1. Run the Vulnerable Code (see what NOT to do)
```bash
python3 vulnerable_code.py
```

### 2. Run the Automated Security Analyzer
```bash
# Scan the vulnerable file
python3 analyzer.py vulnerable_code.py

# Scan the secure file
python3 analyzer.py secure_code.py

# Compare before vs after
python3 analyzer.py vulnerable_code.py secure_code.py --compare

# Save report to file
python3 analyzer.py vulnerable_code.py --report scan_output.txt

# Output as JSON (for integration with other tools)
python3 analyzer.py vulnerable_code.py --json

# Filter by severity
python3 analyzer.py vulnerable_code.py --severity CRITICAL
```

### 3. Run the Secure Code
```bash
# Set required environment variables first
export DB_HOST="localhost"
export DB_USER="dbuser"
export DB_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export API_KEY="your-api-key-here"

python3 secure_code.py
```

---

## 🔍 Vulnerability Details

### 1. SQL Injection
**Vulnerable:**
```python
query = "SELECT * FROM users WHERE username='" + username + "'"
cursor.execute(query)  # ← Attacker controls the query
```
**Attack:** `username = "admin' OR '1'='1'--"` → bypasses authentication  
**Fix:** Parameterized queries — `cursor.execute("SELECT ... WHERE username=?", (username,))`

---

### 2. Command Injection
**Vulnerable:**
```python
subprocess.run("ping -c 1 " + ip_address, shell=True)  # ← Shell injection
os.system(tool_name)  # ← Executes arbitrary commands
```
**Attack:** `ip_address = "127.0.0.1; rm -rf /"` → deletes files  
**Fix:** `shell=False` + list args + IP allowlist regex + tool allowlist

---

### 3. Hardcoded Credentials
**Vulnerable:**
```python
DB_PASSWORD = "SuperSecret123!"   # ← In source code
SECRET_KEY  = "mysecretkey_abc"   # ← In source code
```
**Attack:** Commit repo publicly → credentials exposed forever  
**Fix:** `os.environ.get("DB_PASSWORD")` — load from environment at runtime

---

### 4. Insecure File Handling
**Vulnerable:**
```python
open(filename, 'r')  # ← filename = "../../../../etc/passwd"
os.open(path, flags, 0o777)  # ← World-writable
upload_dir + filename  # ← Path traversal
```
**Attack:** Read `/etc/passwd`, upload shell scripts, overwrite logs  
**Fix:** `Path.resolve()` + prefix check + extension allowlist + `0o640` permissions

---

## 📊 Results

```
Analyzer Comparison: vulnerable_code.py vs secure_code.py

Severity     Before   After   Fixed
--------------------------------------
🔴 CRITICAL     8       0     ✅  8
🟠 HIGH         9       5     ✅  4
🟡 MEDIUM       2       0     ✅  2
--------------------------------------
TOTAL          19       5         14

🎯 Security Improvement: 73.7%
```

---

## 📚 References

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | [CWE-22](https://cwe.mitre.org/data/definitions/22.html)

---

*CodeAlpha Cybersecurity Internship — Task 3 | BAGATHEESHWAR A (CA/DF1/82983)*
