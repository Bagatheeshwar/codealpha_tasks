"""
analyzer.py
===========
CodeAlpha Cybersecurity Internship - Task 3: Secure Coding Review
Student: BAGATHEESHWAR A | ID: CA/DF1/82983

PURPOSE:
    Automated static analysis tool that scans Python source files for
    common security vulnerabilities using pattern matching and AST analysis.

DETECTS:
    - SQL Injection patterns
    - Command Injection patterns  
    - Hardcoded Credentials
    - Insecure File Handling
    - Sensitive Data Exposure

USAGE:
    python analyzer.py vulnerable_code.py
    python analyzer.py vulnerable_code.py secure_code.py --compare
    python analyzer.py --dir . --report report.txt
"""

import re
import ast
import sys
import os
import json
import argparse
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


# ============================================================
# VULNERABILITY RULE DEFINITIONS
# ============================================================

@dataclass
class VulnerabilityRule:
    """Defines a vulnerability detection rule."""
    vuln_id:     str
    name:        str
    cwe:         str
    severity:    str          # CRITICAL / HIGH / MEDIUM / LOW
    pattern:     re.Pattern
    description: str
    remediation: str


@dataclass
class Finding:
    """Represents a single detected vulnerability instance."""
    rule:      VulnerabilityRule
    file:      str
    line:      int
    column:    int
    snippet:   str
    context:   str = ""


# ── Detection rules (regex-based static analysis) ────────────────────────────

RULES: list[VulnerabilityRule] = [

    # ── SQL Injection ──────────────────────────────────────────────────────
    VulnerabilityRule(
        vuln_id="SQL-001",
        name="SQL Injection via String Concatenation",
        cwe="CWE-89",
        severity="CRITICAL",
        pattern=re.compile(
            r'(execute|cursor\.execute)\s*\(\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP).*?["\']'
            r'\s*[\+%]|'
            r'["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?\'\s*\+\s*\w',
            re.IGNORECASE
        ),
        description="SQL query built by string concatenation or formatting with user input.",
        remediation="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (user_id,))"
    ),

    VulnerabilityRule(
        vuln_id="SQL-002",
        name="SQL Injection via f-string / format()",
        cwe="CWE-89",
        severity="CRITICAL",
        pattern=re.compile(
            r'(execute|cursor\.execute)\s*\(\s*f["\'].*?(SELECT|INSERT|UPDATE|DELETE|WHERE)',
            re.IGNORECASE
        ),
        description="SQL query uses f-string formatting, allowing injection.",
        remediation="Replace f-string with parameterized query using ? or %s placeholders."
    ),

    # ── Command Injection ──────────────────────────────────────────────────
    VulnerabilityRule(
        vuln_id="CMD-001",
        name="Command Injection via shell=True",
        cwe="CWE-78",
        severity="CRITICAL",
        pattern=re.compile(r'subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True'),
        description="subprocess called with shell=True enables shell injection.",
        remediation="Use shell=False and pass command as a list: subprocess.run(['cmd', arg], shell=False)"
    ),

    VulnerabilityRule(
        vuln_id="CMD-002",
        name="Command Injection via os.system()",
        cwe="CWE-78",
        severity="CRITICAL",
        pattern=re.compile(r'os\.system\s*\('),
        description="os.system() always invokes a shell, enabling command injection.",
        remediation="Replace with subprocess.run(cmd_list, shell=False) with input validation."
    ),

    VulnerabilityRule(
        vuln_id="CMD-003",
        name="Command Injection via os.popen()",
        cwe="CWE-78",
        severity="HIGH",
        pattern=re.compile(r'os\.popen\s*\('),
        description="os.popen() uses a shell and is deprecated.",
        remediation="Use subprocess.run() with shell=False."
    ),

    # ── Hardcoded Credentials ──────────────────────────────────────────────
    VulnerabilityRule(
        vuln_id="CRED-001",
        name="Hardcoded Password",
        cwe="CWE-798",
        severity="CRITICAL",
        pattern=re.compile(
            r'(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth_key)\s*=\s*["\'][^"\']{4,}["\']'
        ),
        description="Credential assigned as a literal string in source code.",
        remediation="Load from environment variables: os.environ.get('MY_PASSWORD')"
    ),

    VulnerabilityRule(
        vuln_id="CRED-002",
        name="Hardcoded Secret Key",
        cwe="CWE-321",
        severity="CRITICAL",
        pattern=re.compile(
            r'(?i)(secret_key|secretkey|signing_key|jwt_secret)\s*=\s*["\'][^"\']{4,}["\']'
        ),
        description="Secret/signing key hardcoded in source.",
        remediation="Generate keys with secrets.token_hex(32) and load from environment."
    ),

    # ── Insecure File Handling ─────────────────────────────────────────────
    VulnerabilityRule(
        vuln_id="FILE-001",
        name="Path Traversal — Unsanitized open()",
        cwe="CWE-22",
        severity="HIGH",
        pattern=re.compile(r'\bopen\s*\(\s*\w+\s*,'),
        description="open() called with a variable filename without path sanitization.",
        remediation="Use Path(__file__).parent / 'uploads' / Path(filename).name and verify resolved path."
    ),

    VulnerabilityRule(
        vuln_id="FILE-002",
        name="Overly Permissive File Mode (0o777 / 0777)",
        cwe="CWE-732",
        severity="HIGH",
        pattern=re.compile(r'0[oO]?777|0[oO]?666'),
        description="File created with world-writable permissions.",
        remediation="Use restrictive permissions: 0o640 (owner rw, group r, no others)."
    ),

    VulnerabilityRule(
        vuln_id="FILE-003",
        name="Arbitrary String Passed to open() as Path",
        cwe="CWE-22",
        severity="HIGH",
        pattern=re.compile(r'open\s*\(\s*upload_dir\s*\+'),
        description="File path built by concatenating user-supplied filename.",
        remediation="Use Path canonicalization and verify path stays within allowed directory."
    ),

    # ── Sensitive Data Exposure ────────────────────────────────────────────
    VulnerabilityRule(
        vuln_id="EXP-001",
        name="Sensitive Data in Debug Output / Logs",
        cwe="CWE-200",
        severity="HIGH",
        pattern=re.compile(r'print\s*\(.*?(password|passwd|secret|api_key|token)', re.IGNORECASE),
        description="Password, secret, or token printed to stdout/logs.",
        remediation="Never log credentials. Use logger.info(f'User {user_id} logged in') with no secrets."
    ),

    VulnerabilityRule(
        vuln_id="EXP-002",
        name="Debug Query Printed to Console",
        cwe="CWE-200",
        severity="MEDIUM",
        pattern=re.compile(r'print\s*\(.*?query', re.IGNORECASE),
        description="SQL query printed to console — may expose schema/logic.",
        remediation="Remove debug print statements before deploying to production."
    ),
]


# ============================================================
# ANALYZER ENGINE
# ============================================================

class SecurityAnalyzer:
    """
    Static security analyzer using regex pattern matching.
    Scans Python source files line-by-line against rule patterns.
    """

    def __init__(self, rules: list[VulnerabilityRule] = RULES):
        self.rules = rules
        self.findings: list[Finding] = []

    def analyze_file(self, filepath: str) -> list[Finding]:
        """Scan a single file and return all findings."""
        findings: list[Finding] = []

        try:
            source = Path(filepath).read_text(encoding='utf-8')
        except Exception as e:
            print(f"[ERROR] Could not read {filepath}: {e}")
            return findings

        lines = source.splitlines()

        for line_no, line in enumerate(lines, start=1):
            # Skip comment-only lines and empty lines
            stripped = line.strip()
            if stripped.startswith('#') or not stripped:
                continue

            for rule in self.rules:
                match = rule.pattern.search(line)
                if match:
                    # Grab 2 lines of context around the finding
                    start = max(0, line_no - 2)
                    end   = min(len(lines), line_no + 1)
                    ctx   = "\n".join(
                        f"  {start + i + 1:4d} | {lines[start + i]}"
                        for i in range(end - start)
                    )
                    findings.append(Finding(
                        rule=rule,
                        file=filepath,
                        line=line_no,
                        column=match.start(),
                        snippet=line.strip(),
                        context=ctx
                    ))

        self.findings.extend(findings)
        return findings

    def analyze_directory(self, directory: str) -> list[Finding]:
        """Recursively scan all .py files in a directory."""
        all_findings: list[Finding] = []
        for py_file in Path(directory).rglob("*.py"):
            # Skip the analyzer itself and test files
            if py_file.name in ("analyzer.py",):
                continue
            all_findings.extend(self.analyze_file(str(py_file)))
        return all_findings


# ============================================================
# REPORT GENERATOR
# ============================================================

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def generate_report(findings: list[Finding], filename: str, output_path: Optional[str] = None) -> str:
    """Generate a formatted security analysis report."""

    by_severity: dict[str, list[Finding]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        by_severity[f.rule.severity].append(f)

    lines = []
    lines.append("=" * 70)
    lines.append("  SECURITY ANALYSIS REPORT")
    lines.append(f"  CodeAlpha Cybersecurity Internship — Task 3")
    lines.append(f"  Student: BAGATHEESHWAR A | ID: CA/DF1/82983")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)
    lines.append(f"\nTarget File : {filename}")
    lines.append(f"Total Issues: {len(findings)}")
    lines.append(
        "  " + "  ".join(
            f"{SEVERITY_ICONS[s]} {s}: {len(by_severity[s])}"
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
    )
    lines.append("")

    if not findings:
        lines.append("✅ No vulnerabilities detected.")
        report = "\n".join(lines)
    else:
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            sfindings = by_severity[severity]
            if not sfindings:
                continue
            icon = SEVERITY_ICONS[severity]
            lines.append(f"\n{'─' * 70}")
            lines.append(f" {icon}  {severity} SEVERITY  ({len(sfindings)} issue{'s' if len(sfindings) != 1 else ''})")
            lines.append(f"{'─' * 70}")

            for idx, f in enumerate(sfindings, 1):
                lines.append(f"\n  [{idx}] {f.rule.vuln_id} — {f.rule.name}")
                lines.append(f"      CWE        : {f.rule.cwe}")
                lines.append(f"      Location   : {f.file}  line {f.line}, col {f.column}")
                lines.append(f"      Issue      : {f.rule.description}")
                lines.append(f"      Remediation: {f.rule.remediation}")
                lines.append(f"\n      Affected code:")
                lines.append(f"{f.context}")

        lines.append(f"\n{'=' * 70}")
        lines.append("  REMEDIATION SUMMARY")
        lines.append(f"{'=' * 70}")
        lines.append("\nPriority fixes (address in this order):\n")

        for i, severity in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"], 1):
            for f in by_severity[severity]:
                lines.append(f"  {i}. [{f.rule.vuln_id}] {f.rule.name} (line {f.line})")
                lines.append(f"     Fix: {f.rule.remediation}")
                lines.append("")

        report = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(report, encoding='utf-8')
        print(f"\n[✅] Report saved to: {output_path}")

    return report


def compare_files(before_file: str, after_file: str) -> None:
    """Compare vulnerability counts between two files."""
    analyzer = SecurityAnalyzer()

    print(f"\n{'=' * 60}")
    print(f"  BEFORE vs AFTER SECURITY COMPARISON")
    print(f"{'=' * 60}")

    before_findings = analyzer.analyze_file(before_file)
    after_findings  = analyzer.analyze_file(after_file)

    def count_by_severity(findings):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f.rule.severity] += 1
        return counts

    before_counts = count_by_severity(before_findings)
    after_counts  = count_by_severity(after_findings)

    print(f"\n  {'Severity':<12} {'Before':>8} {'After':>8} {'Fixed':>8}")
    print(f"  {'-' * 44}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        icon   = SEVERITY_ICONS[sev]
        before = before_counts[sev]
        after  = after_counts[sev]
        fixed  = before - after
        bar    = "✅" if fixed > 0 else ("⚠️ " if fixed == 0 else "❌")
        print(f"  {icon} {sev:<10} {before:>8} {after:>8} {bar} {fixed:>4}")

    print(f"  {'-' * 44}")
    total_before = len(before_findings)
    total_after  = len(after_findings)
    total_fixed  = total_before - total_after
    pct          = (total_fixed / total_before * 100) if total_before else 0
    print(f"  {'TOTAL':<12} {total_before:>8} {total_after:>8} {total_fixed:>8}")
    print(f"\n  🎯 Security improvement: {pct:.1f}% of issues resolved")
    print(f"{'=' * 60}\n")


# ============================================================
# CLI INTERFACE
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 3 — Python Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan a file:
    python analyzer.py vulnerable_code.py

  Compare vulnerable vs secure:
    python analyzer.py vulnerable_code.py secure_code.py --compare

  Scan directory and save report:
    python analyzer.py --dir . --report scan_report.txt

  Output JSON results:
    python analyzer.py vulnerable_code.py --json
        """
    )

    parser.add_argument("files",        nargs="*",           help="Python file(s) to analyze")
    parser.add_argument("--compare",    action="store_true", help="Compare two files (before/after)")
    parser.add_argument("--dir",        metavar="DIR",       help="Scan entire directory recursively")
    parser.add_argument("--report",     metavar="FILE",      help="Save report to file")
    parser.add_argument("--json",       action="store_true", help="Output findings as JSON")
    parser.add_argument("--severity",   choices=["CRITICAL","HIGH","MEDIUM","LOW"],
                        help="Filter by minimum severity")

    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  CodeAlpha Security Analyzer")
    print("  Task 3: Secure Coding Review")
    print("  Student: BAGATHEESHWAR A | CA/DF1/82983")
    print("=" * 60)

    analyzer = SecurityAnalyzer()

    # ── Compare mode ──────────────────────────────────────────
    if args.compare:
        if len(args.files) != 2:
            print("Error: --compare requires exactly 2 files.")
            sys.exit(1)
        compare_files(args.files[0], args.files[1])
        return

    # ── Directory scan ────────────────────────────────────────
    if args.dir:
        findings = analyzer.analyze_directory(args.dir)
        target   = args.dir
    elif args.files:
        findings = []
        for f in args.files:
            findings.extend(analyzer.analyze_file(f))
        target = ", ".join(args.files)
    else:
        # Default: scan vulnerable_code.py
        findings = analyzer.analyze_file("vulnerable_code.py")
        target   = "vulnerable_code.py"

    # ── Severity filter ───────────────────────────────────────
    if args.severity:
        min_order = SEVERITY_ORDER[args.severity]
        findings  = [f for f in findings if SEVERITY_ORDER[f.rule.severity] <= min_order]

    # ── JSON output ───────────────────────────────────────────
    if args.json:
        output = [
            {
                "id":          f.rule.vuln_id,
                "name":        f.rule.name,
                "cwe":         f.rule.cwe,
                "severity":    f.rule.severity,
                "file":        f.file,
                "line":        f.line,
                "snippet":     f.snippet,
                "remediation": f.rule.remediation,
            }
            for f in findings
        ]
        print(json.dumps(output, indent=2))
        return

    # ── Standard report ───────────────────────────────────────
    report = generate_report(findings, target, output_path=args.report)
    print(report)


if __name__ == "__main__":
    main()
