#!/usr/bin/env python3
"""SecretSweep - lightweight, local-first secret scanner.

Usage:
    python secretsweep.py [PATH ...] [--json] [-o REPORT] [--max-size KB]
                          [--exclude DIR ...] [--no-fail]

Exit codes: 0 = clean, 1 = findings, 2 = error.
Add `secretsweep:ignore` in a line comment to suppress a finding on that line.
Only scan repositories you own or are authorized to review.
"""
import argparse
import fnmatch
import json
import os
import re
import sys

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__",
             "dist", "build", ".idea", ".vscode", ".tox", "vendor"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
            ".7z", ".jar", ".class", ".exe", ".dll", ".so", ".dylib", ".woff",
            ".woff2", ".ttf", ".mp3", ".mp4", ".mov", ".lock", ".min.js"}

# (name, compiled regex, capture group holding the secret value)
PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    ("GitHub Token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), 1),
    ("GitHub Fine-grained PAT", re.compile(r"\b(github_pat_[A-Za-z0-9_]{50,})\b"), 1),
    ("Slack Token", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"), 1),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    ("Stripe Live Key", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"), 1),
    ("Anthropic API Key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"), 1),
    ("OpenAI-style API Key", re.compile(r"\b(sk-[A-Za-z0-9]{32,})\b"), 1),
    ("JSON Web Token", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"), 1),
    ("Private Key Block", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)"), 1),
    ("Credentials in URL", re.compile(r"[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s:/@]{4,})@"), 1),
    ("Generic Secret Assignment", re.compile(
        r"""(?i)\b[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|auth)[\w.-]*"""
        r"""\s*[:=]\s*["']([^"'\s]{8,})["']"""), 1),
]

PLACEHOLDER = re.compile(
    r"(?i)(example|sample|dummy|changeme|change_me|placeholder|your[_-]?|xxxx|\*{3,}|<.+>|\$\{.+\}|\{\{.+\}\}|process\.env|os\.environ|getenv)")

SENSITIVE_FILES = [".env", ".env.*", "*.env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                   "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
                   ".netrc", ".npmrc", ".pypirc", ".htpasswd", "credentials",
                   "credentials.json", "service-account*.json", "terraform.tfstate",
                   "*.kdbx"]
SENSITIVE_SAFE = {".env.example", ".env.sample", ".env.template"}


def redact(value: str) -> str:
    if value.startswith("-----BEGIN"):
        return "[private key header]"
    return "****" if len(value) <= 8 else value[:4] + "*" * 8


def is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\0" in f.read(2048)
    except OSError:
        return True


def sensitive_file_match(name: str):
    low = name.lower()
    if low in SENSITIVE_SAFE:
        return None
    for pat in SENSITIVE_FILES:
        if fnmatch.fnmatch(low, pat):
            return pat
    return None


def scan_file(path: str, max_bytes: int):
    findings = []
    name = os.path.basename(path)
    pat = sensitive_file_match(name)
    if pat:
        findings.append({"type": "Sensitive File", "file": path, "line": 0,
                         "match": f"filename matches '{pat}'"})
    try:
        if os.path.getsize(path) > max_bytes or is_binary(path):
            return findings
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                if "secretsweep:ignore" in line or len(line) > 5000:
                    continue
                for label, rx, grp in PATTERNS:
                    for m in rx.finditer(line):
                        val = m.group(grp)
                        if label in ("Generic Secret Assignment", "Credentials in URL") \
                                and PLACEHOLDER.search(val):
                            continue
                        findings.append({"type": label, "file": path, "line": lineno,
                                         "match": redact(val)})
    except OSError:
        pass
    return findings


def walk(roots, excludes):
    skip = SKIP_DIRS | set(excludes)
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                    continue
                yield os.path.join(dirpath, fn)


def main():
    ap = argparse.ArgumentParser(description="SecretSweep: local secret scanner")
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("-o", "--output", help="write report to file")
    ap.add_argument("--max-size", type=int, default=1024, help="max file size in KB (default 1024)")
    ap.add_argument("--exclude", nargs="*", default=[], help="extra directory names to skip")
    ap.add_argument("--no-fail", action="store_true", help="always exit 0")
    args = ap.parse_args()

    for p in args.paths:
        if not os.path.exists(p):
            print(f"error: path not found: {p}", file=sys.stderr)
            return 2

    findings, scanned = [], 0
    for fp in walk(args.paths, args.exclude):
        scanned += 1
        findings.extend(scan_file(fp, args.max_size * 1024))

    if args.json:
        out = json.dumps({"files_scanned": scanned, "findings": findings}, indent=2)
    else:
        lines = [f"[{x['type']}] {x['file']}" + (f":{x['line']}" if x["line"] else "")
                 + f"  ->  {x['match']}" for x in findings]
        lines.append(f"\nScanned {scanned} files, {len(findings)} potential finding(s).")
        if findings:
            lines.append("Verify manually. If real: revoke/rotate the credential and check "
                         "git history; deleting it from the current file is not enough.")
        out = "\n".join(lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    print(out)
    return 0 if (not findings or args.no_fail) else 1


if __name__ == "__main__":
    sys.exit(main())
