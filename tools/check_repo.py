"""Repository rules, enforced by the git hooks and CI. Exit code 2 when a rule is broken.

  1. No file, commit message or author field names or credits an AI assistant or tool.
  2. No private keys, cloud access keys or tokens in the files.
  3. No real customer data (placeholders only: example domains and documentation address ranges).

Usage:  python tools/check_repo.py            scan files (tracked and not ignored) and all commit metadata
        python tools/check_repo.py --range A..B   scan only the commit metadata in a range (pre-push)
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Patterns are written with character classes so this file does not match its own rules.
ATTRIBUTION = re.compile(r"(?i)(cl[a]ude|anthrop[i]c|co-authored-by:\s*.*(\bai\b|assistant|bot\b|copilot|gpt|llm))")
SECRETS = [
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"(?i)\b(secret|password|token)\s*[:=]\s*[\"'][A-Za-z0-9/+_-]{24,}[\"']"),
]
PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
ALLOW_PRIVATE_IP_IN = {"docker-compose.yml", "tests/test_portal.py", "csportal/demo.py"}   # documented example addresses
SKIP_SUFFIX = {".png", ".jpg", ".ico", ".zip", ".db", ".pyc"}
ME = Path(__file__).name


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


def scan_files(root: Path) -> list[str]:
    problems = []
    for rel in git("ls-files", "-co", "--exclude-standard").splitlines():
        p = root / rel
        if not p.is_file() or p.suffix in SKIP_SUFFIX or p.name == ME:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if ATTRIBUTION.search(rel):
            problems.append(f"{rel}: file name names a tool")
        for n, line in enumerate(text.splitlines(), 1):
            if ATTRIBUTION.search(line):
                problems.append(f"{rel}:{n}: names or credits an AI assistant or tool")
            for pat in SECRETS:
                if pat.search(line) and "check-repo-ok:" not in line:      # explicit, reviewable allow marker
                    problems.append(f"{rel}:{n}: looks like a secret")
            if PRIVATE_IP.search(line) and rel.replace("\\", "/") not in ALLOW_PRIVATE_IP_IN and not rel.startswith("docs/"):
                problems.append(f"{rel}:{n}: private IP address (use documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)")
    return problems


def scan_commits(rng: str = "") -> list[str]:
    problems = []
    args = ["log", "--format=%H%x1f%an <%ae>%x1f%cn <%ce>%x1f%B%x1e"] + ([rng] if rng else ["--all"])
    for rec in git(*args).split("\x1e"):
        if not rec.strip():
            continue
        sha, author, committer, body = (rec.strip("\n").split("\x1f") + ["", "", "", ""])[:4]
        for what, s in (("author", author), ("committer", committer), ("message", body)):
            if ATTRIBUTION.search(s):
                problems.append(f"commit {sha[:10]}: {what} names or credits an AI assistant or tool")
    return problems


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    if "--range" in sys.argv:
        problems = scan_commits(sys.argv[sys.argv.index("--range") + 1])
    else:
        problems = scan_files(root) + scan_commits()
    for p in problems:
        print("RULE BROKEN:", p)
    if problems:
        print(f"{len(problems)} problem(s). Fix them and try again. Do not bypass this check.")
        return 2
    print("repository rules: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
