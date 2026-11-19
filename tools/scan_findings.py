"""List the findings of a Trivy JSON report, one per line, as CI annotations.

Usage:  python tools/scan_findings.py image-scan.json
Prints "::error" lines (shown on the CI run page) and a plain table. Exit code 0 always: the scanner's own
exit code decides whether the build fails. Does not change or hide any finding.
"""
from __future__ import annotations

import json
import sys


def main() -> int:
    try:
        report = json.load(open(sys.argv[1], encoding="utf-8"))
    except (OSError, ValueError, IndexError) as e:
        print(f"::error title=Image scan::report not readable: {e}")
        return 0
    rows = []
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            rows.append((v.get("Severity", ""), v.get("VulnerabilityID", ""), v.get("PkgName", ""),
                         v.get("InstalledVersion", ""), v.get("FixedVersion", ""), res.get("Target", "")))
    rows.sort(key=lambda r: (r[0] != "CRITICAL", r[2], r[1]))
    print(f"{len(rows)} fixable HIGH or CRITICAL finding(s)")
    for sev, vid, pkg, inst, fixed, target in rows:
        line = f"{sev} {vid} {pkg} {inst} -> fixed in {fixed} ({target})"
        print(line)
        print(f"::error title=Image scan::{line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
