"""PhishGuard command-line interface.

Usage:
    phishguard path/to/email.eml
    phishguard path/to/email.eml --json
    python -m phishguard.cli path/to/email.eml
"""
import sys
import json
import argparse
from phishguard.core.engine import analyze_file

GROUPS = [
    ("HEADER  (Envelope Checker)", ["auth_results", "reply_to_mismatch", "brand_name_spoofing"]),
    ("LINKS   (Link Checker)",      ["link_analysis", "virustotal"]),
    ("CONTENT (Message Reader)",    ["content_ml"]),
]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phishguard",
                                 description="PhishGuard - analyze an email for phishing.")
    ap.add_argument("eml", help="path to a .eml file")
    ap.add_argument("--json", action="store_true", help="output machine-readable JSON")
    ap.add_argument("--vt-key", help="VirusTotal API key (or set VT_API_KEY env var)")
    args = ap.parse_args(argv)
    if args.vt_key:
        import os
        os.environ["VT_API_KEY"] = args.vt_key

    try:
        reports, score, verdict = analyze_file(args.eml)
    except FileNotFoundError:
        print(f"Error: file not found: {args.eml}")
        return 2

    if args.json:
        print(json.dumps({
            "file": args.eml,
            "verdict": verdict,
            "risk_score": score,
            "reports": [{"module": r.module, "passed": r.passed,
                         "severity": r.severity.name, "points": r.score,
                         "details": r.details} for r in reports],
        }, indent=2))
        return 0

    by = {r.module: r for r in reports}
    line = "=" * 68
    print(line)
    print(f" PhishGuard  v1.0   |   {args.eml}")
    print(line)
    for title, mods in GROUPS:
        print(f"\n  {title}")
        for mname in mods:
            r = by.get(mname)
            if not r:
                continue
            mark = "PASS" if r.passed else r.severity.name
            pts = "" if r.passed else f"  (+{r.score})"
            print(f"    [{mark:^8}] {r.module}{pts}")
            print(f"               {r.details}")
    print("\n" + "-" * 68)
    verdict_mark = {"SAFE": "SAFE  ", "SUSPICIOUS": "SUSPICIOUS", "PHISHING": "PHISHING"}[verdict]
    print(f"  RISK SCORE : {score}")
    print(f"  VERDICT    : {verdict_mark}")
    print("-" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
