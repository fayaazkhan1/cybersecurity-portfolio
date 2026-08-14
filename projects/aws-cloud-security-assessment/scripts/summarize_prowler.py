#!/usr/bin/env python3

"""Generate public-safe summaries from Prowler CSV reports.

Prowler CSV exports contain account- and resource-specific metadata. This
script intentionally reports only status counts, severity counts, service
counts, and check IDs so the resulting output can be used as sanitized
portfolio evidence.
"""

import argparse
import csv
from collections import Counter
from pathlib import Path


def load_report(path):
    """Load a semicolon-delimited Prowler CSV and summarize safe fields."""

    with Path(path).open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file, delimiter=";"))

    passed = [
        row for row in rows
        if row.get("STATUS", "").upper() == "PASS"
    ]

    failed = [
        row for row in rows
        if row.get("STATUS", "").upper() == "FAIL"
    ]

    severity = Counter(
        row.get("SEVERITY", "UNKNOWN").upper()
        for row in failed
    )

    services = Counter(
        row.get("SERVICE_NAME", "UNKNOWN").upper()
        for row in failed
    )

    failed_ids = {
        row.get("CHECK_ID", "")
        for row in failed
        if row.get("CHECK_ID")
    }

    return {
        "passed": len(passed),
        "failed": len(failed),
        "severity": severity,
        "services": services,
        "failed_ids": failed_ids,
    }


def print_single(report):
    """Print a sanitized summary for one Prowler report."""

    print("=" * 68)
    print("SANITIZED PROWLER SECURITY SUMMARY")
    print("=" * 68)

    print(f"Checks passed : {report['passed']}")
    print(f"Checks failed : {report['failed']}")

    print()
    print("FAILED BY SEVERITY")

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        print(f"{level:<14}: {report['severity'].get(level, 0)}")

    print()
    print("FAILED BY SERVICE")

    for service, count in sorted(report["services"].items()):
        print(f"{service:<14}: {count}")


def print_comparison(before, after):
    """Print a sanitized before/after comparison of two Prowler reports."""

    print("=" * 68)
    print("SANITIZED PROWLER BEFORE / AFTER COMPARISON")
    print("=" * 68)

    print()
    print("RESULTS")
    print(f"Baseline passed : {before['passed']}")
    print(f"Baseline failed : {before['failed']}")
    print(f"After passed    : {after['passed']}")
    print(f"After failed    : {after['failed']}")

    print()
    print("FAILED BY SERVICE")
    print(f"{'Service':<14}{'Before':>8}{'After':>8}")

    services = sorted(set(before["services"]) | set(after["services"]))

    for service in services:
        print(
            f"{service:<14}"
            f"{before['services'].get(service, 0):>8}"
            f"{after['services'].get(service, 0):>8}"
        )

    print()
    print("RESOLVED CHECK IDS")

    resolved = sorted(before["failed_ids"] - after["failed_ids"])

    if resolved:
        for check in resolved:
            print(f"- {check}")
    else:
        print("- None")


def main():
    parser = argparse.ArgumentParser(
        description="Generate sanitized Prowler summaries."
    )

    parser.add_argument(
        "baseline",
        help="Baseline Prowler CSV report",
    )

    parser.add_argument(
        "after",
        nargs="?",
        help="Optional post-remediation Prowler CSV report",
    )

    args = parser.parse_args()

    baseline = load_report(args.baseline)

    if args.after:
        after = load_report(args.after)
        print_comparison(baseline, after)
    else:
        print_single(baseline)


if __name__ == "__main__":
    main()
