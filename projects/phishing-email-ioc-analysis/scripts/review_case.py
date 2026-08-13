"""
review_case.py

Purpose:
Display a sanitized phishing investigation case in a format
that is easy for an analyst to review.

This script reads the already-sanitized JSON artifact.

It does NOT:
- access the original phishing dataset
- visit URLs
- perform DNS lookups
- contact threat-intelligence services
"""

import json
from pathlib import Path


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

CASE_PATH = Path("data/sanitized/case-001.json")


# ---------------------------------------------------------
# LOAD CASE
# ---------------------------------------------------------

if not CASE_PATH.exists():
    print(f"Error: Case file not found: {CASE_PATH}")
    raise SystemExit(1)


# read_text() loads the JSON file as text.
#
# json.loads() then converts that JSON text into a normal
# Python dictionary.
case = json.loads(
    CASE_PATH.read_text(
        encoding="utf-8"
    )
)


# ---------------------------------------------------------
# EXTRACT IMPORTANT SECTIONS
# ---------------------------------------------------------

metadata = case.get(
    "email_metadata",
    {}
)

indicators = case.get(
    "observed_indicators",
    {}
)

assessment = case.get(
    "analyst_assessment",
    {}
)

limitations = case.get(
    "limitations",
    []
)


# ---------------------------------------------------------
# DISPLAY CASE
# ---------------------------------------------------------

print("=" * 70)
print(f"PHISHING INVESTIGATION — {case.get('case_id')}")
print("=" * 70)

print()
print("EMAIL METADATA")
print("--------------")

print(
    f"Date     : "
    f"{metadata.get('date', '<missing>')}"
)

print(
    f"Sender   : "
    f"{metadata.get('sender_masked', '<missing>')}"
)

print(
    f"Receiver : "
    f"{metadata.get('receiver_masked', '<missing>')}"
)

print(
    f"Subject  : "
    f"{metadata.get('subject', '<missing>')}"
)


print()
print("OBSERVED URL INDICATORS")
print("-----------------------")

urls = indicators.get(
    "urls_defanged",
    []
)

if urls:
    for number, url in enumerate(
        urls,
        start=1,
    ):
        print(
            f"{number}. {url}"
        )

else:
    print("No URL indicators recorded.")


print()
print("SANITIZED MESSAGE BODY")
print("----------------------")

body = case.get(
    "body_sanitized",
    ""
)

# Remove excessive whitespace so the message is easier
# to review in a terminal.
clean_body = " ".join(
    body.split()
)

print(clean_body)


print()
print("CURRENT ANALYST ASSESSMENT")
print("--------------------------")

print(
    f"Verdict    : "
    f"{assessment.get('verdict') or 'Not assigned'}"
)

print(
    f"Confidence : "
    f"{assessment.get('confidence') or 'Not assigned'}"
)


print()
print("KNOWN LIMITATIONS")
print("-----------------")

for limitation in limitations:
    print(
        f"- {limitation}"
    )
