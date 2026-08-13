"""
create_case.py

Purpose:
Create a sanitized phishing-investigation case from one record
in the Nazario phishing dataset.

For Case 001, this script:

1. Retrieves Record 27 from the raw CSV dataset.
2. Extracts URLs found inside the email body.
3. Defangs URLs and domains.
4. Masks complete email addresses.
5. Saves a sanitized JSON case file.
6. Prints a safe analyst preview.

IMPORTANT:
This script does NOT visit URLs, resolve domains, or make
network connections.
"""

import csv
import html
import json
import re

from email.utils import parseaddr
from pathlib import Path


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

DATASET_PATH = Path("data/raw/Nazario.csv")

OUTPUT_PATH = Path("data/sanitized/case-001.json")

CASE_ID = "CASE-001"

# This is the candidate we selected from select_case.py.
TARGET_RECORD_ID = 27


# The dataset contains unusually large email bodies.
csv.field_size_limit(10 * 1024 * 1024)


# ---------------------------------------------------------
# REGULAR EXPRESSIONS
# ---------------------------------------------------------

# Finds common URL formats in text.
#
# Examples:
# https://example.com/login
# http://example.com
# www.example.com
#
# This searches text only.
# It does not connect to the URL.
URL_PATTERN = re.compile(
    r"\b(?:https?://|hxxps?://|www\.)[^\s<>'\"]+",
    re.IGNORECASE,
)


# Finds ordinary email addresses.
EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)


# Finds domain-like strings that may appear outside URLs.
#
# Example:
# example.com
# login.example.net
DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

def unique_preserve_order(items):
    """
    Remove duplicates while preserving the order in which
    indicators originally appeared.

    Example:

        ["a", "b", "a"]

    becomes:

        ["a", "b"]
    """

    seen = set()
    unique_items = []

    for item in items:
        if item not in seen:
            seen.add(item)
            unique_items.append(item)

    return unique_items


def defang_domain(domain):
    """
    Convert a domain into a non-clickable representation.

    Example:

        login.example.com

    becomes:

        login[.]example[.]com
    """

    if not domain:
        return domain

    return domain.replace(".", "[.]")


def defang_url(url):
    """
    Defang a URL so it cannot easily be clicked accidentally.

    Example:

        https://example.com/login

    becomes:

        hxxps://example[.]com/login
    """

    if not url:
        return url

    safe_url = url

    # Defang the protocol.
    safe_url = re.sub(
        r"^https://",
        "hxxps://",
        safe_url,
        flags=re.IGNORECASE,
    )

    safe_url = re.sub(
        r"^http://",
        "hxxp://",
        safe_url,
        flags=re.IGNORECASE,
    )

    # Defang periods throughout the indicator.
    #
    # For a portfolio artifact, slightly over-defanging is
    # preferable to accidentally leaving a clickable domain.
    safe_url = safe_url.replace(".", "[.]")

    return safe_url


def mask_email(email_value):
    """
    Hide most of an email address while preserving the
    domain for security analysis.

    Example:

        attacker@example.com

    becomes:

        a***@example[.]com
    """

    if not email_value:
        return "<missing>"

    # parseaddr() handles values such as:
    #
    # PayPal Security <alerts@example.com>
    display_name, email_address = parseaddr(email_value)

    if not email_address or "@" not in email_address:
        return "<unrecognized email format>"

    local_part, domain = email_address.rsplit("@", 1)

    if local_part:
        masked_local = local_part[0] + "***"
    else:
        masked_local = "***"

    return f"{masked_local}@{defang_domain(domain)}"


def extract_urls(body):
    """
    Extract URL-like indicators from the email body.

    The result is only text.

    No network requests are performed.
    """

    if not body:
        return []

    matches = URL_PATTERN.findall(body)

    return unique_preserve_order(matches)


def sanitize_body(body):
    """
    Produce a safer copy of the email body for investigation
    and eventual portfolio use.

    The function:
    - decodes common HTML entities
    - defangs URLs
    - masks email addresses
    - defangs remaining standalone domains
    """

    if not body:
        return ""

    # Convert HTML entities such as:
    #
    # &amp; -> &
    # &lt;  -> <
    #
    # This changes text representation only.
    safe_body = html.unescape(body)

    # Extract URLs before modifying them.
    raw_urls = extract_urls(safe_body)

    # Replace every discovered URL with its defanged version.
    #
    # Sorting longest first reduces the chance that a shorter
    # indicator will accidentally modify part of a longer one.
    for raw_url in sorted(
        raw_urls,
        key=len,
        reverse=True,
    ):
        safe_body = safe_body.replace(
            raw_url,
            defang_url(raw_url),
        )

    # Mask email addresses found inside the message body.
    safe_body = EMAIL_PATTERN.sub(
        lambda match: mask_email(match.group(0)),
        safe_body,
    )

    # Defang any remaining standalone domains.
    safe_body = DOMAIN_PATTERN.sub(
        lambda match: defang_domain(match.group(0)),
        safe_body,
    )

    return safe_body


def get_dataset_record(record_id):
    """
    Retrieve one specific record from the CSV dataset.

    Record numbering starts at 1, matching select_case.py.
    """

    with DATASET_PATH.open(
        "r",
        encoding="utf-8",
        errors="replace",
        newline="",
    ) as csv_file:

        reader = csv.DictReader(csv_file)

        for current_record_id, row in enumerate(
            reader,
            start=1,
        ):
            if current_record_id == record_id:
                return row

    return None


# ---------------------------------------------------------
# MAIN PROGRAM
# ---------------------------------------------------------

if not DATASET_PATH.exists():
    print(f"Error: Dataset not found: {DATASET_PATH}")
    raise SystemExit(1)


record = get_dataset_record(TARGET_RECORD_ID)


if record is None:
    print(
        f"Error: Record {TARGET_RECORD_ID} "
        "was not found in the dataset."
    )
    raise SystemExit(1)


raw_body = record.get("body") or ""

raw_urls = extract_urls(raw_body)

safe_urls = [
    defang_url(url)
    for url in raw_urls
]

safe_body = sanitize_body(raw_body)


# Build the public/sanitized case structure.
#
# Notice that the dataset label is preserved separately from
# our future analyst verdict.
#
# We do NOT let the source label automatically determine
# our own conclusion.
case_data = {
    "case_id": CASE_ID,
    "source": {
        "dataset": "Nazario phishing corpus",
        "record_id": TARGET_RECORD_ID,
        "dataset_label": record.get("label"),
    },
    "email_metadata": {
        "date": record.get("date"),
        "sender_masked": mask_email(
            record.get("sender")
        ),
        "receiver_masked": mask_email(
            record.get("receiver")
        ),
        "subject": record.get("subject"),
    },
    "observed_indicators": {
        "url_count": len(safe_urls),
        "urls_defanged": safe_urls,
    },
    "body_length": len(raw_body),
    "body_sanitized": safe_body,
    "analyst_assessment": {
        "verdict": None,
        "confidence": None,
        "notes": [],
    },
    "limitations": [
        (
            "The source CSV does not contain complete raw "
            "email headers, so SPF, DKIM, DMARC, and "
            "Received-header routing cannot be validated "
            "for this case."
        ),
        (
            "The original dataset label is retained for "
            "reference but is not treated as the analyst's "
            "independent verdict."
        ),
    ],
}


# Make sure the destination directory exists.
OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)


# Write the sanitized case as formatted JSON.
with OUTPUT_PATH.open(
    "w",
    encoding="utf-8",
) as output_file:

    json.dump(
        case_data,
        output_file,
        indent=2,
        ensure_ascii=False,
    )


# ---------------------------------------------------------
# SAFE TERMINAL PREVIEW
# ---------------------------------------------------------

print("Case created successfully")
print("=========================")
print()

print(f"Case ID       : {CASE_ID}")
print(f"Source record : {TARGET_RECORD_ID}")

print(
    "Date          : "
    f"{case_data['email_metadata']['date']}"
)

print(
    "Sender        : "
    f"{case_data['email_metadata']['sender_masked']}"
)

print(
    "Receiver      : "
    f"{case_data['email_metadata']['receiver_masked']}"
)

print(
    "Subject       : "
    f"{case_data['email_metadata']['subject']}"
)

print(
    "Body size     : "
    f"{case_data['body_length']:,} characters"
)

print(
    "Unique URLs   : "
    f"{case_data['observed_indicators']['url_count']}"
)

print()
print("Defanged URL indicators")
print("-----------------------")

for url in safe_urls:
    print(f"- {url}")


print()
print("Sanitized body preview")
print("----------------------")

# Collapse repeated whitespace so the terminal preview
# is easier to read.
preview = " ".join(
    safe_body.split()
)

print(preview[:1500])

if len(preview) > 1500:
    print("...")


print()
print(f"Saved to: {OUTPUT_PATH}")
