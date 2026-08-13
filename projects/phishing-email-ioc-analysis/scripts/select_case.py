"""
select_case.py

Purpose:
Find useful phishing-email candidates for manual investigation
without printing live URLs or full sender addresses.

The script:
1. Reads the Nazario phishing dataset.
2. Examines both the dataset's URL field AND the email body.
3. Counts URLs without visiting or displaying them.
4. Masks sender addresses.
5. Displays 10 useful candidates.

No network requests are made by this script.
"""

import ast
import csv
import re

from email.utils import parseaddr
from pathlib import Path


DATASET_PATH = Path("data/raw/Nazario.csv")

csv.field_size_limit(10 * 1024 * 1024)


URL_PATTERN = re.compile(
    r"\b(?:https?://|hxxps?://|www\.)[^\s<>'\"]+",
    re.IGNORECASE,
)


def mask_email(sender_value):
    """
    Extract an email address from a sender field and mask it.

    Example input:
        PayPal Security <alerts@example.com>

    Example output:
        a***@example[.]com

    parseaddr() is better than simply splitting on '@'
    because real email headers may contain display names.
    """

    if not sender_value:
        return "<missing>"

    display_name, email_address = parseaddr(sender_value)

    if not email_address or "@" not in email_address:
        return "<unrecognized sender format>"

    local_part, domain = email_address.rsplit("@", 1)

    if local_part:
        masked_local = local_part[0] + "***"
    else:
        masked_local = "***"

    safe_domain = domain.replace(".", "[.]")

    return f"{masked_local}@{safe_domain}"


def count_url_field(raw_urls):
    """
    Count URLs contained in the dataset's `urls` field.

    The field may contain a text representation of a list,
    such as:

        ['http://example.com', 'http://example.org']

    We first try ast.literal_eval().

    If that fails, we search the field for URL patterns.
    """

    if not raw_urls:
        return 0

    raw_urls = raw_urls.strip()

    if raw_urls.lower() in {
        "",
        "[]",
        "none",
        "null",
        "nan",
    }:
        return 0

    try:
        parsed_urls = ast.literal_eval(raw_urls)

        if isinstance(parsed_urls, (list, tuple, set)):
            return len(parsed_urls)

    except (ValueError, SyntaxError):
        pass

    return len(URL_PATTERN.findall(raw_urls))


def count_body_urls(body):
    """
    Count UNIQUE URL-like indicators found directly in the email body.

    A phishing email may repeat the same URL multiple times.
    For IOC analysis, we count each unique URL only once.

    IMPORTANT:
    This function only examines text.
    It does not visit or connect to any URL.
    """

    if not body:
        return 0

    matches = URL_PATTERN.findall(body)

    # dict.fromkeys() removes duplicate values while preserving
    # the order in which they originally appeared.
    unique_urls = list(
        dict.fromkeys(matches)
    )

    return len(unique_urls)


def clean_subject(subject, maximum_length=90):
    """
    Prepare a subject for terminal display.

    We remove:
    - line breaks
    - excessive whitespace

    We also defang URL protocols if a URL happens to appear
    inside the subject.
    """

    if not subject:
        return "<no subject>"

    subject = " ".join(subject.split())

    subject = re.sub(
        r"https://",
        "hxxps://",
        subject,
        flags=re.IGNORECASE,
    )

    subject = re.sub(
        r"http://",
        "hxxp://",
        subject,
        flags=re.IGNORECASE,
    )

    if len(subject) > maximum_length:
        subject = subject[:maximum_length] + "..."

    return subject


if not DATASET_PATH.exists():
    print(f"Error: Dataset not found: {DATASET_PATH}")
    raise SystemExit(1)


print("Candidate phishing emails")
print("=========================")
print()


candidate_count = 0


with DATASET_PATH.open(
    "r",
    encoding="utf-8",
    errors="replace",
    newline=""
) as csv_file:

    reader = csv.DictReader(csv_file)

    for record_number, row in enumerate(reader, start=1):

        subject = row.get("subject") or ""
        body = row.get("body") or ""
        sender = row.get("sender") or ""
        date = row.get("date") or ""
        raw_urls = row.get("urls") or ""

        url_field_count = count_url_field(raw_urls)
        body_url_count = count_body_urls(body)

        # max() prevents us from obviously double-counting the same
        # URL if it appears both in the body and the dataset's
        # pre-extracted URL field.
        observed_url_count = max(
            url_field_count,
            body_url_count,
        )

        body_length = len(body)

        # Case 001 is intended to be a link-based phishing case,
        # so we're deliberately looking for records with URLs.
        #
        # These are selection criteria, NOT rules for deciding
        # whether an email is malicious.
        if not subject.strip():
            continue

        if body_length < 100:
            continue

        if observed_url_count == 0:
            continue

        candidate_count += 1

        print(f"Candidate {candidate_count}")
        print(f"  Record ID     : {record_number}")
        print(f"  Date          : {date or '<missing>'}")
        print(f"  Sender        : {mask_email(sender)}")
        print(f"  Subject       : {clean_subject(subject)}")
        print(f"  Body size     : {body_length:,} characters")
        print(f"  URLs observed : {observed_url_count}")
        print(
            f"    URL field   : {url_field_count}"
        )
        print(
            f"    Email body  : {body_url_count}"
        )
        print()

        if candidate_count >= 10:
            break


if candidate_count == 0:
    print("No suitable candidates were found.")
    print()
    print(
        "Run scripts/diagnose_dataset.py "
        "to determine which criterion is excluding the records."
    )
