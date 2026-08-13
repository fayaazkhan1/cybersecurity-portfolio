"""
analyze_iocs.py

Purpose:
Perform offline structural analysis of indicators associated
with CASE-001.

The script examines:
- sender domain
- URL scheme
- URL hostname
- URL port
- URL path
- whether query parameters are present
- relationship between sender and URL domains

IMPORTANT:
This script performs text parsing only.

It does NOT:
- visit URLs
- perform DNS lookups
- contact remote servers
- query threat-intelligence APIs
"""

import csv
import re

from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

DATASET_PATH = Path(
    "data/raw/Nazario.csv"
)

TARGET_RECORD_ID = 27

csv.field_size_limit(
    10 * 1024 * 1024
)


# ---------------------------------------------------------
# REGULAR EXPRESSIONS
# ---------------------------------------------------------

URL_PATTERN = re.compile(
    r"\b(?:https?://|hxxps?://|www\.)"
    r"[^\s<>'\"]+",
    re.IGNORECASE,
)


# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

def unique_preserve_order(items):
    """
    Remove duplicate indicators while keeping their
    original order.
    """

    seen = set()
    result = []

    for item in items:

        if item not in seen:
            seen.add(item)
            result.append(item)

    return result


def defang_domain(domain):
    """
    Convert a normal domain into a safer display format.

    Example:

        example.com

    becomes:

        example[.]com
    """

    if not domain:
        return "<missing>"

    return domain.replace(
        ".",
        "[.]",
    )


def defang_url(url):
    """
    Convert a URL into a safer display format.

    Example:

        https://example.com/login

    becomes:

        hxxps://example[.]com/login
    """

    if not url:
        return "<missing>"

    safe_url = re.sub(
        r"^https://",
        "hxxps://",
        url,
        flags=re.IGNORECASE,
    )

    safe_url = re.sub(
        r"^http://",
        "hxxp://",
        safe_url,
        flags=re.IGNORECASE,
    )

    return safe_url.replace(
        ".",
        "[.]",
    )


def extract_sender_domain(sender):
    """
    Extract only the domain portion of a sender address.

    Example:

        Security Team <alert@example.com>

    becomes:

        example.com
    """

    if not sender:
        return None

    display_name, email_address = parseaddr(
        sender
    )

    if (
        not email_address
        or "@" not in email_address
    ):
        return None

    local_part, domain = email_address.rsplit(
        "@",
        1,
    )

    return domain.lower()


def normalize_hostname(hostname):
    """
    Normalize a hostname for simple comparison.

    For this case, we remove a leading 'www.' because:

        www.example.com

    and:

        example.com

    usually refer to the same organizational web domain.

    IMPORTANT:
    This is only a simple normalization technique.
    It is NOT a full registered-domain parser.
    """

    if not hostname:
        return None

    hostname = hostname.lower()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname


def load_record(record_id):
    """
    Retrieve a specific record from the raw dataset.
    """

    with DATASET_PATH.open(
        "r",
        encoding="utf-8",
        errors="replace",
        newline="",
    ) as csv_file:

        reader = csv.DictReader(
            csv_file
        )

        for current_id, row in enumerate(
            reader,
            start=1,
        ):

            if current_id == record_id:
                return row

    return None


# ---------------------------------------------------------
# LOAD CASE RECORD
# ---------------------------------------------------------

record = load_record(
    TARGET_RECORD_ID
)


if record is None:

    print(
        f"Error: Record {TARGET_RECORD_ID} "
        "was not found."
    )

    raise SystemExit(1)


sender = record.get(
    "sender",
    "",
)

body = record.get(
    "body",
    "",
)


sender_domain = extract_sender_domain(
    sender
)


# ---------------------------------------------------------
# EXTRACT URL INDICATORS
# ---------------------------------------------------------

url_occurrences = URL_PATTERN.findall(
    body
)

unique_urls = unique_preserve_order(
    url_occurrences
)


# ---------------------------------------------------------
# DISPLAY SENDER INFORMATION
# ---------------------------------------------------------

print("=" * 70)
print("CASE-001 IOC STRUCTURE ANALYSIS")
print("=" * 70)

print()
print("SENDER INDICATOR")
print("----------------")

print(
    "Sender domain : "
    f"{defang_domain(sender_domain)}"
)


# ---------------------------------------------------------
# ANALYZE EACH UNIQUE URL
# ---------------------------------------------------------

print()
print("URL INDICATORS")
print("--------------")


for number, url in enumerate(
    unique_urls,
    start=1,
):

    # urlparse() separates the URL into components.
    parsed = urlparse(
        url
    )

    hostname = parsed.hostname

    normalized_hostname = normalize_hostname(
        hostname
    )

    normalized_sender = normalize_hostname(
        sender_domain
    )

    print()
    print(
        f"URL {number}"
    )

    print(
        f"  Indicator      : "
        f"{defang_url(url)}"
    )

    print(
        f"  Scheme         : "
        f"{parsed.scheme or '<missing>'}"
    )

    print(
        f"  Hostname       : "
        f"{defang_domain(hostname)}"
    )

    print(
        f"  Normalized host: "
        f"{defang_domain(normalized_hostname)}"
    )

    print(
        f"  Port           : "
        f"{parsed.port or '<default>'}"
    )

    print(
        f"  Path           : "
        f"{parsed.path or '/'}"
    )

    # We deliberately do not print query parameters.
    #
    # Query strings can sometimes contain tracking IDs,
    # tokens, email addresses, or other sensitive values.
    print(
        f"  Query present  : "
        f"{bool(parsed.query)}"
    )

    print(
        f"  Sender matches : "
        f"{normalized_sender == normalized_hostname}"
    )


print()
print("IMPORTANT")
print("---------")
print(
    "Domain comparison is structural only. "
    "It does not determine whether a domain is "
    "legitimate or malicious."
)
