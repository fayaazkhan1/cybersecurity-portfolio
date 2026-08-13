"""
analyze_links.py

Purpose:
Analyze links contained in the sanitized phishing case.

The script identifies:
- plain-text URL indicators
- HTML href destinations
- repeated links
- unique links

It performs TEXT ANALYSIS ONLY.

It does not:
- visit websites
- resolve domains
- make HTTP requests
- perform DNS lookups
"""

import csv
import re

from pathlib import Path


DATASET_PATH = Path("data/raw/Nazario.csv")

TARGET_RECORD_ID = 27

csv.field_size_limit(
    10 * 1024 * 1024
)


# Detect ordinary URL text.
URL_PATTERN = re.compile(
    r"\b(?:https?://|hxxps?://|www\.)"
    r"[^\s<>'\"]+",
    re.IGNORECASE,
)


# Detect links inside HTML such as:
#
# <a href="https://example.com">
#
# Group 1 contains the destination.
HREF_PATTERN = re.compile(
    r"""href\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def defang(value):
    """
    Defang an indicator for safe terminal display.
    """

    if not value:
        return value

    value = re.sub(
        r"^https://",
        "hxxps://",
        value,
        flags=re.IGNORECASE,
    )

    value = re.sub(
        r"^http://",
        "hxxp://",
        value,
        flags=re.IGNORECASE,
    )

    return value.replace(
        ".",
        "[.]",
    )


def unique_preserve_order(items):
    """
    Remove duplicates without changing original order.
    """

    seen = set()
    result = []

    for item in items:

        if item not in seen:

            seen.add(item)

            result.append(item)

    return result


def load_record(record_id):
    """
    Retrieve a specific dataset record.
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


record = load_record(
    TARGET_RECORD_ID
)


if record is None:

    print(
        f"Record {TARGET_RECORD_ID} "
        "was not found."
    )

    raise SystemExit(1)


body = record.get(
    "body",
    "",
)


# Find every URL occurrence.
url_occurrences = URL_PATTERN.findall(
    body
)


# Remove duplicates.
unique_urls = unique_preserve_order(
    url_occurrences
)


# Specifically inspect HTML href attributes.
href_occurrences = HREF_PATTERN.findall(
    body
)


unique_hrefs = unique_preserve_order(
    href_occurrences
)


print("=" * 70)

print(
    "CASE-001 LINK ANALYSIS"
)

print("=" * 70)


print()
print(
    "PLAIN-TEXT URL ANALYSIS"
)

print(
    "-----------------------"
)

print(
    f"URL occurrences : "
    f"{len(url_occurrences)}"
)

print(
    f"Unique URLs     : "
    f"{len(unique_urls)}"
)


for number, url in enumerate(
    unique_urls,
    start=1,
):

    print(
        f"{number}. {defang(url)}"
    )


print()
print(
    "HTML HREF ANALYSIS"
)

print(
    "------------------"
)

print(
    f"href occurrences : "
    f"{len(href_occurrences)}"
)

print(
    f"Unique hrefs     : "
    f"{len(unique_hrefs)}"
)


if unique_hrefs:

    for number, href in enumerate(
        unique_hrefs,
        start=1,
    ):

        print(
            f"{number}. {defang(href)}"
        )

else:

    print(
        "No HTML href destinations detected."
    )
