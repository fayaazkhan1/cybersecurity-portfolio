"""
diagnose_dataset.py

Purpose:
Understand why no candidate phishing emails were selected.

This script DOES NOT print:
- email bodies
- sender addresses
- live URLs

It only counts characteristics of the dataset.
"""

import ast
import csv
import re
from pathlib import Path


DATASET_PATH = Path("data/raw/Nazario.csv")

# Allow large email-body fields.
csv.field_size_limit(10 * 1024 * 1024)


# Look for common URL forms inside an email body.
#
# Examples this can recognize:
#   http://...
#   https://...
#   hxxp://...
#   hxxps://...
#   www....
#
# We only COUNT matches. We do not display them.
URL_PATTERN = re.compile(
    r"\b(?:https?://|hxxps?://|www\.)[^\s<>'\"]+",
    re.IGNORECASE,
)


def count_preextracted_urls(raw_urls):
    """
    Count indicators from the dataset's existing `urls` column.

    We try to parse it as a Python-style list first.
    If that doesn't work, we safely fall back to counting
    URL-like patterns in the field.
    """

    if not raw_urls:
        return 0

    raw_urls = raw_urls.strip()

    if raw_urls.lower() in {"", "[]", "none", "null", "nan"}:
        return 0

    try:
        parsed = ast.literal_eval(raw_urls)

        if isinstance(parsed, (list, tuple, set)):
            return len(parsed)

    except (ValueError, SyntaxError):
        pass

    return len(URL_PATTERN.findall(raw_urls))


total = 0
has_subject = 0
body_over_100 = 0
nonempty_url_column = 0
parsed_url_column = 0
body_contains_url = 0
would_be_candidate = 0


with DATASET_PATH.open(
    "r",
    encoding="utf-8",
    errors="replace",
    newline=""
) as csv_file:

    reader = csv.DictReader(csv_file)

    for row in reader:
        total += 1

        subject = (row.get("subject") or "").strip()
        body = row.get("body") or ""
        raw_urls = (row.get("urls") or "").strip()

        if subject:
            has_subject += 1

        if len(body) >= 100:
            body_over_100 += 1

        if raw_urls and raw_urls.lower() not in {
            "[]",
            "none",
            "null",
            "nan",
        }:
            nonempty_url_column += 1

        url_column_count = count_preextracted_urls(raw_urls)

        if url_column_count > 0:
            parsed_url_column += 1

        body_url_count = len(URL_PATTERN.findall(body))

        if body_url_count > 0:
            body_contains_url += 1

        total_url_count = max(
            url_column_count,
            body_url_count,
        )

        if (
            subject
            and len(body) >= 100
            and total_url_count > 0
        ):
            would_be_candidate += 1


print("Dataset diagnostic")
print("==================")
print(f"Total records:                   {total}")
print(f"Records with subject:            {has_subject}")
print(f"Records with body >= 100 chars:  {body_over_100}")
print(f"Non-empty `urls` fields:         {nonempty_url_column}")
print(f"Usable URLs from `urls` field:   {parsed_url_column}")
print(f"URLs detected inside body:       {body_contains_url}")
print(f"Records passing new criteria:    {would_be_candidate}")
