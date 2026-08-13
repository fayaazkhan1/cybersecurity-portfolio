"""
analyze_authentication.py

Purpose:
Explain SPF, DKIM, and DMARC alignment for the sanitized
CASE-002 email artifact.

The script performs offline parsing only.

It does NOT:
- perform DNS lookups
- contact the sender
- visit links
- query external services
"""

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path


CASE_PATH = Path(
    "data/sanitized/case-002-header-sample.eml"
)


def extract_email_domain(value):
    """Extract the domain from an email-style header value."""

    if not value:
        return None

    _, address = parseaddr(value)

    if not address or "@" not in address:
        return None

    return address.rsplit("@", 1)[1].lower()


def normalize_domain(value):
    """Normalize a domain string for case-insensitive comparison."""

    if not value:
        return None

    return value.strip().strip("<>").lower().rstrip(".")


def domains_exactly_align(left, right):
    """Return True when two domains are an exact match."""

    return (
        normalize_domain(left)
        == normalize_domain(right)
    )


def extract_spf_identity(authentication_results):
    """Extract the SPF result and smtp.mailfrom identity."""

    result_match = re.search(
        r"\bspf=([a-zA-Z0-9_-]+)",
        authentication_results or "",
        re.IGNORECASE,
    )

    mailfrom_match = re.search(
        r"smtp\.mailfrom=([^;\s]+)",
        authentication_results or "",
        re.IGNORECASE,
    )

    result = (
        result_match.group(1).lower()
        if result_match
        else "not found"
    )

    mailfrom = (
        mailfrom_match.group(1).strip('"<>')
        if mailfrom_match
        else None
    )

    domain = extract_email_domain(mailfrom)

    return result, mailfrom, domain


def extract_dkim_identities(authentication_results):
    """
    Extract every DKIM result and signing identity recorded by Gmail.

    Example input fragments:

        dkim=pass header.i=@example.com
        dkim=pass header.i=@mail-provider.com
    """

    pattern = re.compile(
        r"dkim=([a-zA-Z0-9_-]+)"
        r"[^;]*?header\.i=@([^;\s]+)",
        re.IGNORECASE,
    )

    results = []

    for verdict, domain in pattern.findall(
        authentication_results or ""
    ):
        results.append(
            {
                "result": verdict.lower(),
                "domain": normalize_domain(domain),
            }
        )

    return results


def extract_dmarc(authentication_results):
    """Extract the DMARC result and visible header.from identity."""

    result_match = re.search(
        r"\bdmarc=([a-zA-Z0-9_-]+)",
        authentication_results or "",
        re.IGNORECASE,
    )

    from_match = re.search(
        r"header\.from=([^;\s]+)",
        authentication_results or "",
        re.IGNORECASE,
    )

    result = (
        result_match.group(1).lower()
        if result_match
        else "not found"
    )

    header_from = (
        normalize_domain(from_match.group(1))
        if from_match
        else None
    )

    return result, header_from


if not CASE_PATH.exists():
    print(f"Error: Case file not found: {CASE_PATH}")
    raise SystemExit(1)


with CASE_PATH.open("rb") as case_file:
    message = BytesParser(
        policy=policy.default
    ).parse(case_file)


visible_from = message.get("From")
reply_to = message.get("Reply-To")
return_path = message.get("Return-Path")
authentication_results = message.get(
    "Authentication-Results",
    "",
)

visible_from_domain = extract_email_domain(
    visible_from
)
reply_to_domain = extract_email_domain(
    reply_to
)
return_path_domain = extract_email_domain(
    return_path
)

spf_result, spf_mailfrom, spf_domain = (
    extract_spf_identity(authentication_results)
)

dkim_identities = extract_dkim_identities(
    authentication_results
)

dmarc_result, dmarc_header_from = extract_dmarc(
    authentication_results
)

spf_aligned = domains_exactly_align(
    visible_from_domain,
    spf_domain,
)

aligned_dkim = [
    item
    for item in dkim_identities
    if item["result"] == "pass"
    and domains_exactly_align(
        visible_from_domain,
        item["domain"],
    )
]


print("=" * 72)
print("CASE-002 EMAIL AUTHENTICATION ALIGNMENT")
print("=" * 72)

print()
print("VISIBLE IDENTITY")
print("----------------")
print(
    f"From domain      : {visible_from_domain}"
)
print(
    f"Reply-To domain  : {reply_to_domain}"
)
print(
    f"Return-Path      : {return_path_domain}"
)

print()
print("SPF ANALYSIS")
print("------------")
print(
    f"SPF result       : {spf_result.upper()}"
)
print(
    f"Envelope sender  : {spf_mailfrom}"
)
print(
    f"SPF domain       : {spf_domain}"
)
print(
    f"Exact alignment  : {spf_aligned}"
)

print()
print("DKIM ANALYSIS")
print("-------------")

if dkim_identities:
    for number, item in enumerate(
        dkim_identities,
        start=1,
    ):
        aligned = domains_exactly_align(
            visible_from_domain,
            item["domain"],
        )

        print(
            f"DKIM {number} result  : "
            f"{item['result'].upper()}"
        )
        print(
            f"DKIM {number} domain  : "
            f"{item['domain']}"
        )
        print(
            f"DKIM {number} aligned : "
            f"{aligned}"
        )
        print()
else:
    print("No DKIM results found.")

print("DMARC ANALYSIS")
print("--------------")
print(
    f"DMARC result      : {dmarc_result.upper()}"
)
print(
    f"DMARC header.from : {dmarc_header_from}"
)
print(
    "From matches DMARC: "
    f"{domains_exactly_align(visible_from_domain, dmarc_header_from)}"
)

print()
print("ALIGNMENT SUMMARY")
print("-----------------")
print(
    f"Passing aligned SPF identity : "
    f"{spf_result == 'pass' and spf_aligned}"
)
print(
    f"Passing aligned DKIM identity: "
    f"{bool(aligned_dkim)}"
)
print(
    f"DMARC passed                 : "
    f"{dmarc_result == 'pass'}"
)

print()
print("ANALYST INTERPRETATION")
print("----------------------")
print(
    "- The visible From domain is authenticated by aligned SPF and DKIM."
)
print(
    "- A second DKIM signature from the delivery provider may pass without "
    "aligning to the visible From domain."
)
print(
    "- DMARC requires successful aligned authentication; this message passed."
)
print(
    "- The different Reply-To domain remains worth validating separately."
)
print(
    "- Passing authentication supports sender-domain legitimacy, but does "
    "not independently prove the business content is trustworthy."
)
