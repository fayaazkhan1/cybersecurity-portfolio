"""
parse_email_headers.py

Purpose:
Parse the sanitized CASE-002 email artifact and display the header
evidence a SOC analyst would review.

The script performs offline parsing only.

It does NOT:
- send email
- contact the sender
- visit links
- perform DNS lookups
- query external threat-intelligence services
"""

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

CASE_PATH = Path(
    "data/sanitized/case-002-header-sample.eml"
)


# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

def extract_email_domain(value):
    """
    Extract the domain from a normal email-style header.

    Examples:

        Name <user@example.com>
        <user@example.com>
        user@example.com

    all become:

        example.com
    """

    if not value:
        return None

    _, address = parseaddr(value)

    if not address or "@" not in address:
        return None

    return address.rsplit("@", 1)[1].lower()


def extract_return_path_domain(value):
    """
    Return-Path is normally wrapped in angle brackets.

    parseaddr() can still parse it, so we reuse the same
    domain-extraction logic.
    """

    return extract_email_domain(value)


def find_auth_result(authentication_results, method):
    """
    Extract a simple authentication verdict such as:

        spf=pass
        dkim=pass
        dmarc=pass

    This is intentionally a small parser for this lab.
    """

    if not authentication_results:
        return "not found"

    pattern = rf"\b{re.escape(method)}=([a-zA-Z0-9_-]+)"

    match = re.search(
        pattern,
        authentication_results,
        re.IGNORECASE,
    )

    if not match:
        return "not found"

    return match.group(1).lower()


# ---------------------------------------------------------
# LOAD MESSAGE
# ---------------------------------------------------------

if not CASE_PATH.exists():

    print(
        f"Error: Case file not found: {CASE_PATH}"
    )

    raise SystemExit(1)


with CASE_PATH.open("rb") as case_file:

    message = BytesParser(
        policy=policy.default
    ).parse(case_file)


# ---------------------------------------------------------
# EXTRACT IMPORTANT HEADERS
# ---------------------------------------------------------

from_header = message.get("From")
reply_to = message.get("Reply-To")
return_path = message.get("Return-Path")
sender = message.get("Sender")
subject = message.get("Subject")
date = message.get("Date")
message_id = message.get("Message-Id")

authentication_results = message.get(
    "Authentication-Results"
)

received_spf = message.get(
    "Received-SPF"
)

received_headers = message.get_all(
    "Received",
    [],
)


# ---------------------------------------------------------
# DOMAIN COMPARISON
# ---------------------------------------------------------

from_domain = extract_email_domain(
    from_header
)

reply_to_domain = extract_email_domain(
    reply_to
)

return_path_domain = extract_return_path_domain(
    return_path
)

sender_domain = extract_email_domain(
    sender
)


# ---------------------------------------------------------
# AUTHENTICATION RESULTS
# ---------------------------------------------------------

spf_result = find_auth_result(
    authentication_results,
    "spf"
)

dkim_result = find_auth_result(
    authentication_results,
    "dkim"
)

dmarc_result = find_auth_result(
    authentication_results,
    "dmarc"
)


# ---------------------------------------------------------
# DISPLAY ANALYST SUMMARY
# ---------------------------------------------------------

print("=" * 72)
print("CASE-002 FULL EMAIL HEADER ANALYSIS")
print("=" * 72)

print()
print("MESSAGE IDENTITY")
print("----------------")

print(
    f"Subject      : {subject}"
)

print(
    f"Date         : {date}"
)

print(
    f"From         : {from_header}"
)

print(
    f"Reply-To     : {reply_to}"
)

print(
    f"Return-Path  : {return_path}"
)

print(
    f"Sender       : {sender}"
)

print(
    f"Message-ID   : {message_id}"
)


print()
print("DOMAIN COMPARISON")
print("-----------------")

print(
    f"From domain        : {from_domain}"
)

print(
    f"Reply-To domain    : {reply_to_domain}"
)

print(
    f"Return-Path domain : {return_path_domain}"
)

print(
    f"Sender domain      : {sender_domain}"
)

print()

print(
    "From = Return-Path : "
    f"{from_domain == return_path_domain}"
)

print(
    "From = Reply-To    : "
    f"{from_domain == reply_to_domain}"
)


print()
print("EMAIL AUTHENTICATION")
print("--------------------")

print(
    f"SPF   : {spf_result.upper()}"
)

print(
    f"DKIM  : {dkim_result.upper()}"
)

print(
    f"DMARC : {dmarc_result.upper()}"
)

print()

print(
    f"Received-SPF header present : "
    f"{bool(received_spf)}"
)


print()
print("RECEIVED CHAIN")
print("--------------")

print(
    f"Received header count: "
    f"{len(received_headers)}"
)


for number, received in enumerate(
    received_headers,
    start=1,
):

    # Collapse folded header whitespace so the terminal output
    # stays readable.
    clean_received = " ".join(
        str(received).split()
    )

    print()
    print(
        f"Hop {number}:"
    )

    print(
        clean_received
    )


print()
print("ANALYST NOTES")
print("-------------")

print(
    "- SPF, DKIM, and DMARC results should be interpreted "
    "together rather than independently."
)

print(
    "- A Reply-To domain difference is an investigation "
    "indicator, not automatic proof of phishing."
)

print(
    "- Authentication proves authorized sending/alignment; "
    "it does not by itself prove that message content is safe."
)

print(
    "- This artifact is sanitized and intentionally omits "
    "personalized identifiers and tracking tokens."
)
