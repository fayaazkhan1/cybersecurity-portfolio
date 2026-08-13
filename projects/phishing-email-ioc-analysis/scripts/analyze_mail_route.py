"""
analyze_mail_route.py

Purpose:
Reconstruct the sanitized CASE-002 email delivery path from
Received headers and summarize transport details.

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
from pathlib import Path


CASE_PATH = Path(
    "data/sanitized/case-002-header-sample.eml"
)


def clean_header(value):
    """Collapse folded header whitespace for readable terminal output."""

    return " ".join(str(value).split())


def extract_from_host(received):
    """Extract the hostname appearing after 'from' when present."""

    match = re.search(
        r"\bfrom\s+([^\s(]+)",
        received,
        re.IGNORECASE,
    )

    return match.group(1) if match else None


def extract_by_host(received):
    """Extract the hostname or label appearing after 'by'."""

    match = re.search(
        r"\bby\s+([^\s;]+)",
        received,
        re.IGNORECASE,
    )

    return match.group(1) if match else None


def extract_ip(received):
    """Extract the first bracketed IPv4 address from a Received header."""

    match = re.search(
        r"\[(\d{1,3}(?:\.\d{1,3}){3})\]",
        received,
    )

    return match.group(1) if match else None


def extract_transport(received):
    """Extract the transport token following 'with'."""

    match = re.search(
        r"\bwith\s+([A-Za-z0-9_-]+)",
        received,
        re.IGNORECASE,
    )

    return match.group(1) if match else None


def extract_tls_version(received):
    """Extract TLS version from Gmail's transport detail when present."""

    match = re.search(
        r"version=([A-Za-z0-9_.-]+)",
        received,
        re.IGNORECASE,
    )

    return match.group(1) if match else None


def extract_cipher(received):
    """Extract negotiated TLS cipher from Gmail's Received header."""

    match = re.search(
        r"cipher=([A-Za-z0-9_-]+)",
        received,
        re.IGNORECASE,
    )

    return match.group(1) if match else None


def classify_hop(received, from_host, by_host):
    """Give each hop a simple analyst-friendly role label."""

    lowered = received.lower()

    if "redacted-mailgun-internal-host" in lowered and "with http" in lowered:
        return "Message submitted into Mailgun infrastructure"

    if from_host and "mailgun.net" in from_host.lower():
        if by_host and "google" in by_host.lower():
            return "Mailgun outbound SMTP delivered message to Google"
        return "Mailgun outbound SMTP hop"

    if by_host and "google" in by_host.lower():
        return "Message received by Google"

    return "Mail transfer hop"


if not CASE_PATH.exists():
    print(f"Error: Case file not found: {CASE_PATH}")
    raise SystemExit(1)


with CASE_PATH.open("rb") as case_file:
    message = BytesParser(
        policy=policy.default
    ).parse(case_file)


received_headers = message.get_all(
    "Received",
    [],
)

if not received_headers:
    print("No Received headers were found.")
    raise SystemExit(0)


# Received headers are prepended by each receiving server.
# Therefore, the oldest hop is normally at the bottom of the
# message. Reverse them to reconstruct the route chronologically.
chronological_headers = list(
    reversed(received_headers)
)


parsed_hops = []

for number, header in enumerate(
    chronological_headers,
    start=1,
):
    clean = clean_header(header)

    from_host = extract_from_host(clean)
    by_host = extract_by_host(clean)
    source_ip = extract_ip(clean)
    transport = extract_transport(clean)
    tls_version = extract_tls_version(clean)
    cipher = extract_cipher(clean)

    parsed_hops.append(
        {
            "number": number,
            "raw": clean,
            "from_host": from_host,
            "by_host": by_host,
            "source_ip": source_ip,
            "transport": transport,
            "tls_version": tls_version,
            "cipher": cipher,
            "role": classify_hop(
                clean,
                from_host,
                by_host,
            ),
        }
    )


external_ips = [
    hop["source_ip"]
    for hop in parsed_hops
    if hop["source_ip"]
]


print("=" * 72)
print("CASE-002 MAIL ROUTE RECONSTRUCTION")
print("=" * 72)

print()
print("ROUTE SUMMARY")
print("-------------")
print(
    f"Received headers analyzed : {len(parsed_hops)}"
)

if external_ips:
    print(
        f"Observed sending IP       : {external_ips[-1]}"
    )
else:
    print(
        "Observed sending IP       : Not found"
    )

print()
print("CHRONOLOGICAL DELIVERY PATH")
print("---------------------------")

for hop in parsed_hops:
    print()
    print(
        f"Hop {hop['number']}"
    )
    print(
        f"  Role      : {hop['role']}"
    )
    print(
        f"  From host : {hop['from_host'] or '<not present>'}"
    )
    print(
        f"  By host   : {hop['by_host'] or '<not present>'}"
    )
    print(
        f"  Source IP : {hop['source_ip'] or '<not present>'}"
    )
    print(
        f"  Transport : {hop['transport'] or '<not present>'}"
    )

    if hop["tls_version"] or hop["cipher"]:
        print(
            f"  TLS       : {hop['tls_version'] or '<unknown>'}"
        )
        print(
            f"  Cipher    : {hop['cipher'] or '<unknown>'}"
        )


print()
print("ANALYST INTERPRETATION")
print("----------------------")
print(
    "- Received headers are shown in chronological order here, even though "
    "mail clients normally store the newest hop first."
)
print(
    "- The sanitized chain shows message submission into Mailgun, followed "
    "by Mailgun outbound delivery to Google's mail infrastructure."
)
print(
    "- The public sending IP observed in the retained header is "
    "204.220.171.193."
)
print(
    "- The Google-facing delivery hop used encrypted SMTP with TLS 1.2 and "
    "the ECDHE-ECDSA-AES128-GCM-SHA256 cipher."
)
print(
    "- Consistent routing through the authenticated mail provider supports "
    "the legitimacy hypothesis, but routing alone does not prove the message "
    "content or business request is trustworthy."
)
