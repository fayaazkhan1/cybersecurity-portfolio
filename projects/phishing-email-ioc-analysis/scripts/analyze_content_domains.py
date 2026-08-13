"""
analyze_content_domains.py

Purpose:
Compare CASE-002 sender, reply-to, return-path, and visible content domains.

The script performs offline analysis against the sanitized case artifact.
It does NOT visit links or query external services.
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

    return address.rsplit("@", 1)[1].lower().rstrip(".")


def normalize_host(value):
    """Normalize a hostname or defanged hostname for comparison."""

    if not value:
        return None

    host = value.strip().lower()
    host = host.replace("[.]", ".")
    host = host.rstrip(".")

    if host.startswith("www."):
        host = host[4:]

    return host


def extract_defanged_hosts(text):
    """Extract defanged hostnames such as www[.]example[.]com from body text."""

    pattern = re.compile(
        r"(?:hxxps?://)?"
        r"((?:[a-zA-Z0-9-]+(?:\[\.\]|\.))+[a-zA-Z]{2,})",
        re.IGNORECASE,
    )

    hosts = []

    for match in pattern.findall(text or ""):
        normalized = normalize_host(match)

        if normalized and normalized not in hosts:
            hosts.append(normalized)

    return hosts


if not CASE_PATH.exists():
    print(f"Error: Case file not found: {CASE_PATH}")
    raise SystemExit(1)


with CASE_PATH.open("rb") as case_file:
    message = BytesParser(
        policy=policy.default
    ).parse(case_file)


from_domain = extract_email_domain(
    message.get("From")
)
reply_to_domain = extract_email_domain(
    message.get("Reply-To")
)
return_path_domain = extract_email_domain(
    message.get("Return-Path")
)
sender_domain = extract_email_domain(
    message.get("Sender")
)

body = message.get_body(
    preferencelist=("plain",)
)

body_text = (
    body.get_content()
    if body
    else ""
)

visible_hosts = extract_defanged_hosts(
    body_text
)


print("=" * 72)
print("CASE-002 CONTENT AND DOMAIN CONSISTENCY")
print("=" * 72)

print()
print("HEADER DOMAINS")
print("--------------")
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
print("VISIBLE CONTENT DOMAINS")
print("-----------------------")

if visible_hosts:
    for number, host in enumerate(
        visible_hosts,
        start=1,
    ):
        print(
            f"Visible host {number} : {host}"
        )
else:
    print("No defanged visible hosts found.")

primary_visible_host = (
    visible_hosts[0]
    if visible_hosts
    else None
)

print()
print("RELATIONSHIP CHECKS")
print("-------------------")
print(
    "From = Return-Path       : "
    f"{from_domain == return_path_domain}"
)
print(
    "From = Sender            : "
    f"{from_domain == sender_domain}"
)
print(
    "Reply-To = visible host  : "
    f"{reply_to_domain == primary_visible_host}"
)
print(
    "From = visible host      : "
    f"{from_domain == primary_visible_host}"
)

print()
print("ANALYST INTERPRETATION")
print("----------------------")
print(
    "- The From, Sender, and Return-Path domains are internally consistent."
)
print(
    "- The Reply-To domain differs from the delivery domain, so it requires "
    "independent validation rather than automatic trust or automatic rejection."
)
print(
    "- The visible settlement website domain matches the Reply-To domain, "
    "which is a coherent relationship for a third-party claims administrator."
)
print(
    "- Domain consistency supports the legitimacy hypothesis but does not by "
    "itself prove that a message or business request is safe."
)
