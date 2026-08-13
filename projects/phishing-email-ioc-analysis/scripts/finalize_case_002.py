"""
finalize_case_002.py

Purpose:
Create a structured analyst assessment for CASE-002 after the
header, authentication, routing, domain, and external-validation
work has been completed.

The final verdict is an analyst decision. This script records the
conclusion; it does not automatically decide whether the message
is phishing.
"""

import json
from pathlib import Path


OUTPUT_PATH = Path(
    "outputs/case-002-final-assessment.json"
)


assessment = {
    "case_id": "CASE-002",
    "verdict": (
        "Likely Legitimate Bulk Notification - "
        "Phishing Not Supported"
    ),
    "confidence": "High",
    "mailbox_classification": "Spam",
    "authentication": {
        "spf": "pass",
        "spf_aligned": True,
        "dkim": [
            {
                "domain": "mg.abdataclassactionmail.com",
                "result": "pass",
                "aligned": True,
            },
            {
                "domain": "mailgun.org",
                "result": "pass",
                "aligned": False,
                "context": "delivery-provider signature",
            },
        ],
        "dmarc": "pass",
    },
    "identity_relationships": {
        "from_domain": "mg.abdataclassactionmail.com",
        "return_path_domain": "mg.abdataclassactionmail.com",
        "sender_domain": "mg.abdataclassactionmail.com",
        "reply_to_domain": "googleassistantprivacylitigation.com",
        "visible_site_domain": "googleassistantprivacylitigation.com",
        "from_return_path_match": True,
        "from_sender_match": True,
        "reply_to_visible_site_match": True,
    },
    "routing": {
        "provider": "Mailgun",
        "observed_sending_ip": "204.220.171.193",
        "destination_provider": "Google",
        "transport": "UTF8SMTPS",
        "tls_version": "TLS1_2",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
    },
    "external_validation": {
        "official_site_context_confirmed": True,
        "reply_to_domain_consistent_with_official_site": True,
        "claim_deadline_context_consistent": True,
        "claims_administrator": "A.B. Data, Ltd.",
        "notes_file": "docs/case-002-external-validation.md",
    },
    "analyst_reasoning": [
        "Mailbox spam placement was treated as an investigation trigger, not a verdict.",
        "SPF passed and aligned with the visible From domain.",
        "At least one DKIM signature passed and aligned with the visible From domain.",
        "DMARC passed.",
        "The Received chain was consistent with Mailgun delivery to Google.",
        "From, Sender, and Return-Path domains were internally consistent.",
        "The Reply-To domain matched the visible settlement website domain.",
        "Independent official-source validation supported the settlement context.",
        "No observed evidence supported sender spoofing or phishing classification.",
    ],
    "limitations": [
        "The public artifact is sanitized and omits personalized identifiers and tracking tokens.",
        "Passing authentication does not independently prove that message content is trustworthy.",
        "External website consistency is supporting evidence rather than cryptographic proof of business ownership relationships.",
    ],
}


OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)


OUTPUT_PATH.write_text(
    json.dumps(
        assessment,
        indent=2,
    ),
    encoding="utf-8",
)


print("=" * 72)
print("CASE-002 FINAL ANALYST ASSESSMENT")
print("=" * 72)

print()
print(
    "Verdict     : Likely Legitimate Bulk Notification"
)
print(
    "              Phishing Not Supported"
)
print(
    "Confidence  : High"
)
print(
    "Mailbox     : Spam"
)

print()
print("KEY EVIDENCE")
print("------------")
print("SPF aligned              : True")
print("Aligned DKIM             : True")
print("DMARC passed             : True")
print("From / Return-Path match : True")
print("Reply-To / site match    : True")
print("Mail route consistent    : True")
print("External context valid   : True")

print()
print("ANALYST DECISION")
print("----------------")
print(
    "The available evidence supports authenticated and internally "
    "consistent bulk delivery. No observed evidence supports a "
    "phishing classification."
)

print()
print(
    f"Saved to: {OUTPUT_PATH}"
)
