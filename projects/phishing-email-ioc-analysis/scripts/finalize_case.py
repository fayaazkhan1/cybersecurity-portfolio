"""
finalize_case.py

Purpose:
Update the structured CASE-001 artifact after the analyst
has completed the investigation.

The triage score helps prioritize the case, but the final
verdict is assigned by the analyst after reviewing all
available evidence.
"""

import json
from pathlib import Path


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

CASE_PATH = Path(
    "data/sanitized/case-001.json"
)


# ---------------------------------------------------------
# VERIFY CASE EXISTS
# ---------------------------------------------------------

if not CASE_PATH.exists():

    print(
        f"Error: Case file not found: {CASE_PATH}"
    )

    raise SystemExit(1)


# ---------------------------------------------------------
# LOAD EXISTING CASE
# ---------------------------------------------------------

case = json.loads(
    CASE_PATH.read_text(
        encoding="utf-8"
    )
)


# ---------------------------------------------------------
# ADD FINAL ANALYST ASSESSMENT
# ---------------------------------------------------------

case["analyst_assessment"] = {
    "verdict": "Malicious - Phishing",
    "confidence": "High",
    "triage_priority": "Critical",

    "mitre_attack": [
        {
            "id": "T1566",
            "name": "Phishing",
            "relationship": "Primary"
        },
        {
            "id": "T1566.002",
            "name": "Spearphishing Link",
            "relationship": (
                "Related - targeting not established"
            )
        }
    ],

    "notes": [
        "Lookalike sender domain observed.",
        (
            "Sender domain did not match the displayed "
            "URL domain."
        ),
        (
            "Account restriction and urgency language "
            "were observed."
        ),
        (
            "The message requested account verification."
        ),
        (
            "VirusTotal enrichment returned malicious "
            "and suspicious detections."
        ),
        (
            "The final verdict was assigned through "
            "analyst review rather than automatically "
            "from the triage score."
        )
    ]
}


# ---------------------------------------------------------
# SAVE UPDATED CASE
# ---------------------------------------------------------

CASE_PATH.write_text(
    json.dumps(
        case,
        indent=2,
        ensure_ascii=False
    ),
    encoding="utf-8"
)


# ---------------------------------------------------------
# DISPLAY RESULT
# ---------------------------------------------------------

print("=" * 60)
print("CASE-001 FINALIZED")
print("=" * 60)

print()
print("Verdict         : Malicious - Phishing")
print("Confidence      : High")
print("Triage Priority : Critical")
print("MITRE ATT&CK    : T1566 - Phishing")

print()
print(
    f"Updated: {CASE_PATH}"
)
