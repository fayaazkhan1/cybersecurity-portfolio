"""
risk_scoring.py

Purpose:
Calculate an explainable phishing triage score for CASE-001.

The script combines:

- manual analyst observations
- IOC structural analysis
- VirusTotal enrichment

The score is a lab-developed triage heuristic.

It is NOT:

- an industry-standard severity score
- a machine-learning model
- an automatic malicious/benign verdict
"""

import json

from pathlib import Path


# ---------------------------------------------------------
# FILE LOCATIONS
# ---------------------------------------------------------

VT_RESULT_PATH = Path(
    "outputs/case-001-virustotal-domain.json"
)

OUTPUT_PATH = Path(
    "outputs/case-001-triage-score.json"
)


# ---------------------------------------------------------
# SCORING POLICY
# ---------------------------------------------------------

# Each indicator receives a predefined number of points.
#
# Keeping the weights separate from the observations makes
# the scoring methodology easier to understand and reuse.
WEIGHTS = {
    "lookalike_sender_domain": 20,
    "sender_url_domain_mismatch": 15,
    "account_restriction_language": 10,
    "urgency_language": 10,
    "account_verification_request": 15,
    "virustotal_malicious_detection": 20,
    "virustotal_suspicious_detection": 10,
}


# ---------------------------------------------------------
# MANUAL ANALYST OBSERVATIONS
# ---------------------------------------------------------

# These values come from the manual investigation we
# completed before threat-intelligence enrichment.
#
# True means the indicator was observed.
# False would mean it was not observed.
observations = {
    "lookalike_sender_domain": True,
    "sender_url_domain_mismatch": True,
    "account_restriction_language": True,
    "urgency_language": True,
    "account_verification_request": True,
}


# ---------------------------------------------------------
# LOAD VIRUSTOTAL ENRICHMENT
# ---------------------------------------------------------

if not VT_RESULT_PATH.exists():

    print(
        f"Error: VirusTotal result not found: "
        f"{VT_RESULT_PATH}"
    )

    raise SystemExit(1)


vt_result = json.loads(
    VT_RESULT_PATH.read_text(
        encoding="utf-8"
    )
)


stats = vt_result.get(
    "last_analysis_stats",
    {},
)


malicious_count = stats.get(
    "malicious",
    0,
)

suspicious_count = stats.get(
    "suspicious",
    0,
)


# ---------------------------------------------------------
# CONVERT THREAT INTELLIGENCE INTO BOOLEAN OBSERVATIONS
# ---------------------------------------------------------

observations[
    "virustotal_malicious_detection"
] = malicious_count > 0


observations[
    "virustotal_suspicious_detection"
] = suspicious_count > 0


# ---------------------------------------------------------
# CALCULATE SCORE
# ---------------------------------------------------------

score = 0

scoring_breakdown = []


for indicator, present in observations.items():

    # Get the possible points for this indicator.
    points = WEIGHTS.get(
        indicator,
        0,
    )

    # Award the points only when the indicator is present.
    awarded = points if present else 0

    score += awarded

    # Save a detailed record so the score is explainable.
    scoring_breakdown.append(
        {
            "indicator": indicator,
            "present": present,
            "possible_points": points,
            "awarded_points": awarded,
        }
    )


# ---------------------------------------------------------
# ASSIGN TRIAGE PRIORITY
# ---------------------------------------------------------

if score >= 75:

    triage_priority = "CRITICAL"

elif score >= 50:

    triage_priority = "HIGH"

elif score >= 25:

    triage_priority = "MEDIUM"

else:

    triage_priority = "LOW"


# ---------------------------------------------------------
# BUILD RESULT
# ---------------------------------------------------------

maximum_score = sum(
    WEIGHTS.values()
)


result = {
    "case_id": "CASE-001",
    "score": score,
    "maximum_score": maximum_score,
    "triage_priority": triage_priority,
    "scoring_breakdown": scoring_breakdown,
    "virustotal_context": {
        "malicious": malicious_count,
        "suspicious": suspicious_count,
    },
    "methodology": (
        "Lab-developed rule-based phishing triage "
        "heuristic. The score supports prioritization "
        "and does not replace analyst judgment."
    ),
}


# ---------------------------------------------------------
# SAVE RESULT
# ---------------------------------------------------------

OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)


OUTPUT_PATH.write_text(
    json.dumps(
        result,
        indent=2,
    ),
    encoding="utf-8",
)


# ---------------------------------------------------------
# DISPLAY RESULT
# ---------------------------------------------------------

print("=" * 70)
print("CASE-001 PHISHING TRIAGE")
print("=" * 70)


print()
print("SCORING BREAKDOWN")
print("-----------------")


for item in scoring_breakdown:

    status = (
        "YES"
        if item["present"]
        else "NO"
    )

    print(
        f"{item['indicator']:<38} "
        f"{status:<3} "
        f"+{item['awarded_points']}"
    )


print()
print("-" * 70)

print(
    f"Final score     : "
    f"{score}/{maximum_score}"
)

print(
    f"Triage priority : "
    f"{triage_priority}"
)

print("-" * 70)


print()
print(
    "VirusTotal context:"
)

print(
    f"  Malicious detections  : "
    f"{malicious_count}"
)

print(
    f"  Suspicious detections : "
    f"{suspicious_count}"
)


print()
print(
    "NOTE: This score is a lab-developed triage "
    "heuristic and not an industry-standard "
    "severity score."
)

print(
    f"Saved to: {OUTPUT_PATH}"
)

