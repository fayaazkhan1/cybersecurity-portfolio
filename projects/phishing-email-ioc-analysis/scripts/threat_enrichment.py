"""
threat_enrichment.py

Purpose:
Enrich a phishing indicator using the VirusTotal API.

For CASE-001, the initial IOC is the suspicious sender domain:

    uusaa.com

The script:
1. Loads the VirusTotal API key from .env.
2. Queries the VirusTotal API v3 domain endpoint.
3. Extracts a small set of useful reputation fields.
4. Displays an analyst-friendly summary.
5. Saves a sanitized JSON result.

IMPORTANT:
- The API key is never printed.
- The API key is never written to the output file.
- This script requests an existing report.
- It does not submit files or execute content.
"""

import json
import os

from pathlib import Path

import requests
from dotenv import load_dotenv


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

DOMAIN = "uusaa.com"

OUTPUT_PATH = Path(
    "outputs/case-001-virustotal-domain.json"
)

VT_ENDPOINT = (
    "https://www.virustotal.com/api/v3/domains/"
    f"{DOMAIN}"
)


# ---------------------------------------------------------
# LOAD API KEY
# ---------------------------------------------------------

# load_dotenv() reads variables stored inside the .env file
# and makes them available through os.getenv().
load_dotenv()


api_key = os.getenv(
    "VT_API_KEY"
)


if not api_key:

    print(
        "Error: VT_API_KEY was not found."
    )

    print(
        "Add it to the project's .env file first."
    )

    raise SystemExit(1)


# ---------------------------------------------------------
# BUILD HTTP REQUEST
# ---------------------------------------------------------

# VirusTotal expects the API key inside a request header
# named x-apikey.
headers = {
    "x-apikey": api_key,
}


print(
    f"Querying VirusTotal for domain: {DOMAIN}"
)


try:

    response = requests.get(
        VT_ENDPOINT,
        headers=headers,
        timeout=15,
    )

except requests.RequestException as error:

    print(
        f"Network/API error: {error}"
    )

    raise SystemExit(1)


# ---------------------------------------------------------
# HANDLE COMMON RESPONSES
# ---------------------------------------------------------

if response.status_code == 404:

    print()
    print(
        "No existing VirusTotal domain report was found."
    )

    print(
        "This does NOT mean the domain is benign."
    )

    raise SystemExit(0)


if response.status_code == 401:

    print(
        "Error: VirusTotal rejected the API key."
    )

    raise SystemExit(1)


if response.status_code == 429:

    print(
        "Error: VirusTotal rate limit reached."
    )

    print(
        "Wait before making another request."
    )

    raise SystemExit(1)


if response.status_code != 200:

    print(
        "VirusTotal returned unexpected "
        f"HTTP status {response.status_code}."
    )

    raise SystemExit(1)


# ---------------------------------------------------------
# PARSE RESPONSE
# ---------------------------------------------------------

report = response.json()


data = report.get(
    "data",
    {}
)

attributes = data.get(
    "attributes",
    {}
)


analysis_stats = attributes.get(
    "last_analysis_stats",
    {}
)


# Individual engines can classify a domain as:
#
# malicious
# suspicious
# harmless
# undetected
# timeout
#
# We only keep aggregate counts in the public project output.
malicious = analysis_stats.get(
    "malicious",
    0,
)

suspicious = analysis_stats.get(
    "suspicious",
    0,
)

harmless = analysis_stats.get(
    "harmless",
    0,
)

undetected = analysis_stats.get(
    "undetected",
    0,
)


reputation = attributes.get(
    "reputation"
)


categories = attributes.get(
    "categories",
    {}
)


# ---------------------------------------------------------
# BUILD SANITIZED RESULT
# ---------------------------------------------------------

result = {
    "case_id": "CASE-001",
    "indicator_type": "domain",
    "indicator": "uusaa[.]com",
    "source": "VirusTotal API v3",
    "lookup_type": "existing_domain_report",
    "last_analysis_stats": {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
    },
    "reputation": reputation,
    "categories": categories,
    "analyst_note": (
        "VirusTotal results reflect available/current "
        "reputation data at the time of lookup and do not "
        "necessarily describe the domain's historical state "
        "when the email was sent in 2015."
    ),
}


# ---------------------------------------------------------
# SAVE RESULT
# ---------------------------------------------------------

OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)


with OUTPUT_PATH.open(
    "w",
    encoding="utf-8",
) as output_file:

    json.dump(
        result,
        output_file,
        indent=2,
        ensure_ascii=False,
    )


# ---------------------------------------------------------
# DISPLAY SUMMARY
# ---------------------------------------------------------

print()
print("=" * 60)
print("VIRUSTOTAL DOMAIN ENRICHMENT")
print("=" * 60)

print(
    f"Indicator   : uusaa[.]com"
)

print(
    f"Malicious   : {malicious}"
)

print(
    f"Suspicious  : {suspicious}"
)

print(
    f"Harmless    : {harmless}"
)

print(
    f"Undetected  : {undetected}"
)

print(
    f"Reputation  : {reputation}"
)


print()
print(
    f"Saved to: {OUTPUT_PATH}"
)

print()
print(
    "NOTE: This is current/available threat-intelligence "
    "context, not proof of the domain's state in 2015."
)
