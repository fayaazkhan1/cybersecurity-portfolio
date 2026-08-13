# Phishing Email Investigation & IOC Enrichment

![Status](https://img.shields.io/badge/Status-Case_001_Complete-2ea44f)
![Focus](https://img.shields.io/badge/Focus-SOC_Investigation-1f6feb)
![Python](https://img.shields.io/badge/Python-Automation-3776AB?logo=python&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-T1566-red)

## Overview

This project demonstrates an end-to-end phishing investigation workflow using a public research dataset, Python automation, IOC analysis, VirusTotal enrichment, transparent triage scoring, and SOC-style reporting.

The goal was not simply to label a message as phishing. The workflow separates **source data**, **automated processing**, **analyst observations**, **threat-intelligence context**, and the **final analyst verdict**.

### Case 001 result

- **Verdict:** Malicious — Phishing
- **Confidence:** High
- **Triage priority:** Critical under the lab-developed scoring model
- **Primary MITRE ATT&CK mapping:** `T1566 — Phishing`
- **Suspicious sender domain:** `uusaa[.]com`
- **Displayed URL host:** `usaa[.]com`
- **VirusTotal context:** 3 malicious and 1 suspicious detections at the time of lookup

> The triage score is a lab-developed prioritization heuristic, not an industry-standard severity score.

## Why This Project Matters

Phishing investigations require more than spotting suspicious wording. A SOC analyst should be able to preserve evidence, identify indicators, compare sender and destination infrastructure, enrich IOCs, document limitations, and communicate a defensible conclusion.

This project demonstrates that process from intake through reporting.

## Investigation Workflow

```text
Public research dataset
        ↓
Integrity verification
        ↓
Dataset inspection and validation
        ↓
Case selection
        ↓
Sanitization and IOC extraction
        ↓
URL and sender-domain analysis
        ↓
HTML link inspection
        ↓
VirusTotal enrichment
        ↓
Explainable triage scoring
        ↓
Analyst review
        ↓
Final verdict and SOC report
```

## Key Findings

### 1. Sender-domain discrepancy

The message presented itself as USAA communication but used the sender domain:

```text
uusaa[.]com
```

The additional `u` is consistent with a potential lookalike or typosquatting technique.

### 2. Sender and displayed URL did not match

The displayed URL normalized to:

```text
usaa[.]com
```

while the sender domain was:

```text
uusaa[.]com
```

This mismatch increased suspicion but was treated as one indicator among several rather than proof on its own.

### 3. Social-engineering indicators

The message used:

- Account-restriction language
- A 24-hour deadline
- An account-verification request
- Financial-services impersonation
- Trust and authority language

### 4. Threat-intelligence enrichment

The sender domain was queried through the VirusTotal API for an existing domain report. At the time of analysis, the response included:

| Classification | Engines |
|---|---:|
| Malicious | 3 |
| Suspicious | 1 |
| Harmless | 52 |
| Undetected | 35 |

Because the email dates to 2015, the current reputation result is documented as **supporting context**, not definitive evidence of the domain's historical state.

### 5. Explainable triage model

A documented rule-based scoring model assigned points for observable indicators such as a lookalike sender domain, urgency, domain mismatch, verification language, and VirusTotal detections.

**Case 001 score:** `100/100`  
**Triage priority:** `Critical`

The model supports prioritization; the final malicious verdict remained an analyst decision.

## Case 001 Report

The full SOC-style investigation includes the executive summary, metadata, sender analysis, social-engineering analysis, IOC structure, threat-intelligence enrichment, triage methodology, MITRE ATT&CK mapping, recommended response actions, and evidence limitations.

**[Read the full Case 001 investigation report](reports/case-001-investigation.md)**

Supporting analyst notes are also available in [`reports/case-001-notes.md`](reports/case-001-notes.md).

## Automation Developed

| Script | Purpose |
|---|---|
| [`inspect_dataset.py`](scripts/inspect_dataset.py) | Validate dataset structure and record counts |
| [`diagnose_dataset.py`](scripts/diagnose_dataset.py) | Troubleshoot selection assumptions and dataset characteristics |
| [`select_case.py`](scripts/select_case.py) | Identify useful phishing samples for investigation |
| [`create_case.py`](scripts/create_case.py) | Create a sanitized structured case artifact |
| [`review_case.py`](scripts/review_case.py) | Present sanitized case evidence for analyst review |
| [`analyze_links.py`](scripts/analyze_links.py) | Compare URL occurrences and HTML `href` destinations |
| [`analyze_iocs.py`](scripts/analyze_iocs.py) | Parse URL structure and compare sender/URL domains |
| [`threat_enrichment.py`](scripts/threat_enrichment.py) | Query VirusTotal API v3 for existing domain reputation data |
| [`risk_scoring.py`](scripts/risk_scoring.py) | Calculate an explainable phishing triage score |
| [`finalize_case.py`](scripts/finalize_case.py) | Record the analyst's final verdict in structured JSON |

## Repository Structure

```text
phishing-email-ioc-analysis/
├── data/
│   └── sanitized/           # Public-safe structured case artifact
├── docs/
│   └── scoring-methodology.md
├── outputs/                 # Sanitized enrichment and scoring results
├── reports/
│   ├── case-001-investigation.md
│   └── case-001-notes.md
├── scripts/                 # Analysis and automation scripts
├── .gitignore
├── requirements.txt
└── README.md
```

The raw dataset, `.env`, API key, and Python virtual environment are intentionally excluded from Git.

## Evidence Limitations

Case 001 was derived from a CSV research dataset rather than the complete original `.eml` file. The following evidence was therefore unavailable:

- Full `Received:` header chain
- SPF result
- DKIM result
- DMARC result
- Original MIME structure
- Recipient endpoint telemetry
- Proxy/browser evidence of link interaction
- Evidence of credential submission or account compromise

These gaps are documented rather than inferred.

## Skills Demonstrated

- Phishing email analysis
- IOC extraction and defanging
- URL parsing and deduplication
- Lookalike-domain analysis
- Threat-intelligence enrichment
- VirusTotal API integration
- Python scripting
- Regular expressions
- JSON processing
- Security data sanitization
- Explainable rule-based triage
- MITRE ATT&CK mapping
- SOC investigation documentation
- Incident-response recommendations
- Evidence limitation analysis

## Current Status

**Case 001 is complete.** Planned expansion includes a full-header `.eml` investigation to demonstrate SPF, DKIM, DMARC, routing-header analysis, and a separate attachment/hash-focused case.

## Safe-Handling Notes

- Live indicators are defanged in public documentation.
- The VirusTotal API key is loaded from a local `.env` file and is not committed.
- Raw research data is excluded from the repository.
- Threat-intelligence results are treated as context, not automatic verdicts.

## Disclaimer

This project is for defensive security education and portfolio demonstration. Analysis was performed on public research data and sanitized artifacts. No live phishing infrastructure was intentionally accessed through the analysis scripts.
