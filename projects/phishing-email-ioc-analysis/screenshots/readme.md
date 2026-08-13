# Investigation Evidence

This directory contains supporting evidence for the phishing email investigation project. The screenshots are ordered to follow the investigation workflow from environment setup through final reporting.

| # | Screenshot | What It Demonstrates |
|---:|---|---|
| 01 | [`01-project-environment.png`](01-project-environment.png) | Python and Git environment used for the project |
| 02 | [`02-dataset-integrity.png`](02-dataset-integrity.png) | Dataset integrity verification using the published checksum |
| 03 | [`03-dataset-validation.png`](03-dataset-validation.png) | Programmatic dataset inspection, fields, record count, and label distribution |
| 04 | [`04-case-001-extraction.png`](04-case-001-extraction.png) | Sanitized Case 001 extraction with masked identities and defanged URL evidence |
| 05 | [`05-ioc-structure-analysis.png`](05-ioc-structure-analysis.png) | Sender-domain and URL-host parsing, including the domain mismatch finding |
| 06 | [`06-threat-intelligence-enrichment.png`](06-threat-intelligence-enrichment.png) | VirusTotal API enrichment for the suspicious sender domain |
| 07 | [`07-triage-score.png`](07-triage-score.png) | Transparent rule-based phishing triage scoring and supporting detections |
| 08 | [`08-investigation-report.png`](08-investigation-report.png) | GitHub-rendered final SOC-style investigation report |

## Recruiter-Facing Evidence

The main project README highlights screenshots **04–08** because they show the investigation itself: evidence extraction, IOC analysis, threat-intelligence enrichment, automated triage, and final reporting.

Screenshots **01–03** are retained here as supporting technical evidence but are intentionally not emphasized in the main README.

## Safety

- Indicators are defanged where appropriate.
- No VirusTotal API key is shown in the screenshots.
- Raw phishing research data is not published in this directory.
- Screenshots are evidence of defensive analysis only.

[Return to the project README](../README.md)
