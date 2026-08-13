# Investigation Evidence

This directory contains the supporting screenshots for both email investigations. The files are numbered in the order the project was completed, while the main project README shows only a smaller set of recruiter-facing highlights.

## Case 001 — Malicious Phishing

| # | Screenshot | What It Demonstrates |
|---:|---|---|
| 01 | [`01-project-environment.png`](01-project-environment.png) | Python and Git project environment |
| 02 | [`02-dataset-integrity.png`](02-dataset-integrity.png) | Source-dataset integrity verification |
| 03 | [`03-dataset-validation.png`](03-dataset-validation.png) | Programmatic dataset structure and record validation |
| 04 | [`04-case-001-extraction.png`](04-case-001-extraction.png) | Sanitized case extraction with masked identities and defanged indicators |
| 05 | [`05-ioc-structure-analysis.png`](05-ioc-structure-analysis.png) | Sender-domain and URL-host parsing, including the domain mismatch |
| 06 | [`06-threat-intelligence-enrichment.png`](06-threat-intelligence-enrichment.png) | VirusTotal enrichment for the suspicious sender domain |
| 07 | [`07-triage-score.png`](07-triage-score.png) | Explainable rule-based phishing triage |
| 08 | [`08-investigation-report.png`](08-investigation-report.png) | Rendered Case 001 SOC-style investigation report |

**Outcome:** Malicious — Phishing · **Confidence:** High

## Case 002 — Full Email Header Investigation

| # | Screenshot | What It Demonstrates |
|---:|---|---|
| 09 | [`09-case-002-header-analysis.png`](09-case-002-header-analysis.png) | From, Reply-To, Return-Path, authentication results, and retained Received-chain evidence |
| 10 | [`10-case-002-authentication-alignment.png`](10-case-002-authentication-alignment.png) | SPF, DKIM, and DMARC results plus identity alignment |
| 11 | [`11-case-002-mail-route.png`](11-case-002-mail-route.png) | Chronological Mailgun-to-Google delivery-path reconstruction and TLS transport details |
| 12 | [`12-case-002-domain-consistency.png`](12-case-002-domain-consistency.png) | Sender, Reply-To, Return-Path, and visible-site domain relationship checks |
| 13 | [`13-case-002-investigation-report.png`](13-case-002-investigation-report.png) | Final Case 002 analyst assessment and investigation outcome |

**Outcome:** Likely Legitimate Bulk Notification — Phishing Not Supported · **Confidence:** High

## Recruiter-Facing Evidence

The project README intentionally displays only a few representative screenshots. The complete evidence set remains here for deeper review.

The strongest examples are:

- Case 001: threat-intelligence enrichment and explainable triage
- Case 002: authentication alignment and final investigation outcome

This keeps the main project page readable while preserving the full technical trail.

## Safety

- Indicators are defanged where appropriate.
- No VirusTotal API key is shown.
- Raw phishing research data is not published here.
- Case 002 personal identifiers and tracking values were sanitized before publication.
- Screenshots document defensive analysis only.

[Return to the project README](../README.md) · [View investigation reports](../reports/README.md)
