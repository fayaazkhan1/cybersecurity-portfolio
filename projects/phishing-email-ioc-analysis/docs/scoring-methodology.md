# Phishing Triage Scoring Methodology

## Purpose

This project uses a transparent rule-based scoring model to assist with phishing email triage.

The model converts observable phishing indicators into a repeatable prioritization score.

It is intended for educational and portfolio use and is not an industry-standard risk score, machine-learning model, or replacement for analyst judgment.

## Scoring Rules

| Indicator | Points |
|---|---:|
| Lookalike or typosquatted sender domain | 20 |
| Sender domain differs from displayed URL domain | 15 |
| Account restriction or suspension language | 10 |
| Time-pressure or urgency language | 10 |
| Request to verify or update account information | 15 |
| VirusTotal malicious detections greater than zero | 20 |
| VirusTotal suspicious detections greater than zero | 10 |

## Triage Thresholds

| Score | Triage Priority |
|---:|---|
| 0–24 | Low |
| 25–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

## Interpretation

The score assists with prioritization rather than automatically determining whether an email is malicious.

A higher score indicates that multiple suspicious characteristics are present and that the message warrants increased analyst attention.

The final verdict remains an analyst decision based on the complete available evidence.

## Limitations

- Indicator weights were created specifically for this lab and are subjective.
- Current threat-intelligence results may not represent historical reputation.
- Legitimate emails can occasionally contain urgent language or domain differences.
- Some phishing campaigns may not contain the indicators represented by this model.
- The model does not replace full email-header analysis, sandboxing, endpoint telemetry, or additional incident context.
