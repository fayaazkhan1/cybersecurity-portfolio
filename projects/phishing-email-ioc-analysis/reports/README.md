# Investigation Reports

This directory separates final recruiter-facing investigation reports from supporting analyst notes.

## Case 001 — Malicious Phishing

### Final Investigation

**[Case 001 — Phishing Email Investigation](case-001-investigation.md)**

Use this as the primary malicious-email report. It contains the executive summary, email metadata, sender and URL analysis, social-engineering findings, VirusTotal enrichment, triage methodology, MITRE ATT&CK mapping, analyst verdict, recommended SOC response, and evidence limitations.

**Verdict:** Malicious — Phishing  
**Confidence:** High  
**Triage priority:** Critical under the lab-developed scoring methodology

### Supporting Notes

[`case-001-notes.md`](case-001-notes.md) contains working analysis notes created during the investigation. It is retained to show the progression from initial observations to the final documented conclusion.

---

## Case 002 — Full Email Header Investigation

### Final Investigation

**[Case 002 — Full Email Header Investigation](case-002-investigation.md)**

This case examines a suspicious-looking settlement notification that was delivered to Spam. Rather than assuming the Spam classification meant phishing, the investigation evaluates SPF, DKIM, DMARC, authentication alignment, From / Reply-To / Return-Path relationships, Received-header routing, TLS transport details, domain consistency, and independent official-source validation.

**Verdict:** Likely Legitimate Bulk Notification — Phishing Not Supported  
**Confidence:** High  
**Primary lesson:** Mailbox placement and suspicious presentation are investigation triggers, not substitutes for evidence-based analyst judgment.

Supporting external-validation notes are retained in [`../docs/case-002-external-validation.md`](../docs/case-002-external-validation.md).

---

## Why the Two Cases Matter Together

The cases intentionally demonstrate opposite analyst outcomes:

| Case | Investigation Focus | Outcome |
|---|---|---|
| Case 001 | Phishing content, IOC extraction, threat enrichment, triage | Escalated as malicious phishing |
| Case 002 | Full headers, authentication, routing, domain validation | Cleared as likely legitimate bulk notification |

This shows that the investigation process is evidence-driven rather than designed to force every suspicious message into a malicious classification.

## Reporting Approach

The final reports intentionally distinguish:

- Observed evidence
- Automated findings
- Threat-intelligence or external-validation context
- Analyst interpretation
- Final verdict
- Evidence limitations

This prevents automated results, mailbox labels, reputation data, or source labels from being treated as substitutes for analyst reasoning.
