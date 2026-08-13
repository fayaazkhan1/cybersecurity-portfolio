# Cybersecurity Projects

This directory contains my larger hands-on cybersecurity projects. Each project is documented to show the problem being investigated, the tools used, the evidence collected, the analysis performed, and the final outcome.

## Featured Projects

| Project | Focus | Tools / Skills | Evidence |
|---|---|---|---|
| [Active Directory Password Spray Detection & Investigation Lab](active-directory-wazuh-detection-lab/) | Detect and investigate repeated authentication failures in an isolated Active Directory environment | Wazuh, Windows Server, Active Directory, Event ID 4625, custom correlation rules, MITRE ATT&CK | [Investigation report](active-directory-wazuh-detection-lab/reports/password-spray-investigation.md) · [Detection rule](active-directory-wazuh-detection-lab/detections/password-spray-rule.xml) |
| [Phishing Email Investigation & IOC Enrichment](phishing-email-ioc-analysis/) | Investigate both a malicious phishing sample and a suspicious-looking but likely legitimate bulk message | Python, VirusTotal API, IOC analysis, SPF/DKIM/DMARC, full email headers, mail routing, threat intelligence, false-positive reduction | [Case 001](phishing-email-ioc-analysis/reports/case-001-investigation.md) · [Case 002](phishing-email-ioc-analysis/reports/case-002-investigation.md) · [Evidence](phishing-email-ioc-analysis/screenshots/readme.md) |

## Why These Projects Matter Together

The portfolio is designed around practical SOC and Blue Team workflows rather than isolated tool demonstrations.

```text
Security event or suspicious artifact
        ↓
Data collection and validation
        ↓
Detection / triage
        ↓
Investigation
        ↓
Threat or business context
        ↓
Analyst conclusion
        ↓
Documented response / disposition
```

The email-investigation project deliberately includes two opposite outcomes: one true positive that was escalated as phishing and one suspicious-looking message that was cleared after authentication, routing, and domain validation. This demonstrates both threat detection and false-positive reduction.

I prioritize accurate documentation, reproducible steps, evidence-backed conclusions, and clear limitations when data is unavailable.

## Additional Practice

Smaller exercises and investigation notes are available in [`../soc-labs/`](../soc-labs/).
