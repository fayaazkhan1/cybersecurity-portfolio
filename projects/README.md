# Cybersecurity Projects

This directory contains my larger hands-on cybersecurity projects. Each project is documented to show the problem being investigated, the tools used, the evidence collected, the analysis performed, and the final outcome.

## Featured Projects

| Project | Focus | Tools / Skills | Evidence |
|---|---|---|---|
| [Active Directory Password Spray Detection & Investigation Lab](active-directory-wazuh-detection-lab/) | Detect and investigate repeated authentication failures in an isolated Active Directory environment | Wazuh, Windows Server, Active Directory, Event ID 4625, custom correlation rules, MITRE ATT&CK | [Investigation report](active-directory-wazuh-detection-lab/reports/password-spray-investigation.md) · [Detection rule](active-directory-wazuh-detection-lab/detections/password-spray-rule.xml) |
| [Phishing Email Investigation & IOC Enrichment](phishing-email-ioc-analysis/) | Analyze a phishing sample, extract and compare IOCs, enrich a suspicious sender domain, and document an analyst verdict | Python, VirusTotal API, URL parsing, threat intelligence, rule-based triage, MITRE ATT&CK | [Case 001 report](phishing-email-ioc-analysis/reports/case-001-investigation.md) · [Automation scripts](phishing-email-ioc-analysis/scripts/) |

## What I Aim to Demonstrate

My projects are designed around practical SOC and Blue Team workflows rather than isolated tool demonstrations:

```text
Security event or suspicious artifact
        ↓
Data collection and validation
        ↓
Detection / triage
        ↓
Investigation
        ↓
Threat context
        ↓
Analyst conclusion
        ↓
Documented response actions
```

I prioritize accurate documentation, reproducible steps, evidence-backed conclusions, and clear limitations when data is unavailable.

## Additional Practice

Smaller exercises and investigation notes are available in [`../soc-labs/`](../soc-labs/).
