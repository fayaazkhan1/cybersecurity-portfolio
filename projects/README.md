# Cybersecurity Projects

This directory contains my larger hands-on cybersecurity projects. Each project is documented to show the problem being investigated, the tools used, the evidence collected, the analysis performed, and the final outcome.

## Featured Projects

| Project | Focus | Tools / Skills | Evidence |
|---|---|---|---|
| [Active Directory Password Spray Detection & Investigation Lab](active-directory-wazuh-detection-lab/) | Detect and investigate repeated authentication failures in an isolated Active Directory environment | Wazuh, Windows Server, Active Directory, Event ID 4625, custom correlation rules, MITRE ATT&CK | [Investigation report](active-directory-wazuh-detection-lab/reports/password-spray-investigation.md) · [Detection rule](active-directory-wazuh-detection-lab/detections/password-spray-rule.xml) |
| [Phishing Email Investigation & IOC Enrichment](phishing-email-ioc-analysis/) | Investigate both a malicious phishing sample and a suspicious-looking but likely legitimate bulk message | Python, VirusTotal API, IOC analysis, SPF/DKIM/DMARC, full email headers, mail routing, threat intelligence, false-positive reduction | [Case 001](phishing-email-ioc-analysis/reports/case-001-investigation.md) · [Case 002](phishing-email-ioc-analysis/reports/case-002-investigation.md) · [Evidence](phishing-email-ioc-analysis/screenshots/readme.md) |
| [AWS Cloud Security Misconfiguration Assessment & Remediation](aws-cloud-security-assessment/) | Assess and remediate identity and storage misconfigurations in a dedicated AWS lab | AWS IAM, Amazon S3, IAM Access Analyzer, Prowler, least privilege, public-access controls, remediation validation | [Assessment report](aws-cloud-security-assessment/reports/cloud-security-assessment.md) · [Policies](aws-cloud-security-assessment/policies/) · [Evidence](aws-cloud-security-assessment/screenshots/) |

## Why These Projects Matter Together

The portfolio is designed around practical security workflows rather than isolated tool demonstrations.

```text
Security event, suspicious artifact, or cloud configuration
        ↓
Data collection and validation
        ↓
Detection / assessment
        ↓
Investigation
        ↓
Threat, identity, or business context
        ↓
Remediation / analyst conclusion
        ↓
Validation and documented outcome
```

Together, the projects demonstrate three different security domains:

- **Detection engineering:** generated and detected a controlled password-spray pattern in Active Directory using Wazuh.
- **Email security:** escalated a malicious phishing case and separately cleared a suspicious-looking message after full-header and authentication analysis.
- **Cloud security:** identified excessive IAM permissions and unsafe S3 policy patterns, applied least privilege and storage hardening, and validated remediation with AWS-native tooling and Prowler.

I prioritize accurate documentation, reproducible steps, evidence-backed conclusions, safe handling of sensitive data, and clear limitations when a tool's scope differs from the specific lab finding being investigated.

## Additional Practice

Smaller exercises and investigation notes are available in [`../soc-labs/`](../soc-labs/).
