<div align="center">

# Fayaaz Khan — Cybersecurity Portfolio

### Entry-Level SOC Analyst | Blue Team | Detection & Investigation

Houston, Texas · Open to local, hybrid, and remote opportunities

<p align="center">
  <a href="mailto:fayaazkhan1@gmail.com">
    <img src="https://img.shields.io/badge/Email-Contact_Me-D14836?style=for-the-badge&logo=gmail&logoColor=white" alt="Email Fayaaz Khan" />
  </a>
  <a href="resume/Fayaaz_Yasin_Khan_SOC_Analyst_Resume.pdf">
    <img src="https://img.shields.io/badge/Resume-View_PDF-D32F2F?style=for-the-badge&logo=adobeacrobatreader&logoColor=white" alt="View resume" />
  </a>
  <a href="projects/">
    <img src="https://img.shields.io/badge/Projects-Explore-181717?style=for-the-badge&logo=github&logoColor=white" alt="View projects" />
  </a>
</p>

</div>

---

## About Me

I am an entry-level cybersecurity professional transitioning from a software engineering background and building practical experience for a career in Security Operations.

My portfolio focuses on hands-on Blue Team work: security monitoring, Windows and Active Directory telemetry, detection engineering, phishing and suspicious-email analysis, IOC enrichment, email authentication, incident investigation, Python automation, and analyst reporting.

I hold the **Google Cybersecurity Professional Certificate** and am preparing for **CompTIA Security+**.

---

## Featured Projects

| Project | What I Did | Key Evidence |
|---|---|---|
| [Active Directory Password Spray Detection & Investigation Lab](projects/active-directory-wazuh-detection-lab/) | Built an isolated AD lab, collected Windows authentication telemetry in Wazuh, created a custom threshold rule, generated controlled failures, and investigated the resulting activity | [Detection rule](projects/active-directory-wazuh-detection-lab/detections/password-spray-rule.xml) · [Investigation report](projects/active-directory-wazuh-detection-lab/reports/password-spray-investigation.md) |
| [Phishing Email Investigation & IOC Enrichment](projects/phishing-email-ioc-analysis/) | Completed two contrasting email investigations: escalated a malicious phishing sample, then cleared a suspicious-looking Spam message after SPF/DKIM/DMARC, routing, and domain validation | [Case 001](projects/phishing-email-ioc-analysis/reports/case-001-investigation.md) · [Case 002](projects/phishing-email-ioc-analysis/reports/case-002-investigation.md) · [Evidence](projects/phishing-email-ioc-analysis/screenshots/readme.md) |
| [SOC Labs & Investigations](soc-labs/) | Additional security-operations exercises and technical write-ups | [Explore labs](soc-labs/) |

[View the full project index](projects/)

---

## Project 1 — Active Directory Password Spray Detection

**Focus:** SIEM monitoring · Windows authentication · detection engineering · alert investigation

### Highlights

- Built a Windows Server domain controller for `bluecorp.local`
- Configured Active Directory Domain Services and DNS
- Deployed Wazuh Manager, Indexer, Dashboard, and endpoint agent
- Collected Windows Security Event ID `4625`
- Generated controlled failed-authentication activity against fictional accounts
- Created custom Wazuh correlation rule `100110`
- Configured a five-failures-in-300-seconds threshold
- Mapped the activity to MITRE ATT&CK `T1110.003`
- Documented validation, false positives, troubleshooting, limitations, and response actions

**[View the project](projects/active-directory-wazuh-detection-lab/)** · **[Read the investigation report](projects/active-directory-wazuh-detection-lab/reports/password-spray-investigation.md)**

---

## Project 2 — Phishing & Suspicious-Email Investigation

**Focus:** phishing analysis · full email headers · IOC enrichment · threat intelligence · SPF/DKIM/DMARC · Python automation · analyst reporting

### Case 001 — Malicious Phishing

- Selected and sanitized a phishing research sample for safe public analysis
- Identified a lookalike sender domain: `uusaa[.]com`
- Compared sender infrastructure with the displayed `usaa[.]com` URL hostname
- Parsed URLs and checked for hidden HTML-link destinations
- Enriched the suspicious sender domain through VirusTotal API v3
- Built a documented, explainable phishing triage heuristic
- Assigned **Malicious — Phishing** with **High confidence**
- Mapped the investigation to MITRE ATT&CK `T1566 — Phishing`

### Case 002 — Full Header / False-Positive Investigation

- Investigated a suspicious-looking settlement notification delivered to Spam
- Parsed `From`, `Reply-To`, `Return-Path`, `Sender`, `Message-ID`, authentication, and `Received:` headers
- Confirmed aligned SPF and DKIM plus DMARC pass
- Reconstructed the Mailgun-to-Google delivery route
- Compared sender, Reply-To, Return-Path, and visible-site domains
- Used independent context validation before making the analyst decision
- Assigned **Likely Legitimate Bulk Notification — Phishing Not Supported** with **High confidence**

The two cases intentionally demonstrate both **true-positive escalation** and **false-positive reduction**.

**[View the project](projects/phishing-email-ioc-analysis/)** · **[Case 001 report](projects/phishing-email-ioc-analysis/reports/case-001-investigation.md)** · **[Case 002 report](projects/phishing-email-ioc-analysis/reports/case-002-investigation.md)**

---

## Technical Skills Demonstrated

### Security Operations

- SIEM monitoring and alert investigation
- Windows Security event analysis
- Authentication-event investigation
- Detection-rule development and threshold validation
- Phishing and suspicious-email analysis
- SPF, DKIM, and DMARC interpretation
- Email-header and mail-route analysis
- IOC extraction, defanging, and enrichment
- Threat-intelligence interpretation
- Incident documentation
- MITRE ATT&CK mapping
- False-positive and evidence-limit analysis

### Systems & Tools

- Wazuh
- Windows Server
- Active Directory Domain Services
- DNS
- Ubuntu Linux
- VirtualBox
- VirusTotal API
- Wireshark
- Nmap
- Git and GitHub

### Scripting

- Python
- Bash
- PowerShell fundamentals
- Regular expressions
- JSON processing
- API integration

---

## Certifications & Professional Development

### Google Cybersecurity Professional Certificate

Completed training in security foundations, network security, Linux, SQL, threats and vulnerabilities, detection and response, SIEM concepts, and Python security automation.

[Verify credential](https://coursera.org/verify/professional-cert/J4S6X8PDBPZH)

### CompTIA Security+

Currently preparing for the Security+ exam after completing a full Security+ training course.

---

## Repository Structure

```text
cybersecurity-portfolio/
├── projects/
│   ├── active-directory-wazuh-detection-lab/
│   └── phishing-email-ioc-analysis/
├── soc-labs/
├── google-cert/
├── resume/
└── README.md
```

---

## Roles of Interest

- SOC Analyst
- Junior Cybersecurity Analyst
- Security Operations Analyst
- Cybersecurity Support Analyst
- Junior Incident Response Analyst
- Information Security Analyst

**Location:** Houston, Texas  
**Work preference:** Local, hybrid, or remote  
**Email:** [fayaazkhan1@gmail.com](mailto:fayaazkhan1@gmail.com)  
**Resume:** [Fayaaz_Yasin_Khan_SOC_Analyst_Resume.pdf](resume/Fayaaz_Yasin_Khan_SOC_Analyst_Resume.pdf)

---

<div align="center">

### Building practical security experience through repeatable labs, evidence-backed investigations, and clear documentation.

</div>
