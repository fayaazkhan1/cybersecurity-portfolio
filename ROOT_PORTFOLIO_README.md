# SOC Analyst Cybersecurity Portfolio

Welcome to my cybersecurity portfolio. I am an entry-level cybersecurity professional based in Houston, Texas, building practical experience through hands-on Blue Team projects involving security monitoring, Windows event analysis, SIEM investigations, detection engineering, and incident documentation.

I hold the Google Cybersecurity Professional Certificate and am currently preparing for CompTIA Security+.

## Projects

| Project | Focus | Evidence |
|---|---|---|
| [Active Directory Password Spray Detection & Investigation Lab](projects/active-directory-wazuh-detection-lab/) | Active Directory, Windows Event ID 4625, Wazuh, detection engineering, SOC investigation | [Custom rule](projects/active-directory-wazuh-detection-lab/detections/password-spray-rule.xml) · [Investigation report](projects/active-directory-wazuh-detection-lab/reports/password-spray-investigation.md) · [Test script](projects/active-directory-wazuh-detection-lab/scripts/lab-auth-test.sh) |

## Featured Project

### Active Directory Password Spray Detection & Investigation Lab

Built an isolated Active Directory environment using Windows Server, Ubuntu, VirtualBox, and Wazuh. I generated controlled failed authentications against five fictional domain accounts, analyzed Windows Security Event ID `4625`, and created custom Wazuh rule `100110` to correlate repeated failures within a five-minute window.

**Key outcomes:**

- Deployed a Windows Server domain controller and fictional `bluecorp.local` domain
- Enrolled `DC01` as a Wazuh endpoint
- Collected and investigated Windows authentication telemetry
- Developed and tested a custom Wazuh correlation rule
- Mapped the detection to MITRE ATT&CK `T1110.003`
- Documented false positives, limitations, troubleshooting, and response recommendations

[View the complete project](projects/active-directory-wazuh-detection-lab/)

## Skills Demonstrated

- SIEM monitoring and alert investigation
- Windows Security event analysis
- Active Directory administration
- Wazuh agent deployment and rule development
- Detection validation and tuning
- MITRE ATT&CK mapping
- Bash and PowerShell
- SOC-style technical documentation
- Virtual lab networking

## Certifications and Development

- Google Cybersecurity Professional Certificate
- CompTIA Security+ — currently studying

## Career Focus

I am seeking entry-level opportunities in:

- SOC Analysis
- Security Operations
- Junior Cybersecurity Analysis
- Incident Response Support
- Blue Team Operations

**Location:** Houston, Texas  
**Work preference:** Local, hybrid, or remote  
**Email:** [fayaazkhan1@gmail.com](mailto:fayaazkhan1@gmail.com)
