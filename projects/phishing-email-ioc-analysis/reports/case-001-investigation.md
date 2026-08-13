# Case 001 — Phishing Email Investigation

## Investigation Summary

**Case ID:** CASE-001
**Analyst:** Fayaaz Yasin Khan
**Source:** Nazario Phishing Research Dataset — Record 27
**Verdict:** Malicious — Phishing
**Confidence:** High
**Triage Priority:** Critical
**Primary MITRE ATT&CK Mapping:** T1566 — Phishing

---

## 1. Executive Summary

CASE-001 involved an email presenting itself as a security notification from USAA and requesting that the recipient verify or update account information.

The investigation identified multiple characteristics consistent with phishing activity, including a visually similar sender domain, an account-restriction pretext, time-pressure language, and a request for the recipient to complete account verification.

The sender used the domain:

`uusaa[.]com`

while the visible URL referenced:

`hxxps://www[.]usaa[.]com`

Structural IOC analysis determined that the sender domain and displayed URL domain did not match.

Current VirusTotal enrichment for the sender domain returned three malicious detections and one suspicious detection.

A lab-developed triage model assigned the case a score of **100/100**, resulting in a **Critical** investigation priority.

Based on the combined available evidence, the message was classified as **Malicious — Phishing** with **High confidence**.

---

## 2. Email Metadata

| Field         | Observed Value                                |
| ------------- | --------------------------------------------- |
| Date          | Tue, 17 Nov 2015 22:02:47 -0200               |
| Sender        | `U***@uusaa[.]com`                            |
| Subject       | Your USAA Account Personal Information Update |
| Source Record | Nazario Record 27                             |
| Dataset Label | Phishing                                      |

The recipient address was masked during sanitization to avoid unnecessarily publishing identifying information.

---

## 3. Claimed Organization

The email presents itself as communication from USAA and uses language associated with account security and account verification.

The message attempts to establish legitimacy by referencing account protection, fraud prevention, identity theft, privacy information, and USAA contact information.

---

## 4. Sender Analysis

### Observed Sender Domain

`uusaa[.]com`

### Claimed Brand

`USAA`

The sender domain closely resembles the USAA brand name but contains an additional `u`.

Comparison:

**Claimed brand:** `usaa`
**Observed sender domain:** `uusaa[.]com`

This pattern is consistent with a potential lookalike or typosquatting technique.

The sender-domain discrepancy was treated as a suspicious indicator rather than definitive proof of malicious activity.

---

## 5. Social Engineering Analysis

Several social-engineering characteristics were identified.

### Account Restriction

The recipient is told that the account has been temporarily restricted.

This creates concern that access to financial services may be lost and attempts to pressure the recipient into taking action.

### Urgency

The recipient is instructed to complete verification within 24 hours.

The time constraint increases pressure on the recipient to act quickly rather than independently verifying the message through a trusted channel.

### Account Verification

The message requests that the recipient follow a provided link and complete account verification.

Requests to verify financial-account information through unsolicited email links represent a significant phishing indicator.

### Trust and Authority

The message repeatedly references USAA security, privacy, fraud prevention, and organizational information in an apparent attempt to increase credibility.

---

## 6. URL Analysis

### URL Occurrences

The email contained:

* 2 URL occurrences
* 1 unique URL after deduplication

### Unique URL Indicator

`hxxps://www[.]usaa[.]com`

Structural parsing produced:

| Component           | Result             |
| ------------------- | ------------------ |
| Scheme              | HTTPS              |
| Hostname            | `www[.]usaa[.]com` |
| Normalized Host     | `usaa[.]com`       |
| Port                | Default            |
| Path                | `/`                |
| Query Parameters    | None               |
| Sender Domain Match | False              |

The displayed URL hostname appears consistent with the organization being impersonated.

However, the sender domain was:

`uusaa[.]com`

while the normalized URL hostname was:

`usaa[.]com`

The domains therefore do not match.

This mismatch strengthens suspicion because the message presents itself as USAA communication while originating from a separate visually similar domain.

The domain mismatch is structural evidence and was not treated as independently sufficient to classify the email as malicious.

---

## 7. HTML Link Analysis

Additional parsing was performed to determine whether the stored message body contained an HTML `href` destination different from the displayed URL.

Results:

| Finding                       | Result |
| ----------------------------- | -----: |
| URL occurrences               |      2 |
| Unique URLs                   |      1 |
| HTML href occurrences         |      0 |
| Unique HTML href destinations |      0 |

No separate HTML hyperlink destination was identified in the dataset representation.

This does not establish that the original message contained no redirect or hidden destination. The source dataset may have altered or removed portions of the original email structure during preprocessing.

Because the original `.eml` file is unavailable, the analysis cannot fully reconstruct the original hyperlink behavior.

---

## 8. IOC Structure Analysis

### Sender Domain

`uusaa[.]com`

### Observed URL Hostname

`www[.]usaa[.]com`

### Normalized URL Host

`usaa[.]com`

### Comparison

The sender domain and normalized URL hostname do not match.

The sender domain closely resembles the organization referenced in the message but contains an additional `u`, while the displayed URL uses the expected `usaa[.]com` spelling.

This inconsistency increases suspicion because the email presents itself as communication from USAA while originating from a separate visually similar domain.

The domain comparison was treated as structural evidence only and was not independently sufficient to classify the message as malicious.

---

## 9. Threat Intelligence Enrichment

### Indicator

`uusaa[.]com`

### Source

VirusTotal API v3 — Existing Domain Report

### Results

| Classification | Engines |
| -------------- | ------: |
| Malicious      |       3 |
| Suspicious     |       1 |
| Harmless       |      52 |
| Undetected     |      35 |

**VirusTotal Reputation:** `0`

Current VirusTotal reputation data showed three malicious and one suspicious engine detections for the sender domain `uusaa[.]com`.

These results provide additional support for the suspicious characteristics already identified during manual analysis, including:

* Visually similar sender domain
* Account-restriction pretext
* Time-pressure language
* Account-verification request
* Sender and URL domain mismatch

The VirusTotal result was treated as supporting evidence rather than the sole basis for the malicious verdict.

### Historical Limitation

The analyzed email was sent in November 2015, while the VirusTotal lookup was conducted during the present investigation.

The current reputation, ownership, hosting infrastructure, and security classifications associated with a domain may differ substantially from its historical state.

For this reason, the VirusTotal findings are documented as current threat-intelligence context rather than definitive evidence of the domain's status in 2015.

---

## 10. Automated Triage

A transparent rule-based scoring model was developed to assist with investigation prioritization.

### Scoring Breakdown

| Indicator                                          | Points |
| -------------------------------------------------- | -----: |
| Lookalike or typosquatted sender domain            |    +20 |
| Sender domain differs from displayed URL domain    |    +15 |
| Account restriction or suspension language         |    +10 |
| Time-pressure or urgency language                  |    +10 |
| Request to verify or update account information    |    +15 |
| VirusTotal malicious detections greater than zero  |    +20 |
| VirusTotal suspicious detections greater than zero |    +10 |

### Result

**Final Score:** 100/100
**Triage Priority:** Critical

All seven indicators represented by the lab scoring model were observed during CASE-001.

The scoring model is a **lab-developed triage heuristic** and is not an industry-standard severity, risk, or vulnerability score.

The automated result supports prioritization but does not replace analyst judgment.

The final malicious verdict was assigned only after manual review of the available evidence.

---

## 11. MITRE ATT&CK Mapping

### T1566 — Phishing

**Tactic:** Initial Access

The message uses electronically delivered social engineering while impersonating a trusted financial-services organization and attempting to persuade the recipient to follow an account-verification process.

The broader T1566 — Phishing technique is used as the primary mapping because the available dataset establishes phishing behavior but does not establish that the message was specifically targeted at an individual or organization.

### Related Technique: T1566.002 — Spearphishing Link

The sample contains a link and therefore resembles spearphishing-link behavior.

However, the available dataset does not establish that the message was specifically targeted at a particular individual, company, or industry.

For this reason, T1566.002 is documented as a related technique rather than the primary classification.

No credential-access technique was assigned because the available evidence does not demonstrate that a recipient submitted credentials or that an account was successfully compromised.

---

## 12. Analyst Verdict

### Verdict

**Malicious — Phishing**

### Confidence

**High**

### Triage Priority

**Critical**

### Supporting Evidence

1. The message impersonates a financial-services organization.
2. The sender domain `uusaa[.]com` visually resembles the claimed USAA brand.
3. The sender domain contains an additional character consistent with a potential lookalike or typosquatting technique.
4. The sender domain does not match the displayed `usaa[.]com` URL hostname.
5. The message claims that the recipient's account has been temporarily restricted.
6. The recipient is given a 24-hour verification deadline.
7. The message attempts to direct the recipient through an account-verification process.
8. VirusTotal currently reports three malicious and one suspicious engine detections for the sender domain.
9. The source research dataset identifies the sample as phishing.
10. The lab-developed triage model assigned the case a 100/100 score.

No individual indicator was treated as sufficient to establish the verdict.

The final classification was based on the combined available evidence.

---

## 13. Recommended SOC Response

If this message were discovered in an enterprise environment, recommended response actions would include:

1. Quarantine the reported email.
2. Search the mail environment for additional messages with the same sender domain, subject, or related indicators.
3. Block or monitor the suspicious sender domain according to organizational policy.
4. Identify other users who received similar messages.
5. Determine whether any recipients interacted with the message or followed embedded links.
6. Review web proxy, DNS, endpoint, and identity logs for related activity.
7. Review authentication logs for suspicious sign-ins associated with affected users.
8. If a recipient submitted credentials, immediately initiate credential-reset procedures.
9. Revoke active sessions where appropriate following confirmed credential exposure.
10. Review Multi-Factor Authentication activity for suspicious approvals or enrollment changes.
11. Preserve the original email and related security telemetry for further investigation.
12. Notify affected users and provide phishing-awareness guidance when appropriate.
13. Escalate to incident response if evidence of successful compromise is identified.

---

## 14. Evidence Limitations

The following evidence was unavailable for CASE-001:

* Complete original `.eml` message
* Full `Received:` routing headers
* SPF authentication result
* DKIM authentication result
* DMARC authentication result
* Historical 2015 threat-intelligence state
* Endpoint telemetry from the recipient
* Browser or proxy logs showing link interaction
* Evidence that credentials were entered
* Evidence that the recipient's account was compromised
* Evidence establishing that the phishing message was specifically targeted

These limitations prevent conclusions about the original delivery infrastructure, email-authentication results, successful user interaction, or post-phishing compromise.

The absence of these artifacts was documented rather than inferred.

---

## 15. Investigation Workflow

The CASE-001 investigation followed this process:

1. Verified the integrity of the source research dataset.
2. Programmatically inspected and validated the dataset structure.
3. Selected a suitable phishing record for investigation.
4. Sanitized the sample before creating public portfolio artifacts.
5. Defanged URL and domain indicators.
6. Removed duplicate URL indicators.
7. Analyzed sender-domain and URL-host relationships.
8. Checked for hidden HTML `href` destinations.
9. Enriched the suspicious sender domain using the VirusTotal API.
10. Applied a documented rule-based triage methodology.
11. Reviewed the combined evidence manually.
12. Assigned an analyst verdict and confidence level.
13. Mapped the observed activity to MITRE ATT&CK.
14. Documented recommended SOC response actions and investigation limitations.

---

## 16. Automation Developed

Python scripts were developed to support repeatable analysis tasks including:

* Dataset inspection
* Dataset troubleshooting and validation
* Candidate phishing-case selection
* Case sanitization
* IOC extraction
* URL deduplication
* URL structure analysis
* Sender-domain comparison
* HTML hyperlink analysis
* VirusTotal API enrichment
* Rule-based phishing triage
* Structured JSON evidence generation
* Final case metadata management

Automation was used to assist the investigation rather than replace analyst reasoning.

---

## 17. Skills Demonstrated

This investigation demonstrates hands-on experience with:

* Phishing email analysis
* Security Operations Center investigation workflow
* Social-engineering identification
* Indicator of Compromise extraction
* Indicator defanging
* URL parsing
* Domain analysis
* Lookalike-domain identification
* Threat-intelligence enrichment
* VirusTotal API integration
* Python scripting
* Regular expressions
* JSON processing
* Data sanitization
* Rule-based security automation
* Investigation triage
* MITRE ATT&CK mapping
* Analyst documentation
* Evidence handling
* Evidence limitation analysis
* Incident-response recommendations

---

## 18. Conclusion

CASE-001 demonstrated an end-to-end phishing investigation workflow beginning with a public research dataset and progressing through manual analysis, IOC extraction, Python automation, threat-intelligence enrichment, triage, and analyst reporting.

The strongest indicators were the visually similar `uusaa[.]com` sender domain, the discrepancy between the sender and displayed URL domains, the account-restriction and verification pretext, time-pressure language, and supporting VirusTotal reputation findings.

Based on the combined evidence, the sample was classified as **Malicious — Phishing** with **High confidence** and assigned a **Critical triage priority** under the project's lab-developed scoring methodology.

The investigation also demonstrated the importance of documenting uncertainty. Missing original email headers, historical reputation data, and post-delivery telemetry were recorded as limitations rather than replaced with unsupported assumptions.

