## 4.URL Indicators

### URL Occurrences

The message contains two URL occurrences representing one unique URL indicator after deduplication.

### Unique URL 1

`hxxps://www[.]usaa[.]com`

The visible URL uses a hostname consistent with the organization named in the message.

### HTML Link Analysis

A separate analysis of HTML `href` attributes found:

- URL occurrences: 2
- Unique URLs: 1
- HTML `href` occurrences: 0
- Unique HTML `href` destinations: 0

No hidden HTML hyperlink destination was identified in the dataset representation of this message.

This does not establish that the link was safe. The source dataset does not contain the complete original `.eml` message, and the investigation cannot determine whether HTML was removed during dataset preprocessing or whether the destination historically performed server-side redirection.

## 5. IOC Structure Analysis

### Sender Domain

`uusaa[.]com`

### Observed URL Hostname

`www[.]usaa[.]com`

### Normalized URL Host

`usaa[.]com`

### Comparison

The sender domain and normalized URL hostname do not match.

The sender domain closely resembles the organization referenced in the message but contains an additional `u`, while the displayed URL uses the expected `usaa[.]com` spelling.

This inconsistency increases suspicion because the message presents itself as communication from USAA while originating from a separate visually similar domain.

The domain comparison is structural evidence only and is not independently sufficient to classify the message as malicious.

---

## 6. Threat Intelligence Enrichment

### Indicator

`uusaa[.]com`

### Source

VirusTotal API v3 — existing domain report

### Results

| Classification | Engines |
|---|---:|
| Malicious | 3 |
| Suspicious | 1 |
| Harmless | 52 |
| Undetected | 35 |

**VirusTotal reputation:** `0`

### Analyst Interpretation

Current VirusTotal reputation data showed three malicious and one suspicious engine detections for the sender domain `uusaa[.]com`.

These results provide additional support for the suspicious characteristics already identified during manual analysis, including the visually similar sender domain, account-restriction pretext, urgency, verification request, and mismatch between the sender domain and displayed URL hostname.

The VirusTotal result is treated as supporting evidence rather than the sole basis for classification.

### Historical Limitation

The analyzed email was sent in November 2015, while the VirusTotal lookup was performed during the current investigation.

Current threat-intelligence data may not represent the domain's reputation, ownership, hosting infrastructure, or activity at the time the phishing email was originally sent.

For this reason, the enrichment result is documented as current threat-intelligence context rather than definitive historical evidence.

### Current Link Assessment

The URL itself does not currently provide the same obvious lookalike-domain indicator observed in the sender domain. Further analysis should therefore focus on the sender-domain discrepancy and external threat-intelligence context.
