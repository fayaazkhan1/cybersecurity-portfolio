# Case 002 — Full Email Header Investigation

## Investigation Summary

**Case ID:** CASE-002  
**Analyst:** Fayaaz Yasin Khan  
**Source:** Sanitized real-world email sample from a personal mailbox  
**Mailbox Classification:** Spam  
**Verdict:** Likely Legitimate Bulk Notification — Phishing Not Supported  
**Confidence:** High  
**Primary Focus:** Email authentication, sender identity, mail routing, and domain consistency

---

## 1. Executive Summary

CASE-002 examined a message titled **“Google Assistant Privacy Litigation Settlement”** that was delivered to a Spam folder and initially warranted additional review because it used settlement/payment language, a third-party sender domain, tracked links, and a Reply-To domain different from the visible From domain.

Unlike CASE-001, this investigation did not assume that suspicious presentation or mailbox placement meant the email was malicious. The analysis focused on whether the technical delivery evidence and business-domain relationships were internally consistent.

The message passed SPF, DKIM, and DMARC authentication. The SPF-authenticated envelope-sender domain aligned with the visible From domain, and one passing DKIM signature also aligned with that From domain. A second DKIM signature from Mailgun passed but did not align with the visible sender, which is consistent with an additional delivery-provider signature rather than evidence of spoofing.

Received-header analysis showed a coherent delivery path from Mailgun infrastructure to Google using encrypted SMTP. The From, Sender, and Return-Path domains were internally consistent. Although the Reply-To domain differed from the delivery domain, it matched the visible settlement website domain.

Independent validation against the official settlement website confirmed that the public settlement domain uses the same `googleassistantprivacylitigation.com` domain found in the Reply-To address, identifies A.B. Data, Ltd. as the Claims Administrator, and publishes the same August 27, 2026 claim deadline referenced by the message.

Based on the combined authentication, routing, domain-consistency, and external-validation evidence, the message was assessed as a **Likely Legitimate Bulk Notification** with **High confidence**. The available evidence did not support classification as phishing.

---

## 2. Investigation Objective

The purpose of CASE-002 was to determine whether a suspicious-looking email should be treated as phishing, spam, or legitimate bulk mail by examining full email-header evidence.

The investigation specifically evaluated:

- Visible sender identity
- Reply-To identity
- Return-Path identity
- Sender identity
- SPF authentication
- DKIM authentication
- DMARC authentication
- Authentication alignment
- Received-header routing
- Sending IP and mail provider
- Transport security
- Visible content-domain relationships
- Independent official-source validation

---

## 3. Evidence Handling and Sanitization

The original email contained private recipient information and personalized tracking data.

Before publication, the portfolio artifact removed or replaced:

- Recipient email address
- Personalized claim identifiers
- Claim PIN
- Unsubscribe tokens
- Tracking parameters
- Message-specific identifiers
- Internal provider identifiers not required for analysis

The sanitized artifact retains only the fields necessary to demonstrate defensive email-header analysis.

Public sample:

[`../data/sanitized/case-002-header-sample.eml`](../data/sanitized/case-002-header-sample.eml)

---

## 4. Message Identity

| Field | Observed Value |
|---|---|
| Subject | Google Assistant Privacy Litigation Settlement |
| From | `Google Assistant Class Action Administrator <help@mg.abdataclassactionmail.com>` |
| Reply-To | `info@googleassistantprivacylitigation.com` |
| Return-Path | `bounce+REDACTED@mg.abdataclassactionmail.com` |
| Sender | `help@mg.abdataclassactionmail.com` |
| Message-ID | `<REDACTED@mg.abdataclassactionmail.com>` |
| Date | Sun, 02 Aug 2026 14:04:10 +0000 |

The From, Return-Path, Sender, and Message-ID identities use the `mg.abdataclassactionmail.com` delivery domain.

The Reply-To address uses `googleassistantprivacylitigation.com`, which required separate validation because it differs from the delivery domain.

---

## 5. Initial Suspicion Indicators

The message contained several characteristics that justified investigation:

1. It was delivered to the Spam folder.
2. It referenced a financial settlement and potential payment.
3. It instructed the recipient to file a claim.
4. The visible From domain was not a Google-owned domain.
5. The Reply-To domain differed from the From domain.
6. The original message used tracked links associated with bulk-email delivery.

None of these indicators was treated as definitive proof of phishing.

---

## 6. SPF Analysis

### Result

**SPF: PASS**

### Envelope Sender

`bounce+REDACTED@mg.abdataclassactionmail.com`

### SPF Domain

`mg.abdataclassactionmail.com`

### Alignment

**Exact alignment with visible From domain: True**

The sending infrastructure was authorized to send for the envelope-sender domain, and that domain matched the visible From domain used by the message.

A passing SPF result was treated as evidence of authorized delivery for the envelope identity, not as independent proof that the message content was trustworthy.

---

## 7. DKIM Analysis

Two passing DKIM results were present.

### DKIM Identity 1

| Field | Result |
|---|---|
| Result | PASS |
| Signing identity | `mg.abdataclassactionmail.com` |
| Alignment with visible From | True |

This DKIM identity aligns with the visible sender domain.

### DKIM Identity 2

| Field | Result |
|---|---|
| Result | PASS |
| Signing identity | `mailgun.org` |
| Alignment with visible From | False |

The second signature is consistent with the Mailgun delivery provider applying an additional DKIM signature.

A non-aligned provider signature does not invalidate a separate passing and aligned organizational signature.

---

## 8. DMARC Analysis

### Result

**DMARC: PASS**

### Header From Domain

`mg.abdataclassactionmail.com`

### Observed Authentication Paths

- SPF passed and aligned with the visible From domain.
- One DKIM identity passed and aligned with the visible From domain.
- A second Mailgun DKIM identity passed but did not align with the visible From domain.

The recorded DMARC PASS result is consistent with the available authentication evidence.

The analysis demonstrates why SPF, DKIM, and DMARC should be interpreted together rather than as unrelated checkboxes.

---

## 9. Mail Route Reconstruction

The sanitized message preserves two Received headers.

Because each receiving server prepends its own Received header, the headers were reversed during analysis to reconstruct the delivery path chronologically.

### Chronological Route

**Hop 1 — Mailgun internal submission**

- Role: Message submitted into Mailgun infrastructure
- Transport: HTTP
- Internal host details: Redacted before publication

**Hop 2 — Mailgun to Google**

- From host: `g193.gc579f28.use4.send.mailgun.net`
- By host: `mx.google.com`
- Source IP: `204.220.171.193`
- Transport: `UTF8SMTPS`
- TLS version: `TLS1_2`
- Cipher: `ECDHE-ECDSA-AES128-GCM-SHA256`

The retained route is internally consistent with Mailgun acting as the email-delivery provider.

Encrypted transport confirms that the Mailgun-to-Google SMTP hop used TLS, but transport encryption alone does not establish that message content is legitimate.

---

## 10. Domain Consistency Analysis

### Header Domains

| Identity | Domain |
|---|---|
| From | `mg.abdataclassactionmail.com` |
| Sender | `mg.abdataclassactionmail.com` |
| Return-Path | `mg.abdataclassactionmail.com` |
| Reply-To | `googleassistantprivacylitigation.com` |

### Visible Content Domain

`googleassistantprivacylitigation.com`

### Relationship Checks

| Comparison | Result |
|---|---:|
| From = Return-Path | True |
| From = Sender | True |
| Reply-To = visible website | True |
| From = visible website | False |

The delivery identities are internally consistent.

The Reply-To domain differs from the delivery domain but matches the public-facing settlement domain. This is a coherent pattern for a third-party claims administrator using separate mail-delivery infrastructure and a public settlement website.

The different Reply-To was therefore treated as an investigation indicator requiring validation, not as automatic evidence of phishing.

---

## 11. Independent External Validation

After completing offline header analysis, the business context was validated independently against the official settlement website.

The official settlement site:

- Identifies itself as the Google Assistant Privacy Litigation settlement website.
- States that it is maintained by the Claims Administrator.
- Lists **A.B. Data, Ltd.** as the Claims Administrator.
- Publishes `info@googleassistantprivacylitigation.com` as a contact address.
- Lists **August 27, 2026** as the claim deadline.

These observations are documented separately in:

[`../docs/case-002-external-validation.md`](../docs/case-002-external-validation.md)

The independently published contact domain matches the Reply-To domain in the email sample, and the published claim deadline matches the message context.

This external consistency strengthened the legitimacy hypothesis.

---

## 12. Analyst Verdict

### Verdict

**Likely Legitimate Bulk Notification — Phishing Not Supported**

### Confidence

**High**

### Supporting Evidence

1. SPF passed.
2. The SPF envelope-sender domain aligned with the visible From domain.
3. DKIM passed for the visible sender domain.
4. A second Mailgun provider DKIM signature also passed.
5. DMARC passed.
6. From, Sender, and Return-Path domains were internally consistent.
7. The Received chain was consistent with Mailgun delivery to Google.
8. The Google-facing SMTP hop used TLS.
9. The Reply-To domain matched the visible settlement website domain.
10. Independent official-source validation confirmed the same settlement contact domain and claim deadline.
11. No observed header evidence demonstrated sender spoofing or authentication failure.

### Why the Spam Label Was Not Enough

Mailbox filtering is a useful signal but is not an analyst verdict.

Legitimate bulk mail can be classified as spam because of factors such as mailing reputation, user engagement, content patterns, volume, or filtering heuristics.

CASE-002 therefore treated the Spam-folder placement as an investigation trigger rather than proof of malicious activity.

---

## 13. SOC Disposition

In an enterprise environment, recommended handling would be:

1. Do not escalate solely because the message was classified as spam.
2. Preserve the original message when deeper investigation is required.
3. Review SPF, DKIM, DMARC, and domain alignment before making a sender-spoofing determination.
4. Validate Reply-To and linked business domains independently when they differ from the delivery domain.
5. Avoid using email links for validation; navigate independently to known or officially sourced domains.
6. If business context cannot be independently validated, retain the message as suspicious and escalate according to organizational procedure.
7. If authentication fails or domains become inconsistent, expand the investigation to threat-intelligence, proxy, DNS, endpoint, and identity telemetry.

For this sample, no phishing escalation was supported by the available evidence.

---

## 14. Evidence Limitations

The public portfolio artifact intentionally omits private and tracking data.

Limitations include:

- Personalized claim identifiers were removed.
- Tracking URLs and tokens were removed.
- Internal Mailgun identifiers were redacted.
- Only header evidence necessary for the investigation was preserved publicly.
- No direct administrative access to the sender's infrastructure was available.
- Passing authentication proves authorized sending/alignment for the relevant identities; it does not independently prove the business request itself.
- External website consistency provides supporting context rather than cryptographic proof of organizational ownership relationships.

The final assessment is therefore based on the combined evidence rather than any single indicator.

---

## 15. Automation Developed

CASE-002 added Python automation for:

- RFC822/MIME parsing
- Header extraction
- From / Reply-To / Return-Path comparison
- SPF-result extraction
- DKIM-identity extraction
- DMARC-result extraction
- Authentication-alignment analysis
- Received-header parsing
- Chronological route reconstruction
- Sending-IP extraction
- Transport and TLS extraction
- Content-domain normalization
- Domain relationship comparison

Key scripts:

- [`../scripts/parse_email_headers.py`](../scripts/parse_email_headers.py)
- [`../scripts/analyze_authentication.py`](../scripts/analyze_authentication.py)
- [`../scripts/analyze_mail_route.py`](../scripts/analyze_mail_route.py)
- [`../scripts/analyze_content_domains.py`](../scripts/analyze_content_domains.py)

---

## 16. Skills Demonstrated

This case demonstrates practical experience with:

- Full email-header investigation
- RFC822/MIME parsing
- SPF analysis
- DKIM analysis
- DMARC analysis
- Authentication alignment
- Return-Path analysis
- Reply-To analysis
- Received-header reconstruction
- SMTP routing analysis
- Mail-provider identification
- TLS transport interpretation
- Domain consistency analysis
- Spam-versus-phishing triage
- Independent business-context validation
- Python security automation
- Evidence sanitization
- SOC documentation
- Analyst decision-making

---

## 17. Lessons Learned

CASE-002 demonstrated that suspicious appearance and mailbox placement should not substitute for evidence-based analysis.

The message contained characteristics that initially justified scrutiny, including financial-settlement language, a third-party sender domain, a separate Reply-To domain, tracked links, and Spam-folder placement.

However, the complete evidence told a different story:

- Authentication succeeded and aligned.
- Routing was coherent.
- Delivery infrastructure was consistent.
- The Reply-To matched the public settlement website.
- Independent official-source validation supported the business context.

The key lesson is that a SOC analyst must be capable of both **escalating malicious messages and clearing messages when the evidence does not support a threat classification**.

That distinction reduces false positives and improves analyst credibility.