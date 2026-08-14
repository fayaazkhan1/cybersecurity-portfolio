# AWS Cloud Security Assessment Evidence

This directory contains public-safe screenshots from the AWS IAM and S3 misconfiguration assessment. Evidence is ordered by the investigation workflow rather than by tool.

| # | Screenshot | What It Demonstrates |
|---:|---|---|
| 02 | [`02-iam-overpermission.png`](02-iam-overpermission.png) | Deliberately excessive `s3:*` / `Resource: *` IAM policy and Access Analyzer `FAIL` for destructive actions |
| 03 | [`03-s3-public-policy-analysis.png`](03-s3-public-policy-analysis.png) | Proposed `Principal: *` S3 policy identified as granting public access before deployment |
| 04 | [`04-prowler-baseline.png`](04-prowler-baseline.png) | Sanitized Prowler IAM/S3 baseline: 32 passing and 25 failing checks |
| 05 | [`05-iam-remediation.png`](05-iam-remediation.png) | Applied least-privilege IAM permissions and Access Analyzer `PASS` for prohibited destructive actions |
| 06 | [`06-s3-hardening.png`](06-s3-hardening.png) | All four S3 Block Public Access settings enabled and bucket versioning enabled |
| 07 | [`07-s3-policy-remediation.png`](07-s3-policy-remediation.png) | Restricted S3 resource policy evaluated as non-public with Access Analyzer `PASS` |
| 08 | [`08-prowler-post-remediation.png`](08-prowler-post-remediation.png) | Before/after Prowler comparison and resolved `s3_bucket_object_versioning` check |

## Recruiter-Facing Evidence

The main project README emphasizes screenshots **05, 06, and 08** because they show the strongest remediation and validation results. Screenshots 02–04 and 07 remain here to preserve the full technical evidence trail.

## Safety and Sanitization

- The intentionally public S3 policy was evaluated but never deployed.
- AWS account IDs and IAM ARNs are redacted where appropriate.
- Raw Prowler reports are not published because they contain account- and resource-specific metadata.
- No credentials, access keys, billing data, or sensitive objects are included.

[Return to the project README](../README.md)
