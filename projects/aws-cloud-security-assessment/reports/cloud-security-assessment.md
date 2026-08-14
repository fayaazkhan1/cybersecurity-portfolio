# AWS Cloud Security Misconfiguration Assessment & Remediation

## Investigation Summary

**Project:** AWS Cloud Security Misconfiguration Assessment & Remediation  
**Cloud provider:** Amazon Web Services (AWS)  
**Assessment scope:** IAM and Amazon S3  
**Tools:** AWS CLI, AWS IAM Access Analyzer, Prowler 5.37.1  
**Assessment type:** Controlled lab assessment with deliberate misconfiguration, remediation, and validation

---

## 1. Executive Summary

This project assessed a dedicated AWS lab for identity and storage misconfigurations that commonly create cloud-security risk. The exercise focused on excessive IAM permissions, unsafe S3 resource-policy design, public-access protections, and object-recovery controls.

Three scoped findings were investigated:

1. An IAM identity was deliberately granted `s3:*` against `Resource: *`, which exceeded its intended read-only requirement.
2. A proposed S3 resource policy used `Principal: *` with `s3:GetObject`, representing a public-access configuration if deployed. The unsafe policy was evaluated with IAM Access Analyzer but was **never attached to the live bucket**.
3. The S3 lab bucket initially had versioning disabled, reducing recovery options for overwritten or deleted objects.

The IAM policy was reduced to least privilege by allowing only `s3:ListBucket` and `s3:GetObject` against one lab bucket. AWS IAM Access Analyzer confirmed that destructive actions such as `s3:DeleteBucket`, `s3:PutBucketPolicy`, and `s3:DeleteObject` were no longer granted.

The proposed public S3 policy was replaced with a restricted policy referencing one specific IAM identity. Access Analyzer changed from `FAIL` for the public policy to `PASS` for the remediated policy. All four S3 Block Public Access controls were explicitly enabled, and bucket versioning was enabled.

Prowler provided a broader IAM/S3 posture check. The baseline contained 32 passing and 25 failing checks. After remediation, the scan contained 33 passing and 24 failing checks. S3 failures decreased from 10 to 9, and `s3_bucket_object_versioning` was no longer reported as failed. The aggregate IAM failure count remained unchanged, so the IAM remediation is documented as validated by Access Analyzer rather than by the Prowler total.

---

## 2. Objective

The objective was to demonstrate an evidence-driven cloud-security workflow:

```text
Create controlled misconfiguration
        ↓
Identify the security problem
        ↓
Explain business/security impact
        ↓
Apply remediation
        ↓
Validate the new state
        ↓
Document residual risk and limitations
```

The project emphasizes why a configuration is risky and how remediation is verified rather than treating scanner output as the final conclusion.

---

## 3. Lab Scope and Safety Controls

### In scope

- AWS IAM user permissions
- IAM policy validation
- IAM Access Analyzer targeted access checks
- Amazon S3 Block Public Access
- Amazon S3 versioning
- S3 resource-policy public-access analysis
- Prowler IAM/S3 security assessment

### Safety controls

- Dedicated lab resources only
- No production or employer AWS environment
- No sensitive data stored in the S3 bucket
- The intentionally public S3 policy was **analyzed but never deployed**
- The lab IAM user was created without a console password or access keys
- Raw Prowler reports are excluded from the public repository because they contain account- and resource-specific metadata
- Published IAM ARNs redact the AWS account ID

---

## 4. Methodology

The assessment used two complementary validation approaches.

### Targeted validation

AWS IAM Access Analyzer was used to answer specific security questions about the policies created for the lab:

- Does the over-permissioned IAM policy grant destructive S3 actions?
- Does the remediated IAM policy prevent those actions?
- Would a proposed S3 resource policy grant public access?
- Does the restricted S3 policy avoid public access?

### Broader posture assessment

Prowler 5.37.1 assessed IAM and S3 controls across the lab AWS account. The raw scanner output was not treated as equivalent to the three deliberately scoped findings. Prowler results were instead used to provide additional context and before/after validation where the checks directly matched the changes made.

---

# Finding CS-001 — Over-Permissioned IAM Identity

**Severity:** High  
**Status:** Remediated  
**Control theme:** Least privilege

## Observation

The lab IAM user was deliberately assigned the following inline policy:

```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
```

The hypothetical business requirement was limited to listing one bucket and reading its objects. The configured access therefore exceeded the requirement.

## Risk

`Action: s3:*` with `Resource: *` creates broad S3 privileges. An identity with usable credentials could potentially perform actions unrelated to its job requirement, including destructive or security-sensitive operations.

Excessive privilege increases the blast radius of:

- Credential compromise
- Accidental administrative actions
- Malicious insider activity
- Application misuse

## Detection and validation

IAM Access Analyzer was asked whether the policy prevented three actions outside the intended requirement:

- `s3:DeleteBucket`
- `s3:PutBucketPolicy`
- `s3:DeleteObject`

The initial policy returned:

```text
FAIL
```

with the explanation that the policy granted one or more of the listed actions.

## Remediation

The inline policy was replaced with two scoped permissions:

```text
s3:ListBucket
→ one lab bucket

s3:GetObject
→ objects in one lab bucket
```

The remediated example is stored in [`../policies/iam-least-privilege.json`](../policies/iam-least-privilege.json).

## Post-remediation validation

The same Access Analyzer destructive-action test returned:

```text
PASS
```

The actual attached policy was also queried from IAM to confirm that only `s3:ListBucket` and `s3:GetObject` remained.

## Assessment

The scoped IAM finding was remediated. The Prowler aggregate IAM failure count remained at 15 before and after the changes, so this finding is not presented as a Prowler-resolved issue. Its validation is the targeted Access Analyzer `FAIL → PASS` test.

---

# Finding CS-002 — Proposed Public S3 Resource Policy

**Severity:** High  
**Status:** Remediated in policy simulation  
**Control theme:** Public-access prevention

## Observation

A proposed S3 resource policy was created with:

```json
{
  "Principal": "*",
  "Action": "s3:GetObject"
}
```

The policy represented an unsafe public-read design if attached to the bucket.

## Safety note

The unsafe policy was **never deployed** to the live S3 bucket. It was evaluated as a policy document so that public-access behavior could be tested without intentionally exposing an AWS resource to the internet.

## Risk

If such a policy were deployed without effective compensating controls, objects could become accessible outside the intended trust boundary. Possible impact includes:

- Unauthorized disclosure
- Sensitive data exposure
- Compliance violations
- Increased attack surface

## Detection and validation

IAM Access Analyzer `check-no-public-access` evaluated the simulated resource policy and returned:

```text
FAIL
```

indicating that the resource policy granted public access for the evaluated resource type.

## Remediation

The wildcard principal was replaced with one explicit IAM identity. The public repository uses a redacted ARN in [`../policies/s3-private-policy.json`](../policies/s3-private-policy.json).

The bucket was also configured with all four S3 Block Public Access settings enabled:

- `BlockPublicAcls: true`
- `IgnorePublicAcls: true`
- `BlockPublicPolicy: true`
- `RestrictPublicBuckets: true`

## Post-remediation validation

The restricted S3 resource policy returned:

```text
PASS
```

with Access Analyzer reporting that the policy did not grant public access for the evaluated S3 resource type.

## Assessment

The unsafe design was detected before deployment and replaced with a restricted policy. This finding demonstrates preventative policy analysis rather than cleanup after an actual public exposure.

---

# Finding CS-003 — S3 Versioning Disabled

**Severity:** Medium  
**Status:** Remediated  
**Control theme:** Data resilience and recovery

## Observation

The S3 lab bucket initially did not have object versioning enabled.

## Risk

Without versioning, accidental object overwrite or deletion provides fewer recovery options. The security impact depends on the data stored in the bucket, but reduced recoverability can increase operational impact following user error, destructive activity, or compromised credentials.

## Remediation

S3 versioning was enabled for the lab bucket.

AWS CLI validation returned:

```text
Enabled
```

## Post-remediation Prowler validation

The baseline Prowler assessment reported an S3 versioning failure. After versioning was enabled, the post-remediation comparison identified:

```text
s3_bucket_object_versioning
```

as a resolved failed check.

S3 failures decreased from:

```text
10 → 9
```

and the overall Prowler results changed from:

```text
Baseline: 32 PASS / 25 FAIL
After:    33 PASS / 24 FAIL
```

## Assessment

This finding was independently validated through both AWS CLI state inspection and Prowler before/after results.

---

## 5. Prowler Before / After Comparison

| Metric | Baseline | Post-remediation |
|---|---:|---:|
| Passed checks | 32 | 33 |
| Failed checks | 25 | 24 |
| Critical failures | 1 | 1 |
| High failures | 3 | 3 |
| Medium failures | 12 | 11 |
| Low failures | 9 | 9 |
| IAM failures | 15 | 15 |
| S3 failures | 10 | 9 |

**Resolved check:** `s3_bucket_object_versioning`

The Prowler comparison represents broader IAM/S3 account posture. Remaining findings were not automatically treated as findings created by this lab. The project therefore avoids claiming that every scanner failure was introduced or remediated during the exercise.

---

## 6. Risk Prioritization

| ID | Finding | Severity | Primary risk | Final state |
|---|---|---|---|---|
| CS-001 | Over-permissioned IAM identity | High | Excessive privilege / destructive S3 capability | Remediated |
| CS-002 | Proposed public S3 resource policy | High | Public object exposure if deployed | Remediated in simulation |
| CS-003 | S3 versioning disabled | Medium | Reduced recovery from overwrite/deletion | Remediated |

The High findings were prioritized first because they could expand unauthorized access or expose data. Versioning was treated as Medium because it primarily affected resilience and recovery in this lab context.

---

## 7. Evidence Mapping

| Evidence | Demonstrates |
|---|---|
| `02-iam-overpermission.png` | Wildcard IAM permissions and destructive-action `FAIL` |
| `03-s3-public-policy-analysis.png` | Proposed wildcard S3 principal evaluated as public (`FAIL`) |
| `04-prowler-baseline.png` | Sanitized IAM/S3 baseline posture |
| `05-iam-remediation.png` | Scoped IAM permissions and destructive-action `PASS` |
| `06-s3-hardening.png` | Four S3 Block Public Access controls enabled and versioning enabled |
| `07-s3-policy-remediation.png` | Restricted S3 resource policy evaluated as non-public (`PASS`) |
| `08-prowler-post-remediation.png` | Sanitized before/after posture and resolved versioning check |

---

## 8. Limitations

- The public S3 policy was simulated and was never attached to the live bucket.
- The project evaluated only IAM and S3 rather than the full AWS service catalog.
- Prowler produced broader account findings that were outside the deliberately created lab scope.
- The IAM remediation was validated directly with Access Analyzer; the aggregate Prowler IAM failure count did not change.
- Raw scanner exports are excluded because they contain account-specific identifiers and resource metadata.
- The lab did not contain production workloads or sensitive information, so business impact was assessed conceptually rather than from real organizational data.

---

## 9. Skills Demonstrated

- AWS cloud-security assessment
- IAM policy analysis
- Principle of least privilege
- Amazon S3 security controls
- S3 Block Public Access
- S3 versioning
- IAM Access Analyzer
- Prowler cloud-security scanning
- AWS CLI
- Security misconfiguration analysis
- Before/after remediation validation
- Risk prioritization
- Evidence sanitization
- Python CSV processing
- Security reporting

---

## 10. Analyst Conclusion

The assessment demonstrated three different cloud-security control problems and validated each remediation using evidence appropriate to the finding.

The strongest result was not simply that scanner counts improved. The project demonstrated targeted security reasoning:

- excessive IAM permission was proven and then restricted;
- a public S3 policy design was identified before deployment and replaced with restricted access;
- S3 resilience controls were improved and independently confirmed by Prowler.

The final state reduced the deliberately introduced IAM/S3 risks while preserving a clear distinction between scoped lab findings and broader AWS account posture.
