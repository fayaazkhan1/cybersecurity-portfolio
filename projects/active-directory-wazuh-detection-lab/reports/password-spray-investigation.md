# Password Spray Investigation Report

## Executive Summary

Wazuh detected multiple failed Active Directory authentication attempts against five fictional domain accounts on `DC01`. The attempts originated from the authorized Ubuntu lab system at `192.168.56.20` and occurred within the configured five-minute detection window.

The activity was confirmed as an authorized simulation conducted in an isolated lab.

## Environment

| Item | Value |
|---|---|
| Domain | `bluecorp.local` |
| Domain controller | `DC01` |
| Domain controller IP | `192.168.56.10` |
| Wazuh server / test source | `192.168.56.20` |
| Windows event | Event ID `4625` |
| Base Wazuh rule | `60122` |
| Custom Wazuh rule | `100110` |
| MITRE ATT&CK | `T1110.003 — Password Spraying` |

## Alert Description

The custom rule correlated five Windows failed-logon alerts from the same source within 300 seconds.

## Targeted Accounts

- `ajohnson`
- `bsmith`
- `cgomez`
- `dlee`
- `edavis`

All identities were fictional standard-user accounts created for the lab.

## Findings

- Five failed authentication events were observed.
- Five distinct domain accounts were targeted.
- The events originated from the authorized Ubuntu lab system.
- No related successful authentication was identified after the test.
- No account-lockout event was observed.
- No privileged accounts were targeted.

## Assessment

The activity matched the lab's password-spray detection criteria: several accounts, one source, repeated failed authentication, and a short time interval. Because the source and accounts were authorized, the event was classified as a true-positive detection of simulated behavior rather than a real incident.

## Recommended Production Response

1. Validate whether the source system is authorized.
2. Investigate or isolate an unknown source endpoint.
3. Review the targeted accounts for unusual activity.
4. Search for successful logons after the failures.
5. Determine whether privileged accounts were affected.
6. Reset credentials and revoke sessions when compromise is suspected.
7. Review similar activity across all domain controllers.
8. Preserve logs and document the incident timeline.

## Potential False Positives

- Expired cached credentials
- Misconfigured services or applications
- Scheduled tasks using old passwords
- Vulnerability scanners
- Help-desk testing
- Shared workstations

## Detection Limitations

- The frequency rule does not independently prove every username is distinct.
- Slow attacks may remain below the five-minute threshold.
- Distributed attacks may use several source addresses.
- Source-IP information may be absent or altered.
- Production thresholds require baselining and tuning.

## Conclusion

The lab demonstrated Active Directory authentication monitoring, Windows Event ID 4625 analysis, Wazuh event ingestion, custom detection development, threshold testing, and SOC-style investigation and reporting.
