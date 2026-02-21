# MITRE ATT&CK Coverage

Current coverage of MITRE ATT&CK techniques across all published runbooks. This page is updated as new runbooks are added.

## Coverage Summary

| Metric | Count |
|--------|-------|
| Tactics covered | 7 of 14 |
| Techniques mapped | 15 |
| Runbooks published | 1 |

---

## Covered Tactics

| Tactic | ID | Techniques | Runbooks |
|--------|----|------------|----------|
| Initial Access | TA0001 | 3 | RB-0001 |
| Persistence | TA0003 | 3 | RB-0001 |
| Privilege Escalation | TA0004 | 1 | RB-0001 |
| Defense Evasion | TA0005 | 2 | RB-0001 |
| Credential Access | TA0006 | 3 | RB-0001 |
| Lateral Movement | TA0008 | 1 | RB-0001 |
| Collection | TA0009 | 2 | RB-0001 |

## Technique Detail

All techniques currently mapped from [RB-0001: Unfamiliar Sign-In Properties](runbooks/identity/unfamiliar-sign-in-properties.md):

| Technique ID | Technique Name | Tactic | Confidence |
|-------------|----------------|--------|------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Confirmed |
| T1098 | Account Manipulation | Persistence | Confirmed |
| T1110.003 | Brute Force: Password Spraying | Credential Access | Probable |
| T1110.004 | Brute Force: Credential Stuffing | Credential Access | Probable |
| T1114.003 | Email Collection: Email Forwarding Rule | Collection | Confirmed |
| T1528 | Steal Application Access Token | Credential Access | Confirmed |
| T1530 | Data from Cloud Storage Object | Collection | Confirmed |
| T1534 | Internal Spearphishing | Lateral Movement | Confirmed |
| T1539 | Steal Web Session Cookie | Initial Access | Possible |
| T1556.006 | Modify Authentication Process: MFA | Persistence, Defense Evasion | Confirmed |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Persistence, Defense Evasion | Confirmed |

## Planned Coverage

### Tier 1 (Identity)
- MFA fatigue / MFA bombing
- Impossible travel detection
- Suspicious browser sign-in
- Password spray detection
- Risky sign-in from anonymous IP

### Tier 2 (Lateral Movement & Escalation)
- Privilege escalation via PIM abuse
- OAuth consent grant abuse
- Mailbox delegation abuse
- Cross-tenant access anomaly
- Service principal compromise

### Tier 3 (Cloud Infrastructure)
- Mass secret retrieval from Key Vault
- Storage account public exposure
- Subscription hijacking
- Cryptomining detection
- NSG/firewall rule tampering

---

## Coverage Gaps

Tactics not yet covered by any runbook:

| Tactic | ID | Planned Tier |
|--------|----|-------------|
| Execution | TA0002 | Tier 2 |
| Discovery | TA0007 | Tier 2 |
| Exfiltration | TA0010 | Tier 2 |
| Command and Control | TA0011 | Tier 2 |
| Impact | TA0040 | Tier 3 |
| Resource Development | TA0042 | Tier 3 |
| Reconnaissance | TA0043 | Tier 3 |
