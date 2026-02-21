# MITRE ATT&CK Mapping - Impossible Travel Activity (RB-0002)

> **Author:** Yunus (Threat Intel Lead)
> **Reviewed by:** Arina (IR Architect), Leo (Coordinator)
> **Version:** 1.0

## Tactic Coverage

| Tactic | ID | Techniques Covered | Coverage Level |
|---|---|---|---|
| Initial Access | TA0001 | T1078.004 | Full |
| Persistence | TA0003 | T1098, T1556.006, T1564.008 | Full |
| Defense Evasion | TA0005 | T1550.004, T1556.006, T1564.008 | Full |
| Credential Access | TA0006 | T1539, T1528 | Full |
| Lateral Movement | TA0008 | T1534 | Partial |
| Collection | TA0009 | T1114.003, T1530 | Partial |

## Technique Detail

### T1078.004 - Valid Accounts: Cloud Accounts (Confirmed)
- **Tactic:** Initial Access, Persistence, Defense Evasion, Privilege Escalation
- **Detection:** Query 1 (risk event extraction), Query 2 (speed calculation), Query 3A (baseline)
- **Coverage:** Full - this is the primary detection target
- **Notes:** Impossible travel directly detects concurrent use of valid cloud credentials from incompatible locations

### T1550.004 - Use Alternate Authentication Material: Web Session Cookie (Confirmed) **NEW**
- **Tactic:** Defense Evasion, Lateral Movement
- **Detection:** Query 5A (non-interactive sign-ins from anomalous IP), Query 5B (session cross-IP)
- **Coverage:** Full - unique to RB-0002, not covered by RB-0001
- **Notes:** AiTM attacks intercept session cookies after MFA completion. The stolen cookie is replayed from attacker infrastructure, creating the impossible travel pattern. This technique BYPASSES MFA.

### T1539 - Steal Web Session Cookie (Confirmed)
- **Tactic:** Credential Access
- **Detection:** Query 5A, Query 5B
- **Coverage:** Full
- **Notes:** Precursor to T1550.004. The cookie theft itself happens via AiTM proxy (T1557), but the usage is detected by our token replay queries.

### T1098 - Account Manipulation (Confirmed)
- **Tactic:** Persistence
- **Detection:** Query 6A (directory changes)
- **Coverage:** Full
- **Sub-techniques covered:**
  - T1098.001 - Additional Cloud Credentials
  - T1098.003 - Additional Cloud Roles
  - T1098.005 - Device Registration

### T1528 - Steal Application Access Token (Confirmed)
- **Tactic:** Credential Access
- **Detection:** Query 6A (OAuth consent detection)
- **Coverage:** Full

### T1556.006 - Modify Authentication Process: MFA (Confirmed)
- **Tactic:** Persistence, Defense Evasion
- **Detection:** Query 6A (MFA registration/deletion)
- **Coverage:** Full

### T1564.008 - Hide Artifacts: Email Hiding Rules (Confirmed)
- **Tactic:** Persistence, Defense Evasion
- **Detection:** Query 6C (inbox rule deep dive)
- **Coverage:** Full

### T1114.003 - Email Collection: Email Forwarding Rule (Confirmed)
- **Tactic:** Collection
- **Detection:** Query 6C (inbox rule parameter extraction)
- **Coverage:** Full

### T1534 - Internal Spearphishing (Confirmed)
- **Tactic:** Lateral Movement
- **Detection:** Query 6B (email sent volume monitoring)
- **Coverage:** Partial - volume-based only

### T1530 - Data from Cloud Storage Object (Confirmed)
- **Tactic:** Collection
- **Detection:** Query 6B (file download monitoring)
- **Coverage:** Partial - volume-based only

## Threat Actors

### Midnight Blizzard (APT29)
- **Attribution confidence:** High
- **Relevant TTPs:** Token theft via AiTM (T1550.004, T1539), OAuth application abuse (T1528), persistent access via app registrations (T1098)
- **Motivation:** Espionage
- **Known targets:** Government, diplomatic, technology sectors

### Octo Tempest (Scattered Spider)
- **Attribution confidence:** High
- **Relevant TTPs:** Social engineering for MFA bypass, SIM swapping, identity-based attacks
- **Motivation:** Financial
- **Known targets:** Telecommunications, entertainment, financial services

### Storm-0558
- **Attribution confidence:** Medium
- **Relevant TTPs:** Token forgery (T1550.004), email collection (T1114.003)
- **Motivation:** Espionage
- **Known targets:** Government, diplomatic organizations
- **Notable:** 2023 Microsoft Exchange token forgery campaign

## New Coverage Added by RB-0002

| Technique | RB-0001 Coverage | RB-0002 Coverage | Delta |
|---|---|---|---|
| T1550.004 Web Session Cookie | Listed as gap | **Full coverage** | **NEW** |
| T1539 Steal Web Session Cookie | Possible (via risk event) | **Full coverage** (via token replay detection) | Upgraded |
| T1078.004 Valid Accounts | Full | Full | Maintained |
| T1098 Account Manipulation | Full | Full | Maintained |
| T1556.006 Modify Auth: MFA | Full | Full | Maintained |
| T1564.008 Email Hiding Rules | Full | Full | Maintained |
| T1114.003 Email Forwarding | Full | Full | Maintained |
| T1528 Steal App Token | Full | Full | Maintained |
| T1530 Cloud Storage | Partial | Partial | Maintained |
| T1534 Internal Spearphishing | Partial | Partial | Maintained |

**Net new techniques:** 1 (T1550.004)
**Upgraded techniques:** 1 (T1539: possible → confirmed)
**Total unique techniques across RB-0001 + RB-0002:** 12
