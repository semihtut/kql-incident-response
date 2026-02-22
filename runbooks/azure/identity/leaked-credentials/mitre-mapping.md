# MITRE ATT&CK Mapping - Leaked Credentials (RB-0003)

> **Author:** Yunus (Threat Intel Lead)
> **Reviewed by:** Arina (IR Architect), Leo (Coordinator)
> **Version:** 1.0

## Tactic Coverage

| Tactic | ID | Techniques Covered | Coverage Level |
|---|---|---|---|
| Reconnaissance | TA0043 | T1589.001 | Partial |
| Initial Access | TA0001 | T1078.004 | Full |
| Persistence | TA0003 | T1098, T1556.006, T1564.008 | Full |
| Defense Evasion | TA0005 | T1556.006, T1564.008 | Full |
| Credential Access | TA0006 | T1110.004, T1528 | Full |
| Lateral Movement | TA0008 | T1534 | Partial |
| Collection | TA0009 | T1114.003, T1530 | Partial |

## Technique Detail

### T1589.001 - Gather Victim Identity Information: Credentials (Partial) **NEW**
- **Tactic:** Reconnaissance
- **Detection:** Query 1 (risk event extraction confirms credential was found in leaked database)
- **Coverage:** Partial - we detect the RESULT of credential gathering (the leak), not the act itself
- **Notes:** The leakedCredentials risk event fires when Microsoft's DCU identifies user credentials in dark web dumps, paste sites, or underground forums. This is the first technique in the reconnaissance phase that we can detect across any runbook.

### T1078.004 - Valid Accounts: Cloud Accounts (Confirmed)
- **Tactic:** Initial Access, Persistence, Defense Evasion, Privilege Escalation
- **Detection:** Query 4A (anomalous sign-in detection), Query 6 (MFA/legacy auth assessment)
- **Coverage:** Full - detects unauthorized use of valid credentials post-leak
- **Notes:** Leaked credentials directly enable T1078.004. If the password hasn't been changed and MFA isn't enforced, the attacker has valid credentials ready to use.

### T1110.004 - Brute Force: Credential Stuffing (Confirmed) **NEW**
- **Tactic:** Credential Access
- **Detection:** Query 4A (failed sign-in analysis from multiple IPs)
- **Coverage:** Full - detects credential testing patterns post-leak
- **Notes:** Leaked credentials are frequently used in automated credential stuffing attacks where the same username/password pair is tested across multiple services and tenants.

### T1098 - Account Manipulation (Confirmed)
- **Tactic:** Persistence
- **Detection:** Query 5A (directory changes)
- **Coverage:** Full
- **Sub-techniques covered:**
  - T1098.001 - Additional Cloud Credentials
  - T1098.003 - Additional Cloud Roles
  - T1098.005 - Device Registration

### T1528 - Steal Application Access Token (Confirmed)
- **Tactic:** Credential Access
- **Detection:** Query 5A (OAuth consent detection)
- **Coverage:** Full

### T1556.006 - Modify Authentication Process: MFA (Confirmed)
- **Tactic:** Persistence, Defense Evasion
- **Detection:** Query 5A (MFA registration/deletion)
- **Coverage:** Full

### T1564.008 - Hide Artifacts: Email Hiding Rules (Confirmed)
- **Tactic:** Persistence, Defense Evasion
- **Detection:** Query 5C (inbox rule deep dive)
- **Coverage:** Full

### T1114.003 - Email Collection: Email Forwarding Rule (Confirmed)
- **Tactic:** Collection
- **Detection:** Query 5C (inbox rule parameter extraction)
- **Coverage:** Full

### T1534 - Internal Spearphishing (Confirmed)
- **Tactic:** Lateral Movement
- **Detection:** Query 5B (email sent volume monitoring)
- **Coverage:** Partial - volume-based only

### T1530 - Data from Cloud Storage Object (Confirmed)
- **Tactic:** Collection
- **Detection:** Query 5B (file download monitoring)
- **Coverage:** Partial - volume-based only

## Threat Actors

### Info-Stealer Campaigns (Raccoon, RedLine, Vidar, Lumma)
- **Attribution confidence:** High
- **Relevant TTPs:** Credential harvesting via info-stealer malware (T1589.001), credential stuffing (T1110.004), valid account usage (T1078.004)
- **Motivation:** Financial (credential marketplace sales, initial access broker)
- **Known targets:** Broad targeting - any organization whose employees are infected with info-stealer malware
- **Notable:** Most common source of leaked credentials in 2024-2025. Credentials are sold on Russian Market, Genesis Market successors, and Telegram channels.

### Storm-0539 (Atlas Lion)
- **Attribution confidence:** Medium
- **Relevant TTPs:** Credential reuse (T1078.004), BEC via email rules (T1114.003, T1564.008)
- **Motivation:** Financial (gift card fraud)
- **Known targets:** Retail, hospitality organizations

### FIN7 / FIN8
- **Attribution confidence:** Medium
- **Relevant TTPs:** Credential marketplace usage (T1589.001), valid account abuse (T1078.004), OAuth app persistence (T1528)
- **Motivation:** Financial
- **Known targets:** Financial services, retail, hospitality

### Scattered Spider (Octo Tempest)
- **Attribution confidence:** Medium
- **Relevant TTPs:** Credential reuse with social engineering for MFA bypass
- **Motivation:** Financial (ransomware, extortion)
- **Known targets:** Technology, telecommunications, gaming

## New Coverage Added by RB-0003

| Technique | RB-0001 Coverage | RB-0002 Coverage | RB-0003 Coverage | Delta |
|---|---|---|---|---|
| T1589.001 Credentials Gathering | Not covered | Not covered | **Partial** | **NEW** |
| T1110.004 Credential Stuffing | Probable | Not primary | **Full** (via failed sign-in analysis) | Upgraded |
| T1078.004 Valid Accounts | Full | Full | Full | Maintained |
| T1098 Account Manipulation | Full | Full | Full | Maintained |
| T1556.006 Modify Auth: MFA | Full | Full | Full | Maintained |
| T1564.008 Email Hiding Rules | Full | Full | Full | Maintained |
| T1114.003 Email Forwarding | Full | Full | Full | Maintained |
| T1528 Steal App Token | Full | Full | Full | Maintained |
| T1530 Cloud Storage | Partial | Partial | Partial | Maintained |
| T1534 Internal Spearphishing | Partial | Partial | Partial | Maintained |

**Net new techniques:** 1 (T1589.001 - first Reconnaissance tactic coverage)
**Upgraded techniques:** 1 (T1110.004: probable → confirmed)
**Total unique techniques across RB-0001 + RB-0002 + RB-0003:** 13
