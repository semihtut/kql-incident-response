# MITRE ATT&CK Mapping - Anonymous IP Address Sign-In (RB-0004)

> **Author:** Yunus (Threat Intel Lead)
> **Reviewed by:** Arina (IR Architect), Leo (Coordinator)
> **Version:** 1.0
> **Date:** 2026-02-22

## Tactic Coverage

| Tactic ID | Tactic Name | Techniques Mapped | Notes |
|-----------|-------------|-------------------|-------|
| TA0001 | Initial Access | T1078.004 | Valid Accounts: Cloud Accounts |
| TA0003 | Persistence | T1098, T1098.005, T1556.006, T1564.008 | Account manipulation, device registration, MFA modification, email hiding rules |
| TA0005 | Defense Evasion | T1556.006, T1564.008 | MFA modification, email hiding rules |
| TA0006 | Credential Access | T1528 | Steal Application Access Token |
| TA0008 | Lateral Movement | T1534 | Internal Spearphishing |
| TA0009 | Collection | T1114.003, T1530 | Email forwarding rules, cloud storage data |
| **TA0011** | **Command and Control** | **T1090.003, T1090** | **NEW TACTIC COVERAGE** - Multi-hop Proxy (Tor), Proxy |

> **TA0011 Command and Control is first-time coverage across all runbooks (RB-0001 through RB-0004).** The anonymous IP detection directly addresses adversary use of Tor exit nodes and proxy infrastructure for C2 obfuscation.

## Technique Detail

### T1078.004 - Valid Accounts: Cloud Accounts

| Field | Value |
|---|---|
| **Tactic** | Initial Access |
| **Detection Queries** | Query 1 (risk event extraction), Query 4 (session analysis) |
| **Coverage Level** | Confirmed |
| **Notes** | Sign-in from anonymous IP using valid cloud credentials. The anonymous IP adds a layer of obfuscation to credential-based access. |

### T1090.003 - Proxy: Multi-hop Proxy (NEW)

| Field | Value |
|---|---|
| **Tactic** | Command and Control |
| **Detection Queries** | Query 2 (IP classification - Tor detection via UserAgent analysis) |
| **Coverage Level** | Confirmed |
| **Notes** | Tor exit node usage is the highest-concern anonymous IP type. Detected via UserAgent containing "Tor Browser" signatures and ASN matching known Tor infrastructure. First C2-tactic technique mapped across all runbooks. |

### T1090 - Proxy (NEW)

| Field | Value |
|---|---|
| **Tactic** | Command and Control |
| **Detection Queries** | Query 2 (IP classification), Query 7A (TI lookup) |
| **Coverage Level** | Confirmed |
| **Notes** | Covers general proxy/anonymizer usage beyond Tor, including commercial VPN services, cloud proxy services (iCloud Private Relay), and hosting/VPS providers used as proxy infrastructure. Parent technique to T1090.003. |

### T1098 - Account Manipulation

| Field | Value |
|---|---|
| **Tactic** | Persistence |
| **Detection Queries** | Query 5 (directory changes) |
| **Coverage Level** | Confirmed |
| **Notes** | Post-access persistence via account modifications initiated from anonymous IP session. Includes role assignments, security info changes, and account property updates. |

### T1098.005 - Account Manipulation: Device Registration

| Field | Value |
|---|---|
| **Tactic** | Persistence |
| **Detection Queries** | Query 5 (directory changes) |
| **Coverage Level** | Confirmed |
| **Notes** | Device registration from anonymous IP session. Attacker registers a device to establish persistent access without needing to re-authenticate through anonymous infrastructure. |

### T1114.003 - Email Collection: Email Forwarding Rule

| Field | Value |
|---|---|
| **Tactic** | Collection |
| **Detection Queries** | Query 6 (email/file activity), Query 6B (inbox rule deep dive) |
| **Coverage Level** | Confirmed |
| **Notes** | Email forwarding rules created during or after anonymous IP sign-in. Classic BEC persistence mechanism. |

### T1528 - Steal Application Access Token

| Field | Value |
|---|---|
| **Tactic** | Credential Access |
| **Detection Queries** | Query 5 (OAuth consent detection) |
| **Coverage Level** | Confirmed |
| **Notes** | OAuth application consent from anonymous IP session. Attacker grants broad permissions to a malicious app to maintain persistent access to user data. |

### T1530 - Data from Cloud Storage Object

| Field | Value |
|---|---|
| **Tactic** | Collection |
| **Detection Queries** | Query 6 (file activity from SharePoint/OneDrive) |
| **Coverage Level** | Confirmed |
| **Notes** | Mass file access from SharePoint or OneDrive during anonymous IP session. Key indicator of data exfiltration attempt. |

### T1534 - Internal Spearphishing

| Field | Value |
|---|---|
| **Tactic** | Lateral Movement |
| **Detection Queries** | Query 6 (email send operations) |
| **Coverage Level** | Confirmed |
| **Notes** | Emails sent to internal recipients from compromised account during anonymous IP session. Attacker leverages compromised identity to phish other users from a trusted sender. |

### T1556.006 - Modify Authentication Process: MFA

| Field | Value |
|---|---|
| **Tactic** | Persistence, Defense Evasion |
| **Detection Queries** | Query 5 (MFA registration/modification from anonymous IP) |
| **Coverage Level** | Confirmed |
| **Notes** | MFA method registration or modification from anonymous IP session. Critical persistence indicator - attacker adds their own MFA device to maintain access. |

### T1564.008 - Hide Artifacts: Email Hiding Rules

| Field | Value |
|---|---|
| **Tactic** | Persistence, Defense Evasion |
| **Detection Queries** | Query 6B (inbox rule deep dive - rules that delete or move to RSS/Junk) |
| **Coverage Level** | Confirmed |
| **Notes** | Inbox rules created to hide security notifications, password reset emails, or responses to phishing messages sent from the compromised account. |

## Threat Actors

### Midnight Blizzard (APT29)

| Field | Value |
|---|---|
| **Attribution Confidence** | Medium |
| **Relevant TTPs** | T1078.004, T1090.003, T1528 |
| **Motivation** | Espionage |
| **Known Targets** | Government, diplomatic, think tanks |
| **Notable** | Known to use Tor and residential proxy networks to obfuscate access to compromised cloud accounts. OAuth consent abuse is a hallmark technique. |

### Sandworm (APT44)

| Field | Value |
|---|---|
| **Attribution Confidence** | Medium |
| **Relevant TTPs** | T1078.004, T1090, T1090.003 |
| **Motivation** | Espionage, Disruption |
| **Known Targets** | Critical infrastructure, energy, government |
| **Notable** | Uses layered proxy infrastructure including Tor and commercial VPN services for operational security during intrusions. |

### Storm-1152

| Field | Value |
|---|---|
| **Attribution Confidence** | Low-Medium |
| **Relevant TTPs** | T1078.004, T1090 |
| **Motivation** | Financial (CaaS - Cybercrime as a Service) |
| **Known Targets** | Broad targeting via automated credential abuse |
| **Notable** | Operates at scale using anonymous infrastructure for mass credential testing and account creation. Anonymous IPs are fundamental to their operational model. |

### Scattered Spider (Octo Tempest)

| Field | Value |
|---|---|
| **Attribution Confidence** | Medium |
| **Relevant TTPs** | T1078.004, T1090, T1556.006 |
| **Motivation** | Financial (ransomware, data extortion) |
| **Known Targets** | Telecom, hospitality, technology |
| **Notable** | Known to use VPN and proxy infrastructure during social engineering campaigns. MFA manipulation is a core technique after initial access. |

## Attack Chains

### Chain 1: Credential Theft → Anonymous Access → BEC

```
Credential acquisition (phishing/stealer)
    → Sign-in from Tor/VPN (T1078.004 + T1090.003)
    → MFA bypass or completion
    → Inbox rule creation (T1114.003 + T1564.008)
    → Internal phishing (T1534)
    → Data collection (T1530)
```

| Step | Technique | RB-0004 Coverage |
|---|---|---|
| Anonymous sign-in | T1078.004 + T1090.003 | Query 1, Query 2 |
| Session establishment | T1078.004 | Query 4 |
| Persistence - inbox rules | T1114.003, T1564.008 | Query 6, Query 6B |
| Lateral movement | T1534 | Query 6 |
| Data collection | T1530 | Query 6 |

### Chain 2: Proxy Infrastructure → Automated Account Testing

```
Distributed proxy infrastructure (T1090)
    → Credential spray from anonymous IPs (T1078.004)
    → Successful auth → Anonymous session established
    → OAuth consent (T1528)
    → Persistent data access via API
```

| Step | Technique | RB-0004 Coverage |
|---|---|---|
| Proxy infrastructure | T1090 | Query 2, Query 7A |
| Account access | T1078.004 | Query 1 |
| Persistence - OAuth | T1528 | Query 5 |
| API-based access | T1528 | Query 5 |

## Coverage Gaps

| Technique ID | Technique Name | Gap Description | Risk Level | Recommendation |
|---|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | Phishing that leads to credential capture before anonymous access | Medium | Cover in future email-focused runbook |
| T1567.002 | Exfiltration Over Web Service: to Cloud Storage | Data exfiltration to external cloud storage after anonymous access | Medium | Cover in Tier 2 data exfiltration runbook |
| T1204.001 | User Execution: Malicious Link | User clicking phishing link that leads to credential theft | Low | Cover in email security runbook |
| T1557 | Adversary-in-the-Middle | AiTM phishing proxies that capture tokens | High | Cover in dedicated AiTM runbook (Tier 2) |

## Coverage Delta

### Cross-Runbook Technique Coverage

| Technique | RB-0001 | RB-0002 | RB-0003 | RB-0004 |
|---|---|---|---|---|
| T1078.004 | Yes | Yes | Yes | Yes |
| T1090 | - | - | - | **NEW** |
| T1090.003 | - | - | - | **NEW** |
| T1098 | Yes | Yes | Yes | Yes |
| T1098.005 | - | - | - | **NEW** |
| T1110.003 | Yes | - | - | - |
| T1110.004 | Yes | - | Yes | - |
| T1114.003 | Yes | Yes | Yes | Yes |
| T1528 | Yes | Yes | Yes | Yes |
| T1530 | Yes | Yes | Yes | Yes |
| T1534 | Yes | Yes | Yes | Yes |
| T1539 | Yes | Yes | - | - |
| T1550.004 | - | Yes | - | - |
| T1556.006 | Yes | Yes | Yes | Yes |
| T1564.008 | Yes | Yes | Yes | Yes |
| T1589.001 | - | - | Yes | - |

### Tactic Coverage Across All Runbooks

| Tactic | RB-0001 | RB-0002 | RB-0003 | RB-0004 |
|---|---|---|---|---|
| Reconnaissance | - | - | Yes | - |
| Initial Access | Yes | Yes | Yes | Yes |
| Persistence | Yes | Yes | Yes | Yes |
| Privilege Escalation | Yes | - | - | - |
| Defense Evasion | Yes | Yes | Yes | Yes |
| Credential Access | Yes | Yes | Yes | Yes |
| Lateral Movement | Yes | Yes | Yes | Yes |
| Collection | Yes | Yes | Yes | Yes |
| **Command and Control** | - | - | - | **Yes (NEW)** |

## Summary

- **Net new techniques:** 3 (T1090.003, T1090, T1098.005)
- **Net new tactic:** 1 (TA0011 Command and Control)
- **Total unique techniques across all runbooks:** 16
- **Total tactic coverage:** 9 of 14 (64%)
