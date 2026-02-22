# MITRE ATT&CK Mapping - MFA Fatigue Attack (RB-0005)

> **Author:** Yunus (Threat Intel Lead)
> **Reviewed by:** Arina (IR Architect), Leo (Coordinator)
> **Version:** 1.0
> **Date:** 2026-02-22

## Tactic Coverage

| Tactic ID | Tactic Name | Techniques Mapped | Notes |
|-----------|-------------|-------------------|-------|
| TA0001 | Initial Access | T1078.004 | Valid Accounts: Cloud Accounts - attacker has valid password |
| TA0003 | Persistence | T1098, T1556.006, T1564.008 | Account manipulation, MFA modification, email hiding rules (all post-approval) |
| TA0005 | Defense Evasion | T1556.006, T1564.008 | MFA modification, email hiding rules (all post-approval) |
| **TA0006** | **Credential Access** | **T1621**, T1528 | **NEW TECHNIQUE - T1621 MFA Request Generation**. Also covers OAuth token theft post-approval. |
| TA0008 | Lateral Movement | T1534 | Internal Spearphishing (post-approval) |
| TA0009 | Collection | T1114.003, T1530 | Email forwarding rules, cloud storage data (post-approval) |

> **T1621 - Multi-Factor Authentication Request Generation is first-time technique coverage across all runbooks (RB-0001 through RB-0005).** This is the defining technique for MFA fatigue attacks. While prior runbooks referenced T1621 as a coverage gap (see RB-0001 Gap #2), RB-0005 is the first to provide dedicated, full detection coverage of this technique.

## Technique Detail

### T1621 - Multi-Factor Authentication Request Generation (NEW)

| Field | Value |
|---|---|
| **Tactic** | Credential Access |
| **Detection Queries** | Query 1 (MFA push pattern extraction from SigninLogs), Query 2 (burst frequency analysis - repeated MFA failures followed by success), Query 3 (baseline comparison of MFA challenge frequency) |
| **Coverage Level** | Confirmed |
| **Notes** | This is the PRIMARY technique for RB-0005 and the first dedicated detection across all runbooks. The technique describes adversaries who bombard a user with repeated MFA push notifications, exploiting notification fatigue to coerce the user into approving a fraudulent authentication request. Detection relies on identifying repeated MFA-related ResultType failures (50074, 50076, 500121) from a single IP targeting a single user within a compressed timeframe, followed by a successful authentication. A count of >5 MFA challenges within 1 hour from the same source IP is a strong signal. The time-of-day pattern is critical: attacks conducted between 00:00-06:00 local time exploit the user's reduced alertness. |

### T1078.004 - Valid Accounts: Cloud Accounts

| Field | Value |
|---|---|
| **Tactic** | Initial Access |
| **Detection Queries** | Query 1 (successful sign-in post-MFA approval), Query 4 (session activity analysis) |
| **Coverage Level** | Confirmed |
| **Notes** | The MFA fatigue attack is only possible when the attacker already possesses valid credentials (username + password). The successful sign-in event after MFA approval is the confirmation of T1078.004. This technique is a prerequisite for T1621 - without valid credentials, MFA prompts are never generated. |

### T1098 - Account Manipulation

| Field | Value |
|---|---|
| **Tactic** | Persistence |
| **Detection Queries** | Query 5 (directory changes post-approval) |
| **Coverage Level** | Confirmed |
| **Notes** | Post-MFA-approval persistence via account modifications. Attackers who succeed via MFA fatigue typically move fast to establish persistence before the victim realizes they approved a fraudulent request. Key indicators: MFA method registration, role assignments, and security info changes within 15 minutes of the suspicious MFA approval. |

### T1556.006 - Modify Authentication Process: MFA

| Field | Value |
|---|---|
| **Tactic** | Persistence, Defense Evasion |
| **Detection Queries** | Query 5 (MFA registration/modification post-approval) |
| **Coverage Level** | Confirmed |
| **Notes** | Critical post-approval persistence indicator. After gaining access via MFA fatigue, the attacker registers their own MFA device (phone, authenticator app, FIDO key) to maintain persistent access without needing to repeat the fatigue attack. Detection focuses on MFA method registration events from the attacker's IP/session within the post-approval window. This is the single most important persistence action to detect - if the attacker registers their own MFA method, a password reset alone will NOT revoke access. |

### T1564.008 - Hide Artifacts: Email Hiding Rules

| Field | Value |
|---|---|
| **Tactic** | Persistence, Defense Evasion |
| **Detection Queries** | Query 6 (inbox rule deep dive - rules that delete, move to RSS/Junk, or mark as read) |
| **Coverage Level** | Confirmed |
| **Notes** | Inbox rules created to hide security notifications, MFA registration confirmations, password reset emails, or IT helpdesk responses. Particularly relevant in MFA fatigue scenarios where the victim may become suspicious after approving an unexpected MFA prompt and check their email. The attacker preemptively hides evidence of compromise. |

### T1114.003 - Email Collection: Email Forwarding Rule

| Field | Value |
|---|---|
| **Tactic** | Collection |
| **Detection Queries** | Query 6 (email/file activity - inbox rule parameter extraction with ForwardTo detection) |
| **Coverage Level** | Confirmed |
| **Notes** | Email forwarding rules created during or after MFA fatigue compromise. Classic BEC persistence mechanism. Often combined with T1564.008 - the attacker creates a forwarding rule to exfiltrate email AND a hiding rule to prevent the victim from seeing responses or security alerts. |

### T1528 - Steal Application Access Token

| Field | Value |
|---|---|
| **Tactic** | Credential Access |
| **Detection Queries** | Query 5 (OAuth consent detection from AuditLogs) |
| **Coverage Level** | Confirmed |
| **Notes** | OAuth application consent from the compromised session post-MFA-approval. The attacker grants broad permissions to a malicious or compromised OAuth application to maintain persistent API-level access to user data (Mail.Read, Files.ReadWrite.All). This persistence mechanism survives password resets and MFA method revocation. Scattered Spider and LAPSUS$ both use this technique after MFA fatigue success. |

### T1534 - Internal Spearphishing

| Field | Value |
|---|---|
| **Tactic** | Lateral Movement |
| **Detection Queries** | Query 6 (email send operations - volume monitoring) |
| **Coverage Level** | Confirmed |
| **Notes** | Emails sent to internal recipients from the compromised account post-MFA-approval. The attacker leverages the compromised identity to phish other users from a trusted sender. Particularly dangerous after MFA fatigue compromise because the attacker has full mailbox access and can craft contextually convincing internal phishing messages using existing email threads. |

### T1530 - Data from Cloud Storage Object

| Field | Value |
|---|---|
| **Tactic** | Collection |
| **Detection Queries** | Query 6 (file activity from SharePoint/OneDrive - download volume monitoring) |
| **Coverage Level** | Confirmed |
| **Notes** | Mass file access from SharePoint or OneDrive during the post-MFA-approval session. Key indicator of data exfiltration attempt. MFA fatigue attackers (particularly Scattered Spider) are known to rapidly access and download sensitive files from cloud storage within the first hour of gaining access. |

## Threat Actors

### Scattered Spider (Octo Tempest)

| Field | Value |
|---|---|
| **Attribution Confidence** | HIGH |
| **Relevant TTPs** | T1621, T1078.004, T1556.006, T1528, T1534 |
| **Motivation** | Financial (ransomware, data extortion) |
| **Known Targets** | MGM Resorts, Caesars Entertainment, Twilio, Cloudflare, telecommunications, hospitality, technology |
| **Notable** | The most prolific and sophisticated user of MFA fatigue attacks. Scattered Spider's hallmark is combining MFA bombing with simultaneous social engineering - specifically calling the victim's IT helpdesk or the victim directly, posing as IT support, and instructing the user to approve the MFA prompt. In the MGM Resorts attack (September 2023), they used this exact combination to gain initial access. They also target Okta administrators specifically, understanding that compromising an IdP admin gives them the ability to reset MFA for any user in the organization. Post-approval, they move to OAuth app consent (T1528), MFA method registration (T1556.006), and rapid lateral movement via internal phishing (T1534) and Teams messages. Their speed is exceptional - full persistence is typically established within 10-15 minutes of MFA approval. |

### LAPSUS$ (DEV-0537)

| Field | Value |
|---|---|
| **Attribution Confidence** | HIGH |
| **Relevant TTPs** | T1621, T1078.004, T1098, T1530 |
| **Motivation** | Notoriety, data theft, extortion |
| **Known Targets** | Microsoft, Okta, Nvidia, Samsung, Uber, Rockstar Games, T-Mobile |
| **Notable** | Pioneered the mainstream use of MFA fatigue attacks against major technology companies. In the Uber breach (September 2022), a LAPSUS$-affiliated attacker obtained an Uber contractor's credentials from the dark web, then bombarded the contractor with MFA push notifications for over an hour. The attacker simultaneously contacted the contractor on WhatsApp, claiming to be Uber IT, and instructed them to approve the request. Their operational model: purchase credentials from initial access brokers or info-stealer logs, then MFA bomb the target. LAPSUS$ demonstrated that MFA fatigue is effective even against security-aware technology companies. Post-access, they focus on data theft and public leaking rather than ransomware. |

### Storm-0875 (GhostSec / Scattered Spider Affiliates)

| Field | Value |
|---|---|
| **Attribution Confidence** | MEDIUM |
| **Relevant TTPs** | T1621, T1078.004, T1556.006 |
| **Motivation** | Financial |
| **Known Targets** | Financial services, telecommunications |
| **Notable** | Uses similar MFA fatigue tactics as Scattered Spider, suggesting shared playbooks or overlapping membership. Distinguishing characteristic: frequently combines MFA fatigue with SIM swapping (porting the victim's phone number to an attacker-controlled SIM) to intercept SMS-based MFA codes when push notification fatigue fails. This dual approach - push bombing AND SIM swap as fallback - makes them effective against organizations that use SMS as their primary or fallback MFA method. Often targets accounts that have recently been flagged with leaked credentials, suggesting they monitor info-stealer log marketplaces for fresh credential availability. |

### Cozy Bear (APT29 / Midnight Blizzard)

| Field | Value |
|---|---|
| **Attribution Confidence** | LOW-MEDIUM |
| **Relevant TTPs** | T1621, T1078.004, T1528 |
| **Motivation** | Espionage |
| **Known Targets** | Government agencies, diplomatic organizations, think tanks, technology companies |
| **Notable** | While primarily known for more sophisticated techniques (token forgery, OAuth abuse, supply chain compromise), APT29 has been observed using MFA fatigue in targeted campaigns against government entities where other bypass methods were unavailable. Their use of T1621 is more selective and targeted - typically against specific high-value individuals rather than the spray-and-pray approach of Scattered Spider/LAPSUS$. When APT29 uses MFA fatigue, it is usually combined with extensive prior reconnaissance (identifying the target's work schedule, MFA method, and likely fatigue windows) and timed to coincide with off-hours or high-stress periods. Attribution is lower-confidence because APT29 has many alternative MFA bypass techniques and may not need to resort to fatigue attacks in most campaigns. |

## Attack Chains

### Chain 1: Credential Purchase --> MFA Bombing --> Approval --> BEC

```
Credential acquisition (dark web purchase, info-stealer logs)
    --> Valid password obtained (T1078.004 prerequisite)
    --> MFA push notification bombing (T1621)
    --> Repeated denials... user fatigued... user approves
    --> Successful sign-in (T1078.004)
    --> Inbox rule creation (T1564.008 + T1114.003)
    --> Internal phishing from compromised account (T1534)
    --> Data collection from SharePoint/OneDrive (T1530)
```

| Step | Technique | RB-0005 Coverage |
|---|---|---|
| Credential acquisition | Pre-attack (not detected) | Not covered - see Coverage Gaps |
| MFA bombing | T1621 | Query 1, Query 2 (burst pattern analysis) |
| MFA approval | T1621 + T1078.004 | Query 1 (success after repeated failures) |
| Session establishment | T1078.004 | Query 4 |
| Persistence - inbox rules | T1564.008, T1114.003 | Query 6 |
| Lateral movement | T1534 | Query 6 |
| Data collection | T1530 | Query 6 |

**Chain coverage: 5/7 steps detected. The credential acquisition phase (how the password was originally obtained) is outside this runbook's scope.**

### Chain 2: Phishing --> Credential Theft --> MFA Fatigue + Helpdesk Social Engineering --> Full Account Takeover

```
Phishing email with credential harvester (T1566.002)
    --> User enters credentials on fake login page
    --> Attacker obtains username + password
    --> MFA push notification bombing begins (T1621)
    --> Simultaneously: attacker calls IT helpdesk claiming to be the user
    --> Helpdesk resets MFA OR user approves push under social pressure
    --> Successful sign-in (T1078.004)
    --> MFA method registration - attacker adds own device (T1556.006)
    --> OAuth app consent for persistent API access (T1528)
    --> Email forwarding rule to external address (T1114.003)
    --> Mass file download from SharePoint (T1530)
```

| Step | Technique | RB-0005 Coverage |
|---|---|---|
| Phishing | T1566.002 | Not covered - see Coverage Gaps |
| Credential theft | Pre-attack | Not covered |
| MFA bombing | T1621 | Query 1, Query 2 |
| Helpdesk social engineering | T1598 (Phishing for Information) | Not covered - see Coverage Gaps |
| MFA approval / helpdesk reset | T1621 + T1078.004 | Query 1 |
| MFA method registration | T1556.006 | Query 5 |
| OAuth consent | T1528 | Query 5 |
| Email forwarding | T1114.003 | Query 6 |
| Data exfiltration | T1530 | Query 6 |

**Chain coverage: 6/9 steps detected. Gaps exist in the upstream credential acquisition phase (phishing) and the social engineering component (helpdesk manipulation). The social engineering gap is significant because Scattered Spider's most successful attacks combine MFA bombing with helpdesk calls - the helpdesk call is invisible to log-based detection.**

## Coverage Gaps

| Technique ID | Technique Name | Gap Description | Risk Level | Recommendation |
|---|---|---|---|---|
| T1566 | Phishing | Phishing campaign that captured the credentials used for MFA fatigue. This is the upstream vector - how the attacker got the password in the first place. | Medium | Cover in dedicated email security / phishing investigation runbook using MDO tables (EmailEvents, EmailUrlInfo). Cross-reference when RB-0005 confirms MFA fatigue compromise. |
| T1598 | Phishing for Information | Helpdesk social engineering component where attacker calls IT support pretending to be the victim, requesting MFA reset or providing pressure to approve. This is a critical gap because Scattered Spider's most effective attacks combine MFA bombing with simultaneous helpdesk calls. | High | This gap cannot be closed with KQL alone - it requires integration with IT service management (ITSM) ticketing systems (ServiceNow, Jira SM) to correlate MFA fatigue timing with helpdesk tickets. Recommend adding a manual investigation step: "Check IT helpdesk for MFA reset requests from or about this user within the fatigue attack window." |
| T1567.002 | Exfiltration Over Web Service: to Cloud Storage | Data exfiltration to external cloud storage after MFA fatigue compromise | Medium | Cover in Tier 2 data exfiltration runbook. Add note to containment steps to check for external sharing links. |
| T1557 | Adversary-in-the-Middle | AiTM phishing proxies that capture session tokens, bypassing MFA entirely. Not an MFA fatigue technique per se, but an alternative MFA bypass that should be considered in differential diagnosis. | Medium | Cover in dedicated AiTM runbook (Tier 2). RB-0005 investigation flow should include a decision point: "Is this MFA fatigue or AiTM token theft?" based on whether repeated MFA failures preceded the successful sign-in. |

## Coverage Delta

### Cross-Runbook Technique Coverage

| Technique | RB-0001 | RB-0002 | RB-0003 | RB-0004 | RB-0005 |
|---|---|---|---|---|---|
| T1078.004 | Yes | Yes | Yes | Yes | Yes |
| T1090 | - | - | - | Yes | - |
| T1090.003 | - | - | - | Yes | - |
| T1098 | Yes | Yes | Yes | Yes | Yes |
| T1098.005 | - | - | - | Yes | - |
| T1110.003 | Yes | - | - | - | - |
| T1110.004 | Yes | - | Yes | - | - |
| T1114.003 | Yes | Yes | Yes | Yes | Yes |
| T1528 | Yes | Yes | Yes | Yes | Yes |
| T1530 | Yes | Yes | Yes | Yes | Yes |
| T1534 | Yes | Yes | Yes | Yes | Yes |
| T1539 | Yes | Yes | - | - | - |
| T1550.004 | - | Yes | - | - | - |
| T1556.006 | Yes | Yes | Yes | Yes | Yes |
| T1564.008 | Yes | Yes | Yes | Yes | Yes |
| T1589.001 | - | - | Yes | - | - |
| **T1621** | - | - | - | - | **NEW** |

### Tactic Coverage Across All Runbooks

| Tactic | RB-0001 | RB-0002 | RB-0003 | RB-0004 | RB-0005 |
|---|---|---|---|---|---|
| Reconnaissance | - | - | Yes | - | - |
| Initial Access | Yes | Yes | Yes | Yes | Yes |
| Persistence | Yes | Yes | Yes | Yes | Yes |
| Privilege Escalation | Yes | - | - | - | - |
| Defense Evasion | Yes | Yes | Yes | Yes | Yes |
| Credential Access | Yes | Yes | Yes | Yes | Yes |
| Lateral Movement | Yes | Yes | Yes | Yes | Yes |
| Collection | Yes | Yes | Yes | Yes | Yes |
| Command and Control | - | - | - | Yes | - |

## Summary

- **Net new techniques:** 1 (T1621 - Multi-Factor Authentication Request Generation)
- **Net new tactics:** 0 (all tactics covered by RB-0005 were already covered by prior runbooks)
- **Total unique techniques across all runbooks:** 17 (was 16 after RB-0004, +1 from T1621)
- **Total tactic coverage:** 9 of 14 (64%) - unchanged from RB-0004
- **Threat actors profiled:** 4 (Scattered Spider - HIGH, LAPSUS$ - HIGH, Storm-0875 - MEDIUM, Cozy Bear - LOW-MEDIUM)
- **Attack chains documented:** 2 (credential purchase chain, phishing + social engineering chain)
- **Coverage gaps identified:** 4 (T1566, T1598, T1567.002, T1557)
- **Critical note on T1621:** This technique was identified as a coverage gap in RB-0001 (Gap #2) and mentioned in Yunus's recommendations for Arina and Samet. RB-0005 closes this gap with full, dedicated detection coverage. The technique is particularly significant because it represents a fundamentally different attack vector from the credential-based and token-based access methods covered in RB-0001 through RB-0004. Instead of stealing a second factor, the attacker socially engineers the legitimate user into providing it.
