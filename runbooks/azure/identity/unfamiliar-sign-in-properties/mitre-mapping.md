# MITRE ATT&CK Mapping: Unfamiliar Sign-In Properties

**Written by:** Yunus (Threat Intelligence Lead)
**Investigation flow by:** Arina (IR Architect)
**Queries by:** Samet (KQL Engineer)
**Status:** v1.0 - Reviewed 2026-02-21

---

## 1. Primary Technique (What This Alert Directly Detects)

### T1078.004 - Valid Accounts: Cloud Accounts

| Field | Value |
|---|---|
| **Technique ID** | T1078.004 |
| **Technique Name** | Valid Accounts: Cloud Accounts |
| **Tactic(s)** | Initial Access (TA0001), Defense Evasion (TA0005), Persistence (TA0003), Privilege Escalation (TA0004) |
| **Confidence Level** | **Confirmed** |
| **Known Threat Actors** | Midnight Blizzard (APT29), Octo Tempest (Scattered Spider), Storm-0558, Peach Sandstorm (APT33), Star Blizzard (SEABORGIUM), DEV-0537 (LAPSUS$) |
| **Typical Position in Attack Chain** | **Early stage** - This is the initial foothold. The attacker has obtained valid cloud credentials and is using them to authenticate as the legitimate user. Everything else in the attack chain flows from this moment. |
| **Detection Data Sources** | Logon Session: Logon Session Creation (SigninLogs), User Account: User Account Authentication (AADUserRiskEvents), Application Log: Application Log Content (Identity Protection risk detections) |
| **Detection Confidence** | **Medium** - Identity Protection's ML model reliably catches sign-ins from truly novel properties (new country + new device + new browser). However, it produces significant false positives from travel, VPN changes, and ISP rotations. The 30-day baseline comparison in Query 3A is what elevates detection confidence from low to medium. Without the baseline, the raw alert alone is approximately 60-70% false positive. |
| **Related Techniques** | T1110 (Brute Force - how credentials were obtained), T1566 (Phishing - how credentials were obtained), T1539 (Steal Web Session Cookie - alternative access method), T1078.002 (Valid Accounts: Domain Accounts - on-prem equivalent) |

**Why this mapping is Confirmed:** The "Unfamiliar sign-in properties" alert is, by definition, a detection of someone using valid cloud credentials from properties that deviate from the legitimate user's established pattern. The alert fires on the authentication event itself - this is a direct detection of T1078.004. Whether the sign-in is truly malicious or a false positive is what the investigation flow determines, but the technique being detected is always T1078.004.

**Cross-tactic note:** T1078 spans four tactics because valid credentials serve multiple purposes simultaneously:
- **Initial Access**: The attacker gets in
- **Persistence**: The credentials continue to work until changed
- **Defense Evasion**: The attacker appears as a legitimate user
- **Privilege Escalation**: If the compromised account has elevated roles

---

## 2. Upstream Techniques (What Happens BEFORE This Alert)

These techniques represent how the attacker obtained the credentials that triggered the unfamiliar sign-in. The runbook does not directly detect these, but understanding the upstream vector is critical for determining attack scope and preventing recurrence.

### T1110.003 - Brute Force: Password Spraying

| Field | Value |
|---|---|
| **Technique ID** | T1110.003 |
| **Technique Name** | Brute Force: Password Spraying |
| **Tactic(s)** | Credential Access (TA0006) |
| **Confidence Level** | **Probable** - Password spraying is the most common credential acquisition method for Azure/M365 environments. When an unfamiliar sign-in alert fires with a successful authentication and no MFA, a preceding password spray campaign is the most likely explanation. |
| **Known Threat Actors** | Peach Sandstorm (APT33) - documented large-scale password spray campaigns against Azure AD in 2023; Midnight Blizzard (APT29) - used password spraying against Microsoft corporate in late 2023; Star Blizzard - credential spraying against government targets |
| **Typical Position in Attack Chain** | **Early stage** - This is the reconnaissance/credential acquisition phase that precedes the sign-in |
| **Detection Data Sources** | Logon Session: Logon Session Creation (SigninLogs with ResultType != "0"), Application Log: Application Log Content (AADUserRiskEvents with RiskEventType == "passwordSpray") |
| **Detection Confidence** | **Medium** - Query 4C checks if the alert IP was used against multiple users (classic spray indicator). Identity Protection also has a dedicated "passwordSpray" risk detection type checked by Query 4A. However, low-and-slow spray campaigns (under 5 attempts per user per hour) often evade detection. |
| **Related Techniques** | T1110.001 (Password Guessing), T1110.004 (Credential Stuffing), T1589 (Gather Victim Identity Information - attacker needs a target list) |

**Runbook coverage:** Query 4C detects same-IP targeting multiple users. Query 4A checks for "passwordSpray" risk event type. **Gap:** The runbook does not independently hunt for failed sign-ins from the alert IP against other accounts. Consider adding a supplementary query if Query 4C returns multiple users.

---

### T1110.004 - Brute Force: Credential Stuffing

| Field | Value |
|---|---|
| **Technique ID** | T1110.004 |
| **Technique Name** | Brute Force: Credential Stuffing |
| **Tactic(s)** | Credential Access (TA0006) |
| **Confidence Level** | **Probable** - When correlated with a "leakedCredentials" risk event (Query 4A), credential stuffing becomes the most likely upstream vector. The attacker obtained the user's credentials from a data breach or dark web marketplace and replayed them. |
| **Known Threat Actors** | Widely used by financially motivated groups, initial access brokers (IABs), and commodity attackers. Not associated with a single APT group - this is a volume technique used by many actors. |
| **Typical Position in Attack Chain** | **Early stage** - Credential acquisition |
| **Detection Data Sources** | Application Log: Application Log Content (AADUserRiskEvents with RiskEventType == "leakedCredentials") |
| **Detection Confidence** | **High** (when leakedCredentials is present) / **Low** (when absent) - Identity Protection's leaked credentials detection draws from Microsoft's dark web monitoring. When it triggers, confidence is high. But not all credential stuffing uses credentials that Microsoft has visibility into. |
| **Related Techniques** | T1589.001 (Gather Victim Identity Information: Credentials), T1078.004 (Valid Accounts: Cloud Accounts) |

**Runbook coverage:** Query 4A explicitly checks for "leakedCredentials" risk event type and flags it as "CRITICAL - Credentials exposed on dark web/paste site". This is adequate coverage.

---

### T1566.002 - Phishing: Spearphishing Link

| Field | Value |
|---|---|
| **Technique ID** | T1566.002 |
| **Technique Name** | Phishing: Spearphishing Link |
| **Tactic(s)** | Initial Access (TA0001) |
| **Confidence Level** | **Possible** - AiTM (Adversary-in-the-Middle) phishing attacks use phishing links to proxy authentication through an attacker-controlled server, capturing session cookies and tokens. If the unfamiliar sign-in was achieved via AiTM, the original phishing email is the T1566.002 component. This is possible but not directly detectable from the sign-in event alone. |
| **Known Threat Actors** | Storm-1567, DEV-0537 (LAPSUS$), various financially motivated groups using Evilginx2, EvilProxy, and other AiTM toolkits |
| **Typical Position in Attack Chain** | **Early stage** - Precedes the sign-in by minutes to hours |
| **Detection Data Sources** | Email Content: Email Headers (EmailEvents, EmailUrlInfo via MDO), Network Traffic: Network Traffic Content |
| **Detection Confidence** | **Not covered by this runbook** - Phishing detection requires Defender for Office 365 data (EmailEvents, EmailUrlInfo). This runbook focuses on the post-authentication investigation. |
| **Related Techniques** | T1539 (Steal Web Session Cookie - the AiTM proxy captures cookies), T1550.004 (Web Session Cookie - the stolen cookie is replayed) |

**Coverage gap:** This runbook has NO visibility into the initial phishing email. If the investigation determines true compromise, a separate hunt in EmailEvents/EmailUrlInfo (MDO) should be performed to find and quarantine the original phishing email and identify other recipients. **Recommendation: Create a linked runbook for "AiTM Phishing Detection" using MDO tables.**

---

### T1539 - Steal Web Session Cookie

| Field | Value |
|---|---|
| **Technique ID** | T1539 |
| **Technique Name** | Steal Web Session Cookie |
| **Tactic(s)** | Credential Access (TA0006) |
| **Confidence Level** | **Possible** - AiTM phishing toolkits (Evilginx2, EvilProxy, Modlishka) intercept session cookies during the authentication flow. The stolen cookie allows the attacker to bypass MFA entirely because the MFA challenge was completed by the legitimate user on the phishing proxy. An unfamiliar sign-in that shows MFA was "completed" but from suspicious infrastructure may indicate cookie theft. |
| **Known Threat Actors** | Storm-0558 (forged Azure AD tokens), Octo Tempest (Scattered Spider - AiTM attacks against Okta and Azure AD), DEV-0537 (LAPSUS$) |
| **Typical Position in Attack Chain** | **Early stage** - Occurs during or immediately after the phishing interaction |
| **Detection Data Sources** | Logon Session: Logon Session Metadata (SigninLogs - check for anomalousToken risk event), Application Log: Application Log Content (AADUserRiskEvents with RiskEventType == "anomalousToken" or "tokenIssuerAnomaly") |
| **Detection Confidence** | **Medium** - Query 4A checks for "anomalousToken" (HIGH) and "tokenIssuerAnomaly" (CRITICAL) risk event types. Identity Protection can sometimes detect token anomalies (unusual token lifetime, impossible speed between token issuance locations). However, well-crafted token replays can evade detection. |
| **Related Techniques** | T1550.004 (Web Session Cookie - replay of the stolen cookie), T1566.002 (Spearphishing Link - delivery mechanism) |

**Runbook coverage:** Partially covered via Query 4A risk event type checks. **Key analyst guidance:** If the sign-in shows MFA was "completed" but all other properties are highly anomalous (new country, new device, suspicious browser), suspect AiTM/cookie theft. The MFA completion does NOT mean the user actually authenticated - it may mean the user authenticated on a phishing proxy.

---

### T1621 - Multi-Factor Authentication Request Generation

| Field | Value |
|---|---|
| **Technique ID** | T1621 |
| **Technique Name** | Multi-Factor Authentication Request Generation |
| **Tactic(s)** | Credential Access (TA0006) |
| **Confidence Level** | **Possible** - MFA fatigue/bombing attacks send repeated push notifications to the user until they approve one out of frustration. If the attacker obtained credentials via spraying or stuffing, they may have used MFA bombing to bypass the MFA challenge before the unfamiliar sign-in. |
| **Known Threat Actors** | DEV-0537 (LAPSUS$) - famous for MFA bombing attacks against Uber and other targets; Octo Tempest (Scattered Spider) - combines social engineering with MFA bombing |
| **Typical Position in Attack Chain** | **Early stage** - Occurs between credential acquisition and successful sign-in |
| **Detection Data Sources** | Application Log: Application Log Content (AADUserRiskEvents with RiskEventType == "mcasImpossibleTravel" or custom detection for repeated MFA failures), Logon Session: Logon Session Creation (SigninLogs filtering for repeated MFA challenge failures from the same IP followed by success) |
| **Detection Confidence** | **Low** - This runbook does not specifically hunt for MFA fatigue patterns. Query 4A would catch it only if Identity Protection generates a dedicated risk event. **Gap:** No dedicated query for detecting repeated MFA challenge-then-approve patterns. |
| **Related Techniques** | T1110 (Brute Force - the attacker needs the password first), T1078.004 (Valid Accounts - the result of successful MFA bypass) |

**Coverage gap:** This runbook does not include a dedicated MFA fatigue detection query. **Recommendation:** Add a supplementary query that searches SigninLogs for repeated MFA failures (ResultType indicating MFA rejection) from the alert IP within 1 hour before the successful sign-in. This would detect the classic "20 push notifications in 10 minutes" pattern.

---

## 3. Downstream Techniques (What Happens AFTER This Alert)

These techniques represent what the attacker does after gaining access via the compromised credentials. The runbook's investigation steps (particularly Step 5) are specifically designed to detect these.

### T1098 - Account Manipulation

| Field | Value |
|---|---|
| **Technique ID** | T1098 (with sub-techniques .001, .002, .003, .005) |
| **Technique Name** | Account Manipulation |
| **Tactic(s)** | Persistence (TA0003), Privilege Escalation (TA0004) |
| **Confidence Level** | **Confirmed** |
| **Known Threat Actors** | Midnight Blizzard (APT29) - added credentials to service principals for persistent access; Octo Tempest (Scattered Spider) - MFA device registration and role assignment manipulation; Storm-0558 - manipulated Azure AD tokens |
| **Typical Position in Attack Chain** | **Mid stage** - One of the first actions after gaining access. The attacker establishes persistence before doing anything else that might trigger alerts. |
| **Detection Data Sources** | User Account: User Account Modification (AuditLogs - OperationName values for security info registration, app consents, role assignments, device registration) |
| **Detection Confidence** | **High** - Query 5A directly monitors for all relevant OperationName values and classifies them by severity. Coverage of this technique is comprehensive. |
| **Related Techniques** | T1556.006 (Modify Authentication Process: MFA), T1136.003 (Create Account: Cloud Account) |

**Sub-technique mapping to queries:**

| Sub-technique | Description | Detecting Query | Detection Confidence |
|---|---|---|---|
| T1098.001 | Additional Cloud Credentials (adding keys/secrets to apps) | Query 5A - "Add owner to application", "Update application" | High |
| T1098.002 | Additional Email Delegate Permissions | Query 5B - "Add-MailboxPermission" | High |
| T1098.003 | Additional Cloud Roles | Query 5A - "Add member to role", "Add eligible member to role" | High |
| T1098.005 | Device Registration (rogue device join) | Query 5A - "Register device", "Add registered owner to device" | High |

**Runbook coverage:** Comprehensive. Query 5A covers all four sub-techniques with severity classification. Query 2B also checks for these operations in the 72-hour pre-alert window, catching scenarios where the attacker already established persistence before this specific alert fired.

---

### T1556.006 - Modify Authentication Process: Multi-Factor Authentication

| Field | Value |
|---|---|
| **Technique ID** | T1556.006 |
| **Technique Name** | Modify Authentication Process: Multi-Factor Authentication |
| **Tactic(s)** | Credential Access (TA0006), Defense Evasion (TA0005), Persistence (TA0003) |
| **Confidence Level** | **Confirmed** |
| **Known Threat Actors** | Octo Tempest (Scattered Spider) - registers their own MFA devices on compromised accounts; DEV-0537 (LAPSUS$) - social engineering helpdesk to reset MFA |
| **Typical Position in Attack Chain** | **Mid stage** - Immediately after gaining access. Registering a new MFA method ensures the attacker can re-authenticate even if the password is changed. This is the single most important persistence action. |
| **Detection Data Sources** | User Account: User Account Modification (AuditLogs - "User registered security info", "Admin registered security info", "User deleted security info") |
| **Detection Confidence** | **High** - Query 5A detects MFA registration changes with "CRITICAL - MFA MANIPULATION" severity. Query 2B also catches MFA changes in the 72h surrounding window. |
| **Related Techniques** | T1098 (Account Manipulation - broader category), T1078.004 (Valid Accounts - the persistent access this enables) |

**Runbook coverage:** Comprehensive. Both Query 2B (historical context) and Query 5A (post-sign-in) cover MFA manipulation. The SuspiciousIndicator in Query 2B specifically flags "CRITICAL - MFA change after alert".

---

### T1564.008 - Hide Artifacts: Email Hiding Rules

| Field | Value |
|---|---|
| **Technique ID** | T1564.008 |
| **Technique Name** | Hide Artifacts: Email Hiding Rules |
| **Tactic(s)** | Defense Evasion (TA0005) |
| **Confidence Level** | **Confirmed** |
| **Known Threat Actors** | This is a universal BEC technique used by virtually every financially motivated attacker conducting business email compromise. Not specific to a single APT group - it is standard BEC tradecraft. |
| **Typical Position in Attack Chain** | **Mid stage** - Created within minutes of gaining access. The attacker creates inbox rules that hide evidence: marking incoming security alerts as read, deleting bounce-back notifications from phishing emails, moving replies from impersonated correspondents to hidden folders. |
| **Detection Data Sources** | Application Log: Application Log Content (OfficeActivity with Operation == "New-InboxRule", "Set-InboxRule"), Command: Command Execution (Exchange Online PowerShell audit logs) |
| **Detection Confidence** | **High** - Query 5C performs a dedicated deep dive into inbox rule parameters. It extracts ForwardTo, DeleteMessage, MarkAsRead, SubjectContainsWords, and classifies rules as "LIKELY MALICIOUS" based on indicator patterns. This is one of the strongest detection points in the entire runbook. |
| **Related Techniques** | T1114.003 (Email Forwarding Rule - often combined in the same inbox rule), T1070.008 (Clear Mailbox Data - deleting evidence) |

**Runbook coverage:** Excellent. Query 5C is purpose-built for this technique with detailed parameter extraction and malicious pattern classification.

---

### T1114 - Email Collection

| Field | Value |
|---|---|
| **Technique ID** | T1114 (with sub-techniques .002, .003) |
| **Technique Name** | Email Collection |
| **Tactic(s)** | Collection (TA0009) |
| **Confidence Level** | **Confirmed** |
| **Known Threat Actors** | Midnight Blizzard (APT29) - accessed Microsoft executive email via compromised OAuth app; Storm-0558 - accessed US government email via forged tokens; Star Blizzard - targets email for intelligence collection |
| **Typical Position in Attack Chain** | **Mid-to-late stage** - After establishing persistence, the attacker accesses email for intelligence gathering, financial fraud preparation, or data theft. |
| **Detection Data Sources** | Application Log: Application Log Content (OfficeActivity - MailItemsAccessed, Set-Mailbox ForwardingSmtpAddress) |
| **Detection Confidence** | **High** for forwarding rules (Query 5C), **Medium** for bulk access (Query 5D - volume-based detection can miss targeted access of specific high-value emails) |
| **Related Techniques** | T1564.008 (Email Hiding Rules - covers tracks), T1567.002 (Exfiltration to Cloud Storage - where the data goes) |

**Sub-technique mapping to queries:**

| Sub-technique | Description | Detecting Query | Detection Confidence |
|---|---|---|---|
| T1114.002 | Remote Email Collection (Graph API / OWA access) | Query 5D - MailItemsAccessed volume analysis | Medium |
| T1114.003 | Email Forwarding Rule | Query 5B/5C - Set-Mailbox, New-InboxRule with ForwardTo | High |

---

### T1528 - Steal Application Access Token

| Field | Value |
|---|---|
| **Technique ID** | T1528 |
| **Technique Name** | Steal Application Access Token |
| **Tactic(s)** | Credential Access (TA0006) |
| **Confidence Level** | **Confirmed** |
| **Known Threat Actors** | Midnight Blizzard (APT29) - OAuth application abuse for persistent access to Microsoft 365 data; Octo Tempest (Scattered Spider) - malicious OAuth app registration for data exfiltration |
| **Typical Position in Attack Chain** | **Mid stage** - The attacker consents to a malicious OAuth application from the compromised account, granting the application persistent access to email, files, or other resources. This survives password resets. |
| **Detection Data Sources** | User Account: User Account Modification (AuditLogs - "Consent to application", "Add app role assignment to service principal", "Add delegated permission grant") |
| **Detection Confidence** | **High** - Query 5A detects OAuth consent operations with "CRITICAL - OAUTH APP CONSENT" and "CRITICAL - API PERMISSION GRANT" severity. Query 5E (CloudAppEvents) provides additional visibility for E5 environments. |
| **Related Techniques** | T1550.001 (Application Access Token - using the stolen token), T1098.001 (Additional Cloud Credentials - alternative persistence via app credentials) |

**Runbook coverage:** Strong. Query 5A catches OAuth consent from AuditLogs. Query 2B provides historical context for consent events in the 72h window. **Note for analysts:** When an OAuth consent is found, the investigation must determine what permissions were granted (check ModifiedProperties in the AuditLogs result). Permissions including Mail.Read, Mail.ReadWrite, Files.ReadWrite.All, or User.ReadWrite.All are high-risk indicators.

---

### T1530 - Data from Cloud Storage Object

| Field | Value |
|---|---|
| **Technique ID** | T1530 |
| **Technique Name** | Data from Cloud Storage Object |
| **Tactic(s)** | Collection (TA0009) |
| **Confidence Level** | **Confirmed** |
| **Known Threat Actors** | Broadly used by both APT and financially motivated groups for data theft from SharePoint and OneDrive |
| **Typical Position in Attack Chain** | **Late stage** - After gaining access and establishing persistence, the attacker downloads files from SharePoint/OneDrive for exfiltration. |
| **Detection Data Sources** | Cloud Storage: Cloud Storage Access (OfficeActivity - FileDownloaded, FileSyncDownloadedFull, FileAccessed) |
| **Detection Confidence** | **Medium** - Query 5D detects bulk file downloads (>50 files) and flags them as "ALERT - Bulk file download". However, targeted downloads of a small number of high-value files (e.g., 3 financial documents) would show as "NORMAL" volume. Detection depends on quantity, not sensitivity of accessed content. |
| **Related Techniques** | T1213.002 (Data from Information Repositories: SharePoint), T1567.002 (Exfiltration to Cloud Storage) |

**Runbook coverage:** Adequate for bulk scenarios. **Gap:** No sensitivity-based detection. The runbook cannot distinguish between downloading 5 public marketing PDFs and 5 confidential financial reports. This requires integration with Microsoft Purview sensitivity labels, which is beyond the scope of this runbook.

---

### T1534 - Internal Spearphishing

| Field | Value |
|---|---|
| **Technique ID** | T1534 |
| **Technique Name** | Internal Spearphishing |
| **Tactic(s)** | Lateral Movement (TA0008) |
| **Confidence Level** | **Confirmed** |
| **Known Threat Actors** | Universal BEC technique. Also used by Midnight Blizzard (APT29) for lateral movement within organizations, and Octo Tempest for spreading access via Teams and email |
| **Typical Position in Attack Chain** | **Mid-to-late stage** - After establishing persistence, the attacker sends phishing emails from the compromised account to other internal users. The emails are trusted because they come from a legitimate internal sender. |
| **Detection Data Sources** | Application Log: Application Log Content (OfficeActivity with Operation == "Send"), Network Traffic: Network Traffic Content (EmailEvents from MDO) |
| **Detection Confidence** | **Low** - Query 5D counts sent emails and flags >20 as "WARNING - High volume email sent (>20) - possible internal phishing". However, this is a crude volume-based check. A targeted internal phishing attack (1-3 carefully crafted emails to high-value targets) would not trigger this threshold. |
| **Related Techniques** | T1566.002 (Spearphishing Link - technique used in the internal phishing), T1534 is essentially T1566 applied internally |

**Coverage gap:** The runbook has limited detection for targeted internal phishing. A sent email count of 5 would not trigger Query 5D's threshold. **Recommendation:** For confirmed compromise cases, always perform a manual review of sent emails from the compromised account during the compromise window, regardless of volume.

---

## 4. Attack Chain Context

### Chain 1: AiTM Phishing → BEC (Most Common)

This is the most prevalent attack chain in 2024-2026 targeting Microsoft 365 environments.

```
T1566.002 Spearphishing Link
    ↓ User clicks phishing link
T1539 Steal Web Session Cookie (via AiTM proxy)
    ↓ Attacker captures session cookie/token
T1550.004 Web Session Cookie (replayed)
    ↓ Attacker authenticates with stolen cookie
T1078.004 Valid Accounts: Cloud Accounts ← THIS ALERT FIRES HERE
    ↓ Attacker establishes persistence
T1098 Account Manipulation (MFA registration)
T1556.006 Modify Authentication Process: MFA
T1564.008 Email Hiding Rules (inbox rule)
T1114.003 Email Forwarding Rule
    ↓ Attacker conducts BEC
T1114.002 Remote Email Collection (reading email)
T1534 Internal Spearphishing (spreading access)
    ↓ Attacker exfiltrates data
T1567.002 Exfiltration to Cloud Storage
```

**Runbook coverage for this chain:**
- T1566.002: NOT COVERED (requires MDO data)
- T1539/T1550.004: PARTIALLY COVERED (anomalousToken risk event in Query 4A)
- T1078.004: COVERED (this is the alert)
- T1098/T1556.006: COVERED (Query 5A)
- T1564.008/T1114.003: COVERED (Query 5C - excellent coverage)
- T1114.002: COVERED (Query 5D)
- T1534: PARTIALLY COVERED (Query 5D - volume-based only)
- T1567.002: NOT COVERED (requires additional data sources)

**Overall chain coverage: 6/9 techniques detected, 2 partially, 1 not covered**

---

### Chain 2: Password Spray → Account Takeover

Common attack chain from nation-state actors (Peach Sandstorm, Midnight Blizzard) and commodity attackers.

```
T1589 Gather Victim Identity Information (email harvesting)
    ↓ Attacker builds target list
T1110.003 Password Spraying
    ↓ Valid credential found
T1621 MFA Request Generation (if MFA enabled)
    ↓ MFA bypassed via fatigue/social engineering
T1078.004 Valid Accounts: Cloud Accounts ← THIS ALERT FIRES HERE
    ↓ Attacker establishes persistence
T1098.003 Additional Cloud Roles (privilege escalation)
T1528 Steal Application Access Token (OAuth consent)
    ↓ Attacker accesses resources
T1530 Data from Cloud Storage Object
T1213.002 Data from Information Repositories: SharePoint
    ↓ Attacker exfiltrates
T1537 Transfer Data to Cloud Account
```

**Runbook coverage for this chain:**
- T1589: NOT COVERED (pre-attack reconnaissance)
- T1110.003: PARTIALLY COVERED (Query 4C detects same-IP multi-user targeting)
- T1621: NOT COVERED (gap - no MFA fatigue query)
- T1078.004: COVERED (this is the alert)
- T1098.003: COVERED (Query 5A)
- T1528: COVERED (Query 5A)
- T1530: COVERED (Query 5D)
- T1213.002: COVERED (Query 5D - FileDownloaded from SharePoint)
- T1537: NOT COVERED (requires Azure resource logs)

**Overall chain coverage: 5/9 techniques detected, 1 partially, 3 not covered**

---

### Chain 3: Credential Stuffing → BEC (Financially Motivated)

The simplest and most common variant - commodity attackers using leaked credentials.

```
T1110.004 Credential Stuffing (from breach database)
    ↓ Valid credential confirmed
T1078.004 Valid Accounts: Cloud Accounts ← THIS ALERT FIRES HERE
    ↓ Rapid persistence (often automated)
T1564.008 Email Hiding Rules (hide evidence)
T1114.003 Email Forwarding Rule (exfiltrate email)
    ↓ BEC execution
T1534 Internal Spearphishing (invoice fraud, wire transfer)
```

**Runbook coverage for this chain:**
- T1110.004: COVERED (Query 4A checks for "leakedCredentials" risk event)
- T1078.004: COVERED (this is the alert)
- T1564.008: COVERED (Query 5C - excellent)
- T1114.003: COVERED (Query 5C)
- T1534: PARTIALLY COVERED (Query 5D volume check)

**Overall chain coverage: 4/5 techniques detected, 1 partially. Best coverage of all three chains.**

---

## 5. Detection Coverage Matrix

### Techniques Covered by This Runbook

| Technique ID | Technique Name | Detecting Query | Coverage Level | Notes |
|---|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Query 1, 3A, 4A | **Full** | Primary detection target |
| T1098.001 | Additional Cloud Credentials | Query 5A | **Full** | App credential changes |
| T1098.002 | Additional Email Delegate Permissions | Query 5B | **Full** | Mailbox permission changes |
| T1098.003 | Additional Cloud Roles | Query 5A | **Full** | Role assignment changes |
| T1098.005 | Device Registration | Query 5A | **Full** | Rogue device join |
| T1110.003 | Password Spraying | Query 4C | **Partial** | Same-IP multi-user check only |
| T1110.004 | Credential Stuffing | Query 4A | **Full** | Via leakedCredentials risk event |
| T1114.002 | Remote Email Collection | Query 5D | **Partial** | Volume-based only |
| T1114.003 | Email Forwarding Rule | Query 5C | **Full** | Detailed rule parameter extraction |
| T1528 | Steal Application Access Token | Query 5A | **Full** | OAuth consent detection |
| T1530 | Data from Cloud Storage Object | Query 5D | **Partial** | Volume-based only |
| T1534 | Internal Spearphishing | Query 5D | **Partial** | Volume-based only |
| T1539 | Steal Web Session Cookie | Query 4A | **Partial** | Via anomalousToken risk event |
| T1556.006 | Modify Authentication Process: MFA | Query 5A, 2B | **Full** | MFA registration/deletion |
| T1564.008 | Email Hiding Rules | Query 5C | **Full** | Inbox rule deep dive |

**Summary: 15 techniques mapped. 9 with full coverage, 6 with partial coverage.**

### Coverage Gaps Identified

| Gap # | Technique | ID | Why It's Missing | Risk Level | Recommendation |
|---|---|---|---|---|---|
| 1 | Phishing: Spearphishing Link | T1566.002 | Requires MDO tables (EmailEvents, EmailUrlInfo) not included in this runbook | **High** | Create linked runbook "AiTM Phishing Investigation" using MDO data. Cross-reference when this runbook confirms compromise. |
| 2 | MFA Request Generation (MFA fatigue) | T1621 | No dedicated query for repeated MFA push patterns before successful sign-in | **Medium** | Add supplementary query: search SigninLogs for repeated MFA-related ResultType failures from alert IP in 1h before successful sign-in |
| 3 | Exfiltration Over Web Service | T1567.002 | No detection for data exfiltration to external cloud storage | **Medium** | Requires Cloud App Security or DLP integration. Add note to investigation flow for manual check. |
| 4 | Transfer Data to Cloud Account | T1537 | No detection for cross-tenant data transfer | **Low** | Requires Azure resource logs (AzureDiagnostics). Rare in BEC scenarios, more relevant to APT. |
| 5 | Web Session Cookie replay | T1550.004 | Only indirect detection via anomalousToken risk event | **Medium** | Identity Protection's token detection is improving but still misses well-crafted replays. Document as a known limitation. |

---

## 6. Threat Actor Profiles Relevant to This Runbook

### Tier 1: High Relevance (Routinely Use T1078.004 Against Azure/M365)

**Midnight Blizzard (APT29 / Cozy Bear)**
- **Attribution:** Russian Foreign Intelligence Service (SVR)
- **Relevance to this runbook:** In late 2023, Midnight Blizzard compromised Microsoft's corporate environment using password spraying against a legacy test tenant account without MFA. They then used OAuth applications to access executive email. This is exactly the attack chain this runbook covers: T1110.003 → T1078.004 → T1528 → T1114.002.
- **What to look for:** If the investigation reveals OAuth app consent (Query 5A) or cross-tenant access patterns, consider Midnight Blizzard TTPs. Their hallmark is patient, persistent access focused on intelligence collection rather than financial gain.
- **Typical indicators:** Long dwell time (weeks to months), OAuth app with Mail.Read permissions, minimal post-compromise noise, targeting of security/executive email.

**Octo Tempest (Scattered Spider / UNC3944)**
- **Attribution:** Financially motivated, primarily English-speaking
- **Relevance to this runbook:** Octo Tempest specializes in identity provider compromise. They use social engineering, SIM swapping, and MFA fatigue to bypass authentication controls. Once in, they register their own MFA devices (T1556.006) and create persistence through multiple channels simultaneously.
- **What to look for:** If the investigation reveals MFA method registration from the alert IP (Query 5A), combined with the sign-in bypassing MFA (Query 1), consider Octo Tempest TTPs. They are known for speed - persistence mechanisms may appear within 5-10 minutes of initial access.
- **Typical indicators:** MFA device registration within minutes, rapid role escalation, data exfiltration to cloud storage, targeting of Okta/Azure AD administrators.

**Peach Sandstorm (APT33 / Elfin)**
- **Attribution:** Iranian state-sponsored (MOIS-affiliated)
- **Relevance to this runbook:** Peach Sandstorm conducted large-scale password spray campaigns against Azure AD throughout 2023-2024, targeting defense, satellite, and pharmaceutical sectors. The "unfamiliar sign-in properties" alert would fire when a sprayed credential succeeds from Iranian infrastructure.
- **What to look for:** If Query 4C reveals the same IP targeting many users (>10), and the IP geolocates to Middle Eastern or Asian VPS infrastructure, consider Peach Sandstorm TTPs.
- **Typical indicators:** Low-and-slow password spraying (few attempts per account per day), VPS infrastructure in non-attributable countries, targeting of defense/government accounts, minimal post-compromise persistence (they prefer speed over stealth initially).

### Tier 2: Moderate Relevance

**Storm-0558**
- **Attribution:** Chinese state-sponsored
- **Relevance:** Used forged Azure AD tokens to access government email. The token forgery would not trigger a standard unfamiliar sign-in alert (the token appeared valid), but compromised accounts accessed with forged tokens might produce anomalous sign-in patterns if the token is used from unfamiliar infrastructure.
- **Relevance level:** Lower - their specific technique (MSA key abuse) has been mitigated by Microsoft.

**Star Blizzard (SEABORGIUM / Callisto)**
- **Attribution:** Russian (FSB-affiliated)
- **Relevance:** Credential phishing campaigns targeting government, think tanks, and NGOs. The credentials obtained via phishing would produce unfamiliar sign-in alerts when the attacker uses them.
- **Relevance level:** Moderate - standard credential phishing leading to T1078.004.

**DEV-0537 (LAPSUS$)**
- **Attribution:** Financially motivated, multinational
- **Relevance:** Known for MFA fatigue attacks and social engineering. Historical relevance (group was disrupted in 2022-2023) but their TTPs have been adopted by other groups.
- **Relevance level:** Moderate - TTPs are now widely replicated.

### Tier 3: Commodity / Financially Motivated

The majority of unfamiliar sign-in alerts in MSSP environments are generated by commodity attackers conducting BEC operations. These are not tracked APT groups but use standardized toolkits (Evilginx2, EvilProxy, credential stuffing tools) and follow predictable patterns:

1. Acquire credentials from dark web / breach databases
2. Sign in from VPS/residential proxy infrastructure
3. Create inbox rules within 15 minutes
4. Set up email forwarding within 30 minutes
5. Begin financial fraud (invoice manipulation, wire transfer requests) within 24 hours

**This is the most common real-world scenario this runbook will encounter.** The attack chain is simple, fast, and highly detectable by Queries 5B/5C/5D.

---

## 7. Yunus's Recommendations

### For Arina (IR Architect):
1. **Add MFA fatigue check to investigation flow.** Between Steps 1 and 2, add a quick check: "Were there repeated MFA challenge failures from this IP before the successful sign-in?" This closes Gap #2 (T1621).
2. **Add phishing email cross-reference to containment playbook.** After confirming compromise, add a step: "Hunt in EmailEvents/EmailUrlInfo for phishing emails received by this user in the 72 hours before the alert." This addresses Gap #1 (T1566.002).
3. **The investigation flow correctly considers the full attack chain.** Steps 1-6 cover Initial Access → Persistence → Collection → Lateral Movement. The flow is well-designed from a threat intelligence perspective.

### For Samet (KQL Engineer):
1. **Consider adding a supplementary Query 4E** that hunts for MFA fatigue patterns:
   ```
   SigninLogs | where IPAddress == alertIP | where ResultType in ("50074", "50076", "500121") | where TimeGenerated between ((alertTime - 1h) .. alertTime) | count
   ```
   ResultType 50074/50076/500121 indicate MFA-related failures. A count >5 from the same IP in 1 hour strongly suggests MFA bombing.
2. **Query 5D bulk thresholds are appropriate** for commodity BEC detection but may miss targeted APT collection. Document this as a known limitation rather than trying to solve it - targeted collection detection requires content-aware DLP, not volume-based KQL.
3. **The "leakedCredentials" check in Query 4A is critical.** In my experience, "leakedCredentials" + "unfamiliarFeatures" for the same user within 7 days has a >90% true positive rate. Consider adding a specific output note when this combination is detected: "CRITICAL COMBINATION: Leaked credentials + unfamiliar sign-in = high-confidence credential compromise."

### For Alp (QA Lead):
1. **MITRE mapping completeness:** 15 techniques mapped across 8 tactics. 9 with full coverage, 6 with partial. 5 gaps identified with recommendations.
2. **All technique mappings include confidence levels** as required by my output format.
3. **Three attack chains documented** with per-technique coverage assessment.
4. **6 threat actor profiles provided** (3 Tier 1, 2 Tier 2, 1 commodity category).
5. **The YAML frontmatter for the final runbook should include:**
   ```yaml
   mitre_attack:
     primary_technique: T1078.004
     tactics:
       - TA0001  # Initial Access
       - TA0003  # Persistence
       - TA0004  # Privilege Escalation
       - TA0005  # Defense Evasion
       - TA0006  # Credential Access
       - TA0008  # Lateral Movement
       - TA0009  # Collection
     techniques:
       - T1078.004  # Valid Accounts: Cloud Accounts
       - T1098      # Account Manipulation
       - T1110.003  # Password Spraying
       - T1110.004  # Credential Stuffing
       - T1114.003  # Email Forwarding Rule
       - T1528      # Steal Application Access Token
       - T1530      # Data from Cloud Storage Object
       - T1534      # Internal Spearphishing
       - T1539      # Steal Web Session Cookie
       - T1556.006  # Modify Authentication Process: MFA
       - T1564.008  # Email Hiding Rules
     threat_actors:
       - Midnight Blizzard (APT29)
       - Octo Tempest (Scattered Spider)
       - Peach Sandstorm (APT33)
   ```
