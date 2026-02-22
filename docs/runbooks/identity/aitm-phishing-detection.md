---
title: "AiTM Phishing / Anomalous Token Detection"
id: RB-0014
severity: critical
status: reviewed
description: >
  Investigation runbook for Adversary-in-the-Middle (AiTM) phishing attacks and
  anomalous token usage in Microsoft Entra ID. Covers detection of stolen session
  cookies and tokens via reverse-proxy phishing kits (EvilGinx, Modlishka, Muraena),
  anomalous token characteristics flagged by Identity Protection, session cookie
  replay from new IPs, MFA bypass via token theft, post-compromise BEC activity,
  and org-wide AiTM campaign sweep. AiTM attacks completely bypass MFA because
  the attacker captures the authenticated session token AFTER the user completes
  MFA -- the attacker never needs to solve the MFA challenge themselves.
mitre_attack:
  tactics:
    - tactic_id: TA0001
      tactic_name: "Initial Access"
    - tactic_id: TA0006
      tactic_name: "Credential Access"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
    - tactic_id: TA0009
      tactic_name: "Collection"
    - tactic_id: TA0010
      tactic_name: "Exfiltration"
    - tactic_id: TA0003
      tactic_name: "Persistence"
  techniques:
    - technique_id: T1557
      technique_name: "Adversary-in-the-Middle"
      confidence: confirmed
    - technique_id: T1539
      technique_name: "Steal Web Session Cookie"
      confidence: confirmed
    - technique_id: T1550.004
      technique_name: "Use Alternate Authentication Material: Web Session Cookie"
      confidence: confirmed
    - technique_id: T1566.002
      technique_name: "Phishing: Spearphishing Link"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1114.002
      technique_name: "Email Collection: Remote Email Collection"
      confidence: confirmed
threat_actors:
  - "Storm-1167"
  - "Storm-1295"
  - "Star Blizzard (SEABORGIUM)"
  - "Scattered Spider (Octo Tempest)"
  - "DEV-1101 (Phishing-as-a-Service)"
log_sources:
  - table: "SigninLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "AADUserRiskEvents"
    product: "Entra ID Identity Protection"
    license: "Entra ID P2"
    required: true
    alternatives: []
  - table: "AADNonInteractiveUserSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: true
    alternatives: []
  - table: "AuditLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "CloudAppEvents"
    product: "Microsoft Defender for Cloud Apps"
    license: "Microsoft 365 E5 / Defender for Cloud Apps"
    required: false
    alternatives: []
  - table: "OfficeActivity"
    product: "Office 365"
    license: "Office 365 E1+"
    required: false
    alternatives: []
  - table: "BehaviorAnalytics"
    product: "Microsoft Sentinel"
    license: "Sentinel UEBA"
    required: false
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-22
updated: 2026-02-22
version: "1.0"
tier: 2
category: identity
key_log_sources:
  - SigninLogs
  - AADUserRiskEvents
  - AADNonInteractiveUserSignInLogs
  - AuditLogs
  - CloudAppEvents
  - OfficeActivity
tactic_slugs:
  - initial-access
  - cred-access
  - defense-evasion
  - collection
  - exfiltration
  - persistence
data_checks:
  - query: "AADUserRiskEvents | where RiskEventType == 'anomalousToken' | take 1"
    label: primary
    description: "Anomalous token risk detection (AiTM indicator)"
  - query: "SigninLogs | take 1"
    description: "For sign-in context, IP, device, session analysis"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "For token replay detection via non-interactive sign-ins"
  - query: "AuditLogs | take 1"
    description: "For post-compromise persistence actions"
  - query: "CloudAppEvents | take 1"
    label: optional
    description: "For BEC activity and data access post-compromise"
---

# AiTM Phishing / Anomalous Token Detection - Investigation Runbook

> **RB-0014** | Severity: Critical | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Entra ID Identity Protection + SigninLogs Anomaly Analysis
>
> **Risk Detection Name:** `anomalousToken` / `tokenIssuerAnomaly` / `suspiciousInboxForwardingActivity`
>
> **Primary MITRE Technique:** T1557 - Adversary-in-the-Middle + T1539 - Steal Web Session Cookie

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Anomalous Token Risk Event Analysis](#step-1-anomalous-token-risk-event-analysis)
   - [Step 2: Session IP Divergence Detection](#step-2-session-ip-divergence-detection)
   - [Step 3: Token Replay via Non-Interactive Sign-Ins](#step-3-token-replay-via-non-interactive-sign-ins)
   - [Step 4: Baseline Comparison - Establish Normal Session Pattern](#step-4-baseline-comparison---establish-normal-session-pattern)
   - [Step 5: Post-Compromise BEC Activity Audit](#step-5-post-compromise-bec-activity-audit)
   - [Step 6: Persistence Mechanism Detection](#step-6-persistence-mechanism-detection)
   - [Step 7: Org-Wide AiTM Campaign Sweep](#step-7-org-wide-aitm-campaign-sweep)
6. [Containment Playbook](#6-containment-playbook)
7. [Evidence Collection Checklist](#7-evidence-collection-checklist)
8. [Escalation Criteria](#8-escalation-criteria)
9. [False Positive Documentation](#9-false-positive-documentation)
10. [MITRE ATT&CK Mapping](#10-mitre-attck-mapping)
11. [Query Summary](#11-query-summary)
12. [Appendix A: Datatable Tests](#appendix-a-datatable-tests)
13. [References](#references)

---

## 1. Alert Context

**What triggers this alert:**
AiTM phishing and anomalous token attacks are detected through multiple complementary mechanisms:

1. **Identity Protection `anomalousToken` risk detection:** Entra ID's ML models detect tokens with unusual characteristics -- tokens presented from an IP/device/location that doesn't match the original authentication session. This is the primary detection for session cookie replay.
2. **Identity Protection `tokenIssuerAnomaly`:** Detects anomalies in the token issuer chain, which may indicate token forgery or manipulation.
3. **Session IP divergence:** A user authenticates interactively (with MFA) from one IP, and then non-interactive token-based access occurs from a completely different IP within the same session lifetime. This is the hallmark of AiTM -- the user authenticated through the attacker's proxy, and the attacker replays the captured session cookie from their own infrastructure.
4. **BEC pattern detection:** Post-compromise activity pattern: email access → inbox rule creation → email forwarding → financial fraud email sent -- all from the stolen session.

**Why it matters:**
AiTM phishing is the **most dangerous identity attack vector in production today**. Unlike traditional credential phishing (which MFA blocks), AiTM attacks capture the authenticated session token AFTER the user successfully completes MFA. The attack works like this:

1. User receives phishing email with a link to the attacker's reverse-proxy server (EvilGinx, Modlishka)
2. The proxy forwards the user to the real Microsoft login page, acting as a transparent man-in-the-middle
3. User enters credentials and completes MFA challenge -- everything looks legitimate to the user
4. The proxy captures the session cookie (authentication token) returned by Microsoft after successful MFA
5. The attacker replays this session cookie from their own infrastructure, gaining full access to the user's session

**MFA does NOT protect against AiTM.** Only phishing-resistant MFA methods (FIDO2 keys, Windows Hello for Business, passkeys with device-bound credentials) can prevent AiTM because they use origin binding that detects the proxy domain.

Storm-1167 operates a phishing-as-a-service platform that has enabled AiTM campaigns affecting thousands of organizations. Microsoft reports AiTM phishing has increased 146% year-over-year (2023-2024) and is now the primary initial access vector for BEC attacks.

**Why this is CRITICAL severity:**
- AiTM bypasses ALL forms of traditional MFA (SMS, phone call, push notification, TOTP)
- The attacker gets a fully authenticated session -- they appear as the legitimate user
- Session tokens can be valid for hours (default 1h for access tokens, 90 days for refresh tokens)
- If the attacker captures a refresh token, they can generate new access tokens for up to 90 days
- Post-compromise actions (email reading, rule creation, BEC) happen within minutes
- The user has NO indication they were compromised -- their MFA prompt was legitimate
- Password reset does NOT invalidate existing session tokens (must revoke sessions explicitly)
- AiTM is commonly followed by BEC financial fraud within hours of compromise

**However:** This alert has a **low false positive rate** (~5-10%). Legitimate triggers include:
- Corporate VPN split-tunneling causing IP changes mid-session
- Users on mobile networks with frequent IP changes (carrier-grade NAT)
- Cloud proxy services (Zscaler, Netskope) that change egress IPs during a session
- Traveling users switching between Wi-Fi and cellular networks

**Worst case scenario if this is real:**
A finance executive receives a phishing email containing a link to a convincing Microsoft login page (actually an EvilGinx proxy). They enter their credentials and approve the MFA push notification on their phone -- everything looks normal. The attacker captures the session cookie and immediately: reads the executive's inbox (identifying pending wire transfers and financial approvals), creates an inbox forwarding rule to a personal email for ongoing monitoring, composes a reply to a pending vendor payment email modifying the bank account details to the attacker's account, and registers an MFA method for persistent access. The vendor processes the fraudulent wire transfer before the modification is detected. Because the attacker used a legitimate session token, all actions appear to come from the executive's account with no MFA bypass or anomalous authentication in the logs -- only the `anomalousToken` risk detection and session IP divergence reveal the attack.

**Key difference from other identity runbooks:**
- RB-0001 through RB-0006 (Credential attacks): The attacker compromises credentials or bypasses MFA challenges. Detectable via sign-in anomalies.
- RB-0012 (MFA Registration): Investigates post-compromise persistence via MFA method addition.
- **RB-0014 (This runbook):** Investigates **session token theft** -- the attacker NEVER compromises credentials and NEVER bypasses MFA. They steal the authenticated session AFTER MFA succeeds. Detection relies on token anomaly analysis, not authentication failure patterns. This is fundamentally different from all other identity attack vectors because the authentication itself is completely legitimate.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID P2 + Microsoft Sentinel (Identity Protection required for `anomalousToken` detection)
- **Sentinel Connectors:** Microsoft Entra ID (SigninLogs, AADUserRiskEvents, AADNonInteractiveUserSignInLogs)
- **Permissions:** Security Reader (investigation), Security Administrator (containment)

### Recommended for Full Coverage
- **License:** Entra ID P2 + Microsoft 365 E5 + Defender for Cloud Apps + Sentinel
- **Additional:** Continuous Access Evaluation (CAE) enabled, Token Protection (preview) enabled
- **Phishing-Resistant MFA:** FIDO2/Windows Hello enforced via Authentication Strengths

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID P2 + Sentinel | SigninLogs, AADUserRiskEvents, AADNonInteractiveUserSignInLogs, AuditLogs | Steps 1-4, 6-7 |
| Above + M365 E5 / MDCA | Above + CloudAppEvents | Steps 1-7 (full BEC detection) |
| Above + Office 365 E1+ | Above + OfficeActivity | Steps 1-7 (full coverage) |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let TargetUPN = "victim.user@contoso.com";                // User flagged for anomalous token
let AlertTime = datetime(2026-02-22T14:00:00Z);           // Time of anomalous token detection
let LookbackWindow = 24h;                                 // Window to analyze pre-alert activity
let ForwardWindow = 12h;                                   // Window after alert for BEC detection
let BaselineDays = 14d;                                    // Baseline comparison window
let SuspiciousIP = "198.51.100.50";                       // IP from token replay (if known)
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- `anomalousToken` risk detection AND email forwarding rule created in the same session
- User authenticated from IP-A (corporate) but token replayed from IP-B (residential/VPN provider/foreign) within minutes
- Non-interactive sign-in from new IP accessing email or files immediately after interactive sign-in from different IP
- Inbox rule created with forwarding to external domain within hours of anomalous token detection
- Token replay from known AiTM infrastructure IPs (EvilGinx hosting providers, bulletproof hosting)
- BEC pattern: email read → rule creation → reply to financial email -- all from the suspicious IP

### Standard Investigation
- `anomalousToken` detection without immediate post-compromise activity
- Session IP change within the same ISP/cloud provider (possible VPN split-tunnel)
- Non-interactive token access from a new IP for a single resource
- `tokenIssuerAnomaly` without corroborating sign-in anomalies

### Likely Benign
- IP change correlates with known VPN/proxy rotation (Zscaler, Netskope egress IPs)
- User traveling internationally with expected IP changes
- Mobile user switching between Wi-Fi and cellular networks
- Corporate proxy causing different egress IPs for different services

---

## 5. Investigation Steps

### Step 1: Anomalous Token Risk Event Analysis

**Purpose:** Examine the Identity Protection risk detection that flagged the anomalous token. Understand the risk event type, the associated IP, timing, and what characteristics of the token were anomalous. This provides the initial indicators for the investigation.

**Data needed:** AADUserRiskEvents

```kql
// ============================================================
// QUERY 1: Anomalous Token Risk Event Analysis
// Purpose: Analyze Identity Protection risk detections for token anomalies
// Tables: AADUserRiskEvents
// Investigation Step: 1 - Anomalous Token Risk Event Analysis
// ============================================================
let TargetUPN = "victim.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Token-related risk events ---
AADUserRiskEvents
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where UserPrincipalName =~ TargetUPN
| where RiskEventType in (
    "anomalousToken",
    "tokenIssuerAnomaly",
    "unfamiliarFeatures",
    "suspiciousInboxForwardingActivity",
    "mcasImpossibleTravel",
    "anonymizedIPAddress",
    "maliciousIPAddress",
    "investigationsThreatIntelligence"
)
| project
    TimeGenerated,
    UserPrincipalName,
    RiskEventType,
    RiskLevel,
    RiskState,
    RiskDetail,
    DetectionTimingType,
    IPAddress,
    Location = strcat(City, ", ", CountryOrRegion),
    Source,
    Activity,
    TokenElevationType = tostring(AdditionalInfo),
    CorrelationId
| extend
    RiskCategory = case(
        RiskEventType == "anomalousToken",
            "TOKEN ANOMALY - Session token with unusual characteristics (primary AiTM indicator)",
        RiskEventType == "tokenIssuerAnomaly",
            "TOKEN ISSUER - Anomaly in token issuer chain (possible token forgery)",
        RiskEventType == "suspiciousInboxForwardingActivity",
            "BEC INDICATOR - Inbox forwarding rule detected (post-compromise activity)",
        RiskEventType == "unfamiliarFeatures",
            "SESSION ANOMALY - Unfamiliar sign-in properties",
        RiskEventType == "mcasImpossibleTravel",
            "LOCATION ANOMALY - Impossible travel detected by MDCA",
        RiskEventType in ("anonymizedIPAddress", "maliciousIPAddress"),
            "SUSPICIOUS IP - Sign-in from flagged IP infrastructure",
        RiskEventType == "investigationsThreatIntelligence",
            "THREAT INTEL - Microsoft TI matched this activity",
        strcat("OTHER - ", RiskEventType)
    ),
    AiTMConfidence = case(
        RiskEventType == "anomalousToken" and RiskLevel == "high",
            "HIGH CONFIDENCE AiTM - Anomalous token with high risk",
        RiskEventType == "anomalousToken",
            "PROBABLE AiTM - Anomalous token detected",
        RiskEventType == "tokenIssuerAnomaly",
            "POSSIBLE AiTM - Token issuer anomaly",
        RiskEventType == "suspiciousInboxForwardingActivity",
            "BEC FOLLOW-UP - Post-AiTM activity pattern",
        "CORROBORATING - Supporting evidence for AiTM"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- `anomalousToken` is the primary AiTM detection -- Identity Protection uses ML to detect tokens presented from unexpected contexts
- `suspiciousInboxForwardingActivity` is a BEC detection that often follows AiTM compromise
- `DetectionTimingType == "realtime"` means the risk was detected during the sign-in, not retroactively
- `AdditionalInfo` may contain technical details about token anomaly characteristics

**Tuning Guidance:**
- Multiple risk events for the same user within the same window = compound evidence, higher confidence
- `anomalousToken` + `suspiciousInboxForwardingActivity` = confirmed AiTM → BEC attack chain
- If `RiskState == "atRisk"`, no remediation has occurred yet -- the attacker may still have access
- `anomalousToken` with `RiskLevel == "high"` has very low false positive rate (< 5%)

**Expected findings:**
- Token anomaly risk detections with timing, IP, and risk level
- Whether the risk was detected in realtime or offline
- Corroborating risk events that strengthen the AiTM assessment

**Next action:**
- If `anomalousToken` confirmed, proceed to Step 2 for session IP divergence
- If multiple risk types found, this strongly confirms AiTM
- Note all risk event IPs for cross-reference in subsequent queries

---

### Step 2: Session IP Divergence Detection

**Purpose:** Detect the hallmark of AiTM attacks: the user authenticates interactively from one IP (through the phishing proxy), and then token-based access occurs from a completely different IP (the attacker's infrastructure). This IP divergence within the same session is the strongest forensic indicator of session cookie theft.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 2: Session IP Divergence Detection
// Purpose: Detect IP switches within the same authentication session
// Tables: SigninLogs
// Investigation Step: 2 - Session IP Divergence Detection
// ============================================================
let TargetUPN = "victim.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- All sign-ins for the target user ---
let UserSignIns = SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where UserPrincipalName =~ TargetUPN
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    Country = tostring(LocationDetails.countryOrRegion),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    IsCompliant = DeviceDetail.isCompliant,
    IsManaged = DeviceDetail.isManaged,
    ResultType,
    RiskLevelDuringSignIn,
    AuthenticationRequirement,
    MfaDetail = tostring(AuthenticationDetails),
    ResourceDisplayName,
    ConditionalAccessStatus,
    CorrelationId,
    OriginalRequestId,
    IsInteractive;
// --- Find IP divergence: interactive from IP-A, then access from IP-B ---
let InteractiveSessions = UserSignIns
| where IsInteractive == true and ResultType == "0"
| project
    AuthTime = TimeGenerated,
    AuthIP = IPAddress,
    AuthLocation = Location,
    AuthCountry = Country,
    AuthDevice = strcat(DeviceOS, " / ", Browser),
    AuthApp = AppDisplayName,
    MfaCompleted = MfaDetail has "MFA completed" or AuthenticationRequirement == "multiFactorAuthentication",
    CorrelationId;
let SubsequentAccess = UserSignIns
| where ResultType == "0"
| project
    AccessTime = TimeGenerated,
    AccessIP = IPAddress,
    AccessLocation = Location,
    AccessCountry = Country,
    AccessApp = AppDisplayName,
    AccessResource = ResourceDisplayName;
// --- Cross-join to find divergent IPs ---
InteractiveSessions
| join kind=inner SubsequentAccess on $left.CorrelationId == $right.CorrelationId
| where AccessIP != AuthIP
| where AccessTime >= AuthTime
| extend
    TimeDeltaMinutes = datetime_diff("minute", AccessTime, AuthTime),
    IPDivergenceType = case(
        AuthCountry != AccessCountry,
            "CRITICAL - Cross-country IP divergence (different countries)",
        AuthIP != AccessIP and TimeDeltaMinutes < 5,
            "HIGH - Immediate IP switch (< 5 min, classic AiTM)",
        AuthIP != AccessIP and TimeDeltaMinutes < 60,
            "HIGH - IP switch within 1 hour",
        "MEDIUM - IP switch within session"
    )
| project
    AuthTime,
    AuthIP,
    AuthLocation,
    AuthDevice,
    MfaCompleted,
    AccessTime,
    AccessIP,
    AccessLocation,
    AccessApp,
    TimeDeltaMinutes,
    IPDivergenceType
| sort by IPDivergenceType asc, TimeDeltaMinutes asc
```

**Performance Notes:**
- Joining on `CorrelationId` links sign-in events to the same authentication session
- If `CorrelationId` doesn't match, try `OriginalRequestId` for token refresh chains
- Cross-country IP divergence is the strongest AiTM indicator with the lowest false positive rate

**Tuning Guidance:**
- IP switch within 5 minutes across countries = almost certainly AiTM (users can't travel that fast)
- IP switch within same ISP/cloud provider may be VPN split-tunnel (lower confidence)
- If `MfaCompleted == true` and then access from a different country, this is classic AiTM
- Known corporate VPN egress IPs should be whitelisted to reduce false positives
- If `AuthDevice` shows the user's known device but `AccessIP` is from a hosting provider, confirm AiTM

**Expected findings:**
- IP divergence between interactive authentication and subsequent token-based access
- Cross-country or cross-ISP IP changes within minutes = AiTM confirmed
- Whether MFA was completed before the IP divergence occurred

**Next action:**
- If cross-country IP divergence confirmed, this is AiTM -- proceed to containment
- If IP divergence is within the same country/ISP, proceed to Step 3 for non-interactive analysis
- Record both IPs for the incident report

---

### Step 3: Token Replay via Non-Interactive Sign-Ins

**Purpose:** Analyze non-interactive sign-in logs to detect token replay. After stealing a session cookie via AiTM, the attacker replays it to access Microsoft 365 services. These replayed tokens appear as non-interactive sign-ins from the attacker's IP, accessing resources the user normally accesses but from an infrastructure that doesn't match the user's pattern.

**Data needed:** AADNonInteractiveUserSignInLogs

```kql
// ============================================================
// QUERY 3: Token Replay via Non-Interactive Sign-Ins
// Purpose: Detect token replay patterns in non-interactive sign-in logs
// Tables: AADNonInteractiveUserSignInLogs
// Investigation Step: 3 - Token Replay Detection
// ============================================================
let TargetUPN = "victim.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
let SuspiciousIP = "198.51.100.50";
// --- Non-interactive sign-ins (token-based access) ---
AADNonInteractiveUserSignInLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 12h)
| where UserPrincipalName =~ TargetUPN
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    Country = tostring(LocationDetails.countryOrRegion),
    UserAgent,
    ResourceDisplayName,
    ResultType,
    TokenIssuerType,
    UniqueTokenIdentifier
| where ResultType == "0"  // Successful token presentations only
| extend
    IsSuspiciousIP = IPAddress == SuspiciousIP,
    AccessCategory = case(
        AppDisplayName in ("Microsoft Exchange Online", "Office 365 Exchange Online", "Outlook"),
            "EMAIL - Exchange/Outlook access",
        AppDisplayName in ("Microsoft Teams"),
            "TEAMS - Teams access",
        AppDisplayName in ("SharePoint Online", "OneDrive for Business"),
            "FILES - SharePoint/OneDrive access",
        AppDisplayName in ("Microsoft Graph"),
            "API - Graph API access",
        AppDisplayName in ("Azure Portal", "Microsoft Azure Management"),
            "ADMIN - Azure management",
        strcat("OTHER - ", AppDisplayName)
    )
| summarize
    TokenPresentations = count(),
    UniqueApps = make_set(AppDisplayName, 20),
    Categories = make_set(AccessCategory, 10),
    UniqueResources = make_set(ResourceDisplayName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    UserAgents = make_set(UserAgent, 5)
    by IPAddress, Country
| extend
    TokenReplayAssessment = case(
        IPAddress == SuspiciousIP and TokenPresentations > 10,
            "CRITICAL - Mass token replay from suspicious IP",
        IPAddress == SuspiciousIP,
            "HIGH - Token presentations from suspicious IP",
        TokenPresentations > 50 and Country !in ("US"),  // Adjust to org's country
            "HIGH - Heavy token usage from foreign IP",
        TokenPresentations > 100,
            "MEDIUM - High volume token usage (review IP ownership)",
        "LOW - Standard token access pattern"
    )
| where TokenReplayAssessment !startswith "LOW"
| sort by TokenReplayAssessment asc, TokenPresentations desc
```

**Performance Notes:**
- `AADNonInteractiveUserSignInLogs` captures all token-based resource access (no user interaction)
- `UserAgent` from the attacker's replayed session may differ from the user's legitimate browser
- A single stolen session cookie generates many non-interactive sign-ins as the attacker accesses different services

**Tuning Guidance:**
- Adjust `Country !in ("US")` to your organization's primary operating countries
- If `UserAgent` changes mid-session (e.g., from Chrome to Python requests library), this is strong AiTM evidence
- Email access (`Exchange Online`) from the suspicious IP is the highest priority -- this enables BEC
- If `TokenIssuerType` is unusual, this may indicate token manipulation beyond simple replay

**Expected findings:**
- Token replay patterns from the attacker's IP: apps accessed, volume, timing
- Whether email and file access occurred from the suspicious IP
- User agent comparison between legitimate and attacker sessions

**Next action:**
- If email access from suspicious IP confirmed, proceed to Step 5 for BEC analysis
- If file access detected, check for data exfiltration patterns
- Proceed to Step 4 for baseline comparison

---

### Step 4: Baseline Comparison - Establish Normal Session Pattern

**Purpose:** Compare the suspicious session against the user's normal sign-in and access patterns. Establish the user's typical IPs, countries, devices, and access times. This determines whether the anomalous token activity represents a genuine deviation from normal behavior or matches known legitimate patterns (e.g., VPN rotation).

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 4: Baseline Comparison - Normal Session Pattern
// Purpose: Compare suspicious session against user's baseline
// Tables: SigninLogs
// Investigation Step: 4 - Baseline Comparison
// ============================================================
let TargetUPN = "victim.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 14d;
let SuspiciousIP = "198.51.100.50";
// --- User's baseline sign-in pattern ---
let UserBaseline = SigninLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime - 1h)
| where UserPrincipalName =~ TargetUPN
| where ResultType == "0"
| summarize
    TotalSignIns = count(),
    BaselineIPs = make_set(IPAddress, 30),
    BaselineCountries = make_set(tostring(LocationDetails.countryOrRegion), 10),
    BaselineDevices = make_set(strcat(tostring(DeviceDetail.operatingSystem), "/", tostring(DeviceDetail.browser)), 10),
    BaselineApps = make_set(AppDisplayName, 20),
    TypicalHours = make_list(hourofday(TimeGenerated), 1000),
    BaselineCities = make_set(tostring(LocationDetails.city), 15);
// --- Current suspicious activity ---
let CurrentActivity = SigninLogs
| where TimeGenerated between (AlertTime - 1h .. AlertTime + 4h)
| where UserPrincipalName =~ TargetUPN
| where ResultType == "0"
| summarize
    CurrentIPs = make_set(IPAddress, 20),
    CurrentCountries = make_set(tostring(LocationDetails.countryOrRegion), 10),
    CurrentDevices = make_set(strcat(tostring(DeviceDetail.operatingSystem), "/", tostring(DeviceDetail.browser)), 10);
// --- Compare ---
UserBaseline
| extend Placeholder = 1
| join kind=inner (CurrentActivity | extend Placeholder = 1) on Placeholder
| project-away Placeholder, Placeholder1
| extend
    NewIPs = set_difference(CurrentIPs, BaselineIPs),
    NewCountries = set_difference(CurrentCountries, BaselineCountries),
    NewDevices = set_difference(CurrentDevices, BaselineDevices),
    SuspiciousIPInBaseline = BaselineIPs has SuspiciousIP
| extend
    BaselineAssessment = case(
        array_length(NewCountries) > 0 and not(SuspiciousIPInBaseline),
            "ANOMALOUS - Token access from country never seen in 14-day baseline",
        array_length(NewIPs) > 0 and not(SuspiciousIPInBaseline),
            "SUSPICIOUS - Token access from IP never seen in baseline",
        array_length(NewDevices) > 0,
            "SUSPICIOUS - New device fingerprint not in baseline",
        SuspiciousIPInBaseline,
            "WITHIN BASELINE - Suspicious IP is in user's normal IP set",
        "WITHIN BASELINE - Activity matches established patterns"
    )
| project
    TotalBaselineSignIns = TotalSignIns,
    BaselineIPs,
    BaselineCountries,
    NewIPs,
    NewCountries,
    NewDevices,
    SuspiciousIPInBaseline,
    BaselineAssessment
```

**Performance Notes:**
- 14-day baseline is optimal for AiTM -- shorter windows may miss VPN rotation patterns
- `make_set` with limits captures enough IPs and devices for meaningful comparison
- `set_difference` efficiently identifies new IPs/countries not in the baseline

**Tuning Guidance:**
- If the suspicious IP is in the user's baseline, this may be a false positive (VPN, proxy)
- New countries are the strongest anomaly signal -- users rarely sign in from new countries
- New device fingerprints (OS/browser combination) may indicate the attacker's environment
- If the baseline shows only 1-2 IPs and the current session adds 3+, this is a significant deviation

**Expected findings:**
- Whether the suspicious IP/country has ever been seen in the user's history
- Whether the device fingerprint matches the user's known devices
- Clear determination of anomaly vs. normal variation

**Next action:**
- If new country/IP confirmed as anomalous, proceed to Step 5 for BEC detection
- If within baseline, review Steps 1-3 results for other corroborating evidence
- If inconclusive, the risk may be lower -- continue investigation but reduce urgency

---

### Step 5: Post-Compromise BEC Activity Audit

**Purpose:** Detect Business Email Compromise (BEC) activity that typically follows AiTM attacks. The standard attack chain is: AiTM token theft → email inbox access → inbox rule creation (forwarding/hiding) → BEC email sent (payment redirect, invoice fraud). This step detects each stage of the post-compromise BEC activity.

**Data needed:** AuditLogs, CloudAppEvents

```kql
// ============================================================
// QUERY 5A: Inbox Rule & Email Manipulation Detection
// Purpose: Detect inbox rules created after AiTM compromise
// Tables: AuditLogs
// Investigation Step: 5 - Post-Compromise BEC Activity
// ============================================================
let TargetUPN = "victim.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 12h;
// --- Inbox rule and email manipulation events ---
AuditLogs
| where TimeGenerated between (AlertTime - 1h .. AlertTime + ForwardWindow)
| where OperationName in (
    "Set-Mailbox",
    "New-InboxRule",
    "Set-InboxRule",
    "Enable-InboxRule",
    "Set-TransportRule",
    "Set-OwaMailboxPolicy",
    "Update user",
    "User registered security info"
)
| where InitiatedBy has TargetUPN or TargetResources has TargetUPN
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    BECIndicator = case(
        OperationName in ("New-InboxRule", "Set-InboxRule") and
            ModifiedProperties has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo"),
            "CRITICAL - Email forwarding rule created (BEC exfiltration)",
        OperationName in ("New-InboxRule", "Set-InboxRule") and
            ModifiedProperties has_any ("DeleteMessage", "MarkAsRead", "MoveToFolder"),
            "HIGH - Email hiding rule created (concealment)",
        OperationName == "Set-Mailbox" and ModifiedProperties has "ForwardingSmtpAddress",
            "CRITICAL - Mailbox-level forwarding set (all email redirected)",
        OperationName == "User registered security info",
            "HIGH - MFA method registered (persistence, see RB-0012)",
        OperationName == "Update user" and ModifiedProperties has "StrongAuthentication",
            "HIGH - Authentication method modified",
        "REVIEW - Admin action post-compromise"
    ),
    MinutesSinceAlert = datetime_diff("minute", TimeGenerated, AlertTime)
| where BECIndicator !startswith "REVIEW" or OperationName in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| sort by TimeGenerated asc
```

```kql
// ============================================================
// QUERY 5B: Email Access and Send Activity (CloudAppEvents)
// Purpose: Detect email reading and sending from suspicious session
// Tables: CloudAppEvents
// Investigation Step: 5 - Post-Compromise BEC Activity
// ============================================================
let TargetUPN = "victim.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let SuspiciousIP = "198.51.100.50";
// --- Email activity from suspicious IP ---
CloudAppEvents
| where TimeGenerated between (AlertTime .. AlertTime + 48h)
| where AccountDisplayName =~ TargetUPN or AccountId =~ TargetUPN
| where IPAddress == SuspiciousIP or RawEventData has SuspiciousIP
| where ActionType in (
    "MailItemsAccessed",
    "Send",
    "SendAs",
    "SendOnBehalf",
    "Create",
    "Update",
    "SoftDelete",
    "HardDelete",
    "MoveToDeletedItems",
    "SearchQueryInitiatedExchange"
)
| project
    TimeGenerated,
    ActionType,
    AccountDisplayName,
    IPAddress,
    ObjectName,
    ObjectType,
    City,
    CountryCode
| extend
    BECStage = case(
        ActionType == "MailItemsAccessed",
            "STAGE 1 - Email inbox reading (reconnaissance)",
        ActionType == "SearchQueryInitiatedExchange",
            "STAGE 1 - Email search (targeted reconnaissance)",
        ActionType in ("Send", "SendAs", "SendOnBehalf"),
            "STAGE 3 - Email sent as user (BEC fraud email)",
        ActionType in ("SoftDelete", "HardDelete", "MoveToDeletedItems"),
            "STAGE 4 - Email deletion (evidence destruction)",
        ActionType == "Create",
            "STAGE 2 - Draft/rule creation",
        "OTHER - Review action type"
    )
| summarize
    EventCount = count(),
    FirstActivity = min(TimeGenerated),
    LastActivity = max(TimeGenerated),
    SampleObjects = make_set(ObjectName, 5)
    by BECStage, ActionType
| sort by BECStage asc
```

**Performance Notes:**
- Query 5A detects inbox rules in AuditLogs; Query 5B detects email access in CloudAppEvents
- `ForwardTo`, `ForwardAsAttachmentTo`, and `RedirectTo` in inbox rules are the primary BEC exfiltration mechanisms
- `MailItemsAccessed` events > 50 from the suspicious IP = mass email reading (reconnaissance for BEC)
- `Send` or `SendAs` events from the suspicious IP = the attacker sent emails as the user

**Tuning Guidance:**
- If inbox rules forward to external domains (gmail.com, outlook.com, protonmail.com), this is almost certainly BEC
- Email deletion after sending indicates the attacker is hiding their sent BEC emails
- Search queries (`SearchQueryInitiatedExchange`) for terms like "wire", "payment", "invoice", "bank" indicate targeted financial BEC
- If `MFA method registered` appears in the same window, the attacker is establishing persistence (cross-reference RB-0012)

**Expected findings:**
- Complete BEC activity timeline: email reading → rule creation → BEC email sent → evidence deletion
- Whether inbox forwarding rules were created (ongoing data exfiltration)
- Whether the attacker sent emails as the user (financial fraud risk)

**Next action:**
- If BEC emails sent, identify recipients and alert them immediately
- If inbox rules created, remove them during containment
- If MFA methods registered, cross-reference RB-0012 and remove rogue methods
- Proceed to Step 6 for persistence detection

---

### Step 6: Persistence Mechanism Detection

**Purpose:** After AiTM token theft, sophisticated attackers establish multiple persistence mechanisms to maintain access even after the stolen token expires. Common persistence methods include: MFA method registration (RB-0012), OAuth consent grant (RB-0011), inbox forwarding rules, and service principal credential addition (RB-0010). This step checks for all of them in a single sweep.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 6: Persistence Mechanism Detection
// Purpose: Detect all persistence mechanisms established post-AiTM
// Tables: AuditLogs
// Investigation Step: 6 - Persistence Mechanism Detection
// ============================================================
let TargetUPN = "victim.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 12h;
// --- All persistence-relevant actions after AiTM ---
AuditLogs
| where TimeGenerated between (AlertTime - 30m .. AlertTime + ForwardWindow)
| where InitiatedBy has TargetUPN or TargetResources has TargetUPN
| where OperationName in (
    // MFA persistence (RB-0012)
    "User registered security info",
    "User registered all required security info",
    "Admin registered security info",
    // OAuth persistence (RB-0011)
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment grant to user",
    // Inbox rule persistence (RB-0008)
    "New-InboxRule",
    "Set-InboxRule",
    "Set-Mailbox",
    // SP credential persistence (RB-0010)
    "Add service principal credentials",
    "Add application",
    "Add owner to application",
    // Role escalation (RB-0013)
    "Add member to role",
    "Add eligible member to role",
    // Password/account persistence
    "Reset password (self-service)",
    "Change password (self-service)",
    "Update user"
)
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    PersistenceType = case(
        OperationName has "security info",
            "MFA REGISTRATION - Attacker adding their own MFA method",
        OperationName in ("Consent to application", "Add delegated permission grant"),
            "OAUTH CONSENT - Attacker granting app access to data",
        OperationName in ("New-InboxRule", "Set-InboxRule"),
            "INBOX RULE - Email forwarding for ongoing access",
        OperationName == "Set-Mailbox" and ModifiedProperties has "Forward",
            "MAILBOX FORWARD - All email redirected",
        OperationName has "service principal" or OperationName == "Add application",
            "APP/SP PERSISTENCE - Application-level access",
        OperationName has "role",
            "ROLE ESCALATION - Privilege escalation",
        OperationName has "password",
            "PASSWORD CHANGE - Credential modification",
        OperationName == "Update user" and ModifiedProperties has "StrongAuthentication",
            "AUTH METHOD CHANGE - Authentication modification",
        "OTHER PERSISTENCE - Review"
    ),
    MinutesSinceAiTM = datetime_diff("minute", TimeGenerated, AlertTime),
    CrossReferenceRunbook = case(
        OperationName has "security info", "See RB-0012",
        OperationName in ("Consent to application", "Add delegated permission grant"), "See RB-0011",
        OperationName in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox"), "See RB-0008",
        OperationName has "service principal" or OperationName == "Add application", "See RB-0010",
        OperationName has "role", "See RB-0013",
        ""
    )
| project
    TimeGenerated,
    PersistenceType,
    OperationName,
    ActorUPN,
    ActorIP,
    TargetResource,
    MinutesSinceAiTM,
    CrossReferenceRunbook
| sort by TimeGenerated asc
```

**Performance Notes:**
- This query is a comprehensive sweep across ALL persistence mechanisms in a single pass
- `CrossReferenceRunbook` links each finding to the detailed investigation runbook for that technique
- Starting 30 minutes before AlertTime captures persistence established during the initial compromise session

**Tuning Guidance:**
- Multiple persistence types within the same session = sophisticated attacker (likely nation-state or organized crime)
- MFA registration is the most common persistence mechanism post-AiTM
- Inbox rules are the most common BEC persistence mechanism
- If the attacker changed the password, they've locked out the legitimate user -- highest urgency

**Expected findings:**
- All persistence mechanisms established after the AiTM compromise
- Timeline showing the order of persistence establishment
- Cross-references to detailed runbooks for each persistence type

**Next action:**
- For each persistence mechanism found, follow the linked runbook for detailed remediation
- During containment, remove ALL persistence mechanisms simultaneously (not one at a time)
- Proceed to Step 7 for org-wide campaign sweep

---

### Step 7: Org-Wide AiTM Campaign Sweep

**Purpose:** Scan the entire organization for other users affected by the same AiTM campaign. AiTM phishing typically targets multiple users simultaneously. Identify other users with anomalous token detections, session IP divergence from the same attacker infrastructure, or BEC indicators in the same time window.

**Data needed:** AADUserRiskEvents, SigninLogs

```kql
// ============================================================
// QUERY 7: Org-Wide AiTM Campaign Sweep
// Purpose: Find other users affected by the same AiTM campaign
// Tables: AADUserRiskEvents, SigninLogs
// Investigation Step: 7 - Org-Wide AiTM Campaign Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let SweepWindow = 7d;
let SuspiciousIP = "198.51.100.50";
// --- All anomalous token detections in the org ---
let TokenAnomalies = AADUserRiskEvents
| where TimeGenerated between (AlertTime - SweepWindow .. AlertTime + 1d)
| where RiskEventType in ("anomalousToken", "tokenIssuerAnomaly")
| project
    TimeGenerated,
    UserPrincipalName,
    RiskEventType,
    RiskLevel,
    IPAddress,
    Location = strcat(City, ", ", CountryOrRegion);
// --- Sign-ins from the known attacker IP ---
let AttackerIPActivity = SigninLogs
| where TimeGenerated between (AlertTime - SweepWindow .. AlertTime + 1d)
| where IPAddress == SuspiciousIP and ResultType == "0"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion));
// --- Combine indicators ---
TokenAnomalies
| extend DataSource = "AnomalousToken"
| project TimeGenerated, UserPrincipalName, DataSource, IPAddress, Location,
    Detail = strcat(RiskEventType, " (", RiskLevel, ")")
| union (
    AttackerIPActivity
    | extend DataSource = "AttackerIPSignIn"
    | project TimeGenerated, UserPrincipalName, DataSource, IPAddress, Location,
        Detail = strcat("Sign-in to ", AppDisplayName)
)
| summarize
    IndicatorCount = count(),
    DataSources = make_set(DataSource, 5),
    IPs = make_set(IPAddress, 10),
    Locations = make_set(Location, 10),
    Details = make_set(Detail, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName
| extend
    CampaignAssessment = case(
        IndicatorCount > 3 and DataSources has "AnomalousToken" and DataSources has "AttackerIPSignIn",
            "CRITICAL - Multiple AiTM indicators + attacker IP access",
        DataSources has "AnomalousToken",
            "HIGH - Anomalous token detection (probable AiTM victim)",
        DataSources has "AttackerIPSignIn" and IndicatorCount > 5,
            "HIGH - Heavy activity from attacker IP",
        DataSources has "AttackerIPSignIn",
            "MEDIUM - Sign-in from known attacker IP",
        "LOW - Single indicator"
    )
| where CampaignAssessment !startswith "LOW"
| sort by CampaignAssessment asc, IndicatorCount desc
```

**Performance Notes:**
- 7-day sweep captures campaigns that may have started days before detection
- Combining anomalous token detections with attacker IP sign-ins provides comprehensive coverage
- If the attacker uses multiple IPs, add them to the `SuspiciousIP` filter or use IP range matching

**Tuning Guidance:**
- If > 5 users have anomalous token detections in the same window, this is a mass AiTM campaign
- Check if affected users received the same phishing email (search email logs for common URLs)
- If the attacker IP is from known phishing infrastructure (hosting provider, bulletproof hosting), block the entire subnet
- Cross-reference affected users with email phishing data to identify the initial delivery vector

**Expected findings:**
- All users affected by the AiTM campaign
- Common attacker infrastructure (IPs, timing patterns)
- Campaign scope and velocity

**Next action:**
- For each affected user, perform full investigation (Steps 1-6)
- Block attacker IP ranges at network level
- Search for and quarantine phishing emails across the organization
- Begin containment for ALL affected users simultaneously

---

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to assess whether the suspected AiTM/token theft session shows anomalous behavioral patterns. AiTM phishing attacks result in sign-ins from the attacker's infrastructure — UEBA's ISP/country/device first-time detection is particularly effective here because the stolen token will be replayed from a location that's completely new for the user.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 4. UEBA needs approximately **one week** after activation before generating meaningful insights.

#### Query 8A: Token Replay Anomaly Assessment

```kql
// ============================================================
// Query 8A: UEBA Anomaly Assessment for AiTM/Token Theft
// Purpose: Check if UEBA flagged the suspected session as
//          anomalous — attacker's replayed token should trigger
//          first-time ISP/country/device detections
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T10:30:00Z);
let TargetUser = "user@contoso.com";
let LookbackWindow = 7d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
| where UserPrincipalName =~ TargetUser
| project
    TimeGenerated,
    ActivityType,
    ActionType,
    InvestigationPriority,
    SourceIPAddress,
    SourceIPLocation,
    // ISP/Country — attacker's proxy will be a new ISP/country
    FirstTimeISP = tobool(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommonForUser = tobool(ActivityInsights.ISPUncommonlyUsedByUser),
    ISPUncommonAmongPeers = tobool(ActivityInsights.ISPUncommonlyUsedAmongPeers),
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommonAmongPeers = tobool(ActivityInsights.CountryUncommonlyConnectedFromAmongPeers),
    // Device/Browser — stolen token used from attacker's device
    FirstTimeDevice = tobool(ActivityInsights.FirstTimeUserConnectedFromDevice),
    FirstTimeBrowser = tobool(ActivityInsights.FirstTimeUserConnectedViaBrowser),
    // Application access — attacker typically targets email/SharePoint
    FirstTimeApp = tobool(ActivityInsights.FirstTimeUserUsedApp),
    AppUncommonAmongPeers = tobool(ActivityInsights.AppUncommonlyUsedAmongPeers),
    // Action anomalies — post-compromise BEC actions
    FirstTimeAction = tobool(ActivityInsights.FirstTimeUserPerformedAction),
    ActionUncommonAmongPeers = tobool(ActivityInsights.ActionUncommonlyPerformedAmongPeers),
    // User context
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    // Threat intel
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| order by InvestigationPriority desc, TimeGenerated desc
```

#### Query 8B: Post-Compromise BEC Activity Anomalies

```kql
// ============================================================
// Query 8B: Post-AiTM BEC Activity Behavioral Analysis
// Purpose: Assess whether post-compromise email/data access
//          activities deviate from user's established baseline
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <10 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T10:30:00Z);
let TargetUser = "user@contoso.com";
let PostCompromiseWindow = 12h;
BehaviorAnalytics
| where TimeGenerated between (AlertTime .. (AlertTime + PostCompromiseWindow))
| where UserPrincipalName =~ TargetUser
| summarize
    TotalActivities = count(),
    HighAnomalyCount = countif(InvestigationPriority >= 7),
    MediumAnomalyCount = countif(InvestigationPriority >= 4 and InvestigationPriority < 7),
    MaxPriority = max(InvestigationPriority),
    FirstTimeActionCount = countif(tobool(ActivityInsights.FirstTimeUserPerformedAction)),
    FirstTimeResourceCount = countif(tobool(ActivityInsights.FirstTimeUserAccessedResource)),
    FirstTimeAppCount = countif(tobool(ActivityInsights.FirstTimeUserUsedApp)),
    UncommonActionAmongPeers = countif(tobool(ActivityInsights.ActionUncommonlyPerformedAmongPeers)),
    UncommonAppAmongPeers = countif(tobool(ActivityInsights.AppUncommonlyUsedAmongPeers)),
    UniqueIPs = dcount(SourceIPAddress),
    UniqueCountries = dcount(SourceIPLocation),
    Countries = make_set(SourceIPLocation),
    ActivityTypes = make_set(ActivityType),
    BlastRadius = take_any(tostring(UsersInsights.BlastRadius)),
    ThreatIntelHits = countif(isnotempty(tostring(DevicesInsights.ThreatIntelIndicatorType)))
| extend
    AnomalyRatio = round(todouble(HighAnomalyCount + MediumAnomalyCount) / TotalActivities * 100, 1),
    BECSignals = FirstTimeActionCount + FirstTimeResourceCount + FirstTimeAppCount
        + UncommonActionAmongPeers + UncommonAppAmongPeers
```

**Tuning Guidance:**

- **InvestigationPriority threshold**: `>= 7` = high-confidence anomaly, `>= 4` = moderate, `< 4` = likely normal
- **ISP/Country first-time flags**: AiTM attacks ALWAYS result in token replay from the attacker's infrastructure. `FirstTimeISP = true` AND `FirstTimeCountry = true` for a token-based session is an extremely strong indicator of AiTM compromise
- **Post-compromise window**: Default 12h. AiTM attackers often act fast (mailbox rules, data exfiltration within hours). Expand to 24h for slower campaigns
- **BECSignals count**: Sum of first-time and uncommon activities post-compromise. `>= 3` signals strongly indicate active BEC activity

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| InvestigationPriority | >= 7 (high anomaly) | < 4 (normal behavior) |
| FirstTimeISP | true — token replayed from new ISP | false — user's ISP |
| FirstTimeCountry | true — attacker in different country | false — user's country |
| FirstTimeDevice | true — attacker's device | false — user's device |
| FirstTimeApp | true — accessing unfamiliar apps | false — usual apps |
| Post-compromise BECSignals | >= 3 — active BEC underway | 0 — no anomalous actions |
| ActionUncommonAmongPeers | true — mail rule/forwarding unusual | false — normal for role |
| UniqueCountries (12h) | 2+ — concurrent multi-country | 1 — single location |
| BlastRadius | High — privileged/exec account | Low — standard user |
| ThreatIndicator | Proxy, VPN, Hosting | Empty |

**Decision guidance:**

- **FirstTimeISP + FirstTimeCountry + FirstTimeDevice = all true** → Near-certain AiTM token replay. The stolen session cookie is being used from infrastructure the user has never touched. Proceed to Containment immediately
- **Post-compromise BECSignals >= 3** → Attacker is actively performing BEC operations (mail rules, data access, forwarding). Revoke all sessions and proceed to Containment
- **Multiple countries in 12h window** → Concurrent sessions from different countries confirms token theft — legitimate user cannot be in two countries simultaneously
- **InvestigationPriority < 4 + all flags false** → Token anomaly may be a false positive from VPN switching or mobile network handoff. Combined with clean findings from Steps 1-7, consider closing
- **BlastRadius = High** → Executive or privileged account compromised via AiTM. Maximum priority escalation

---

## 6. Containment Playbook

### Immediate Actions (First 15 Minutes)

| Priority | Action | Command/Location | Who |
|---|---|---|---|
| P0 | Revoke ALL sessions for affected user | `Revoke-MgUserSignInSession -UserId [UPN]` | Security Admin |
| P0 | Enable Continuous Access Evaluation (CAE) | Entra Portal > Security > CA > Session > CAE | Security Admin |
| P0 | Reset password | Entra Portal > Users > [User] > Reset Password | Helpdesk Admin |
| P0 | Confirm user risk as compromised | Identity Protection > Risky users > Confirm compromised | Security Admin |
| P0 | Remove rogue MFA methods | Entra Portal > Users > [User] > Authentication methods | Auth Admin |
| P1 | Remove inbox forwarding rules | Exchange Admin > Mailboxes > [User] > Mail flow settings | Exchange Admin |
| P1 | Revoke OAuth consent grants | Entra Portal > Enterprise Apps > [App] > Delete | Cloud App Admin |

### Secondary Actions (First 4 Hours)

| Priority | Action | Details |
|---|---|---|
| P1 | Block attacker IP at CA policy level | Add suspicious IP to named locations block list |
| P1 | Search for and quarantine phishing emails | Use Defender for Office 365 Threat Explorer |
| P2 | Notify BEC email recipients | Alert anyone who received emails from the compromised account |
| P2 | Review all persistence mechanisms | Run RB-0008, RB-0010, RB-0011, RB-0012, RB-0013 for the user |
| P3 | Enforce phishing-resistant MFA | Deploy FIDO2/WHfB via Authentication Strengths CA policy |
| P3 | Enable Token Protection (preview) | Bind tokens to devices to prevent replay |
| P3 | Implement sign-in frequency controls | Reduce token lifetime for sensitive apps via CA session controls |

### Session Revocation Commands

```powershell
# Revoke all sessions -- this invalidates ALL tokens
Connect-MgGraph -Scopes "User.ReadWrite.All"
$UserId = "victim.user@contoso.com"
Revoke-MgUserSignInSession -UserId $UserId

# Also revoke refresh tokens via Graph API
Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/users/$UserId/revokeSignInSessions"

# Reset password with force change
$PasswordProfile = @{
    Password = [System.Web.Security.Membership]::GeneratePassword(24, 6)
    ForceChangePasswordNextSignIn = $true
}
Update-MgUser -UserId $UserId -PasswordProfile $PasswordProfile

# Remove inbox forwarding rules
Connect-ExchangeOnline
Get-InboxRule -Mailbox $UserId | Where-Object {
    $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo
} | Remove-InboxRule -Confirm:$false
```

---

## 7. Evidence Collection Checklist

| Evidence | Source | Retention | Priority |
|---|---|---|---|
| Anomalous token risk events | Microsoft Sentinel (AADUserRiskEvents) | Export query results | Critical |
| Sign-in logs with IP divergence | Microsoft Sentinel (SigninLogs) | Export query results | Critical |
| Non-interactive token replay logs | Microsoft Sentinel (AADNonInteractiveUserSignInLogs) | Export query results | Critical |
| Inbox rules created/modified | Exchange Admin / AuditLogs | Screenshot + export | Critical |
| BEC email content (if sent) | Defender for Office 365 | Export .eml | Critical |
| Phishing email (initial vector) | Defender for Office 365 | Export .eml + URL analysis | Critical |
| Persistence mechanisms audit | AuditLogs query results | Export query results | High |
| Org-wide campaign sweep results | Query results from Step 7 | Export CSV | High |
| Attacker IP WHOIS and threat intel | IP reputation services | Screenshot | Medium |
| User session token details | Sign-in diagnostic logs | Export | Medium |

---

## 8. Escalation Criteria

### Escalate to Incident Commander When:
- Multiple users affected by the same AiTM campaign (> 3 users)
- BEC emails sent to external recipients (financial fraud risk)
- Executive, finance, or legal account compromised
- Attacker established multiple persistence mechanisms (MFA + rules + OAuth)
- Evidence of data exfiltration (mass email/file access from attacker IP)

### Escalate to Legal/Privacy When:
- Financial BEC emails sent (wire transfer, invoice modification)
- Sensitive data accessed via the stolen session (email, files)
- Regulatory notification requirements may apply

### Escalate to Microsoft When:
- AiTM phishing infrastructure hosted on Azure/Microsoft services
- Token Protection bypass or CAE bypass detected
- Report phishing URLs: [Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site)

---

## 9. False Positive Documentation

| Scenario | How to Verify | Action |
|---|---|---|
| VPN split-tunneling IP change | Verify corporate VPN configuration, match egress IPs | Add VPN IPs to known locations |
| Cloud proxy IP rotation | Verify Zscaler/Netskope egress IP ranges | Whitelist proxy IP ranges |
| Mobile user Wi-Fi to cellular | Check device management for known mobile device | Correlate with device enrollment |
| International travel | Verify travel with user/manager | Document expected IP changes |
| Token refresh during network change | Check if both IPs are from same ISP/region | Lower severity if same ISP |

---

## 10. MITRE ATT&CK Mapping

| Technique | ID | Tactic | How Detected |
|---|---|---|---|
| Adversary-in-the-Middle | T1557 | Credential Access | Session IP divergence, anomalousToken risk event |
| Steal Web Session Cookie | T1539 | Credential Access | Token replay in non-interactive sign-in logs |
| Use Alternate Auth Material: Web Session Cookie | T1550.004 | Defense Evasion | Non-interactive access from attacker IP |
| Phishing: Spearphishing Link | T1566.002 | Initial Access | Phishing email with AiTM proxy URL |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence | Attacker using stolen session as legitimate user |
| Email Collection: Remote Email Collection | T1114.002 | Collection | Mass email access from attacker IP |

---

## 11. Query Summary

| # | Query | Table | Purpose |
|---|---|---|---|
| 1 | Anomalous Token Risk Event Analysis | AADUserRiskEvents | Identify token anomaly risk detections |
| 2 | Session IP Divergence Detection | SigninLogs | Detect IP switches within authentication sessions |
| 3 | Token Replay via Non-Interactive Sign-Ins | AADNonInteractiveUserSignInLogs | Detect token replay patterns |
| 4 | Baseline Comparison | SigninLogs | Compare suspicious session against user baseline |
| 5A | Inbox Rule & Email Manipulation | AuditLogs | Detect BEC inbox rules and forwarding |
| 5B | Email Access and Send Activity | CloudAppEvents | Detect email reading and BEC sending |
| 6 | Persistence Mechanism Detection | AuditLogs | Find all persistence types post-AiTM |
| 7 | Org-Wide AiTM Campaign Sweep | AADUserRiskEvents + SigninLogs | Find other campaign victims |

---

## Appendix A: Datatable Tests

### Test 1: Anomalous Token Detection

```kql
// ============================================================
// TEST 1: Anomalous Token Detection
// Validates: Query 1 - Detect anomalous token risk events
// Expected: victim.user anomalousToken = "HIGH CONFIDENCE AiTM"
//           victim.user suspiciousInbox = "BEC FOLLOW-UP"
//           normal.user = "CORROBORATING" (unfamiliar features only)
// ============================================================
let TestRiskEvents = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    RiskEventType: string,
    RiskLevel: string,
    RiskState: string,
    RiskDetail: string,
    DetectionTimingType: string,
    IPAddress: string,
    City: string,
    CountryOrRegion: string,
    Source: string,
    Activity: string,
    AdditionalInfo: string,
    CorrelationId: string
) [
    // --- victim.user: Anomalous token (primary AiTM indicator) ---
    datetime(2026-02-22T14:00:00Z), "victim.user@contoso.com",
        "anomalousToken", "high", "atRisk", "detectedSuspiciousActivity",
        "realtime", "198.51.100.50", "Unknown", "NL",
        "IdentityProtection", "signin", "Token presented from unexpected context", "corr-aitm-001",
    // --- victim.user: Inbox forwarding (BEC indicator) ---
    datetime(2026-02-22T14:30:00Z), "victim.user@contoso.com",
        "suspiciousInboxForwardingActivity", "medium", "atRisk", "detectedSuspiciousActivity",
        "offline", "198.51.100.50", "Unknown", "NL",
        "MCAS", "inboxForwarding", "", "corr-aitm-002",
    // --- normal.user: Unfamiliar features only (not AiTM) ---
    datetime(2026-02-22T10:00:00Z), "normal.user@contoso.com",
        "unfamiliarFeatures", "low", "atRisk", "detectedSuspiciousActivity",
        "realtime", "10.0.0.50", "Chicago", "US",
        "IdentityProtection", "signin", "", "corr-normal-001"
];
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- Run detection ---
TestRiskEvents
| where TimeGenerated between (AlertTime - 24h .. AlertTime + 4h)
| extend
    AiTMConfidence = case(
        RiskEventType == "anomalousToken" and RiskLevel == "high",
            "HIGH CONFIDENCE AiTM - Anomalous token with high risk",
        RiskEventType == "anomalousToken",
            "PROBABLE AiTM - Anomalous token detected",
        RiskEventType == "suspiciousInboxForwardingActivity",
            "BEC FOLLOW-UP - Post-AiTM activity pattern",
        "CORROBORATING - Supporting evidence"
    )
| project UserPrincipalName, RiskEventType, RiskLevel, IPAddress, AiTMConfidence
// Expected: victim.user anomalousToken = "HIGH CONFIDENCE AiTM"
// Expected: victim.user suspiciousInboxForwarding = "BEC FOLLOW-UP"
// Expected: normal.user unfamiliarFeatures = "CORROBORATING"
```

### Test 2: Session IP Divergence

```kql
// ============================================================
// TEST 2: Session IP Divergence
// Validates: Query 2 - Detect IP switches within authentication sessions
// Expected: victim.user IP switch US→NL in 2 min = "CRITICAL - Cross-country"
//           traveler.user IP switch within same country = "MEDIUM"
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    AppDisplayName: string,
    IPAddress: string,
    LocationDetails: dynamic,
    DeviceDetail: dynamic,
    ResultType: string,
    AuthenticationRequirement: string,
    AuthenticationDetails: string,
    RiskLevelDuringSignIn: string,
    ResourceDisplayName: string,
    CorrelationId: string,
    IsInteractive: bool
) [
    // --- victim.user: Interactive auth from US (legitimate user) ---
    datetime(2026-02-22T13:58:00Z), "victim.user@contoso.com",
        "Microsoft Office", "10.0.0.20",
        dynamic({"city":"New York","countryOrRegion":"US"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        "0", "multiFactorAuthentication", "MFA completed", "none",
        "Microsoft Office 365", "corr-victim-001", true,
    // --- victim.user: Token replay from NL (attacker) 2 min later ---
    datetime(2026-02-22T14:00:00Z), "victim.user@contoso.com",
        "Microsoft Exchange Online", "198.51.100.50",
        dynamic({"city":"Amsterdam","countryOrRegion":"NL"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        "0", "singleFactorAuthentication", "", "none",
        "Microsoft Exchange Online", "corr-victim-001", false,
    // --- traveler.user: IP switch within same country (VPN change) ---
    datetime(2026-02-22T12:00:00Z), "traveler.user@contoso.com",
        "Microsoft Office", "192.0.2.10",
        dynamic({"city":"San Francisco","countryOrRegion":"US"}),
        dynamic({"operatingSystem":"macOS","browser":"Safari"}),
        "0", "multiFactorAuthentication", "MFA completed", "none",
        "Microsoft Office 365", "corr-travel-001", true,
    datetime(2026-02-22T12:30:00Z), "traveler.user@contoso.com",
        "Microsoft Teams", "192.0.2.20",
        dynamic({"city":"Los Angeles","countryOrRegion":"US"}),
        dynamic({"operatingSystem":"macOS","browser":"Safari"}),
        "0", "singleFactorAuthentication", "", "none",
        "Microsoft Teams", "corr-travel-001", false
];
// --- Detect IP divergence ---
let InteractiveSessions = TestSigninLogs
| where IsInteractive == true and ResultType == "0"
| project
    AuthTime = TimeGenerated, AuthIP = IPAddress,
    AuthCountry = tostring(LocationDetails.countryOrRegion),
    AuthLocation = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    UserPrincipalName, CorrelationId;
let SubsequentAccess = TestSigninLogs
| where ResultType == "0"
| project
    AccessTime = TimeGenerated, AccessIP = IPAddress,
    AccessCountry = tostring(LocationDetails.countryOrRegion),
    AccessLocation = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    AccessApp = AppDisplayName,
    UserPrincipalName, CorrelationId;
InteractiveSessions
| join kind=inner SubsequentAccess on UserPrincipalName, CorrelationId
| where AccessIP != AuthIP and AccessTime >= AuthTime
| extend
    TimeDeltaMinutes = datetime_diff("minute", AccessTime, AuthTime),
    IPDivergenceType = case(
        AuthCountry != AccessCountry,
            "CRITICAL - Cross-country IP divergence",
        TimeDeltaMinutes < 5,
            "HIGH - Immediate IP switch (< 5 min)",
        "MEDIUM - IP switch within session"
    )
| project UserPrincipalName, AuthIP, AuthLocation, AccessIP, AccessLocation, TimeDeltaMinutes, IPDivergenceType
// Expected: victim.user US→NL in 2 min = "CRITICAL - Cross-country IP divergence"
// Expected: traveler.user SF→LA in 30 min = "MEDIUM - IP switch within session" (same country)
```

### Test 3: Persistence Mechanism Detection

```kql
// ============================================================
// TEST 3: Persistence Mechanism Detection
// Validates: Query 6 - Detect all persistence types post-AiTM
// Expected: MFA registration = "MFA REGISTRATION" (RB-0012)
//           Inbox rule = "INBOX RULE" (RB-0008)
//           OAuth consent = "OAUTH CONSENT" (RB-0011)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- MFA registration (persistence) ---
    datetime(2026-02-22T14:05:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"victim.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Victim User","modifiedProperties":[
            {"displayName":"StrongAuthenticationMethod","newValue":"PhoneAppNotification"}
        ]}]),
        "success",
    // --- Inbox forwarding rule (BEC persistence) ---
    datetime(2026-02-22T14:10:00Z), "New-InboxRule",
        dynamic({"user":{"userPrincipalName":"victim.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Auto-Forward","modifiedProperties":[
            {"displayName":"ForwardTo","newValue":"attacker@protonmail.com"}
        ]}]),
        "success",
    // --- OAuth consent grant (data access persistence) ---
    datetime(2026-02-22T14:15:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"victim.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Document Viewer Pro","modifiedProperties":[
            {"displayName":"ConsentAction.Permissions","newValue":"Mail.ReadWrite Files.Read.All"}
        ]}]),
        "success"
];
let TargetUPN = "victim.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- Run persistence detection ---
TestAuditLogs
| where TimeGenerated between (AlertTime - 30m .. AlertTime + 12h)
| where InitiatedBy has TargetUPN
| extend
    PersistenceType = case(
        OperationName has "security info",
            "MFA REGISTRATION - Attacker adding their own MFA method",
        OperationName in ("Consent to application", "Add delegated permission grant"),
            "OAUTH CONSENT - Attacker granting app access to data",
        OperationName in ("New-InboxRule", "Set-InboxRule"),
            "INBOX RULE - Email forwarding for ongoing access",
        "OTHER"
    ),
    CrossReferenceRunbook = case(
        OperationName has "security info", "See RB-0012",
        OperationName has "Consent", "See RB-0011",
        OperationName has "InboxRule", "See RB-0008",
        ""
    ),
    MinutesSinceAiTM = datetime_diff("minute", TimeGenerated, AlertTime)
| project TimeGenerated, PersistenceType, OperationName, MinutesSinceAiTM, CrossReferenceRunbook
// Expected: +5 min = "MFA REGISTRATION" (See RB-0012)
// Expected: +10 min = "INBOX RULE" (See RB-0008)
// Expected: +15 min = "OAUTH CONSENT" (See RB-0011)
```

### Test 4: Org-Wide AiTM Campaign Sweep

```kql
// ============================================================
// TEST 4: Org-Wide AiTM Campaign Sweep
// Validates: Query 7 - Find other users in the same AiTM campaign
// Expected: victim.user = "CRITICAL" (anomalousToken + attacker IP)
//           finance.vp = "HIGH" (anomalousToken only)
//           hr.director = "MEDIUM" (attacker IP sign-in only)
// ============================================================
let TestRiskEvents = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    RiskEventType: string,
    RiskLevel: string,
    IPAddress: string,
    City: string,
    CountryOrRegion: string
) [
    datetime(2026-02-22T14:00:00Z), "victim.user@contoso.com",
        "anomalousToken", "high", "198.51.100.50", "Amsterdam", "NL",
    datetime(2026-02-22T14:20:00Z), "finance.vp@contoso.com",
        "anomalousToken", "high", "198.51.100.51", "Amsterdam", "NL"
];
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    AppDisplayName: string,
    LocationDetails: dynamic,
    ResultType: string
) [
    datetime(2026-02-22T14:05:00Z), "victim.user@contoso.com",
        "198.51.100.50", "Microsoft Exchange Online",
        dynamic({"city":"Amsterdam","countryOrRegion":"NL"}), "0",
    datetime(2026-02-22T14:25:00Z), "finance.vp@contoso.com",
        "198.51.100.51", "Microsoft Exchange Online",
        dynamic({"city":"Amsterdam","countryOrRegion":"NL"}), "0",
    datetime(2026-02-22T15:00:00Z), "hr.director@contoso.com",
        "198.51.100.50", "Microsoft Office",
        dynamic({"city":"Amsterdam","countryOrRegion":"NL"}), "0"
];
let SuspiciousIP = "198.51.100.50";
// --- Campaign sweep ---
let TokenAnomalies = TestRiskEvents
| where RiskEventType == "anomalousToken"
| extend DataSource = "AnomalousToken"
| project TimeGenerated, UserPrincipalName, DataSource, IPAddress,
    Location = strcat(City, ", ", CountryOrRegion),
    Detail = strcat(RiskEventType, " (", RiskLevel, ")");
let AttackerIPActivity = TestSigninLogs
| where IPAddress == SuspiciousIP and ResultType == "0"
| extend DataSource = "AttackerIPSignIn"
| project TimeGenerated, UserPrincipalName, DataSource, IPAddress,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    Detail = strcat("Sign-in to ", AppDisplayName);
TokenAnomalies
| union AttackerIPActivity
| summarize
    IndicatorCount = count(),
    DataSources = make_set(DataSource, 5),
    IPs = make_set(IPAddress, 10)
    by UserPrincipalName
| extend
    CampaignAssessment = case(
        DataSources has "AnomalousToken" and DataSources has "AttackerIPSignIn",
            "CRITICAL - Multiple AiTM indicators + attacker IP access",
        DataSources has "AnomalousToken",
            "HIGH - Anomalous token detection (probable AiTM victim)",
        DataSources has "AttackerIPSignIn",
            "MEDIUM - Sign-in from known attacker IP",
        "LOW"
    )
| where CampaignAssessment !startswith "LOW"
| project UserPrincipalName, IndicatorCount, DataSources, IPs, CampaignAssessment
| sort by CampaignAssessment asc
// Expected: victim.user = "CRITICAL" (both AnomalousToken and AttackerIPSignIn)
// Expected: finance.vp = "HIGH" (AnomalousToken only, different IP in same range)
// Expected: hr.director = "MEDIUM" (AttackerIPSignIn only, no token anomaly)
```

---

## References

- [Microsoft: Defend against AiTM phishing attacks](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection)
- [Microsoft: Token theft playbook](https://learn.microsoft.com/en-us/security/operations/token-theft-playbook)
- [Microsoft: Continuous Access Evaluation in Entra ID](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Microsoft: Token Protection (device-bound tokens)](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection)
- [Microsoft: Authentication Strengths and phishing-resistant MFA](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)
- [Microsoft: Investigating AiTM phishing attacks (Incident Response)](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing)
- [MITRE ATT&CK T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [MITRE ATT&CK T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK T1550.004 - Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/)
- [Microsoft: Storm-1167 AiTM phishing-as-a-service analysis](https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/)
- [EvilGinx: Understanding reverse-proxy phishing frameworks](https://breakdev.org/evilginx-3-0-update/)
- [CISA: Phishing-resistant MFA fact sheet](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf)
