---
title: "Session Token Theft / Cookie Hijacking"
id: RB-0021
severity: critical
status: reviewed
description: >
  Investigation runbook for detecting stolen session tokens and hijacked browser
  cookies being replayed from attacker-controlled infrastructure. Covers detection
  of same-session cross-IP anomalies, Primary Refresh Token (PRT) abuse, token
  protection bypass analysis, infostealer-based cookie theft, CAE enforcement
  validation, post-theft lateral resource access, and organization-wide token
  theft sweep. Unlike AiTM-focused detection (RB-0014), this runbook is
  vector-agnostic — it detects stolen tokens regardless of how they were obtained
  (AiTM phishing, infostealer malware, XSS, physical access, PRT extraction).
  Token theft is the #1 identity attack vector in 2025-2026 because it completely
  bypasses MFA after the legitimate user has already authenticated.
mitre_attack:
  tactics:
    - tactic_id: TA0006
      tactic_name: "Credential Access"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
    - tactic_id: TA0008
      tactic_name: "Lateral Movement"
    - tactic_id: TA0009
      tactic_name: "Collection"
    - tactic_id: TA0003
      tactic_name: "Persistence"
  techniques:
    - technique_id: T1539
      technique_name: "Steal Web Session Cookie"
      confidence: confirmed
    - technique_id: T1550.004
      technique_name: "Use Alternate Authentication Material: Web Session Cookie"
      confidence: confirmed
    - technique_id: T1528
      technique_name: "Steal Application Access Token"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1550.001
      technique_name: "Use Alternate Authentication Material: Application Access Token"
      confidence: probable
threat_actors:
  - "Storm-1167"
  - "Midnight Blizzard (APT29)"
  - "Scattered Spider (Octo Tempest)"
  - "Storm-0558"
  - "Lumma Stealer Operators"
  - "RedLine Stealer Operators"
log_sources:
  - table: "SigninLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "AADNonInteractiveUserSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: true
    alternatives: []
  - table: "AADUserRiskEvents"
    product: "Entra ID Identity Protection"
    license: "Entra ID P2"
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
    alternatives: ["OfficeActivity"]
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
tier: 1
data_checks:
  - query: "SigninLogs | take 1"
    label: primary
    description: "Interactive sign-in logs for session origin identification"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "Non-interactive sign-ins for token replay detection"
  - query: "AADUserRiskEvents | where RiskEventType in ('anomalousToken', 'attackerinTheMiddle', 'attemptedPRTAccess') | take 1"
    description: "Risk events for token theft detection (requires Entra ID P2)"
  - query: "AuditLogs | take 1"
    description: "For post-theft persistence actions"
  - query: "CloudAppEvents | take 1"
    description: "For post-theft cloud app activity (requires Defender for Cloud Apps)"
---

# Session Token Theft / Cookie Hijacking - Investigation Runbook

> **RB-0021** | Severity: Critical | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Entra ID Identity Protection + SigninLogs Cross-IP Analysis
>
> **Detection Logic:** Stolen session token replayed from attacker infrastructure
>
> **Primary MITRE Technique:** T1539 - Steal Web Session Cookie

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Stolen Token Detection via Session Cross-IP Analysis](#step-1-stolen-token-detection-via-session-cross-ip-analysis)
   - [Step 2: Risk Event Correlation — Token Anomaly Signals](#step-2-risk-event-correlation--token-anomaly-signals)
   - [Step 3: Token Forensics — Protection Status and CAE Analysis](#step-3-token-forensics--protection-status-and-cae-analysis)
   - [Step 4: PRT Abuse Detection — Primary Refresh Token Indicators](#step-4-prt-abuse-detection--primary-refresh-token-indicators)
   - [Step 5: Baseline Comparison — Establish Normal Session Pattern](#step-5-baseline-comparison--establish-normal-session-pattern)
   - [Step 6: Post-Theft Activity and Lateral Resource Access](#step-6-post-theft-activity-and-lateral-resource-access)
   - [Step 7: Organization-Wide Token Theft Sweep](#step-7-organization-wide-token-theft-sweep)
   - [Step 8: UEBA Enrichment — Behavioral Context Analysis](#step-8-ueba-enrichment--behavioral-context-analysis)
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
This detection fires when a user's authenticated session token appears from a different IP address, device, or geographic location than where the original authentication occurred. The token was legitimately issued but is now being used by an unauthorized party. Detection sources include:

1. **SigninLogs + AADNonInteractiveUserSignInLogs Session Cross-IP:** The same `SessionId` appearing from multiple distinct IP addresses indicates the session cookie or token was exported from the legitimate user's browser and imported into the attacker's environment.
2. **AADUserRiskEvents `anomalousToken`:** Identity Protection detects tokens with abnormal characteristics — unusual lifetime, unexpected IP/UserAgent/application combination, or suspicious token renewal patterns.
3. **AADUserRiskEvents `attemptedPRTAccess`:** Defender for Endpoint detects an attempt to extract the Primary Refresh Token from the device's TPM or `BrowserCore.exe`.
4. **CloudAppEvents anomaly signals:** Defender for Cloud Apps detects `UncommonForUser` activity patterns from unusual ISPs/locations after token-based authentication.

**How tokens get stolen — the four vectors:**

| Vector | Mechanism | Prevalence | Related Runbook |
|---|---|---|---|
| **AiTM Phishing** | Reverse proxy (Evilginx, Modlishka) captures session cookie during legitimate MFA authentication | Very High | [RB-0014](aitm-phishing-detection.md) |
| **Infostealer Malware** | Lumma, RedLine, Raccoon steal browser cookies from disk (`%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies`) | Very High | This runbook |
| **PRT Extraction** | Mimikatz `cloudap` plugin or `BrowserCore.exe` exploitation extracts the Primary Refresh Token from device TPM/memory | Medium | This runbook (Step 4) |
| **Browser Extension / XSS** | Malicious extension or cross-site scripting exports `document.cookie` containing session tokens | Low-Medium | This runbook |

**Why this is CRITICAL severity:**
- Token theft **completely bypasses MFA** — the attacker presents a legitimately issued, fully authenticated token
- Unlike credential theft, there is no failed authentication attempt — the token is valid from the moment it's stolen
- Attackers gain the same access level as the victim, including access to email, SharePoint, Teams, and all OAuth-consented apps
- Token theft enables immediate **Business Email Compromise (BEC)** — reading email, setting forwarding rules, sending phishing from the victim's mailbox
- PRT theft is particularly dangerous because the PRT provides SSO across ALL Azure AD-integrated resources

**Relationship to RB-0014 (AiTM Phishing):**
RB-0014 focuses on detecting the **phishing delivery and AiTM proxy infrastructure**. This runbook (RB-0021) focuses on detecting the **stolen token being used**, regardless of how it was stolen. Use RB-0014 when you suspect a phishing campaign; use this runbook when you detect anomalous token behavior from any source.

---

## 2. Prerequisites

{{ data_check_timeline(page.meta.data_checks) }}

---

## 3. Input Parameters

Set these values before running the investigation queries:

```kql
// === INVESTIGATION PARAMETERS ===
let TargetUser = "user@company.com";             // Compromised user's UPN
let AlertTime = datetime(2026-02-22T14:30:00Z);  // Time of token anomaly detection
let LookbackWindow = 24h;                        // Initial analysis window
let BaselineWindow = 14d;                        // Historical baseline period
// Known hosting/VPS ASNs (attacker infrastructure indicators)
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
```

---

## 4. Quick Triage Criteria

Use this decision matrix for initial severity assessment:

| Indicator | True Positive Signal | False Positive Signal |
|---|---|---|
| Session IP change | Session moves to hosting/VPS IP in different country | VPN gateway change, mobile network handoff |
| Device fingerprint | Different OS/browser for same session | Browser auto-update changing user agent |
| Token risk event | `anomalousToken` or `attemptedPRTAccess` in AADUserRiskEvents | `aiConfirmedSigninSafe` in RiskDetail |
| Post-token activity | Inbox rule creation, email forwarding, file download burst | Normal email/file access patterns |
| CAE status | Token NOT CAE-capable (easier to abuse) | CAE-enforced token with IP binding |
| Time pattern | Activity during victim's off-hours | Activity during normal business hours from expected location |

---

## 5. Investigation Steps

### Step 1: Stolen Token Detection via Session Cross-IP Analysis

**Objective:** Identify sessions where the same `SessionId` appears from multiple distinct IP addresses — the definitive indicator that a session token was exported from the legitimate user's device and imported into the attacker's environment.

```kql
// Step 1: Stolen Token Detection via Session Cross-IP Analysis
// Table: SigninLogs + AADNonInteractiveUserSignInLogs | Detects same session from different IPs
let TargetUser = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// Combine interactive and non-interactive sign-ins
let AllSignIns = union
    (SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ TargetUser
    | where ResultType == "0"
    | where isnotempty(SessionId)
    | extend SignInType = "Interactive"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ TargetUser
    | where ResultType == "0"
    | where isnotempty(SessionId)
    | extend SignInType = "NonInteractive");
// Find sessions used from multiple IPs
let MultiIPSessions = AllSignIns
    | summarize DistinctIPs = dcount(IPAddress) by SessionId
    | where DistinctIPs > 1;
AllSignIns
| where SessionId in ((MultiIPSessions | project SessionId))
| extend
    ParsedLocation = parse_json(LocationDetails),
    ParsedDevice = parse_json(DeviceDetail)
| extend
    Country = tostring(ParsedLocation.countryOrRegion),
    City = tostring(ParsedLocation.city),
    DeviceOS = tostring(ParsedDevice.operatingSystem),
    Browser = tostring(ParsedDevice.browser),
    DeviceTrust = tostring(ParsedDevice.trustType),
    IsManaged = tostring(ParsedDevice.isManaged),
    IsCompliant = tostring(ParsedDevice.isCompliant)
| summarize
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 10),
    Countries = make_set(Country, 10),
    Cities = make_set(City, 10),
    UserAgents = make_set(UserAgent, 10),
    Browsers = make_set(Browser, 10),
    DeviceOSes = make_set(DeviceOS, 10),
    SignInTypes = make_set(SignInType),
    Resources = make_set(ResourceDisplayName, 20),
    Apps = make_set(AppDisplayName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    EventCount = count()
    by SessionId, UserPrincipalName
| extend
    SessionDuration = datetime_diff('minute', LastSeen, FirstSeen),
    CrossCountry = array_length(Countries) > 1,
    CrossDevice = array_length(DeviceOSes) > 1,
    HijackVerdict = case(
        array_length(Countries) > 1 and array_length(DeviceOSes) > 1,
            "CRITICAL - Cross-country + cross-device session hijack",
        array_length(Countries) > 1,
            "HIGH - Cross-country session IP divergence",
        array_length(DeviceOSes) > 1,
            "HIGH - Cross-device session (different OS)",
        DistinctIPs > 3,
            "MEDIUM - Session from many IPs (proxy chain or VPN)",
        "LOW - Minor IP variation (likely VPN/mobile handoff)"
    )
| sort by case(
    HijackVerdict has "CRITICAL", 1,
    HijackVerdict has "HIGH", 2,
    HijackVerdict has "MEDIUM", 3,
    4
) asc
```

**What to look for:**

- **"CRITICAL - Cross-country + cross-device session hijack"** = Same session from different countries AND different operating systems — near-certain token theft
- **CrossCountry = true** = Session appears in a country the user has never been — stolen token exported to attacker's location
- **CrossDevice = true** = Session jumps from Windows to Linux/Mac — attacker imported the cookie into a different browser environment
- **DistinctIPs > 3** = Session bouncing across many IPs — attacker using proxy chain or multiple infrastructure nodes
- **Resources containing "Office 365 Exchange Online"** + **"Microsoft Teams"** = Post-theft BEC activity (reading email, exfiltrating data)
- **"LOW - Minor IP variation"** = Likely VPN gateway change or mobile network handoff — common false positive

---

### Step 2: Risk Event Correlation — Token Anomaly Signals

**Objective:** Correlate Identity Protection risk events specifically related to token theft (`anomalousToken`, `attackerinTheMiddle`, `attemptedPRTAccess`, `tokenIssuerAnomaly`) with sign-in context to understand the full attack timeline.

```kql
// Step 2: Risk Event Correlation — Token Anomaly Signals
// Table: AADUserRiskEvents + SigninLogs | Correlates token-related risk events with sign-ins
let TargetUser = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 7d;
// Token-theft-related risk event types
let TokenRiskTypes = dynamic([
    "anomalousToken", "attackerinTheMiddle", "attemptedPRTAccess",
    "tokenIssuerAnomaly", "unfamiliarFeatures", "unlikelyTravel"
]);
let TokenRiskEvents = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
    | where UserPrincipalName =~ TargetUser
    | where RiskEventType in (TokenRiskTypes)
    | project
        RiskTime = TimeGenerated,
        RiskEventType,
        RiskLevel,
        RiskState,
        RiskDetail,
        DetectionTimingType,
        RiskIP = IpAddress,
        RiskLocation = Location,
        CorrelationId,
        RequestId,
        Source;
// Correlate with sign-in context
TokenRiskEvents
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
    | where UserPrincipalName =~ TargetUser
    | extend
        ParsedLocation = parse_json(LocationDetails),
        ParsedDevice = parse_json(DeviceDetail)
    | project
        SignInTime = TimeGenerated,
        CorrelationId,
        SignInIP = IPAddress,
        AppDisplayName,
        ResourceDisplayName,
        Country = tostring(ParsedLocation.countryOrRegion),
        City = tostring(ParsedLocation.city),
        UserAgent,
        DeviceOS = tostring(ParsedDevice.operatingSystem),
        Browser = tostring(ParsedDevice.browser),
        ConditionalAccessStatus,
        AuthenticationRequirement,
        RiskLevelDuringSignIn,
        SessionId,
        IsInteractive
) on CorrelationId
| extend
    ThreatLevel = case(
        RiskEventType == "attemptedPRTAccess",
            "CRITICAL - PRT extraction attempt detected by MDE",
        RiskEventType == "attackerinTheMiddle" and RiskLevel in ("high", "medium"),
            "CRITICAL - AiTM proxy detected (see also RB-0014)",
        RiskEventType == "anomalousToken" and RiskLevel == "high",
            "CRITICAL - High-confidence anomalous token",
        RiskEventType == "anomalousToken" and RiskLevel == "medium",
            "HIGH - Moderate-confidence anomalous token",
        RiskEventType == "tokenIssuerAnomaly",
            "HIGH - Token issuer anomaly (potential SAML manipulation)",
        RiskEventType == "unfamiliarFeatures" and RiskLevel in ("high", "medium"),
            "MEDIUM - Unfamiliar sign-in features (correlate with other signals)",
        "LOW - Risk event present but low confidence"
    ),
    AutoRemediated = RiskDetail has_any ("aiConfirmedSigninSafe", "adminDismissedAllRiskForUser")
| project
    RiskTime,
    RiskEventType,
    RiskLevel,
    ThreatLevel,
    DetectionTimingType,
    RiskIP,
    SignInIP,
    Country,
    City,
    AppDisplayName,
    UserAgent,
    DeviceOS,
    SessionId,
    AutoRemediated,
    ConditionalAccessStatus,
    RiskState
| sort by RiskTime desc
```

**What to look for:**

- **`attemptedPRTAccess`** = Defender for Endpoint detected PRT extraction on the user's device — the device itself is compromised (malware, physical access). Proceed immediately to Step 4.
- **`anomalousToken` with RiskLevel = "high"** = Identity Protection has high confidence the token has abnormal characteristics. Correlate the `RiskIP` with Step 1 findings.
- **`attackerinTheMiddle`** = AiTM proxy detected — cross-reference with [RB-0014](aitm-phishing-detection.md) for phishing campaign analysis.
- **`tokenIssuerAnomaly`** = SAML token issuer has unusual characteristics — potential federation trust manipulation (see [RB-0014](aitm-phishing-detection.md) or Golden SAML scenario).
- **DetectionTimingType = "offline"** = Risk was detected retroactively — the token may have already been used for hours before detection.
- **AutoRemediated = true** = AI confirmed the sign-in as safe or admin dismissed the risk — verify this was a correct decision.

---

### Step 3: Token Forensics — Protection Status and CAE Analysis

**Objective:** Examine the token-level properties of the compromised session to determine if token protection was enforced, whether CAE (Continuous Access Evaluation) could have prevented replay, and identify the specific token characteristics that indicate theft.

```kql
// Step 3: Token Forensics — Protection Status and CAE Analysis
// Table: SigninLogs + AADNonInteractiveUserSignInLogs | Token-level forensic analysis
let TargetUser = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
union
    (SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ TargetUser
    | where ResultType == "0"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ TargetUser
    | where ResultType == "0")
| extend
    ParsedDevice = parse_json(DeviceDetail),
    ParsedLocation = parse_json(LocationDetails),
    ParsedAuthDetails = todynamic(AuthenticationProcessingDetails)
// Extract token forensic fields
| mv-apply detail = ParsedAuthDetails on (
    summarize
        IsCAEToken = take_anyif(tostring(detail.value), tostring(detail.key) == "Is CAE Token"),
        IsClientCapable = take_anyif(tostring(detail.value), tostring(detail.key) == "Is Client Capable"),
        RootKeyType = take_anyif(tostring(detail.value), tostring(detail.key) == "Root Key Type"),
        LegacyTLS = take_anyif(tostring(detail.value), tostring(detail.key) == "Legacy TLS (TLS 1.0, 1.1, 3DES)")
)
| project
    TimeGenerated,
    SessionId,
    UniqueTokenIdentifier,
    IPAddress,
    AutonomousSystemNumber,
    Country = tostring(ParsedLocation.countryOrRegion),
    City = tostring(ParsedLocation.city),
    UserAgent,
    DeviceOS = tostring(ParsedDevice.operatingSystem),
    Browser = tostring(ParsedDevice.browser),
    DeviceTrust = tostring(ParsedDevice.trustType),
    IsManaged = tostring(ParsedDevice.isManaged),
    IsCompliant = tostring(ParsedDevice.isCompliant),
    AppDisplayName,
    ResourceDisplayName,
    IncomingTokenType,
    TokenProtectionStatus = tostring(TokenIssuerType),
    IsCAEToken = coalesce(IsCAEToken, "Unknown"),
    IsClientCapable = coalesce(IsClientCapable, "Unknown"),
    RootKeyType = coalesce(RootKeyType, "Unknown"),
    LegacyTLS = coalesce(LegacyTLS, "Unknown"),
    AuthenticationRequirement,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn
| extend
    IsHostingIP = AutonomousSystemNumber in (HostingASNs),
    DeviceBound = iff(RootKeyType == "TPM", true, false),
    TokenRiskSignals = pack_array(
        iff(IsHostingIP, "HostingIP", ""),
        iff(IsCAEToken == "False", "NoCAE", ""),
        iff(DeviceBound == false, "NotDeviceBound", ""),
        iff(LegacyTLS == "True", "LegacyTLS", ""),
        iff(IsManaged != "true" and IsCompliant != "true", "UnmanagedDevice", ""),
        iff(AuthenticationRequirement == "singleFactorAuthentication", "NoMFARequired", "")
    ),
    SecurityPosture = case(
        RootKeyType == "TPM" and IsCAEToken == "True",
            "STRONG - TPM-bound token with CAE (theft very difficult)",
        IsCAEToken == "True",
            "MODERATE - CAE enabled (token revocable but not device-bound)",
        RootKeyType == "TPM",
            "MODERATE - Device-bound but no CAE (replay limited to same device)",
        "WEAK - Token not device-bound, no CAE (easily replayable)"
    )
| sort by TimeGenerated asc
```

**What to look for:**

- **SecurityPosture = "WEAK"** = Token is neither device-bound nor CAE-protected — can be freely exported and replayed from any device. This is the most exploitable configuration.
- **IsHostingIP = true** + **IsManaged = false** = Token used from a hosting provider on an unmanaged device — strong indicator of attacker infrastructure
- **LegacyTLS = "True"** = Client using TLS 1.0/1.1 — legacy protocol usage from a modern environment is suspicious
- **RootKeyType = "Software"** vs **"TPM"** = Software-based keys can be exported; TPM-bound keys are resistant to extraction
- **IncomingTokenType = "primaryRefreshToken"** from unmanaged device = PRT was extracted and replayed — proceed to Step 4
- **AuthenticationRequirement = "singleFactorAuthentication"** = MFA was not enforced for this resource — lower bar for attacker

---

### Step 4: PRT Abuse Detection — Primary Refresh Token Indicators

**Objective:** Specifically detect Primary Refresh Token extraction and replay. The PRT is the "master token" that provides SSO across all Azure AD-integrated applications. PRT theft grants access to EVERY resource the user can access — email, files, Teams, Azure portal — without any additional authentication.

```kql
// Step 4: PRT Abuse Detection — Primary Refresh Token Indicators
// Table: AADUserRiskEvents + SigninLogs | Detects PRT extraction and anomalous renewal
let TargetUser = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 7d;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// Check for PRT-related risk events
let PRTRiskEvents = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
    | where UserPrincipalName =~ TargetUser
    | where RiskEventType in ("attemptedPRTAccess", "anomalousToken")
    | project
        RiskTime = TimeGenerated,
        RiskEventType,
        RiskLevel,
        RiskDetail,
        DetectionTimingType,
        RiskIP = IpAddress,
        CorrelationId,
        Source,
        AdditionalInfo;
// Detect PRT-based sign-ins with anomalous patterns
let PRTSignIns = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
    | where UserPrincipalName =~ TargetUser
    | where ResultType == "0"
    | extend
        ParsedDevice = parse_json(DeviceDetail),
        ParsedLocation = parse_json(LocationDetails),
        ParsedAuthDetails = todynamic(AuthenticationProcessingDetails)
    | mv-apply detail = ParsedAuthDetails on (
        summarize
            RootKeyType = take_anyif(tostring(detail.value), tostring(detail.key) == "Root Key Type")
    )
    | extend
        DeviceOS = tostring(ParsedDevice.operatingSystem),
        DeviceTrust = tostring(ParsedDevice.trustType),
        IsManaged = tostring(ParsedDevice.isManaged),
        Country = tostring(ParsedLocation.countryOrRegion),
        City = tostring(ParsedLocation.city)
    | where
        // PRT indicators: device-authenticated sign-in patterns
        AuthenticationRequirement == "singleFactorAuthentication"
        or IncomingTokenType has "primaryRefreshToken"
        or RootKeyType == "TPM"
    | project
        TimeGenerated,
        IPAddress,
        AutonomousSystemNumber,
        Country,
        City,
        UserAgent,
        DeviceOS,
        DeviceTrust,
        IsManaged,
        AppDisplayName,
        ResourceDisplayName,
        IncomingTokenType,
        AuthenticationRequirement,
        SessionId,
        RootKeyType = coalesce(RootKeyType, "Unknown"),
        CorrelationId;
// Combine risk events with PRT sign-in context
let PRTAnalysis = PRTSignIns
    | summarize
        DistinctIPs = dcount(IPAddress),
        IPs = make_set(IPAddress, 10),
        Countries = make_set(Country, 10),
        DeviceOSes = make_set(DeviceOS, 10),
        DeviceTrusts = make_set(DeviceTrust, 10),
        Apps = make_set(AppDisplayName, 20),
        SignInCount = count(),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by UserPrincipalName;
PRTAnalysis
| extend
    PRTAbuseIndicators = pack_array(
        iff(array_length(Countries) > 1, "MultiCountryPRT", ""),
        iff(array_length(DeviceOSes) > 1, "MultiDevicePRT", ""),
        iff(set_has_element(DeviceTrusts, ""), "UntrustedDevicePRT", ""),
        iff(DistinctIPs > 3, "ManyIPsPRT", "")
    ),
    PRTVerdict = case(
        array_length(Countries) > 1 and array_length(DeviceOSes) > 1,
            "CRITICAL - PRT used across countries and different devices",
        array_length(Countries) > 1,
            "HIGH - PRT used from multiple countries",
        array_length(DeviceOSes) > 1,
            "HIGH - PRT used from different device types",
        DistinctIPs > 3 and set_has_element(DeviceTrusts, ""),
            "MEDIUM - PRT from many IPs including untrusted devices",
        "LOW - PRT usage within expected parameters"
    )
| join kind=leftouter (
    PRTRiskEvents
    | summarize
        RiskEvents = make_set(RiskEventType),
        MaxRiskLevel = max(case(RiskLevel == "high", 3, RiskLevel == "medium", 2, 1))
) on $left.UserPrincipalName == $left.UserPrincipalName
| project
    UserPrincipalName,
    PRTVerdict,
    DistinctIPs,
    IPs,
    Countries,
    DeviceOSes,
    Apps,
    SignInCount,
    FirstSeen,
    LastSeen,
    RiskEvents = coalesce(RiskEvents, dynamic([]))
```

**What to look for:**

- **"CRITICAL - PRT used across countries and different devices"** = PRT has been extracted and is being replayed from attacker infrastructure on a different device — confirmed compromise
- **RiskEvents containing "attemptedPRTAccess"** = MDE detected PRT extraction on the user's endpoint — the device is compromised by malware
- **UntrustedDevicePRT** = PRT being used from a device that is NOT Azure AD joined/registered — PRT should only exist on enrolled devices
- **MultiDevicePRT** = PRT appearing on a different OS type (e.g., Windows PRT on a Linux machine) — PRT was extracted and replayed
- **"LOW"** with no risk events = PRT usage is consistent with the registered device — likely legitimate SSO behavior

---

### Step 5: Baseline Comparison — Establish Normal Session Pattern

**Objective:** Compare the user's current session and token usage patterns against their 14-day historical baseline to determine if the activity is truly anomalous. A user who regularly uses VPN from multiple countries will have a different baseline than one who always connects from the office.

```kql
// Step 5: Baseline Comparison — Establish Normal Session Pattern
// Table: SigninLogs + AADNonInteractiveUserSignInLogs | Historical session baseline
let TargetUser = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let BaselineWindow = 14d;
let CurrentWindow = 24h;
// Historical baseline (14 days before current window)
let HistoricalBaseline = union
    (SigninLogs
    | where TimeGenerated between ((AlertTime - BaselineWindow) .. (AlertTime - CurrentWindow))
    | where UserPrincipalName =~ TargetUser
    | where ResultType == "0"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - BaselineWindow) .. (AlertTime - CurrentWindow))
    | where UserPrincipalName =~ TargetUser
    | where ResultType == "0")
| extend
    ParsedLocation = parse_json(LocationDetails),
    ParsedDevice = parse_json(DeviceDetail)
| summarize
    BaselineIPs = make_set(IPAddress, 50),
    BaselineCountries = make_set(tostring(ParsedLocation.countryOrRegion), 20),
    BaselineCities = make_set(tostring(ParsedLocation.city), 30),
    BaselineDeviceOSes = make_set(tostring(ParsedDevice.operatingSystem), 10),
    BaselineBrowsers = make_set(tostring(ParsedDevice.browser), 10),
    BaselineApps = make_set(AppDisplayName, 30),
    BaselineResources = make_set(ResourceDisplayName, 30),
    BaselineASNs = make_set(AutonomousSystemNumber, 30),
    BaselineSessionCount = dcount(SessionId),
    BaselineIPCount = dcount(IPAddress),
    BaselineAvgDailySessions = round(toreal(dcount(SessionId)) / 14.0, 1);
// Current window activity
let CurrentActivity = union
    (SigninLogs
    | where TimeGenerated between ((AlertTime - CurrentWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ TargetUser
    | where ResultType == "0"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - CurrentWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ TargetUser
    | where ResultType == "0")
| extend
    ParsedLocation = parse_json(LocationDetails),
    ParsedDevice = parse_json(DeviceDetail)
| summarize
    CurrentIPs = make_set(IPAddress, 50),
    CurrentCountries = make_set(tostring(ParsedLocation.countryOrRegion), 20),
    CurrentCities = make_set(tostring(ParsedLocation.city), 30),
    CurrentDeviceOSes = make_set(tostring(ParsedDevice.operatingSystem), 10),
    CurrentBrowsers = make_set(tostring(ParsedDevice.browser), 10),
    CurrentApps = make_set(AppDisplayName, 30),
    CurrentResources = make_set(ResourceDisplayName, 30),
    CurrentASNs = make_set(AutonomousSystemNumber, 30),
    CurrentSessionCount = dcount(SessionId),
    CurrentIPCount = dcount(IPAddress);
// Compare
HistoricalBaseline
| extend p = 1
| join kind=fullouter (CurrentActivity | extend p = 1) on p
| project-away p, p1
| extend
    // Detect new entities not in baseline
    NewCountries = set_difference(CurrentCountries, BaselineCountries),
    NewDeviceOSes = set_difference(CurrentDeviceOSes, BaselineDeviceOSes),
    NewBrowsers = set_difference(CurrentBrowsers, BaselineBrowsers),
    NewASNs = set_difference(CurrentASNs, BaselineASNs),
    NewApps = set_difference(CurrentApps, BaselineApps),
    NewResources = set_difference(CurrentResources, BaselineResources)
| extend
    NewCountryCount = array_length(NewCountries),
    NewDeviceCount = array_length(NewDeviceOSes),
    NewASNCount = array_length(NewASNs),
    NewAppCount = array_length(NewApps),
    NewResourceCount = array_length(NewResources),
    SessionSpike = round(iff(coalesce(BaselineAvgDailySessions, 0) > 0,
        toreal(coalesce(CurrentSessionCount, 0)) / BaselineAvgDailySessions, 999.0), 1),
    AnomalyVerdict = case(
        array_length(set_difference(CurrentCountries, BaselineCountries)) > 0
            and array_length(set_difference(CurrentDeviceOSes, BaselineDeviceOSes)) > 0,
            "HIGH ANOMALY - New country AND new device type (never seen before)",
        array_length(set_difference(CurrentCountries, BaselineCountries)) > 0,
            "HIGH ANOMALY - Session from a country never seen in 14-day baseline",
        array_length(set_difference(CurrentASNs, BaselineASNs)) > 2,
            "MODERATE ANOMALY - Multiple new network providers",
        array_length(set_difference(CurrentDeviceOSes, BaselineDeviceOSes)) > 0,
            "MODERATE ANOMALY - New device/OS type",
        array_length(set_difference(CurrentApps, BaselineApps)) > 3,
            "MODERATE ANOMALY - Accessing many new applications",
        "LOW ANOMALY - Activity within historical range"
    )
| project
    AnomalyVerdict,
    NewCountries,
    NewDeviceOSes,
    NewASNs,
    NewApps,
    NewResources,
    SessionSpike,
    BaselineAvgDailySessions,
    CurrentSessionCount,
    BaselineCountries,
    BaselineDeviceOSes,
    BaselineIPCount,
    CurrentIPCount
```

**What to look for:**

- **"HIGH ANOMALY - New country AND new device type"** = Two major "firsts" simultaneously — very high confidence of token theft
- **NewCountries not empty** = Session appeared from a country the user has never authenticated from in 14 days
- **NewASNs containing hosting ASNs** = Token used from cloud/VPS infrastructure the user never used before
- **SessionSpike > 5** = 5x more sessions than the user's daily average — potential automated token abuse
- **NewResources not empty** = Attacker accessing resources the user doesn't normally use — reconnaissance with the stolen token
- **"LOW ANOMALY"** = Activity fits the user's normal pattern — likely legitimate VPN change or travel

---

### Step 6: Post-Theft Activity and Lateral Resource Access

**Objective:** Identify what the attacker did with the stolen token — email access, inbox rule creation, file exfiltration, OAuth app consent, MFA manipulation, and access to new resources. This step reveals the attacker's objectives and the blast radius of the compromise.

```kql
// Step 6A: Post-Theft Persistence and Email Compromise
// Table: AuditLogs + OfficeActivity | Detects attacker actions after token theft
let TargetUser = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let PostTheftWindow = 48h;
// Dangerous post-theft audit operations
let PostTheftAudit = AuditLogs
    | where TimeGenerated between (AlertTime .. (AlertTime + PostTheftWindow))
    | where InitiatedBy has TargetUser
    | where OperationName in (
        // MFA persistence
        "User registered security info",
        "User registered all required security info",
        "User deleted security info",
        "User changed default security info",
        // Email compromise
        "Set-Mailbox", "New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
        "Set inbox rule", "Update inbox rule",
        // OAuth app abuse
        "Consent to application", "Add OAuth2PermissionGrant",
        "Add delegated permission grant",
        // Account persistence
        "Update user", "Reset password", "Change user password",
        "Add member to role", "Add eligible member to role",
        // Device registration
        "Register device", "Add registered owner to device"
    )
    | extend
        ParsedTargets = parse_json(TargetResources),
        InitiatedByIP = tostring(parse_json(InitiatedBy).user.ipAddress)
    | project
        TimeGenerated,
        ActionCategory = case(
            OperationName has_any ("security info"), "MFA_MANIPULATION",
            OperationName has_any ("InboxRule", "inbox rule", "Mailbox", "Set-Mailbox"),
                "EMAIL_COMPROMISE",
            OperationName has_any ("Consent", "OAuth", "permission"),
                "OAUTH_ABUSE",
            OperationName has_any ("password", "Password"), "CREDENTIAL_CHANGE",
            OperationName has_any ("role", "Role"), "PRIVILEGE_ESCALATION",
            OperationName has_any ("device", "Device"), "DEVICE_REGISTRATION",
            "OTHER"
        ),
        OperationName,
        TargetResource = tostring(ParsedTargets[0].displayName),
        InitiatedByIP,
        Result,
        HoursAfterTheft = round(datetime_diff('minute', TimeGenerated, AlertTime) / 60.0, 1);
// Post-theft email/file activity
let PostTheftOffice = OfficeActivity
    | where TimeGenerated between (AlertTime .. (AlertTime + PostTheftWindow))
    | where UserId =~ TargetUser
    | where Operation in (
        // Email operations
        "MailItemsAccessed", "Send", "SendAs", "SendOnBehalf",
        "New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
        "Set-Mailbox",
        // File operations
        "FileDownloaded", "FileAccessed", "FileSyncDownloadedFull",
        "FileModified", "FileCopied"
    )
    | project
        TimeGenerated,
        ActionCategory = case(
            Operation in ("MailItemsAccessed", "Send", "SendAs", "SendOnBehalf"),
                "EMAIL_ACCESS",
            Operation has_any ("InboxRule", "Mailbox"),
                "EMAIL_COMPROMISE",
            Operation has_any ("File", "file"),
                "FILE_EXFILTRATION",
            "OTHER"
        ),
        OperationName = Operation,
        TargetResource = coalesce(OfficeObjectId, SourceFileName),
        InitiatedByIP = ClientIP,
        Result = "success",
        HoursAfterTheft = round(datetime_diff('minute', TimeGenerated, AlertTime) / 60.0, 1);
union PostTheftAudit, PostTheftOffice
| extend
    SeverityLevel = case(
        ActionCategory == "MFA_MANIPULATION",
            "CRITICAL - Attacker registering persistence MFA method",
        ActionCategory == "EMAIL_COMPROMISE",
            "CRITICAL - Inbox rule creation (exfiltration/hiding)",
        ActionCategory == "OAUTH_ABUSE",
            "HIGH - OAuth app consent (persistent access)",
        ActionCategory == "PRIVILEGE_ESCALATION",
            "HIGH - Role assignment after token theft",
        ActionCategory == "CREDENTIAL_CHANGE",
            "HIGH - Password change (locking out legitimate user)",
        ActionCategory == "FILE_EXFILTRATION",
            "MEDIUM - File access/download",
        ActionCategory == "EMAIL_ACCESS",
            "MEDIUM - Email access",
        "LOW"
    )
| sort by TimeGenerated asc
```

```kql
// Step 6B: Post-Theft Cloud App Activity (requires Defender for Cloud Apps)
// Table: CloudAppEvents | Detects anomalous app usage after token theft
let TargetUser = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let PostTheftWindow = 48h;
CloudAppEvents
| where Timestamp between (AlertTime .. (AlertTime + PostTheftWindow))
| where AccountDisplayName =~ TargetUser or AccountObjectId =~ TargetUser
| extend
    UncommonActivities = todynamic(UncommonForUser),
    LastSeenData = todynamic(LastSeenForUser)
| where
    // Filter for events with anomaly enrichment
    tostring(UncommonActivities) != "[]"
    or ActionType in (
        "MailItemsAccessed", "New-InboxRule", "Set-Mailbox",
        "Set-InboxRule", "UpdateInboxRules",
        "FileDownloaded", "FileAccessed", "FileSyncDownloadedFull",
        "Add-MailboxPermission", "Add-RecipientPermission"
    )
| project
    Timestamp,
    ActionType,
    IPAddress,
    CountryCode,
    City,
    Isp,
    IsAnonymousProxy,
    UncommonActivities,
    LastSeenData,
    Application,
    UserAgentTags = todynamic(UserAgentTags)
| extend
    IsFirstTimeISP = iff(tostring(LastSeenData.ISP) == "-1", true, false),
    ActivityRisk = case(
        IsAnonymousProxy == true and ActionType has_any ("InboxRule", "Mailbox"),
            "CRITICAL - Email rule from anonymous proxy",
        isnotempty(tostring(UncommonActivities)) and ActionType has_any ("InboxRule", "Mailbox"),
            "CRITICAL - Uncommon email compromise activity",
        IsAnonymousProxy == true,
            "HIGH - Activity from anonymous proxy",
        isnotempty(tostring(UncommonActivities)),
            "MEDIUM - Uncommon activity pattern",
        "LOW"
    )
| where ActivityRisk != "LOW"
| sort by Timestamp asc
```

**What to look for:**

- **MFA_MANIPULATION within hours of theft** = Attacker registering their own MFA method for persistent access — immediate containment required
- **EMAIL_COMPROMISE** = Inbox forwarding rule or inbox rule created — attacker is either exfiltrating email or hiding traces
- **OAUTH_ABUSE** = Attacker granting consent to a malicious app using the stolen token — persistent access even after token revocation
- **FILE_EXFILTRATION** with high volume = Bulk file download — data breach in progress
- **IsAnonymousProxy = true** with email operations = BEC attack from anonymizing infrastructure
- **HoursAfterTheft < 1** = Rapid automated exploitation — attacker has playbook for post-compromise actions

---

### Step 7: Organization-Wide Token Theft Sweep

**Objective:** Sweep the entire organization for users showing token theft indicators — same-session cross-IP anomalies and anomalous token risk events. Token theft campaigns often target multiple users simultaneously (phishing campaigns, infostealer distribution).

```kql
// Step 7: Organization-Wide Token Theft Sweep
// Table: AADUserRiskEvents + SigninLogs | Finds all users with token theft indicators
let AlertTime = datetime(2026-02-22T14:30:00Z);
let SweepWindow = 7d;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// Users with token-related risk events
let TokenRiskUsers = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - SweepWindow) .. AlertTime)
    | where RiskEventType in ("anomalousToken", "attackerinTheMiddle",
        "attemptedPRTAccess", "tokenIssuerAnomaly")
    | summarize
        RiskEvents = make_set(RiskEventType),
        RiskCount = count(),
        MaxRiskLevel = max(case(RiskLevel == "high", 3, RiskLevel == "medium", 2, 1)),
        RiskIPs = make_set(IpAddress, 10),
        FirstRisk = min(TimeGenerated),
        LastRisk = max(TimeGenerated)
        by UserPrincipalName;
// Detect sessions with cross-IP anomalies (potential stolen tokens org-wide)
let CrossIPSessions = union
    (SigninLogs
    | where TimeGenerated between ((AlertTime - SweepWindow) .. AlertTime)
    | where ResultType == "0"
    | where isnotempty(SessionId)),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - SweepWindow) .. AlertTime)
    | where ResultType == "0"
    | where isnotempty(SessionId))
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| summarize
    DistinctIPs = dcount(IPAddress),
    DistinctCountries = dcount(Country),
    Countries = make_set(Country, 10),
    IPs = make_set(IPAddress, 10),
    HasHostingIP = countif(AutonomousSystemNumber in (HostingASNs))
    by SessionId, UserPrincipalName
| where DistinctCountries > 1 or (DistinctIPs > 2 and HasHostingIP > 0);
// Combine risk events and cross-IP sessions
let SuspiciousUsers = union
    (TokenRiskUsers | project UserPrincipalName),
    (CrossIPSessions | project UserPrincipalName)
| distinct UserPrincipalName;
// Build comprehensive risk summary per user
TokenRiskUsers
| join kind=fullouter (
    CrossIPSessions
    | summarize
        SuspiciousSessions = count(),
        AffectedCountries = make_set(Countries),
        SessionIPs = make_set(IPs)
        by UserPrincipalName
) on UserPrincipalName
| extend UserPrincipalName = coalesce(UserPrincipalName, UserPrincipalName1)
| extend
    OverallRisk = case(
        isnotempty(RiskEvents) and set_has_element(RiskEvents, "attemptedPRTAccess"),
            "CRITICAL - PRT extraction detected",
        isnotempty(RiskEvents) and set_has_element(RiskEvents, "attackerinTheMiddle"),
            "CRITICAL - AiTM attack confirmed",
        MaxRiskLevel >= 3 and coalesce(SuspiciousSessions, 0) > 0,
            "CRITICAL - High-risk token event + suspicious sessions",
        isnotempty(RiskEvents) and MaxRiskLevel >= 2,
            "HIGH - Moderate-risk token anomaly",
        coalesce(SuspiciousSessions, 0) > 0,
            "HIGH - Cross-country/hosting-IP session detected",
        "MEDIUM - Token anomaly signals present"
    )
| project
    UserPrincipalName,
    OverallRisk,
    RiskEvents = coalesce(RiskEvents, dynamic([])),
    RiskCount = coalesce(RiskCount, 0),
    SuspiciousSessions = coalesce(SuspiciousSessions, 0),
    RiskIPs = coalesce(RiskIPs, dynamic([])),
    AffectedCountries = coalesce(AffectedCountries, dynamic([])),
    FirstRisk = coalesce(FirstRisk, datetime(null)),
    LastRisk = coalesce(LastRisk, datetime(null))
| sort by case(
    OverallRisk has "CRITICAL", 1,
    OverallRisk has "HIGH", 2,
    3
) asc, RiskCount desc
```

**What to look for:**

- **Multiple "CRITICAL" users in the same time window** = Active token theft campaign — likely phishing wave or widespread infostealer infection
- **Same RiskIPs across multiple users** = Attacker reusing infrastructure across multiple stolen tokens
- **`attemptedPRTAccess` on multiple devices** = Infostealer malware spreading across the organization
- **`attackerinTheMiddle` cluster** = Active AiTM phishing campaign — cross-reference with [RB-0014](aitm-phishing-detection.md)
- **AffectedCountries containing the same unusual country** = Attacker infrastructure concentrated in one region
- **SuspiciousSessions > 0 without RiskEvents** = Cross-IP session anomaly but no Identity Protection risk event — may be a false positive (VPN) or a detection gap

---

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Microsoft Sentinel's UEBA engine to assess whether the user's session behavior deviates from their historical pattern. UEBA's `ActivityInsights` fields reveal if the user suddenly accessed new applications, performed unusual actions, or connected from unprecedented locations — critical context for distinguishing a stolen token from a legitimate user on VPN or traveling.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If UEBA is not configured in your environment, skip this step. The investigation remains valid without UEBA, but behavioral context significantly improves confidence in True/False Positive determination.

#### Query 8A: Token Theft Victim — Comprehensive UEBA Assessment

```kql
// Step 8A: UEBA Behavioral Assessment for Token Theft Victim
// Table: BehaviorAnalytics | Checks behavioral anomalies during theft window
let AlertTime = datetime(2026-02-22T14:30:00Z);
let TargetUser = "user@company.com";
let LookbackWindow = 7d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
| where UserPrincipalName =~ TargetUser
| project
    TimeGenerated,
    UserPrincipalName,
    ActivityType,
    ActionType,
    InvestigationPriority,
    SourceIPAddress,
    SourceIPLocation,
    ActivityInsights = parse_json(ActivityInsights),
    UsersInsights = parse_json(UsersInsights),
    DevicesInsights = parse_json(DevicesInsights)
| extend
    // App and action anomalies (primary indicators for token theft)
    FirstTimeAppUsed = tostring(ActivityInsights.FirstTimeUserUsedApp),
    AppUncommonlyUsed = tostring(ActivityInsights.AppUncommonlyUsedByUser),
    AppUncommonAmongPeers = tostring(ActivityInsights.AppUncommonlyUsedAmongPeers),
    FirstTimeActionPerformed = tostring(ActivityInsights.FirstTimeUserPerformedAction),
    ActionUncommonlyPerformed = tostring(ActivityInsights.ActionUncommonlyPerformedByUser),
    // Location anomalies (strong token theft signal)
    FirstTimeCountry = tostring(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommon = tostring(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    CountryUncommonAmongPeers = tostring(ActivityInsights.CountryUncommonlyConnectedFromAmongPeers),
    FirstTimeISP = tostring(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommon = tostring(ActivityInsights.ISPUncommonlyUsedByUser),
    ISPUncommonAmongPeers = tostring(ActivityInsights.ISPUncommonlyUsedAmongPeers),
    // Device anomalies
    FirstTimeDevice = tostring(ActivityInsights.FirstTimeUserUsedDevice),
    DeviceUncommon = tostring(ActivityInsights.DeviceUncommonlyUsedByUser),
    FirstTimeBrowser = tostring(ActivityInsights.FirstTimeUserUsedBrowser),
    BrowserUncommon = tostring(ActivityInsights.BrowserUncommonlyUsedByUser),
    // Volume anomalies
    UncommonHighVolume = tostring(ActivityInsights.UncommonHighVolumeOfActions),
    // Resource access anomalies
    FirstTimeResource = tostring(ActivityInsights.FirstTimeUserAccessedResource),
    ResourceUncommon = tostring(ActivityInsights.ResourceUncommonlyAccessedByUser),
    ResourceUncommonAmongPeers = tostring(ActivityInsights.ResourceUncommonlyAccessedAmongPeers),
    // User profile
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tostring(UsersInsights.IsDormantAccount),
    IsNewAccount = tostring(UsersInsights.IsNewAccount),
    // Device threat intelligence
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| extend
    // Count total anomaly signals for severity scoring
    AnomalyCount = toint(FirstTimeAppUsed == "True")
        + toint(AppUncommonlyUsed == "True")
        + toint(FirstTimeActionPerformed == "True")
        + toint(FirstTimeCountry == "True")
        + toint(CountryUncommon == "True")
        + toint(FirstTimeISP == "True")
        + toint(ISPUncommon == "True")
        + toint(FirstTimeDevice == "True")
        + toint(FirstTimeBrowser == "True")
        + toint(UncommonHighVolume == "True")
        + toint(FirstTimeResource == "True")
        + toint(isnotempty(ThreatIndicator)),
    RiskLevel = case(
        InvestigationPriority >= 7, "HIGH",
        InvestigationPriority >= 4, "MEDIUM",
        "LOW"
    )
| order by InvestigationPriority desc, TimeGenerated desc
```

#### Query 8B: UEBA Anomaly Summary with Token Theft Confidence Score

```kql
// Step 8B: UEBA Anomaly Summary — Token Theft Confidence
// Table: BehaviorAnalytics | Aggregated anomaly assessment
let AlertTime = datetime(2026-02-22T14:30:00Z);
let TargetUser = "user@company.com";
let LookbackWindow = 3d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
| where UserPrincipalName =~ TargetUser
| extend
    ActivityInsights = parse_json(ActivityInsights),
    UsersInsights = parse_json(UsersInsights),
    DevicesInsights = parse_json(DevicesInsights)
| summarize
    MaxPriority = max(InvestigationPriority),
    AvgPriority = round(avg(InvestigationPriority), 1),
    HighPriorityEvents = countif(InvestigationPriority >= 7),
    TotalEvents = count(),
    // Token theft specific signals
    NewCountryEvents = countif(tostring(ActivityInsights.FirstTimeUserConnectedFromCountry) == "True"),
    NewISPEvents = countif(tostring(ActivityInsights.FirstTimeUserConnectedViaISP) == "True"),
    NewDeviceEvents = countif(tostring(ActivityInsights.FirstTimeUserUsedDevice) == "True"),
    NewBrowserEvents = countif(tostring(ActivityInsights.FirstTimeUserUsedBrowser) == "True"),
    NewAppEvents = countif(tostring(ActivityInsights.FirstTimeUserUsedApp) == "True"),
    NewResourceEvents = countif(tostring(ActivityInsights.FirstTimeUserAccessedResource) == "True"),
    HighVolumeEvents = countif(tostring(ActivityInsights.UncommonHighVolumeOfActions) == "True"),
    ThreatIndicators = countif(isnotempty(tostring(DevicesInsights.ThreatIntelIndicatorType))),
    BlastRadius = take_any(tostring(UsersInsights.BlastRadius)),
    IsDormant = take_any(tostring(UsersInsights.IsDormantAccount))
    by UserPrincipalName
| extend
    TheftConfidence = case(
        MaxPriority >= 7 and NewCountryEvents > 0 and NewDeviceEvents > 0,
            "VERY HIGH - Multiple first-time signals with high investigation priority",
        MaxPriority >= 7 and (NewCountryEvents > 0 or NewISPEvents > 0),
            "HIGH - High priority with new location indicators",
        NewCountryEvents > 0 and NewDeviceEvents > 0,
            "HIGH - New country + new device (even without high priority)",
        ThreatIndicators > 0,
            "HIGH - Threat intelligence match on device",
        IsDormant == "True" and TotalEvents > 0,
            "HIGH - Dormant account suddenly active",
        MaxPriority >= 4 and HighVolumeEvents > 0,
            "MEDIUM - Moderate priority with unusual volume",
        NewISPEvents > 0 or NewBrowserEvents > 0,
            "MEDIUM - New ISP or browser (could be VPN/update)",
        "LOW - Activity within behavioral norms"
    )
```

**Expected findings:**

| Indicator | Token Theft Signal | Legitimate Signal |
|---|---|---|
| InvestigationPriority >= 7 | Significant behavioral deviation flagged by UEBA | Normal account behavior |
| FirstTimeCountry + FirstTimeISP = True | Token replayed from new country/ISP — attacker infrastructure | User traveling with VPN |
| FirstTimeDevice + FirstTimeBrowser = True | Token imported into attacker's browser environment | User switched browsers legitimately |
| UncommonHighVolume = True | Automated token abuse — attacker scripting bulk access | User performing legitimate bulk operations |
| ThreatIndicator present | Device has known malware indicators — infostealer source | False positive from security tool |
| FirstTimeResource = True | Attacker exploring resources with stolen token | User accessing new work resource |

**Decision guidance:**

- **TheftConfidence = "VERY HIGH"** → Multiple first-time signals at high priority. This is almost certainly a stolen token being used from attacker infrastructure. Revoke all sessions immediately.
- **ThreatIndicator present** → The source device has malware indicators from MDE. This confirms infostealer-based token theft. Isolate the device AND revoke tokens.
- **IsDormant = True** → A dormant account suddenly showing token-based activity is a strong compromise indicator. Dormant accounts don't start new sessions spontaneously.
- **TheftConfidence = "LOW"** → UEBA sees no significant deviation. If Steps 1-2 showed anomalies, this could mean the attacker is operating within the user's normal patterns (sophisticated actor using similar infrastructure).

---

## 6. Containment Playbook

### Immediate Actions (0-15 minutes)
- [ ] **Revoke ALL user sessions** via Entra ID portal or `Revoke-MgUserSignInSession`
- [ ] **Revoke refresh tokens** — forces re-authentication across all devices and applications
- [ ] **Reset user password** — invalidates all existing tokens including PRT
- [ ] **Block suspicious IPs** via Conditional Access Named Locations (use IPs from Step 1)
- [ ] **Disable user account** temporarily if active BEC is confirmed (Step 6)

### Short-term Actions (15 min - 2 hours)
- [ ] **Remove any MFA methods** registered after the theft timestamp (Step 6 — MFA_MANIPULATION)
- [ ] **Delete inbox forwarding rules** created after theft (Step 6 — EMAIL_COMPROMISE)
- [ ] **Revoke OAuth app consents** granted after theft (Step 6 — OAUTH_ABUSE)
- [ ] **Check for sent emails** from the compromised mailbox — recall if phishing was sent
- [ ] **Re-register MFA** with the legitimate user present (out-of-band verification via phone)
- [ ] **If PRT compromise** (Step 4): Isolate the device, run full AV scan, consider device wipe

### Recovery Actions (2-24 hours)
- [ ] Enable **Token Protection** (Conditional Access) to bind tokens to devices for critical users
- [ ] Enforce **Continuous Access Evaluation (CAE)** to enable near-real-time token revocation
- [ ] Implement **Conditional Access: Require compliant device** for sensitive resources
- [ ] Review **session lifetime policies** — reduce maximum session length for high-risk resources
- [ ] If infostealer confirmed: scan all endpoints with the same risk indicators
- [ ] Deploy **Conditional Access: Block legacy authentication** if not already done
- [ ] Implement **Sign-in frequency** policy (e.g., re-auth every 4h for sensitive apps)

---

## 7. Evidence Collection Checklist

| Evidence Item | Source Table | Retention | Collection Query |
|---|---|---|---|
| Session cross-IP anomalies | SigninLogs + AADNonInteractive | 30 days | Step 1 query |
| Token risk events | AADUserRiskEvents | 30 days | Step 2 query |
| Token protection/CAE status | SigninLogs | 30 days | Step 3 query |
| PRT abuse indicators | AADUserRiskEvents + SigninLogs | 30 days | Step 4 query |
| Historical session baseline | SigninLogs + AADNonInteractive | 30 days | Step 5 query |
| Post-theft actions (audit) | AuditLogs + OfficeActivity | 90/180 days | Step 6A query |
| Post-theft cloud app activity | CloudAppEvents | 30 days | Step 6B query |
| Org-wide token theft sweep | AADUserRiskEvents + SigninLogs | 30 days | Step 7 query |
| UEBA behavioral assessment | BehaviorAnalytics | 30 days | Step 8 query |

---

## 8. Escalation Criteria

| Condition | Action |
|---|---|
| Cross-country session + MFA registration after theft (Steps 1, 6) | Escalate to **P1 Incident** — active token theft with persistence |
| `attemptedPRTAccess` risk event (Step 2, 4) | Escalate to **P1 Incident** — device compromised, PRT extracted |
| Multiple users with `anomalousToken` in same window (Step 7) | Escalate to **P1 Incident** — active phishing or infostealer campaign |
| Email forwarding rule + bulk file download after theft (Step 6) | Escalate to **P1 Incident** — active BEC and data exfiltration |
| Single user `anomalousToken` + hosting IP (Steps 2, 3) | Escalate to **P2 Incident** — confirmed token theft, single user |
| Cross-IP session without risk event, new country (Steps 1, 5) | Escalate to **P2 Incident** — investigate as potential token theft |
| Minor IP variation, same country, no post-theft activity | Escalate to **P3** — likely VPN/mobile, monitor for 48h |

---

## 9. False Positive Documentation

| Scenario | How to Identify | Recommended Action |
|---|---|---|
| VPN gateway rotation | Same city/country, IPs from known corporate VPN ranges | Add VPN IP ranges to Named Locations, exclude from detection |
| Mobile network handoff | IPs from same carrier, same city, ~5 min gap | Tune threshold to require different countries |
| User traveling internationally | Expected travel (calendar), sequential country progression | Verify with user, mark as legitimate travel |
| Browser auto-update | Same IP, same session, slightly different UserAgent string | Exclude minor UA version changes from device mismatch logic |
| Split-tunnel VPN | Some traffic via VPN, some direct — same session from 2 IPs | Document user's VPN configuration, tune for same-country split |
| Shared device (kiosk/conference room) | Known shared device IP, multiple users with same SessionId pattern | Exclude shared device IPs, add to device allowlist |

---

## 10. MITRE ATT&CK Mapping

| Technique ID | Technique Name | How It Applies | Detection Query |
|---|---|---|---|
| **T1539** | **Steal Web Session Cookie** | Browser cookies/session tokens stolen via infostealer or AiTM | **Steps 1, 2, 7** |
| **T1550.004** | **Use Alternate Authentication Material: Web Session Cookie** | Stolen session cookie replayed from attacker browser | **Steps 1, 3, 5** |
| **T1528** | **Steal Application Access Token** | OAuth/refresh tokens stolen and replayed for resource access | **Steps 2, 3, 4** |
| T1078.004 | Valid Accounts: Cloud Accounts | Attacker using the legitimate user's valid session | Steps 1, 5, 6 |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | PRT extracted and used for SSO across resources | Steps 3, 4 |
| T1114.002 | Email Collection: Remote Email Collection | Post-theft email access and exfiltration | Step 6 |

---

## 11. Query Summary

| Step | Query | Purpose | Primary Table |
|---|---|---|---|
| 1 | Session Cross-IP Analysis | Detect same session from different IPs | SigninLogs + AADNonInteractive |
| 2 | Risk Event Correlation | Correlate anomalousToken/PRT risk events | AADUserRiskEvents + SigninLogs |
| 3 | Token Forensics | Token protection, CAE, device binding analysis | SigninLogs + AADNonInteractive |
| 4 | PRT Abuse Detection | Primary Refresh Token extraction/replay | AADUserRiskEvents + SigninLogs |
| 5 | Baseline Comparison | Compare against 14-day session history | SigninLogs + AADNonInteractive |
| 6A | Post-Theft Persistence | MFA, email rules, OAuth consent after theft | AuditLogs + OfficeActivity |
| 6B | Post-Theft Cloud Activity | Cloud app anomaly detection after theft | CloudAppEvents |
| 7 | Org-Wide Token Theft Sweep | Find all users with token theft indicators | AADUserRiskEvents + SigninLogs |
| 8A | UEBA Assessment | Behavioral anomaly context for victim | BehaviorAnalytics |
| 8B | UEBA Anomaly Summary | Aggregated theft confidence score | BehaviorAnalytics |

---

## Appendix A: Datatable Tests

### Test 1: Session Cross-IP Hijack Detection

```kql
// TEST 1: Verifies detection of same session from different IPs/countries
let TestSignIns = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, SessionId: string,
    IPAddress: string, LocationDetails: dynamic, DeviceDetail: dynamic,
    ResultType: string, AppDisplayName: string, ResourceDisplayName: string,
    AutonomousSystemNumber: string, UserAgent: string, SignInType: string
)[
    // Legitimate session from corporate office
    datetime(2026-02-22T09:00:00Z), "alice@contoso.com", "session-001",
        "10.0.0.100", dynamic({"countryOrRegion":"US","city":"Seattle"}),
        dynamic({"operatingSystem":"Windows","browser":"Edge"}),
        "0", "Office 365", "Exchange Online", "1234", "Mozilla/5.0 Edge", "Interactive",
    // Same session from different country (stolen token)
    datetime(2026-02-22T09:30:00Z), "alice@contoso.com", "session-001",
        "198.51.100.50", dynamic({"countryOrRegion":"RU","city":"Moscow"}),
        dynamic({"operatingSystem":"Linux","browser":"Chrome"}),
        "0", "Office 365", "Exchange Online", "14061", "Mozilla/5.0 Chrome", "NonInteractive",
    // Normal user (single IP per session)
    datetime(2026-02-22T09:00:00Z), "bob@contoso.com", "session-002",
        "10.0.0.101", dynamic({"countryOrRegion":"US","city":"Seattle"}),
        dynamic({"operatingSystem":"Windows","browser":"Edge"}),
        "0", "Office 365", "Exchange Online", "1234", "Mozilla/5.0 Edge", "Interactive"
];
let MultiIPSessions = TestSignIns
    | summarize DistinctIPs = dcount(IPAddress) by SessionId
    | where DistinctIPs > 1;
TestSignIns
| where SessionId in ((MultiIPSessions | project SessionId))
| summarize
    DistinctIPs = dcount(IPAddress),
    Countries = make_set(tostring(LocationDetails.countryOrRegion)),
    DeviceOSes = make_set(tostring(DeviceDetail.operatingSystem))
    by SessionId, UserPrincipalName
| extend HijackVerdict = case(
    array_length(Countries) > 1 and array_length(DeviceOSes) > 1,
        "CRITICAL - Cross-country + cross-device session hijack",
    "OTHER"
)
| where SessionId == "session-001"
    and HijackVerdict == "CRITICAL - Cross-country + cross-device session hijack"
// EXPECTED: 1 row — session-001 flagged as CRITICAL (US→RU, Windows→Linux)
```

### Test 2: Token Risk Event Correlation

```kql
// TEST 2: Verifies correlation of anomalousToken risk events with sign-in context
let TestRiskEvents = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, RiskEventType: string,
    RiskLevel: string, RiskState: string, RiskDetail: string,
    DetectionTimingType: string, IpAddress: string, CorrelationId: string,
    Source: string, Location: dynamic
)[
    // High anomalous token
    datetime(2026-02-22T10:00:00Z), "alice@contoso.com", "anomalousToken",
        "high", "atRisk", "", "realtime", "198.51.100.50", "corr-001",
        "IdentityProtection", dynamic({"countryOrRegion":"RU"}),
    // PRT extraction attempt
    datetime(2026-02-22T11:00:00Z), "alice@contoso.com", "attemptedPRTAccess",
        "high", "atRisk", "", "offline", "10.0.0.100", "corr-002",
        "MDE", dynamic({"countryOrRegion":"US"}),
    // Low unfamiliar features (benign)
    datetime(2026-02-22T09:00:00Z), "bob@contoso.com", "unfamiliarFeatures",
        "low", "none", "aiConfirmedSigninSafe", "realtime", "10.0.0.101", "corr-003",
        "IdentityProtection", dynamic({"countryOrRegion":"US"})
];
let TokenRiskTypes = dynamic(["anomalousToken", "attackerinTheMiddle",
    "attemptedPRTAccess", "tokenIssuerAnomaly", "unfamiliarFeatures"]);
TestRiskEvents
| where RiskEventType in (TokenRiskTypes)
| extend ThreatLevel = case(
    RiskEventType == "attemptedPRTAccess",
        "CRITICAL - PRT extraction attempt detected by MDE",
    RiskEventType == "anomalousToken" and RiskLevel == "high",
        "CRITICAL - High-confidence anomalous token",
    RiskDetail has "aiConfirmedSigninSafe",
        "LOW - AI confirmed safe",
    "OTHER"
)
| where UserPrincipalName == "alice@contoso.com"
| summarize
    CriticalEvents = countif(ThreatLevel has "CRITICAL"),
    RiskTypes = make_set(RiskEventType)
| where CriticalEvents == 2
    and set_has_element(RiskTypes, "anomalousToken")
    and set_has_element(RiskTypes, "attemptedPRTAccess")
// EXPECTED: 1 row — alice has 2 CRITICAL events (anomalousToken + PRT)
```

### Test 3: Post-Theft Activity Detection

```kql
// TEST 3: Verifies detection of post-theft persistence and email compromise
let AlertTime = datetime(2026-02-22T10:00:00Z);
let TargetUser = "alice@contoso.com";
let TestAuditLogs = datatable(
    TimeGenerated: datetime, OperationName: string,
    InitiatedBy: dynamic, TargetResources: dynamic, Result: string
)[
    // MFA registration after token theft
    datetime(2026-02-22T10:30:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Phone - SMS"}]), "success",
    // Inbox rule creation
    datetime(2026-02-22T11:00:00Z), "New-InboxRule",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Forward to external"}]), "success",
    // OAuth consent
    datetime(2026-02-22T11:30:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"SuspiciousApp"}]), "success"
];
TestAuditLogs
| where TimeGenerated between (AlertTime .. (AlertTime + 48h))
| where InitiatedBy has TargetUser
| extend ActionCategory = case(
    OperationName has_any ("security info"), "MFA_MANIPULATION",
    OperationName has_any ("InboxRule", "inbox rule"), "EMAIL_COMPROMISE",
    OperationName has_any ("Consent", "OAuth"), "OAUTH_ABUSE",
    "OTHER"
)
| where ActionCategory in ("MFA_MANIPULATION", "EMAIL_COMPROMISE", "OAUTH_ABUSE")
| summarize
    PostTheftActions = count(),
    Categories = make_set(ActionCategory)
| where PostTheftActions == 3
    and set_has_element(Categories, "MFA_MANIPULATION")
    and set_has_element(Categories, "EMAIL_COMPROMISE")
    and set_has_element(Categories, "OAUTH_ABUSE")
// EXPECTED: 1 row — 3 post-theft actions detected (MFA + Email + OAuth)
```

### Test 4: Org-Wide Token Theft Sweep

```kql
// TEST 4: Verifies detection of multiple users with token theft indicators
let TestRiskEvents = datatable(
    UserPrincipalName: string, RiskEventType: string,
    RiskLevel: string, IpAddress: string, TimeGenerated: datetime
)[
    "alice@contoso.com", "anomalousToken", "high", "198.51.100.50",
        datetime(2026-02-22T10:00:00Z),
    "charlie@contoso.com", "attackerinTheMiddle", "high", "198.51.100.51",
        datetime(2026-02-22T10:30:00Z),
    "bob@contoso.com", "unfamiliarFeatures", "low", "10.0.0.101",
        datetime(2026-02-22T09:00:00Z)
];
let TokenRiskTypes = dynamic(["anomalousToken", "attackerinTheMiddle",
    "attemptedPRTAccess", "tokenIssuerAnomaly"]);
TestRiskEvents
| where RiskEventType in (TokenRiskTypes)
| summarize
    RiskEvents = make_set(RiskEventType),
    MaxRiskLevel = max(case(RiskLevel == "high", 3, RiskLevel == "medium", 2, 1)),
    RiskIPs = make_set(IpAddress)
    by UserPrincipalName
| extend OverallRisk = case(
    set_has_element(RiskEvents, "attackerinTheMiddle"),
        "CRITICAL - AiTM attack confirmed",
    MaxRiskLevel >= 3,
        "CRITICAL - High-risk token event",
    "OTHER"
)
| where OverallRisk has "CRITICAL"
| summarize
    CriticalUsers = count(),
    Users = make_set(UserPrincipalName)
| where CriticalUsers == 2
// EXPECTED: 1 row — 2 CRITICAL users (alice + charlie), bob excluded (low unfamiliar)
```

---

## References

- [Microsoft Token Theft Playbook](https://learn.microsoft.com/en-us/security/operations/token-theft-playbook)
- [Token Protection in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection)
- [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Protecting Tokens in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/devices/protecting-tokens-microsoft-entra-id)
- [Microsoft Entra ID Identity Protection Risk Detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [AADNonInteractiveUserSignInLogs Reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
- [AADUserRiskEvents Reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aaduserriskevents)
- [MITRE ATT&CK T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK T1550.004 - Use Alternate Authentication Material: Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/)
- [AzureAD-Attack-Defense: Primary Refresh Token Replay](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/blob/main/ReplayOfPrimaryRefreshToken.md)
- [AzureAD-Attack-Defense: AiTM Attack](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/blob/main/Adversary-in-the-Middle.md)
- [Lumma Stealer Technical Analysis](https://www.microsoft.com/en-us/security/blog/2025/03/05/lumma-stealer-breaking-down-the-delivery-techniques-and-defense-strategies/)
- [Scattered Spider Token Theft Techniques](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)
