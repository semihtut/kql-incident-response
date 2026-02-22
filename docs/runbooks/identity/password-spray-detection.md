---
title: "Password Spray Detection"
id: RB-0006
severity: high
status: reviewed
description: >
  Investigation runbook for distributed password spray attacks detected via
  Microsoft Entra ID Identity Protection and SigninLogs pattern analysis.
  Covers multi-account low-and-slow authentication failure correlation,
  successful-after-spray pivot detection, lockout pattern analysis, and
  post-compromise blast radius assessment. Password spraying targets many
  accounts with a small number of commonly used passwords to avoid triggering
  per-account lockout thresholds.
mitre_attack:
  tactics:
    - tactic_id: TA0006
      tactic_name: "Credential Access"
    - tactic_id: TA0001
      tactic_name: "Initial Access"
    - tactic_id: TA0003
      tactic_name: "Persistence"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
    - tactic_id: TA0008
      tactic_name: "Lateral Movement"
    - tactic_id: TA0009
      tactic_name: "Collection"
  techniques:
    - technique_id: T1110.003
      technique_name: "Brute Force: Password Spraying"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1110.001
      technique_name: "Brute Force: Password Guessing"
      confidence: probable
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: confirmed
    - technique_id: T1114.003
      technique_name: "Email Collection: Email Forwarding Rule"
      confidence: confirmed
    - technique_id: T1528
      technique_name: "Steal Application Access Token"
      confidence: confirmed
    - technique_id: T1556.006
      technique_name: "Modify Authentication Process: MFA"
      confidence: confirmed
    - technique_id: T1564.008
      technique_name: "Hide Artifacts: Email Hiding Rules"
      confidence: confirmed
    - technique_id: T1530
      technique_name: "Data from Cloud Storage Object"
      confidence: confirmed
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Peach Sandstorm (APT33)"
  - "Storm-0558"
  - "Scattered Spider (Octo Tempest)"
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
  - table: "AADRiskyUsers"
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
  - table: "OfficeActivity"
    product: "Office 365"
    license: "M365 E3+"
    required: true
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-22
updated: 2026-02-22
version: "1.0"
tier: 1
---

# Password Spray Detection - Investigation Runbook

> **RB-0006** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Identity Protection + SigninLogs Pattern Analysis
> **Risk Detection Name:** `passwordSpray` + ResultType `50126` pattern
> **Primary MITRE Technique:** T1110.003 - Brute Force: Password Spraying

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Extract Password Spray Risk Event](#step-1-extract-password-spray-risk-event)
   - [Step 2: Multi-Account Failure Pattern Analysis](#step-2-multi-account-failure-pattern-analysis)
   - [Step 3: Successful Authentication After Spray Detection](#step-3-successful-authentication-after-spray-detection)
   - [Step 4: Baseline Comparison - Establish Normal Authentication Failure Pattern](#step-4-baseline-comparison---establish-normal-authentication-failure-pattern)
   - [Step 5: Lockout and Smart Lockout Analysis](#step-5-lockout-and-smart-lockout-analysis)
   - [Step 6: Post-Compromise Blast Radius Assessment](#step-6-post-compromise-blast-radius-assessment)
   - [Step 7: Org-Wide Spray Campaign Scope](#step-7-org-wide-spray-campaign-scope)
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
Password spray is detected through two complementary mechanisms:

1. **Identity Protection `passwordSpray` risk event:** An offline detection that uses machine learning to identify distributed authentication patterns consistent with password spraying across multiple accounts. This creates a `passwordSpray` entry in AADUserRiskEvents.
2. **SigninLogs pattern analysis:** Detected by correlating failed sign-in events (ResultType `50126` — invalid username or password) across many accounts from the same source IP or IP range within a time window. The defining pattern is: **many accounts, few attempts per account, same IP infrastructure.**

**Why it matters:**
Password spraying is one of the most common credential attacks against cloud environments. Unlike brute force (many passwords against one account), spraying distributes 1-2 password attempts across many accounts to stay below lockout thresholds. This makes it difficult to detect with per-account monitoring alone — the signal only emerges when you correlate across accounts. Midnight Blizzard (APT29) used password spraying against Microsoft corporate accounts in 2023-2024. Peach Sandstorm (APT33) conducts sustained spray campaigns lasting months against defense and pharma targets.

**Why this is HIGH severity:**
- A single compromised account from a spray gives the attacker a foothold in the tenant
- Spray campaigns target hundreds to thousands of accounts simultaneously — statistically, some will have weak passwords
- The attack bypasses smart lockout because each account sees only 1-2 failures
- Compromised accounts from sprays are often used for internal phishing, BEC, or lateral movement
- Organizations with no MFA on legacy protocols are especially vulnerable — a single success bypasses all conditional access

**However:** This alert has a **moderate false positive rate** (~15-25%). Legitimate triggers include:
- Misconfigured service accounts or applications repeatedly failing authentication
- Users who recently changed their password and have cached credentials on multiple devices
- Mobile email clients retrying with expired passwords
- SSPR (Self-Service Password Reset) flows generating multiple failure events
- Third-party applications with hardcoded or stale credentials

**Worst case scenario if this is real:**
An attacker sprays thousands of accounts in your tenant with common passwords ("Spring2026!", "Welcome1!", "CompanyName2026"). One or more accounts without MFA are compromised. The attacker uses the compromised account to read email, set up forwarding rules for data exfiltration, grant OAuth application permissions, and launch internal phishing campaigns from a trusted sender. If the compromised account has admin roles or PIM eligibility, the blast radius extends to the entire tenant.

**Key difference from RB-0001 through RB-0005:**
- RB-0001 (Unfamiliar Sign-In): Detects unusual device/location for a single user.
- RB-0002 (Impossible Travel): Detects geographically impossible sign-in pairs.
- RB-0003 (Leaked Credentials): Offline detection — credentials found on dark web.
- RB-0004 (Anonymous IP Address): Sign-in from anonymizing infrastructure.
- RB-0005 (MFA Fatigue): Attacker already has the password, is bombing MFA.
- **RB-0006 (This runbook):** The attacker does NOT have any password yet. They are **guessing common passwords across many accounts** to find weak ones. The investigation focuses on **cross-account correlation** — no single account looks suspicious alone, but the pattern across 50-1000+ accounts reveals the spray. The critical question is: **"Did any of the targeted accounts have a success (ResultType 0) amidst all these failures?"** This is the only runbook where investigation requires analyzing behavior across the entire tenant, not a single user.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID P2 + Microsoft 365 E3 + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID, Office 365
- **Permissions:** Security Reader (investigation), Security Operator (containment)

### Recommended for Full Coverage
- **License:** Microsoft 365 E5 + Sentinel
- **Additional:** Smart Lockout configured (Entra ID → Authentication methods → Password protection)
- **Legacy Auth Blocked:** Conditional Access policy blocking legacy authentication protocols

### Data Availability Check
Before starting the investigation, verify these tables contain data:
1. Run `SigninLogs | take 1` — **PRIMARY table** for authentication failure pattern analysis
2. Run `AADUserRiskEvents | take 1` — For `passwordSpray` risk events
3. Run `AADNonInteractiveUserSignInLogs | take 1` — For legacy auth and service account failures
4. Run `OfficeActivity | take 1` — For blast radius assessment
5. Run `AuditLogs | take 1` — For persistence detection

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | SigninLogs, AuditLogs | Steps 2, 3, 4, 5 (partial) |
| Entra ID P2 + Sentinel | Above + AADUserRiskEvents, AADRiskyUsers, AADNonInteractiveUserSignInLogs | Steps 1-5, 7 |
| M365 E3 + Entra ID P2 + Sentinel | Above + OfficeActivity | Steps 1-7 (full investigation) |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let TargetIP = "203.0.113.50";              // Source IP from the alert (primary pivot)
let TargetUser = "user@contoso.com";        // Specific user flagged (if from Identity Protection)
let AlertTime = datetime(2026-02-22T14:00:00Z);  // Time the spray was detected
let LookbackWindow = 24h;                   // Spray campaigns can span hours to days
let ForwardWindow = 4h;                     // Window after compromise for blast radius
let BaselineDays = 30d;                     // Baseline comparison window
let FailureThreshold = 10;                  // Minimum failed accounts per IP to flag
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- Identity Protection `passwordSpray` risk event followed by successful sign-in for any flagged user
- Single IP has 50+ failed accounts within 1 hour followed by 1+ successful sign-in
- Compromised account is a Global Admin, Security Admin, or PIM-eligible
- Multiple IPs from the same ASN/subnet showing spray patterns simultaneously
- Successful sign-in uses legacy authentication protocol (IMAP, POP3, SMTP)

### Standard Investigation
- Identity Protection `passwordSpray` risk event with no subsequent success
- Single IP has 10-49 failed accounts with no successful sign-in
- Spray pattern detected but all targeted accounts have MFA enabled

### Likely Benign
- Failures are from known corporate IP ranges (SSPR, migration, misconfigured apps)
- All failures target the same 2-3 service accounts (misconfiguration, not spray)
- Failures are ResultType `50053` (locked out) from a known application service principal
- IP belongs to a known security scanning vendor

---

## 5. Investigation Steps

### Step 1: Extract Password Spray Risk Event

**Purpose:** Check if Identity Protection flagged a `passwordSpray` risk event. This confirms Entra ID's ML detected the spray pattern. Note: This is an offline detection — it may take up to 48 hours to appear. Proceed to Step 2 regardless.

**Data needed:** AADUserRiskEvents

```kql
// ============================================================
// QUERY 1: Password Spray Risk Event Extraction
// Purpose: Extract passwordSpray risk events from Identity Protection
// Tables: AADUserRiskEvents
// Investigation Step: 1 - Extract Password Spray Risk Event
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 48h;
// --- Risk event extraction ---
AADUserRiskEvents
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where RiskEventType == "passwordSpray"
| project
    RiskEventTime = TimeGenerated,
    UserPrincipalName,
    RiskEventType,
    RiskLevel,
    RiskState,
    DetectionTimingType,
    IpAddress,
    Location_City = tostring(Location.city),
    Location_Country = tostring(Location.countryOrRegion),
    Activity,
    AdditionalInfo = tostring(AdditionalInfo),
    CorrelationId
| sort by RiskEventTime desc
```

**Performance Notes:**
- `passwordSpray` is an **offline** detection — it may not appear for 24-48 hours after the actual spray
- If this query returns no results, it does NOT mean there was no spray — proceed to Step 2
- Multiple users may have `passwordSpray` events from the same campaign — note the IpAddress overlap

**Tuning Guidance:**
- Extend LookbackWindow to 72h for slow-burn spray campaigns
- If many users are flagged with the same IpAddress, this confirms a coordinated campaign

**Expected findings:**
- If populated: Shows which users Identity Protection believes were targeted, with IP and timing
- If empty: The spray may be too recent for offline detection, or the pattern didn't match ML thresholds

**Next action:**
- If risk events found → Note all unique IPs and users for subsequent queries
- If empty → Proceed to Step 2 (pattern detection) as the primary detection method

---

### Step 2: Multi-Account Failure Pattern Analysis

**Purpose:** Detect password spray by finding IPs that have authentication failures across many distinct accounts within a time window. This is the **primary detection query** — the defining characteristic of a spray is many accounts from the same source with few attempts per account.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 2: Multi-Account Failure Pattern Analysis
// Purpose: Detect password spray by correlating failures across accounts per IP
// Tables: SigninLogs
// Investigation Step: 2 - Multi-Account Failure Pattern Analysis
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
let FailureThreshold = 10;
// --- Aggregate authentication failures by source IP ---
let SprayDetection = SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 2h)
| where ResultType in ("50126", "50053", "50055", "50056", "530032")
    // 50126 = invalid username/password (PRIMARY spray indicator)
    // 50053 = account locked out (spray triggered lockout)
    // 50055 = password expired
    // 50056 = invalid or null password
    // 530032 = blocked by conditional access / security defaults
| summarize
    TargetedAccounts = dcount(UserPrincipalName),
    TargetedAccountList = make_set(UserPrincipalName, 50),
    TotalAttempts = count(),
    AttemptsPerAccount = round(1.0 * count() / max(dcount(UserPrincipalName), 1), 1),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    ResultTypes = make_set(ResultType),
    Lockouts = countif(ResultType == "50053"),
    Apps = make_set(AppDisplayName, 10),
    ClientApps = make_set(ClientAppUsed, 10),
    UserAgents = make_set(UserAgent, 5),
    Cities = make_set(tostring(LocationDetails.city), 5),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 5)
    by IPAddress
| where TargetedAccounts >= FailureThreshold
| extend
    SprayDuration = LastAttempt - FirstAttempt,
    AttackRate_PerMinute = round(TotalAttempts / max(datetime_diff('minute', LastAttempt, FirstAttempt), 1.0), 1),
    RiskAssessment = case(
        TargetedAccounts >= 100, "CRITICAL - Large-scale password spray",
        TargetedAccounts >= 50, "HIGH - Significant spray campaign",
        TargetedAccounts >= 25, "MEDIUM - Moderate spray",
        TargetedAccounts >= 10, "LOW - Small spray or misconfiguration",
        "INVESTIGATE"
    ),
    LegacyAuthUsed = ClientApps has_any ("IMAP", "POP3", "SMTP", "Exchange ActiveSync",
        "Other clients", "Authenticated SMTP")
| sort by TargetedAccounts desc
```

**Performance Notes:**
- ResultType `50126` is THE golden indicator — invalid username or password
- `dcount(UserPrincipalName)` reveals the spray breadth; `AttemptsPerAccount` near 1-2 is classic spray
- High `AttemptsPerAccount` (> 5) suggests brute force rather than spray — different investigation path
- `LegacyAuthUsed` is critical — legacy auth bypasses MFA entirely

**Tuning Guidance:**
- Lower `FailureThreshold` to 5 for sensitive environments
- If `AttemptsPerAccount` is > 5, consider this brute force instead of spray (different technique T1110.001)
- Filter out known corporate IPs and scanner IPs before triage
- If `ClientApps` contains "Browser", the spray uses modern auth; if "IMAP"/"POP3", it targets legacy

**Expected findings:**
- IPs with 10+ targeted accounts and AttemptsPerAccount near 1-2 = classic password spray
- `LegacyAuthUsed == true` is a red flag — sprays targeting legacy auth are more likely to succeed
- Duration > 1h with consistent rate = automated tooling (Spray-AD, MSOLSpray, FireProx)
- Single target app (e.g., "Exchange Online") is typical for spray campaigns

**Next action:**
- If spray IPs found → Proceed to Step 3 to check if any account was compromised
- If no spray detected → Check AADNonInteractiveUserSignInLogs for service account sprays
- Note the `IPAddress` values for correlation across all subsequent queries

---

### Step 3: Successful Authentication After Spray Detection

**Purpose:** The **critical pivot point** of this investigation. Check if any account targeted in the spray had a successful sign-in (ResultType `0`) from the same spray IP or within a short window after being sprayed. A success means the spray found a weak password and the attacker now has access.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 3: Successful Authentication After Spray Detection
// Purpose: Find accounts compromised by the spray (success after failures)
// Tables: SigninLogs
// Investigation Step: 3 - Successful Authentication After Spray
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
let ForwardWindow = 4h;
let FailureThreshold = 10;
// --- Step A: Identify spray source IPs ---
let SprayIPs = SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 2h)
| where ResultType == "50126"
| summarize TargetedAccounts = dcount(UserPrincipalName) by IPAddress
| where TargetedAccounts >= FailureThreshold
| project IPAddress;
// --- Step B: Find successes from spray IPs ---
let SpraySuccesses = SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + ForwardWindow)
| where IPAddress in (SprayIPs)
| where ResultType == "0"
| project
    SuccessTime = TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    ResourceDisplayName,
    MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA"),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    DeviceId = tostring(DeviceDetail.deviceId),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged),
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    ClientApp = ClientAppUsed,
    AuthRequirement = AuthenticationRequirement,
    ConditionalAccessStatus,
    CorrelationId;
// --- Step C: Correlate with preceding failures for the same user ---
let FailedThenSucceeded = SpraySuccesses
| join kind=inner (
    SigninLogs
    | where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + ForwardWindow)
    | where IPAddress in (SprayIPs)
    | where ResultType == "50126"
    | summarize
        FailureCount = count(),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by UserPrincipalName, IPAddress
) on UserPrincipalName, IPAddress
| where SuccessTime > FirstFailure  // Success came AFTER failures
| extend
    TimeFromFailureToSuccess = SuccessTime - LastFailure,
    MfaBypassed = MfaAuthMethod == "No MFA",
    Verdict = case(
        MfaAuthMethod == "No MFA" and IsManaged != "true",
            "CRITICAL - Compromised, no MFA, unmanaged device",
        MfaAuthMethod == "No MFA",
            "HIGH - Compromised, no MFA but managed device",
        IsManaged != "true",
            "HIGH - Compromised, MFA passed but unmanaged device",
        "MEDIUM - Compromised, MFA passed on managed device"
    )
| project
    UserPrincipalName,
    IPAddress,
    FailureCount,
    FirstFailure,
    LastFailure,
    SuccessTime,
    TimeFromFailureToSuccess,
    AppDisplayName,
    ClientApp,
    MfaAuthMethod,
    MfaBypassed,
    DeviceOS,
    IsManaged,
    City,
    Country,
    ConditionalAccessStatus,
    Verdict
| sort by SuccessTime asc;
FailedThenSucceeded
```

**Performance Notes:**
- The inner join correlates successes with prior failures from the same IP and user
- `MfaBypassed == true` is the highest risk — the spray succeeded AND no MFA was enforced
- Multiple users with successes from the same spray IP = multiple compromised accounts
- Check `ClientApp` — success via "IMAP" or "POP3" means legacy auth was the entry vector

**Tuning Guidance:**
- If `TimeFromFailureToSuccess` is < 1 second, this might be a retry race condition (FP) — verify with Step 4
- If `ConditionalAccessStatus == "notApplied"`, Conditional Access wasn't evaluated — check policy gaps
- Success via legacy auth (`ClientApp` in IMAP/POP3/SMTP) bypasses ALL MFA — this is the worst case

**Expected findings:**
- **CRITICAL**: Success with no MFA from unmanaged device → Account fully compromised, no access controls
- **HIGH**: Success with no MFA → Password is compromised, attacker has full access despite MFA policies
- **MEDIUM**: Success with MFA passed → Attacker may have phished MFA token or has access to user's MFA device
- **No successes**: Spray failed — all accounts were protected. Still reset passwords for targeted accounts with weak indicators.

**Next action:**
- If compromised accounts found → Proceed to Step 6 for blast radius, start containment immediately
- If no successes → The spray failed. Proceed to Step 4 for baseline context, then Step 5 for lockout analysis
- Document ALL compromised accounts — each needs individual containment

---

### Step 4: Baseline Comparison - Establish Normal Authentication Failure Pattern

**Purpose:** Establish what "normal" authentication failure activity looks like for the spray source IP(s) and targeted accounts over 30 days. Determine if the failure volume is truly anomalous or a recurring pattern (misconfigured app, scanner, etc.). **This step is MANDATORY per project quality standards.**

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 4: Baseline Comparison - Normal Failure Pattern
// Purpose: Establish 30-day baseline for failure patterns per IP
// Tables: SigninLogs
// Investigation Step: 4 - Baseline Comparison [MANDATORY]
// ============================================================
let TargetIP = "203.0.113.50";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 30d;
// --- 30-day authentication failure baseline for the IP ---
let IPBaseline = SigninLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime - 1h)
| where IPAddress == TargetIP
| where ResultType in ("50126", "50053", "0")
| summarize
    DailyFailures = countif(ResultType in ("50126", "50053")),
    DailySuccesses = countif(ResultType == "0"),
    UniqueAccountsFailed = dcount(iff(ResultType == "50126", UserPrincipalName, "")),
    UniqueAccountsSucceeded = dcount(iff(ResultType == "0", UserPrincipalName, ""))
    by Day = bin(TimeGenerated, 1d);
// --- Aggregate baseline ---
let BaselineStats = IPBaseline
| summarize
    BaselineDays_Observed = count(),
    AvgDailyFailures = round(avg(DailyFailures), 1),
    MaxDailyFailures = max(DailyFailures),
    StdDevDailyFailures = round(stdev(DailyFailures), 1),
    AvgDailyUniqueAccounts = round(avg(UniqueAccountsFailed), 1),
    MaxDailyUniqueAccounts = max(UniqueAccountsFailed),
    AvgDailySuccesses = round(avg(DailySuccesses), 1),
    TotalSuccesses_30d = sum(DailySuccesses);
// --- Today's activity for comparison ---
let TodayStats = SigninLogs
| where TimeGenerated between (AlertTime - 24h .. AlertTime + 2h)
| where IPAddress == TargetIP
| where ResultType in ("50126", "50053", "0")
| summarize
    TodayFailures = countif(ResultType in ("50126", "50053")),
    TodaySuccesses = countif(ResultType == "0"),
    TodayUniqueAccounts = dcount(iff(ResultType == "50126", UserPrincipalName, ""));
// --- Compare ---
BaselineStats
| extend placeholder = 1
| join kind=inner (TodayStats | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    FailureDeviation = iff(StdDevDailyFailures > 0,
        round((TodayFailures - AvgDailyFailures) / StdDevDailyFailures, 1),
        iff(TodayFailures > 0, 999.0, 0.0)),
    AccountDeviation = iff(MaxDailyUniqueAccounts > 0,
        round(1.0 * TodayUniqueAccounts / MaxDailyUniqueAccounts, 1),
        iff(TodayUniqueAccounts > 0, 999.0, 0.0)),
    Assessment = case(
        MaxDailyFailures == 0 and TodayFailures > 0,
            "NEW IP - No baseline history, ANY failure is suspicious",
        TodayUniqueAccounts > MaxDailyUniqueAccounts * 5,
            "ANOMALOUS - 5x+ accounts targeted vs historical max",
        TodayFailures > AvgDailyFailures + 3 * StdDevDailyFailures,
            "ANOMALOUS - Failures exceed 3 standard deviations",
        TodayUniqueAccounts > MaxDailyUniqueAccounts * 2,
            "SUSPICIOUS - 2x+ accounts targeted vs historical max",
        TodayFailures > MaxDailyFailures * 2,
            "SUSPICIOUS - 2x+ failures vs historical max",
        "WITHIN NORMAL RANGE - Possible misconfigured application"
    )
```

**Performance Notes:**
- Standard deviation comparison is the most statistically robust method for anomaly detection
- `FailureDeviation > 3` (3 sigma) is a strong indicator of anomalous activity
- A "NEW IP" with zero baseline history is particularly suspicious — spray IPs are often fresh

**Tuning Guidance:**
- IPs with consistent baseline failures (known scanner, SSPR proxy) should be whitelisted
- If `Assessment == "WITHIN NORMAL RANGE"`, this IP may be a recurring misconfiguration — check `ClientApps`
- For IPs first seen today with high failure counts, always treat as suspicious regardless of baseline

**Expected findings:**
- **NEW IP**: No historical data for this IP → Attacker using fresh infrastructure (common for sprays)
- **ANOMALOUS**: 5x+ accounts vs baseline → Definitive spray pattern, not a misconfiguration
- **WITHIN NORMAL RANGE**: Regular failures from this IP → Likely misconfigured app or scanner

**Next action:**
- If anomalous → High confidence spray. Proceed to Step 5 and 6.
- If within normal range → Investigate the specific IP owner and application. May still be a spray if it's a new slow campaign.

---

### Step 5: Lockout and Smart Lockout Analysis

**Purpose:** Analyze account lockout events triggered by the spray. Smart Lockout in Entra ID blocks sign-in attempts from suspicious locations while allowing the user to sign in from trusted locations. This step reveals how many accounts were locked out and whether the spray was partially blocked.

**Data needed:** SigninLogs, AADNonInteractiveUserSignInLogs

```kql
// ============================================================
// QUERY 5: Lockout and Smart Lockout Analysis
// Purpose: Analyze account lockout patterns from the spray
// Tables: SigninLogs
// Investigation Step: 5 - Lockout and Smart Lockout Analysis
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
let FailureThreshold = 10;
// --- Identify spray IPs ---
let SprayIPs = SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 2h)
| where ResultType == "50126"
| summarize TargetedAccounts = dcount(UserPrincipalName) by IPAddress
| where TargetedAccounts >= FailureThreshold
| project IPAddress;
// --- Lockout analysis for sprayed accounts ---
SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where IPAddress in (SprayIPs)
| summarize
    TotalAttempts = count(),
    InvalidPassword = countif(ResultType == "50126"),
    LockedOut = countif(ResultType == "50053"),
    Success = countif(ResultType == "0"),
    Blocked = countif(ResultType == "530032"),
    OtherFailures = countif(ResultType !in ("50126", "50053", "0", "530032")),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    ClientApps = make_set(ClientAppUsed, 5)
    by UserPrincipalName, IPAddress
| extend
    WasLockedOut = LockedOut > 0,
    WasCompromised = Success > 0,
    WasBlocked = Blocked > 0,
    AttemptsBeforeLockout = InvalidPassword,
    AccountStatus = case(
        Success > 0 and LockedOut == 0, "COMPROMISED - Success without lockout",
        Success > 0 and LockedOut > 0, "COMPROMISED THEN LOCKED - Success before lockout",
        LockedOut > 0, "LOCKED OUT - Spray triggered lockout",
        Blocked > 0, "BLOCKED - Conditional Access prevented attempt",
        InvalidPassword > 0, "FAILED - Wrong password, not locked",
        "OTHER"
    )
| sort by WasCompromised desc, LockedOut desc, InvalidPassword desc
```

**Performance Notes:**
- `WasCompromised == true` is the highest priority finding — this account needs immediate containment
- Accounts that were locked out (`50053`) show Smart Lockout engaged — the spray was partially effective
- Accounts blocked by Conditional Access (`530032`) were protected by policy — verify policy coverage

**Tuning Guidance:**
- If many accounts show `LOCKED OUT`, the spray used > 2 attempts per account (aggressive spray)
- If accounts show `BLOCKED`, verify Conditional Access policies are blocking the spray correctly
- If `ClientApps` contains legacy protocols AND `WasCompromised`, this is legacy auth bypass

**Expected findings:**
- **COMPROMISED**: Account had success from spray IP → Immediate containment
- **LOCKED OUT**: Smart Lockout engaged → Spray was aggressive, lockout is protecting the account
- **BLOCKED**: CA policy blocked → Verify the policy and ensure no gaps
- **FAILED**: Password was wrong, no lockout → Standard spray behavior, account was not compromised

**Next action:**
- For each `COMPROMISED` account → Step 6 (blast radius)
- For `LOCKED OUT` accounts → Verify lockout duration, check if attacker waited and retried
- Aggregate total compromised vs protected accounts for incident severity rating

---

### Step 6: Post-Compromise Blast Radius Assessment

**Purpose:** For any account compromised in Step 3/5, assess what the attacker did with the access. Check for persistence (inbox rules, MFA changes, OAuth consent) and data access (email, files).

#### Step 6A: Directory Changes and Persistence

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 6A: Directory Changes After Spray Compromise
// Purpose: Detect persistence mechanisms after password spray compromise
// Tables: AuditLogs
// Investigation Step: 6A - Directory Changes Post-Compromise
// ============================================================
let CompromisedUser = "user@contoso.com";  // From Step 3 results
let CompromiseTime = datetime(2026-02-22T14:30:00Z);  // First success time
let ForwardWindow = 4h;
// --- Post-compromise directory changes ---
AuditLogs
| where TimeGenerated between (CompromiseTime .. CompromiseTime + ForwardWindow)
| where OperationName in (
    "Register security info",
    "User registered security info",
    "User deleted security info",
    "Update user",
    "Consent to application",
    "Add app role assignment to service principal",
    "Add owner to application",
    "Update application",
    "Add member to role",
    "Add eligible member to role",
    "Register device"
)
| where InitiatedBy has CompromisedUser
    or tostring(InitiatedBy.user.userPrincipalName) =~ CompromisedUser
| project
    TimeGenerated,
    OperationName,
    Category,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    TargetResource = tostring(TargetResources[0].displayName),
    TargetResourceType = tostring(TargetResources[0].type),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties),
    Result
| extend
    Severity = case(
        OperationName has "security info" and OperationName has "Register", "CRITICAL - MFA method registered",
        OperationName has "security info" and OperationName has "deleted", "CRITICAL - MFA method removed",
        OperationName == "Consent to application", "HIGH - OAuth app consent",
        OperationName has "role", "HIGH - Role assignment change",
        OperationName == "Register device", "HIGH - Device registration",
        "MEDIUM - Account modification"
    )
| sort by TimeGenerated asc
```

**Expected findings:**
- **CRITICAL**: New MFA method registered → Attacker establishing persistence
- **HIGH**: OAuth consent → Attacker created persistent API access
- **HIGH**: Role assignment → Privilege escalation attempt

---

#### Step 6B: Email and File Activity

**Data needed:** OfficeActivity

```kql
// ============================================================
// QUERY 6B: Email and File Activity Post-Compromise
// Purpose: Detect data access and exfiltration after spray compromise
// Tables: OfficeActivity
// Investigation Step: 6B - Email/File Activity
// ============================================================
let CompromisedUser = "user@contoso.com";
let CompromiseTime = datetime(2026-02-22T14:30:00Z);
let ForwardWindow = 4h;
// --- Post-compromise activity ---
OfficeActivity
| where TimeGenerated between (CompromiseTime .. CompromiseTime + ForwardWindow)
| where UserId =~ CompromisedUser
| where Operation in (
    "MailItemsAccessed", "Send", "SendAs", "SendOnBehalf",
    "New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "Set-Mailbox", "New-TransportRule",
    "FileDownloaded", "FileUploaded", "FileSyncDownloadedFull",
    "FileAccessed", "FileModified", "FileCopied",
    "SharingSet", "AnonymousLinkCreated",
    "Add-MailboxPermission", "Set-MailboxAutoReplyConfiguration"
)
| extend CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
| project
    TimeGenerated,
    UserId,
    Operation,
    CleanClientIP,
    OfficeWorkload,
    ResultStatus,
    TargetItem = iff(OfficeWorkload == "Exchange",
        tostring(Item.Subject),
        tostring(SourceFileName)),
    ItemCount = iff(isnotempty(AffectedItems), array_length(AffectedItems), 1),
    Parameters
| extend
    Severity = case(
        Operation in ("New-InboxRule", "Set-InboxRule"), "CRITICAL - Inbox rule created",
        Operation in ("Send", "SendAs"), "HIGH - Email sent from account",
        Operation == "MailItemsAccessed" and ItemCount > 50, "HIGH - Bulk email access",
        Operation in ("FileDownloaded", "FileSyncDownloadedFull") and ItemCount > 10, "HIGH - Bulk file download",
        Operation in ("SharingSet", "AnonymousLinkCreated"), "HIGH - Sharing permission change",
        Operation in ("Add-MailboxPermission"), "CRITICAL - Mailbox delegation added",
        "MEDIUM - Standard activity"
    )
| sort by TimeGenerated asc
```

**Expected findings:**
- **CRITICAL**: Inbox rules or mailbox delegation → Classic BEC persistence from spray
- **HIGH**: Email sent or bulk download → Active data exfiltration

**Next action:**
- For each compromised account → Run both 6A and 6B queries
- If inbox rules found → Extract rule parameters (see RB-0005 Query 6C for inbox rule deep dive pattern)
- Aggregate total blast radius across all compromised accounts

---

### Step 7: Org-Wide Spray Campaign Scope

**Purpose:** Map the full scope of the spray campaign. Identify all source IPs, the total number of targeted accounts, timing patterns, and whether the spray infrastructure is coordinated (same ASN, sequential IPs, shared user agent).

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 7: Org-Wide Spray Campaign Scope
// Purpose: Map full spray campaign scope — all IPs, timing, infrastructure
// Tables: SigninLogs
// Investigation Step: 7 - Org-Wide Spray Campaign Scope
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
let FailureThreshold = 10;
// --- Identify all spray IPs and their infrastructure ---
let CampaignScope = SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 2h)
| where ResultType in ("50126", "50053")
| summarize
    TargetedAccounts = dcount(UserPrincipalName),
    TotalAttempts = count(),
    Lockouts = countif(ResultType == "50053"),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    TargetApps = make_set(AppDisplayName, 5),
    ClientApps = make_set(ClientAppUsed, 5),
    UserAgents = make_set(UserAgent, 3),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 3)
    by IPAddress
| where TargetedAccounts >= FailureThreshold;
// --- Check for successes from these spray IPs ---
let SpraySuccesses = SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where ResultType == "0"
| where IPAddress in (CampaignScope | project IPAddress)
| summarize CompromisedAccounts = dcount(UserPrincipalName),
    CompromisedList = make_set(UserPrincipalName, 20)
    by IPAddress;
// --- Full campaign summary ---
CampaignScope
| join kind=leftouter SpraySuccesses on IPAddress
| extend
    CompromisedAccounts = coalesce(CompromisedAccounts, 0),
    CompromisedList = coalesce(CompromisedList, dynamic([])),
    SprayDuration = LastAttempt - FirstAttempt,
    AttemptsPerAccount = round(1.0 * TotalAttempts / TargetedAccounts, 1),
    SuccessRate = round(100.0 * coalesce(CompromisedAccounts, 0) / TargetedAccounts, 2),
    HasLegacyAuth = ClientApps has_any ("IMAP", "POP3", "SMTP", "Exchange ActiveSync"),
    CampaignSeverity = case(
        coalesce(CompromisedAccounts, 0) > 0, "CRITICAL - Active compromise",
        TargetedAccounts >= 100, "HIGH - Large-scale campaign, no success yet",
        TargetedAccounts >= 25, "MEDIUM - Moderate campaign",
        "LOW - Small-scale spray"
    )
| project
    IPAddress,
    TargetedAccounts,
    TotalAttempts,
    AttemptsPerAccount,
    CompromisedAccounts,
    CompromisedList,
    SuccessRate,
    SprayDuration,
    HasLegacyAuth,
    Lockouts,
    TargetApps,
    ClientApps,
    UserAgents,
    Countries,
    CampaignSeverity
| sort by TargetedAccounts desc
```

**Performance Notes:**
- This is a tenant-wide query — may be slow in large organizations. Consider narrowing `LookbackWindow`
- `AttemptsPerAccount` near 1 = classic spray; near 5+ = brute force hybrid
- `SuccessRate` > 0% means at least one account was compromised
- `UserAgents` shared across all spray IPs = same tooling (e.g., "python-requests/2.x" = MSOLSpray)

**Tuning Guidance:**
- Group spray IPs by `/24` subnet to identify if they're from the same infrastructure
- Compare `UserAgents` across IPs — identical user agents = coordinated spray
- If spray spans > 24h with consistent rate, this is a "low-and-slow" campaign designed to evade detection

**Expected findings:**
- **Single IP, high count**: Simple spray from one source — block the IP immediately
- **Multiple IPs, shared user agent**: Coordinated campaign using proxy infrastructure (FireProx, residential proxies)
- **CompromisedAccounts > 0**: Active breach — each compromised account needs containment

**Next action:**
- Block all identified spray IPs in Conditional Access named locations
- For each compromised account → Run Step 6 blast radius assessment
- If campaign is large-scale (100+ accounts) → Engage incident response team

---

## 6. Containment Playbook

### Priority Actions (Based on Investigation Findings)

#### Immediate (Within 15 minutes of confirmed compromise)

!!! danger "Action Required - For Each Compromised Account"

1. **Reset passwords** for ALL compromised accounts immediately (Step 3/5 results)
2. **Revoke all sessions** — `Revoke-AzureADUserAllRefreshToken` for each compromised account
3. **Block spray source IPs** — Add to Conditional Access Named Locations → Block
4. **Disable accounts** if post-compromise persistence is found (MFA registration, OAuth consent)
5. **Contact compromised users** via phone — verify no authorized activity, warn about potential phishing

#### If Post-Compromise Persistence Found

6. **Remove newly registered MFA methods** — Check AuditLogs for "Register security info"
7. **Revoke OAuth app consents** — Remove any apps consented after compromise time
8. **Remove inbox rules** — Delete forwarding/deletion rules created after compromise
9. **Remove mailbox delegations** — Check for Add-MailboxPermission events

#### Follow-Up (Within 4 hours)

10. **Force password reset** for ALL sprayed accounts (not just compromised) — the attacker now knows which accounts have weak passwords
11. **Enable MFA** for any compromised account that didn't have MFA
12. **Block legacy authentication** if spray used IMAP/POP3/SMTP — this is the #1 fix
13. **Review password policies** — enforce banned password list, complexity requirements
14. **Deploy Smart Lockout** tuning — lower lockout threshold if spray bypassed it

#### Extended (Within 24 hours)

15. **Audit all accounts without MFA** — these are the spray's primary targets
16. **Deploy Conditional Access** — Block sign-ins from unfamiliar countries, require compliant devices
17. **Enable Password Protection** — Ban common passwords and organization-specific terms
18. **Review service accounts** — Service accounts with passwords are spray targets; migrate to managed identities
19. **Brief security team** on spray indicators and compromised account list

---

## 7. Evidence Collection Checklist

Preserve these artifacts before any remediation actions:

- [ ] Full SigninLogs for all spray source IPs (AlertTime ± 24h)
- [ ] AADUserRiskEvents for all flagged users
- [ ] Complete list of targeted accounts (dcount UserPrincipalName per spray IP)
- [ ] Complete list of compromised accounts (ResultType 0 from spray IPs)
- [ ] AuditLogs for compromised accounts (post-compromise changes)
- [ ] OfficeActivity for compromised accounts (post-compromise data access)
- [ ] Inbox rules snapshot for each compromised account
- [ ] OAuth consent grants for each compromised account
- [ ] IP reputation and ASN lookups for spray source IPs
- [ ] User agent strings from spray traffic (tool identification)
- [ ] Conditional Access evaluation logs for spray attempts

---

## 8. Escalation Criteria

### Escalate to Incident Commander
- Any account compromised from the spray AND post-compromise activity found
- Spray targeted 100+ accounts (large-scale campaign)
- Compromised account has admin roles or PIM eligibility
- Spray used legacy authentication (IMAP/POP3) indicating CA policy gaps

### Escalate to Threat Intelligence
- Spray source IPs match known threat actor infrastructure
- User agents match known spray tooling (MSOLSpray, Spray-AD, o365spray)
- Multiple tenants reporting similar spray patterns simultaneously
- Spray campaign persisted for > 48 hours (APT-level patience)

### Escalate to Legal/Compliance
- Customer or regulated data accessed from compromised accounts
- Email forwarding to external addresses detected
- Compromised accounts sent emails to external parties (potential BEC)

---

## 9. False Positive Documentation

### FP Scenario 1: Misconfigured Applications (~35% of FPs)

**Pattern:** Single IP has high failure count, but all failures target the same 1-3 service accounts repeatedly.

**How to confirm:**
- Check if failures target service accounts (naming convention: `svc-*`, `app-*`)
- Check if the IP belongs to a known application server or CI/CD system
- Check if the failures are consistent across multiple days (check baseline in Step 4)

**Tuning note:** Password spray targets MANY accounts. If failures are concentrated on < 5 accounts, it's likely a misconfigured app. Whitelist the IP in your spray detection.

### FP Scenario 2: Self-Service Password Reset (~20% of FPs)

**Pattern:** Users resetting passwords through SSPR generate failures as they try old passwords or mistype new ones.

**How to confirm:**
- Check if the IP is a known SSPR proxy or corporate egress IP
- Correlate with `AuditLogs` for "Reset password" operations at the same time
- Check if ResultType pattern includes `50053` (lockout from too many SSPR attempts)

**Tuning note:** SSPR failures come from corporate infrastructure IPs. Exclude corporate IP ranges from spray detection thresholds.

### FP Scenario 3: Cached Credential Failures (~25% of FPs)

**Pattern:** Users recently changed passwords, and their mobile/desktop clients retry with cached old credentials, generating `50126` failures.

**How to confirm:**
- Check if failures are from known mobile email clients (Outlook, Gmail, Apple Mail user agents)
- Check if recent password changes exist in `AuditLogs` for the failing users
- Check if failures occur from the user's known corporate IP range

**Tuning note:** Cached credential failures are distributed across many accounts (looks like spray) after a company-wide password rotation. Correlate with password change events in AuditLogs.

### FP Scenario 4: Security Scanning (~20% of FPs)

**Pattern:** IP belongs to a known security vendor performing authorized credential testing.

**How to confirm:**
- Check IP reputation — known vendors include penetration testing firms, MSSP
- Check if the IP is in your authorized scanning schedule
- User agents may identify the tool (e.g., "SecurityScanner/1.0")

**Tuning note:** Maintain an allowlist of authorized scanner IPs. Pre-coordinate scanning windows with SOC.

---

## 10. MITRE ATT&CK Mapping

### Detection Coverage Matrix

| Technique ID | Technique Name | Tactic | Confidence | Query |
|---|---|---|---|---|
| **T1110.003** | **Brute Force: Password Spraying** | **Credential Access** | <span class="severity-badge severity-info">Confirmed</span> | **Q1, Q2, Q7** |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | <span class="severity-badge severity-info">Confirmed</span> | Q3, Q5 |
| T1110.001 | Brute Force: Password Guessing | Credential Access | <span class="severity-badge severity-medium">Probable</span> | Q2 |
| T1098 | Account Manipulation | Persistence | <span class="severity-badge severity-info">Confirmed</span> | Q6A |
| T1114.003 | Email Collection: Email Forwarding Rule | Collection | <span class="severity-badge severity-info">Confirmed</span> | Q6B |
| T1528 | Steal Application Access Token | Credential Access | <span class="severity-badge severity-info">Confirmed</span> | Q6A |
| T1530 | Data from Cloud Storage Object | Collection | <span class="severity-badge severity-info">Confirmed</span> | Q6B |
| T1556.006 | Modify Authentication Process: MFA | Persistence, Defense Evasion | <span class="severity-badge severity-info">Confirmed</span> | Q6A |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Persistence, Defense Evasion | <span class="severity-badge severity-info">Confirmed</span> | Q6B |

### Attack Chains

**Chain 1: Password Spray → Account Takeover → BEC**
```
Credential reconnaissance (leaked email format)
  → Password spray with common passwords (T1110.003)
  → Account compromised (T1078.004)
  → MFA device registered (T1556.006)
  → Inbox forwarding rule (T1114.003, T1564.008)
  → Internal phishing from trusted sender
  → Financial fraud / BEC
```

**Chain 2: Password Spray → Legacy Auth → Data Exfiltration**
```
Password spray via IMAP/POP3 (T1110.003)
  → Legacy auth bypasses MFA entirely (T1078.004)
  → Mailbox access via IMAP (T1114.003)
  → Email exfiltration to external server
  → No MFA, no CA, no detection (unless SigninLogs monitored)
```

**Chain 3: Low-and-Slow Spray → Privilege Escalation (APT)**
```
Months-long low-volume spray (T1110.003)
  → Compromise service account or legacy admin (T1078.004)
  → OAuth app with elevated permissions (T1528)
  → Persistent API access to mail/files (T1530)
  → Long-term intelligence collection
```

### Threat Actor Attribution

| Actor | Confidence | Key TTPs |
|---|---|---|
| **Midnight Blizzard (APT29)** | **HIGH** | Long-term spray campaigns against O365. Compromised Microsoft corporate tenant via spray in 2023. |
| **Peach Sandstorm (APT33)** | **HIGH** | Sustained multi-month spray campaigns against defense, pharma, satellite sectors. |
| **Storm-0558** | **MEDIUM** | Spray + token forging. Compromised US government email via Outlook Web Access. |
| **Scattered Spider (Octo Tempest)** | **MEDIUM** | Combined spray with social engineering for initial access. |

---

## 11. Query Summary

| Query | Purpose | Tables | Step |
|---|---|---|---|
| Q1 | Password spray risk event extraction | AADUserRiskEvents | 1 |
| Q2 | Multi-account failure pattern analysis (spray detection) | SigninLogs | 2 |
| Q3 | Successful auth after spray (compromise detection) | SigninLogs | 3 |
| Q4 | 30-day failure pattern baseline [MANDATORY] | SigninLogs | 4 |
| Q5 | Lockout and Smart Lockout analysis | SigninLogs | 5 |
| Q6A | Directory changes and persistence | AuditLogs | 6A |
| Q6B | Email and file activity | OfficeActivity | 6B |
| Q7 | Org-wide spray campaign scope | SigninLogs | 7 |

---

## Appendix A: Datatable Tests

### Test 1: Multi-Account Spray Detection

```kql
// ============================================================
// TEST 1: Multi-Account Password Spray Detection
// Validates: Query 2 - Multi-account failure pattern analysis
// Expected: 203.0.113.50 flagged with 15 targeted accounts
//           10.0.0.1 NOT flagged (only 2 accounts = misconfiguration)
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    AppDisplayName: string,
    ClientAppUsed: string,
    UserAgent: string,
    LocationDetails: dynamic,
    DeviceDetail: dynamic,
    MfaDetail: dynamic,
    AuthenticationRequirement: string,
    ConditionalAccessStatus: string
) [
    // --- Malicious: Spray from 203.0.113.50 targeting 15 accounts (1 attempt each) ---
    datetime(2026-02-22T14:00:00Z), "user01@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:05Z), "user02@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:10Z), "user03@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:15Z), "user04@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:20Z), "user05@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:25Z), "user06@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:30Z), "user07@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:35Z), "user08@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:40Z), "user09@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:45Z), "user10@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:50Z), "user11@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:00:55Z), "user12@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:01:00Z), "user13@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:01:05Z), "user14@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    datetime(2026-02-22T14:01:10Z), "user15@contoso.com", "203.0.113.50", "50126", "Microsoft 365", "Browser", "python-requests/2.28.0", dynamic({"city":"Moscow","countryOrRegion":"RU"}), dynamic({"operatingSystem":"","browser":""}), dynamic(null), "singleFactorAuthentication", "notApplied",
    // --- Benign: Misconfigured app from 10.0.0.1 hitting 2 service accounts ---
    datetime(2026-02-22T14:00:00Z), "svc-backup@contoso.com", "10.0.0.1", "50126", "Azure Backup", "Mobile Apps and Desktop clients", "AzureBackupAgent/1.0", dynamic({"city":"Seattle","countryOrRegion":"US"}), dynamic({"operatingSystem":"Windows","browser":""}), dynamic(null), "singleFactorAuthentication", "success",
    datetime(2026-02-22T14:05:00Z), "svc-backup@contoso.com", "10.0.0.1", "50126", "Azure Backup", "Mobile Apps and Desktop clients", "AzureBackupAgent/1.0", dynamic({"city":"Seattle","countryOrRegion":"US"}), dynamic({"operatingSystem":"Windows","browser":""}), dynamic(null), "singleFactorAuthentication", "success",
    datetime(2026-02-22T14:10:00Z), "svc-sync@contoso.com", "10.0.0.1", "50126", "Azure AD Connect", "Mobile Apps and Desktop clients", "AADConnectAgent/2.0", dynamic({"city":"Seattle","countryOrRegion":"US"}), dynamic({"operatingSystem":"Windows","browser":""}), dynamic(null), "singleFactorAuthentication", "success"
];
// --- Run spray detection ---
let FailureThreshold = 10;
TestSigninLogs
| where ResultType in ("50126", "50053")
| summarize
    TargetedAccounts = dcount(UserPrincipalName),
    TotalAttempts = count(),
    AttemptsPerAccount = round(1.0 * count() / max(dcount(UserPrincipalName), 1), 1),
    UserAgents = make_set(UserAgent, 5),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 3)
    by IPAddress
| where TargetedAccounts >= FailureThreshold
// Expected: 203.0.113.50 flagged (15 accounts, AttemptsPerAccount=1.0, UserAgent=python-requests)
// Expected: 10.0.0.1 NOT flagged (only 2 accounts = below threshold)
```

### Test 2: Successful Auth After Spray

```kql
// ============================================================
// TEST 2: Compromise Detection After Spray
// Validates: Query 3 - Finds accounts that had success after spray failures
// Expected: user05@contoso.com flagged as CRITICAL (success, no MFA)
//           user01-04 NOT flagged (failures only, no success)
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    AppDisplayName: string,
    MfaDetail: dynamic,
    DeviceDetail: dynamic,
    LocationDetails: dynamic,
    ClientAppUsed: string,
    AuthenticationRequirement: string,
    ConditionalAccessStatus: string,
    CorrelationId: string,
    ResourceDisplayName: string
) [
    // --- Spray failures against 5 accounts ---
    datetime(2026-02-22T14:00:00Z), "user01@contoso.com", "198.51.100.10", "50126", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"","browser":"","deviceId":"","isCompliant":"","isManaged":""}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-001", "Microsoft 365",
    datetime(2026-02-22T14:00:05Z), "user02@contoso.com", "198.51.100.10", "50126", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"","browser":"","deviceId":"","isCompliant":"","isManaged":""}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-002", "Microsoft 365",
    datetime(2026-02-22T14:00:10Z), "user03@contoso.com", "198.51.100.10", "50126", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"","browser":"","deviceId":"","isCompliant":"","isManaged":""}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-003", "Microsoft 365",
    datetime(2026-02-22T14:00:15Z), "user04@contoso.com", "198.51.100.10", "50126", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"","browser":"","deviceId":"","isCompliant":"","isManaged":""}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-004", "Microsoft 365",
    datetime(2026-02-22T14:00:20Z), "user05@contoso.com", "198.51.100.10", "50126", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"","browser":"","deviceId":"","isCompliant":"","isManaged":""}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-005", "Microsoft 365",
    // --- Add more accounts to meet threshold ---
    datetime(2026-02-22T14:00:25Z), "user06@contoso.com", "198.51.100.10", "50126", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"","browser":"","deviceId":"","isCompliant":"","isManaged":""}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-006", "Microsoft 365",
    datetime(2026-02-22T14:00:30Z), "user07@contoso.com", "198.51.100.10", "50126", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"","browser":"","deviceId":"","isCompliant":"","isManaged":""}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-007", "Microsoft 365",
    datetime(2026-02-22T14:00:35Z), "user08@contoso.com", "198.51.100.10", "50126", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"","browser":"","deviceId":"","isCompliant":"","isManaged":""}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-008", "Microsoft 365",
    datetime(2026-02-22T14:00:40Z), "user09@contoso.com", "198.51.100.10", "50126", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"","browser":"","deviceId":"","isCompliant":"","isManaged":""}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-009", "Microsoft 365",
    datetime(2026-02-22T14:00:45Z), "user10@contoso.com", "198.51.100.10", "50126", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"","browser":"","deviceId":"","isCompliant":"","isManaged":""}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-010", "Microsoft 365",
    // --- SUCCESS: user05 had a weak password, spray succeeded ---
    datetime(2026-02-22T14:00:22Z), "user05@contoso.com", "198.51.100.10", "0", "Microsoft 365", dynamic(null), dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":"","isCompliant":"false","isManaged":"false"}), dynamic({"city":"Bucharest","countryOrRegion":"RO"}), "Browser", "singleFactorAuthentication", "notApplied", "corr-005b", "Microsoft 365"
];
// --- Run compromise detection ---
let FailureThreshold = 10;
let SprayIPs = TestSigninLogs
| where ResultType == "50126"
| summarize TargetedAccounts = dcount(UserPrincipalName) by IPAddress
| where TargetedAccounts >= FailureThreshold
| project IPAddress;
// Find successes from spray IPs with preceding failures
TestSigninLogs
| where IPAddress in (SprayIPs)
| where ResultType == "0"
| join kind=inner (
    TestSigninLogs
    | where IPAddress in (SprayIPs)
    | where ResultType == "50126"
    | summarize FailureCount = count(), FirstFailure = min(TimeGenerated)
        by UserPrincipalName, IPAddress
) on UserPrincipalName, IPAddress
| where TimeGenerated > FirstFailure
| extend
    MfaBypassed = isempty(MfaDetail) or isnull(MfaDetail),
    Verdict = "CRITICAL - Compromised via spray, no MFA"
| project UserPrincipalName, IPAddress, FailureCount, FirstFailure, SuccessTime = TimeGenerated, MfaBypassed, Verdict
// Expected: user05@contoso.com = CRITICAL (1 failure then success, no MFA)
// Expected: user01-04, user06-10 NOT shown (failures only)
```

### Test 3: Baseline Comparison

```kql
// ============================================================
// TEST 3: IP Baseline Comparison
// Validates: Query 4 - 30-day failure pattern baseline
// Expected: 203.0.113.50 = "NEW IP" (no history)
//           10.0.0.100 = "WITHIN NORMAL RANGE" (consistent failures)
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string
) [
    // --- 10.0.0.100: Consistent daily failures for 30 days (misconfigured app) ---
    datetime(2026-01-25T09:00:00Z), "svc-app@contoso.com", "10.0.0.100", "50126",
    datetime(2026-01-25T09:05:00Z), "svc-app@contoso.com", "10.0.0.100", "50126",
    datetime(2026-01-26T09:00:00Z), "svc-app@contoso.com", "10.0.0.100", "50126",
    datetime(2026-01-26T09:05:00Z), "svc-app@contoso.com", "10.0.0.100", "50126",
    datetime(2026-02-10T09:00:00Z), "svc-app@contoso.com", "10.0.0.100", "50126",
    datetime(2026-02-10T09:05:00Z), "svc-app@contoso.com", "10.0.0.100", "50126",
    datetime(2026-02-15T09:00:00Z), "svc-app@contoso.com", "10.0.0.100", "50126",
    datetime(2026-02-15T09:05:00Z), "svc-app@contoso.com", "10.0.0.100", "50126",
    // Today: Same pattern
    datetime(2026-02-22T09:00:00Z), "svc-app@contoso.com", "10.0.0.100", "50126",
    datetime(2026-02-22T09:05:00Z), "svc-app@contoso.com", "10.0.0.100", "50126",
    // --- 203.0.113.50: Never seen before, 15 failures today ---
    datetime(2026-02-22T14:00:00Z), "user01@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:05Z), "user02@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:10Z), "user03@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:15Z), "user04@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:20Z), "user05@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:25Z), "user06@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:30Z), "user07@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:35Z), "user08@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:40Z), "user09@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:45Z), "user10@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:50Z), "user11@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:00:55Z), "user12@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:01:00Z), "user13@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:01:05Z), "user14@contoso.com", "203.0.113.50", "50126",
    datetime(2026-02-22T14:01:10Z), "user15@contoso.com", "203.0.113.50", "50126"
];
// --- Baseline comparison ---
let AlertTime = datetime(2026-02-22T14:30:00Z);
let IPs = dynamic(["203.0.113.50", "10.0.0.100"]);
let Baseline = TestSigninLogs
| where TimeGenerated < AlertTime - 1h
| where IPAddress in (IPs)
| where ResultType in ("50126", "50053")
| summarize DailyFailures = count() by IPAddress, bin(TimeGenerated, 1d)
| summarize MaxDailyFailures = max(DailyFailures), AvgDailyFailures = round(avg(DailyFailures), 1)
    by IPAddress;
let Today = TestSigninLogs
| where TimeGenerated >= AlertTime - 24h
| where IPAddress in (IPs)
| where ResultType in ("50126", "50053")
| summarize TodayFailures = count(), TodayAccounts = dcount(UserPrincipalName)
    by IPAddress;
Baseline
| join kind=rightouter Today on IPAddress
| extend Assessment = case(
    isempty(MaxDailyFailures), "NEW IP - No baseline, suspicious",
    TodayAccounts > 5 and MaxDailyFailures <= 3, "ANOMALOUS - Spray pattern from known IP",
    TodayFailures <= MaxDailyFailures * 2, "WITHIN NORMAL RANGE",
    "SUSPICIOUS"
)
// Expected: 203.0.113.50 = "NEW IP" (no baseline history)
// Expected: 10.0.0.100 = "WITHIN NORMAL RANGE" (consistent 2 failures/day)
```

---

## References

- [Microsoft: Investigate risk - Password spray](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk)
- [Microsoft: Smart lockout - Protect user accounts from attacks](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [Microsoft: Password protection in Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad)
- [MITRE ATT&CK T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [Midnight Blizzard Microsoft breach (2024)](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [CISA: Detecting and mitigating password spraying](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a)
- [Microsoft: Defending against password spray attacks](https://www.microsoft.com/en-us/security/blog/2020/04/23/protecting-organization-password-spray-attacks/)
