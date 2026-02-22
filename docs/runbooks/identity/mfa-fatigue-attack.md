---
title: "MFA Fatigue Attack"
id: RB-0005
severity: high
status: reviewed
description: >
  Investigation runbook for Microsoft Entra ID Identity Protection
  MFA fatigue (push spam / MFA bombing) detection. Covers repeated MFA
  denial pattern analysis, denial-then-approval pivot detection, temporal
  burst analysis, and post-approval blast radius assessment. The attacker
  already has valid credentials — the investigation starts from MFA, not
  from credential compromise.
mitre_attack:
  tactics:
    - tactic_id: TA0001
      tactic_name: "Initial Access"
    - tactic_id: TA0003
      tactic_name: "Persistence"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
    - tactic_id: TA0006
      tactic_name: "Credential Access"
    - tactic_id: TA0008
      tactic_name: "Lateral Movement"
    - tactic_id: TA0009
      tactic_name: "Collection"
  techniques:
    - technique_id: T1621
      technique_name: "Multi-Factor Authentication Request Generation"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
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
    - technique_id: T1534
      technique_name: "Internal Spearphishing"
      confidence: confirmed
    - technique_id: T1530
      technique_name: "Data from Cloud Storage Object"
      confidence: confirmed
threat_actors:
  - "Scattered Spider (Octo Tempest)"
  - "LAPSUS$ (DEV-0537)"
  - "Storm-0875"
  - "Midnight Blizzard (APT29)"
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
category: identity
key_log_sources:
  - SigninLogs
  - AADUserRiskEvents
  - AADRiskyUsers
  - AADNonInteractiveUserSignInLogs
  - AuditLogs
  - OfficeActivity
tactic_slugs:
  - initial-access
  - persistence
  - defense-evasion
  - cred-access
  - lateral-movement
  - collection
data_checks:
  - query: "SigninLogs | take 1"
    label: primary
    description: "MFA denial pattern analysis"
  - query: "AADUserRiskEvents | take 1"
    description: "For <code>mfaFraud</code> risk events (may be empty if fraud reporting not configured)"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "For post-approval token tracking"
  - query: "OfficeActivity | take 1"
    description: "For blast radius assessment"
  - query: "AuditLogs | take 1"
    description: "For persistence detection"
---

# MFA Fatigue Attack - Investigation Runbook

> **RB-0005** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Identity Protection + SigninLogs Pattern Analysis
>
> **Risk Detection Name:** `mfaFraud` + ResultType `500121` pattern
>
> **Primary MITRE Technique:** T1621 - Multi-Factor Authentication Request Generation

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Extract MFA Fraud Risk Event](#step-1-extract-mfa-fraud-risk-event)
   - [Step 2: MFA Denial Pattern Analysis](#step-2-mfa-denial-pattern-analysis)
   - [Step 3: Denial-Then-Approval Detection](#step-3-denial-then-approval-detection)
   - [Step 4: Baseline Comparison - Establish Normal MFA Behavior](#step-4-baseline-comparison---establish-normal-mfa-behavior)
   - [Step 5: Post-Approval Session Analysis](#step-5-post-approval-session-analysis)
   - [Step 6: Analyze Post-Approval Activity (Blast Radius Assessment)](#step-6-analyze-post-approval-activity-blast-radius-assessment)
   - [Step 7: Org-Wide MFA Bombing Campaign Detection](#step-7-org-wide-mfa-bombing-campaign-detection)
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
MFA fatigue (also called MFA bombing or MFA push spam) is detected through two complementary mechanisms:

1. **Identity Protection `mfaFraud` risk event:** Fires when a user reports fraud through the Microsoft Authenticator app by denying the push notification and selecting "No, it's not me" or when an admin has configured fraud alert. This creates a `mfaFraud` entry in AADUserRiskEvents.
2. **SigninLogs pattern analysis:** Detected by looking for repeated MFA denial events (ResultType `500121`) for a single user within a short time window. This is the more reliable detection because most users simply deny the push rather than explicitly reporting fraud.

**Why it matters:**
MFA fatigue is a post-credential-compromise technique. **The attacker already has the user's password.** They are repeatedly triggering MFA push notifications hoping the user will approve out of annoyance, confusion, or because they mistake the notification for a legitimate authentication prompt. This technique was popularized by the Scattered Spider (Octo Tempest) group, which combined MFA bombing with social engineering calls to IT helpdesks, and by the LAPSUS$ group, which used it against major technology companies including Microsoft, Okta, and Uber.

**Why this is HIGH severity (unlike the Medium-severity identity alerts):**
- The attacker has already compromised the password — this is not speculative, it's confirmed credential compromise
- If the user approves even ONE push, the attacker gains full authenticated access
- Scattered Spider specifically targets high-value accounts (IT admins, executives) with this technique
- The attacks often happen at night or early morning when users are groggy and more likely to approve accidentally
- Once approved, attackers typically move extremely fast — inbox rules, OAuth consent, and data exfiltration within minutes

**However:** This alert has a **moderate false positive rate** (~20-30%). Legitimate triggers include:
- Users with phone connectivity issues causing MFA to fail, then retrying multiple times
- MFA method enrollment or migration causing repeated challenges
- Users accidentally denying a legitimate push and immediately retrying
- Poor cell coverage in buildings, tunnels, or rural areas causing authentication timeouts
- App updates or OS updates causing temporary Authenticator failures
- Users with multiple devices receiving pushes on the wrong device

**Worst case scenario if this is real:**
An attacker has the user's password (obtained via phishing, credential stuffing, info-stealer malware, or dark web purchase) and is MFA bombing them until they approve. Once approved, the attacker has full authenticated access to all cloud resources the user can reach. Scattered Spider is known to immediately register their own MFA device, set up email forwarding rules, grant OAuth app permissions, and begin internal phishing — all within the first 10 minutes after gaining access. If the compromised user is an IT admin or has elevated privileges (PIM-eligible roles), the blast radius can include the entire tenant.

**Key difference from RB-0001, RB-0002, RB-0003, and RB-0004:**
- RB-0001 (Unfamiliar Sign-In Properties): Detects unusual device/location. The sign-in may have already succeeded.
- RB-0002 (Impossible Travel): Detects geographically impossible sign-in pairs. Requires two locations.
- RB-0003 (Leaked Credentials): Offline detection — credentials found on dark web. No sign-in has occurred yet.
- RB-0004 (Anonymous IP Address): Sign-in from anonymizing infrastructure. IP is the focus.
- **RB-0005 (This runbook):** The attacker ALREADY HAS the password. The investigation focuses on **MFA denial patterns and timing**, not on the sign-in properties. The critical question is: **"Did the user eventually approve after repeated denials?"** The unique steps are: MFA denial burst detection, denial-then-approval pivot analysis, and time-of-day correlation. This is the only runbook where confirmed credential compromise is the *starting point*, not the conclusion.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID P2 + Microsoft 365 E3 + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID, Office 365
- **Permissions:** Security Reader (investigation), Security Operator (containment)
- **MFA Configuration:** Push notifications enabled via Microsoft Authenticator

### Recommended for Full Coverage
- **License:** Microsoft 365 E5 + Sentinel
- **Additional:** MFA fraud alert enabled in Entra ID Authentication Methods policy
- **Number Matching:** Enabled in Authenticator (significantly reduces MFA fatigue success)

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

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
let TargetUser = "user@contoso.com";       // UPN from the alert
let AlertTime = datetime(2026-02-22T03:15:00Z);  // Time the MFA bombing was detected
let LookbackWindow = 4h;                   // Window before alert to look for denial patterns
let ForwardWindow = 4h;                    // Window after alert to check for approval + blast radius
let BaselineDays = 30d;                    // Baseline comparison window
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- User reports MFA fraud via Authenticator AND successful sign-in occurred after denials
- >= 10 MFA denials in 5 minutes followed by successful authentication
- MFA bombing at night (00:00-06:00 local time) with eventual approval
- Multiple users being MFA bombed simultaneously from same IP range
- User called helpdesk reporting suspicious MFA prompts AND account shows approval

### Standard Investigation
- User has 3-9 MFA denials in a short window, no subsequent approval
- MFA denials from unfamiliar IP but user did not approve
- Single burst of MFA denials during business hours

### Likely Benign
- 2-3 MFA denials followed by successful authentication on same device/IP within 5 minutes
- User's normal pattern includes occasional MFA denials (check baseline)
- MFA denials during known Authenticator update/migration window
- MFA denials from user's known home or office IP

---

## 5. Investigation Steps

### Step 1: Extract MFA Fraud Risk Event

**Purpose:** Check if Identity Protection detected an `mfaFraud` risk event. This confirms the user explicitly reported fraud via the Authenticator app. Note: This step may return empty if the user simply denied the push without reporting fraud — proceed to Step 2 regardless.

**Data needed:** AADUserRiskEvents, SigninLogs

```kql
// ============================================================
// QUERY 1: MFA Fraud Risk Event Extraction
// Purpose: Extract mfaFraud risk events and correlate with sign-in attempts
// Tables: AADUserRiskEvents, SigninLogs
// Investigation Step: 1 - Extract MFA Fraud Risk Event
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T03:15:00Z);
let LookbackWindow = 24h;
// --- Risk event extraction ---
AADUserRiskEvents
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where UserPrincipalName =~ TargetUser
| where RiskEventType == "mfaFraud"
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
    CorrelationId,
    AdditionalInfo = tostring(AdditionalInfo)
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
    | where UserPrincipalName =~ TargetUser
    | project
        SigninTime = TimeGenerated,
        CorrelationId,
        IPAddress,
        AppDisplayName,
        ResultType,
        ResultDescription,
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), "N/A"),
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        Browser = tostring(DeviceDetail.browser),
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        ClientApp = ClientAppUsed,
        AuthRequirement = AuthenticationRequirement,
        ConditionalAccessStatus
) on CorrelationId
| project-away CorrelationId1
| sort by RiskEventTime desc
```

**Performance Notes:**
- The `mfaFraud` risk event only fires when the user actively reports fraud, not from every denial
- If this query returns no results, it does NOT mean there was no MFA fatigue — proceed to Step 2
- The CorrelationId join links the risk event to the specific sign-in attempt

**Tuning Guidance:**
- Extend LookbackWindow to 48h if investigating older alerts
- If AADUserRiskEvents is empty, your environment may not have fraud reporting configured — rely on Step 2 pattern detection instead

**Expected findings:**
- If populated: Shows the exact sign-in that triggered the fraud report, including IP, location, device, and app
- If empty: No fraud was reported — this is common. The user may have simply denied pushes without reporting

**Next action:**
- If risk event found → Note the IP, time, and correlation details for subsequent queries
- If empty → Proceed to Step 2 (MFA denial pattern analysis) as the primary detection method

---

### Step 2: MFA Denial Pattern Analysis

**Purpose:** Detect MFA fatigue bombing by finding burst patterns of MFA denials (ResultType `500121`) for the target user. This is the **primary detection query** for MFA fatigue — more reliable than the mfaFraud risk event.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 2: MFA Denial Pattern Analysis
// Purpose: Detect burst patterns of MFA denials indicating MFA bombing
// Tables: SigninLogs
// Investigation Step: 2 - MFA Denial Pattern Analysis
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T03:15:00Z);
let LookbackWindow = 4h;
// --- MFA denial burst detection ---
let MfaDenials = SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 2h)
| where UserPrincipalName =~ TargetUser
| where ResultType in ("500121", "50074", "50076")  // MFA denied, MFA required, MFA not satisfied
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    ResultType,
    ResultDescription = case(
        ResultType == "500121", "MFA denied by user",
        ResultType == "50074", "Strong auth required",
        ResultType == "50076", "MFA required not satisfied",
        ResultType
    ),
    MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
    MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), "N/A"),
    AppDisplayName,
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    UserAgent,
    CorrelationId,
    ConditionalAccessStatus,
    AuthRequirement = AuthenticationRequirement;
// --- Summarize burst patterns (5-minute windows) ---
let BurstAnalysis = MfaDenials
| summarize
    DenialsIn5Min = countif(ResultType == "500121"),
    MfaChallenges = count(),
    FirstDenial = min(TimeGenerated),
    LastDenial = max(TimeGenerated),
    SourceIPs = make_set(IPAddress),
    SourceIPCount = dcount(IPAddress),
    Apps = make_set(AppDisplayName),
    MfaMethods = make_set(MfaAuthMethod)
    by UserPrincipalName, Bin5Min = bin(TimeGenerated, 5m);
// --- Flag suspicious burst patterns ---
BurstAnalysis
| extend
    BurstDuration = LastDenial - FirstDenial,
    RiskAssessment = case(
        DenialsIn5Min >= 10, "CRITICAL - Aggressive MFA bombing",
        DenialsIn5Min >= 5, "HIGH - Sustained MFA fatigue attack",
        DenialsIn5Min >= 3, "MEDIUM - Possible MFA fatigue",
        "LOW - Isolated denials"
    )
| where DenialsIn5Min >= 3  // Threshold for suspicious activity
| sort by Bin5Min asc
```

**Performance Notes:**
- ResultType `500121` is THE golden indicator for MFA denied by user
- Bin by 5 minutes to detect rapid burst patterns; also consider 1-hour windows for slower attacks
- SourceIPCount > 1 is unusual — typically the attacker uses one IP for all attempts

**Tuning Guidance:**
- Adjust threshold from 3 to 5 if your org has high MFA failure noise
- For environments with number matching enabled, MFA fatigue attacks are rare — lower threshold to 2
- Add `| where ResultType == "500121"` only (removing 50074, 50076) for stricter detection

**Expected findings:**
- 5-minute bins with 3+ MFA denials indicate MFA bombing
- Look at the SourceIPs — consistent single IP suggests automated attack
- Check if apps are consistent — attackers typically target one app (usually Exchange Online or Microsoft 365)
- MfaMethods should show "PhoneAppNotification" (push) — fatigue attacks target push notifications, not OTP

**Next action:**
- If bursts found → Proceed to Step 3 to check if user eventually approved
- If no bursts → MFA fatigue unlikely; check if this is a regular denied-then-retry pattern (FP)

---

### Step 3: Denial-Then-Approval Detection

**Purpose:** The **critical pivot point** of this investigation. Check if a successful MFA authentication (ResultType `0`) occurred AFTER the MFA denial burst. If yes, the MFA fatigue attack likely **succeeded** and the attacker gained access.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 3: Denial-Then-Approval Detection
// Purpose: Detect if MFA was eventually approved after denial bursts
// Tables: SigninLogs
// Investigation Step: 3 - Denial-Then-Approval Detection
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T03:15:00Z);
let LookbackWindow = 4h;
let ForwardWindow = 4h;
// --- Get all MFA-related sign-in events in timeline ---
let MfaTimeline = SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + ForwardWindow)
| where UserPrincipalName =~ TargetUser
| where ResultType in ("500121", "50074", "50076", "0", "50140")
    // 500121 = MFA denied, 50074 = MFA required, 50076 = MFA not satisfied,
    // 0 = success, 50140 = keep me signed in interrupt
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    ResultType,
    EventType = case(
        ResultType == "500121", "MFA_DENIED",
        ResultType == "50074", "MFA_CHALLENGED",
        ResultType == "50076", "MFA_NOT_SATISFIED",
        ResultType == "0", "SUCCESS",
        ResultType == "50140", "KMSI_INTERRUPT",
        "OTHER"
    ),
    MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
    MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), "N/A"),
    AppDisplayName,
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    DeviceId = tostring(DeviceDetail.deviceId),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged),
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    ClientApp = ClientAppUsed,
    CorrelationId
| sort by TimeGenerated asc;
// --- Detect denial-then-approval pattern ---
let DenialCount = MfaTimeline
| where EventType == "MFA_DENIED"
| summarize
    TotalDenials = count(),
    FirstDenial = min(TimeGenerated),
    LastDenial = max(TimeGenerated),
    DenialIPs = make_set(IPAddress)
    by UserPrincipalName;
let FirstApproval = MfaTimeline
| where EventType == "SUCCESS"
| summarize
    ApprovalTime = min(TimeGenerated),
    ApprovalIP = take_any(IPAddress),
    ApprovalDevice = take_any(DeviceOS),
    ApprovalBrowser = take_any(Browser),
    ApprovalDeviceId = take_any(DeviceId),
    ApprovalApp = take_any(AppDisplayName),
    ApprovalCity = take_any(City),
    ApprovalCountry = take_any(Country),
    ApprovalIsManaged = take_any(IsManaged)
    by UserPrincipalName;
// --- Join denial and approval data ---
DenialCount
| join kind=leftouter FirstApproval on UserPrincipalName
| extend
    ApprovalAfterDenials = isnotempty(ApprovalTime) and ApprovalTime > FirstDenial,
    TimeToApproval = iff(isnotempty(ApprovalTime), ApprovalTime - LastDenial, timespan(0)),
    ApprovalFromDifferentIP = iff(isnotempty(ApprovalIP), not(set_has_element(DenialIPs, ApprovalIP)), false),
    Verdict = case(
        isempty(ApprovalTime), "DEFENSE HELD - No approval after denials",
        ApprovalTime < FirstDenial, "PRE-EXISTING SESSION - Approval before denials",
        TotalDenials >= 5 and isnotempty(ApprovalTime) and ApprovalTime > LastDenial, "LIKELY COMPROMISED - Approval after sustained bombing",
        TotalDenials >= 3 and isnotempty(ApprovalTime) and ApprovalTime > LastDenial, "POSSIBLY COMPROMISED - Approval after multiple denials",
        "INVESTIGATE FURTHER"
    )
| project
    UserPrincipalName,
    TotalDenials,
    FirstDenial,
    LastDenial,
    DenialIPs,
    ApprovalTime,
    TimeToApproval,
    ApprovalIP,
    ApprovalDevice,
    ApprovalBrowser,
    ApprovalCity,
    ApprovalCountry,
    ApprovalIsManaged,
    ApprovalFromDifferentIP,
    Verdict
```

**Performance Notes:**
- The self-join approach is lightweight because it's already filtered to a single user
- `set_has_element` checks if the approval IP matches any of the denial IPs — a mismatch is highly suspicious
- TimeToApproval close to 0 (< 2 minutes) after last denial suggests immediate user surrender

**Tuning Guidance:**
- If `ApprovalFromDifferentIP` is true AND approval device is unmanaged → extremely high confidence compromise
- If `ApprovalFromDifferentIP` is false AND approval is from managed device → may be legitimate retry
- Adjust the 5-denial threshold for "LIKELY COMPROMISED" based on your org's MFA noise

**Expected findings:**
- **"DEFENSE HELD"**: User denied all pushes and never approved — credential compromise is confirmed but access was blocked. Reset password, investigate how credentials were obtained.
- **"LIKELY COMPROMISED"**: 5+ denials followed by approval — high probability the user caved to fatigue. Proceed to Step 5 for session and blast radius analysis.
- **"POSSIBLY COMPROMISED"**: 3-4 denials then approval — could be fatigue or legitimate retry. Check approval device/IP match.
- **"PRE-EXISTING SESSION"**: The approval happened before the denials — the denials may be a different event.

**Next action:**
- If "DEFENSE HELD" → Password is compromised. Reset immediately. Skip Steps 5-6 (no post-access activity). Investigate credential source.
- If "LIKELY COMPROMISED" or "POSSIBLY COMPROMISED" → Proceed to Steps 4-6 for full analysis
- Review the full MFA timeline for the user by running `MfaTimeline` without the aggregation

---

### Step 4: Baseline Comparison - Establish Normal MFA Behavior

**Purpose:** Establish what "normal" MFA behavior looks like for this user over 30 days. Compare the current MFA denial pattern against the baseline to determine if this activity is truly anomalous. **This step is MANDATORY per project quality standards.**

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 4: Baseline Comparison - Normal MFA Behavior Pattern
// Purpose: Establish 30-day MFA behavior baseline for the affected user
// Tables: SigninLogs
// Investigation Step: 4 - Baseline Comparison [MANDATORY]
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T03:15:00Z);
let BaselineDays = 30d;
// --- 30-day MFA behavior baseline ---
let MfaBaseline = SigninLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime - 1h)
| where UserPrincipalName =~ TargetUser
| where AuthenticationRequirement == "multiFactorAuthentication"
    or ResultType in ("500121", "50074", "50076")
| extend
    MfaOutcome = case(
        ResultType == "0", "Approved",
        ResultType == "500121", "Denied",
        ResultType == "50074", "Challenged",
        ResultType == "50076", "NotSatisfied",
        "Other"
    ),
    HourOfDay = hourofday(TimeGenerated),
    DayOfWeek = dayofweek(TimeGenerated),
    IsBusinessHours = hourofday(TimeGenerated) between (8 .. 18),
    MfaMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A");
// --- Daily MFA summary ---
let DailyBaseline = MfaBaseline
| summarize
    TotalMfaChallenges = count(),
    MfaDenials = countif(MfaOutcome == "Denied"),
    MfaApprovals = countif(MfaOutcome == "Approved"),
    UniqueIPs = dcount(IPAddress),
    MfaMethods = make_set(MfaMethod)
    by UserPrincipalName, Day = bin(TimeGenerated, 1d);
// --- Aggregate baseline statistics ---
DailyBaseline
| summarize
    BaselineDays_Observed = dcount(Day),
    AvgDailyMfaChallenges = round(avg(TotalMfaChallenges), 1),
    AvgDailyDenials = round(avg(MfaDenials), 1),
    MaxDailyDenials = max(MfaDenials),
    TotalDenials_30d = sum(MfaDenials),
    TotalApprovals_30d = sum(MfaApprovals),
    DenialRate = round(100.0 * sum(MfaDenials) / max(sum(TotalMfaChallenges), 1), 1),
    AvgDailyIPs = round(avg(UniqueIPs), 1),
    AllMfaMethods = make_set(MfaMethods)
    by UserPrincipalName
| extend
    BaselineAssessment = case(
        MaxDailyDenials == 0, "User has ZERO MFA denials in 30 days - ANY denial is anomalous",
        MaxDailyDenials <= 2, "User rarely has MFA denials - 3+ denials is anomalous",
        MaxDailyDenials <= 5, "User occasionally has MFA denials - pattern may be normal",
        "User frequently has MFA denials - investigate phone/connectivity issues"
    )
```

**Performance Notes:**
- Focus on `AuthenticationRequirement == "multiFactorAuthentication"` to capture MFA-specific events
- The `MaxDailyDenials` is the key metric — if the user has never had more than 1 denial per day and today has 10, that's a clear anomaly
- `DenialRate` above 10% over 30 days suggests ongoing phone/connectivity issues (potential FP context)

**Tuning Guidance:**
- A user with `MaxDailyDenials == 0` who suddenly has 5+ denials is almost certainly under attack
- A user with `MaxDailyDenials >= 3` regularly may have legitimate phone issues — weight toward FP
- Check `AllMfaMethods` — if user normally uses "PhoneAppOTP" (code) but today's denials are "PhoneAppNotification" (push), the attack is targeting push specifically

**Expected findings:**
- **Strong anomaly**: Baseline shows 0 denials, today shows 5+ → MFA fatigue attack highly likely
- **Moderate anomaly**: Baseline shows 1-2 denials max, today shows 5+ → Suspicious, proceed with investigation
- **Weak anomaly**: Baseline shows regular denials → May be a phone/app issue, but still investigate if burst pattern is present

**Next action:**
- Compare today's denial count against `MaxDailyDenials` from baseline
- If today's count is 3x+ the baseline max → High confidence attack
- Proceed to Step 5 if MFA was approved after denials

---

### Step 5: Post-Approval Session Analysis

**Purpose:** If MFA was eventually approved (from Step 3), analyze the session that was established. Compare the approval session's device, IP, and browser against the denial pattern to determine if the legitimate user approved on their device (user fatigue) or if the attacker approved from a different session (social engineering / device compromise).

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 5: Post-Approval Session Analysis
// Purpose: Analyze the session established after MFA approval
// Tables: SigninLogs
// Investigation Step: 5 - Post-Approval Session Analysis
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T03:15:00Z);
let ForwardWindow = 4h;
// --- All successful sign-ins after MFA denials ---
SigninLogs
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where UserPrincipalName =~ TargetUser
| where ResultType == "0"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    ResourceDisplayName,
    MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
    MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), "N/A"),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    DeviceId = tostring(DeviceDetail.deviceId),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged),
    TrustType = tostring(DeviceDetail.trustType),
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    ClientApp = ClientAppUsed,
    AuthRequirement = AuthenticationRequirement,
    ConditionalAccessStatus,
    CorrelationId,
    UserAgent
| extend
    SessionRisk = case(
        IsManaged == "true" and IsCompliant == "true", "LOW - Managed compliant device",
        IsManaged == "true", "MEDIUM - Managed but not compliant",
        DeviceId == "", "HIGH - Unregistered device",
        "MEDIUM - Registered but unmanaged"
    ),
    TimeOfDay = case(
        hourofday(TimeGenerated) between (0 .. 6), "SUSPICIOUS - Night hours (00:00-06:00)",
        hourofday(TimeGenerated) between (6 .. 9), "MODERATE - Early morning",
        hourofday(TimeGenerated) between (9 .. 18), "NORMAL - Business hours",
        hourofday(TimeGenerated) between (18 .. 22), "MODERATE - Evening",
        "SUSPICIOUS - Late night"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- Focus on the FIRST successful sign-in after the denial burst — this is the most likely attacker session
- Check `DeviceId` — if it matches the user's known device, they approved on their own phone (user fatigue)
- If DeviceId is empty or unknown — the approval came from a new/unregistered device (high risk)

**Tuning Guidance:**
- Time-of-day matters: Approval at 3am local time is far more suspicious than 10am
- Compare the approval IP against the denial IPs from Step 2 — same IP = same attacker session
- If `IsManaged == "true"` and device matches user's known device → The user was fatigued into approving on their own phone, but the session token was issued to the attacker's device

**Expected findings:**
- **High Risk**: Approval from unmanaged/unknown device + different IP + night hours → Attacker gained access
- **Medium Risk**: Approval from user's device but at unusual hour → User was fatigued, attacker has token
- **Low Risk**: Approval from managed device at normal hour + same IP → Likely legitimate retry

**Next action:**
- If high/medium risk → Proceed to Step 6 for blast radius assessment
- If low risk → Cross-check with user via out-of-band communication (phone call, not email/Teams)
- Check non-interactive sign-ins from the same IP after approval (Query 7)

---

### Step 6: Analyze Post-Approval Activity (Blast Radius Assessment)

**Purpose:** If MFA was approved (fatigue succeeded), assess what the attacker did with the access. Check for persistence mechanisms (inbox rules, MFA changes, OAuth consent) and data access (email, files).

#### Step 6A: Directory Changes and Persistence

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 6A: Directory Changes and Persistence
// Purpose: Detect persistence after MFA fatigue approval
// Tables: AuditLogs
// Investigation Step: 6A - Directory Changes Post-Approval
// ============================================================
let TargetUser = "user@contoso.com";
let ApprovalTime = datetime(2026-02-22T03:45:00Z);  // From Step 3 results
let ForwardWindow = 4h;
// --- Post-approval directory changes ---
AuditLogs
| where TimeGenerated between (ApprovalTime .. ApprovalTime + ForwardWindow)
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
| where InitiatedBy has TargetUser
    or tostring(InitiatedBy.user.userPrincipalName) =~ TargetUser
| project
    TimeGenerated,
    OperationName,
    Category,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
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

**Performance Notes:**
- MFA method registration within minutes of a fatigue approval is the #1 persistence indicator
- Scattered Spider typically registers their own phone as an MFA device within 5 minutes of approval
- Check for "Consent to application" with broad permissions (Mail.Read, Files.ReadWrite.All)

**Expected findings:**
- **CRITICAL**: New MFA method registered → Attacker added their own Authenticator device
- **HIGH**: OAuth consent granted → Attacker established persistent API access
- **HIGH**: Role assignment change → Privilege escalation attempt

**Next action:**
- If MFA method registered → Immediate containment: remove the new MFA method, revoke sessions
- If OAuth consent → Revoke the app, remove consent grants
- Proceed to Step 6B for email/file activity

---

#### Step 6B: Email and File Activity

**Data needed:** OfficeActivity

```kql
// ============================================================
// QUERY 6B: Email and File Activity Post-Approval
// Purpose: Detect data access and exfiltration after MFA fatigue approval
// Tables: OfficeActivity
// Investigation Step: 6B - Email/File Activity
// ============================================================
let TargetUser = "user@contoso.com";
let ApprovalTime = datetime(2026-02-22T03:45:00Z);
let ForwardWindow = 4h;
// --- Post-approval email and file activity ---
OfficeActivity
| where TimeGenerated between (ApprovalTime .. ApprovalTime + ForwardWindow)
| where UserId =~ TargetUser
| where Operation in (
    // Email operations
    "MailItemsAccessed", "Send", "SendAs", "SendOnBehalf",
    "New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "Set-Mailbox", "New-TransportRule",
    // File operations
    "FileDownloaded", "FileUploaded", "FileSyncDownloadedFull",
    "FileAccessed", "FileModified", "FileCopied",
    "SharingSet", "AnonymousLinkCreated",
    // Admin operations
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

**Performance Notes:**
- OfficeActivity has up to 60-minute ingestion latency — re-run 2 hours after approval time for complete data
- `ClientIP` includes port numbers; use `extract()` to normalize
- `AffectedItems` may be null for some operations — use `iff(isnotempty(...))` for safe access

**Expected findings:**
- **CRITICAL**: Inbox rules created within minutes of approval → Classic BEC persistence
- **HIGH**: Bulk email access → Attacker reading mailbox for sensitive data
- **HIGH**: Emails sent from the account → Phishing from compromised account

**Next action:**
- If inbox rules found → Run Step 6C for deep dive on rule parameters
- If email sent → Identify recipients and notify them of potential phishing
- If file downloads → Identify what was accessed and assess data sensitivity

---

#### Step 6C: Inbox Rule Deep Dive

**Data needed:** OfficeActivity

```kql
// ============================================================
// QUERY 6C: Inbox Rule Deep Dive
// Purpose: Extract and classify inbox rule parameters for malicious patterns
// Tables: OfficeActivity
// Investigation Step: 6C - Inbox Rule Deep Dive
// ============================================================
let TargetUser = "user@contoso.com";
let ApprovalTime = datetime(2026-02-22T03:45:00Z);
let ForwardWindow = 4h;
// --- Inbox rule parameter extraction ---
OfficeActivity
| where TimeGenerated between (ApprovalTime .. ApprovalTime + ForwardWindow)
| where UserId =~ TargetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| mv-expand Parameter = parse_json(Parameters)
| summarize
    RuleParams = make_bag(pack(tostring(Parameter.Name), tostring(Parameter.Value)))
    by TimeGenerated, UserId, Operation, CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
| extend
    RuleName = tostring(RuleParams["Name"]),
    ForwardTo = tostring(RuleParams["ForwardTo"]),
    ForwardAsAttachmentTo = tostring(RuleParams["ForwardAsAttachmentTo"]),
    RedirectTo = tostring(RuleParams["RedirectTo"]),
    DeleteMessage = tostring(RuleParams["DeleteMessage"]),
    MoveToFolder = tostring(RuleParams["MoveToFolder"]),
    SubjectContainsWords = tostring(RuleParams["SubjectContainsWords"]),
    BodyContainsWords = tostring(RuleParams["BodyContainsWords"]),
    FromAddressContainsWords = tostring(RuleParams["FromAddressContainsWords"]),
    MarkAsRead = tostring(RuleParams["MarkAsRead"])
| extend
    IsMalicious = case(
        isnotempty(ForwardTo) or isnotempty(ForwardAsAttachmentTo) or isnotempty(RedirectTo),
            "CRITICAL - External forwarding rule",
        DeleteMessage == "True" or MoveToFolder has_any ("RSS", "Junk", "Deleted"),
            "HIGH - Message deletion/hiding rule",
        SubjectContainsWords has_any ("password", "reset", "security", "MFA", "verify", "invoice", "payment", "wire"),
            "HIGH - Keyword-targeted rule (covering tracks)",
        MarkAsRead == "True" and isnotempty(FromAddressContainsWords),
            "MEDIUM - Auto-read rule from specific sender",
        "LOW - Standard rule"
    )
| project
    TimeGenerated,
    UserId,
    Operation,
    CleanClientIP,
    RuleName,
    ForwardTo,
    ForwardAsAttachmentTo,
    RedirectTo,
    DeleteMessage,
    MoveToFolder,
    SubjectContainsWords,
    BodyContainsWords,
    IsMalicious
| sort by TimeGenerated asc
```

**Performance Notes:**
- `mv-expand` + `make_bag` pattern extracts all rule parameters into a single accessible object
- Check for forwarding to external domains — this is the #1 BEC persistence mechanism
- Rules that delete messages containing "password", "security", or "MFA" are designed to hide notifications

**Expected findings:**
- **CRITICAL**: Forwarding rule to external email address → BEC confirmed, data exfiltration in progress
- **HIGH**: Delete rules targeting security keywords → Attacker hiding their tracks
- **MEDIUM**: Auto-read rules → Attacker ensuring user doesn't notice incoming responses to phishing

---

### Step 7: Org-Wide MFA Bombing Campaign Detection

**Purpose:** Check if the MFA fatigue attack is targeting multiple users simultaneously, indicating a coordinated campaign. Scattered Spider and LAPSUS$ are known to target multiple accounts in the same organization concurrently.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 7: Org-Wide MFA Denial Pattern
// Purpose: Detect coordinated MFA fatigue campaigns across multiple users
// Tables: SigninLogs
// Investigation Step: 7 - Org-Wide MFA Bombing Campaign Detection
// ============================================================
let AlertTime = datetime(2026-02-22T03:15:00Z);
let LookbackWindow = 24h;
// --- Org-wide MFA denial analysis ---
SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where ResultType == "500121"  // MFA denied by user
| summarize
    DenialCount = count(),
    FirstDenial = min(TimeGenerated),
    LastDenial = max(TimeGenerated),
    SourceIPs = make_set(IPAddress, 10),
    SourceIPCount = dcount(IPAddress),
    TargetApps = make_set(AppDisplayName, 5),
    DenialBursts_5min = dcountif(bin(TimeGenerated, 5m), true)
    by UserPrincipalName
| where DenialCount >= 3  // Minimum threshold
| extend
    AttackDuration = LastDenial - FirstDenial,
    CampaignRisk = case(
        DenialCount >= 10, "CRITICAL",
        DenialCount >= 5, "HIGH",
        DenialCount >= 3, "MEDIUM",
        "LOW"
    )
| sort by DenialCount desc
| extend
    TotalAffectedUsers = toscalar(
        SigninLogs
        | where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
        | where ResultType == "500121"
        | summarize DenialCount = count() by UserPrincipalName
        | where DenialCount >= 3
        | count
    )
```

**Performance Notes:**
- This query scans ALL users, not just the target — may be slow in large tenants
- If multiple users show 5+ denials in the same time window → coordinated campaign
- Check `SourceIPs` overlap between users — shared IP infrastructure = single attacker

**Tuning Guidance:**
- If > 3 users are being MFA bombed concurrently → Escalate as a campaign incident
- If all users share the same department or role → Targeted attack on specific group
- Check if the SourceIPs are from the same ASN → Attacker using same infrastructure

**Expected findings:**
- **Single user**: Targeted attack on a specific individual
- **2-3 users**: Small-scale campaign, possibly targeting IT admins or executives
- **5+ users**: Coordinated campaign — escalate to incident commander, engage threat intel

**Next action:**
- If campaign detected → Escalate to security leadership, activate incident response plan
- Cross-reference affected users' roles — are they privileged accounts?
- Check if any affected user's credentials appeared in recent dark web dumps (correlate with RB-0003)

---

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to assess whether the MFA push activity represents a genuine anomaly. UEBA's ML engine tracks the volume and pattern of operations per user — the `UncommonHighVolumeOfOperations` insight directly maps to MFA fatigue detection. Additionally, if the attacker bypassed MFA and gained access, UEBA will flag any post-access activity from the attacker's IP/location as anomalous.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 4. UEBA needs approximately **one week** after activation before generating meaningful insights.

#### Query 8A: MFA Activity Anomaly Assessment

```kql
// ============================================================
// Query 8A: UEBA Anomaly Assessment for MFA Fatigue
// Purpose: Check if UEBA flagged the burst of MFA requests as
//          anomalous and assess the attacker's source IP/location
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T03:15:00Z);
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
    // Volume anomaly — directly maps to MFA push spam
    UncommonHighVolume = tobool(ActivityInsights.UncommonHighVolumeOfOperations),
    // Action anomaly — is this activity pattern unusual for this user?
    ActionUncommonForUser = tobool(ActivityInsights.ActionUncommonlyPerformedByUser),
    ActionUncommonAmongPeers = tobool(ActivityInsights.ActionUncommonlyPerformedAmongPeers),
    // Source analysis — attacker's IP/location
    FirstTimeISP = tobool(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommonForUser = tobool(ActivityInsights.ISPUncommonlyUsedByUser),
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommonForUser = tobool(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    // Device analysis
    FirstTimeDevice = tobool(ActivityInsights.FirstTimeUserConnectedFromDevice),
    FirstTimeBrowser = tobool(ActivityInsights.FirstTimeUserConnectedViaBrowser),
    // User context
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    // Threat intel on source IP
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| order by InvestigationPriority desc, TimeGenerated desc
```

#### Query 8B: Post-Approval Behavioral Deviation

```kql
// ============================================================
// Query 8B: Post-MFA-Approval Behavioral Anomalies
// Purpose: If the user approved an MFA push (Step 3), check if
//          post-approval activity shows attacker behavior patterns
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <10 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T03:15:00Z);
let TargetUser = "user@contoso.com";
let PostApprovalWindow = 4h;
BehaviorAnalytics
| where TimeGenerated between (AlertTime .. (AlertTime + PostApprovalWindow))
| where UserPrincipalName =~ TargetUser
| summarize
    TotalActivities = count(),
    HighAnomalyCount = countif(InvestigationPriority >= 7),
    MediumAnomalyCount = countif(InvestigationPriority >= 4 and InvestigationPriority < 7),
    MaxPriority = max(InvestigationPriority),
    // Volume anomalies
    HighVolumeFlags = countif(tobool(ActivityInsights.UncommonHighVolumeOfOperations)),
    // First-time activities (attacker exploration)
    FirstTimeActionCount = countif(tobool(ActivityInsights.FirstTimeUserPerformedAction)),
    FirstTimeResourceCount = countif(tobool(ActivityInsights.FirstTimeUserAccessedResource)),
    FirstTimeAppCount = countif(tobool(ActivityInsights.FirstTimeUserUsedApp)),
    // Uncommon among peers
    UncommonActionAmongPeers = countif(tobool(ActivityInsights.ActionUncommonlyPerformedAmongPeers)),
    UncommonAppAmongPeers = countif(tobool(ActivityInsights.AppUncommonlyUsedAmongPeers)),
    // IP/location diversity in post-approval window
    UniqueIPs = dcount(SourceIPAddress),
    UniqueCountries = dcount(SourceIPLocation),
    Countries = make_set(SourceIPLocation),
    ActivityTypes = make_set(ActivityType),
    BlastRadius = take_any(tostring(UsersInsights.BlastRadius))
| extend
    AnomalyRatio = round(todouble(HighAnomalyCount + MediumAnomalyCount) / TotalActivities * 100, 1),
    AttackerSignals = HighVolumeFlags + FirstTimeActionCount + FirstTimeResourceCount
        + FirstTimeAppCount + UncommonActionAmongPeers
```

**Tuning Guidance:**

- **InvestigationPriority threshold**: `>= 7` = high-confidence anomaly, `>= 4` = moderate, `< 4` = likely normal
- **UncommonHighVolumeOfOperations**: This is the **most direct UEBA signal** for MFA fatigue — UEBA's ML engine detects burst patterns that exceed the user's normal operation volume. If `true`, UEBA independently confirms abnormal activity volume
- **Post-approval analysis (Query 8B)**: Focus on the time window AFTER the MFA push was approved. Multiple "first time" flags in a 4-hour window strongly suggest an attacker exploring the environment
- **AttackerSignals count**: Sum of suspicious indicators — `>= 3` signals in the post-approval window is strong evidence

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| InvestigationPriority | >= 7 (high anomaly) | < 4 (normal behavior) |
| UncommonHighVolume | true — burst exceeds ML baseline | false — normal volume |
| FirstTimeISP | true — attacker's ISP never seen | false — known ISP |
| FirstTimeCountry | true — attacker from new country | false — user's country |
| Post-approval FirstTimeAction | Multiple first-time actions | No first-time actions |
| Post-approval FirstTimeResource | Accessing new resources | Normal resource access |
| Post-approval FirstTimeApp | Using new applications | Usual applications |
| AttackerSignals (4h) | >= 3 — strong attacker pattern | 0 — clean post-approval |
| BlastRadius | High — privileged account | Low — standard user |
| ActivityTypes (post-approval) | ResourceAccess, ElevateAccess | LogOn only |

**Decision guidance:**

- **UncommonHighVolumeOfOperations = true + InvestigationPriority >= 7** → UEBA independently confirms the MFA push spam as anomalous. Very high confidence of active attack
- **Post-approval AttackerSignals >= 3** → Attacker gained access and is actively exploring. Multiple first-time actions/resources/apps in a short window is a hallmark of post-compromise activity. Proceed to Containment immediately
- **FirstTimeISP + FirstTimeCountry in post-approval** → The MFA-approved session originated from a completely new location. This is NOT the legitimate user
- **InvestigationPriority < 4 + no post-approval anomalies** → MFA denials may have been accidental (user pressing wrong button) or from a legitimate MFA re-enrollment. Combined with clean findings from Steps 1-7, consider closing as false positive
- **BlastRadius = High** → Privileged account under MFA fatigue attack requires immediate escalation regardless of other indicators

---

## 6. Containment Playbook

### Priority Actions (Based on Investigation Findings)

#### Immediate (Within 15 minutes of confirmed MFA fatigue)

!!! danger "Action Required - Even BEFORE Investigation Completes"

**If active MFA bombing is detected (3+ denials in 5 minutes), take these actions immediately:**

1. **Block sign-in for the user** — Entra ID → Users → Block sign-in. This stops the bombing AND prevents approval.
2. **Revoke all active sessions** — `Revoke-AzureADUserAllRefreshToken` or Entra ID portal → Revoke sessions
3. **Reset the user's password** — The password IS compromised (attacker couldn't trigger MFA without it)
4. **Contact the user via phone** — Verify they did NOT approve any MFA prompts. Do NOT use email or Teams (attacker may have access).

#### If MFA Was Approved (Fatigue Succeeded)

5. **Remove any newly registered MFA methods** — Check AuditLogs for "Register security info" after the approval timestamp. Remove any MFA methods registered after the bombing started.
6. **Revoke OAuth app consents** — Check for any apps consented after approval timestamp. Remove via Entra ID → Enterprise Applications.
7. **Remove inbox rules** — Delete any forwarding or deletion rules created after approval. Exchange Admin → Mail Flow → Rules.
8. **Disable the compromised account** until investigation is complete

#### Follow-Up (Within 4 hours)

9. **Re-register MFA** — Have the user re-enroll MFA from a known clean device, preferably in person or via verified phone call
10. **Enable number matching** in Authenticator if not already enabled — this dramatically reduces MFA fatigue effectiveness
11. **Review Conditional Access policies** — Consider adding "require compliant device" for sensitive apps
12. **Investigate credential source** — How did the attacker get the password? Check for:
    - Recent phishing emails targeting this user
    - User's credentials in dark web dumps (correlate with RB-0003 Leaked Credentials)
    - Info-stealer malware on user's device (check Defender for Endpoint)
    - Password reuse across personal and corporate accounts

#### Extended (Within 24 hours)

13. **Enable MFA fraud reporting** — If not already enabled, configure fraud alerts in Entra ID
14. **Review all affected users** — If campaign detected in Step 7, apply containment to all targets
15. **Deploy Conditional Access improvements:**
    - Require phishing-resistant MFA (FIDO2 keys, Windows Hello) for admins
    - Require compliant devices for all cloud app access
    - Block legacy authentication protocols
16. **Brief the security team** on MFA fatigue indicators for future detection

---

## 7. Evidence Collection Checklist

Preserve these artifacts before any remediation actions:

- [ ] Full SigninLogs export for the user (AlertTime ± 24h) including all MFA denial events
- [ ] AADUserRiskEvents for the user (if mfaFraud risk event exists)
- [ ] AuditLogs for the user (post-approval changes — MFA registration, OAuth, roles)
- [ ] OfficeActivity for the user (post-approval email/file activity)
- [ ] AADNonInteractiveUserSignInLogs (post-approval token usage)
- [ ] Inbox rules snapshot (Export-InboxRule for the user)
- [ ] OAuth consent grants snapshot (Get-AzureADOAuth2PermissionGrant)
- [ ] MFA registration details (registered methods, registration dates)
- [ ] Screenshots of the MFA denial timeline and burst patterns
- [ ] IP reputation lookups for attacker IPs used during bombing

---

## 8. Escalation Criteria

### Escalate to Incident Commander
- MFA fatigue attack succeeded (denial-then-approval detected) AND post-access persistence found
- Multiple users targeted simultaneously (campaign detected)
- Targeted user is a Global Admin, Security Admin, or PIM-eligible for privileged roles
- Evidence of helpdesk social engineering alongside MFA bombing (Scattered Spider TTP)

### Escalate to Threat Intelligence
- SourceIPs match known threat actor infrastructure
- Attack pattern matches Scattered Spider or LAPSUS$ TTPs
- User's credentials confirmed in recent dark web dump
- MFA bombing combined with SIM swap or voice phishing attempts

### Escalate to Legal/Compliance
- Customer or regulated data was accessed after MFA approval
- Email forwarding to external addresses detected (potential data exfiltration)
- Attacker sent emails from compromised account to external parties

---

## 9. False Positive Documentation

### FP Scenario 1: Phone/App Connectivity Issues (~30% of FPs)

**Pattern:** User has 3-5 MFA denials followed by eventual approval, all from the same managed device and IP.

**How to confirm:**
- Check if denials and approval are from the same `DeviceId` and `IPAddress`
- Check if the user is in an area with known poor cell coverage
- Ask the user: "Were you trying to sign in and had trouble with MFA?"

**Tuning note:** If the denial-to-approval pattern is from the same device/IP within 5 minutes, and the device is managed, lower the risk score.

### FP Scenario 2: MFA Method Enrollment/Migration (~25% of FPs)

**Pattern:** User has multiple MFA failures during a window when the organization is rolling out new MFA methods or the user is setting up a new phone.

**How to confirm:**
- Check if there's a concurrent "Register security info" event in AuditLogs
- Verify with IT helpdesk if the user requested MFA re-enrollment
- Check if the organization has an active MFA migration campaign

**Tuning note:** Correlate with IT change management tickets. Exclude users in active MFA enrollment from automated alerting.

### FP Scenario 3: Accidental Deny-Then-Retry (~25% of FPs)

**Pattern:** User accidentally denies an MFA push notification, then immediately retries. Typically shows 1-2 denials followed by quick approval from the same device.

**How to confirm:**
- TimeToApproval < 2 minutes after denial
- Same IP, same device, same app
- Only 1-2 denials, not a sustained burst

**Tuning note:** Set minimum denial threshold to 3 within a 5-minute window to filter out accidental denials.

### FP Scenario 4: Auto-Deny from Wrong Device (~20% of FPs)

**Pattern:** User receives MFA push on a device they're not actively using (old phone, tablet). The push times out or is dismissed, showing as a denial.

**How to confirm:**
- Check if user has multiple MFA devices registered
- Denial is from "timeout" rather than active denial (check MfaDetail.authDetail)
- Eventual approval from a different device (the correct one)

**Tuning note:** `MfaDetail.authDetail` containing "MFA denied; phone app reported fraud" is a true fraud report. "MFA denied; user declined the authentication" may be accidental.

---

## 10. MITRE ATT&CK Mapping

### Detection Coverage Matrix

| Technique ID | Technique Name | Tactic | Confidence | Query |
|---|---|---|---|---|
| **T1621** | **Multi-Factor Authentication Request Generation** | **Credential Access** | <span class="severity-badge severity-info">Confirmed</span> | **Q2, Q3** |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | <span class="severity-badge severity-info">Confirmed</span> | Q1, Q3 |
| T1098 | Account Manipulation | Persistence | <span class="severity-badge severity-info">Confirmed</span> | Q6A |
| T1114.003 | Email Collection: Email Forwarding Rule | Collection | <span class="severity-badge severity-info">Confirmed</span> | Q6B, Q6C |
| T1528 | Steal Application Access Token | Credential Access | <span class="severity-badge severity-info">Confirmed</span> | Q6A |
| T1530 | Data from Cloud Storage Object | Collection | <span class="severity-badge severity-info">Confirmed</span> | Q6B |
| T1534 | Internal Spearphishing | Lateral Movement | <span class="severity-badge severity-info">Confirmed</span> | Q6B |
| T1556.006 | Modify Authentication Process: MFA | Persistence, Defense Evasion | <span class="severity-badge severity-info">Confirmed</span> | Q6A |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Persistence, Defense Evasion | <span class="severity-badge severity-info">Confirmed</span> | Q6C |

### Attack Chains

**Chain 1: Credential Purchase → MFA Fatigue → BEC**
```
Dark web credential purchase
  → MFA push bombing (T1621)
  → User approves out of fatigue (T1078.004)
  → MFA device registered (T1556.006)
  → Inbox forwarding rule (T1114.003, T1564.008)
  → Internal phishing (T1534)
  → Data exfiltration (T1530)
```

**Chain 2: MFA Fatigue + Helpdesk Social Engineering (Scattered Spider)**
```
Credential phishing / purchase
  → MFA push bombing at 2am (T1621)
  → Simultaneously call IT helpdesk impersonating user
  → Helpdesk resets MFA or adds attacker device (T1556.006)
  → Full account takeover (T1078.004)
  → OAuth app consent for persistence (T1528)
  → Lateral movement via email (T1534)
```

### Threat Actor Attribution

| Actor | Confidence | Key TTPs |
|---|---|---|
| **Scattered Spider (Octo Tempest)** | **HIGH** | T1621 + helpdesk social engineering. Primary users of MFA fatigue. |
| **LAPSUS$ (DEV-0537)** | **HIGH** | T1621 at scale against tech companies. Credential purchase + MFA bombing. |
| **Storm-0875** | **MEDIUM** | T1621 + SIM swapping for MFA bypass. Affiliated with Scattered Spider. |
| **Midnight Blizzard (APT29)** | **LOW-MEDIUM** | Occasionally uses T1621 in targeted espionage campaigns. |

---

## 11. Query Summary

| Query | Purpose | Tables | Step |
|---|---|---|---|
| Q1 | MFA fraud risk event extraction | AADUserRiskEvents, SigninLogs | 1 |
| Q2 | MFA denial pattern analysis (burst detection) | SigninLogs | 2 |
| Q3 | Denial-then-approval detection | SigninLogs | 3 |
| Q4 | 30-day MFA behavior baseline [MANDATORY] | SigninLogs | 4 |
| Q5 | Post-approval session analysis | SigninLogs | 5 |
| Q6A | Directory changes and persistence | AuditLogs | 6A |
| Q6B | Email and file activity | OfficeActivity | 6B |
| Q6C | Inbox rule deep dive | OfficeActivity | 6C |
| Q7 | Org-wide MFA bombing campaign | SigninLogs | 7 |

---

## Appendix A: Datatable Tests

### Test 1: MFA Denial Pattern Detection

```kql
// ============================================================
// TEST 1: MFA Denial Burst Detection
// Validates: Query 2 - MFA denial pattern analysis
// Expected: Identifies user.target@contoso.com as MFA bombing target
//           with 8 denials in a 10-minute window
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    AppDisplayName: string,
    AuthenticationRequirement: string,
    MfaDetail: dynamic,
    DeviceDetail: dynamic,
    LocationDetails: dynamic,
    ClientAppUsed: string,
    UserAgent: string,
    CorrelationId: string,
    ConditionalAccessStatus: string
) [
    // --- Malicious: MFA fatigue bombing (8 denials in 10 minutes) ---
    datetime(2026-02-22T03:10:00Z), "user.target@contoso.com", "203.0.113.50", "500121",
        "Microsoft 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied; user declined the authentication"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Browser", "Mozilla/5.0", "corr-001", "success",
    datetime(2026-02-22T03:11:00Z), "user.target@contoso.com", "203.0.113.50", "500121",
        "Microsoft 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied; user declined the authentication"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Browser", "Mozilla/5.0", "corr-002", "success",
    datetime(2026-02-22T03:12:00Z), "user.target@contoso.com", "203.0.113.50", "500121",
        "Microsoft 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied; user declined the authentication"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Browser", "Mozilla/5.0", "corr-003", "success",
    datetime(2026-02-22T03:13:30Z), "user.target@contoso.com", "203.0.113.50", "500121",
        "Microsoft 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied; user declined the authentication"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Browser", "Mozilla/5.0", "corr-004", "success",
    datetime(2026-02-22T03:14:00Z), "user.target@contoso.com", "203.0.113.50", "500121",
        "Microsoft 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied; user declined the authentication"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Browser", "Mozilla/5.0", "corr-005", "success",
    datetime(2026-02-22T03:15:00Z), "user.target@contoso.com", "203.0.113.50", "500121",
        "Microsoft 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied; user declined the authentication"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Browser", "Mozilla/5.0", "corr-006", "success",
    datetime(2026-02-22T03:16:30Z), "user.target@contoso.com", "203.0.113.50", "500121",
        "Microsoft 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied; user declined the authentication"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Browser", "Mozilla/5.0", "corr-007", "success",
    datetime(2026-02-22T03:18:00Z), "user.target@contoso.com", "203.0.113.50", "500121",
        "Microsoft 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied; user declined the authentication"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Browser", "Mozilla/5.0", "corr-008", "success",
    // --- Benign: Normal user with 1 accidental denial then approval ---
    datetime(2026-02-22T10:00:00Z), "normal.user@contoso.com", "10.0.0.5", "500121",
        "Microsoft 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied; user declined the authentication"}),
        dynamic({"operatingSystem":"iOS","browser":"Mobile Safari"}),
        dynamic({"city":"Seattle","countryOrRegion":"US"}), "Mobile Apps and Desktop clients", "Outlook/4.0", "corr-100", "success",
    datetime(2026-02-22T10:01:00Z), "normal.user@contoso.com", "10.0.0.5", "0",
        "Microsoft 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA completed in app"}),
        dynamic({"operatingSystem":"iOS","browser":"Mobile Safari"}),
        dynamic({"city":"Seattle","countryOrRegion":"US"}), "Mobile Apps and Desktop clients", "Outlook/4.0", "corr-101", "success"
];
// --- Run pattern detection ---
TestSigninLogs
| where ResultType in ("500121", "50074", "50076")
| summarize
    DenialsIn5Min = countif(ResultType == "500121"),
    MfaChallenges = count(),
    FirstDenial = min(TimeGenerated),
    LastDenial = max(TimeGenerated),
    SourceIPs = make_set(IPAddress)
    by UserPrincipalName, Bin5Min = bin(TimeGenerated, 5m)
| where DenialsIn5Min >= 3
// Expected: user.target@contoso.com flagged with 8 denials
// Expected: normal.user@contoso.com NOT flagged (only 1 denial)
```

### Test 2: Denial-Then-Approval Detection

```kql
// ============================================================
// TEST 2: Denial-Then-Approval Pivot Detection
// Validates: Query 3 - Detects if user approved after MFA bombing
// Expected: user.victim@contoso.com shows "LIKELY COMPROMISED"
//           user.strong@contoso.com shows "DEFENSE HELD"
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    AppDisplayName: string,
    MfaDetail: dynamic,
    DeviceDetail: dynamic,
    LocationDetails: dynamic
) [
    // --- Victim: 6 denials then approval from different IP ---
    datetime(2026-02-22T02:00:00Z), "user.victim@contoso.com", "198.51.100.10", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    datetime(2026-02-22T02:01:00Z), "user.victim@contoso.com", "198.51.100.10", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    datetime(2026-02-22T02:02:00Z), "user.victim@contoso.com", "198.51.100.10", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    datetime(2026-02-22T02:03:00Z), "user.victim@contoso.com", "198.51.100.10", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    datetime(2026-02-22T02:04:00Z), "user.victim@contoso.com", "198.51.100.10", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    datetime(2026-02-22T02:05:00Z), "user.victim@contoso.com", "198.51.100.10", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    // User caves and approves at 2:10
    datetime(2026-02-22T02:10:00Z), "user.victim@contoso.com", "198.51.100.10", "0",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA completed in app"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    // --- Strong user: 5 denials, NEVER approves ---
    datetime(2026-02-22T02:00:00Z), "user.strong@contoso.com", "198.51.100.20", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Mumbai","countryOrRegion":"IN"}),
    datetime(2026-02-22T02:01:00Z), "user.strong@contoso.com", "198.51.100.20", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Mumbai","countryOrRegion":"IN"}),
    datetime(2026-02-22T02:02:00Z), "user.strong@contoso.com", "198.51.100.20", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Mumbai","countryOrRegion":"IN"}),
    datetime(2026-02-22T02:03:00Z), "user.strong@contoso.com", "198.51.100.20", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Mumbai","countryOrRegion":"IN"}),
    datetime(2026-02-22T02:04:00Z), "user.strong@contoso.com", "198.51.100.20", "500121",
        "Microsoft 365", dynamic({"authMethod":"PhoneAppNotification","authDetail":"MFA denied"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","deviceId":""}),
        dynamic({"city":"Mumbai","countryOrRegion":"IN"})
];
// --- Run denial-then-approval detection ---
let DenialCount = TestSigninLogs
| where ResultType == "500121"
| summarize TotalDenials = count(), FirstDenial = min(TimeGenerated), LastDenial = max(TimeGenerated), DenialIPs = make_set(IPAddress)
    by UserPrincipalName;
let FirstApproval = TestSigninLogs
| where ResultType == "0"
| summarize ApprovalTime = min(TimeGenerated), ApprovalIP = take_any(IPAddress)
    by UserPrincipalName;
DenialCount
| join kind=leftouter FirstApproval on UserPrincipalName
| extend Verdict = case(
    isempty(ApprovalTime), "DEFENSE HELD - No approval after denials",
    TotalDenials >= 5 and isnotempty(ApprovalTime) and ApprovalTime > LastDenial, "LIKELY COMPROMISED - Approval after sustained bombing",
    TotalDenials >= 3 and isnotempty(ApprovalTime) and ApprovalTime > LastDenial, "POSSIBLY COMPROMISED",
    "INVESTIGATE FURTHER"
)
// Expected: user.victim@contoso.com = "LIKELY COMPROMISED" (6 denials then approval)
// Expected: user.strong@contoso.com = "DEFENSE HELD" (5 denials, no approval)
```

### Test 3: MFA Baseline Comparison

```kql
// ============================================================
// TEST 3: MFA Behavior Baseline Comparison
// Validates: Query 4 - 30-day baseline detection
// Expected: user.anomalous@contoso.com flagged (normally 0 denials, today 8)
//           user.noisy@contoso.com NOT flagged (regular denial pattern)
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    AuthenticationRequirement: string,
    MfaDetail: dynamic
) [
    // --- user.anomalous: 30 days of clean MFA, then burst today ---
    // Baseline: Successful MFA every day, 0 denials
    datetime(2026-01-25T09:00:00Z), "user.anomalous@contoso.com", "10.0.0.1", "0", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-01-26T09:00:00Z), "user.anomalous@contoso.com", "10.0.0.1", "0", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-01-27T09:00:00Z), "user.anomalous@contoso.com", "10.0.0.1", "0", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-10T09:00:00Z), "user.anomalous@contoso.com", "10.0.0.1", "0", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-15T09:00:00Z), "user.anomalous@contoso.com", "10.0.0.1", "0", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    // Today: 8 MFA denials (MFA fatigue attack)
    datetime(2026-02-22T03:10:00Z), "user.anomalous@contoso.com", "203.0.113.50", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-22T03:11:00Z), "user.anomalous@contoso.com", "203.0.113.50", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-22T03:12:00Z), "user.anomalous@contoso.com", "203.0.113.50", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-22T03:13:00Z), "user.anomalous@contoso.com", "203.0.113.50", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-22T03:14:00Z), "user.anomalous@contoso.com", "203.0.113.50", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-22T03:15:00Z), "user.anomalous@contoso.com", "203.0.113.50", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-22T03:16:00Z), "user.anomalous@contoso.com", "203.0.113.50", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-22T03:17:00Z), "user.anomalous@contoso.com", "203.0.113.50", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    // --- user.noisy: Regular MFA denials (phone issues) - 2-3 per day normally ---
    datetime(2026-01-25T09:00:00Z), "user.noisy@contoso.com", "10.0.0.2", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-01-25T09:02:00Z), "user.noisy@contoso.com", "10.0.0.2", "0", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-01-26T14:00:00Z), "user.noisy@contoso.com", "10.0.0.2", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-01-26T14:00:30Z), "user.noisy@contoso.com", "10.0.0.2", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-01-26T14:01:00Z), "user.noisy@contoso.com", "10.0.0.2", "0", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-15T10:00:00Z), "user.noisy@contoso.com", "10.0.0.2", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-15T10:01:00Z), "user.noisy@contoso.com", "10.0.0.2", "0", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    // Today: 3 denials (similar to normal pattern)
    datetime(2026-02-22T09:00:00Z), "user.noisy@contoso.com", "10.0.0.2", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-22T09:01:00Z), "user.noisy@contoso.com", "10.0.0.2", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-22T09:02:00Z), "user.noisy@contoso.com", "10.0.0.2", "500121", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
    datetime(2026-02-22T09:03:00Z), "user.noisy@contoso.com", "10.0.0.2", "0", "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"})
];
// --- Baseline analysis ---
let AlertTime = datetime(2026-02-22T12:00:00Z);
let BaselineData = TestSigninLogs
| where TimeGenerated < AlertTime - 1h
| where ResultType in ("500121", "0") and AuthenticationRequirement == "multiFactorAuthentication"
| summarize MaxDailyDenials = max(countif(ResultType == "500121"))
    by UserPrincipalName, bin(TimeGenerated, 1d)
| summarize BaselineMaxDenials = max(MaxDailyDenials) by UserPrincipalName;
let TodayData = TestSigninLogs
| where TimeGenerated >= AlertTime - 1d
| where ResultType == "500121"
| summarize TodayDenials = count() by UserPrincipalName;
BaselineData
| join kind=fullouter TodayData on UserPrincipalName
| extend Assessment = case(
    BaselineMaxDenials == 0 and TodayDenials >= 3, "ANOMALOUS - Zero baseline, attack likely",
    TodayDenials > BaselineMaxDenials * 3, "ANOMALOUS - 3x+ above baseline",
    "WITHIN NORMAL RANGE"
)
// Expected: user.anomalous = "ANOMALOUS - Zero baseline, attack likely"
// Expected: user.noisy = "WITHIN NORMAL RANGE"
```

### Test 4: Post-Approval Persistence Detection

```kql
// ============================================================
// TEST 4: Post-Approval Persistence Detection
// Validates: Query 6A - Directory changes after MFA fatigue approval
// Expected: Detects MFA registration + OAuth consent as CRITICAL/HIGH
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    Category: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Malicious: MFA method registered 3 minutes after approval ---
    datetime(2026-02-22T02:13:00Z), "Register security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user.victim@contoso.com"}}),
        dynamic([{"displayName":"PhoneAppNotification","type":"User","modifiedProperties":[{"displayName":"StrongAuthenticationMethod","oldValue":"[]","newValue":"[{\"MethodType\":6}]"}]}]),
        "success",
    // --- Malicious: OAuth app consent 5 minutes after approval ---
    datetime(2026-02-22T02:15:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user.victim@contoso.com"}}),
        dynamic([{"displayName":"Suspicious App","type":"ServicePrincipal","modifiedProperties":[{"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"Mail.Read, Mail.ReadWrite, Files.ReadWrite.All"}]}]),
        "success",
    // --- Benign: Normal role assignment by admin ---
    datetime(2026-02-22T10:00:00Z), "Add member to role", "RoleManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"displayName":"user.normal@contoso.com","type":"User"}]),
        "success"
];
// --- Run persistence detection ---
let TargetUser = "user.victim@contoso.com";
let ApprovalTime = datetime(2026-02-22T02:10:00Z);
TestAuditLogs
| where TimeGenerated between (ApprovalTime .. ApprovalTime + 4h)
| where tostring(InitiatedBy.user.userPrincipalName) =~ TargetUser
| extend Severity = case(
    OperationName has "security info" and OperationName has "Register", "CRITICAL - MFA method registered",
    OperationName == "Consent to application", "HIGH - OAuth app consent",
    OperationName has "role", "HIGH - Role assignment change",
    "MEDIUM"
)
// Expected: 2 results - CRITICAL MFA registration + HIGH OAuth consent
// Expected: Admin's role assignment NOT included (different user)
```

### Test 5: Org-Wide Campaign Detection

```kql
// ============================================================
// TEST 5: Org-Wide MFA Bombing Campaign Detection
// Validates: Query 7 - Multiple users targeted simultaneously
// Expected: Detects 3 users being MFA bombed from same IP range
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    AppDisplayName: string
) [
    // --- Campaign: 3 users MFA bombed from same IP range ---
    // User 1: 5 denials
    datetime(2026-02-22T03:00:00Z), "admin@contoso.com", "198.51.100.10", "500121", "Microsoft 365",
    datetime(2026-02-22T03:01:00Z), "admin@contoso.com", "198.51.100.10", "500121", "Microsoft 365",
    datetime(2026-02-22T03:02:00Z), "admin@contoso.com", "198.51.100.10", "500121", "Microsoft 365",
    datetime(2026-02-22T03:03:00Z), "admin@contoso.com", "198.51.100.10", "500121", "Microsoft 365",
    datetime(2026-02-22T03:04:00Z), "admin@contoso.com", "198.51.100.10", "500121", "Microsoft 365",
    // User 2: 4 denials
    datetime(2026-02-22T03:00:30Z), "cfo@contoso.com", "198.51.100.11", "500121", "Microsoft 365",
    datetime(2026-02-22T03:01:30Z), "cfo@contoso.com", "198.51.100.11", "500121", "Microsoft 365",
    datetime(2026-02-22T03:02:30Z), "cfo@contoso.com", "198.51.100.11", "500121", "Microsoft 365",
    datetime(2026-02-22T03:03:30Z), "cfo@contoso.com", "198.51.100.11", "500121", "Microsoft 365",
    // User 3: 6 denials
    datetime(2026-02-22T03:00:15Z), "hr.director@contoso.com", "198.51.100.12", "500121", "Microsoft 365",
    datetime(2026-02-22T03:01:15Z), "hr.director@contoso.com", "198.51.100.12", "500121", "Microsoft 365",
    datetime(2026-02-22T03:02:15Z), "hr.director@contoso.com", "198.51.100.12", "500121", "Microsoft 365",
    datetime(2026-02-22T03:03:15Z), "hr.director@contoso.com", "198.51.100.12", "500121", "Microsoft 365",
    datetime(2026-02-22T03:04:15Z), "hr.director@contoso.com", "198.51.100.12", "500121", "Microsoft 365",
    datetime(2026-02-22T03:05:15Z), "hr.director@contoso.com", "198.51.100.12", "500121", "Microsoft 365",
    // --- Noise: Normal user with 1 denial ---
    datetime(2026-02-22T10:00:00Z), "regular@contoso.com", "10.0.0.5", "500121", "Microsoft 365"
];
// --- Org-wide campaign detection ---
TestSigninLogs
| where ResultType == "500121"
| summarize DenialCount = count(), SourceIPs = make_set(IPAddress)
    by UserPrincipalName
| where DenialCount >= 3
| sort by DenialCount desc
// Expected: 3 users flagged (admin=5, cfo=4, hr.director=6)
// Expected: regular@contoso.com NOT flagged (only 1 denial)
// Expected: All IPs in 198.51.100.0/24 range = same attacker infrastructure
```

---

## References

- [Microsoft: Investigate risk - MFA fatigue](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk)
- [Microsoft: MFA fraud alert configuration](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings#fraud-alert)
- [Microsoft: Number matching in MFA](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match)
- [MITRE ATT&CK T1621 - Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/)
- [Scattered Spider threat profile](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)
- [LAPSUS$ investigation by Microsoft](https://www.microsoft.com/en-us/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/)
- [Uber breach via MFA fatigue (2022)](https://www.uber.com/newsroom/security-update/)
- [Cisco breach via MFA fatigue (2022)](https://blog.talosintelligence.com/recent-cyber-attack/)
