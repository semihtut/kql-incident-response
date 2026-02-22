---
title: "Leaked Credentials"
id: RB-0003
severity: high
status: reviewed
description: >
  Investigation runbook for Microsoft Entra ID Identity Protection
  "Leaked credentials" risk detection. Covers credential exposure assessment
  from dark web/paste site matches, password timeline analysis, anomalous
  sign-in hunting, legacy auth exposure, and post-access blast radius assessment.
mitre_attack:
  tactics:
    - tactic_id: TA0043
      tactic_name: "Reconnaissance"
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
    - technique_id: T1589.001
      technique_name: "Gather Victim Identity Information: Credentials"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1110.004
      technique_name: "Brute Force: Credential Stuffing"
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
  - "Info-Stealer Campaigns (Raccoon, RedLine, Vidar, Lumma)"
  - "Storm-0539 (Atlas Lion)"
  - "FIN7 / FIN8"
  - "Scattered Spider (Octo Tempest)"
log_sources:
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
  - table: "ThreatIntelligenceIndicator"
    product: "Microsoft Sentinel"
    license: "Sentinel + TI feeds"
    required: false
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-22
updated: 2026-02-22
version: "1.0"
tier: 1
data_checks:
  - query: "AADUserRiskEvents | take 1"
    label: primary
    description: "If empty, Entra ID P2 or the connector is missing"
  - query: "AADRiskyUsers | take 1"
    description: "Required for user risk state assessment"
  - query: "SigninLogs | take 1"
    description: "Must be present for sign-in baseline and anomaly detection"
  - query: "AuditLogs | where OperationName has &quot;password&quot; | take 1"
    description: "Verify password change events are captured"
  - query: "OfficeActivity | take 1"
    description: "If empty, the Office 365 connector is not configured"
---

# Leaked Credentials - Investigation Runbook

> **RB-0003** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Identity Protection
> **Risk Detection Name:** `leakedCredentials`
> **Primary MITRE Technique:** T1078.004 - Valid Accounts: Cloud Accounts

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Extract Leaked Credential Risk Event](#step-1-extract-leaked-credential-risk-event)
   - [Step 2: User Risk State and Password Timeline](#step-2-user-risk-state-and-password-timeline)
   - [Step 3: Baseline Comparison - Establish Normal Sign-In Pattern](#step-3-baseline-comparison---establish-normal-sign-in-pattern)
   - [Step 4: Anomalous Sign-In Detection (Post-Leak)](#step-4-anomalous-sign-in-detection-post-leak)
   - [Step 5: Analyze Post-Sign-In Activity (Blast Radius Assessment)](#step-5-analyze-post-sign-in-activity-blast-radius-assessment)
   - [Step 6: MFA and Legacy Auth Exposure Assessment](#step-6-mfa-and-legacy-auth-exposure-assessment)
   - [Step 7: IP Reputation and Context](#step-7-ip-reputation-and-context)
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
The "Leaked credentials" risk detection is generated by Entra ID Identity Protection when Microsoft's Digital Crimes Unit (DCU) and security research partners discover user credentials in dark web dumps, paste sites, underground forums, or info-stealer malware logs. Microsoft acquires these credential databases and runs them through a hash-matching algorithm against Entra ID user credentials. When a match is found, a `leakedCredentials` risk event is generated. This is strictly an **offline** detection - there is processing lag between credential acquisition and matching, ranging from hours to days.

**Why it matters:**
Leaked credentials represent a direct, confirmed exposure of a user's authentication secret. Unlike "unfamiliar sign-in" (RB-0001) or "impossible travel" (RB-0002) which detect anomalous sign-in behavior, leaked credentials confirm that the password itself has been compromised and is potentially available to any attacker who purchases or downloads the credential dump. The exposure window may be days, weeks, or months between the actual breach and Microsoft's detection.

**However:** This alert has a **moderate false positive rate** (~40-50% in typical environments). Legitimate triggers include:
- Old/stale credential leaks where the user has already changed their password
- Users who registered on third-party sites with their corporate email but a different password (email match, not credential match)
- Test or lab accounts that appear in leaked databases
- Accounts where security teams have already enforced a password reset before the detection fired
- SSO-only accounts where the leaked password is not the Entra ID password

**Worst case scenario if this is real:**
An attacker has obtained the user's valid Entra ID password from a credential dump or info-stealer log. If the user does not have MFA enforced, the attacker can sign in directly with the leaked credentials. Even with MFA, if legacy authentication protocols (IMAP, POP3, SMTP, Exchange ActiveSync) are not blocked, the attacker can bypass MFA entirely through these protocols. In the worst case, the attacker has been using the credentials silently for weeks before the leak was detected, establishing persistence via inbox rules, OAuth apps, and MFA method registration.

**Key difference from RB-0001 and RB-0002:**
RB-0001 and RB-0002 detect anomalous sign-in events and provide a specific sign-in to investigate. This runbook (RB-0003) starts from a credential exposure notification with **no associated sign-in event**. The risk event typically has no IP address or location. The investigation must proactively HUNT for evidence of unauthorized credential usage by comparing recent sign-in activity against a baseline. Additionally, this runbook adds password timeline analysis and legacy auth exposure assessment as unique investigation steps.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID P2 + Microsoft 365 E3 + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID, Office 365
- **Permissions:** Security Reader (investigation), Security Operator (containment)

### Recommended for Full Coverage
- **License:** Microsoft 365 E5 + Sentinel with TI feeds
- **Additional Connectors:** Threat Intelligence (TAXII/Platform)

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | SigninLogs, AuditLogs | Steps 3, 6 (partial) |
| Entra ID P2 + Sentinel | Above + AADUserRiskEvents, AADRiskyUsers, AADNonInteractiveUserSignInLogs | Steps 1-4, 6, 7 (partial) |
| M365 E3 + Entra ID P2 + Sentinel | Above + OfficeActivity | Steps 1-7 (core investigation) |
| M365 E5 + Sentinel + TI | ALL tables | Steps 1-7 (full investigation) |

---

## 3. Input Parameters

All queries in this runbook use the following shared input parameters. Replace these values with the actual alert data before running. Unlike RB-0001/RB-0002, there is NO associated IP address in the risk event itself.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Set these before running any query
// ============================================================
let TargetUser = "user@contoso.com";          // UserPrincipalName from the risk event
let AlertTime = datetime(2026-02-22T10:00:00Z); // TimeGenerated of the risk event
// NOTE: No signInIP parameter - leakedCredentials risk events
// typically do not have an associated IP address
```

---

## 4. Quick Triage Criteria

The goal of quick triage is to determine within 2-3 steps whether this alert requires immediate containment or can be closed with a password reset.

### Quick Close Conditions (all must be true to close as low-risk):
1. The user's password was **changed AFTER** the risk event was generated
2. The user has **MFA enforced** via Conditional Access (not just registered, but enforced)
3. **Legacy authentication is blocked** for the user (no IMAP/POP3/SMTP access)
4. There are **no anomalous sign-ins** from unknown IPs/locations in the past 30 days
5. There is **no suspicious post-sign-in activity** (no inbox rules, no app consents, no MFA changes)

### Quick Escalation Conditions (any one triggers deep investigation):
- Password has NOT been changed since the risk event
- User does NOT have MFA enforced
- Legacy auth protocols are permitted for the user
- Successful sign-ins from unknown IPs/countries detected in post-leak window
- Failed sign-ins from multiple unknown IPs (credential testing in progress)
- User holds privileged roles (Global Admin, Security Admin, Exchange Admin, etc.)
- Post-sign-in persistence detected (inbox rules, MFA changes, OAuth consents)

---

## 5. Investigation Steps

### Step 1: Extract Leaked Credential Risk Event

**Purpose:** Pull the leaked credential risk event details from AADUserRiskEvents. Unlike RB-0001/RB-0002, this risk event will typically have empty IP and location fields because the detection comes from credential database matching, not a sign-in event. The key information is the detection timing, risk level, and whether additional risk events exist for this user.

**Data needed from:**
- Table: AADUserRiskEvents - get the risk event details (RiskEventType == "leakedCredentials")

**What to extract:**
- User identity: UserPrincipalName, display name
- Risk event: RiskLevel, RiskState, DetectionTimingType (always "offline")
- Timeline: When was the leak detected vs. when might the actual exposure have occurred
- Additional risk events: Are there OTHER risk events for this user (compound risk)
- AdditionalInfo: May contain metadata about the leak source

#### Query 1: Extract Leaked Credential Risk Event

```kql
// ============================================================
// Query 1: Extract Leaked Credential Risk Event
// Purpose: Pull the risk event and check for compound risk
//          (multiple risk events for the same user)
// Table: AADUserRiskEvents
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let LookbackWindow = 30d;
// --- Part 1: Get the leaked credential risk event ---
let LeakEvent = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
    | where UserPrincipalName == TargetUser
    | where RiskEventType == "leakedCredentials"
    | project
        RiskTimeGenerated = TimeGenerated,
        UserPrincipalName,
        RiskEventType,
        RiskLevel,
        RiskState,
        RiskDetail,
        DetectionTimingType,
        // These are typically empty for leakedCredentials
        RiskIpAddress = IpAddress,
        RiskLocation = Location,
        AdditionalInfo,
        CorrelationId,
        Id
    | top 1 by RiskTimeGenerated desc;
// --- Part 2: Check for compound risk (other risk events) ---
let OtherRiskEvents = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
    | where UserPrincipalName == TargetUser
    | where RiskEventType != "leakedCredentials"
    | summarize
        OtherRiskEventCount = count(),
        OtherRiskTypes = make_set(RiskEventType),
        OtherRiskLevels = make_set(RiskLevel),
        LatestOtherRisk = max(TimeGenerated);
// --- Part 3: Combined output ---
LeakEvent
| extend placeholder = 1
| join kind=leftouter (OtherRiskEvents | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    CompoundRiskAssessment = case(
        OtherRiskEventCount > 0 and OtherRiskTypes has "impossibleTravel",
            "CRITICAL - Leaked credentials + impossible travel (active compromise likely)",
        OtherRiskEventCount > 0 and OtherRiskTypes has "unfamiliarFeatures",
            "HIGH - Leaked credentials + unfamiliar sign-in (credential may be in use)",
        OtherRiskEventCount > 0 and OtherRiskTypes has "anonymizedIPAddress",
            "HIGH - Leaked credentials + anonymous IP (credential being tested via proxy)",
        OtherRiskEventCount > 0,
            strcat("ELEVATED - Leaked credentials + ", tostring(OtherRiskEventCount), " other risk events"),
        "SINGLE RISK - Only leaked credentials detected"
    ),
    IpAvailable = isnotempty(RiskIpAddress),
    LocationAvailable = isnotempty(tostring(RiskLocation))
```

<details>
<summary>Expected Output Columns</summary>

| Column | Type | Description |
|---|---|---|
| RiskTimeGenerated | datetime | When the leaked credential was detected |
| UserPrincipalName | string | Affected user |
| RiskEventType | string | "leakedCredentials" |
| RiskLevel | string | Risk level assigned |
| RiskState | string | Current risk state |
| RiskDetail | string | Risk detail or remediation status |
| DetectionTimingType | string | Always "offline" for leakedCredentials |
| RiskIpAddress | string | Usually empty |
| RiskLocation | dynamic | Usually empty |
| AdditionalInfo | dynamic | Leak source metadata (if available) |
| OtherRiskEventCount | long | Number of other risk events for this user |
| OtherRiskTypes | dynamic | Set of other risk event types |
| CompoundRiskAssessment | string | Assessment of combined risk |
| IpAvailable | bool | Whether the risk event has an associated IP |

</details>

**Performance Notes:**
- Query scans 30-day window to catch delayed detections
- The compound risk check is critical - if leaked credentials co-occur with other risk events, the probability of active compromise increases dramatically
- Expected result: 1 row with risk event details and compound risk assessment

**Tuning Guidance:**
- **LookbackWindow**: Default 30d. Leaked credential detections can lag by days or weeks
- **Compound risk**: If OtherRiskEventCount > 0, treat severity as escalated regardless of individual risk levels

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Risk level | High or medium risk with compound events | Low risk, single event |
| Compound risk | Additional risk events (impossible travel, unfamiliar sign-in) | No other risk events |
| Risk state | "atRisk" or "confirmedCompromised" | "remediated" or "dismissed" |
| Detection timing | Recent detection (within last 7 days) | Old detection (>30 days, likely stale) |

**Next action:**
- If compound risk detected -> escalate severity, proceed to Step 2 with HIGH urgency
- If single risk event + risk state "atRisk" -> proceed to Step 2 normally
- If risk state already "remediated" -> verify remediation was adequate, still complete investigation

---

### Step 2: User Risk State and Password Timeline

**Purpose:** Determine when the user last changed their password relative to the leak detection. If the password was changed AFTER the leak was detected, the immediate credential exposure risk is mitigated. Also check the user's current risk state and whether any administrative action has already been taken.

**Data needed from:**
- Table: AADRiskyUsers - current user risk state
- Table: AuditLogs - password change history

#### Query 2: User Risk State and Password Timeline

```kql
// ============================================================
// Query 2: User Risk State and Password Timeline
// Purpose: Check user's current risk state and determine if
//          the password has been changed since the leak detection
// Tables: AADRiskyUsers, AuditLogs
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let LookbackWindow = 90d;
// --- Part 1: Current risk state ---
let RiskState = AADRiskyUsers
    | where UserPrincipalName == TargetUser
    | top 1 by TimeGenerated desc
    | project
        UserPrincipalName,
        UserDisplayName,
        CurrentRiskLevel = RiskLevel,
        CurrentRiskState = RiskState,
        RiskDetail,
        RiskLastUpdatedDateTime,
        IsProcessing;
// --- Part 2: Password change history ---
let PasswordChanges = AuditLogs
    | where TimeGenerated > ago(LookbackWindow)
    | where OperationName in (
        "Change user password",
        "Reset user password",
        "Reset password (by admin)",
        "Change password (self-service)",
        "Update StsRefreshTokenValidFrom"
    )
    | mv-expand TargetResource = TargetResources
    | where tostring(TargetResource.userPrincipalName) == TargetUser
        or tostring(InitiatedBy.user.userPrincipalName) == TargetUser
    | project
        PasswordChangeTime = TimeGenerated,
        OperationName,
        InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
        InitiatedByApp = tostring(InitiatedBy.app.displayName),
        ChangeType = case(
            OperationName has "self-service" or tostring(InitiatedBy.user.userPrincipalName) == TargetUser,
                "Self-service password change",
            OperationName has "admin" or tostring(InitiatedBy.user.userPrincipalName) != TargetUser,
                "Admin-initiated password reset",
            "System/automated change"
        )
    | top 5 by PasswordChangeTime desc;
// --- Part 3: Most recent password change relative to alert ---
let LastPasswordChange = toscalar(PasswordChanges | top 1 by PasswordChangeTime desc | project PasswordChangeTime);
// --- Part 4: Combined output ---
RiskState
| extend
    LastPasswordChange = LastPasswordChange,
    PasswordChangedAfterLeak = iff(isnotempty(LastPasswordChange) and LastPasswordChange > AlertTime,
        "YES - Password was changed AFTER leak detection",
        "NO - Password has NOT been changed since leak detection"),
    DaysSincePasswordChange = iff(isnotempty(LastPasswordChange),
        datetime_diff("day", now(), LastPasswordChange),
        -1),
    PasswordUrgency = case(
        isnotempty(LastPasswordChange) and LastPasswordChange > AlertTime,
            "LOW - Password already rotated after detection",
        isnotempty(LastPasswordChange) and datetime_diff("day", AlertTime, LastPasswordChange) < 30,
            "MEDIUM - Password changed recently but before detection",
        isnotempty(LastPasswordChange) and datetime_diff("day", AlertTime, LastPasswordChange) >= 30,
            "HIGH - Password unchanged for 30+ days before detection",
        isempty(LastPasswordChange),
            "CRITICAL - No password change detected in 90-day window",
        "UNKNOWN"
    )
```

**Performance Notes:**
- AuditLogs scan is filtered by specific OperationName values - fast
- AADRiskyUsers returns the most recent risk state for the user
- Expected result: 1 row with risk state, last password change, and urgency assessment

**Tuning Guidance:**
- **LookbackWindow for password changes**: Default 90d. Extend to 180d for very old accounts
- **If no password change found**: The password may have been set >90 days ago and never changed. This significantly increases risk

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Password timeline | Password NOT changed since leak detection | Password changed AFTER leak detection |
| Risk state | "atRisk" or "confirmedCompromised" | "remediated" or "dismissed" |
| Change source | No password changes detected | Admin-initiated reset after alert |
| Staleness | Password >90 days old | Password recently rotated |

**Next action:**
- If password NOT changed + risk state "atRisk" -> HIGH urgency, proceed to Step 3
- If password changed after detection -> lower urgency but still complete investigation
- If risk state "confirmedCompromised" -> skip to Containment immediately

---

### Step 3: Baseline Comparison - Establish Normal Sign-In Pattern

**Purpose:** Build a 30-day sign-in baseline for the user to enable anomaly detection in Step 4. Without understanding what "normal" looks like, you cannot determine if post-leak sign-ins are suspicious. This step is MANDATORY.

**Label:** Step 3: Baseline Comparison - Establish Normal Sign-In Pattern

**Data needed from:**
- Table: SigninLogs - pull 30 days of historical sign-in data for the user

**Baseline metrics to calculate:**
- Distinct countries, cities, and IP addresses
- Typical sign-in times (business hours vs. off-hours)
- Known devices and browsers
- Known applications
- Success vs. failure ratio
- Average daily sign-in count

#### Query 3: Sign-In Baseline (30-day) - MANDATORY

```kql
// ============================================================
// Query 3: Sign-In Baseline (30-day)
// Purpose: Establish the user's normal sign-in pattern over
//          the past 30 days for anomaly comparison in Step 4
// Table: SigninLogs
// MANDATORY - Do not skip this query
// Expected runtime: 5-15 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let BaselinePeriod = 30d;
let BaselineStart = AlertTime - BaselinePeriod;
let BaselineEnd = AlertTime - 1d;
// --- Part 1: Geographic and device footprint ---
let BaselineSignins = SigninLogs
    | where TimeGenerated between (BaselineStart .. BaselineEnd)
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | extend
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        DeviceId = tostring(DeviceDetail.deviceId),
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceBrowser = tostring(DeviceDetail.browser);
// --- Part 2: Summarize baseline ---
let BaselineSummary = BaselineSignins
    | summarize
        TotalSignins = count(),
        DistinctIPs = dcount(IPAddress),
        DistinctCities = dcount(City),
        DistinctCountries = dcount(Country),
        DistinctDevices = dcount(DeviceId),
        KnownIPs = make_set(IPAddress, 50),
        KnownCities = make_set(City),
        KnownCountries = make_set(Country),
        KnownDeviceIds = make_set(DeviceId, 20),
        KnownBrowsers = make_set(DeviceBrowser),
        KnownOSs = make_set(DeviceOS),
        KnownApps = make_set(AppDisplayName, 20),
        FirstSignin = min(TimeGenerated),
        LastSignin = max(TimeGenerated),
        ActiveDays = dcount(bin(TimeGenerated, 1d));
// --- Part 3: Time-of-day pattern ---
let TimePattern = BaselineSignins
    | extend HourOfDay = hourofday(TimeGenerated)
    | summarize HourCounts = count() by HourOfDay
    | order by HourOfDay asc
    | summarize
        BusinessHourSignins = sumif(HourCounts, HourOfDay between (8 .. 18)),
        OffHourSignins = sumif(HourCounts, HourOfDay < 8 or HourOfDay > 18),
        PeakHour = arg_max(HourCounts, HourOfDay);
// --- Part 4: Failure baseline ---
let FailureBaseline = SigninLogs
    | where TimeGenerated between (BaselineStart .. BaselineEnd)
    | where UserPrincipalName == TargetUser
    | where ResultType != "0"
    | summarize
        FailedSignins = count(),
        FailedDistinctIPs = dcount(IPAddress),
        FailureResultCodes = make_set(ResultType, 10);
// --- Part 5: Combined output ---
BaselineSummary
| extend placeholder = 1
| join kind=leftouter (TimePattern | extend placeholder = 1) on placeholder
| join kind=leftouter (FailureBaseline | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1, placeholder2
| extend
    AvgSigninsPerDay = round(toreal(TotalSignins) / toreal(ActiveDays), 1),
    FailedSignins = coalesce(FailedSignins, 0),
    FailedDistinctIPs = coalesce(FailedDistinctIPs, 0),
    BaselineRichness = case(
        ActiveDays >= 20, "STRONG - 20+ active days, reliable baseline",
        ActiveDays >= 10, "MODERATE - 10-20 active days, usable baseline",
        ActiveDays >= 3, "WEAK - 3-10 active days, limited baseline",
        "INSUFFICIENT - <3 active days, cannot establish pattern"
    )
```

**Performance Notes:**
- Query scans 30 days of SigninLogs for a single user - moderate volume
- The time-of-day pattern helps identify off-hours sign-ins as anomalous
- Failure baseline is important for leaked credentials because attackers often test credentials with failed attempts first
- If the user has >50 distinct IPs, consider reducing BaselinePeriod to 14d

**Tuning Guidance:**
- **BaselinePeriod**: Default 30d. Use 14d for very active users, 60d for infrequent users
- **BaselineRichness**: If INSUFFICIENT, the user may be a new account or inactive. New accounts with leaked credentials are especially risky

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Baseline richness | New account with <3 days of data | Well-established pattern with 20+ days |
| Failure baseline | Spike in failed sign-ins from unknown IPs | Consistent low failure rate |
| Geographic scope | User typically signs in from single country | User already signs in from multiple countries |
| Device scope | User consistently uses 1-2 devices | User already uses many devices |

**Next action:**
- Save KnownIPs, KnownCountries, KnownDeviceIds for comparison in Step 4
- If BaselineRichness is INSUFFICIENT -> investigate cautiously, lean toward password reset
- Proceed to Step 4 with baseline reference data

---

### Step 4: Anomalous Sign-In Detection (Post-Leak)

**Purpose:** Search for sign-ins that deviate from the baseline established in Step 3. Focus on the period around and after the leak detection. Include BOTH successful AND failed sign-ins - failed sign-ins from unknown IPs indicate credential testing. This is the core detection step unique to leaked credentials investigations.

**Data needed from:**
- Table: SigninLogs - successful and failed sign-ins from unfamiliar IPs, locations, or devices
- Table: AADNonInteractiveUserSignInLogs - token activity from anomalous IPs

#### Query 4A: Anomalous Sign-In Detection

```kql
// ============================================================
// Query 4A: Anomalous Sign-In Detection (Post-Leak)
// Purpose: Find sign-ins from IPs, locations, and devices NOT
//          present in the 30-day baseline. Includes failed
//          sign-ins to detect credential testing.
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let BaselinePeriod = 30d;
let PostLeakWindow = 7d;
let BaselineStart = AlertTime - BaselinePeriod;
let BaselineEnd = AlertTime - 1d;
// --- Part 1: Build baseline IP set ---
let BaselineIPs = SigninLogs
    | where TimeGenerated between (BaselineStart .. BaselineEnd)
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | distinct IPAddress;
// --- Part 2: Build baseline country set ---
let BaselineCountries = SigninLogs
    | where TimeGenerated between (BaselineStart .. BaselineEnd)
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | distinct Country;
// --- Part 3: Find ALL sign-ins (success + failure) from non-baseline IPs ---
let AnomalousSignins = SigninLogs
    | where TimeGenerated between ((AlertTime - 7d) .. (AlertTime + PostLeakWindow))
    | where UserPrincipalName == TargetUser
    | where IPAddress !in (BaselineIPs)
    | extend
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        DeviceId = tostring(DeviceDetail.deviceId),
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceBrowser = tostring(DeviceDetail.browser),
        DeviceIsCompliant = tostring(DeviceDetail.isCompliant),
        DeviceIsManaged = tostring(DeviceDetail.isManaged)
    | project
        SigninTime = TimeGenerated,
        IPAddress,
        City,
        Country,
        DeviceId,
        DeviceOS,
        DeviceBrowser,
        DeviceIsCompliant,
        DeviceIsManaged,
        UserAgent,
        AppDisplayName,
        ResourceDisplayName,
        ClientAppUsed,
        AuthenticationRequirement,
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA performed"),
        ConditionalAccessStatus,
        ResultType,
        ResultDescription = case(
            ResultType == "0", "SUCCESS",
            ResultType == "50126", "INVALID PASSWORD",
            ResultType == "50074", "MFA REQUIRED - Strong auth needed",
            ResultType == "50076", "MFA REQUIRED - Reauthentication needed",
            ResultType == "53003", "BLOCKED BY CONDITIONAL ACCESS",
            ResultType == "530032", "BLOCKED - Security policy",
            ResultType == "50053", "ACCOUNT LOCKED",
            ResultType == "50057", "ACCOUNT DISABLED",
            strcat("OTHER - ", ResultType)
        ),
        IsNewCountry = Country !in (BaselineCountries),
        MinutesFromAlert = datetime_diff("minute", TimeGenerated, AlertTime)
    | extend
        SigninRiskAssessment = case(
            ResultType == "0" and IsNewCountry and AuthenticationRequirement == "singleFactorAuthentication",
                "CRITICAL - Successful sign-in from new country WITHOUT MFA",
            ResultType == "0" and IsNewCountry,
                "HIGH - Successful sign-in from new country",
            ResultType == "0" and not(IsNewCountry),
                "MEDIUM - Successful sign-in from new IP (known country)",
            ResultType == "50126",
                "MONITOR - Invalid password from unknown IP (credential testing)",
            ResultType in ("50074", "50076"),
                "MONITOR - MFA blocked unauthorized access (credential valid but MFA stopped it)",
            ResultType == "53003",
                "INFO - Conditional Access blocked the sign-in",
            "INFO - Failed for other reason"
        )
    | order by SigninTime desc;
// --- Part 4: Summary ---
AnomalousSignins
| summarize
    TotalAnomalousSignins = count(),
    SuccessfulFromNewIP = countif(ResultType == "0"),
    FailedFromNewIP = countif(ResultType != "0"),
    DistinctAnomalousIPs = dcount(IPAddress),
    AnomalousIPList = make_set(IPAddress, 20),
    AnomalousCountries = make_set(Country),
    NewCountries = make_set_if(Country, IsNewCountry),
    CriticalEvents = countif(SigninRiskAssessment has "CRITICAL"),
    HighEvents = countif(SigninRiskAssessment has "HIGH"),
    CredentialTestingEvents = countif(ResultType == "50126"),
    MFABlockedEvents = countif(ResultType in ("50074", "50076")),
    EarliestAnomaly = min(SigninTime),
    LatestAnomaly = max(SigninTime)
| extend
    OverallAssessment = case(
        CriticalEvents > 0,
            "CRITICAL - Successful unauthorized access detected from new country without MFA",
        HighEvents > 0,
            "HIGH - Successful access from new location (with MFA)",
        CredentialTestingEvents > 5,
            "HIGH - Active credential testing detected (multiple invalid password attempts)",
        MFABlockedEvents > 0,
            "MEDIUM - Credential is valid but MFA is blocking access",
        SuccessfulFromNewIP > 0,
            "MEDIUM - Access from new IP in known country",
        FailedFromNewIP > 0 and CredentialTestingEvents > 0,
            "LOW-MEDIUM - Some credential testing but all blocked",
        TotalAnomalousSignins == 0,
            "LOW - No sign-ins from unknown IPs detected",
        "REVIEW"
    )
```

#### Query 4B: Non-Interactive Sign-Ins from Anomalous IPs

```kql
// ============================================================
// Query 4B: Non-Interactive Sign-Ins from Anomalous IPs
// Purpose: Check for token/session usage from IPs not in the
//          user's 30-day baseline (silent compromise indicator)
// Table: AADNonInteractiveUserSignInLogs
// Expected runtime: 5-10 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let BaselinePeriod = 30d;
let PostLeakWindow = 7d;
let BaselineStart = AlertTime - BaselinePeriod;
let BaselineEnd = AlertTime - 1d;
// Build baseline IP set from interactive sign-ins
let BaselineIPs = SigninLogs
    | where TimeGenerated between (BaselineStart .. BaselineEnd)
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | distinct IPAddress;
// Check non-interactive sign-ins from unknown IPs
AADNonInteractiveUserSignInLogs
| where TimeGenerated between ((AlertTime - 7d) .. (AlertTime + PostLeakWindow))
| where UserPrincipalName == TargetUser
| where ResultType == "0"
| where IPAddress !in (BaselineIPs)
| summarize
    TotalEvents = count(),
    DistinctIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 20),
    DistinctApps = make_set(AppDisplayName),
    DistinctResources = make_set(ResourceDisplayName),
    EarliestEvent = min(TimeGenerated),
    LatestEvent = max(TimeGenerated),
    Countries = make_set(tostring(LocationDetails.countryOrRegion))
| extend
    NonInteractiveAssessment = case(
        TotalEvents > 0 and DistinctIPs > 0,
            "WARNING - Active token usage from unknown IPs (possible silent compromise)",
        "CLEAR - No non-interactive activity from unknown IPs"
    )
```

**Performance Notes:**
- Query 4A intentionally includes failed sign-ins (ResultType != "0") which is unique to this runbook
- The baseline IP comparison efficiently identifies sign-ins from previously unseen sources
- Query 4B scans AADNonInteractiveUserSignInLogs which can be high volume - the user filter is critical
- Expected result for 4A: summary of anomalous sign-in activity with risk assessment
- Expected result for 4B: summary of non-interactive activity from unknown IPs

**Tuning Guidance:**
- **PostLeakWindow**: Default 7d. Expand to 14d or 30d for thorough investigation of long-standing leaks
- **Credential testing threshold**: Default 5 failed attempts. In high-security environments, lower to 3
- **Baseline IP comparison**: If user has >50 baseline IPs, the anomaly detection may be less sensitive

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Successful anomalous sign-ins | SUCCESS from new country without MFA | No successful anomalous sign-ins |
| Credential testing | Multiple "50126" (invalid password) from unknown IPs | No or very few failures from unknown IPs |
| MFA blocking | "50074" results showing valid cred + MFA block | N/A (MFA blocking is good but confirms cred exposure) |
| Non-interactive | Token activity from unknown IPs | No non-interactive from unknown IPs |

**Next action:**
- If CRITICAL or HIGH assessment -> proceed to Step 5 and Containment
- If MFA blocked events detected -> credential is confirmed valid, proceed to Step 5 + force password reset
- If credential testing detected -> proceed to Step 5, consider preemptive password reset
- If no anomalous activity -> proceed to Step 6 for MFA/legacy auth check

---

### Step 5: Analyze Post-Sign-In Activity (Blast Radius Assessment)

**Purpose:** If any anomalous sign-ins were successful, determine what the account did after those sign-ins. Check for persistence mechanisms, data access, and lateral movement indicators. This step reuses patterns from RB-0001 Step 5 / RB-0002 Step 6.

**Data needed from:**
- Table: AuditLogs - directory changes made by this user after the alert
- Table: OfficeActivity - email, SharePoint, OneDrive, Teams activity after the alert

#### Query 5A: Directory Changes After Leak Detection (Persistence Detection)

```kql
// ============================================================
// Query 5A: Directory Changes After Leak Detection
// Purpose: Check for persistence mechanisms created via
//          directory operations after the leaked credential
// Table: AuditLogs
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let PostLeakWindow = 7d;
AuditLogs
| where TimeGenerated between ((AlertTime - 7d) .. (AlertTime + PostLeakWindow))
| where OperationName in (
    "User registered security info",
    "User deleted security info",
    "Admin registered security info",
    "Register security info",
    "Update StsRefreshTokenValidFrom",
    "Consent to application",
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Add owner to application",
    "Add app role assignment grant to user",
    "Update user",
    "Reset password (by admin)",
    "Reset user password",
    "Change user password",
    "Register device",
    "Add registered owner to device",
    "Add member to role",
    "Add eligible member to role"
)
| mv-expand TargetResource = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) == TargetUser
    or tostring(TargetResource.userPrincipalName) == TargetUser
| extend
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    TargetUPN = tostring(TargetResource.userPrincipalName),
    TargetDisplayName = tostring(TargetResource.displayName),
    ModifiedProperties = TargetResource.modifiedProperties
| project
    TimeGenerated,
    OperationName,
    Category,
    InitiatedByUser,
    InitiatedByApp,
    TargetUPN,
    TargetDisplayName,
    ModifiedProperties,
    DaysFromAlert = datetime_diff("day", TimeGenerated, AlertTime),
    Severity = case(
        OperationName has "security info", "CRITICAL - MFA MANIPULATION",
        OperationName has "Consent to application", "CRITICAL - OAUTH APP CONSENT",
        OperationName has "delegated permission", "CRITICAL - API PERMISSION GRANT",
        OperationName has "owner to application", "CRITICAL - APP OWNERSHIP CHANGE",
        OperationName has "member to role", "CRITICAL - ROLE ESCALATION",
        OperationName has "password", "HIGH - PASSWORD CHANGE",
        OperationName has "Register device", "HIGH - DEVICE REGISTRATION",
        OperationName has "Update user", "MEDIUM - USER MODIFICATION",
        "INFO"
    ),
    CorrelationId
| order by TimeGenerated asc
```

#### Query 5B: Email and File Activity

```kql
// ============================================================
// Query 5B: Email and File Activity After Leak Detection
// Purpose: Check for inbox rule creation, email forwarding,
//          bulk email access, and file exfiltration patterns
// Table: OfficeActivity
// Expected runtime: 5-10 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let PostLeakWindow = 7d;
OfficeActivity
| where TimeGenerated between ((AlertTime - 7d) .. (AlertTime + PostLeakWindow))
| where UserId == TargetUser
| extend CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
| project
    TimeGenerated,
    Operation,
    OfficeWorkload,
    UserId,
    CleanClientIP,
    RawClientIP = ClientIP,
    DaysFromAlert = datetime_diff("day", TimeGenerated, AlertTime),
    RiskCategory = case(
        Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule"),
            "CRITICAL - INBOX RULE",
        Operation in ("Set-Mailbox", "Set-TransportRule") and OfficeWorkload == "Exchange",
            "CRITICAL - MAILBOX FORWARDING",
        Operation in ("Add-MailboxPermission", "Add-RecipientPermission"),
            "HIGH - DELEGATE ACCESS",
        Operation == "MailItemsAccessed",
            "MONITOR - EMAIL ACCESS",
        Operation == "Send",
            "MONITOR - EMAIL SENT",
        Operation in ("FileDownloaded", "FileSyncDownloadedFull"),
            "MONITOR - FILE DOWNLOAD",
        Operation in ("FileAccessed", "FileAccessedExtended"),
            "INFO - FILE ACCESS",
        "INFO"
    ),
    Parameters
| order by TimeGenerated asc
```

#### Query 5C: Inbox Rule Deep Dive

```kql
// ============================================================
// Query 5C: Inbox Rule Deep Dive
// Purpose: Extract inbox rule creation details - the #1
//          persistence mechanism in BEC attacks
// Table: OfficeActivity
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let PostLeakWindow = 7d;
OfficeActivity
| where TimeGenerated between ((AlertTime - 7d) .. (AlertTime + PostLeakWindow))
| where UserId == TargetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| mv-expand Parameter = parse_json(Parameters)
| summarize
    RuleParameters = make_bag(pack(tostring(Parameter.Name), tostring(Parameter.Value)))
    by TimeGenerated, Operation, UserId, ClientIP
| extend
    RuleName = tostring(RuleParameters.Name),
    ForwardTo = tostring(RuleParameters.ForwardTo),
    ForwardAsAttachmentTo = tostring(RuleParameters.ForwardAsAttachmentTo),
    RedirectTo = tostring(RuleParameters.RedirectTo),
    DeleteMessage = tostring(RuleParameters.DeleteMessage),
    MarkAsRead = tostring(RuleParameters.MarkAsRead),
    MoveToFolder = tostring(RuleParameters.MoveToFolder),
    SubjectContainsWords = tostring(RuleParameters.SubjectContainsWords),
    FromAddressContainsWords = tostring(RuleParameters.FromAddressContainsWords)
| extend
    IsMalicious = iff(
        isnotempty(ForwardTo) or isnotempty(ForwardAsAttachmentTo) or isnotempty(RedirectTo)
        or DeleteMessage == "True" or MarkAsRead == "True"
        or SubjectContainsWords has_any ("invoice", "payment", "wire", "transfer", "urgent", "password", "security"),
        "LIKELY MALICIOUS",
        "REVIEW REQUIRED"
    )
| project
    TimeGenerated,
    Operation,
    UserId,
    RuleName,
    ForwardTo,
    ForwardAsAttachmentTo,
    RedirectTo,
    DeleteMessage,
    MarkAsRead,
    MoveToFolder,
    SubjectContainsWords,
    FromAddressContainsWords,
    IsMalicious,
    CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
```

**Performance Notes:**
- All queries in this step scan a 14-day window (7 days before and after alert) to catch pre-detection compromise
- OfficeActivity has up to 60 min ingestion latency. If the alert is <1 hour old, results may be incomplete
- Unlike RB-0001/RB-0002 which check 4h post-sign-in windows, leaked credentials may have been in use for days before detection, so we check a wider window

**Tuning Guidance:**
- **PostLeakWindow**: Default 7d. For fast triage use 3d, for thorough investigation expand to 30d
- **Pre-leak activity**: We also check 7 days BEFORE the alert because the credentials may have been used before Microsoft detected the leak

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Inbox rules | New rule forwarding/deleting email | No new inbox rules |
| MFA changes | New MFA method registered from anomalous IP | No MFA changes or changes from known IP |
| OAuth apps | New app consent with broad permissions | No new app consents |
| File access | Bulk downloads from anomalous IP | Normal file access patterns |

**Next action:**
- If ANY persistence found -> CONFIRMED COMPROMISE, proceed to Containment
- If bulk data access detected -> CONFIRMED COMPROMISE with data exposure
- If no suspicious activity -> proceed to Step 6

---

### Step 6: MFA and Legacy Auth Exposure Assessment

**Purpose:** Determine whether the leaked credential can be exploited even if the organization has Conditional Access policies. This step checks MFA enforcement status and legacy authentication exposure. A leaked password with MFA enforced is significantly less risky than one without MFA. However, legacy auth protocols (IMAP, POP3, SMTP, Exchange ActiveSync) bypass MFA entirely.

**Data needed from:**
- Table: SigninLogs - check for legacy auth usage and MFA status

#### Query 6: MFA and Legacy Auth Assessment

```kql
// ============================================================
// Query 6: MFA and Legacy Auth Assessment
// Purpose: Determine MFA enforcement status and check for
//          legacy authentication protocol exposure
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let AssessmentPeriod = 30d;
// --- Part 1: MFA usage analysis ---
let MfaAnalysis = SigninLogs
    | where TimeGenerated > (AlertTime - AssessmentPeriod)
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | summarize
        TotalSuccessfulSignins = count(),
        MFAEnforced = countif(AuthenticationRequirement == "multiFactorAuthentication"),
        SFAOnly = countif(AuthenticationRequirement == "singleFactorAuthentication"),
        MFAMethods = make_set_if(tostring(MfaDetail.authMethod), isnotempty(MfaDetail)),
        DistinctApps = make_set(AppDisplayName, 20);
// --- Part 2: Legacy auth detection ---
let LegacyAuth = SigninLogs
    | where TimeGenerated > (AlertTime - AssessmentPeriod)
    | where UserPrincipalName == TargetUser
    | where ClientAppUsed in (
        "Exchange ActiveSync",
        "IMAP4", "POP3", "SMTP",
        "Other clients",
        "Authenticated SMTP",
        "Exchange Web Services"
    )
    | summarize
        LegacyAuthEvents = count(),
        LegacySuccessful = countif(ResultType == "0"),
        LegacyFailed = countif(ResultType != "0"),
        LegacyProtocols = make_set(ClientAppUsed),
        LegacyIPs = make_set(IPAddress, 10),
        LegacyApps = make_set(AppDisplayName, 10);
// --- Part 3: Conditional Access assessment ---
let CaAnalysis = SigninLogs
    | where TimeGenerated > (AlertTime - AssessmentPeriod)
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | summarize
        CASuccess = countif(ConditionalAccessStatus == "success"),
        CANotApplied = countif(ConditionalAccessStatus == "notApplied"),
        CAFailure = countif(ConditionalAccessStatus == "failure");
// --- Part 4: Combined output ---
MfaAnalysis
| extend placeholder = 1
| join kind=leftouter (LegacyAuth | extend placeholder = 1) on placeholder
| join kind=leftouter (CaAnalysis | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1, placeholder2
| extend
    LegacyAuthEvents = coalesce(LegacyAuthEvents, 0),
    LegacySuccessful = coalesce(LegacySuccessful, 0),
    LegacyFailed = coalesce(LegacyFailed, 0),
    MFACoverage = round(100.0 * MFAEnforced / TotalSuccessfulSignins, 1),
    MFAStatus = case(
        SFAOnly == 0 and MFAEnforced > 0,
            "FULLY ENFORCED - All sign-ins required MFA",
        toreal(MFAEnforced) / TotalSuccessfulSignins > 0.9,
            "MOSTLY ENFORCED - >90% of sign-ins had MFA",
        MFAEnforced > 0,
            "PARTIALLY ENFORCED - Some sign-ins bypassed MFA",
        "NOT ENFORCED - No MFA detected in sign-in history"
    ),
    LegacyAuthRisk = case(
        LegacySuccessful > 0,
            "CRITICAL - Legacy auth is ACTIVE and bypasses MFA",
        LegacyFailed > 0,
            "MEDIUM - Legacy auth attempted but failed",
        "LOW - No legacy auth activity detected"
    ),
    OverallExposure = case(
        SFAOnly > 0 and LegacySuccessful > 0,
            "CRITICAL - No MFA + active legacy auth = fully exposed",
        SFAOnly == 0 and LegacySuccessful > 0,
            "HIGH - MFA enforced but legacy auth bypasses it",
        SFAOnly > 0 and LegacySuccessful == 0,
            "HIGH - No MFA enforced (legacy auth not active but still vulnerable)",
        SFAOnly == 0 and LegacySuccessful == 0,
            "LOW - MFA enforced and no legacy auth exposure",
        "REVIEW"
    ),
    CANotApplied = coalesce(CANotApplied, 0)
```

**Performance Notes:**
- Query scans 30 days of SigninLogs for a single user - moderate volume
- Legacy auth detection is critical for leaked credentials because these protocols bypass MFA
- Expected result: 1 row with MFA status, legacy auth exposure, and overall risk assessment

**Tuning Guidance:**
- **Legacy auth protocols**: The list includes all known legacy auth protocols. "Other clients" catches unidentified legacy protocols
- **MFA coverage**: Even 90% MFA coverage means some sign-ins bypass MFA - investigate why
- **Exchange Web Services**: While technically modern auth, older EWS implementations may not enforce MFA

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| MFA status | Not enforced or partially enforced | Fully enforced on all sign-ins |
| Legacy auth | Active successful legacy auth sign-ins | No legacy auth detected |
| CA policies | Some sign-ins have "notApplied" | All sign-ins protected by CA |
| Overall | Password-only access possible | MFA + no legacy auth = credential alone insufficient |

**Next action:**
- If CRITICAL exposure (no MFA + legacy auth active) -> immediate password reset + block legacy auth
- If HIGH exposure (MFA but legacy auth active) -> block legacy auth + force password reset
- If LOW exposure (MFA enforced + no legacy auth) -> force password reset as precaution, lower urgency
- Proceed to Step 7 for IP reputation on any anomalous IPs found in Step 4

---

### Step 7: IP Reputation and Context

**Purpose:** If anomalous sign-in IPs were identified in Step 4, check their reputation against threat intelligence feeds and organizational usage patterns.

#### Query 7A: Threat Intelligence Lookup

```kql
// ============================================================
// Query 7A: Threat Intelligence Lookup
// Purpose: Check anomalous IPs found in Step 4 against
//          configured threat intelligence feeds
// Table: ThreatIntelligenceIndicator
// Expected runtime: <3 seconds
// ============================================================
// Replace with anomalous IPs from Query 4A results
let AnomalousIPs = dynamic(["198.51.100.42", "203.0.113.99"]);
ThreatIntelligenceIndicator
| where isnotempty(NetworkIP)
| where Active == true
| where ExpirationDateTime > now()
| where NetworkIP in (AnomalousIPs)
| where ConfidenceScore >= 50
| project
    NetworkIP,
    ThreatType,
    ConfidenceScore,
    Description,
    Tags,
    ThreatSeverity,
    SourceSystem,
    ExpirationDateTime,
    LastUpdated = TimeGenerated,
    TIAssessment = case(
        ConfidenceScore >= 80, "HIGH CONFIDENCE - Known malicious IP",
        ConfidenceScore >= 50, "MEDIUM CONFIDENCE - Potentially malicious IP",
        "LOW CONFIDENCE - Weak indicator"
    )
| order by ConfidenceScore desc
```

#### Query 7B: Organizational IP Usage Check

```kql
// ============================================================
// Query 7B: Organizational IP Usage Check
// Purpose: Determine if anomalous IPs from Step 4 have been
//          used by other legitimate users in the organization
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
// Replace with anomalous IPs from Query 4A results
let AnomalousIPs = dynamic(["198.51.100.42", "203.0.113.99"]);
let TargetUser = "user@contoso.com";
let LookbackPeriod = 30d;
SigninLogs
| where TimeGenerated > ago(LookbackPeriod)
| where IPAddress in (AnomalousIPs)
| where ResultType == "0"
| summarize
    TotalSignins = count(),
    DistinctUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 20),
    EarliestSeen = min(TimeGenerated),
    LatestSeen = max(TimeGenerated),
    DistinctApps = make_set(AppDisplayName, 10)
    by IPAddress
| extend
    IPClassification = case(
        DistinctUsers > 10,
            "LIKELY CORPORATE - Used by 10+ users (shared exit IP)",
        DistinctUsers > 3,
            "POSSIBLY CORPORATE - Used by multiple users",
        DistinctUsers == 1 and UserList has TargetUser,
            "SINGLE USER - Only used by the target user",
        DistinctUsers == 1 and not(UserList has TargetUser),
            "SINGLE OTHER USER - Used by a different user only",
        DistinctUsers == 0,
            "NEVER SEEN - IP has never been used for successful sign-ins",
        "UNKNOWN"
    ),
    IsTargetUserIncluded = iff(UserList has TargetUser, "Yes", "No")
| order by DistinctUsers desc
```

**Performance Notes:**
- Query 7A: ThreatIntelligenceIndicator is typically a small table - very fast
- Query 7B: 30-day scan filtered by specific IPs - fast
- Only run these queries if Step 4 identified anomalous IPs

**Tuning Guidance:**
- **TI ConfidenceScore**: Default >= 50. Increase to >= 80 for high precision
- **AnomalousIPs**: Replace the placeholder array with actual IPs from Query 4A results

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| TI match | Anomalous IP in threat intelligence feeds | IP not in TI feeds |
| Org usage | IP never seen in organization | IP used by other org users (shared VPN) |
| User count | Single user or no users | 10+ users (corporate IP) |

---

## 6. Containment Playbook

Execute in this order. IMPORTANT: Collect evidence (Section 7 checklist) BEFORE taking containment actions that could alert the attacker or destroy evidence.

### Immediate Actions (within 15 minutes of confirmed compromise):

1. **Force password reset** - Reset the user's password immediately. This is the MOST CRITICAL action for leaked credentials. Use a strong temporary password and communicate via out-of-band channel (phone call, SMS, in-person). Do NOT send the new password via the potentially compromised email.

2. **Revoke all active sessions** - Revoke the user's refresh tokens via Entra ID to invalidate all active sessions across all devices.

3. **Block legacy authentication** - If legacy auth is active for this user, create a Conditional Access policy to block legacy auth protocols immediately. Legacy auth bypasses MFA and is the primary exploitation vector for leaked credentials.

4. **Disable suspicious inbox rules** - If inbox rules were created for forwarding/deletion, disable them immediately.

### Follow-up Actions (within 1 hour):

5. **Enforce MFA** - If the user does not have MFA enforced, enable it immediately. Require MFA registration through a trusted device/session.

6. **Review and remove unauthorized MFA methods** - If the attacker registered a new MFA method, remove it. Verify remaining MFA methods with the user through out-of-band channel.

7. **Revoke OAuth application consents** - If unauthorized applications were granted consent, revoke the application permissions.

8. **Remove email forwarding rules** - Check and remove any mailbox forwarding rules (both inbox rules and mailbox-level forwarding via Set-Mailbox).

### Extended Actions (within 24 hours):

9. **Notify the user** - Contact the user via out-of-band channel. Instruct them to change their password on ALL services where they used the same password.

10. **Check for data exposure** - Review what data was accessed during the compromise window. Determine if notification is required.

11. **Hunt for related compromises** - Check if other users in the organization appear in the same credential dump. Run the leak detection across all users.

12. **Review password policy** - Evaluate whether the organization should implement banned password lists, password expiration, or Azure AD Password Protection.

13. **Block anomalous IPs** - If specific attacker IPs were identified, add them to Conditional Access as blocked locations.

---

## 7. Evidence Collection Checklist

Preserve the following BEFORE taking containment actions:

- [ ] Risk event record from AADUserRiskEvents (including AdditionalInfo and detection timing)
- [ ] User risk state from AADRiskyUsers (current risk level and state)
- [ ] Password change history from AuditLogs (last 90 days)
- [ ] 30-day sign-in baseline for the user (SigninLogs - all successful sign-ins)
- [ ] All anomalous sign-in records (successful AND failed from non-baseline IPs)
- [ ] Non-interactive sign-in records from anomalous IPs
- [ ] All AuditLogs entries for the user in the 14 days surrounding the event
- [ ] All OfficeActivity records for the user in the 14 days surrounding the event
- [ ] Inbox rules snapshot (current state before remediation)
- [ ] Mailbox forwarding configuration snapshot
- [ ] OAuth application consent list for the user
- [ ] MFA registration details for the user
- [ ] Legacy auth usage summary (which protocols, which IPs)
- [ ] MFA enforcement status and Conditional Access policy results
- [ ] IP reputation and TI lookup results for anomalous IPs
- [ ] Screenshot of the risk event in the Entra ID portal
- [ ] Timeline of all events (chronological reconstruction)

---

## 8. Escalation Criteria

### Escalate to Senior Analyst when:
- Successful sign-in from unknown IP/country without MFA detected
- Post-sign-in persistence confirmed (inbox rules, OAuth apps, MFA changes)
- Active credential testing detected (>5 failed sign-ins from unknown IPs)
- User has active legacy auth that bypasses MFA
- Compound risk events (leaked credentials + other risk detections)

### Escalate to Customer/Management when:
- Confirmed credential compromise with verified post-sign-in abuse
- Any data exposure involving PII, financial data, or regulated information
- Compromise of executive or finance team accounts (high BEC risk)
- Multiple users affected by the same credential dump

### Escalate to Incident Response Team when:
- Evidence of coordinated credential stuffing campaign against the organization
- Compromise has spread to multiple accounts
- Attacker has gained administrative privileges
- Evidence of info-stealer malware infection (source of credential leak)
- Leaked credentials include service accounts or service principal secrets

---

## 9. False Positive Documentation

### Common Benign Scenarios

**1. Old/stale credential leaks (~50% of false positives)**
- Pattern: The leaked credentials come from a breach that occurred months or years ago. The user has since changed their password multiple times
- How to confirm: Query 2 shows password was changed well before the leak detection. No anomalous sign-ins detected in Step 4
- Tuning note: Microsoft's detection can lag significantly. If the password was changed >90 days before the detection, the risk is minimal. Document and close as BTP

**2. Test/lab accounts (~15% of false positives)**
- Pattern: The affected account is a test, lab, or demo account that appeared in a credential dump. The account may have been used to sign up for testing services
- How to confirm: Account name suggests test/lab purpose. Account has no production access or sensitive role assignments
- Tuning note: Exclude known test accounts from Identity Protection or set their risk policy to a lower severity

**3. Shared email, different password (~15% of false positives)**
- Pattern: The user registered on a third-party website using their corporate email address but a different password. The third-party site was breached, and the email appeared in the dump, but the actual leaked password is not the Entra ID password
- How to confirm: Query 4A shows no successful sign-ins from unknown IPs (the leaked password doesn't work for Entra ID). MFA is enforced. Password has not been changed
- Tuning note: Microsoft's matching algorithm compares password hashes, but some detections are email-match only. If no evidence of successful usage, treat as lower risk

**4. Pre-rotated password (~10% of false positives)**
- Pattern: The security team was already aware of the breach and forced a password reset before Identity Protection's detection fired
- How to confirm: Query 2 shows admin-initiated password reset before the risk event timestamp. Risk state may show "remediated"
- Tuning note: If your organization subscribes to Have I Been Pwned or other breach notification services, you may action leaked credentials before Identity Protection detects them

**5. SSO-only accounts (~10% of false positives)**
- Pattern: The user authenticates exclusively through a federated identity provider (Okta, PingFederate, etc.). The "leaked credential" is the Entra ID password hash that is never actually used for authentication because all sign-ins go through the federated IdP
- How to confirm: All SigninLogs show federated authentication. The Entra ID password is not used for any sign-in
- Tuning note: For fully federated environments, leaked Entra ID passwords are lower risk because the password is not the active authentication credential. Still reset as a precaution

---

## 10. MITRE ATT&CK Mapping

### Primary Technique

**T1078.004 - Valid Accounts: Cloud Accounts** (Confirmed)

The "Leaked credentials" alert detects that a user's cloud credentials have been exposed in a credential dump, directly enabling T1078.004. The secondary key technique is **T1589.001 - Gather Victim Identity Information: Credentials**, which represents the attacker's reconnaissance phase of acquiring credentials from breaches, info-stealer logs, or underground marketplaces.

### Detection Coverage Matrix

| Technique ID | Technique Name | Detecting Query | Coverage Level | Notes |
|---|---|---|---|---|
| T1589.001 | Gather Victim Identity Info: Credentials | Query 1 | **Partial** | Detects the RESULT of credential gathering (leak found) - NEW reconnaissance coverage |
| T1078.004 | Valid Accounts: Cloud Accounts | Query 4A, 6 | **Full** | Detects unauthorized use of leaked credentials |
| T1110.004 | Brute Force: Credential Stuffing | Query 4A | **Full** | Detects credential testing patterns (failed sign-ins from multiple IPs) |
| T1098 | Account Manipulation | Query 5A | **Full** | Post-access persistence |
| T1098.005 | Device Registration | Query 5A | **Full** | Rogue device join |
| T1114.003 | Email Forwarding Rule | Query 5C | **Full** | Inbox rule persistence |
| T1528 | Steal Application Access Token | Query 5A | **Full** | OAuth consent detection |
| T1530 | Data from Cloud Storage Object | Query 5B | **Partial** | Volume-based only |
| T1534 | Internal Spearphishing | Query 5B | **Partial** | Volume-based only |
| T1556.006 | Modify Authentication Process: MFA | Query 5A | **Full** | MFA registration/deletion |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Query 5C | **Full** | Inbox rule deep dive |

**Summary: 11 techniques mapped. 7 with full coverage, 4 with partial coverage.**

**New coverage vs RB-0001/RB-0002:** T1589.001 (Gather Victim Identity Information: Credentials) is the key new technique, providing the first coverage in the **Reconnaissance** tactic across all runbooks. T1110.004 (Credential Stuffing) is upgraded from probable to confirmed via dedicated failed sign-in analysis.

### Attack Chains

**Chain 1: Info-Stealer -> Credential Marketplace -> Account Takeover (Most Relevant)**

```
T1204.001 User Execution: Malicious Link (info-stealer infection)
    | Credentials harvested by malware
T1589.001 Gather Victim Identity Info: Credentials  <-- LEAK DETECTED HERE
    | Credentials sold on dark web marketplace
T1078.004 Valid Accounts: Cloud Accounts  <-- ATTACKER SIGNS IN
    | Attacker bypasses MFA via legacy auth or no MFA
T1098 Account Manipulation (MFA registration)
T1556.006 Modify Authentication Process: MFA
T1564.008 Email Hiding Rules
T1114.003 Email Forwarding Rule
    | Attacker conducts BEC
T1534 Internal Spearphishing
```

Coverage: 8/9 techniques detected (1 partial)

**Chain 2: Credential Stuffing Campaign**

```
T1589.001 Gather Victim Identity Info (bulk credential dump)
    | Automated testing against cloud tenants
T1110.004 Credential Stuffing  <-- DETECTED VIA FAILED SIGN-INS
    | Valid credential found
T1078.004 Valid Accounts: Cloud Accounts
    | Attacker establishes persistence
T1098 Account Manipulation
T1528 Steal Application Access Token (OAuth consent)
T1530 Data from Cloud Storage Object
```

Coverage: 6/6 techniques detected

### Coverage Gaps

| Gap # | Technique | ID | Risk Level | Recommendation |
|---|---|---|---|---|
| 1 | User Execution: Malicious Link | T1204.001 | **High** | Requires endpoint detection (Defender for Endpoint) - outside Sentinel scope |
| 2 | Exfiltration Over Web Service | T1567.002 | **Medium** | Requires Cloud App Security or DLP integration |
| 3 | OS Credential Dumping | T1003 | **High** | Requires endpoint telemetry for info-stealer detection |
| 4 | Phishing: Spearphishing Link | T1566.002 | **Medium** | Create linked runbook for phishing investigation |

> For detailed threat actor profiles, per-technique analysis, and full confidence assessments, see [MITRE Coverage](../../mitre-coverage.md).

---

## 11. Query Summary

| Query | Step | Tables | Purpose | License | Required |
|---|---|---|---|---|---|
| 1 | Step 1 | AADUserRiskEvents | Extract leaked credential risk event and check compound risk | Entra ID P2 | Yes |
| 2 | Step 2 | AADRiskyUsers, AuditLogs | User risk state and password change timeline | Entra ID P2 | Yes |
| 3 | Step 3 | SigninLogs | 30-day sign-in baseline for anomaly detection | Entra ID Free | **MANDATORY** |
| 4A | Step 4 | SigninLogs | Anomalous sign-in detection from non-baseline IPs | Entra ID Free | Yes |
| 4B | Step 4 | AADNonInteractiveUserSignInLogs | Non-interactive sign-ins from anomalous IPs | Entra ID P1/P2 | Yes |
| 5A | Step 5 | AuditLogs | Directory changes after leak detection (persistence) | Entra ID Free | Yes |
| 5B | Step 5 | OfficeActivity | Email and file activity after leak detection | M365 E3+ | Yes |
| 5C | Step 5 | OfficeActivity | Inbox rule deep dive | M365 E3+ | Yes |
| 6 | Step 6 | SigninLogs | MFA enforcement and legacy auth exposure assessment | Entra ID Free | Yes |
| 7A | Step 7 | ThreatIntelligenceIndicator | IP reputation for anomalous IPs | Sentinel + TI | Optional |
| 7B | Step 7 | SigninLogs | Organizational IP usage for anomalous IPs | Entra ID Free | Optional |

**Total: 11 queries (8 required, 1 mandatory, 2 optional)**

**Minimum license for core investigation:** Entra ID P2 + M365 E3 + Sentinel (9 queries)
**Full investigation:** M365 E5 + Sentinel + TI feeds (all 11 queries)

---

## Appendix A: Datatable Tests

All queries include datatable-based inline tests with synthetic data. Each test validates query logic with a mix of malicious and benign scenarios without access to production data.

### Test 1: Query 1 - Extract Leaked Credential Risk Event

```kql
// ============================================================
// TEST: Query 1 - Extract Leaked Credential Risk Event
// Synthetic data: 6 risk event rows (2 leaked + 4 other types)
// ============================================================
let TestRiskEvents = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    RiskEventType: string,
    RiskLevel: string,
    RiskState: string,
    RiskDetail: string,
    DetectionTimingType: string,
    IpAddress: string,
    Location: dynamic,
    AdditionalInfo: dynamic,
    CorrelationId: string,
    Id: string
) [
    // TARGET: Leaked credential risk event (offline detection, no IP)
    datetime(2026-02-22T10:00:00Z), "user@contoso.com", "leakedCredentials", "high",
        "atRisk", "", "offline", "",
        dynamic(null), dynamic([{"Key":"source","Value":"dark_web_dump"}]),
        "corr-001", "risk-001",
    // COMPOUND: Unfamiliar sign-in 2 days later (indicates cred usage)
    datetime(2026-02-24T14:00:00Z), "user@contoso.com", "unfamiliarFeatures", "medium",
        "atRisk", "", "realtime", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic(null), "corr-002", "risk-002",
    // DIFFERENT USER: Should be filtered out
    datetime(2026-02-22T11:00:00Z), "other@contoso.com", "leakedCredentials", "medium",
        "atRisk", "", "offline", "",
        dynamic(null), dynamic(null), "corr-003", "risk-003",
    // DIFFERENT TYPE: anonymizedIPAddress for different user
    datetime(2026-02-23T09:00:00Z), "colleague@contoso.com", "anonymizedIPAddress", "low",
        "atRisk", "", "realtime", "203.0.113.10",
        dynamic({"city":"Unknown"}), dynamic(null), "corr-004", "risk-004",
    // OLD EVENT: Already remediated leak for target user
    datetime(2026-01-15T08:00:00Z), "user@contoso.com", "leakedCredentials", "medium",
        "remediated", "adminDismissedAllRiskForUser", "offline", "",
        dynamic(null), dynamic(null), "corr-005", "risk-005",
    // BENIGN: Normal risk event for other user
    datetime(2026-02-21T16:00:00Z), "vpnuser@contoso.com", "impossibleTravel", "low",
        "dismissed", "", "realtime", "203.0.113.10",
        dynamic({"city":"London"}), dynamic(null), "corr-006", "risk-006"
];
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let LookbackWindow = 30d;
// Part 1: Get the leaked credential risk event
let LeakEvent = TestRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
    | where UserPrincipalName == TargetUser
    | where RiskEventType == "leakedCredentials"
    | project
        RiskTimeGenerated = TimeGenerated, UserPrincipalName, RiskEventType,
        RiskLevel, RiskState, DetectionTimingType, RiskIpAddress = IpAddress,
        AdditionalInfo, Id
    | top 1 by RiskTimeGenerated desc;
// Part 2: Check for compound risk
let OtherRiskEvents = TestRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 7d))
    | where UserPrincipalName == TargetUser
    | where RiskEventType != "leakedCredentials"
    | summarize
        OtherRiskEventCount = count(),
        OtherRiskTypes = make_set(RiskEventType);
LeakEvent
| extend placeholder = 1
| join kind=leftouter (OtherRiskEvents | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    CompoundRiskAssessment = case(
        OtherRiskEventCount > 0 and OtherRiskTypes has "unfamiliarFeatures",
            "HIGH - Leaked credentials + unfamiliar sign-in",
        OtherRiskEventCount > 0,
            strcat("ELEVATED - ", tostring(OtherRiskEventCount), " other risk events"),
        "SINGLE RISK"
    )
// Expected: 1 row - risk-001 (most recent leakedCredentials for user@contoso.com)
//   RiskLevel=high, RiskState=atRisk, DetectionTimingType=offline
//   RiskIpAddress="" (empty - no IP for leaked creds)
//   OtherRiskEventCount=1 (unfamiliarFeatures from risk-002)
//   CompoundRiskAssessment="HIGH - Leaked credentials + unfamiliar sign-in"
//   Filtered out: risk-003 (different user), risk-005 (older event, superseded by top 1)
```

### Test 2: Query 2 - Password Timeline

```kql
// ============================================================
// TEST: Query 2 - Password Timeline
// Synthetic data: 8 audit log rows for password operations
// ============================================================
let TestRiskyUsers = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    UserDisplayName: string,
    RiskLevel: string,
    RiskState: string,
    RiskDetail: string,
    RiskLastUpdatedDateTime: datetime,
    IsProcessing: bool
) [
    datetime(2026-02-22T10:05:00Z), "user@contoso.com", "Test User", "high",
        "atRisk", "", datetime(2026-02-22T10:05:00Z), false,
    datetime(2026-02-22T11:00:00Z), "other@contoso.com", "Other User", "low",
        "remediated", "adminDismissedAllRiskForUser", datetime(2026-02-22T11:00:00Z), false
];
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    Category: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    CorrelationId: string
) [
    // Target user changed password 60 days ago (BEFORE leak detection)
    datetime(2025-12-24T09:00:00Z), "Change user password", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com"}]), "pwd-001",
    // Different user password reset (should be filtered)
    datetime(2026-02-22T15:00:00Z), "Reset user password", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"other@contoso.com"}]), "pwd-002",
    // Target user password NOT reset after leak (no newer entry)
    // Admin reset for different user
    datetime(2026-02-20T10:00:00Z), "Reset password (by admin)", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"colleague@contoso.com"}]), "pwd-003",
    // Non-password operation for target user
    datetime(2026-02-22T11:00:00Z), "Update user", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User"}]), "pwd-004"
];
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
// Get risk state
let RiskState = TestRiskyUsers
    | where UserPrincipalName == TargetUser
    | top 1 by TimeGenerated desc
    | project UserPrincipalName, CurrentRiskLevel = RiskLevel, CurrentRiskState = RiskState;
// Get password changes
let PasswordChanges = TestAuditLogs
    | where OperationName in ("Change user password", "Reset user password", "Reset password (by admin)", "Change password (self-service)")
    | mv-expand TargetResource = TargetResources
    | where tostring(TargetResource.userPrincipalName) == TargetUser
        or tostring(InitiatedBy.user.userPrincipalName) == TargetUser
    | project PasswordChangeTime = TimeGenerated, OperationName;
let LastPasswordChange = toscalar(PasswordChanges | top 1 by PasswordChangeTime desc | project PasswordChangeTime);
RiskState
| extend
    LastPasswordChange = LastPasswordChange,
    PasswordChangedAfterLeak = iff(isnotempty(LastPasswordChange) and LastPasswordChange > AlertTime,
        "YES", "NO"),
    DaysSincePasswordChange = iff(isnotempty(LastPasswordChange),
        datetime_diff("day", AlertTime, LastPasswordChange), -1),
    PasswordUrgency = case(
        isnotempty(LastPasswordChange) and LastPasswordChange > AlertTime, "LOW",
        isnotempty(LastPasswordChange) and datetime_diff("day", AlertTime, LastPasswordChange) >= 30, "HIGH",
        "CRITICAL"
    )
// Expected: CurrentRiskLevel=high, CurrentRiskState=atRisk
//   LastPasswordChange=2025-12-24 (60 days before alert)
//   PasswordChangedAfterLeak=NO
//   DaysSincePasswordChange=60
//   PasswordUrgency=HIGH (>30 days since last change, before leak)
```

### Test 3: Query 3 - Sign-In Baseline

```kql
// ============================================================
// TEST: Query 3 - Sign-In Baseline (30-day)
// Synthetic data: 10 baseline sign-ins from known locations
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    LocationDetails: dynamic,
    DeviceDetail: dynamic,
    AppDisplayName: string,
    AuthenticationRequirement: string,
    MfaDetail: dynamic,
    ClientAppUsed: string,
    ConditionalAccessStatus: string,
    ResultType: string
) [
    // Normal: Istanbul office (Mon-Fri)
    datetime(2026-01-23T09:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Browser", "success", "0",
    datetime(2026-01-24T09:30:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Teams", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Mobile Apps and Desktop clients", "success", "0",
    datetime(2026-01-27T08:45:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Browser", "success", "0",
    datetime(2026-01-28T09:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Browser", "success", "0",
    // Normal: Home IP (evenings)
    datetime(2026-01-25T19:00:00Z), "user@contoso.com", "85.100.50.30",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Outlook", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Mobile Apps and Desktop clients", "success", "0",
    // Normal: Mobile
    datetime(2026-02-10T12:00:00Z), "user@contoso.com", "100.64.0.5",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-mob","operatingSystem":"iOS 17","browser":"Safari"}),
        "Microsoft Outlook", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Mobile Apps and Desktop clients", "success", "0",
    // Normal: Ankara trip
    datetime(2026-02-03T10:00:00Z), "user@contoso.com", "10.1.1.50",
        dynamic({"city":"Ankara","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Browser", "success", "0",
    // Different user (should be filtered)
    datetime(2026-01-28T09:00:00Z), "other@contoso.com", "10.1.1.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-002","operatingSystem":"Windows 11","browser":"Edge 120.0"}),
        "Microsoft Office 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppOTP"}), "Browser", "success", "0",
    // Failed sign-in (should be excluded from success baseline)
    datetime(2026-02-01T03:00:00Z), "user@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"deviceId":"","operatingSystem":"Linux","browser":"Python/3.9"}),
        "Microsoft Office 365", "singleFactorAuthentication",
        dynamic(null), "Browser", "notApplied", "50126",
    // Legacy auth sign-in from known IP
    datetime(2026-02-15T08:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"","operatingSystem":"","browser":""}),
        "Microsoft Exchange Online", "singleFactorAuthentication",
        dynamic(null), "Exchange ActiveSync", "notApplied", "0"
];
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let BaselineStart = AlertTime - 30d;
let BaselineEnd = AlertTime - 1d;
let BaselineSignins = TestSigninLogs
    | where TimeGenerated between (BaselineStart .. BaselineEnd)
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | extend
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        DeviceId = tostring(DeviceDetail.deviceId);
BaselineSignins
| summarize
    TotalSignins = count(),
    DistinctIPs = dcount(IPAddress),
    DistinctCities = dcount(City),
    DistinctCountries = dcount(Country),
    KnownIPs = make_set(IPAddress),
    KnownCities = make_set(City),
    KnownCountries = make_set(Country),
    ActiveDays = dcount(bin(TimeGenerated, 1d))
| extend
    AvgSigninsPerDay = round(toreal(TotalSignins) / toreal(ActiveDays), 1),
    BaselineRichness = case(
        ActiveDays >= 20, "STRONG",
        ActiveDays >= 10, "MODERATE",
        ActiveDays >= 3, "WEAK",
        "INSUFFICIENT"
    )
// Expected: TotalSignins=8 (7 normal + 1 legacy auth, all successful)
//   DistinctIPs=4 (85.100.50.25, 85.100.50.30, 100.64.0.5, 10.1.1.50)
//   DistinctCities=2 (Istanbul, Ankara), DistinctCountries=1 (TR)
//   KnownIPs includes all 4 IPs above
//   ActiveDays=7 (7 distinct days with sign-ins)
//   BaselineRichness="WEAK" (only 7 active days)
//   Filtered out: other@contoso.com (different user), 50126 (failed sign-in)
```

### Test 4: Query 4A - Anomalous Sign-In Detection

```kql
// ============================================================
// TEST: Query 4A - Anomalous Sign-In Detection
// Synthetic data: 12 rows (6 anomalous + 6 normal/filtered)
// ============================================================
let BaselineIPs = dynamic(["85.100.50.25", "85.100.50.30", "100.64.0.5", "10.1.1.50"]);
let BaselineCountries = dynamic(["TR"]);
let TestSignins = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    LocationDetails: dynamic,
    DeviceDetail: dynamic,
    UserAgent: string,
    AppDisplayName: string,
    ResourceDisplayName: string,
    ClientAppUsed: string,
    AuthenticationRequirement: string,
    MfaDetail: dynamic,
    ConditionalAccessStatus: string,
    ResultType: string
) [
    // MALICIOUS 1: Successful sign-in from Russia WITHOUT MFA
    datetime(2026-02-23T02:00:00Z), "user@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"deviceId":"","operatingSystem":"Linux","browser":"Python/3.9"}),
        "python-requests/2.28.1", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null), "notApplied", "0",
    // MALICIOUS 2: Failed sign-in (credential testing) from Germany
    datetime(2026-02-22T15:00:00Z), "user@contoso.com", "203.0.113.99",
        dynamic({"city":"Berlin","countryOrRegion":"DE"}),
        dynamic({"deviceId":"","operatingSystem":"Windows","browser":"Chrome"}),
        "Mozilla/5.0 Chrome/120", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null), "notApplied", "50126",
    // MALICIOUS 3: Another failed attempt from same IP
    datetime(2026-02-22T15:05:00Z), "user@contoso.com", "203.0.113.99",
        dynamic({"city":"Berlin","countryOrRegion":"DE"}),
        dynamic({"deviceId":"","operatingSystem":"Windows","browser":"Chrome"}),
        "Mozilla/5.0 Chrome/120", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null), "notApplied", "50126",
    // MALICIOUS 4: MFA blocked (credential valid but MFA stopped it)
    datetime(2026-02-22T16:00:00Z), "user@contoso.com", "198.51.100.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"deviceId":"","operatingSystem":"Windows","browser":"Chrome"}),
        "Mozilla/5.0 Chrome/120", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic(null), "success", "50074",
    // MALICIOUS 5: Legacy auth attempt (IMAP) from China
    datetime(2026-02-24T04:00:00Z), "user@contoso.com", "101.200.0.1",
        dynamic({"city":"Beijing","countryOrRegion":"CN"}),
        dynamic({"deviceId":"","operatingSystem":"","browser":""}),
        "", "Microsoft Exchange Online", "Microsoft Exchange Online", "IMAP4",
        "singleFactorAuthentication", dynamic(null), "notApplied", "50126",
    // MALICIOUS 6: Successful legacy auth from unknown IP
    datetime(2026-02-24T05:00:00Z), "user@contoso.com", "101.200.0.1",
        dynamic({"city":"Beijing","countryOrRegion":"CN"}),
        dynamic({"deviceId":"","operatingSystem":"","browser":""}),
        "", "Microsoft Exchange Online", "Microsoft Exchange Online", "IMAP4",
        "singleFactorAuthentication", dynamic(null), "notApplied", "0",
    // BENIGN 1: Normal sign-in from known IP (in baseline)
    datetime(2026-02-22T09:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Mozilla/5.0 Chrome/120", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}), "success", "0",
    // BENIGN 2: Normal sign-in from known home IP
    datetime(2026-02-22T19:00:00Z), "user@contoso.com", "85.100.50.30",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Mozilla/5.0 Chrome/120", "Microsoft Outlook", "Microsoft Office 365", "Mobile Apps and Desktop clients",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}), "success", "0",
    // BENIGN 3: Different user (should be filtered)
    datetime(2026-02-23T10:00:00Z), "other@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"deviceId":"dev-other","operatingSystem":"Linux","browser":"Python"}),
        "python-requests", "Microsoft Graph", "Microsoft Graph", "Browser",
        "singleFactorAuthentication", dynamic(null), "notApplied", "0",
    // BENIGN 4: Normal from known mobile IP
    datetime(2026-02-23T12:00:00Z), "user@contoso.com", "100.64.0.5",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-mob","operatingSystem":"iOS 17","browser":"Safari"}),
        "Safari/17.0", "Microsoft Outlook", "Microsoft Office 365", "Mobile Apps and Desktop clients",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}), "success", "0",
    // BENIGN 5: Normal from known Ankara IP
    datetime(2026-02-25T10:00:00Z), "user@contoso.com", "10.1.1.50",
        dynamic({"city":"Ankara","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Mozilla/5.0 Chrome/120", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}), "success", "0",
    // BENIGN 6: Normal from known office IP
    datetime(2026-02-26T09:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Mozilla/5.0 Chrome/120", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}), "success", "0"
];
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
TestSignins
| where TimeGenerated between ((AlertTime - 7d) .. (AlertTime + 7d))
| where UserPrincipalName == TargetUser
| where IPAddress !in (BaselineIPs)
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    IsNewCountry = tostring(LocationDetails.countryOrRegion) !in (BaselineCountries)
| summarize
    TotalAnomalousSignins = count(),
    SuccessfulFromNewIP = countif(ResultType == "0"),
    FailedFromNewIP = countif(ResultType != "0"),
    DistinctAnomalousIPs = dcount(IPAddress),
    AnomalousCountries = make_set(Country),
    CriticalEvents = countif(ResultType == "0" and tostring(LocationDetails.countryOrRegion) !in (BaselineCountries)),
    CredentialTestingEvents = countif(ResultType == "50126"),
    MFABlockedEvents = countif(ResultType == "50074")
| extend
    OverallAssessment = case(
        CriticalEvents > 0, "CRITICAL - Successful unauthorized access from new country",
        CredentialTestingEvents > 5, "HIGH - Active credential testing",
        MFABlockedEvents > 0, "MEDIUM - MFA blocking valid credential",
        "LOW"
    )
// Expected: TotalAnomalousSignins=6, SuccessfulFromNewIP=2 (Moscow + Beijing IMAP),
//   FailedFromNewIP=4 (2x Berlin 50126 + 1x Moscow 50074 + 1x Beijing 50126)
//   DistinctAnomalousIPs=4, AnomalousCountries=[RU, DE, CN]
//   CriticalEvents=2 (successful from RU and CN - both new countries)
//   CredentialTestingEvents=3 (2x Berlin + 1x Beijing)
//   MFABlockedEvents=1
//   OverallAssessment="CRITICAL"
//   Filtered: B1,B2,B4,B5,B6 (baseline IPs), B3 (different user)
```

### Test 5: Query 5A/5B - Post-Sign-In Activity

```kql
// ============================================================
// TEST: Query 5A/5B - Post-Sign-In Persistence and BEC
// Synthetic data: 6 malicious + 8 benign = 14 rows
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    Category: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    CorrelationId: string
) [
    // MALICIOUS 1: MFA method registered AFTER leak (attacker adding their phone)
    datetime(2026-02-23T02:15:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User",
            "modifiedProperties":[{"displayName":"StrongAuthenticationMethod","oldValue":"[]","newValue":"[{\"MethodType\":6}]"}]}]),
        "audit-m01",
    // MALICIOUS 2: OAuth app consent with broad permissions
    datetime(2026-02-23T02:30:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"Malicious App","modifiedProperties":[
            {"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"Mail.ReadWrite Files.ReadWrite.All"}]}]),
        "audit-m02",
    // MALICIOUS 3: Device registration (rogue device)
    datetime(2026-02-23T03:00:00Z), "Register device", "DeviceManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"DESKTOP-ATKR01","modifiedProperties":[]}]),
        "audit-m03",
    // BENIGN 1: Different user activity
    datetime(2026-02-23T10:00:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"colleague@contoso.com"}}),
        dynamic([{"userPrincipalName":"colleague@contoso.com"}]),
        "audit-b01",
    // BENIGN 2: Target user activity well BEFORE alert
    datetime(2026-02-10T09:00:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"Slack"}]),
        "audit-b02",
    // BENIGN 3: Admin action on different user
    datetime(2026-02-23T15:00:00Z), "Reset password (by admin)", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"other@contoso.com"}]),
        "audit-b03"
];
let TestOfficeActivity = datatable(
    TimeGenerated: datetime,
    Operation: string,
    OfficeWorkload: string,
    UserId: string,
    ClientIP: string,
    Parameters: dynamic
) [
    // MALICIOUS 4: Inbox rule forwarding to external
    datetime(2026-02-23T02:45:00Z), "New-InboxRule", "Exchange", "user@contoso.com",
        "198.51.100.42:54321",
        dynamic([{"Name":"Name","Value":".."},{"Name":"ForwardTo","Value":"attacker@evil.com"},{"Name":"DeleteMessage","Value":"True"}]),
    // MALICIOUS 5: Bulk email access
    datetime(2026-02-23T03:15:00Z), "MailItemsAccessed", "Exchange", "user@contoso.com",
        "198.51.100.42:54321", dynamic([]),
    // MALICIOUS 6: File download
    datetime(2026-02-23T03:30:00Z), "FileDownloaded", "SharePoint", "user@contoso.com",
        "[::ffff:198.51.100.42]:12345", dynamic([]),
    // BENIGN 4: Normal email from known IP
    datetime(2026-02-22T10:00:00Z), "MailItemsAccessed", "Exchange", "user@contoso.com",
        "85.100.50.25:50000", dynamic([]),
    // BENIGN 5: Different user
    datetime(2026-02-23T15:00:00Z), "FileDownloaded", "SharePoint", "colleague@contoso.com",
        "10.1.1.2", dynamic([]),
    // BENIGN 6: Target user before alert window
    datetime(2026-02-10T11:00:00Z), "Send", "Exchange", "user@contoso.com",
        "85.100.50.25:50000", dynamic([]),
    // BENIGN 7: Other user inbox rule
    datetime(2026-02-23T14:50:00Z), "New-InboxRule", "Exchange", "colleague@contoso.com",
        "10.1.1.2:44000",
        dynamic([{"Name":"Name","Value":"Move JIRA"},{"Name":"MoveToFolder","Value":"JIRA"}]),
    // BENIGN 8: Outside window
    datetime(2026-02-08T08:00:00Z), "FileAccessed", "SharePoint", "user@contoso.com",
        "85.100.50.25:50000", dynamic([])
];
// Test 5A: Directory changes
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
let PostLeakWindow = 7d;
TestAuditLogs
| where TimeGenerated between ((AlertTime - 7d) .. (AlertTime + PostLeakWindow))
| where OperationName in (
    "User registered security info", "Consent to application", "Register device",
    "Reset password (by admin)"
)
| mv-expand TargetResource = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) == TargetUser
    or tostring(TargetResource.userPrincipalName) == TargetUser
| project
    TimeGenerated, OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    TargetDisplayName = tostring(TargetResource.displayName),
    DaysFromAlert = datetime_diff("day", TimeGenerated, AlertTime),
    Severity = case(
        OperationName has "security info", "CRITICAL - MFA MANIPULATION",
        OperationName has "Consent to application", "CRITICAL - OAUTH APP CONSENT",
        OperationName has "Register device", "HIGH - DEVICE REGISTRATION",
        "INFO"
    )
| order by TimeGenerated asc
// Expected: 3 rows (M1: MFA +1 day, M2: OAuth +1 day, M3: device +1 day)
// Filtered: B01 (different user), B02 (before 7d window), B03 (different target)
```

### Test 6: Query 6 - MFA and Legacy Auth Assessment

```kql
// ============================================================
// TEST: Query 6 - MFA and Legacy Auth Assessment
// Synthetic data: 8 sign-in rows testing MFA and legacy auth
// ============================================================
let TestSignins = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    AppDisplayName: string,
    ClientAppUsed: string,
    AuthenticationRequirement: string,
    MfaDetail: dynamic,
    ConditionalAccessStatus: string,
    ResultType: string
) [
    // MFA enforced sign-ins (4 rows)
    datetime(2026-02-15T09:00:00Z), "user@contoso.com", "85.100.50.25",
        "Microsoft Office 365", "Browser", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "success", "0",
    datetime(2026-02-16T09:00:00Z), "user@contoso.com", "85.100.50.25",
        "Microsoft Teams", "Mobile Apps and Desktop clients", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "success", "0",
    datetime(2026-02-17T10:00:00Z), "user@contoso.com", "85.100.50.30",
        "Microsoft Outlook", "Mobile Apps and Desktop clients", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "success", "0",
    datetime(2026-02-18T09:00:00Z), "user@contoso.com", "85.100.50.25",
        "Microsoft Office 365", "Browser", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "success", "0",
    // Legacy auth sign-in - IMAP (bypasses MFA!)
    datetime(2026-02-15T08:00:00Z), "user@contoso.com", "85.100.50.25",
        "Microsoft Exchange Online", "IMAP4", "singleFactorAuthentication",
        dynamic(null), "notApplied", "0",
    // Legacy auth sign-in - Exchange ActiveSync
    datetime(2026-02-16T08:00:00Z), "user@contoso.com", "85.100.50.25",
        "Microsoft Exchange Online", "Exchange ActiveSync", "singleFactorAuthentication",
        dynamic(null), "notApplied", "0",
    // Different user (should be filtered)
    datetime(2026-02-15T09:00:00Z), "other@contoso.com", "10.1.1.1",
        "Microsoft Office 365", "Browser", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppOTP"}), "success", "0",
    // Failed sign-in (should be excluded from success analysis)
    datetime(2026-02-19T03:00:00Z), "user@contoso.com", "198.51.100.42",
        "Microsoft Office 365", "Browser", "singleFactorAuthentication",
        dynamic(null), "notApplied", "50126"
];
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:00:00Z);
// MFA analysis
let MfaAnalysis = TestSignins
    | where TimeGenerated > (AlertTime - 30d)
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | summarize
        TotalSuccessfulSignins = count(),
        MFAEnforced = countif(AuthenticationRequirement == "multiFactorAuthentication"),
        SFAOnly = countif(AuthenticationRequirement == "singleFactorAuthentication");
// Legacy auth
let LegacyAuth = TestSignins
    | where TimeGenerated > (AlertTime - 30d)
    | where UserPrincipalName == TargetUser
    | where ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Other clients", "Authenticated SMTP")
    | summarize
        LegacyAuthEvents = count(),
        LegacySuccessful = countif(ResultType == "0"),
        LegacyProtocols = make_set(ClientAppUsed);
MfaAnalysis
| extend placeholder = 1
| join kind=leftouter (LegacyAuth | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    LegacyAuthEvents = coalesce(LegacyAuthEvents, 0),
    LegacySuccessful = coalesce(LegacySuccessful, 0),
    MFACoverage = round(100.0 * MFAEnforced / TotalSuccessfulSignins, 1),
    MFAStatus = case(
        SFAOnly == 0, "FULLY ENFORCED",
        toreal(MFAEnforced) / TotalSuccessfulSignins > 0.9, "MOSTLY ENFORCED",
        MFAEnforced > 0, "PARTIALLY ENFORCED",
        "NOT ENFORCED"
    ),
    LegacyAuthRisk = case(
        LegacySuccessful > 0, "CRITICAL - Legacy auth ACTIVE",
        "LOW"
    ),
    OverallExposure = case(
        SFAOnly > 0 and LegacySuccessful > 0, "HIGH - MFA enforced but legacy auth bypasses it",
        SFAOnly == 0 and LegacySuccessful == 0, "LOW - MFA enforced, no legacy auth",
        "REVIEW"
    )
// Expected: TotalSuccessfulSignins=6 (4 MFA + 2 legacy), MFAEnforced=4, SFAOnly=2
//   MFACoverage=66.7%, MFAStatus="PARTIALLY ENFORCED"
//   LegacyAuthEvents=2, LegacySuccessful=2, LegacyProtocols=[IMAP4, Exchange ActiveSync]
//   LegacyAuthRisk="CRITICAL - Legacy auth ACTIVE"
//   OverallExposure="HIGH - MFA enforced but legacy auth bypasses it"
```

---

## References

- [Microsoft Entra ID Identity Protection risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [Leaked credentials risk detection](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#leaked-credentials)
- [Investigate risk detections](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk)
- [Block legacy authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication)
- [MITRE ATT&CK T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK T1589.001 - Gather Victim Identity Information: Credentials](https://attack.mitre.org/techniques/T1589/001/)
- [MITRE ATT&CK T1110.004 - Brute Force: Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)
- [Azure AD Password Protection](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad)
