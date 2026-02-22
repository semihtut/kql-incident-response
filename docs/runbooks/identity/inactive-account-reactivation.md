---
title: "Inactive Account Reactivation"
id: RB-0019
severity: medium
status: reviewed
description: >
  Investigation runbook for detecting dormant or inactive accounts that
  suddenly become active after extended periods of inactivity. Covers
  dormancy period analysis, reactivation sign-in context, comparison
  against HR offboarding records, post-reactivation activity audit, and
  organization-wide stale account abuse sweep. Dormant accounts are
  prime targets for attackers because they often have weak or unchanged
  passwords, no MFA enforcement, and their activity is less likely to be
  noticed by the legitimate account owner.
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
  techniques:
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1078
      technique_name: "Valid Accounts"
      confidence: confirmed
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: probable
    - technique_id: T1078.002
      technique_name: "Valid Accounts: Domain Accounts"
      confidence: probable
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Storm-0558"
  - "Volt Typhoon"
  - "Scattered Spider (Octo Tempest)"
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
  - table: "AuditLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "AADUserRiskEvents"
    product: "Entra ID Identity Protection"
    license: "Entra ID P2"
    required: false
    alternatives: []
  - table: "IdentityInfo"
    product: "Microsoft Sentinel UEBA"
    license: "Microsoft Sentinel"
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
data_checks:
  - query: "SigninLogs | take 1"
    label: primary
    description: "Sign-in events for dormancy detection"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "For background token activity on inactive accounts"
  - query: "AuditLogs | take 1"
    description: "For post-reactivation account changes"
  - query: "IdentityInfo | take 1"
    description: "For account metadata (department, manager, status)"
---

# Inactive Account Reactivation - Investigation Runbook

> **RB-0019** | Severity: Medium | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Custom Detection via SigninLogs Dormancy Analysis
>
> **Detection Logic:** Successful sign-in on accounts with no activity in 30-90+ days
>
> **Primary MITRE Technique:** T1078.004 - Valid Accounts: Cloud Accounts

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Reactivation Event Analysis](#step-1-reactivation-event-analysis)
   - [Step 2: Account Dormancy Period and Last Activity](#step-2-account-dormancy-period-and-last-activity)
   - [Step 3: Account Metadata and Status Validation](#step-3-account-metadata-and-status-validation)
   - [Step 4: Baseline Comparison - Establish Normal Activity Pattern](#step-4-baseline-comparison---establish-normal-activity-pattern)
   - [Step 5: Post-Reactivation Activity Audit](#step-5-post-reactivation-activity-audit)
   - [Step 6: Risk Event and Authentication Context](#step-6-risk-event-and-authentication-context)
   - [Step 7: Organization-Wide Dormant Account Activity Sweep](#step-7-organization-wide-dormant-account-activity-sweep)
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
This detection fires when a user account that has been inactive (no interactive or non-interactive sign-ins) for a configurable dormancy threshold (default: 60 days) suddenly produces a successful sign-in event. The dormancy period is calculated by comparing the current sign-in timestamp against the most recent previous sign-in in SigninLogs and AADNonInteractiveUserSignInLogs.

Categories of inactive accounts that may reactivate:
1. **Former employee accounts:** Accounts not properly deprovisioned after offboarding — the most dangerous category
2. **Seasonal/contract workers:** Accounts that legitimately go dormant between projects — verify with HR
3. **Shared/service accounts:** Generic accounts used intermittently — often have weak credentials
4. **Test/dev accounts:** Development accounts forgotten after project completion — often over-privileged
5. **Compromised and abandoned:** Accounts previously compromised, locked, then unlocked without proper remediation

**Why it matters:**
Dormant accounts are attractive targets for attackers because:

- **Weak credentials:** Passwords may not have been rotated; older accounts may predate MFA requirements
- **No one watching:** The legitimate owner isn't using the account, so malicious activity goes unnoticed
- **Retained permissions:** Accounts often retain group memberships, role assignments, and application access from their active period
- **Shadow IT:** Forgotten accounts don't appear in active directory reviews or access certifications
- **Credential databases:** Passwords from old breaches may still be valid for dormant accounts that never changed their password

Volt Typhoon specifically targets dormant and under-monitored accounts for long-term persistence in critical infrastructure. Storm-0558 exploited an inactive signing key (analogous to dormant identity) in the 2023 Microsoft email breach.

**Why this is MEDIUM severity:**
- Dormant account reactivation has a higher false positive rate (returning employees, seasonal workers)
- Requires HR/IT correlation to determine if reactivation is authorized
- Escalates to HIGH/CRITICAL if post-reactivation activity shows compromise indicators
- The account's permissions and the sensitivity of accessed resources determine actual impact

---

## 2. Prerequisites

{{ data_check_timeline(page.meta.data_checks) }}

---

## 3. Input Parameters

Set these values before running the investigation queries:

```kql
// === INVESTIGATION PARAMETERS ===
let InvestigationTarget = "user@company.com";   // UPN of reactivated account
let AlertTime = datetime(2026-02-22T14:30:00Z); // Time of reactivation sign-in
let DormancyThreshold = 60d;                     // Minimum inactive period to flag
let LookbackWindow = 180d;                       // Maximum lookback for last activity
```

---

## 4. Quick Triage Criteria

Use this decision matrix for initial severity assessment:

| Indicator | True Positive Signal | False Positive Signal |
|---|---|---|
| Dormancy period | 90+ days inactive | 30-60 days (vacation, leave) |
| Account status | Should be disabled per offboarding | Active employee returning from leave |
| Sign-in location | Foreign country, hosting IP | User's known home/office location |
| Post-reactivation | MFA registration, data access burst | Normal email/Teams access |
| Account type | Admin, service, shared account | Regular user account |
| HR records | Terminated employee, no rehire | Approved return, seasonal worker |

---

## 5. Investigation Steps

### Step 1: Reactivation Event Analysis

**Objective:** Analyze the sign-in that reactivated the dormant account — where it came from, what it accessed, and how it authenticated.

```kql
// Step 1: Reactivation Event Analysis
// Table: SigninLogs | Analyzes the sign-in that reactivated the dormant account
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where UserPrincipalName =~ InvestigationTarget
| extend ParsedLocation = parse_json(LocationDetails)
| extend
    City = tostring(ParsedLocation.city),
    State = tostring(ParsedLocation.state),
    Country = tostring(ParsedLocation.countryOrRegion),
    Latitude = toreal(ParsedLocation.geoCoordinates.latitude),
    Longitude = toreal(ParsedLocation.geoCoordinates.longitude)
| project
    TimeGenerated,
    IPAddress,
    AutonomousSystemNumber,
    Country, City, State,
    UserAgent,
    ClientAppUsed,
    AppDisplayName,
    ResourceDisplayName,
    ResultType,
    AuthResult = case(
        ResultType == "0", "Success",
        ResultType == "50126", "Wrong Password",
        ResultType == "50053", "Smart Lockout",
        ResultType == "50074", "MFA Required",
        ResultType == "53003", "Blocked by CA",
        strcat("Error: ", ResultType)
    ),
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    AuthenticationRequirement,
    MfaDetail = tostring(MfaDetail),
    DeviceDetail = tostring(DeviceDetail)
| sort by TimeGenerated asc
```

**What to look for:**

- **AuthResult = "Success"** from unexpected location = account compromise
- **AuthenticationRequirement = "singleFactorAuthentication"** = account has NO MFA — high risk for dormant accounts
- **ClientAppUsed = "Other clients"** or legacy auth = may bypass MFA
- **RiskLevelDuringSignIn** = did Identity Protection flag this sign-in?
- **Failed attempts before success** = possible brute force or credential stuffing against the dormant account
- **AppDisplayName** = what was the first resource accessed? (Azure Portal = reconnaissance, Exchange = BEC, Microsoft Graph = data access)

---

### Step 2: Account Dormancy Period and Last Activity

**Objective:** Calculate the exact dormancy period and identify the last activity before the reactivation to understand the timeline.

```kql
// Step 2: Account Dormancy Period and Last Activity
// Table: SigninLogs + AADNonInteractiveUserSignInLogs | Calculates dormancy period
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 180d;
// Interactive sign-in history
let InteractiveHistory = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. AlertTime)
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | summarize
        LastInteractiveSignIn = max(TimeGenerated),
        InteractiveSignInCount = count(),
        InteractiveApps = make_set(AppDisplayName, 20),
        InteractiveIPs = make_set(IPAddress, 20),
        InteractiveCountries = make_set(
            tostring(parse_json(LocationDetails).countryOrRegion), 10
        );
// Non-interactive sign-in history (token refreshes, background apps)
let NonInteractiveHistory = AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. AlertTime)
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | summarize
        LastNonInteractiveSignIn = max(TimeGenerated),
        NonInteractiveSignInCount = count(),
        NonInteractiveApps = make_set(AppDisplayName, 20);
InteractiveHistory
| extend placeholder = 1
| join kind=fullouter (NonInteractiveHistory | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    LastAnyActivity = max_of(
        coalesce(LastInteractiveSignIn, datetime(1970-01-01)),
        coalesce(LastNonInteractiveSignIn, datetime(1970-01-01))
    ),
    DormancyDays_Interactive = datetime_diff('day', AlertTime, coalesce(LastInteractiveSignIn, AlertTime - 365d)),
    DormancyDays_AnyActivity = datetime_diff('day', AlertTime,
        max_of(
            coalesce(LastInteractiveSignIn, datetime(1970-01-01)),
            coalesce(LastNonInteractiveSignIn, datetime(1970-01-01))
        ))
| extend
    DormancyClassification = case(
        DormancyDays_Interactive > 180, "CRITICAL - Inactive 6+ months",
        DormancyDays_Interactive > 90, "HIGH - Inactive 3-6 months",
        DormancyDays_Interactive > 60, "MEDIUM - Inactive 2-3 months",
        DormancyDays_Interactive > 30, "LOW - Inactive 1-2 months",
        "MINIMAL - Active within 30 days"
    )
```

**What to look for:**

- **DormancyDays_Interactive > 90** = Account hasn't been used interactively in 3+ months — high risk
- **DormancyDays_Interactive > 180** = Half a year inactive — should probably be disabled
- **NonInteractiveSignInCount > 0 but InteractiveSignInCount == 0** = Background token refreshes but no human usage — may indicate leftover app tokens
- **InteractiveApps and InteractiveIPs** = What the account was used for before going dormant — context for expected vs unexpected access
- **No data at all in 180d** = Account may never have been used or data has aged out — verify in Entra Portal

---

### Step 3: Account Metadata and Status Validation

**Objective:** Check the account's current state in Entra ID — is it supposed to be active? What permissions does it hold? Is there an HR offboarding record?

```kql
// Step 3: Account Metadata and Status Validation
// Table: IdentityInfo + AuditLogs | Checks account status and recent administrative changes
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
// Check IdentityInfo for account metadata (if UEBA is enabled)
let AccountMetadata = IdentityInfo
    | where TimeGenerated > ago(30d)
    | where AccountUPN =~ InvestigationTarget
    | summarize arg_max(TimeGenerated, *) by AccountUPN
    | project
        AccountUPN,
        AccountDisplayName,
        Department,
        JobTitle,
        Manager,
        City,
        Country,
        AccountEnabled = IsAccountEnabled,
        AssignedRoles,
        GroupMembership,
        LastMetadataUpdate = TimeGenerated;
// Check for recent admin actions on this account (enable, password reset, etc.)
let AdminActions = AuditLogs
    | where TimeGenerated between ((AlertTime - 30d) .. (AlertTime + 4h))
    | where TargetResources[0].userPrincipalName =~ InvestigationTarget
    | where OperationName in (
        "Enable account", "Disable account", "Update user",
        "Reset password", "Restore user", "Add member to role",
        "Add member to group", "Remove member from role",
        "Remove member from group"
    )
    | project
        TimeGenerated,
        OperationName,
        InitiatedBy = coalesce(
            tostring(InitiatedBy.user.userPrincipalName),
            tostring(InitiatedBy.app.displayName)
        ),
        InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
        Result,
        ModifiedProperties = tostring(TargetResources[0].modifiedProperties);
AccountMetadata
| extend placeholder = 1
| join kind=fullouter (AdminActions | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
```

**What to look for:**

- **AccountEnabled = true for a terminated employee** = Account should have been disabled during offboarding — process failure
- **"Enable account" operation before the reactivation sign-in** = Someone re-enabled a disabled account — who and why?
- **"Reset password" by admin before reactivation** = Could be legitimate rehire or attacker with admin access
- **"Restore user" operation** = Account was deleted and restored from recycle bin — very suspicious if not authorized
- **AssignedRoles containing "Global Administrator" or privileged roles** = Dormant account with active admin privileges — critical finding
- **GroupMembership** = What groups does this account still belong to? (VPN access, sensitive data groups, etc.)

---

### Step 4: Baseline Comparison - Establish Normal Activity Pattern

**Objective:** Compare the reactivation sign-in characteristics against the account's historical behavior to determine if the new activity matches the original user's pattern.

```kql
// Step 4: Baseline Comparison - Establish Normal Activity Pattern
// Table: SigninLogs | Compares reactivation against pre-dormancy behavior
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 365d;
let DormancyThreshold = 60d;
// Get the pre-dormancy activity pattern (before the gap)
let PreDormancyPattern = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime - DormancyThreshold))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | extend ParsedLocation = parse_json(LocationDetails)
    | summarize
        PreDormancySignIns = count(),
        PreDormancyLastDate = max(TimeGenerated),
        PreDormancyIPs = make_set(IPAddress, 50),
        PreDormancyASNs = make_set(AutonomousSystemNumber, 20),
        PreDormancyCountries = make_set(tostring(ParsedLocation.countryOrRegion), 10),
        PreDormancyCities = make_set(tostring(ParsedLocation.city), 30),
        PreDormancyApps = make_set(AppDisplayName, 20),
        PreDormancyUserAgents = make_set(UserAgent, 30);
// Get the reactivation sign-in details
let ReactivationPattern = SigninLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | extend ParsedLocation = parse_json(LocationDetails)
    | summarize
        ReactivationSignIns = count(),
        ReactivationIPs = make_set(IPAddress, 20),
        ReactivationASNs = make_set(AutonomousSystemNumber, 10),
        ReactivationCountries = make_set(tostring(ParsedLocation.countryOrRegion), 5),
        ReactivationCities = make_set(tostring(ParsedLocation.city), 10),
        ReactivationApps = make_set(AppDisplayName, 10),
        ReactivationUserAgents = make_set(UserAgent, 10);
PreDormancyPattern
| extend placeholder = 1
| join kind=inner (ReactivationPattern | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    NewIPs = set_difference(ReactivationIPs, PreDormancyIPs),
    NewCountries = set_difference(ReactivationCountries, PreDormancyCountries),
    NewApps = set_difference(ReactivationApps, PreDormancyApps),
    NewUserAgents = set_difference(ReactivationUserAgents, PreDormancyUserAgents)
| extend
    AnomalyScore = 0
        + iff(array_length(NewCountries) > 0, 30, 0)
        + iff(array_length(NewIPs) > 0, 15, 0)
        + iff(array_length(NewApps) > 0, 10, 0)
        + iff(array_length(NewUserAgents) > 0, 10, 0)
        + iff(PreDormancySignIns == 0, 35, 0),
    AnomalyVerdict = case(
        array_length(set_difference(ReactivationCountries, PreDormancyCountries)) > 0,
            "HIGH ANOMALY - Reactivation from country not in pre-dormancy pattern",
        PreDormancySignIns == 0,
            "HIGH ANOMALY - No pre-dormancy activity found (account may never have been used)",
        array_length(set_difference(ReactivationIPs, PreDormancyIPs)) > 0
            and array_length(set_difference(ReactivationUserAgents, PreDormancyUserAgents)) > 0,
            "MODERATE ANOMALY - New IP and new UserAgent",
        array_length(set_difference(ReactivationApps, PreDormancyApps)) > 0,
            "LOW ANOMALY - Accessing new applications not used before dormancy",
        "MINIMAL ANOMALY - Reactivation matches pre-dormancy pattern"
    )
```

**What to look for:**

- **"Reactivation from country not in pre-dormancy pattern"** = User was always in US, now signing in from NL — strong compromise indicator
- **"No pre-dormancy activity found"** = This account was never actively used — it was created and abandoned, or data aged out
- **"New IP and new UserAgent"** = Different device and network — either new environment or different person
- **AnomalyScore > 50** = Multiple anomaly indicators combined — high confidence of compromise
- **"MINIMAL ANOMALY"** = Same IP, same country, same apps as before dormancy — likely legitimate return

---

### Step 5: Post-Reactivation Activity Audit

**Objective:** Examine all activity in the first 24-72 hours after reactivation to detect account takeover indicators.

```kql
// Step 5: Post-Reactivation Activity Audit
// Table: AuditLogs + SigninLogs | Detects takeover actions after dormant account reactivation
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
// Reactivation timestamp
let ReactivationTime = toscalar(
    SigninLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | summarize min(TimeGenerated)
);
// Post-reactivation audit events
AuditLogs
| where TimeGenerated between (ReactivationTime .. (ReactivationTime + 72h))
| where InitiatedBy has InvestigationTarget
| extend
    ActionCategory = case(
        OperationName has_any ("security info", "Register", "MFA"), "MFA_REGISTRATION",
        OperationName has_any ("password", "Password"), "PASSWORD_CHANGE",
        OperationName has_any ("Consent", "OAuth", "permission"), "APP_CONSENT",
        OperationName has_any ("inbox", "forwarding", "redirect", "rule"), "EMAIL_MANIPULATION",
        OperationName has_any ("role", "Role"), "ROLE_CHANGE",
        OperationName has_any ("group", "Group"), "GROUP_CHANGE",
        OperationName has_any ("application", "credential", "service principal"), "APP_MODIFICATION",
        OperationName has_any ("conditional access", "policy"), "POLICY_CHANGE",
        "OTHER"
    ),
    HoursSinceReactivation = round(datetime_diff('minute', TimeGenerated, ReactivationTime) / 60.0, 1)
| where ActionCategory != "OTHER"
| project
    TimeGenerated,
    HoursSinceReactivation,
    ActionCategory,
    OperationName,
    TargetResource = tostring(TargetResources[0].displayName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    Result
| extend
    SuspicionLevel = case(
        ActionCategory == "MFA_REGISTRATION" and HoursSinceReactivation < 1,
            "CRITICAL - MFA registration within 1h of reactivation",
        ActionCategory == "PASSWORD_CHANGE" and HoursSinceReactivation < 4,
            "HIGH - Password change shortly after reactivation",
        ActionCategory == "EMAIL_MANIPULATION",
            "HIGH - Email rule modification",
        ActionCategory == "APP_CONSENT",
            "HIGH - OAuth app consent",
        ActionCategory == "ROLE_CHANGE",
            "CRITICAL - Role assignment change",
        ActionCategory == "POLICY_CHANGE",
            "CRITICAL - Security policy change",
        "MEDIUM"
    )
| sort by TimeGenerated asc
```

**What to look for:**

- **"MFA registration within 1h of reactivation"** = Attacker securing persistent access on a dormant account (see [RB-0012](suspicious-mfa-registration.md))
- **"Password change shortly after reactivation"** = Attacker resetting password to one they control (see [RB-0018](sspr-abuse.md))
- **"Email rule modification"** = BEC operation using the reactivated account (see [RB-0008](../email/suspicious-inbox-forwarding-rule.md))
- **ROLE_CHANGE on a dormant account** = Attacker escalating privileges on an account that shouldn't have any (see [RB-0013](privileged-role-assignment.md))
- **Multiple high-severity actions in rapid succession** = Full account takeover chain

---

### Step 6: Risk Event and Authentication Context

**Objective:** Check if Identity Protection generated risk events for the dormant account and analyze the authentication strength.

```kql
// Step 6: Risk Event and Authentication Context
// Table: AADUserRiskEvents + SigninLogs | Correlates risk events with reactivation
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 7d;
// Identity Protection risk events
let RiskEvents = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | project
        TimeGenerated,
        EventType = "RiskEvent",
        Detail = strcat(RiskEventType, " | Level: ", RiskLevel, " | Detail: ", RiskDetail),
        RiskLevel,
        IPAddress = IpAddress,
        RiskEventType;
// Authentication details for reactivation sign-ins
let AuthDetails = SigninLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | extend
        MFAMethod = tostring(parse_json(MfaDetail).authMethod),
        MFAResult = tostring(parse_json(MfaDetail).authDetail),
        DeviceOS = tostring(parse_json(DeviceDetail).operatingSystem),
        DeviceBrowser = tostring(parse_json(DeviceDetail).browser),
        DeviceCompliant = tostring(parse_json(DeviceDetail).isCompliant),
        DeviceManaged = tostring(parse_json(DeviceDetail).isManaged)
    | project
        TimeGenerated,
        EventType = "ReactivationAuth",
        Detail = strcat(
            "MFA: ", coalesce(MFAMethod, "None"),
            " | Device: ", coalesce(DeviceOS, "Unknown"),
            "/", coalesce(DeviceBrowser, "Unknown"),
            " | Compliant: ", coalesce(DeviceCompliant, "Unknown"),
            " | Managed: ", coalesce(DeviceManaged, "Unknown")
        ),
        RiskLevel = RiskLevelDuringSignIn,
        IPAddress,
        RiskEventType = "";
union RiskEvents, AuthDetails
| sort by TimeGenerated asc
```

**What to look for:**

- **RiskEventType = "leakedCredentials"** = The dormant account's password is in a known breach database — very likely compromised
- **RiskEventType = "unfamiliarFeatures"** or **"anonymizedIPAddress"** = Sign-in from suspicious source
- **MFA = "None"** = Dormant account has no MFA — password-only authentication is the highest risk
- **DeviceCompliant = "false"** and **DeviceManaged = "false"** = Unmanaged personal device — not a corporate asset
- **Multiple RiskEvents** clustered around the reactivation = Identity Protection is signaling strong compromise indicators
- **RiskLevel = "none"** with no risk events = Identity Protection did not flag this — your dormancy detection caught what ML didn't

---

### Step 7: Organization-Wide Dormant Account Activity Sweep

**Objective:** Find all dormant accounts that have recently become active across the organization to identify a broader campaign.

```kql
// Step 7: Organization-Wide Dormant Account Activity Sweep
// Table: SigninLogs | Finds all recently-reactivated dormant accounts
let AlertTime = datetime(2026-02-22T14:30:00Z);
let DormancyThreshold = 60d;
let RecentWindow = 7d;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// Find accounts with recent successful sign-ins
let RecentActiveAccounts = SigninLogs
    | where TimeGenerated between ((AlertTime - RecentWindow) .. AlertTime)
    | where ResultType == "0"
    | summarize
        RecentSignInTime = max(TimeGenerated),
        RecentIPs = make_set(IPAddress, 10),
        RecentASNs = make_set(AutonomousSystemNumber, 10),
        RecentCountries = make_set(
            tostring(parse_json(LocationDetails).countryOrRegion), 5
        ),
        RecentApps = make_set(AppDisplayName, 10),
        RecentSignInCount = count()
        by UserPrincipalName;
// Find the last sign-in BEFORE the recent window
let PriorActivity = SigninLogs
    | where TimeGenerated between ((AlertTime - 365d) .. (AlertTime - RecentWindow))
    | where ResultType == "0"
    | summarize
        LastPriorSignIn = max(TimeGenerated),
        PriorCountries = make_set(
            tostring(parse_json(LocationDetails).countryOrRegion), 5
        )
        by UserPrincipalName;
// Join to find dormant accounts that recently reactivated
RecentActiveAccounts
| join kind=leftouter PriorActivity on UserPrincipalName
| extend
    DaysInactive = datetime_diff('day', RecentSignInTime,
        coalesce(LastPriorSignIn, datetime(1970-01-01))),
    HasPriorActivity = isnotnull(LastPriorSignIn)
| where DaysInactive >= DormancyThreshold or not(HasPriorActivity)
| extend
    FromHostingIP = iff(
        array_length(set_intersect(RecentASNs, HostingASNs)) > 0, true, false
    ),
    NewCountry = iff(
        array_length(set_difference(RecentCountries, coalesce(PriorCountries, dynamic([])))) > 0,
        true, false
    )
| extend
    RiskScore = 0
        + iff(DaysInactive > 180, 30, iff(DaysInactive > 90, 20, 10))
        + iff(FromHostingIP, 30, 0)
        + iff(NewCountry, 25, 0)
        + iff(not(HasPriorActivity), 15, 0),
    RiskVerdict = case(
        FromHostingIP and NewCountry, "CRITICAL - Dormant account from hosting IP + new country",
        FromHostingIP, "HIGH - Dormant account reactivated from hosting IP",
        NewCountry, "HIGH - Dormant account from new country",
        DaysInactive > 180, "MEDIUM - Reactivated after 6+ months",
        "LOW - Reactivated after dormancy period"
    )
| where RiskScore >= 30
| project
    UserPrincipalName,
    DaysInactive,
    HasPriorActivity,
    RecentSignInTime,
    RecentCountries,
    FromHostingIP,
    NewCountry,
    RiskScore,
    RiskVerdict,
    RecentApps
| sort by RiskScore desc
```

**What to look for:**

- **RiskVerdict = "CRITICAL"** = Dormant account reactivated from hosting IP AND new country — almost certainly compromised
- **Multiple dormant accounts reactivating in the same window** = Coordinated campaign using old accounts
- **Same RecentIPs across multiple dormant accounts** = Single attacker activating multiple stale accounts
- **HasPriorActivity = false** = Account was never used — possible test/shadow account being abused
- **DaysInactive > 365** = Over a year inactive — should definitely be disabled

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to assess the reactivated dormant account's behavioral context. This runbook is uniquely aligned with UEBA — the `IsDormantAccount` insight directly maps to the investigation target. UEBA's baseline for dormant accounts will show maximum anomaly since there's no recent behavioral baseline to compare against, making every post-reactivation action a "first time" event.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 4.

#### Query 8A: Dormant Account Behavioral Assessment

```kql
// ============================================================
// Query 8A: UEBA Assessment for Reactivated Dormant Account
// Purpose: Assess UEBA signals for a dormant account that has
//          become active — every action is likely "first time"
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T08:00:00Z);
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
    FirstTimeAction = tobool(ActivityInsights.FirstTimeUserPerformedAction),
    ActionUncommonForUser = tobool(ActivityInsights.ActionUncommonlyPerformedByUser),
    ActionUncommonAmongPeers = tobool(ActivityInsights.ActionUncommonlyPerformedAmongPeers),
    FirstTimeISP = tobool(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommonAmongPeers = tobool(ActivityInsights.ISPUncommonlyUsedAmongPeers),
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    FirstTimeDevice = tobool(ActivityInsights.FirstTimeUserConnectedFromDevice),
    FirstTimeApp = tobool(ActivityInsights.FirstTimeUserUsedApp),
    FirstTimeResource = tobool(ActivityInsights.FirstTimeUserAccessedResource),
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| order by InvestigationPriority desc, TimeGenerated desc
```

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| InvestigationPriority | >= 7 | < 4 (unlikely for dormant) |
| IsDormantAccount | true — confirmed dormant | Unexpected if false |
| FirstTimeISP + FirstTimeCountry | true — unknown infrastructure | ISP matches org patterns |
| ISPUncommonAmongPeers | true — infrastructure not used by peers | false — org ISP |
| FirstTimeAction + FirstTimeApp | Multiple first-time activities | Expected for reactivation |
| BlastRadius | High — privileged dormant account | Low |
| ThreatIndicator | Populated — malicious infrastructure | Empty |

**Decision guidance:**

- **IsDormantAccount = true + ISPUncommonAmongPeers = true + ThreatIndicator populated** → Dormant account reactivated from malicious infrastructure. Near-certain credential compromise. Proceed to Containment immediately
- **IsDormantAccount = true + ISPUncommonAmongPeers = true** → Even without threat intel, unknown infrastructure accessing a dormant account is high risk
- **IsDormantAccount = true + ISP matches org patterns** → Could be legitimate reactivation (employee return, seasonal worker). Verify with HR/manager
- **BlastRadius = High** → Dormant privileged account reactivation always requires immediate investigation regardless of other indicators

---

## 6. Containment Playbook

### Immediate Actions (0-30 minutes)
- [ ] **Disable the account** immediately if reactivation is unauthorized
- [ ] **Revoke all active sessions** via `Revoke-AzureADUserAllRefreshToken`
- [ ] **Reset the password** to prevent further access
- [ ] **Verify with HR/IT:** Is this account supposed to be active? Was there a rehire or return from leave?
- [ ] **Check for MFA methods** — remove any registered during the suspicious window

### Short-term Actions (30 min - 4 hours)
- [ ] **Review all audit actions** performed by the account in the post-reactivation window
- [ ] **Remove group memberships** and role assignments that are no longer needed
- [ ] **Audit inbox rules and OAuth app consents** created by the account
- [ ] **Check if password was in a known breach** via Identity Protection leaked credentials
- [ ] **If admin-enabled:** Who enabled the account? Verify the admin action was authorized

### Recovery Actions (4-24 hours)
- [ ] Implement automated dormant account detection (accounts inactive >90 days → disable)
- [ ] Require access recertification for accounts returning from extended inactivity
- [ ] Deploy Conditional Access policy requiring step-up authentication for dormant accounts
- [ ] Review offboarding process to ensure timely account deprovisioning
- [ ] Run organization-wide dormant account sweep (Step 7) and bulk-disable unauthorized

---

## 7. Evidence Collection Checklist

| Evidence Item | Source Table | Retention | Collection Query |
|---|---|---|---|
| Reactivation sign-in details | SigninLogs | 30 days | Step 1 query |
| Dormancy period and last activity | SigninLogs + NonInteractive | 30 days | Step 2 query |
| Account metadata and admin actions | IdentityInfo + AuditLogs | 30 days | Step 3 query |
| Pre-dormancy behavior pattern | SigninLogs | 30 days | Step 4 query |
| Post-reactivation audit trail | AuditLogs | 30 days | Step 5 query |
| Risk events and auth context | AADUserRiskEvents + SigninLogs | 30/90 days | Step 6 query |
| Org-wide dormant account sweep | SigninLogs | 30 days | Step 7 query |

---

## 8. Escalation Criteria

| Condition | Action |
|---|---|
| Dormant account with admin roles reactivated | Escalate to **P1 Incident** — privileged access at risk |
| Reactivation + MFA registration + email rules (Step 5) | Escalate to **P1 Incident** — full account takeover |
| Multiple dormant accounts reactivated simultaneously (Step 7) | Escalate to **P1 Incident** — coordinated campaign |
| Terminated employee account reactivated | Escalate to **P2 Incident** — offboarding process failure |
| Reactivation from hosting IP or new country (Steps 1, 4) | Escalate to **P2 Incident** — suspected compromise |
| Reactivation matches returning employee/contractor | Close as **FP** — document for future reference |

---

## 9. False Positive Documentation

| Scenario | How to Identify | Recommended Action |
|---|---|---|
| Employee returning from leave | HR confirms leave return, same location/device | Document and close |
| Seasonal/contract worker | Recurring pattern (Q4 activation yearly), HR confirms | Create exception for seasonal accounts |
| Shared account used intermittently | Documented shared account, known usage pattern | Add to shared account monitoring list |
| IT admin testing account | Admin ticket or change request exists | Verify against ticket, close |
| Account re-enabled after lockout | Prior lockout in AuditLogs, admin re-enabled | Review lockout cause, close if legitimate |

---

## 10. MITRE ATT&CK Mapping

| Technique ID | Technique Name | How It Applies | Detection Query |
|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Using dormant cloud account credentials | Steps 1, 4, 7 |
| T1078 | Valid Accounts | Leveraging legitimate but inactive accounts | Steps 2, 3 |
| T1098 | Account Manipulation | Post-reactivation account modifications | Step 5 |
| T1078.002 | Valid Accounts: Domain Accounts | Dormant hybrid-synced domain accounts | Step 3 |

---

## 11. Query Summary

| Step | Query | Purpose | Primary Table |
|---|---|---|---|
| 1 | Reactivation Event Analysis | Analyze the sign-in that broke dormancy | SigninLogs |
| 2 | Account Dormancy Period | Calculate inactive duration and last activity | SigninLogs + NonInteractive |
| 3 | Account Metadata Validation | Check account status, roles, and admin actions | IdentityInfo + AuditLogs |
| 4 | Baseline Comparison | Compare reactivation against pre-dormancy pattern | SigninLogs |
| 5 | Post-Reactivation Activity | Detect takeover actions after reactivation | AuditLogs |
| 6 | Risk Event Correlation | Check Identity Protection risk events | AADUserRiskEvents + SigninLogs |
| 7 | Org-Wide Dormant Sweep | Find all recently-reactivated dormant accounts | SigninLogs |

---

## Appendix A: Datatable Tests

### Test 1: Dormancy Period Calculation

```kql
// TEST 1: Verifies correct dormancy period calculation
let AlertTime = datetime(2026-02-22T14:30:00Z);
let TestSigninLogs = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, ResultType: string,
    IPAddress: string, AppDisplayName: string, LocationDetails: dynamic
)[
    // Last activity 95 days ago
    datetime(2025-11-19T09:00:00Z), "dormant@contoso.com", "0", "10.0.0.100",
        "Outlook", dynamic({"countryOrRegion":"US","city":"Chicago"}),
    datetime(2025-11-18T09:00:00Z), "dormant@contoso.com", "0", "10.0.0.100",
        "Teams", dynamic({"countryOrRegion":"US","city":"Chicago"}),
    // Active user for comparison
    datetime(2026-02-21T09:00:00Z), "active@contoso.com", "0", "10.0.0.200",
        "Outlook", dynamic({"countryOrRegion":"US","city":"New York"})
];
TestSigninLogs
| where ResultType == "0"
| summarize LastSignIn = max(TimeGenerated) by UserPrincipalName
| extend DaysInactive = datetime_diff('day', AlertTime, LastSignIn)
| extend IsDormant = DaysInactive > 60
| where IsDormant == true
| where UserPrincipalName == "dormant@contoso.com" and DaysInactive == 95
// EXPECTED: 1 row — dormant@contoso.com inactive for 95 days
```

### Test 2: Reactivation From New Country Detection

```kql
// TEST 2: Verifies detection of reactivation from a country not in pre-dormancy pattern
let TestPreDormancy = datatable(
    UserPrincipalName: string, Country: string, SignInCount: int
)[
    "dormant@contoso.com", "US", 150,
    "dormant@contoso.com", "CA", 10
];
let TestReactivation = datatable(
    UserPrincipalName: string, Country: string
)[
    "dormant@contoso.com", "RU"
];
let PreDormancyCountries = TestPreDormancy
    | summarize Countries = make_set(Country) by UserPrincipalName;
TestReactivation
| join kind=inner PreDormancyCountries on UserPrincipalName
| extend
    IsNewCountry = iff(Country !in (Countries), true, false),
    Verdict = iff(Country !in (Countries),
        "HIGH ANOMALY - Reactivation from country not in pre-dormancy pattern",
        "Normal")
| where IsNewCountry == true
// EXPECTED: 1 row — Russia (RU) not in pre-dormancy pattern (US, CA)
```

### Test 3: Post-Reactivation Takeover Detection

```kql
// TEST 3: Verifies detection of MFA registration shortly after dormant account reactivation
let ReactivationTime = datetime(2026-02-22T14:30:00Z);
let TestAuditLogs = datatable(
    TimeGenerated: datetime, OperationName: string, InitiatedBy: dynamic,
    TargetResources: dynamic, Result: string
)[
    // MFA registration 20 minutes after reactivation
    datetime(2026-02-22T14:50:00Z), "Register security info",
        dynamic({"user":{"userPrincipalName":"dormant@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Phone","modifiedProperties":[]}]), "success",
    // Inbox rule 45 minutes after reactivation
    datetime(2026-02-22T15:15:00Z), "Set inbox rule",
        dynamic({"user":{"userPrincipalName":"dormant@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"ForwardAll","modifiedProperties":[]}]), "success"
];
let InvestigationTarget = "dormant@contoso.com";
TestAuditLogs
| where InitiatedBy has InvestigationTarget
| extend
    HoursSinceReactivation = round(datetime_diff('minute', TimeGenerated, ReactivationTime) / 60.0, 1),
    ActionCategory = case(
        OperationName has_any ("security info", "Register"), "MFA_REGISTRATION",
        OperationName has_any ("inbox", "rule"), "EMAIL_MANIPULATION",
        "OTHER"
    )
| where ActionCategory != "OTHER"
| summarize
    ActionCount = count(),
    Categories = make_set(ActionCategory),
    EarliestAction = min(HoursSinceReactivation)
| where ActionCount == 2 and EarliestAction < 1
// EXPECTED: 1 row — 2 suspicious actions within 1 hour of reactivation
```

### Test 4: Org-Wide Dormant Account Sweep

```kql
// TEST 4: Verifies detection of multiple dormant accounts reactivated from same infrastructure
let AlertTime = datetime(2026-02-22T14:30:00Z);
let DormancyThreshold = 60d;
let HostingASNs = dynamic([14061, 16509]);
// Recent sign-ins (reactivations)
let TestRecent = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, ResultType: string,
    IPAddress: string, AutonomousSystemNumber: int,
    LocationDetails: dynamic
)[
    datetime(2026-02-22T14:00:00Z), "dormant1@contoso.com", "0", "198.51.100.50", 14061,
        dynamic({"countryOrRegion":"NL"}),
    datetime(2026-02-22T14:10:00Z), "dormant2@contoso.com", "0", "198.51.100.51", 14061,
        dynamic({"countryOrRegion":"NL"}),
    datetime(2026-02-22T14:20:00Z), "active@contoso.com", "0", "10.0.0.100", 0,
        dynamic({"countryOrRegion":"US"})
];
// Prior activity (only active user has recent history)
let TestPrior = datatable(
    UserPrincipalName: string, LastPriorSignIn: datetime
)[
    "active@contoso.com", datetime(2026-02-21T09:00:00Z),
    "dormant1@contoso.com", datetime(2025-10-01T09:00:00Z),
    "dormant2@contoso.com", datetime(2025-09-15T09:00:00Z)
];
TestRecent
| where ResultType == "0"
| summarize
    RecentTime = max(TimeGenerated),
    RecentASNs = make_set(AutonomousSystemNumber)
    by UserPrincipalName
| join kind=leftouter TestPrior on UserPrincipalName
| extend DaysInactive = datetime_diff('day', RecentTime, LastPriorSignIn)
| where DaysInactive >= DormancyThreshold
| extend FromHostingIP = iff(array_length(set_intersect(RecentASNs, HostingASNs)) > 0, true, false)
| where FromHostingIP == true
| summarize DormantAccountCount = count(), Accounts = make_set(UserPrincipalName)
| where DormantAccountCount == 2
// EXPECTED: 1 row — 2 dormant accounts (dormant1, dormant2) reactivated from hosting IPs
```

---

## References

- [Inactive user accounts in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts)
- [Access reviews for inactive users](https://learn.microsoft.com/en-us/entra/id-governance/create-access-review)
- [Employee offboarding best practices](https://learn.microsoft.com/en-us/entra/identity/users/howto-manage-user-lifecycle)
- [MITRE ATT&CK T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [Volt Typhoon and dormant account abuse](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)
- [Storm-0558 inactive signing key exploitation](https://msrc.microsoft.com/blog/2023/09/results-of-major-technical-investigation-for-storm-0558-key-acquisition/)
