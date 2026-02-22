---
title: "Self-Service Password Reset Abuse"
id: RB-0018
severity: high
status: reviewed
description: >
  Investigation runbook for detecting abuse of Self-Service Password Reset
  (SSPR) functionality in Entra ID. Covers SSPR initiated from atypical
  locations or devices, password resets by compromised users, SSPR followed
  by immediate suspicious activity, MFA bypass via SSPR flow, and
  organization-wide anomalous password reset patterns. SSPR abuse is a
  critical step in account takeover chains where attackers who have
  compromised a user's email or phone can reset the password to fully
  take over the account.
mitre_attack:
  tactics:
    - tactic_id: TA0006
      tactic_name: "Credential Access"
    - tactic_id: TA0003
      tactic_name: "Persistence"
    - tactic_id: TA0001
      tactic_name: "Initial Access"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
  techniques:
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1556
      technique_name: "Modify Authentication Process"
      confidence: probable
    - technique_id: T1110.001
      technique_name: "Brute Force: Password Guessing"
      confidence: probable
threat_actors:
  - "Scattered Spider (Octo Tempest)"
  - "LAPSUS$"
  - "Storm-0539"
  - "Star Blizzard (SEABORGIUM)"
log_sources:
  - table: "AuditLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "SigninLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "AADUserRiskEvents"
    product: "Entra ID Identity Protection"
    license: "Entra ID P2"
    required: false
    alternatives: []
  - table: "AADNonInteractiveUserSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: true
    alternatives: []
  - table: "OfficeActivity"
    product: "Office 365"
    license: "M365 E3+"
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
  - query: "AuditLogs | where OperationName has 'password' and OperationName has 'reset' | take 1"
    label: primary
    description: "Self-service password reset audit events"
  - query: "SigninLogs | take 1"
    description: "For pre/post-reset sign-in context"
  - query: "AADUserRiskEvents | take 1"
    description: "For correlated risk events around the reset"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "For post-reset token-based access"
---

# Self-Service Password Reset Abuse - Investigation Runbook

> **RB-0018** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Entra ID Audit Logs + SigninLogs Correlation
>
> **Detection Logic:** SSPR events correlated with atypical location, device, or post-reset activity
>
> **Primary MITRE Technique:** T1098 - Account Manipulation

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: SSPR Event Extraction and Context](#step-1-sspr-event-extraction-and-context)
   - [Step 2: Pre-Reset Sign-In and Risk Context](#step-2-pre-reset-sign-in-and-risk-context)
   - [Step 3: Reset Location vs User Normal Location](#step-3-reset-location-vs-user-normal-location)
   - [Step 4: Baseline Comparison - Establish Normal Password Reset Pattern](#step-4-baseline-comparison---establish-normal-password-reset-pattern)
   - [Step 5: Post-Reset Activity Audit](#step-5-post-reset-activity-audit)
   - [Step 6: SSPR Authentication Method Abuse Detection](#step-6-sspr-authentication-method-abuse-detection)
   - [Step 7: Organization-Wide Anomalous SSPR Sweep](#step-7-organization-wide-anomalous-sspr-sweep)
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
This detection fires when a Self-Service Password Reset (SSPR) event in Entra ID exhibits suspicious characteristics:

1. **Atypical location:** SSPR initiated from a country, city, or IP address not seen in the user's 30-day sign-in history
2. **Atypical device/browser:** SSPR from a new device or browser not associated with the user
3. **Risk correlation:** SSPR occurring shortly after Identity Protection risk events (leaked credentials, unfamiliar sign-in)
4. **Post-reset anomaly:** Immediate suspicious activity after password reset (MFA changes, inbox rules, app consent)
5. **Hosting infrastructure:** SSPR initiated from VPS/hosting provider IP (see [RB-0017](high-risk-isp-sign-ins.md))

SSPR events are recorded in AuditLogs with operations like:
- `Self-service password reset flow activity progress`
- `Reset password (by user)` / `Change password (by user)`
- `User submitted the data required for resetting their password`

**Why it matters:**
SSPR is a legitimate feature that allows users to reset their own passwords. However, attackers exploit SSPR in account takeover chains:

1. **Compromised email/phone:** If an attacker has access to the user's email (via AiTM phishing) or phone number (via SIM swap), they can complete SSPR verification and set a new password, fully taking over the account
2. **Post-phishing pivot:** After stealing a session token via AiTM, the attacker uses SSPR to set a password they know, enabling persistent access even after the stolen token expires
3. **Social engineering helpdesk:** Scattered Spider/LAPSUS$ are known for calling IT helpdesks to trigger password resets for targeted accounts
4. **Combined with MFA reset:** Attacker resets password AND registers a new MFA method in rapid succession, achieving complete account takeover

**Why this is HIGH severity:**
- SSPR changes the authentication credential — the user's original password becomes invalid
- If combined with MFA method registration, the legitimate user is completely locked out
- The attacker gains full authenticated access under their own controlled credentials
- Post-SSPR activity is treated as "legitimate" by most security tools since it's a fresh sign-in

---

## 2. Prerequisites

{{ data_check_timeline(page.meta.data_checks) }}

---

## 3. Input Parameters

Set these values before running the investigation queries:

```kql
// === INVESTIGATION PARAMETERS ===
let InvestigationTarget = "user@company.com";   // UPN of account that had SSPR
let AlertTime = datetime(2026-02-22T14:30:00Z); // Time of SSPR event
let LookbackWindow = 24h;                       // Analysis window
let BaselineWindow = 90d;                        // Historical baseline period (SSPR is rare)
```

---

## 4. Quick Triage Criteria

Use this decision matrix for initial severity assessment:

| Indicator | True Positive Signal | False Positive Signal |
|---|---|---|
| Reset location | Foreign country, VPS/hosting IP, Tor | User's home city, office IP |
| Pre-reset context | Risk events, failed MFA, unfamiliar sign-in | No prior risk events |
| Post-reset activity | MFA change, inbox rule, app consent within 1h | Normal email/Teams usage |
| Account type | Executive, admin, finance | Regular user |
| Reset frequency | First-ever or rare reset | User resets password regularly |
| SSPR method | Email verification (compromised inbox) | Authenticator app push |

---

## 5. Investigation Steps

### Step 1: SSPR Event Extraction and Context

**Objective:** Extract all SSPR-related audit events for the target user, including the verification method used and outcome.

```kql
// Step 1: SSPR Event Extraction and Context
// Table: AuditLogs | Extracts SSPR events with method and outcome details
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
AuditLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where OperationName has_any (
    "Self-service password reset",
    "Reset password",
    "Change password",
    "User submitted",
    "Password reset"
)
| where TargetResources[0].userPrincipalName =~ InvestigationTarget
    or InitiatedBy.user.userPrincipalName =~ InvestigationTarget
| extend
    Actor = coalesce(
        tostring(InitiatedBy.user.userPrincipalName),
        tostring(InitiatedBy.app.displayName)
    ),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    AdditionalDetail = tostring(AdditionalDetails),
    ResultReason = ResultDescription
| project
    TimeGenerated,
    OperationName,
    Actor,
    ActorIP,
    TargetUser,
    Result,
    ResultReason,
    AdditionalDetail,
    CorrelationId
| sort by TimeGenerated asc
```

**What to look for:**

- **OperationName sequence:** The SSPR flow generates multiple events: `Self-service password reset flow activity progress` → `Reset password (by user)`. Look for the complete chain.
- **Actor vs TargetUser:** If different, this may be an admin reset rather than self-service
- **ActorIP:** Cross-reference with known hosting providers (see RB-0017 ASN list)
- **Result = "failure"** followed by **Result = "success"** = attacker may have failed initial verification but succeeded on retry
- **Multiple CorrelationIds** = multiple reset attempts — indicates brute-forcing the SSPR verification

---

### Step 2: Pre-Reset Sign-In and Risk Context

**Objective:** Examine sign-in activity and risk events in the hours before the SSPR to determine if the account was already compromised.

```kql
// Step 2: Pre-Reset Sign-In and Risk Context
// Table: SigninLogs + AADUserRiskEvents | Examines pre-reset compromise indicators
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
// Pre-reset sign-in activity (6 hours before)
let PreResetSignIns = SigninLogs
    | where TimeGenerated between ((AlertTime - 6h) .. AlertTime)
    | where UserPrincipalName =~ InvestigationTarget
    | extend ParsedLocation = parse_json(LocationDetails)
    | project
        TimeGenerated,
        EventType = "SignIn",
        Detail = strcat(
            iff(ResultType == "0", "SUCCESS", strcat("FAILED (", ResultType, ")")),
            " | ", AppDisplayName,
            " | IP: ", IPAddress,
            " | ", tostring(ParsedLocation.countryOrRegion),
            "/", tostring(ParsedLocation.city)
        ),
        IPAddress,
        ResultType,
        RiskLevel = RiskLevelDuringSignIn,
        UserAgent;
// Risk events around the reset window
let RiskEvents = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | project
        TimeGenerated,
        EventType = "RiskEvent",
        Detail = strcat(RiskEventType, " | ", RiskDetail, " | Level: ", RiskLevel),
        IPAddress = IpAddress,
        ResultType = "",
        RiskLevel,
        UserAgent = "";
union PreResetSignIns, RiskEvents
| sort by TimeGenerated asc
```

**What to look for:**

- **RiskEvent before SSPR:** `leakedCredentials`, `unfamiliarFeatures`, `anonymizedIPAddress` — account was flagged before reset
- **Failed sign-ins from foreign IP → SSPR** = Attacker couldn't sign in (wrong password or MFA), so they used SSPR to reset the password
- **Successful sign-in from different IP shortly before SSPR** = AiTM session token stolen, attacker using it to navigate to SSPR
- **RiskLevel = "high"** before SSPR = strong indicator that the SSPR is part of an attack chain
- **No pre-reset anomalies** = may be legitimate user reset or the pre-compromise happened outside the window

---

### Step 3: Reset Location vs User Normal Location

**Objective:** Compare the IP/location of the SSPR event against the user's established sign-in locations.

```kql
// Step 3: Reset Location vs User Normal Location
// Table: AuditLogs + SigninLogs | Compares SSPR origin against known user locations
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let BaselineWindow = 30d;
// Get SSPR source IP
let SSPRSourceIPs = AuditLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where OperationName has_any ("Reset password", "Self-service password reset")
    | where TargetResources[0].userPrincipalName =~ InvestigationTarget
        or InitiatedBy.user.userPrincipalName =~ InvestigationTarget
    | extend ActorIP = tostring(InitiatedBy.user.ipAddress)
    | where isnotempty(ActorIP)
    | distinct ActorIP;
// Get user's normal sign-in locations (30-day baseline)
let NormalLocations = SigninLogs
    | where TimeGenerated between ((AlertTime - BaselineWindow) .. AlertTime)
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | extend ParsedLocation = parse_json(LocationDetails)
    | summarize
        SignInCount = count(),
        LastSeen = max(TimeGenerated)
        by
        IPAddress,
        Country = tostring(ParsedLocation.countryOrRegion),
        City = tostring(ParsedLocation.city),
        ASN = AutonomousSystemNumber
    | sort by SignInCount desc;
// Compare SSPR IP against normal locations
let SSPRLocationMatch = NormalLocations
    | where IPAddress in (SSPRSourceIPs)
    | extend MatchType = "SSPR IP matches known location";
let SSPRLocationNew = SSPRSourceIPs
    | where ActorIP !in ((NormalLocations | project IPAddress))
    | extend MatchType = "SSPR IP is NEW - not in baseline";
// Get SSPR IP sign-in details for geolocation
let SSPRIPDetails = SigninLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where IPAddress in (SSPRSourceIPs)
    | extend ParsedLocation = parse_json(LocationDetails)
    | summarize arg_max(TimeGenerated, *) by IPAddress
    | project
        IPAddress,
        Country = tostring(ParsedLocation.countryOrRegion),
        City = tostring(ParsedLocation.city),
        ASN = AutonomousSystemNumber;
SSPRIPDetails
| extend
    IsNewIP = iff(IPAddress !in ((NormalLocations | project IPAddress)), true, false),
    IsNewCountry = iff(Country !in ((NormalLocations | project Country)), true, false)
| extend
    LocationVerdict = case(
        IsNewIP and IsNewCountry, "HIGH RISK - SSPR from new IP AND new country",
        IsNewIP, "MEDIUM RISK - SSPR from new IP in known country",
        "LOW RISK - SSPR from known IP"
    )
```

**What to look for:**

- **"HIGH RISK - SSPR from new IP AND new country"** = SSPR from a location never seen for this user — very suspicious
- **"MEDIUM RISK - SSPR from new IP"** = Same country but new IP — could be mobile network or VPN
- **"LOW RISK"** = SSPR from a known IP — likely legitimate user resetting their own password
- **Cross-reference with RB-0017:** Is the SSPR IP from a hosting/VPS provider?

---

### Step 4: Baseline Comparison - Establish Normal Password Reset Pattern

**Objective:** Determine how frequently this user resets their password and whether the current reset is anomalous.

```kql
// Step 4: Baseline Comparison - Establish Normal Password Reset Pattern
// Table: AuditLogs | Compares current SSPR against 90-day historical pattern
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let BaselineWindow = 90d;
let CurrentWindow = 24h;
// Historical SSPR events (90-day baseline)
let HistoricalSSPR = AuditLogs
    | where TimeGenerated between ((AlertTime - BaselineWindow) .. (AlertTime - CurrentWindow))
    | where OperationName has_any ("Reset password", "Change password", "Self-service password reset")
    | where TargetResources[0].userPrincipalName =~ InvestigationTarget
        or InitiatedBy.user.userPrincipalName =~ InvestigationTarget
    | where Result == "success"
    | summarize
        BaselineResetCount = count(),
        BaselineResetDates = make_set(format_datetime(TimeGenerated, 'yyyy-MM-dd'), 20),
        BaselineResetIPs = make_set(tostring(InitiatedBy.user.ipAddress), 20),
        AvgDaysBetweenResets = datetime_diff('day',
            max(TimeGenerated), min(TimeGenerated)) / max_of(count(), 1);
// Current reset events
let CurrentSSPR = AuditLogs
    | where TimeGenerated between ((AlertTime - CurrentWindow) .. (AlertTime + 4h))
    | where OperationName has_any ("Reset password", "Change password", "Self-service password reset")
    | where TargetResources[0].userPrincipalName =~ InvestigationTarget
        or InitiatedBy.user.userPrincipalName =~ InvestigationTarget
    | where Result == "success"
    | summarize
        CurrentResetCount = count(),
        CurrentResetIPs = make_set(tostring(InitiatedBy.user.ipAddress), 20);
HistoricalSSPR
| extend placeholder = 1
| join kind=fullouter (CurrentSSPR | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    BaselineResetCount = coalesce(BaselineResetCount, 0),
    CurrentResetCount = coalesce(CurrentResetCount, 0),
    NewResetIPs = set_difference(CurrentResetIPs, BaselineResetIPs),
    AnomalyVerdict = case(
        coalesce(BaselineResetCount, 0) == 0 and coalesce(CurrentResetCount, 0) > 0,
            "HIGH ANOMALY - First-ever password reset in 90 days",
        coalesce(CurrentResetCount, 0) > 1,
            "HIGH ANOMALY - Multiple resets in 24h window",
        array_length(set_difference(CurrentResetIPs, coalesce(BaselineResetIPs, dynamic([])))) > 0,
            "MODERATE ANOMALY - Reset from new IP not seen in baseline",
        "LOW ANOMALY - Within normal reset pattern"
    )
```

**What to look for:**

- **"First-ever password reset in 90 days"** = This user has never reset their password — suspicious if from atypical location
- **"Multiple resets in 24h"** = Multiple reset attempts in one day — possible brute-force of SSPR verification
- **"Reset from new IP"** = The IP used for SSPR has never been seen for password resets before
- **BaselineResetCount is very low (0-1 in 90 days)** = SSPR is rare for this user, any reset warrants attention
- **AvgDaysBetweenResets** = If the user normally resets every ~90 days and just reset 2 days ago, the current reset is anomalous

---

### Step 5: Post-Reset Activity Audit

**Objective:** Examine all activity after the password reset to detect immediate account takeover indicators (MFA changes, persistence, data access).

```kql
// Step 5: Post-Reset Activity Audit
// Table: SigninLogs + AuditLogs | Detects post-SSPR attack chain
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
// Get the exact SSPR completion time
let SSPRTime = toscalar(
    AuditLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where OperationName has_any ("Reset password", "Self-service password reset")
    | where TargetResources[0].userPrincipalName =~ InvestigationTarget
        or InitiatedBy.user.userPrincipalName =~ InvestigationTarget
    | where Result == "success"
    | summarize max(TimeGenerated)
);
// Post-reset sign-ins (first 4 hours)
let PostResetSignIns = SigninLogs
    | where TimeGenerated between (SSPRTime .. (SSPRTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | extend ParsedLocation = parse_json(LocationDetails)
    | project
        TimeGenerated,
        ActivityType = "POST_RESET_SIGNIN",
        Detail = strcat("Sign-in to ", AppDisplayName,
            " from ", IPAddress,
            " (", tostring(ParsedLocation.countryOrRegion), "/",
            tostring(ParsedLocation.city), ")"),
        IPAddress,
        Resource = AppDisplayName,
        OperationName = "Sign-in";
// Post-reset audit actions (first 24 hours)
let PostResetAudit = AuditLogs
    | where TimeGenerated between (SSPRTime .. (SSPRTime + 24h))
    | where InitiatedBy has InvestigationTarget
    | where OperationName in (
        "Register security info", "User registered security info",
        "Update security info", "Delete security info",
        "Consent to application", "Add OAuth2PermissionGrant",
        "Set inbox rule", "New-InboxRule",
        "Add member to role", "Add member to group",
        "Add application", "Add service principal credentials",
        "Update conditional access policy"
    )
    | project
        TimeGenerated,
        ActivityType = case(
            OperationName has_any ("security info"), "MFA_CHANGE",
            OperationName has_any ("inbox", "rule"), "EMAIL_MANIPULATION",
            OperationName has_any ("Consent", "OAuth"), "APP_CONSENT",
            OperationName has_any ("role", "group"), "PRIVILEGE_CHANGE",
            "OTHER"
        ),
        Detail = strcat(OperationName, " → ", tostring(TargetResources[0].displayName)),
        IPAddress = tostring(InitiatedBy.user.ipAddress),
        Resource = tostring(TargetResources[0].displayName),
        OperationName;
union PostResetSignIns, PostResetAudit
| extend
    MinutesSinceReset = datetime_diff('minute', TimeGenerated, SSPRTime),
    SuspicionLevel = case(
        ActivityType == "MFA_CHANGE" and datetime_diff('minute', TimeGenerated, SSPRTime) < 60,
            "CRITICAL - MFA change within 1h of reset",
        ActivityType == "EMAIL_MANIPULATION" and datetime_diff('minute', TimeGenerated, SSPRTime) < 120,
            "HIGH - Email rule within 2h of reset",
        ActivityType == "APP_CONSENT",
            "HIGH - App consent after reset",
        ActivityType == "PRIVILEGE_CHANGE",
            "CRITICAL - Privilege change after reset",
        "NORMAL"
    )
| sort by TimeGenerated asc
```

**What to look for:**

- **"CRITICAL - MFA change within 1h of reset"** = Classic account takeover pattern: reset password → register attacker's MFA (see [RB-0012](suspicious-mfa-registration.md))
- **"HIGH - Email rule within 2h"** = BEC operation: reset → create forwarding rule (see [RB-0008](../email/suspicious-inbox-forwarding-rule.md))
- **POST_RESET_SIGNIN from different IP than SSPR IP** = Reset may have been done remotely, but sign-in is from another location
- **Multiple activities from same IP** = Single attacker session doing reset → MFA → persistence → data access
- **MinutesSinceReset < 5 for MFA_CHANGE** = Automated takeover — too fast for manual user action

---

### Step 6: SSPR Authentication Method Abuse Detection

**Objective:** Determine if the SSPR verification method itself was compromised (email to hacked inbox, SMS to SIM-swapped phone).

```kql
// Step 6: SSPR Authentication Method Abuse Detection
// Table: AuditLogs | Analyzes the SSPR verification method and its integrity
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
// Get SSPR flow details
let SSPRFlow = AuditLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where OperationName has "Self-service password reset"
    | where TargetResources[0].userPrincipalName =~ InvestigationTarget
        or InitiatedBy.user.userPrincipalName =~ InvestigationTarget
    | extend
        AdditionalDetail = tostring(AdditionalDetails),
        ModifiedProps = tostring(TargetResources[0].modifiedProperties)
    | project
        TimeGenerated,
        OperationName,
        Result,
        ResultDescription,
        AdditionalDetail,
        ModifiedProps,
        ActorIP = tostring(InitiatedBy.user.ipAddress),
        CorrelationId;
// Check for recent MFA method changes BEFORE the SSPR (attacker prepping)
let PreResetMFAChanges = AuditLogs
    | where TimeGenerated between ((AlertTime - 72h) .. AlertTime)
    | where OperationName has_any (
        "Register security info", "Update security info",
        "User registered security info", "User started security info registration"
    )
    | where TargetResources[0].userPrincipalName =~ InvestigationTarget
        or InitiatedBy.user.userPrincipalName =~ InvestigationTarget
    | project
        TimeGenerated,
        OperationName,
        Detail = tostring(TargetResources[0].modifiedProperties),
        ActorIP = tostring(InitiatedBy.user.ipAddress),
        Result;
// Check for email compromise indicators (sign-ins to email before SSPR)
let EmailAccess = SigninLogs
    | where TimeGenerated between ((AlertTime - 24h) .. AlertTime)
    | where UserPrincipalName =~ InvestigationTarget
    | where AppDisplayName has_any ("Outlook", "Exchange", "Mail")
    | where ResultType == "0"
    | project
        TimeGenerated,
        OperationName = strcat("Email access via ", AppDisplayName),
        Detail = strcat("IP: ", IPAddress, " | UA: ", UserAgent),
        ActorIP = IPAddress,
        Result = "success";
union SSPRFlow, PreResetMFAChanges, EmailAccess
| sort by TimeGenerated asc
```

**What to look for:**

- **MFA method change 1-72h BEFORE SSPR** = Attacker registered their own MFA method first, then used it for SSPR verification — premeditated takeover
- **Email access from suspicious IP BEFORE SSPR** = Attacker accessed the user's email first (via AiTM) and used the verification email sent by SSPR
- **Multiple CorrelationIds for SSPR** = Multiple reset attempts — attacker retrying with different verification methods
- **ResultDescription containing "email"** or **"SMS"** = Verification method used — if email, check for inbox compromise; if SMS, check for SIM swap indicators
- **ActorIP on SSPR matching ActorIP on pre-reset MFA change** = Same attacker session — complete takeover chain

---

### Step 7: Organization-Wide Anomalous SSPR Sweep

**Objective:** Determine if other accounts in the organization are experiencing unusual SSPR activity, indicating a broader campaign.

```kql
// Step 7: Organization-Wide Anomalous SSPR Sweep
// Table: AuditLogs + SigninLogs | Finds anomalous SSPR patterns across the org
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 7d;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// All successful SSPR events in the past 7 days
let AllSSPR = AuditLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. AlertTime)
    | where OperationName has_any ("Reset password", "Self-service password reset")
    | where Result == "success"
    | extend
        TargetUser = tostring(TargetResources[0].userPrincipalName),
        ActorIP = tostring(InitiatedBy.user.ipAddress);
// Correlate with sign-in data for ASN enrichment
let SSPRWithASN = AllSSPR
    | join kind=leftouter (
        SigninLogs
        | where TimeGenerated between ((AlertTime - LookbackWindow) .. AlertTime)
        | summarize arg_max(TimeGenerated, AutonomousSystemNumber) by IPAddress
    ) on $left.ActorIP == $right.IPAddress;
SSPRWithASN
| summarize
    ResetCount = count(),
    ResetDates = make_set(format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm'), 10),
    SourceIPs = make_set(ActorIP, 10),
    FromHostingIP = countif(AutonomousSystemNumber in (HostingASNs))
    by TargetUser
| extend
    RiskIndicator = case(
        ResetCount > 2 and FromHostingIP > 0, "CRITICAL - Multiple resets from hosting IPs",
        FromHostingIP > 0, "HIGH - Reset from hosting infrastructure",
        ResetCount > 3, "MEDIUM - Excessive reset frequency",
        ResetCount > 1, "LOW - Multiple resets in 7 days",
        "NORMAL"
    )
| where RiskIndicator != "NORMAL"
| sort by case(
    RiskIndicator has "CRITICAL", 1,
    RiskIndicator has "HIGH", 2,
    RiskIndicator has "MEDIUM", 3,
    4
) asc, ResetCount desc
```

**What to look for:**

- **"CRITICAL - Multiple resets from hosting IPs"** = Accounts being reset from attacker infrastructure — likely compromised
- **"HIGH - Reset from hosting infrastructure"** = Single reset from VPS/hosting — needs immediate investigation
- **Multiple users with resets in the same time window** = Coordinated campaign
- **Same ActorIP across different TargetUsers** = Single attacker resetting multiple accounts
- **Shared hosting ASN across resets** = Same attack infrastructure being reused

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to assess whether the self-service password reset is anomalous. UEBA provides critical account status context — `IsDormantAccount` and `IsNewAccount` — that reveals if the password reset is a legitimate user action or an attacker leveraging SSPR to take over an account. Geographic and ISP anomalies during the reset further indicate whether the reset originated from the real user.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 4.

#### Query 8A: Password Reset Anomaly Assessment

```kql
// ============================================================
// Query 8A: UEBA Anomaly Assessment for SSPR
// Purpose: Check if the password reset activity is anomalous
//          and assess account dormancy/blast radius
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T07:00:00Z);
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
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommonForUser = tobool(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    IsNewAccount = tobool(UsersInsights.IsNewAccount),
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| order by InvestigationPriority desc, TimeGenerated desc
```

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| InvestigationPriority | >= 7 | < 4 |
| IsDormantAccount | true — dormant account resetting password | false |
| FirstTimeAction | true — user never reset password via SSPR | false — resets periodically |
| FirstTimeISP | true — reset from new ISP | false — user's ISP |
| FirstTimeCountry | true — from unusual location | false — user's location |
| BlastRadius | High — privileged account | Low |

**Decision guidance:**

- **IsDormantAccount = true + FirstTimeISP** → Dormant account password reset from new infrastructure. Near-certain account takeover
- **FirstTimeAction = true + FirstTimeCountry = true** → Password reset from unusual location by user who never used SSPR. High suspicion
- **InvestigationPriority < 4 + user's normal location** → Likely forgotten password scenario

---

## 6. Containment Playbook

### Immediate Actions (0-30 minutes)
- [ ] **Force another password reset** by an admin (not self-service) for the affected account
- [ ] **Revoke all active sessions** via `Revoke-AzureADUserAllRefreshToken`
- [ ] **Review and remove** any MFA methods registered after the suspicious SSPR
- [ ] **Temporarily disable SSPR** for the affected account if attack is ongoing
- [ ] **Contact the user** via out-of-band channel (phone call) to verify they initiated the reset

### Short-term Actions (30 min - 4 hours)
- [ ] **Audit all inbox rules** created after the SSPR — remove any forwarding/redirect rules
- [ ] **Review OAuth app consents** granted after the reset — revoke suspicious grants
- [ ] **Check for new devices/MFA methods** registered in the post-reset window
- [ ] **Review SSPR policy:** Are verification methods strong enough? (Authenticator > SMS > Email)
- [ ] **Block hosting IPs** used in the attack via Conditional Access Named Locations

### Recovery Actions (4-24 hours)
- [ ] Require Authenticator app (not email/SMS) as SSPR verification method
- [ ] Implement Conditional Access policy requiring compliant device for SSPR
- [ ] Enable Identity Protection risk-based SSPR restrictions
- [ ] Review SSPR registration data — ensure only valid phone/email are registered
- [ ] Implement alert rule for SSPR from hosting/VPS IPs

---

## 7. Evidence Collection Checklist

| Evidence Item | Source Table | Retention | Collection Query |
|---|---|---|---|
| SSPR flow events and verification method | AuditLogs | 30 days | Step 1 query |
| Pre-reset sign-in and risk context | SigninLogs + AADUserRiskEvents | 30/90 days | Step 2 query |
| SSPR location vs normal locations | AuditLogs + SigninLogs | 30 days | Step 3 query |
| Historical SSPR frequency baseline | AuditLogs | 30 days | Step 4 query |
| Post-reset activity chain | SigninLogs + AuditLogs | 30 days | Step 5 query |
| SSPR verification method integrity | AuditLogs | 30 days | Step 6 query |
| Org-wide SSPR anomaly sweep | AuditLogs | 30 days | Step 7 query |

---

## 8. Escalation Criteria

| Condition | Action |
|---|---|
| SSPR from hosting IP + MFA change within 1h (Steps 5, 6) | Escalate to **P1 Incident** — full account takeover |
| SSPR + email rule creation within 2h (Step 5) | Escalate to **P1 Incident** — BEC in progress |
| Multiple accounts with SSPR from same IP (Step 7) | Escalate to **P1 Incident** — coordinated campaign |
| Executive/admin account SSPR from atypical location | Escalate to **P2 Incident** — high-value target |
| SSPR with pre-reset MFA method change (Step 6) | Escalate to **P1 Incident** — premeditated takeover |
| SSPR from known country but new IP | Escalate to **P3 Incident** — review and verify with user |

---

## 9. False Positive Documentation

| Scenario | How to Identify | Recommended Action |
|---|---|---|
| User forgot password | SSPR from known location, no post-reset anomalies | Confirm with user, close alert |
| IT helpdesk-assisted reset | Admin-initiated reset, helpdesk ticket exists | Verify against helpdesk ticket |
| Onboarding/offboarding | New hire first-day reset, or departing employee | Correlate with HR records |
| Password expiry forced reset | Regular cadence (e.g., every 90 days), known location | Document pattern, reduce alert threshold |
| User traveling (mobile network) | SSPR from new city but known country, user confirmed | Document travel, close alert |

---

## 10. MITRE ATT&CK Mapping

| Technique ID | Technique Name | How It Applies | Detection Query |
|---|---|---|---|
| T1098 | Account Manipulation | Password reset changes authentication credential | Steps 1, 4 |
| T1078.004 | Valid Accounts: Cloud Accounts | Post-reset sign-in with attacker-set password | Step 5 |
| T1556 | Modify Authentication Process | SSPR abuse to change authentication credential | Steps 1, 6 |
| T1110.001 | Brute Force: Password Guessing | Brute-forcing SSPR verification codes | Step 1 (multiple attempts) |

---

## 11. Query Summary

| Step | Query | Purpose | Primary Table |
|---|---|---|---|
| 1 | SSPR Event Extraction | Extract SSPR events with method and outcome | AuditLogs |
| 2 | Pre-Reset Sign-In Context | Examine risk events before the reset | SigninLogs + AADUserRiskEvents |
| 3 | Reset Location Comparison | Compare SSPR origin against known locations | AuditLogs + SigninLogs |
| 4 | Baseline Comparison | Compare reset frequency against 90-day history | AuditLogs |
| 5 | Post-Reset Activity Audit | Detect takeover actions after password reset | SigninLogs + AuditLogs |
| 6 | SSPR Method Abuse Detection | Analyze verification method integrity | AuditLogs + SigninLogs |
| 7 | Org-Wide SSPR Sweep | Find anomalous resets across the organization | AuditLogs + SigninLogs |

---

## Appendix A: Datatable Tests

### Test 1: SSPR Event Detection

```kql
// TEST 1: Verifies SSPR event extraction and classification
let TestAuditLogs = datatable(
    TimeGenerated: datetime, OperationName: string, Result: string,
    ResultDescription: string, InitiatedBy: dynamic, TargetResources: dynamic,
    AdditionalDetails: string, CorrelationId: string
)[
    datetime(2026-02-22T14:20:00Z), "Self-service password reset flow activity progress",
        "success", "User submitted data for password reset",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"userPrincipalName":"alice@contoso.com"}]),
        "SSPR step 1", "corr-001",
    datetime(2026-02-22T14:25:00Z), "Reset password (by user)",
        "success", "Password reset completed",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"userPrincipalName":"alice@contoso.com"}]),
        "SSPR complete", "corr-001",
    // Admin-initiated reset (different operation)
    datetime(2026-02-22T15:00:00Z), "Reset password (by admin)",
        "success", "Admin reset password",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com","ipAddress":"10.0.0.1"}}),
        dynamic([{"userPrincipalName":"bob@contoso.com"}]),
        "Admin reset", "corr-002"
];
let InvestigationTarget = "alice@contoso.com";
TestAuditLogs
| where OperationName has_any ("Self-service password reset", "Reset password")
| where TargetResources[0].userPrincipalName =~ InvestigationTarget
    or InitiatedBy.user.userPrincipalName =~ InvestigationTarget
| summarize
    EventCount = count(),
    Operations = make_set(OperationName),
    ActorIP = take_any(tostring(InitiatedBy.user.ipAddress))
| where EventCount == 2 and ActorIP == "198.51.100.50"
// EXPECTED: 1 row — 2 SSPR events for alice from IP 198.51.100.50
```

### Test 2: Post-Reset MFA Change Detection

```kql
// TEST 2: Verifies detection of MFA registration within 1 hour of password reset
let SSPRTime = datetime(2026-02-22T14:25:00Z);
let TestAuditLogs = datatable(
    TimeGenerated: datetime, OperationName: string, Result: string,
    InitiatedBy: dynamic, TargetResources: dynamic
)[
    // SSPR completion
    datetime(2026-02-22T14:25:00Z), "Reset password (by user)", "success",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"userPrincipalName":"alice@contoso.com","modifiedProperties":[]}]),
    // MFA registration 15 minutes after reset - SUSPICIOUS
    datetime(2026-02-22T14:40:00Z), "Register security info", "success",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Phone +1-555-ATTACKER","modifiedProperties":[]}]),
    // Normal activity 3 hours later
    datetime(2026-02-22T17:30:00Z), "Update user", "success",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"10.0.0.100"}}),
        dynamic([{"displayName":"alice@contoso.com","modifiedProperties":[]}])
];
let InvestigationTarget = "alice@contoso.com";
TestAuditLogs
| where TimeGenerated between (SSPRTime .. (SSPRTime + 1h))
| where InitiatedBy has InvestigationTarget
| where OperationName has_any ("security info", "Register")
| extend MinutesSinceReset = datetime_diff('minute', TimeGenerated, SSPRTime)
| where MinutesSinceReset <= 60
| project TimeGenerated, OperationName, MinutesSinceReset,
    SuspicionLevel = "CRITICAL - MFA change within 1h of reset"
| where MinutesSinceReset == 15
// EXPECTED: 1 row — MFA registration 15 minutes after password reset
```

### Test 3: SSPR From New Location Detection

```kql
// TEST 3: Verifies detection of SSPR from location not in user's baseline
let TestBaseline = datatable(
    IPAddress: string, Country: string, City: string, SignInCount: int
)[
    "10.0.0.100", "US", "Chicago", 150,
    "10.0.0.200", "US", "New York", 50
];
let TestSSPRIP = datatable(
    IPAddress: string, Country: string, City: string
)[
    "198.51.100.50", "NL", "Amsterdam"
];
TestSSPRIP
| extend
    IsNewIP = iff(IPAddress !in ((TestBaseline | project IPAddress)), true, false),
    IsNewCountry = iff(Country !in ((TestBaseline | project Country)), true, false)
| extend LocationVerdict = case(
    IsNewIP and IsNewCountry, "HIGH RISK - SSPR from new IP AND new country",
    IsNewIP, "MEDIUM RISK - SSPR from new IP in known country",
    "LOW RISK - SSPR from known IP"
)
| where LocationVerdict == "HIGH RISK - SSPR from new IP AND new country"
// EXPECTED: 1 row — SSPR from Netherlands not in US-only baseline
```

### Test 4: Org-Wide SSPR Campaign Detection

```kql
// TEST 4: Verifies detection of multiple accounts with SSPR from hosting IPs
let HostingASNs = dynamic([14061, 16509, 15169]);
let TestSSPR = datatable(
    TimeGenerated: datetime, TargetUser: string, ActorIP: string,
    AutonomousSystemNumber: int
)[
    // Same attacker IP resetting multiple accounts
    datetime(2026-02-22T14:00:00Z), "alice@contoso.com", "198.51.100.50", 14061,
    datetime(2026-02-22T14:10:00Z), "bob@contoso.com", "198.51.100.50", 14061,
    datetime(2026-02-22T14:20:00Z), "charlie@contoso.com", "198.51.100.51", 14061,
    // Legitimate reset from residential IP
    datetime(2026-02-22T15:00:00Z), "dave@contoso.com", "192.0.2.100", 7922
];
TestSSPR
| summarize
    ResetCount = count(),
    TargetedAccounts = dcount(TargetUser),
    AccountsList = make_set(TargetUser),
    FromHostingIP = countif(AutonomousSystemNumber in (HostingASNs))
    by AutonomousSystemNumber
| where FromHostingIP > 0 and TargetedAccounts >= 2
// EXPECTED: 1 row — ASN 14061 with 3 accounts reset from hosting IPs
```

---

## References

- [Self-Service Password Reset in Entra ID - Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-howitworks)
- [SSPR Audit Events in Azure AD](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-reporting)
- [Combined registration for SSPR and MFA](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-registration-mfa-sspr-combined)
- [MITRE ATT&CK T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [Scattered Spider social engineering and SSPR abuse](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)
- [LAPSUS$ account takeover via SSPR and helpdesk](https://www.microsoft.com/en-us/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/)
