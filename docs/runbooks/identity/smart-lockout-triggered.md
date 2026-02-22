---
title: "Smart Lockout Triggered"
id: RB-0016
severity: high
status: reviewed
description: >
  Investigation runbook for Azure AD Smart Lockout events indicating active
  brute force or credential stuffing attacks against user accounts. Covers
  lockout trigger analysis (ResultType 50053), attack source infrastructure
  profiling, extranet vs intranet lockout differentiation, post-lockout
  successful authentication detection, and coordinated multi-account lockout
  campaign identification. Smart Lockout is definitive proof that an attacker
  is actively attempting to compromise an account — unlike failed sign-ins
  which may be user error, a lockout means the threshold was exceeded from
  an unrecognized location.
mitre_attack:
  tactics:
    - tactic_id: TA0006
      tactic_name: "Credential Access"
    - tactic_id: TA0001
      tactic_name: "Initial Access"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
  techniques:
    - technique_id: T1110.001
      technique_name: "Brute Force: Password Guessing"
      confidence: confirmed
    - technique_id: T1110.003
      technique_name: "Brute Force: Password Spraying"
      confidence: probable
    - technique_id: T1110.004
      technique_name: "Brute Force: Credential Stuffing"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Peach Sandstorm (APT33)"
  - "Storm-1283"
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
  - table: "AADUserRiskEvents"
    product: "Entra ID Identity Protection"
    license: "Entra ID P2"
    required: false
    alternatives: []
  - table: "AuditLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "IdentityLogonEvents"
    product: "Defender for Identity"
    license: "Defender for Identity"
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
  - query: "SigninLogs | where ResultType == '50053' | take 1"
    label: primary
    description: "Smart Lockout event detection (ResultType 50053)"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "For non-interactive brute force attempts"
  - query: "AADUserRiskEvents | take 1"
    description: "For correlated Identity Protection risk events"
  - query: "AuditLogs | take 1"
    description: "For post-lockout account changes and persistence"
---

# Smart Lockout Triggered - Investigation Runbook

> **RB-0016** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Smart Lockout + SigninLogs Analysis
> **Risk Detection:** ResultType `50053` (Account locked due to repeated sign-in attempts)
> **Primary MITRE Technique:** T1110.001 - Brute Force: Password Guessing

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Smart Lockout Event Analysis](#step-1-smart-lockout-event-analysis)
   - [Step 2: Attack Source Infrastructure Profiling](#step-2-attack-source-infrastructure-profiling)
   - [Step 3: Pre-Lockout Failure Pattern Analysis](#step-3-pre-lockout-failure-pattern-analysis)
   - [Step 4: Baseline Comparison - Establish Normal Lockout Pattern](#step-4-baseline-comparison---establish-normal-lockout-pattern)
   - [Step 5: Post-Lockout Successful Authentication Detection](#step-5-post-lockout-successful-authentication-detection)
   - [Step 6: Coordinated Multi-Account Lockout Campaign](#step-6-coordinated-multi-account-lockout-campaign)
   - [Step 7: Post-Compromise Activity Sweep](#step-7-post-compromise-activity-sweep)
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
Azure AD Smart Lockout triggers when a user account exceeds the failed authentication threshold from an **unrecognized location**. The system differentiates between:

1. **Extranet lockout:** Failed attempts from IP addresses not on the organization's trusted network — these are locked out after the configured threshold (default: 10 attempts). This is the primary attack indicator.
2. **Intranet lockout:** Failed attempts from corporate/trusted IPs — these have a higher threshold, as they're more likely to be the legitimate user. Intranet lockouts appearing in logs suggest on-prem compromise or internal lateral movement.

The lockout is recorded as `ResultType 50053` in SigninLogs with `ResultDescription` containing "Account is locked."

**Why it matters:**
Smart Lockout is **definitive proof** that someone is actively brute-forcing a specific account. Unlike a few failed sign-ins (which could be user error), reaching the lockout threshold from an unrecognized location means sustained, automated password guessing. The critical question is: **did the attacker succeed before the lockout triggered?** Smart Lockout uses a familiar-vs-unfamiliar location model — an attacker from an unfamiliar IP gets locked out at the lower threshold, but the legitimate user from a familiar IP can still sign in. This means:

- The attacker may have **already guessed the correct password** on an earlier attempt before lockout
- If the password was correct, subsequent sign-ins from the attacker IP may succeed after the lockout window expires
- Multi-account lockouts from the same infrastructure indicate a coordinated spray/stuff campaign

**Why this is HIGH severity:**
- Lockout is proof of active attack, not speculative — someone is targeting this specific account
- Credential stuffing uses known breached password lists — success rate is high against password-reuse
- The lockout window is temporary (default: 60 seconds for extranet) — attacker can resume after waiting
- Smart Lockout only protects against extranet attacks — intranet-sourced brute force has no lockout protection

---

## 2. Prerequisites

{{ data_check_timeline(page.meta.data_checks) }}

---

## 3. Input Parameters

Set these values before running the investigation queries:

```kql
// === INVESTIGATION PARAMETERS ===
let InvestigationTarget = "user@company.com";   // UPN of locked-out account
let AlertTime = datetime(2026-02-22T14:30:00Z); // Time of lockout event
let LookbackWindow = 24h;                       // Analysis window
let BaselineWindow = 30d;                        // Historical baseline period
```

---

## 4. Quick Triage Criteria

Use this decision matrix for initial severity assessment:

| Indicator | True Positive Signal | False Positive Signal |
|---|---|---|
| Source IP | VPS/hosting provider, Tor, foreign residential proxy | Corporate VPN, known office IP |
| Lockout pattern | Multiple accounts locked from same IP range | Single user, single event |
| Post-lockout auth | Successful sign-in from same source IP | No successful auth from attacker IP |
| Account type | Executive, admin, service account | Regular user who forgot password |
| Time of day | Outside business hours, weekend | During normal work hours |
| Failure count | Hundreds of failures before lockout | 10-15 failures (threshold boundary) |

---

## 5. Investigation Steps

### Step 1: Smart Lockout Event Analysis

**Objective:** Extract all lockout events for the target account, quantify the attack intensity, and identify attacker infrastructure.

```kql
// Step 1: Smart Lockout Event Analysis
// Table: SigninLogs | Identifies all lockout events and the attack source
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where UserPrincipalName =~ InvestigationTarget
| where ResultType == "50053"  // Smart Lockout triggered
| extend ParsedLocation = parse_json(LocationDetails)
| extend
    City = tostring(ParsedLocation.city),
    State = tostring(ParsedLocation.state),
    Country = tostring(ParsedLocation.countryOrRegion),
    Latitude = toreal(ParsedLocation.geoCoordinates.latitude),
    Longitude = toreal(ParsedLocation.geoCoordinates.longitude)
| summarize
    LockoutCount = count(),
    FirstLockout = min(TimeGenerated),
    LastLockout = max(TimeGenerated),
    DistinctIPs = dcount(IPAddress),
    SourceIPs = make_set(IPAddress, 50),
    UserAgents = make_set(UserAgent, 20),
    Countries = make_set(Country, 10),
    Cities = make_set(City, 20),
    ClientApps = make_set(ClientAppUsed, 10),
    ResourcesTargeted = make_set(ResourceDisplayName, 10),
    ASNs = make_set(AutonomousSystemNumber, 20)
| extend
    AttackDuration = datetime_diff('minute', LastLockout, FirstLockout),
    AvgLockoutsPerHour = round(LockoutCount / max_of(datetime_diff('hour', LastLockout, FirstLockout), 1), 1)
```

**What to look for:**

- **LockoutCount > 5** within the lookback window = sustained attack, not a one-off
- **DistinctIPs > 1** = distributed attack infrastructure (proxy rotation, botnet)
- **UserAgents** containing `python-requests`, `curl`, `Go-http-client` = automated tooling
- **ClientAppUsed** = `Other clients` or `Exchange ActiveSync` = legacy auth exploitation attempt
- **Countries** containing locations the user has never visited = foreign-sourced attack
- **AttackDuration** spanning hours = persistent, determined attacker

---

### Step 2: Attack Source Infrastructure Profiling

**Objective:** Profile the IP addresses triggering lockouts to determine if they are known malicious infrastructure (VPS, hosting, Tor exit nodes).

```kql
// Step 2: Attack Source Infrastructure Profiling
// Table: SigninLogs | Profiles attacker IP infrastructure across all sign-in attempts
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
let KnownHostingASNs = dynamic([
    14061,   // DigitalOcean
    16509,   // Amazon AWS
    15169,   // Google Cloud
    8075,    // Microsoft Azure
    13335,   // Cloudflare
    24940,   // Hetzner
    16276,   // OVHcloud
    63949,   // Linode/Akamai
    20473,   // Vultr/Choopa
    14618,   // Amazon AWS
    46606,   // Unified Layer
    36352,   // ColoCrossing
    55286,   // ServerMania
    396982   // Google Cloud
]);
SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where UserPrincipalName =~ InvestigationTarget
| where ResultType in ("50053", "50126", "50074", "0")  // Lockout, wrong password, MFA required, success
| extend ParsedLocation = parse_json(LocationDetails)
| extend
    Country = tostring(ParsedLocation.countryOrRegion),
    City = tostring(ParsedLocation.city)
| summarize
    TotalAttempts = count(),
    LockoutEvents = countif(ResultType == "50053"),
    WrongPassword = countif(ResultType == "50126"),
    MFATriggered = countif(ResultType == "50074"),
    SuccessfulAuth = countif(ResultType == "0"),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    UserAgents = make_set(UserAgent, 10),
    ClientApps = make_set(ClientAppUsed, 5)
    by IPAddress, AutonomousSystemNumber, Country, City
| extend
    IsHostingProvider = AutonomousSystemNumber in (KnownHostingASNs),
    PasswordFoundBeforeLockout = iff(SuccessfulAuth > 0 or MFATriggered > 0, true, false),
    AttackIntensity = case(
        TotalAttempts > 100, "Critical - Automated",
        TotalAttempts > 30, "High - Sustained",
        TotalAttempts > 10, "Medium - Targeted",
        "Low - Probing"
    )
| sort by TotalAttempts desc
```

**What to look for:**

- **IsHostingProvider = true** = strong indicator of attacker-controlled infrastructure
- **PasswordFoundBeforeLockout = true** = **CRITICAL** — attacker may have found the correct password. If MFATriggered > 0, the password is compromised
- **SuccessfulAuth > 0** from a hosting IP = confirmed account compromise
- **Multiple IPs with same ASN** = attacker rotating IPs within the same provider
- **AttackIntensity = "Critical - Automated"** = automated tooling (Hydra, Spray365, MSOLSpray)

---

### Step 3: Pre-Lockout Failure Pattern Analysis

**Objective:** Analyze the failure pattern before lockout to determine attack type (brute force, credential stuffing, or password spray).

```kql
// Step 3: Pre-Lockout Failure Pattern Analysis
// Table: SigninLogs | Differentiates brute force vs credential stuffing vs spray
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where UserPrincipalName =~ InvestigationTarget
| where ResultType in ("50053", "50126", "50057", "50055", "53003", "50074", "0")
| extend
    ResultCategory = case(
        ResultType == "50053", "SmartLockout",
        ResultType == "50126", "InvalidPassword",
        ResultType == "50057", "AccountDisabled",
        ResultType == "50055", "PasswordExpired",
        ResultType == "53003", "BlockedByCA",
        ResultType == "50074", "MFARequired",
        ResultType == "0", "Success",
        "Other"
    )
| summarize
    AttemptCount = count(),
    ResultTypes = make_set(ResultCategory),
    DistinctUserAgents = dcount(UserAgent),
    UserAgents = make_set(UserAgent, 10)
    by bin(TimeGenerated, 5m), IPAddress
| extend
    AttackPattern = case(
        AttemptCount > 20 and DistinctUserAgents == 1, "Brute Force - Single Tool",
        AttemptCount > 20 and DistinctUserAgents > 3, "Credential Stuffing - Multi-Tool",
        AttemptCount between (5 .. 20), "Targeted Password Guessing",
        AttemptCount <= 5, "Low-and-Slow Spray",
        "Unknown Pattern"
    )
| sort by TimeGenerated asc
```

**What to look for:**

- **Brute Force pattern:** High attempt count, single UserAgent, single IP — automated tool cycling through password list
- **Credential Stuffing:** High attempt count, multiple UserAgents — using breached credential databases
- **Low-and-Slow:** Few attempts per window, but sustained over time — evading rate limits
- **InvalidPassword → MFARequired → Success** sequence = password was found, attacker may have bypassed MFA
- **ResultTypes containing "BlockedByCA"** = Conditional Access is providing defense-in-depth

---

### Step 4: Baseline Comparison - Establish Normal Lockout Pattern

**Objective:** Determine if lockout events are anomalous for this specific user or if they have a history of account lockouts (forgotten password, misconfigured device).

```kql
// Step 4: Baseline Comparison - Establish Normal Lockout Pattern
// Table: SigninLogs | Compares current lockout against 30-day historical baseline
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let BaselineWindow = 30d;
let BaselineStart = AlertTime - BaselineWindow;
let CurrentWindow = 24h;
// Historical baseline: lockout and failure patterns
let HistoricalPattern = SigninLogs
    | where TimeGenerated between (BaselineStart .. (AlertTime - CurrentWindow))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType in ("50053", "50126")
    | summarize
        BaselineDays = datetime_diff('day', max(TimeGenerated), min(TimeGenerated)),
        TotalLockouts_Baseline = countif(ResultType == "50053"),
        TotalFailures_Baseline = countif(ResultType == "50126"),
        DistinctLockoutDays = dcountif(bin(TimeGenerated, 1d), ResultType == "50053"),
        BaselineIPs = make_set(IPAddress, 50),
        BaselineCountries = make_set(
            tostring(parse_json(LocationDetails).countryOrRegion), 10
        ),
        BaselineUserAgents = make_set(UserAgent, 20);
// Current incident window
let CurrentPattern = SigninLogs
    | where TimeGenerated between ((AlertTime - CurrentWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType in ("50053", "50126")
    | summarize
        TotalLockouts_Current = countif(ResultType == "50053"),
        TotalFailures_Current = countif(ResultType == "50126"),
        CurrentIPs = make_set(IPAddress, 50),
        CurrentCountries = make_set(
            tostring(parse_json(LocationDetails).countryOrRegion), 10
        ),
        CurrentUserAgents = make_set(UserAgent, 20);
HistoricalPattern
| extend placeholder = 1
| join kind=inner (CurrentPattern | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    AvgDailyLockouts_Baseline = round(
        iff(BaselineDays > 0, toreal(TotalLockouts_Baseline) / BaselineDays, 0.0), 2
    ),
    LockoutSpikeMultiplier = round(
        iff(TotalLockouts_Baseline > 0,
            toreal(TotalLockouts_Current) / max_of(toreal(TotalLockouts_Baseline) / max_of(BaselineDays, 1), 0.01),
            999.0),
        1
    ),
    NewSourceIPs = set_difference(CurrentIPs, BaselineIPs),
    NewCountries = set_difference(CurrentCountries, BaselineCountries),
    NewUserAgents = set_difference(CurrentUserAgents, BaselineUserAgents)
| extend
    AnomalyVerdict = case(
        TotalLockouts_Baseline == 0 and TotalLockouts_Current > 0, "HIGH ANOMALY - First-ever lockout",
        LockoutSpikeMultiplier > 10, "HIGH ANOMALY - Lockout spike >10x baseline",
        LockoutSpikeMultiplier > 3, "MODERATE ANOMALY - Lockout spike >3x baseline",
        array_length(NewSourceIPs) > 0, "MODERATE ANOMALY - Lockouts from new IPs",
        array_length(NewCountries) > 0, "HIGH ANOMALY - Lockouts from new countries",
        "LOW ANOMALY - Within normal lockout pattern"
    )
```

**What to look for:**

- **"First-ever lockout"** = This user has never been locked out before — highly suspicious
- **LockoutSpikeMultiplier > 10** = Lockout volume is 10x above their daily baseline — definite attack
- **NewSourceIPs / NewCountries** = Attack coming from infrastructure never seen for this user
- **NewUserAgents** containing automated tool signatures = confirms tooling, not user error
- **LOW ANOMALY** = User frequently locks themselves out (misconfigured device, cached wrong password) — may be FP

---

### Step 5: Post-Lockout Successful Authentication Detection

**Objective:** Determine if the attacker successfully authenticated after or during the lockout period — this is the most critical finding.

```kql
// Step 5: Post-Lockout Successful Authentication Detection
// Table: SigninLogs + AADNonInteractiveUserSignInLogs | Finds successful auth after lockout
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
// Get attacker IPs from lockout events
let AttackerIPs = SigninLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "50053"
    | distinct IPAddress;
// Check for successful auth from attacker IPs (interactive)
let InteractiveSuccess = SigninLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 72h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | where IPAddress in (AttackerIPs)
    | extend AuthType = "Interactive", Source = "SigninLogs";
// Check for successful auth from attacker IPs (non-interactive)
let NonInteractiveSuccess = AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 72h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | where IPAddress in (AttackerIPs)
    | extend AuthType = "Non-Interactive", Source = "AADNonInteractiveUserSignInLogs";
// Also check for MFA challenge from attacker IPs (password was correct)
let MFAChallenged = SigninLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 72h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType in ("50074", "50076", "50079")  // MFA required/prompted
    | where IPAddress in (AttackerIPs)
    | extend AuthType = "MFA-Challenged", Source = "SigninLogs";
union InteractiveSuccess, NonInteractiveSuccess, MFAChallenged
| extend ParsedLocation = parse_json(LocationDetails)
| project
    TimeGenerated,
    AuthType,
    Source,
    IPAddress,
    AutonomousSystemNumber,
    Country = tostring(ParsedLocation.countryOrRegion),
    City = tostring(ParsedLocation.city),
    UserAgent,
    ClientAppUsed,
    ResourceDisplayName,
    AppDisplayName,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    ResultType
| sort by TimeGenerated asc
```

**What to look for:**

- **ANY row in this result = HIGH PRIORITY finding:**
  - `AuthType = "Interactive"` + `ResultType = "0"` = **CONFIRMED COMPROMISE** — attacker successfully signed in
  - `AuthType = "MFA-Challenged"` = **PASSWORD COMPROMISED** — attacker knows the password; MFA is the only remaining defense
  - `AuthType = "Non-Interactive"` = **TOKEN ABUSE** — attacker may have obtained a token before lockout
- **TimeGenerated** relative to lockout: Success immediately before lockout = password found on early attempts; Success after lockout window = attacker waited and retried
- **ResourceDisplayName** = what the attacker accessed (Office 365, Azure Portal, etc.)

---

### Step 6: Coordinated Multi-Account Lockout Campaign

**Objective:** Determine if other accounts in the organization are being locked out from the same attacker infrastructure, indicating a coordinated spray/stuffing campaign.

```kql
// Step 6: Coordinated Multi-Account Lockout Campaign
// Table: SigninLogs | Finds other accounts targeted from same attack infrastructure
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
// Get attacker IP ranges (same /24 subnet) and ASNs
let AttackerASNs = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "50053"
    | distinct AutonomousSystemNumber;
let AttackerIPs = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "50053"
    | distinct IPAddress;
// Find all lockouts org-wide from the same infrastructure
SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where ResultType in ("50053", "50126")
| where IPAddress in (AttackerIPs) or AutonomousSystemNumber in (AttackerASNs)
| summarize
    LockoutCount = countif(ResultType == "50053"),
    FailureCount = countif(ResultType == "50126"),
    TotalAttempts = count(),
    TargetedAccounts = dcount(UserPrincipalName),
    AccountsList = make_set(UserPrincipalName, 100),
    SourceIPs = make_set(IPAddress, 50),
    Countries = make_set(tostring(parse_json(LocationDetails).countryOrRegion), 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AutonomousSystemNumber
| extend
    CampaignDuration = datetime_diff('minute', LastSeen, FirstSeen),
    CampaignScope = case(
        TargetedAccounts > 50, "CRITICAL - Large-scale campaign",
        TargetedAccounts > 10, "HIGH - Multi-target campaign",
        TargetedAccounts > 3, "MEDIUM - Targeted group",
        "LOW - Isolated attack"
    )
| sort by TargetedAccounts desc
```

**What to look for:**

- **TargetedAccounts > 10** = coordinated campaign, not an isolated attack
- **CampaignScope = "CRITICAL"** = large-scale password spray/credential stuffing across the organization
- **AccountsList** = check if targeted accounts share patterns (same department, VIPs, admins)
- **Multiple ASNs** involved = attacker using distributed infrastructure to evade detection
- **CampaignDuration** spanning hours = persistent, well-resourced adversary

---

### Step 7: Post-Compromise Activity Sweep

**Objective:** If any account was successfully compromised after lockout, check for immediate post-compromise actions (persistence, data access, lateral movement).

```kql
// Step 7: Post-Compromise Activity Sweep
// Table: AuditLogs + SigninLogs | Detects post-compromise persistence and data access
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
// Get attacker IPs
let AttackerIPs = SigninLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "50053"
    | distinct IPAddress;
// Check AuditLogs for post-compromise activity
let PersistenceActions = AuditLogs
    | where TimeGenerated between (AlertTime .. (AlertTime + 72h))
    | where InitiatedBy has InvestigationTarget
    | where OperationName in (
        "Update user", "Add member to role", "Add member to group",
        "Register security info", "Update security info",
        "Add application", "Add service principal credentials",
        "Consent to application", "Add OAuth2PermissionGrant",
        "Set inbox rule", "New-InboxRule",
        "Add app role assignment to service principal",
        "Add delegated permission grant"
    )
    | project
        TimeGenerated,
        ActivityType = "Persistence/Escalation",
        OperationName,
        TargetResource = tostring(TargetResources[0].displayName),
        ModifiedProperties = tostring(TargetResources[0].modifiedProperties),
        InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
    | extend FromAttackerIP = iff(InitiatedByIP in (AttackerIPs), true, false);
// Check for new sign-in locations/apps post-lockout
let NewAccess = SigninLogs
    | where TimeGenerated between (AlertTime .. (AlertTime + 72h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | extend ParsedLocation = parse_json(LocationDetails)
    | project
        TimeGenerated,
        ActivityType = "Resource Access",
        OperationName = strcat("Sign-in to ", ResourceDisplayName),
        TargetResource = AppDisplayName,
        ModifiedProperties = strcat("IP: ", IPAddress, " | Country: ",
            tostring(ParsedLocation.countryOrRegion)),
        InitiatedByIP = IPAddress
    | extend FromAttackerIP = iff(InitiatedByIP in (AttackerIPs), true, false);
union PersistenceActions, NewAccess
| sort by TimeGenerated asc
```

**What to look for:**

- **FromAttackerIP = true** on ANY audit action = **CONFIRMED COMPROMISE** with active attacker operations
- **"Register security info"** = attacker registering their own MFA method (see [RB-0012](suspicious-mfa-registration.md))
- **"Consent to application"** = attacker granting OAuth app permissions (see [RB-0011](consent-grant-attack.md))
- **"Add member to role"** = privilege escalation attempt (see [RB-0013](privileged-role-assignment.md))
- **"Set inbox rule"** = BEC-style email manipulation (see [RB-0008](../email/suspicious-inbox-forwarding-rule.md))
- **Timeline pattern:** lockout → successful auth → persistence → data access = complete attack chain

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to assess the source of lockout-triggering authentication failures. UEBA's `FailedLogOn` activity type tracking and geographic anomaly detection reveal whether the lockout source is an external attacker or a legitimate user with a forgotten password.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 4.

#### Query 8A: Lockout Source Anomaly Assessment

```kql
// ============================================================
// Query 8A: UEBA Anomaly Assessment for Smart Lockout
// Purpose: Assess whether the lockout-triggering failed logins
//          originate from anomalous locations/ISPs
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T02:30:00Z);
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
    // Volume anomaly
    UncommonHighVolume = tobool(ActivityInsights.UncommonHighVolumeOfOperations),
    // Source analysis
    FirstTimeISP = tobool(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommonAmongPeers = tobool(ActivityInsights.ISPUncommonlyUsedAmongPeers),
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommonForUser = tobool(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    // User context
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| order by InvestigationPriority desc, TimeGenerated desc
```

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| InvestigationPriority | >= 7 | < 4 |
| UncommonHighVolume | true — burst exceeds baseline | false |
| FirstTimeCountry | true — brute force from new country | false — user's location |
| ISPUncommonAmongPeers | true — attack from unusual ISP | false — known ISP |
| ThreatIndicator | Botnet, Proxy, Brute force tool | Empty |

**Decision guidance:**

- **UncommonHighVolume = true + FirstTimeCountry = true + ThreatIndicator populated** → External brute force from malicious infrastructure. Block IP and monitor for successful login
- **InvestigationPriority < 4 + user's normal ISP** → Likely legitimate lockout (forgotten password, application misconfiguration)
- **IsDormantAccount = true** → Brute force against dormant account is higher risk — may be targeted attack

---

## 6. Containment Playbook

### Immediate Actions (0-30 minutes)
- [ ] **Reset password** for the locked-out account immediately if any successful auth from attacker IPs detected
- [ ] **Revoke all active sessions** via `Revoke-AzureADUserAllRefreshToken` or Entra Portal
- [ ] **Block attacker IPs** in Conditional Access as Named Location → Block
- [ ] **Enable enhanced lockout** — reduce threshold for the affected account if attacks persist
- [ ] **Notify the user** via out-of-band channel (phone call, not email) to confirm they did not generate the lockouts

### Short-term Actions (30 min - 4 hours)
- [ ] **Review and enforce MFA** for all compromised/targeted accounts
- [ ] **Check for password reuse** — query `AADUserRiskEvents` for `leakedCredentials` risk events
- [ ] **Block legacy authentication** via Conditional Access if attacker used `Other clients`, `IMAP`, or `SMTP`
- [ ] **Review Conditional Access policies** to ensure geo-blocking or risk-based policies cover the attack source

### Recovery Actions (4-24 hours)
- [ ] If multi-account campaign: force password reset for ALL targeted accounts
- [ ] Review all MFA method changes made during the attack window
- [ ] Audit service principal credentials if attacker gained access
- [ ] Implement IP-based Conditional Access restrictions for high-value accounts

---

## 7. Evidence Collection Checklist

| Evidence Item | Source Table | Retention | Collection Query |
|---|---|---|---|
| All lockout events (ResultType 50053) | SigninLogs | 30 days | Step 1 query |
| Attacker IP infrastructure details | SigninLogs | 30 days | Step 2 query |
| Pre-lockout failure patterns | SigninLogs | 30 days | Step 3 query |
| Post-lockout successful authentications | SigninLogs + NonInteractive | 30 days | Step 5 query |
| Multi-account lockout campaign scope | SigninLogs | 30 days | Step 6 query |
| Post-compromise audit trail | AuditLogs | 30 days | Step 7 query |
| Identity Protection risk events | AADUserRiskEvents | 90 days | Risk correlation |
| Conditional Access evaluation logs | SigninLogs.ConditionalAccessPolicies | 30 days | CA policy analysis |

---

## 8. Escalation Criteria

| Condition | Action |
|---|---|
| Successful auth from attacker IP detected (Step 5) | Escalate to **P1 Incident** — confirmed compromise |
| Multi-account campaign targeting >10 accounts (Step 6) | Escalate to **P1 Incident** — organizational attack |
| Executive/admin account locked out | Escalate to **P2 Incident** — high-value target |
| Post-compromise persistence detected (Step 7) | Escalate to **P1 Incident** — active attacker in environment |
| Lockout from intranet/trusted IP | Escalate to **P2 Incident** — potential on-prem compromise |
| Attacker bypassed MFA after lockout | Escalate to **P1 Incident** + involve Identity team |

---

## 9. False Positive Documentation

| Scenario | How to Identify | Recommended Action |
|---|---|---|
| User forgot password | Single IP, user's known location, business hours | Confirm with user, close alert |
| Cached wrong password on device | Repeated failures from same device, same UserAgent | Help user update cached credentials |
| Password sync delay (hybrid) | On-prem password change not yet synced to Entra | Verify AD Connect sync status |
| Automated script with old creds | Service account, consistent UserAgent, known app | Update application credentials |
| VPN IP rotation matching lockout | Corporate VPN IP, known ASN | Whitelist VPN IP ranges in Smart Lockout |

---

## 10. MITRE ATT&CK Mapping

| Technique ID | Technique Name | How It Applies | Detection Query |
|---|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Direct password brute force triggering lockout | Steps 1, 3 |
| T1110.003 | Brute Force: Password Spraying | Multi-account spray from same infrastructure | Step 6 |
| T1110.004 | Brute Force: Credential Stuffing | Using breached credential databases against accounts | Step 3 (multi-UA pattern) |
| T1078.004 | Valid Accounts: Cloud Accounts | Successful authentication using brute-forced credentials | Step 5 |

---

## 11. Query Summary

| Step | Query | Purpose | Primary Table |
|---|---|---|---|
| 1 | Smart Lockout Event Analysis | Quantify lockouts and identify attacker IPs | SigninLogs |
| 2 | Attack Source Infrastructure Profiling | Determine if IPs are hosting/VPS/Tor | SigninLogs |
| 3 | Pre-Lockout Failure Pattern | Differentiate brute force vs stuffing vs spray | SigninLogs |
| 4 | Baseline Comparison | Compare lockout volume against 30d history | SigninLogs |
| 5 | Post-Lockout Success Detection | Find successful auth from attacker IPs | SigninLogs + NonInteractive |
| 6 | Multi-Account Campaign | Detect coordinated lockout across org | SigninLogs |
| 7 | Post-Compromise Sweep | Find persistence and data access after breach | AuditLogs + SigninLogs |

---

## Appendix A: Datatable Tests

### Test 1: Smart Lockout Event Detection

```kql
// TEST 1: Verifies lockout event detection and attacker IP identification
let TestSigninLogs = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, ResultType: string,
    IPAddress: string, AutonomousSystemNumber: int, UserAgent: string,
    ClientAppUsed: string, ResourceDisplayName: string,
    LocationDetails: dynamic, ConditionalAccessStatus: string,
    RiskLevelDuringSignIn: string
)[
    datetime(2026-02-22T14:00:00Z), "alice@contoso.com", "50126", "198.51.100.50", 14061,
        "python-requests/2.28", "Browser", "Microsoft 365",
        dynamic({"city":"Amsterdam","state":"NH","countryOrRegion":"NL","geoCoordinates":{"latitude":52.37,"longitude":4.89}}),
        "notApplied", "none",
    datetime(2026-02-22T14:01:00Z), "alice@contoso.com", "50126", "198.51.100.50", 14061,
        "python-requests/2.28", "Browser", "Microsoft 365",
        dynamic({"city":"Amsterdam","state":"NH","countryOrRegion":"NL","geoCoordinates":{"latitude":52.37,"longitude":4.89}}),
        "notApplied", "none",
    datetime(2026-02-22T14:02:00Z), "alice@contoso.com", "50053", "198.51.100.50", 14061,
        "python-requests/2.28", "Browser", "Microsoft 365",
        dynamic({"city":"Amsterdam","state":"NH","countryOrRegion":"NL","geoCoordinates":{"latitude":52.37,"longitude":4.89}}),
        "notApplied", "none",
    datetime(2026-02-22T14:03:00Z), "alice@contoso.com", "50053", "198.51.100.51", 14061,
        "python-requests/2.28", "Browser", "Microsoft 365",
        dynamic({"city":"Amsterdam","state":"NH","countryOrRegion":"NL","geoCoordinates":{"latitude":52.37,"longitude":4.89}}),
        "notApplied", "none",
    datetime(2026-02-22T14:30:00Z), "alice@contoso.com", "50053", "198.51.100.52", 14061,
        "python-requests/2.28", "Browser", "Microsoft 365",
        dynamic({"city":"Amsterdam","state":"NH","countryOrRegion":"NL","geoCoordinates":{"latitude":52.37,"longitude":4.89}}),
        "notApplied", "none"
];
TestSigninLogs
| where ResultType == "50053"
| extend ParsedLocation = parse_json(LocationDetails)
| summarize
    LockoutCount = count(),
    DistinctIPs = dcount(IPAddress),
    SourceIPs = make_set(IPAddress, 50),
    Countries = make_set(tostring(ParsedLocation.countryOrRegion), 10)
| where LockoutCount >= 3 and DistinctIPs >= 2
// EXPECTED: 1 row — 3 lockout events from 3 different DigitalOcean IPs in Netherlands
```

### Test 2: Hosting Provider IP Detection

```kql
// TEST 2: Verifies hosting/VPS IP classification from ASN data
let KnownHostingASNs = dynamic([14061, 16509, 15169, 8075, 13335, 24940, 16276, 63949, 20473]);
let TestSigninLogs = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, ResultType: string,
    IPAddress: string, AutonomousSystemNumber: int, UserAgent: string,
    LocationDetails: dynamic
)[
    // DigitalOcean - hosting provider
    datetime(2026-02-22T14:00:00Z), "alice@contoso.com", "50053", "198.51.100.50", 14061,
        "python-requests/2.28", dynamic({"countryOrRegion":"NL"}),
    // AWS - hosting provider
    datetime(2026-02-22T14:01:00Z), "alice@contoso.com", "50053", "203.0.113.10", 16509,
        "Go-http-client/1.1", dynamic({"countryOrRegion":"US"}),
    // Comcast - residential ISP (legitimate)
    datetime(2026-02-22T14:02:00Z), "bob@contoso.com", "50053", "192.0.2.100", 7922,
        "Mozilla/5.0", dynamic({"countryOrRegion":"US"}),
    // Hetzner - hosting provider
    datetime(2026-02-22T14:03:00Z), "charlie@contoso.com", "50053", "203.0.113.20", 24940,
        "curl/7.84", dynamic({"countryOrRegion":"DE"})
];
TestSigninLogs
| extend IsHostingProvider = AutonomousSystemNumber in (KnownHostingASNs)
| summarize
    HostingProviderHits = countif(IsHostingProvider),
    ResidentialHits = countif(not(IsHostingProvider)),
    HostingIPs = make_set_if(IPAddress, IsHostingProvider)
| where HostingProviderHits == 3 and ResidentialHits == 1
// EXPECTED: 1 row — 3 hosting IPs (DigitalOcean, AWS, Hetzner), 1 residential (Comcast)
```

### Test 3: Post-Lockout Success Detection

```kql
// TEST 3: Verifies detection of successful auth from attacker IP after lockout
let TestSigninLogs = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, ResultType: string,
    IPAddress: string, AutonomousSystemNumber: int, UserAgent: string,
    ResourceDisplayName: string, AppDisplayName: string,
    LocationDetails: dynamic
)[
    // Lockout events from attacker IP
    datetime(2026-02-22T14:00:00Z), "alice@contoso.com", "50053", "198.51.100.50", 14061,
        "python-requests/2.28", "Microsoft 365", "Office 365",
        dynamic({"countryOrRegion":"NL"}),
    datetime(2026-02-22T14:05:00Z), "alice@contoso.com", "50053", "198.51.100.50", 14061,
        "python-requests/2.28", "Microsoft 365", "Office 365",
        dynamic({"countryOrRegion":"NL"}),
    // Successful auth from attacker IP 2 hours later (lockout expired)
    datetime(2026-02-22T16:00:00Z), "alice@contoso.com", "0", "198.51.100.50", 14061,
        "Mozilla/5.0 (Windows NT 10.0)", "Microsoft 365", "Outlook",
        dynamic({"countryOrRegion":"NL"}),
    // Legitimate user login from different IP
    datetime(2026-02-22T15:00:00Z), "alice@contoso.com", "0", "10.0.0.100", 0,
        "Mozilla/5.0 (Windows NT 10.0)", "Microsoft 365", "Outlook",
        dynamic({"countryOrRegion":"US"})
];
let AttackerIPs = TestSigninLogs
    | where ResultType == "50053"
    | distinct IPAddress;
TestSigninLogs
| where ResultType == "0"
| where IPAddress in (AttackerIPs)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResourceDisplayName
| where UserPrincipalName == "alice@contoso.com" and IPAddress == "198.51.100.50"
// EXPECTED: 1 row — successful auth from attacker IP 198.51.100.50 at 16:00
```

### Test 4: Multi-Account Campaign Detection

```kql
// TEST 4: Verifies detection of coordinated lockout campaign across multiple accounts
let TestSigninLogs = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, ResultType: string,
    IPAddress: string, AutonomousSystemNumber: int,
    LocationDetails: dynamic
)[
    // Same ASN targeting multiple accounts
    datetime(2026-02-22T14:00:00Z), "alice@contoso.com", "50053", "198.51.100.50", 14061,
        dynamic({"countryOrRegion":"NL"}),
    datetime(2026-02-22T14:01:00Z), "bob@contoso.com", "50053", "198.51.100.51", 14061,
        dynamic({"countryOrRegion":"NL"}),
    datetime(2026-02-22T14:02:00Z), "charlie@contoso.com", "50053", "198.51.100.52", 14061,
        dynamic({"countryOrRegion":"NL"}),
    datetime(2026-02-22T14:03:00Z), "dave@contoso.com", "50126", "198.51.100.50", 14061,
        dynamic({"countryOrRegion":"NL"}),
    datetime(2026-02-22T14:04:00Z), "eve@contoso.com", "50053", "198.51.100.53", 14061,
        dynamic({"countryOrRegion":"NL"}),
    // Different ASN - isolated attack
    datetime(2026-02-22T14:05:00Z), "frank@contoso.com", "50053", "203.0.113.10", 7922,
        dynamic({"countryOrRegion":"US"})
];
TestSigninLogs
| where ResultType in ("50053", "50126")
| summarize
    TargetedAccounts = dcount(UserPrincipalName),
    LockoutCount = countif(ResultType == "50053"),
    FailureCount = countif(ResultType == "50126"),
    AccountsList = make_set(UserPrincipalName, 100)
    by AutonomousSystemNumber
| where TargetedAccounts >= 3
// EXPECTED: 1 row — ASN 14061 targeting 5 accounts (alice, bob, charlie, dave, eve)
```

---

## References

- [Azure AD Smart Lockout - Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [Protect against smart lockout attacks - Microsoft Security](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-smart-lockout)
- [ResultType error codes for sign-in logs](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Midnight Blizzard password spray on Microsoft](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [Peach Sandstorm sustained password spray campaigns](https://www.microsoft.com/en-us/security/blog/2023/09/14/peach-sandstorm-password-spray-campaigns-enable-intelligence-collection-at-high-value-targets/)
