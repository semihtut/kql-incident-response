---
title: "Azure AD Connect Sync Account Abuse"
id: RB-0025
severity: critical
status: reviewed
description: >
  Investigation runbook for detecting abuse of Azure AD Connect synchronization
  accounts that bridge on-premise Active Directory and Entra ID (Azure AD).
  Covers sync account sign-in anomaly detection from unexpected IPs, sync cycle
  timing deviation analysis, unauthorized directory operations performed by the
  sync account, sync infrastructure change detection (new AAD Connect agents,
  PTA agent registration/deregistration), Pass-through Authentication agent
  health monitoring, organization-wide hybrid identity sweep, and UEBA
  behavioral enrichment. The sync account (Sync_SERVERNAME_GUID@tenant.onmicrosoft.com)
  is one of the most privileged identities in any hybrid environment — if
  compromised, an attacker can synchronize malicious changes from on-premises
  AD to the cloud, create backdoor accounts, modify existing users, or abuse
  Pass-through Authentication to intercept credentials in real time.
mitre_attack:
  tactics:
    - tactic_id: TA0003
      tactic_name: "Persistence"
    - tactic_id: TA0004
      tactic_name: "Privilege Escalation"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
    - tactic_id: TA0006
      tactic_name: "Credential Access"
    - tactic_id: TA0008
      tactic_name: "Lateral Movement"
  techniques:
    - technique_id: T1078.002
      technique_name: "Valid Accounts: Domain Accounts"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1550
      technique_name: "Use Alternate Authentication Material"
      confidence: confirmed
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: probable
    - technique_id: T1136.003
      technique_name: "Create Account: Cloud Account"
      confidence: probable
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Storm-0501"
  - "Scattered Spider (Octo Tempest)"
  - "LAPSUS$"
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
  - table: "AADProvisioningLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: false
    alternatives: []
  - table: "IdentityDirectoryEvents"
    product: "Microsoft Defender for Identity"
    license: "Microsoft 365 E5 / Defender for Identity"
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
  - query: "SigninLogs | where UserPrincipalName startswith 'Sync_' | take 1"
    label: primary
    description: "Sync account sign-in detection"
  - query: "AuditLogs | take 1"
    description: "Directory operations by sync account"
  - query: "AADNonInteractiveUserSignInLogs | where UserPrincipalName startswith 'Sync_' | take 1"
    description: "Non-interactive sync account authentication"
---

# Azure AD Connect Sync Account Abuse - Investigation Runbook

> **RB-0025** | Severity: Critical | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** SigninLogs + AADNonInteractiveUserSignInLogs + AuditLogs Analysis
> **Detection Logic:** Sync account activity from unauthorized IPs, off-schedule timing, or performing operations outside normal sync scope
> **Primary MITRE Technique:** T1078.002 - Valid Accounts: Domain Accounts

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Sync Account Sign-In Anomaly Detection](#step-1-sync-account-sign-in-anomaly-detection)
   - [Step 2: Sync Cycle Timing Analysis](#step-2-sync-cycle-timing-analysis)
   - [Step 3: Sync Account Directory Operations Audit](#step-3-sync-account-directory-operations-audit)
   - [Step 4: Baseline Comparison - Establish Normal Sync Pattern](#step-4-baseline-comparison---establish-normal-sync-pattern)
   - [Step 5: Sync Infrastructure Change Detection](#step-5-sync-infrastructure-change-detection)
   - [Step 6: Pass-through Authentication Agent Health](#step-6-pass-through-authentication-agent-health)
   - [Step 7: Organization-Wide Hybrid Identity Sweep](#step-7-organization-wide-hybrid-identity-sweep)
   - [Step 8: UEBA Enrichment - Behavioral Context Analysis](#step-8-ueba-enrichment---behavioral-context-analysis)
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
This detection fires when the Azure AD Connect synchronization account exhibits behavior inconsistent with its expected operational profile. The sync account is the highest-privilege hybrid identity in any Microsoft tenant and has a very narrow, predictable behavior pattern. Detection sources include:

1. **SigninLogs + AADNonInteractiveUserSignInLogs IP anomaly:** The sync account (`Sync_SERVERNAME_GUID@tenant.onmicrosoft.com`) signs in from an IP address that is NOT the known AAD Connect server. The sync account should ONLY ever authenticate from a single server IP. Any other IP is immediately suspicious.
2. **Sync cycle timing deviation:** Normal Azure AD Connect delta sync runs every 30 minutes on a consistent cadence. Off-schedule sign-ins, burst activity, extended gaps followed by unusual activity, or activity during maintenance windows all indicate potential abuse.
3. **AuditLogs unauthorized operations:** The sync account performing operations outside the normal synchronization scope — role assignments, Conditional Access policy changes, application consent grants, or operations targeting objects not in the sync scope.
4. **Infrastructure change events:** New AAD Connect connector registration, PTA agent registration/deregistration, sync account password changes, or sync account permission modifications indicate an attacker deploying their own sync infrastructure or hijacking the existing one.

**What is the sync account and why it matters:**
Azure AD Connect uses a dedicated service account to synchronize identity data between on-premises Active Directory and Entra ID (Azure AD). This account:

- Has the naming convention `Sync_SERVERNAME_GUID@tenant.onmicrosoft.com` (auto-generated during setup)
- Holds the **Directory Synchronization Accounts** role, which grants broad read/write access to directory objects
- Can create, modify, and delete cloud users and groups as part of normal synchronization
- Can reset passwords for synced accounts (Password Hash Sync and Password Writeback scenarios)
- Authenticates exclusively from the AAD Connect server — it should never sign in from any other source
- Operates on a predictable 30-minute delta sync cycle

**Why this is CRITICAL severity:**
- The sync account bridges on-premises AD and cloud — compromising it gives an attacker control over both domains simultaneously
- An attacker with sync account access can **create backdoor cloud accounts** that appear to be synced from on-premises
- The sync account can **modify any synced user's attributes**, including security-relevant properties like `proxyAddresses` or `manager`
- In Password Hash Sync (PHS) environments, the sync account transmits password hashes — interception enables offline cracking
- In Pass-through Authentication (PTA) environments, compromising the PTA agent allows **real-time credential interception** for every authentication that flows through it
- Midnight Blizzard (APT29) and Storm-0501 have specifically targeted AAD Connect infrastructure as a pivot between on-premises and cloud environments
- Scattered Spider has deployed rogue AAD Connect instances to establish persistent sync from attacker-controlled on-premises infrastructure

**Attack scenarios this runbook detects:**

| Scenario | Mechanism | Impact |
|---|---|---|
| **Sync account credential theft** | Attacker extracts sync account credentials from AAD Connect server (DPAPI, SQL database, memory dump) | Full directory write access from attacker infrastructure |
| **Rogue AAD Connect deployment** | Attacker installs their own AAD Connect instance, registers new sync connector | Persistent sync from attacker-controlled environment |
| **PTA agent hijacking** | Attacker registers a malicious PTA agent or compromises existing one | Real-time credential interception for all PTA-authenticated users |
| **Sync account permission escalation** | Attacker elevates sync account beyond Directory Synchronization Accounts role | Broader tenant access than intended |
| **On-premises AD compromise pivoting to cloud** | Attacker compromises on-prem AD, uses existing AAD Connect to sync malicious changes to cloud | Backdoor accounts, privilege escalation in cloud |

---

## 2. Prerequisites

{{ data_check_timeline(page.meta.data_checks) }}

---

## 3. Input Parameters

Set these values before running the investigation queries:

```kql
// === INVESTIGATION PARAMETERS ===
let SyncAccountPattern = "Sync_";                          // Prefix for sync account UPN
let AADConnectServerIPs = dynamic(["10.0.1.50"]);          // Known AAD Connect server IP(s)
let AlertTime = datetime(2026-02-22T14:30:00Z);            // Time of anomaly detection
let LookbackWindow = 24h;                                  // Initial analysis window
let BaselineWindow = 14d;                                  // Historical baseline period
let TenantDomain = "contoso.onmicrosoft.com";              // Tenant domain for sync account matching
```

---

## 4. Quick Triage Criteria

Use this decision matrix for initial severity assessment:

| Indicator | True Positive Signal | False Positive Signal |
|---|---|---|
| Sign-in IP | IP is NOT the AAD Connect server IP | IP matches known AAD Connect server(s) |
| Timing pattern | Activity outside 30-min sync cadence, random intervals | Consistent 30-minute delta sync pattern |
| Operations performed | Role assignments, CA policy changes, application consent | User/group create/update (normal sync operations) |
| New sync infrastructure | New connector/agent registration from unknown server | Planned AAD Connect migration or upgrade |
| Credential changes | Sync account password changed by non-admin | Planned credential rotation by identity team |
| Multiple sync accounts | New Sync_* account appeared unexpectedly | Planned new AAD Connect staging server |

---

## 5. Investigation Steps

### Step 1: Sync Account Sign-In Anomaly Detection

**Objective:** Detect sign-ins to any sync account (`Sync_*@*.onmicrosoft.com`) from IP addresses other than the authorized AAD Connect server. The sync account should ONLY authenticate from the AAD Connect server IP. Any other source IP is an immediate high-confidence indicator of credential compromise or rogue sync infrastructure deployment.

```kql
// Step 1: Sync Account Sign-In Anomaly Detection
// Table: SigninLogs + AADNonInteractiveUserSignInLogs | Detects sync account from unexpected IPs
let SyncAccountPattern = "Sync_";
let AADConnectServerIPs = dynamic(["10.0.1.50"]);
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
// Combine interactive and non-interactive sign-ins for sync accounts
let AllSyncSignIns = union
    (SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName startswith SyncAccountPattern
    | where ResultType == "0"
    | extend SignInType = "Interactive"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName startswith SyncAccountPattern
    | where ResultType == "0"
    | extend SignInType = "NonInteractive");
AllSyncSignIns
| extend
    ParsedLocation = parse_json(LocationDetails),
    ParsedDevice = parse_json(DeviceDetail)
| extend
    Country = tostring(ParsedLocation.countryOrRegion),
    City = tostring(ParsedLocation.city),
    DeviceOS = tostring(ParsedDevice.operatingSystem),
    Browser = tostring(ParsedDevice.browser),
    IsKnownServer = IPAddress in (AADConnectServerIPs)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AutonomousSystemNumber,
    Country,
    City,
    DeviceOS,
    Browser,
    UserAgent,
    AppDisplayName,
    ResourceDisplayName,
    SignInType,
    IsKnownServer,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    SessionId,
    CorrelationId
| extend
    IPVerdict = case(
        IsKnownServer, "EXPECTED - Known AAD Connect server IP",
        IPAddress startswith "10." or IPAddress startswith "172." or IPAddress startswith "192.168.",
            "SUSPICIOUS - Private IP but not the known AAD Connect server",
        "CRITICAL - Public IP / Unknown source — potential credential compromise"
    )
| summarize
    TotalSignIns = count(),
    KnownServerSignIns = countif(IsKnownServer),
    UnknownIPSignIns = countif(not(IsKnownServer)),
    UnknownIPs = make_set_if(IPAddress, not(IsKnownServer), 20),
    UnknownCountries = make_set_if(Country, not(IsKnownServer), 10),
    UnknownCities = make_set_if(City, not(IsKnownServer), 10),
    Apps = make_set(AppDisplayName, 20),
    Resources = make_set(ResourceDisplayName, 20),
    SignInTypes = make_set(SignInType),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName
| extend
    AnomalyVerdict = case(
        UnknownIPSignIns > 0 and array_length(UnknownCountries) > 0,
            "CRITICAL - Sync account used from unauthorized IP(s)",
        UnknownIPSignIns > 0,
            "HIGH - Sync account used from unrecognized IP (check if new server)",
        KnownServerSignIns > 0 and UnknownIPSignIns == 0,
            "NORMAL - All sign-ins from known AAD Connect server",
        "INFO - No successful sync account sign-ins in window"
    )
| sort by UnknownIPSignIns desc
```

**What to look for:**

- **"CRITICAL - Sync account used from unauthorized IP(s)"** = Sync account authenticating from an IP that is NOT the AAD Connect server. This is the strongest single indicator of sync account compromise. Proceed immediately to containment.
- **UnknownIPs containing public IP addresses** = Sync account credentials being used from the internet — attacker has extracted the credentials and is authenticating remotely
- **UnknownCountries not empty** = Sync account appearing from a foreign country — near-certain credential theft
- **Apps containing unexpected applications** = Sync account being used with tools other than Azure AD Connect (e.g., "Microsoft Graph PowerShell", "Azure Portal") — attacker interacting manually
- **SignInTypes containing "Interactive"** = Sync accounts should NEVER have interactive sign-ins — this indicates manual human login with the sync credentials
- **Multiple UserPrincipalName entries** = More than one sync account exists — verify if the second one is a rogue deployment (see Step 5)

---

### Step 2: Sync Cycle Timing Analysis

**Objective:** Analyze the sync account's sign-in timing pattern. Azure AD Connect delta sync runs every 30 minutes by default, producing a predictable cadence. Off-schedule sign-ins, burst activity, or activity during unusual hours may indicate attacker-controlled usage rather than the legitimate sync engine.

```kql
// Step 2: Sync Cycle Timing Analysis
// Table: AADNonInteractiveUserSignInLogs | Analyzes sync account timing pattern
let SyncAccountPattern = "Sync_";
let AADConnectServerIPs = dynamic(["10.0.1.50"]);
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
// Get all sync account sign-ins and compute time deltas
let SyncSignIns = AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName startswith SyncAccountPattern
    | where ResultType == "0"
    | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResourceDisplayName
    | sort by UserPrincipalName asc, TimeGenerated asc;
// Compute time delta between consecutive sign-ins per sync account
SyncSignIns
| serialize
| extend PrevTime = prev(TimeGenerated, 1), PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend
    TimeDeltaMinutes = round(datetime_diff('second', TimeGenerated, PrevTime) / 60.0, 1),
    HourOfDay = hourofday(TimeGenerated),
    DayOfWeek = dayofweek(TimeGenerated) / 1d,
    IsKnownServer = IPAddress in (AADConnectServerIPs)
| extend
    TimingVerdict = case(
        TimeDeltaMinutes between (28.0 .. 32.0),
            "NORMAL - Standard 30-minute delta sync cycle",
        TimeDeltaMinutes between (25.0 .. 35.0),
            "NORMAL - Minor timing variance (expected jitter)",
        TimeDeltaMinutes < 5.0,
            "SUSPICIOUS - Burst activity (< 5 min between sign-ins)",
        TimeDeltaMinutes between (5.0 .. 25.0),
            "SUSPICIOUS - Off-cycle activity (not aligned with 30-min cadence)",
        TimeDeltaMinutes > 60.0 and TimeDeltaMinutes < 120.0,
            "INFO - Missed one sync cycle (possible server restart)",
        TimeDeltaMinutes >= 120.0,
            "SUSPICIOUS - Extended gap (> 2 hours) — server down or sync disabled?",
        "UNKNOWN"
    )
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    IsKnownServer,
    TimeDeltaMinutes,
    HourOfDay,
    DayOfWeek,
    TimingVerdict,
    AppDisplayName,
    ResourceDisplayName
| summarize
    TotalSignIns = count(),
    NormalCycles = countif(TimingVerdict has "NORMAL"),
    SuspiciousCycles = countif(TimingVerdict has "SUSPICIOUS"),
    BurstEvents = countif(TimeDeltaMinutes < 5.0),
    OffCycleEvents = countif(TimeDeltaMinutes between (5.0 .. 25.0)),
    ExtendedGaps = countif(TimeDeltaMinutes >= 120.0),
    AvgDeltaMinutes = round(avg(TimeDeltaMinutes), 1),
    MinDeltaMinutes = round(min(TimeDeltaMinutes), 1),
    MaxDeltaMinutes = round(max(TimeDeltaMinutes), 1),
    UnauthorizedIPEvents = countif(not(IsKnownServer)),
    ActiveHours = make_set(HourOfDay, 24)
    by UserPrincipalName
| extend
    OverallTimingAssessment = case(
        BurstEvents > 3 and UnauthorizedIPEvents > 0,
            "CRITICAL - Burst activity from unauthorized IP (attacker-controlled sync)",
        BurstEvents > 5,
            "HIGH - Excessive burst activity (automated tool, not normal sync engine)",
        OffCycleEvents > 3,
            "HIGH - Multiple off-cycle events (sync pattern disrupted)",
        SuspiciousCycles > NormalCycles,
            "HIGH - More suspicious than normal timing events",
        SuspiciousCycles > 0 and UnauthorizedIPEvents > 0,
            "HIGH - Off-cycle activity from unauthorized IP",
        ExtendedGaps > 0 and BurstEvents > 0,
            "MEDIUM - Gap followed by burst (possible service recovery or attack start)",
        SuspiciousCycles > 0,
            "MEDIUM - Some timing anomalies detected",
        "NORMAL - Consistent 30-minute sync cadence"
    )
```

**What to look for:**

- **"CRITICAL - Burst activity from unauthorized IP"** = Rapid-fire sign-ins from an IP that is NOT the AAD Connect server — attacker programmatically using the sync credentials
- **BurstEvents > 3** = Multiple sign-ins within 5 minutes — normal sync produces exactly one sign-in per 30-minute cycle. Burst activity indicates manual or scripted usage
- **OffCycleEvents > 3** = Sign-ins occurring between sync cycles — the sync engine does NOT produce random sign-ins. Off-cycle activity suggests human or tool-based usage
- **ExtendedGaps followed by BurstEvents** = Sync stopped (server shutdown or attacker disabling sync) then burst of activity (attacker using extracted credentials)
- **AvgDeltaMinutes significantly deviating from 30** = Aggregate timing not matching expected cadence
- **"NORMAL"** = Consistent 30-minute pattern from known server — legitimate sync operation

---

### Step 3: Sync Account Directory Operations Audit

**Objective:** Review ALL operations performed by the sync account in AuditLogs. Normal sync operations include user/group creation, updates, and membership changes. Suspicious operations include role assignments, Conditional Access policy modifications, application consent grants, or any operation outside the typical synchronization scope.

```kql
// Step 3: Sync Account Directory Operations Audit
// Table: AuditLogs | Reviews all operations initiated by the sync account
let SyncAccountPattern = "Sync_";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
// Normal sync operations — these are expected
let NormalSyncOperations = dynamic([
    "Add user", "Update user", "Delete user",
    "Add group", "Update group", "Delete group",
    "Add member to group", "Remove member from group",
    "Add group member", "Remove group member",
    "Add contact", "Update contact", "Delete contact",
    "Change user password", "Reset user password"
]);
AuditLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where InitiatedBy has SyncAccountPattern
| extend
    InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
    InitiatorIP = tostring(InitiatedBy.user.ipAddress),
    InitiatorApp = tostring(InitiatedBy.app.displayName)
| where InitiatorUPN startswith SyncAccountPattern
    or InitiatorApp has "Azure AD Connect"
    or InitiatorApp has "Microsoft Azure AD Sync"
| extend
    TargetResource = tostring(TargetResources[0].displayName),
    TargetResourceType = tostring(TargetResources[0].type),
    TargetResourceId = tostring(TargetResources[0].id),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    IsNormalOperation = OperationName in (NormalSyncOperations),
    OperationCategory = case(
        OperationName in (NormalSyncOperations), "NORMAL_SYNC",
        OperationName has_any ("role", "Role"), "ROLE_ASSIGNMENT",
        OperationName has_any ("Conditional Access", "conditional access", "policy"),
            "CA_POLICY_CHANGE",
        OperationName has_any ("Consent", "OAuth", "permission", "grant"),
            "APP_CONSENT",
        OperationName has_any ("service principal", "application"),
            "APP_MODIFICATION",
        OperationName has_any ("device", "Device"), "DEVICE_OPERATION",
        OperationName has_any ("domain", "Domain"), "DOMAIN_CHANGE",
        OperationName has_any ("credential", "secret", "certificate"),
            "CREDENTIAL_CHANGE",
        "OTHER_OPERATION"
    )
| summarize
    TotalOperations = count(),
    NormalSyncOps = countif(IsNormalOperation),
    AbnormalOps = countif(not(IsNormalOperation)),
    OperationTypes = make_set(OperationCategory),
    AbnormalOperations = make_set_if(OperationName, not(IsNormalOperation), 30),
    NormalOperations = make_set_if(OperationName, IsNormalOperation, 30),
    TargetResources = make_set_if(TargetResource, not(IsNormalOperation), 30),
    SourceIPs = make_set(InitiatorIP, 10),
    FirstOp = min(TimeGenerated),
    LastOp = max(TimeGenerated)
    by InitiatorUPN
| extend
    OperationVerdict = case(
        set_has_element(OperationTypes, "ROLE_ASSIGNMENT"),
            "CRITICAL - Sync account performing role assignments (NEVER normal)",
        set_has_element(OperationTypes, "CA_POLICY_CHANGE"),
            "CRITICAL - Sync account modifying Conditional Access policies",
        set_has_element(OperationTypes, "APP_CONSENT"),
            "CRITICAL - Sync account granting application consent",
        set_has_element(OperationTypes, "DOMAIN_CHANGE"),
            "CRITICAL - Sync account modifying domain configuration",
        set_has_element(OperationTypes, "CREDENTIAL_CHANGE"),
            "HIGH - Sync account modifying credentials",
        set_has_element(OperationTypes, "APP_MODIFICATION"),
            "HIGH - Sync account modifying applications/service principals",
        AbnormalOps > 0,
            "MEDIUM - Sync account performing non-standard operations",
        NormalSyncOps > 0 and AbnormalOps == 0,
            "NORMAL - Only standard sync operations detected",
        "INFO - No operations found"
    ),
    AbnormalRatio = iff(TotalOperations > 0,
        round(toreal(AbnormalOps) / TotalOperations * 100, 1), 0.0)
| sort by AbnormalOps desc
```

**What to look for:**

- **"CRITICAL - Sync account performing role assignments"** = The sync account should NEVER assign directory roles. This is a definitive indicator of abuse — an attacker using sync credentials to escalate privileges.
- **"CRITICAL - Sync account modifying Conditional Access policies"** = Sync account has no legitimate reason to touch CA policies — attacker weakening security controls.
- **"CRITICAL - Sync account granting application consent"** = Attacker using sync account's broad permissions to consent to malicious OAuth applications.
- **AbnormalRatio > 10%** = More than 10% of operations are non-standard — sync is predominantly predictable CRUD on users and groups.
- **TargetResources containing admin accounts or privileged groups** = Attacker modifying high-value targets via the sync account.
- **SourceIPs not matching AAD Connect server** = Operations performed from unauthorized infrastructure — correlate with Step 1.

---

### Step 4: Baseline Comparison - Establish Normal Sync Pattern

**Objective:** Compare the sync account's current activity against its 14-day historical baseline. Sync accounts are among the most predictable identities in any tenant — the same IP, the same operations, the same timing, every day. Any deviation is highly significant. This is the mandatory baseline step per project quality standards.

```kql
// Step 4: Baseline Comparison - Establish Normal Sync Pattern
// Table: SigninLogs + AADNonInteractiveUserSignInLogs + AuditLogs | 14-day baseline comparison
let SyncAccountPattern = "Sync_";
let AADConnectServerIPs = dynamic(["10.0.1.50"]);
let AlertTime = datetime(2026-02-22T14:30:00Z);
let BaselineWindow = 14d;
let CurrentWindow = 24h;
// Historical baseline (14 days before current window)
let HistoricalSignIns = union
    (SigninLogs
    | where TimeGenerated between ((AlertTime - BaselineWindow) .. (AlertTime - CurrentWindow))
    | where UserPrincipalName startswith SyncAccountPattern
    | where ResultType == "0"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - BaselineWindow) .. (AlertTime - CurrentWindow))
    | where UserPrincipalName startswith SyncAccountPattern
    | where ResultType == "0")
| summarize
    BaselineIPs = make_set(IPAddress, 20),
    BaselineCountries = make_set(tostring(parse_json(LocationDetails).countryOrRegion), 10),
    BaselineApps = make_set(AppDisplayName, 20),
    BaselineResources = make_set(ResourceDisplayName, 20),
    BaselineASNs = make_set(AutonomousSystemNumber, 20),
    BaselineDailySignIns = dcount(bin(TimeGenerated, 1d)),
    BaselineTotalSignIns = count(),
    BaselineAvgDailySignIns = round(toreal(count()) / 14.0, 1);
// Historical operations baseline
let HistoricalOps = AuditLogs
    | where TimeGenerated between ((AlertTime - BaselineWindow) .. (AlertTime - CurrentWindow))
    | where InitiatedBy has SyncAccountPattern
    | summarize
        BaselineOperations = make_set(OperationName, 50),
        BaselineTotalOps = count(),
        BaselineAvgDailyOps = round(toreal(count()) / 14.0, 1);
// Current window sign-ins
let CurrentSignIns = union
    (SigninLogs
    | where TimeGenerated between ((AlertTime - CurrentWindow) .. (AlertTime + 4h))
    | where UserPrincipalName startswith SyncAccountPattern
    | where ResultType == "0"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - CurrentWindow) .. (AlertTime + 4h))
    | where UserPrincipalName startswith SyncAccountPattern
    | where ResultType == "0")
| summarize
    CurrentIPs = make_set(IPAddress, 20),
    CurrentCountries = make_set(tostring(parse_json(LocationDetails).countryOrRegion), 10),
    CurrentApps = make_set(AppDisplayName, 20),
    CurrentResources = make_set(ResourceDisplayName, 20),
    CurrentASNs = make_set(AutonomousSystemNumber, 20),
    CurrentTotalSignIns = count();
// Current window operations
let CurrentOps = AuditLogs
    | where TimeGenerated between ((AlertTime - CurrentWindow) .. (AlertTime + 4h))
    | where InitiatedBy has SyncAccountPattern
    | summarize
        CurrentOperations = make_set(OperationName, 50),
        CurrentTotalOps = count();
// Compare
HistoricalSignIns
| extend p = 1
| join kind=fullouter (CurrentSignIns | extend p = 1) on p
| join kind=fullouter (HistoricalOps | extend p = 1) on p
| join kind=fullouter (CurrentOps | extend p = 1) on p
| project-away p, p1, p2, p3
| extend
    NewIPs = set_difference(CurrentIPs, BaselineIPs),
    NewCountries = set_difference(CurrentCountries, BaselineCountries),
    NewApps = set_difference(CurrentApps, BaselineApps),
    NewResources = set_difference(CurrentResources, BaselineResources),
    NewOperations = set_difference(CurrentOperations, BaselineOperations),
    SignInSpike = round(iff(coalesce(BaselineAvgDailySignIns, 0) > 0,
        toreal(coalesce(CurrentTotalSignIns, 0)) / BaselineAvgDailySignIns, 999.0), 1),
    OpsSpike = round(iff(coalesce(BaselineAvgDailyOps, 0) > 0,
        toreal(coalesce(CurrentTotalOps, 0)) / BaselineAvgDailyOps, 999.0), 1)
| extend
    AnomalyVerdict = case(
        array_length(NewIPs) > 0 and array_length(NewOperations) > 0,
            "CRITICAL ANOMALY - New IP AND new operation types (never seen in 14 days)",
        array_length(NewIPs) > 0,
            "CRITICAL ANOMALY - Sync account used from IP never seen in 14-day baseline",
        array_length(NewCountries) > 0,
            "CRITICAL ANOMALY - Sync account from new country (should never change)",
        array_length(NewOperations) > 0,
            "HIGH ANOMALY - New operation types not seen in baseline",
        array_length(NewApps) > 0,
            "HIGH ANOMALY - Sync account using new applications",
        SignInSpike > 3.0,
            "MODERATE ANOMALY - Sign-in volume 3x above daily baseline",
        OpsSpike > 3.0,
            "MODERATE ANOMALY - Operation volume 3x above daily baseline",
        "NORMAL - Activity within 14-day baseline parameters"
    )
| project
    AnomalyVerdict,
    NewIPs,
    NewCountries,
    NewApps,
    NewOperations,
    NewResources,
    SignInSpike,
    OpsSpike,
    BaselineIPs,
    BaselineAvgDailySignIns,
    CurrentTotalSignIns,
    BaselineAvgDailyOps,
    CurrentTotalOps
```

**What to look for:**

- **"CRITICAL ANOMALY - New IP AND new operation types"** = Two major firsts simultaneously. Sync accounts are the most predictable entities in a tenant — any new IP is alarming; combined with new operations, this is near-certain compromise.
- **NewIPs not empty** = The sync account should always come from the same 1-2 IPs (AAD Connect server, possibly a staging server). Any new IP is a very strong signal.
- **NewCountries not empty** = The sync account's geographic origin should NEVER change. A new country means the credentials are being used from a completely different location.
- **NewOperations containing non-sync operations** = Operations the sync account has never performed before, such as role assignments or application changes.
- **SignInSpike > 3** = Triple the normal daily sign-in volume — potential automated abuse of sync credentials.
- **"NORMAL"** = Sync account behavior is identical to its 14-day baseline. If this step shows NORMAL but Step 1 shows anomalies, investigate the time range carefully.

---

### Step 5: Sync Infrastructure Change Detection

**Objective:** Detect changes to the synchronization infrastructure itself — new AAD Connect connector registrations, PTA agent registrations or deregistrations, sync account password changes, sync account permission modifications, and new sync account creation. These events indicate an attacker deploying their own sync infrastructure or hijacking the existing deployment.

```kql
// Step 5: Sync Infrastructure Change Detection
// Table: AuditLogs | Detects changes to the AAD Connect infrastructure
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 30d;
let SyncAccountPattern = "Sync_";
// Infrastructure change audit operations
let InfraChangeOperations = dynamic([
    // Connector and agent registration
    "Register connector", "Unregister connector",
    "Set DirSyncEnabled flag", "Set company DirSync enabled",
    // Sync account lifecycle
    "Add user", "Delete user", "Reset user password",
    "Change user password", "Update user",
    // Sync permissions
    "Add member to role", "Add eligible member to role",
    "Remove member from role",
    // Sync configuration
    "Set DirSyncConfiguration",
    "Export", "Import",
    // Password writeback
    "Set Password",
    // PTA agent
    "Register connector", "Update connector"
]);
AuditLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where OperationName in (InfraChangeOperations)
    or (OperationName has "connector" or OperationName has "Connector")
    or (OperationName has "DirSync" or OperationName has "dirsync")
    or (TargetResources has SyncAccountPattern)
    or (OperationName has "password" and TargetResources has SyncAccountPattern)
| extend
    InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
    InitiatorApp = tostring(InitiatedBy.app.displayName),
    InitiatorIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    TargetResourceType = tostring(TargetResources[0].type),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    InfraChangeCategory = case(
        OperationName has "Register connector" or OperationName has "Unregister connector",
            "CONNECTOR_REGISTRATION",
        OperationName has "DirSync",
            "DIRSYNC_CONFIG",
        OperationName has "password" and TargetResource startswith SyncAccountPattern,
            "SYNC_ACCOUNT_PASSWORD_CHANGE",
        OperationName has "role" and TargetResource startswith SyncAccountPattern,
            "SYNC_ACCOUNT_ROLE_CHANGE",
        OperationName == "Add user" and TargetResource startswith SyncAccountPattern,
            "NEW_SYNC_ACCOUNT_CREATED",
        OperationName == "Delete user" and TargetResource startswith SyncAccountPattern,
            "SYNC_ACCOUNT_DELETED",
        OperationName has "Update user" and TargetResource startswith SyncAccountPattern,
            "SYNC_ACCOUNT_MODIFIED",
        "OTHER_INFRA_CHANGE"
    ),
    Severity = case(
        OperationName has "Register connector",
            "CRITICAL - New connector/agent registered (possible rogue infrastructure)",
        OperationName == "Add user" and TargetResource startswith SyncAccountPattern,
            "CRITICAL - New sync account created (possible rogue AAD Connect)",
        OperationName has "Unregister connector",
            "HIGH - Connector deregistered (possible tampering)",
        OperationName has "password" and TargetResource startswith SyncAccountPattern,
            "HIGH - Sync account password changed",
        OperationName has "role" and TargetResource startswith SyncAccountPattern,
            "HIGH - Sync account role membership changed",
        OperationName has "DirSync",
            "MEDIUM - Directory sync configuration changed",
        "LOW - Infrastructure change event"
    )
| project
    TimeGenerated,
    OperationName,
    InfraChangeCategory,
    Severity,
    InitiatorUPN,
    InitiatorApp,
    InitiatorIP,
    TargetResource,
    ModifiedProperties,
    Result
| sort by TimeGenerated asc
```

**What to look for:**

- **"CRITICAL - New connector/agent registered"** = A new AAD Connect connector or PTA agent was registered. If this was not a planned deployment, an attacker may have deployed rogue sync infrastructure.
- **"CRITICAL - New sync account created"** = A new `Sync_*` account appeared. Each AAD Connect installation creates its own sync account — an unexpected new account means a rogue AAD Connect installation.
- **"HIGH - Sync account password changed"** = If the sync account password was changed by anyone other than the identity team during a planned rotation, the credentials may have been reset by an attacker for persistent access.
- **"HIGH - Connector deregistered"** = Legitimate AAD Connect deregistration requires planning. Unexpected deregistration may indicate an attacker removing the legitimate connector before registering their own.
- **InitiatorUPN or InitiatorIP unfamiliar** = Infrastructure changes by unknown actors from unknown IPs are high-confidence indicators of rogue deployment.
- **Multiple CONNECTOR_REGISTRATION events in a short window** = Attacker setting up redundant connectors for resilient persistence.

---

### Step 6: Pass-through Authentication Agent Health

**Objective:** Check PTA agent status for heartbeat failures, new agent registrations from unexpected servers, and agent deregistrations. PTA agents are critical authentication infrastructure — if a malicious agent is registered, the attacker can intercept plaintext credentials for every user who authenticates through Pass-through Authentication.

```kql
// Step 6: Pass-through Authentication Agent Health
// Table: AuditLogs + SigninLogs | Monitors PTA agent health and registration
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 30d;
// PTA-specific audit events
let PTAEvents = AuditLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where OperationName has_any (
        "Register connector", "Unregister connector",
        "Update connector", "Set connector"
    )
    or (Category == "ApplicationManagement" and OperationName has "connector")
    | extend
        InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
        InitiatorApp = tostring(InitiatedBy.app.displayName),
        InitiatorIP = tostring(InitiatedBy.user.ipAddress),
        TargetResource = tostring(TargetResources[0].displayName),
        TargetResourceType = tostring(TargetResources[0].type),
        ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
    | extend
        PTAEventType = case(
            OperationName has "Register", "AGENT_REGISTERED",
            OperationName has "Unregister", "AGENT_DEREGISTERED",
            OperationName has "Update", "AGENT_UPDATED",
            "OTHER_PTA_EVENT"
        ),
        PTASeverity = case(
            OperationName has "Register",
                "CRITICAL - New PTA agent registered (verify source server)",
            OperationName has "Unregister",
                "HIGH - PTA agent deregistered (potential tampering)",
            OperationName has "Update",
                "MEDIUM - PTA agent configuration updated",
            "LOW - PTA event"
        )
    | project
        TimeGenerated,
        OperationName,
        PTAEventType,
        PTASeverity,
        InitiatorUPN,
        InitiatorApp,
        InitiatorIP,
        TargetResource,
        ModifiedProperties,
        Result;
// PTA-specific sign-in error analysis
let PTASignInErrors = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where ResultType in (
        "80007",  // PTA agent unreachable
        "80010",  // PTA agent unable to decrypt password
        "80012",  // PTA agent - user tried to log on outside allowed hours
        "80013",  // PTA agent unable to complete due to time skew
        "80014"   // PTA agent - validation timeout
    )
    | summarize
        PTAErrorCount = count(),
        PTAErrorTypes = make_set(ResultType, 10),
        AffectedUsers = dcount(UserPrincipalName),
        AffectedUserList = make_set(UserPrincipalName, 20),
        FirstError = min(TimeGenerated),
        LastError = max(TimeGenerated)
    | extend
        PTAHealthVerdict = case(
            PTAErrorCount > 50 and AffectedUsers > 10,
                "CRITICAL - Mass PTA failures affecting many users (agent down or compromised)",
            PTAErrorCount > 20,
                "HIGH - Significant PTA error volume (agent health issue)",
            PTAErrorCount > 5,
                "MEDIUM - Elevated PTA errors (monitor agent)",
            "LOW - Minimal PTA errors"
        );
// Combine PTA events and error analysis
PTAEvents
| summarize
    RegistrationEvents = countif(PTAEventType == "AGENT_REGISTERED"),
    DeregistrationEvents = countif(PTAEventType == "AGENT_DEREGISTERED"),
    UpdateEvents = countif(PTAEventType == "AGENT_UPDATED"),
    AgentEvents = make_list(pack(
        "Time", TimeGenerated,
        "Operation", OperationName,
        "Severity", PTASeverity,
        "Initiator", coalesce(InitiatorUPN, InitiatorApp),
        "IP", InitiatorIP,
        "Target", TargetResource
    ), 20)
| extend p = 1
| join kind=fullouter (PTASignInErrors | extend p = 1) on p
| project-away p, p1
| extend
    OverallPTAAssessment = case(
        coalesce(RegistrationEvents, 0) > 0 and coalesce(PTAErrorCount, 0) > 20,
            "CRITICAL - New agent registration + mass authentication failures",
        coalesce(RegistrationEvents, 0) > 1,
            "CRITICAL - Multiple PTA agents registered (possible rogue agents)",
        coalesce(DeregistrationEvents, 0) > 0 and coalesce(RegistrationEvents, 0) > 0,
            "HIGH - Agent deregistered then new agent registered (possible swap attack)",
        coalesce(RegistrationEvents, 0) > 0,
            "HIGH - New PTA agent registered (verify authorization)",
        coalesce(PTAErrorCount, 0) > 50,
            "HIGH - Mass PTA failures (infrastructure issue or attack)",
        coalesce(DeregistrationEvents, 0) > 0,
            "MEDIUM - PTA agent deregistered",
        "NORMAL - No suspicious PTA events"
    )
```

**What to look for:**

- **"CRITICAL - Multiple PTA agents registered"** = More than one new PTA agent registration in the time window — attacker deploying redundant malicious agents for credential interception.
- **"CRITICAL - New agent registration + mass authentication failures"** = A rogue agent was registered and is causing authentication failures because it cannot properly validate credentials — or an attacker replaced the legitimate agent.
- **"HIGH - Agent deregistered then new agent registered"** = Agent swap attack — the attacker removed the legitimate PTA agent and replaced it with their own to intercept credentials in real time.
- **PTAErrorCount > 50 with AffectedUsers > 10** = Mass PTA failures affecting many users — either the legitimate agent is down (infrastructure issue) or a malicious agent is failing to handle authentications properly.
- **ResultType = "80010"** = PTA agent unable to decrypt password — may indicate the agent was replaced with one that does not have the correct decryption keys.
- **"NORMAL"** = No suspicious PTA events. If PTA is not used in the environment (Password Hash Sync only), this step will show minimal results.

---

### Step 7: Organization-Wide Hybrid Identity Sweep

**Objective:** Sweep the entire tenant for ALL sync-related accounts and infrastructure. List all `Sync_*` accounts, their sign-in patterns, all registered AAD Connect and PTA agents, and detect if new sync infrastructure was deployed without authorization. This reveals the complete hybrid identity attack surface.

```kql
// Step 7: Organization-Wide Hybrid Identity Sweep
// Table: SigninLogs + AADNonInteractiveUserSignInLogs + AuditLogs | Full hybrid identity inventory
let SyncAccountPattern = "Sync_";
let AADConnectServerIPs = dynamic(["10.0.1.50"]);
let AlertTime = datetime(2026-02-22T14:30:00Z);
let SweepWindow = 30d;
// Discover ALL sync accounts and their activity
let AllSyncAccounts = union
    (SigninLogs
    | where TimeGenerated between ((AlertTime - SweepWindow) .. (AlertTime + 4h))
    | where UserPrincipalName startswith SyncAccountPattern
    | where ResultType == "0"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - SweepWindow) .. (AlertTime + 4h))
    | where UserPrincipalName startswith SyncAccountPattern
    | where ResultType == "0")
| extend
    Country = tostring(parse_json(LocationDetails).countryOrRegion),
    City = tostring(parse_json(LocationDetails).city)
| summarize
    TotalSignIns = count(),
    UniqueIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 20),
    Countries = make_set(Country, 10),
    Cities = make_set(City, 10),
    Apps = make_set(AppDisplayName, 10),
    Resources = make_set(ResourceDisplayName, 10),
    ASNs = make_set(AutonomousSystemNumber, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    KnownServerSignIns = countif(IPAddress in (AADConnectServerIPs)),
    UnknownIPSignIns = countif(not(IPAddress in (AADConnectServerIPs))),
    ActiveDays = dcount(bin(TimeGenerated, 1d))
    by UserPrincipalName;
// Enrich with audit operations per sync account
let SyncAccountOps = AuditLogs
    | where TimeGenerated between ((AlertTime - SweepWindow) .. (AlertTime + 4h))
    | where InitiatedBy has SyncAccountPattern
    | extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
    | where InitiatorUPN startswith SyncAccountPattern
    | summarize
        TotalOps = count(),
        OperationTypes = make_set(OperationName, 30),
        DistinctOperations = dcount(OperationName)
        by InitiatorUPN;
// Combine sign-in and operations data
AllSyncAccounts
| join kind=leftouter SyncAccountOps on $left.UserPrincipalName == $right.InitiatorUPN
| extend
    // Extract server name from sync account (Sync_SERVERNAME_GUID@domain)
    ServerName = extract(@"Sync_([^_]+)_", 1, UserPrincipalName),
    SyncAccountRisk = case(
        UnknownIPSignIns > 0 and array_length(Countries) > 1,
            "CRITICAL - Sync account active from multiple countries including unknown IPs",
        UnknownIPSignIns > 0,
            "CRITICAL - Sync account used from unauthorized IP(s)",
        UniqueIPs > 3,
            "HIGH - Sync account from unusually many IPs (expected: 1-2)",
        ActiveDays < 7 and FirstSeen > ago(14d),
            "HIGH - Recently created sync account (check if authorized)",
        TotalSignIns > 0 and KnownServerSignIns == TotalSignIns,
            "NORMAL - All activity from known AAD Connect server",
        "INFO - Minimal activity"
    )
| project
    UserPrincipalName,
    ServerName,
    SyncAccountRisk,
    TotalSignIns,
    UniqueIPs,
    IPList,
    Countries,
    KnownServerSignIns,
    UnknownIPSignIns,
    TotalOps = coalesce(TotalOps, 0),
    DistinctOperations = coalesce(DistinctOperations, 0),
    OperationTypes = coalesce(OperationTypes, dynamic([])),
    FirstSeen,
    LastSeen,
    ActiveDays,
    Apps
| sort by case(
    SyncAccountRisk has "CRITICAL", 1,
    SyncAccountRisk has "HIGH", 2,
    SyncAccountRisk has "NORMAL", 3,
    4
) asc
```

**What to look for:**

- **Multiple `Sync_*` accounts with different ServerName values** = Multiple AAD Connect installations exist. Verify each is authorized. An unexpected server name indicates a rogue AAD Connect deployment.
- **"CRITICAL - Sync account active from multiple countries"** = Sync account credentials being used from different geographic locations — confirmed credential compromise.
- **"HIGH - Recently created sync account"** = A sync account that was created in the last 14 days and did not exist in historical data — could indicate attacker deploying a new AAD Connect instance.
- **UnknownIPSignIns > 0 for ANY sync account** = Any sync account authenticating from an unauthorized IP is a high-priority finding.
- **UniqueIPs > 3** = Sync accounts should use 1-2 IPs maximum (primary server, possibly staging server). More than 3 is abnormal.
- **OperationTypes containing non-standard operations** = Cross-reference with Step 3 findings for each sync account.

---

### Step 8: UEBA Enrichment - Behavioral Context Analysis

**Purpose:** Leverage Microsoft Sentinel's UEBA engine to assess behavioral anomalies for the sync account. Sync accounts have extremely predictable behavior — the same IP, the same ISP, the same operations, at the same cadence, every single day. Because of this rigidity, UEBA deviations are highly meaningful. Even a single `FirstTimeISP` or `ISPUncommon` flag is significant for a sync account, whereas it might be noise for a regular user.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If UEBA is not configured in your environment, skip this step. The investigation remains valid without UEBA, but behavioral context significantly improves confidence in True/False Positive determination. Note: Sync accounts have extremely narrow behavioral profiles, making UEBA deviations much more significant than for regular users.

#### Query 8A: Sync Account UEBA Behavioral Assessment

```kql
// Step 8A: UEBA Behavioral Assessment for Sync Account
// Table: BehaviorAnalytics | Checks behavioral anomalies for sync account
let AlertTime = datetime(2026-02-22T14:30:00Z);
let SyncAccountPattern = "Sync_";
let LookbackWindow = 7d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
| where UserPrincipalName startswith SyncAccountPattern
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
    // ISP anomalies — critical for sync accounts (should always be the same ISP)
    FirstTimeISP = tostring(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommon = tostring(ActivityInsights.ISPUncommonlyUsedByUser),
    ISPUncommonAmongPeers = tostring(ActivityInsights.ISPUncommonlyUsedAmongPeers),
    // Country anomalies — sync account should never change country
    FirstTimeCountry = tostring(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommon = tostring(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    CountryUncommonAmongPeers = tostring(ActivityInsights.CountryUncommonlyConnectedFromAmongPeers),
    // Action anomalies
    FirstTimeActionPerformed = tostring(ActivityInsights.FirstTimeUserPerformedAction),
    ActionUncommonlyPerformed = tostring(ActivityInsights.ActionUncommonlyPerformedByUser),
    ActionUncommonAmongPeers = tostring(ActivityInsights.ActionUncommonlyPerformedAmongPeers),
    // App anomalies — sync account should only use AAD Connect
    FirstTimeAppUsed = tostring(ActivityInsights.FirstTimeUserUsedApp),
    AppUncommonlyUsed = tostring(ActivityInsights.AppUncommonlyUsedByUser),
    // Volume anomalies
    UncommonHighVolume = tostring(ActivityInsights.UncommonHighVolumeOfActions),
    // Resource access anomalies
    FirstTimeResource = tostring(ActivityInsights.FirstTimeUserAccessedResource),
    ResourceUncommon = tostring(ActivityInsights.ResourceUncommonlyAccessedByUser),
    // Device anomalies
    FirstTimeDevice = tostring(ActivityInsights.FirstTimeUserUsedDevice),
    DeviceUncommon = tostring(ActivityInsights.DeviceUncommonlyUsedByUser),
    // User profile
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tostring(UsersInsights.IsDormantAccount)
| extend
    AnomalyCount = toint(FirstTimeISP == "True")
        + toint(ISPUncommon == "True")
        + toint(FirstTimeCountry == "True")
        + toint(CountryUncommon == "True")
        + toint(FirstTimeActionPerformed == "True")
        + toint(FirstTimeAppUsed == "True")
        + toint(UncommonHighVolume == "True")
        + toint(FirstTimeResource == "True")
        + toint(FirstTimeDevice == "True"),
    SyncAccountUEBAVerdict = case(
        InvestigationPriority >= 7 and (FirstTimeISP == "True" or FirstTimeCountry == "True"),
            "CRITICAL - High priority with new ISP/country (sync account NEVER changes ISP)",
        FirstTimeCountry == "True",
            "CRITICAL - First-time country for sync account (should be impossible)",
        FirstTimeISP == "True" and FirstTimeDevice == "True",
            "CRITICAL - New ISP + new device (sync account uses one server, one ISP)",
        FirstTimeISP == "True",
            "HIGH - New ISP for sync account (verify AAD Connect server change)",
        InvestigationPriority >= 7,
            "HIGH - High investigation priority for sync account",
        UncommonHighVolume == "True",
            "MEDIUM - Unusual activity volume for sync account",
        FirstTimeActionPerformed == "True",
            "MEDIUM - New action type for sync account",
        "LOW - Sync account within behavioral norms"
    )
| order by InvestigationPriority desc, TimeGenerated desc
```

#### Query 8B: Sync Account UEBA Summary

```kql
// Step 8B: UEBA Anomaly Summary — Sync Account Confidence Score
// Table: BehaviorAnalytics | Aggregated anomaly assessment
let AlertTime = datetime(2026-02-22T14:30:00Z);
let SyncAccountPattern = "Sync_";
let LookbackWindow = 7d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
| where UserPrincipalName startswith SyncAccountPattern
| extend
    ActivityInsights = parse_json(ActivityInsights),
    UsersInsights = parse_json(UsersInsights)
| summarize
    MaxPriority = max(InvestigationPriority),
    AvgPriority = round(avg(InvestigationPriority), 1),
    HighPriorityEvents = countif(InvestigationPriority >= 7),
    TotalEvents = count(),
    NewISPEvents = countif(tostring(ActivityInsights.FirstTimeUserConnectedViaISP) == "True"),
    ISPUncommonEvents = countif(tostring(ActivityInsights.ISPUncommonlyUsedByUser) == "True"),
    NewCountryEvents = countif(tostring(ActivityInsights.FirstTimeUserConnectedFromCountry) == "True"),
    CountryUncommonEvents = countif(tostring(ActivityInsights.CountryUncommonlyConnectedFromByUser) == "True"),
    NewDeviceEvents = countif(tostring(ActivityInsights.FirstTimeUserUsedDevice) == "True"),
    NewAppEvents = countif(tostring(ActivityInsights.FirstTimeUserUsedApp) == "True"),
    NewActionEvents = countif(tostring(ActivityInsights.FirstTimeUserPerformedAction) == "True"),
    NewResourceEvents = countif(tostring(ActivityInsights.FirstTimeUserAccessedResource) == "True"),
    HighVolumeEvents = countif(tostring(ActivityInsights.UncommonHighVolumeOfActions) == "True"),
    BlastRadius = take_any(tostring(UsersInsights.BlastRadius)),
    IsDormant = take_any(tostring(UsersInsights.IsDormantAccount))
    by UserPrincipalName
| extend
    AbuseConfidence = case(
        NewCountryEvents > 0 and NewISPEvents > 0,
            "VERY HIGH - New country + new ISP (sync account NEVER changes these)",
        MaxPriority >= 7 and (NewISPEvents > 0 or NewCountryEvents > 0),
            "VERY HIGH - High priority with location anomalies",
        NewCountryEvents > 0,
            "HIGH - New country alone is critical for a sync account",
        NewISPEvents > 0 and NewDeviceEvents > 0,
            "HIGH - New ISP + new device (possible rogue server)",
        NewISPEvents > 0,
            "HIGH - New ISP detected for sync account",
        IsDormant == "True" and TotalEvents > 0,
            "HIGH - Dormant sync account suddenly active",
        MaxPriority >= 7,
            "MEDIUM - High investigation priority without location change",
        HighVolumeEvents > 0 or NewActionEvents > 0,
            "MEDIUM - Volume or action anomaly",
        "LOW - Sync account within behavioral norms"
    )
```

**Expected findings:**

| Indicator | Abuse Signal | Legitimate Signal |
|---|---|---|
| FirstTimeISP = True | Sync account connecting from new ISP — credentials used from different network | AAD Connect server migrated to new hosting (planned) |
| ISPUncommon = True | ISP never associated with this sync account before | Same as above — verify with infra team |
| FirstTimeCountry = True | Sync account from new country — should NEVER happen | Very rare: international server migration |
| UncommonHighVolume = True | Abnormal operation count — attacker running bulk operations | AAD Connect full sync triggered (verify in sync logs) |
| FirstTimeDevice = True | Sync account on a new device — possible rogue AAD Connect server | Server replacement/rebuild (verify with infra team) |
| IsDormant = True | Previously dormant sync account suddenly active — rogue deployment activated | Staging server brought online for testing |

**Decision guidance:**

- **AbuseConfidence = "VERY HIGH"** with **NewCountryEvents > 0** = Sync accounts do NOT change countries. This is near-certain credential theft. The sync account credentials have been extracted and are being used from attacker infrastructure. Revoke immediately.
- **NewISPEvents > 0** = Even a single ISP change for a sync account is significant. Unlike users who travel and use different networks, the sync account runs on a fixed server. A new ISP means either the server moved (verify with infrastructure team) or the credentials are compromised.
- **IsDormant = True** = A dormant sync account becoming active indicates a rogue AAD Connect installation was brought online. This is a persistence mechanism.
- **AbuseConfidence = "LOW"** = UEBA sees no deviation. The sync account is behaving normally. If other steps show anomalies, this may mean the attacker is operating from similar infrastructure (e.g., same network as the legitimate server).

---

## 6. Containment Playbook

### Immediate Actions (0-15 minutes)

- [ ] **Block the unauthorized IP** in Conditional Access Named Locations — create a block policy specifically for sync accounts
- [ ] **Revoke all sync account sessions** via Entra ID portal or `Revoke-MgUserSignInSession`
- [ ] **Alert the infrastructure/identity team** — confirm whether any AAD Connect changes were planned
- [ ] **If rogue PTA agent detected** (Step 6): Deregister the suspicious agent immediately via Entra ID Portal > Azure AD Connect > Pass-through Authentication
- [ ] **Disable the compromised sync account** if a second legitimate sync account exists

### Short-term Actions (15 min - 2 hours)

- [ ] **Verify AAD Connect server integrity** — check for unauthorized access, malware, unauthorized software
- [ ] **Check for unauthorized PTA agents** — list all registered PTA agents, verify each maps to a known server
- [ ] **Review ALL sync operations** performed during the compromise window (Step 3) — identify and revert unauthorized changes
- [ ] **Review user/group modifications** — check if any backdoor accounts were created or existing accounts modified
- [ ] **Rotate the sync account password** — generate new credentials via the AAD Connect wizard
- [ ] **If rogue AAD Connect detected** (Step 7): Deregister the rogue connector, disable its sync account, and block its server IP

### Recovery Actions (2-24 hours)

- [ ] **Rotate the sync account credentials** via the AAD Connect configuration wizard (not manually)
- [ ] **Review AAD Connect server security** — patch OS, check firewall rules, verify admin access logs
- [ ] **Audit all sync account permissions** — ensure the sync account has only the Directory Synchronization Accounts role (no additional roles)
- [ ] **Consider switching to Cloud Sync** — Azure AD Cloud Sync eliminates the on-premises server dependency and provides a more secure architecture
- [ ] **Implement Conditional Access for sync accounts** — restrict sync account sign-ins to the AAD Connect server IP(s) only
- [ ] **Enable AAD Connect Health monitoring** — provides proactive alerting for sync failures and anomalies
- [ ] **If PTA compromise confirmed** — rotate the PTA agent credentials, consider migration to Password Hash Sync (PHS) which does not expose plaintext credentials

---

## 7. Evidence Collection Checklist

| Evidence Item | Source Table | Retention | Collection Query |
|---|---|---|---|
| Sync account sign-in anomalies | SigninLogs + AADNonInteractive | 30 days | Step 1 query |
| Sync cycle timing analysis | AADNonInteractiveUserSignInLogs | 30 days | Step 2 query |
| Sync account directory operations | AuditLogs | 90 days | Step 3 query |
| 14-day baseline comparison | SigninLogs + AADNonInteractive + AuditLogs | 30 days | Step 4 query |
| Sync infrastructure changes | AuditLogs | 90 days | Step 5 query |
| PTA agent health and events | AuditLogs + SigninLogs | 30/90 days | Step 6 query |
| Organization-wide hybrid identity sweep | SigninLogs + AADNonInteractive + AuditLogs | 30 days | Step 7 query |
| UEBA behavioral assessment | BehaviorAnalytics | 30 days | Step 8 query |

---

## 8. Escalation Criteria

| Condition | Action |
|---|---|
| Sync account sign-in from unauthorized public IP (Step 1) | Escalate to **P1 Incident** — confirmed credential compromise |
| New sync account or connector registered without authorization (Steps 5, 7) | Escalate to **P1 Incident** — rogue AAD Connect infrastructure deployed |
| Sync account performing role assignments or CA policy changes (Step 3) | Escalate to **P1 Incident** — active privilege escalation via sync account |
| Rogue PTA agent registered (Step 6) | Escalate to **P1 Incident** — real-time credential interception capability |
| Multiple sync accounts with unauthorized IPs (Step 7) | Escalate to **P1 Incident** — coordinated hybrid identity attack |
| Off-cycle sync activity from known IP but with unusual operations (Steps 2, 3) | Escalate to **P2 Incident** — possible AAD Connect server compromise |
| Sync account password changed by unexpected actor (Step 5) | Escalate to **P2 Incident** — credential takeover attempt |
| Minor timing anomalies, all from known IP, normal operations | Escalate to **P3** — likely server maintenance or sync configuration change |

---

## 9. False Positive Documentation

| Scenario | How to Identify | Recommended Action |
|---|---|---|
| AAD Connect server migration | Planned infrastructure change, new IP from same datacenter/network | Update AADConnectServerIPs parameter, document new server |
| AAD Connect upgrade | Version upgrade may cause temporary timing changes | Correlate with change management tickets, timing normalizes post-upgrade |
| Staging server activation | Second AAD Connect staging server brought online for testing | Verify staging server is documented, expect new Sync_ account |
| Full sync triggered | Admin manually triggers full sync (instead of delta) causing volume spike | Verify with identity team, check AAD Connect sync scheduler logs |
| PTA agent server patching | Agent restart during patching causes heartbeat gap and reconnection | Correlate with patching schedule, verify agent returns to normal |
| Credential rotation by identity team | Planned sync account password rotation | Verify rotation is documented, confirm actor matches identity team member |

---

## 10. MITRE ATT&CK Mapping

| Technique ID | Technique Name | How It Applies | Detection Query |
|---|---|---|---|
| **T1078.002** | **Valid Accounts: Domain Accounts** | Sync account is a domain account bridging on-prem and cloud — compromising it provides cross-domain access | **Steps 1, 2, 4** |
| **T1078.004** | **Valid Accounts: Cloud Accounts** | Sync account authenticates to Entra ID as a cloud identity — abuse grants cloud directory access | **Steps 1, 3, 7** |
| **T1550** | **Use Alternate Authentication Material** | Attacker uses extracted sync account credentials or tokens to authenticate without original password | **Steps 1, 4, 8** |
| T1098 | Account Manipulation | Sync account used to modify user attributes, group memberships, or create backdoor accounts | Steps 3, 5 |
| T1136.003 | Create Account: Cloud Account | Sync account used to create new cloud accounts that appear as synced objects | Steps 3, 7 |

---

## 11. Query Summary

| Step | Query | Purpose | Primary Table |
|---|---|---|---|
| 1 | Sync Account Sign-In Anomaly | Detect sync account from unauthorized IPs | SigninLogs + AADNonInteractive |
| 2 | Sync Cycle Timing Analysis | Analyze sync timing pattern for deviations | AADNonInteractiveUserSignInLogs |
| 3 | Directory Operations Audit | Review all sync account operations | AuditLogs |
| 4 | Baseline Comparison | Compare against 14-day sync behavior baseline | SigninLogs + AADNonInteractive + AuditLogs |
| 5 | Infrastructure Change Detection | Detect new connectors, agents, credential changes | AuditLogs |
| 6 | PTA Agent Health | Monitor PTA agent registration and error patterns | AuditLogs + SigninLogs |
| 7 | Organization-Wide Hybrid Sweep | Inventory all sync accounts and infrastructure | SigninLogs + AADNonInteractive + AuditLogs |
| 8A | UEBA Behavioral Assessment | Behavioral anomaly context for sync account | BehaviorAnalytics |
| 8B | UEBA Anomaly Summary | Aggregated abuse confidence score | BehaviorAnalytics |

---

## Appendix A: Datatable Tests

### Test 1: Sync Account Sign-In from Unauthorized IP

```kql
// TEST 1: Verifies detection of sync account sign-in from unauthorized IP
let AADConnectServerIPs = dynamic(["10.0.1.50"]);
let TestSignIns = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, IPAddress: string,
    LocationDetails: dynamic, DeviceDetail: dynamic, ResultType: string,
    AppDisplayName: string, ResourceDisplayName: string,
    AutonomousSystemNumber: string, UserAgent: string, SignInType: string,
    SessionId: string, ConditionalAccessStatus: string,
    AuthenticationRequirement: string, CorrelationId: string
)[
    // Legitimate sync from AAD Connect server
    datetime(2026-02-22T09:00:00Z), "Sync_SERVER01_abc123@contoso.onmicrosoft.com",
        "10.0.1.50", dynamic({"countryOrRegion":"US","city":"Seattle"}),
        dynamic({"operatingSystem":"Windows Server","browser":""}),
        "0", "Azure Active Directory Connect", "Windows Azure Active Directory",
        "8075", "Azure AD Connect", "NonInteractive", "sess-001", "notApplied",
        "singleFactorAuthentication", "corr-001",
    // Legitimate sync 30 min later
    datetime(2026-02-22T09:30:00Z), "Sync_SERVER01_abc123@contoso.onmicrosoft.com",
        "10.0.1.50", dynamic({"countryOrRegion":"US","city":"Seattle"}),
        dynamic({"operatingSystem":"Windows Server","browser":""}),
        "0", "Azure Active Directory Connect", "Windows Azure Active Directory",
        "8075", "Azure AD Connect", "NonInteractive", "sess-002", "notApplied",
        "singleFactorAuthentication", "corr-002",
    // MALICIOUS: Sync account from attacker IP in Russia
    datetime(2026-02-22T14:00:00Z), "Sync_SERVER01_abc123@contoso.onmicrosoft.com",
        "198.51.100.50", dynamic({"countryOrRegion":"RU","city":"Moscow"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome"}),
        "0", "Microsoft Graph PowerShell", "Microsoft Graph",
        "14061", "Mozilla/5.0 PowerShell", "Interactive", "sess-003", "notApplied",
        "singleFactorAuthentication", "corr-003",
    // Normal user (should be excluded)
    datetime(2026-02-22T10:00:00Z), "alice@contoso.com",
        "10.0.0.100", dynamic({"countryOrRegion":"US","city":"Seattle"}),
        dynamic({"operatingSystem":"Windows","browser":"Edge"}),
        "0", "Office 365", "Exchange Online",
        "1234", "Mozilla/5.0 Edge", "Interactive", "sess-004", "notApplied",
        "multiFactorAuthentication", "corr-004"
];
let SyncAccountPattern = "Sync_";
let SyncSignIns = TestSignIns
    | where UserPrincipalName startswith SyncAccountPattern;
SyncSignIns
| extend IsKnownServer = IPAddress in (AADConnectServerIPs)
| summarize
    TotalSignIns = count(),
    KnownServerSignIns = countif(IsKnownServer),
    UnknownIPSignIns = countif(not(IsKnownServer)),
    UnknownIPs = make_set_if(IPAddress, not(IsKnownServer)),
    UnknownCountries = make_set_if(
        tostring(LocationDetails.countryOrRegion), not(IsKnownServer))
    by UserPrincipalName
| where UnknownIPSignIns > 0
    and set_has_element(UnknownIPs, "198.51.100.50")
    and set_has_element(UnknownCountries, "RU")
// EXPECTED: 1 row — Sync_SERVER01 with 1 unauthorized sign-in from 198.51.100.50 (RU)
```

### Test 2: Sync Cycle Timing Anomaly Detection

```kql
// TEST 2: Verifies detection of off-cycle and burst sync activity
let TestSignIns = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, IPAddress: string,
    AppDisplayName: string, ResourceDisplayName: string, ResultType: string
)[
    // Normal 30-min cadence
    datetime(2026-02-22T08:00:00Z), "Sync_SERVER01_abc@contoso.onmicrosoft.com",
        "10.0.1.50", "Azure AD Connect", "Azure AD", "0",
    datetime(2026-02-22T08:30:00Z), "Sync_SERVER01_abc@contoso.onmicrosoft.com",
        "10.0.1.50", "Azure AD Connect", "Azure AD", "0",
    datetime(2026-02-22T09:00:00Z), "Sync_SERVER01_abc@contoso.onmicrosoft.com",
        "10.0.1.50", "Azure AD Connect", "Azure AD", "0",
    // Burst activity (attacker) — 3 sign-ins within 5 minutes
    datetime(2026-02-22T14:00:00Z), "Sync_SERVER01_abc@contoso.onmicrosoft.com",
        "10.0.1.50", "Azure AD Connect", "Azure AD", "0",
    datetime(2026-02-22T14:01:00Z), "Sync_SERVER01_abc@contoso.onmicrosoft.com",
        "10.0.1.50", "Azure AD Connect", "Azure AD", "0",
    datetime(2026-02-22T14:02:00Z), "Sync_SERVER01_abc@contoso.onmicrosoft.com",
        "10.0.1.50", "Azure AD Connect", "Azure AD", "0",
    datetime(2026-02-22T14:03:00Z), "Sync_SERVER01_abc@contoso.onmicrosoft.com",
        "10.0.1.50", "Azure AD Connect", "Azure AD", "0"
];
TestSignIns
| sort by TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated, 1), PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser and isnotempty(PrevTime)
| extend TimeDeltaMinutes = round(datetime_diff('second', TimeGenerated, PrevTime) / 60.0, 1)
| summarize
    BurstEvents = countif(TimeDeltaMinutes < 5.0),
    NormalCycles = countif(TimeDeltaMinutes between (28.0 .. 32.0)),
    TotalDeltas = count()
    by UserPrincipalName
| where BurstEvents >= 3
    and NormalCycles >= 2
// EXPECTED: 1 row — 3 burst events (14:01, 14:02, 14:03 are all < 5 min from previous) + 2 normal cycles (08:30, 09:00)
```

### Test 3: Unauthorized Directory Operations by Sync Account

```kql
// TEST 3: Verifies detection of sync account performing unauthorized operations
let SyncAccountPattern = "Sync_";
let NormalSyncOperations = dynamic([
    "Add user", "Update user", "Delete user",
    "Add group", "Update group", "Delete group",
    "Add member to group", "Remove member from group"
]);
let TestAuditLogs = datatable(
    TimeGenerated: datetime, OperationName: string,
    InitiatedBy: dynamic, TargetResources: dynamic, Result: string
)[
    // Normal sync operation — user creation
    datetime(2026-02-22T09:00:00Z), "Add user",
        dynamic({"user":{"userPrincipalName":"Sync_SERVER01_abc@contoso.onmicrosoft.com","ipAddress":"10.0.1.50"}}),
        dynamic([{"displayName":"newuser@contoso.com","type":"User"}]), "success",
    // Normal sync operation — group update
    datetime(2026-02-22T09:01:00Z), "Update group",
        dynamic({"user":{"userPrincipalName":"Sync_SERVER01_abc@contoso.onmicrosoft.com","ipAddress":"10.0.1.50"}}),
        dynamic([{"displayName":"Sales Team","type":"Group"}]), "success",
    // MALICIOUS: Role assignment by sync account
    datetime(2026-02-22T14:00:00Z), "Add member to role",
        dynamic({"user":{"userPrincipalName":"Sync_SERVER01_abc@contoso.onmicrosoft.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Global Administrator","type":"Role"}]), "success",
    // MALICIOUS: Consent grant by sync account
    datetime(2026-02-22T14:05:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"Sync_SERVER01_abc@contoso.onmicrosoft.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"MaliciousApp","type":"Application"}]), "success",
    // Normal sync operation by different user (should not flag)
    datetime(2026-02-22T10:00:00Z), "Update user",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com","ipAddress":"10.0.0.1"}}),
        dynamic([{"displayName":"bob@contoso.com","type":"User"}]), "success"
];
TestAuditLogs
| where InitiatedBy has SyncAccountPattern
| extend
    InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
    IsNormalOperation = OperationName in (NormalSyncOperations)
| where InitiatorUPN startswith SyncAccountPattern
| summarize
    NormalSyncOps = countif(IsNormalOperation),
    AbnormalOps = countif(not(IsNormalOperation)),
    AbnormalOperations = make_set_if(OperationName, not(IsNormalOperation))
    by InitiatorUPN
| where AbnormalOps == 2
    and set_has_element(AbnormalOperations, "Add member to role")
    and set_has_element(AbnormalOperations, "Consent to application")
// EXPECTED: 1 row — Sync_SERVER01 with 2 abnormal ops (role assignment + consent grant)
```

### Test 4: Organization-Wide Hybrid Identity Sweep

```kql
// TEST 4: Verifies detection of multiple sync accounts including rogue deployment
let AADConnectServerIPs = dynamic(["10.0.1.50"]);
let TestSyncAccounts = datatable(
    UserPrincipalName: string, IPAddress: string, Country: string,
    TotalSignIns: long, FirstSeen: datetime
)[
    // Legitimate sync account — all from known server
    "Sync_SERVER01_abc@contoso.onmicrosoft.com", "10.0.1.50", "US",
        1400, datetime(2025-06-01),
    // ROGUE sync account — from unknown server and IP
    "Sync_ATKSERVER_xyz@contoso.onmicrosoft.com", "198.51.100.99", "DE",
        50, datetime(2026-02-20),
    // Legitimate sync account but also has unauthorized IP
    "Sync_SERVER01_abc@contoso.onmicrosoft.com", "203.0.113.10", "RU",
        5, datetime(2026-02-22)
];
TestSyncAccounts
| summarize
    UniqueIPs = dcount(IPAddress),
    IPList = make_set(IPAddress),
    Countries = make_set(Country),
    TotalSignIns = sum(TotalSignIns),
    KnownServerSignIns = sumif(TotalSignIns, IPAddress in (AADConnectServerIPs)),
    UnknownIPSignIns = sumif(TotalSignIns, not(IPAddress in (AADConnectServerIPs))),
    FirstSeen = min(FirstSeen)
    by UserPrincipalName
| extend
    ServerName = extract(@"Sync_([^_]+)_", 1, UserPrincipalName),
    SyncAccountRisk = case(
        UnknownIPSignIns > 0 and array_length(Countries) > 1,
            "CRITICAL - Sync account active from multiple countries including unknown IPs",
        UnknownIPSignIns > 0,
            "CRITICAL - Sync account used from unauthorized IP(s)",
        FirstSeen > ago(14d),
            "HIGH - Recently created sync account",
        "NORMAL - All activity from known server"
    )
| where SyncAccountRisk has "CRITICAL" or SyncAccountRisk has "HIGH"
| summarize
    RiskyAccounts = count(),
    AccountList = make_set(UserPrincipalName),
    ServerNames = make_set(ServerName)
| where RiskyAccounts == 2
    and set_has_element(ServerNames, "ATKSERVER")
// EXPECTED: 1 row — 2 risky accounts (SERVER01 with unauthorized IP + ATKSERVER rogue deployment)
```

---

## References

- [Azure AD Connect: Accounts and Permissions](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)
- [Azure AD Connect: Design Concepts - Sync Service Account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-connect-design-concepts)
- [Pass-through Authentication Security Deep Dive](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-security-deep-dive)
- [Azure AD Connect Health Monitoring](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-health-sync)
- [Microsoft Identity Security: Protecting Hybrid Identity Infrastructure](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-connectivity)
- [Midnight Blizzard AAD Connect Abuse Techniques](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [Storm-0501 Ransomware Hybrid Identity Attacks](https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/)
- [Scattered Spider Hybrid Identity Techniques](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)
- [MITRE ATT&CK T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [MITRE ATT&CK T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [MITRE ATT&CK T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK T1136.003 - Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)
- [AADInternals: Extracting Azure AD Connect Credentials](https://aadinternals.com/post/on-prem_admin/)
- [Securing Azure AD Connect Server](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites#harden-your-azure-ad-connect-server)
