---
title: "Unfamiliar Sign-In Properties"
id: RB-0001
severity: medium
status: reviewed
description: >
  Investigation runbook for Microsoft Entra ID Identity Protection
  "Unfamiliar sign-in properties" risk detection. Covers credential
  compromise via valid accounts, post-access persistence (inbox rules,
  MFA manipulation, OAuth consent), and blast radius assessment.
mitre_attack:
  tactics:
    - tactic_id: TA0001
      tactic_name: "Initial Access"
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
    - tactic_id: TA0009
      tactic_name: "Collection"
  techniques:
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: confirmed
    - technique_id: T1110.003
      technique_name: "Brute Force: Password Spraying"
      confidence: probable
    - technique_id: T1110.004
      technique_name: "Brute Force: Credential Stuffing"
      confidence: probable
    - technique_id: T1114.003
      technique_name: "Email Collection: Email Forwarding Rule"
      confidence: confirmed
    - technique_id: T1528
      technique_name: "Steal Application Access Token"
      confidence: confirmed
    - technique_id: T1530
      technique_name: "Data from Cloud Storage Object"
      confidence: confirmed
    - technique_id: T1534
      technique_name: "Internal Spearphishing"
      confidence: confirmed
    - technique_id: T1539
      technique_name: "Steal Web Session Cookie"
      confidence: possible
    - technique_id: T1556.006
      technique_name: "Modify Authentication Process: MFA"
      confidence: confirmed
    - technique_id: T1564.008
      technique_name: "Hide Artifacts: Email Hiding Rules"
      confidence: confirmed
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Octo Tempest (Scattered Spider)"
  - "Peach Sandstorm (APT33)"
log_sources:
  - table: "SigninLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "AADNonInteractiveUserSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: false
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
  - table: "AuditLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "IdentityInfo"
    product: "Sentinel UEBA"
    license: "Sentinel UEBA"
    required: false
    alternatives: ["AuditLogs (Category == RoleManagement)"]
  - table: "OfficeActivity"
    product: "Office 365"
    license: "M365 E3+"
    required: true
    alternatives: []
  - table: "CloudAppEvents"
    product: "Defender for Cloud Apps"
    license: "MCAS / M365 E5"
    required: false
    alternatives: ["OfficeActivity"]
  - table: "SecurityAlert"
    product: "Microsoft Sentinel"
    license: "Sentinel"
    required: true
    alternatives: []
  - table: "ThreatIntelligenceIndicator"
    product: "Microsoft Sentinel"
    license: "Sentinel + TI feeds"
    required: false
    alternatives: []
  - table: "BehaviorAnalytics"
    product: "Sentinel UEBA"
    license: "Sentinel UEBA"
    required: false
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-21
updated: 2026-02-21
version: "1.0"
tier: 1
---

# Unfamiliar Sign-In Properties - Investigation Runbook

<div class="runbook-meta" markdown>
<div class="runbook-meta-item">
  <span class="runbook-meta-label">ID</span>
  <code>RB-0001</code>
</div>
<div class="runbook-meta-item">
  <span class="runbook-meta-label">Severity</span>
  <span class="severity-badge severity-medium">Medium</span>
</div>
<div class="runbook-meta-item">
  <span class="runbook-meta-label">Source</span>
  Entra ID Identity Protection
</div>
<div class="runbook-meta-item">
  <span class="runbook-meta-label">Tactics</span>
  <span class="mitre-tag mitre-initial-access">Initial Access</span>
  <span class="mitre-tag mitre-persistence">Persistence</span>
  <span class="mitre-tag mitre-priv-esc">Priv Esc</span>
  <span class="mitre-tag mitre-defense-evasion">Defense Evasion</span>
  <span class="mitre-tag mitre-cred-access">Cred Access</span>
  <span class="mitre-tag mitre-lateral-movement">Lateral Movement</span>
  <span class="mitre-tag mitre-collection">Collection</span>
</div>
</div>

??? abstract "Investigation Flow Diagram"

    ```mermaid
    flowchart TD
        A["Alert: Unfamiliar Sign-In Properties"] --> B["Step 1: Extract Alert Entities\n& Sign-In Details"]
        B --> C["Step 2: Check User Context\n& Account Status"]
        C --> D["Step 3: Baseline Comparison\nEstablish Normal Behavior"]
        D --> E{"Activity\nAnomalous?"}
        E -->|"No - Matches baseline"| F["Document as\nFalse Positive"]
        E -->|"Yes - Deviates from normal"| G["Step 4: Check Correlated\nRisk Events"]
        G --> H["Step 5: Post-Sign-In Activity\nBlast Radius Assessment"]
        H --> I{"Inbox Rules?\nMFA Changes?\nOAuth Grants?"}
        I -->|"Persistence found"| J["Step 6: IP Reputation\n& Source Context"]
        I -->|"No persistence"| J
        J --> K["Step 7: Final\nDetermination"]
        K --> L{"Confirmed\nCompromise?"}
        L -->|"Yes"| M["Containment\nPlaybook"]
        L -->|"No - Suspicious"| N["Continue Monitoring\n+ Watchlist"]
        L -->|"Benign"| F
        M --> O["Evidence\nCollection"]
        O --> P["Escalation\nif needed"]

        style A fill:#ffd93d,color:#0d1117,stroke:#fbbf24
        style M fill:#ff4757,color:#e6edf3,stroke:#dc2626
        style O fill:#4fc3f7,color:#0d1117,stroke:#38bdf8
        style F fill:#69db7c,color:#0d1117,stroke:#4ade80
        style N fill:#ff8c42,color:#0d1117,stroke:#fb923c
    ```

> **RB-0001** | Severity: Medium | Version: 1.0 | Last updated: 2026-02-21
>
> **Alert Source:** Microsoft Entra ID Identity Protection
> **Risk Detection Name:** `unfamiliarFeatures`
> **Primary MITRE Technique:** T1078.004 - Valid Accounts: Cloud Accounts

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Extract Alert Entities and Sign-In Details](#step-1-extract-alert-entities-and-sign-in-details)
   - [Step 2: Check User Context and Account Status](#step-2-check-user-context-and-account-status)
   - [Step 3: Baseline Comparison - Establish Normal Behavior Pattern](#step-3-baseline-comparison---establish-normal-behavior-pattern)
   - [Step 4: Check for Correlated Risk Events](#step-4-check-for-correlated-risk-events)
   - [Step 5: Analyze Post-Sign-In Activity (Blast Radius Assessment)](#step-5-analyze-post-sign-in-activity-blast-radius-assessment)
   - [Step 6: Check Source IP Reputation and Context](#step-6-check-source-ip-reputation-and-context)
   - [Step 7: Final Determination and Classification](#step-7-final-determination-and-classification)
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
The "Unfamiliar sign-in properties" risk detection is generated by Entra ID Identity Protection when a user signs in from properties (IP address, location, device, browser, ASN/network) that have not been observed in that user's recent sign-in history. Identity Protection uses a rolling ML model that learns each user's typical sign-in patterns over approximately 30 days. When a sign-in deviates significantly from the learned pattern, it triggers this detection.

**Why it matters:**
This is one of the most common Identity Protection alerts and often the first indicator of credential compromise. An attacker who has obtained valid credentials (via phishing, credential stuffing, dark web purchase, or password spray) will typically sign in from infrastructure that looks nothing like the legitimate user's patterns - different country, different ISP, different device fingerprint.

**However:** This is also one of the highest false-positive alerts. Legitimate triggers include:
- User traveling for business or vacation
- User switching to a new device, browser, or ISP
- User connecting via a new VPN or corporate network change
- First sign-in after a long period of inactivity

**Worst case scenario if this is real:**
An attacker has valid credentials and is actively accessing the user's account. They may be reading email, setting up persistence (inbox rules, MFA device registration, OAuth app consent), and preparing for business email compromise or data exfiltration. Every minute of delay means more potential damage.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID P2 + Microsoft 365 E3 + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID, Office 365
- **Permissions:** Security Reader (investigation), Security Operator (containment)

### Recommended for Full Coverage
- **License:** Microsoft 365 E5 + Sentinel with UEBA enabled + TI feeds
- **Additional Connectors:** Defender for Cloud Apps, Threat Intelligence (TAXII/Platform)

### Data Availability Check
Before starting the investigation, verify these tables contain data:
1. Run `AADUserRiskEvents | take 1` - If empty, Entra ID P2 or the connector is missing
2. Run `OfficeActivity | take 1` - If empty, the Office 365 connector is not configured
3. Run `IdentityInfo | take 1` - If empty, UEBA is not enabled (use Query 2A-Fallback for user context)

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | SigninLogs, AuditLogs, SecurityAlert, ThreatIntelligenceIndicator | Steps 1 (partial), 5 (partial), 6 (partial) |
| Entra ID P2 + Sentinel | Above + AADNonInteractiveUserSignInLogs, AADUserRiskEvents, AADRiskyUsers | Steps 1-4, 6 |
| M365 E3 + Entra ID P2 + Sentinel | Above + OfficeActivity | Steps 1-6 (core investigation) |
| M365 E5 + Sentinel + UEBA | ALL 11 tables | Steps 1-7 (full investigation) |

---

## 3. Input Parameters

All queries in this runbook use the following shared input parameters. Replace these values with the actual alert data before running.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Set these before running any query
// ============================================================
let targetUser = "user@contoso.com";          // UserPrincipalName from the alert
let alertTime = datetime(2026-02-21T14:30:00Z); // TimeGenerated of the risk event
let alertIP = "198.51.100.42";                // Source IP from the risk event
```

---

## 4. Quick Triage Criteria

The goal of quick triage is to determine within 2-3 steps whether this alert can be confidently closed as a false positive or requires deep investigation.

### Quick Close Conditions (all must be true to close as FP):
1. The sign-in was **successful AND passed MFA** (user completed a real MFA challenge, not just a cached token)
2. The unfamiliar property is **only the IP/ASN** (not location + device + browser combined)
3. The IP belongs to a **known corporate VPN, cloud proxy, or recognized ISP** in the user's country
4. There is **no other risk event** for this user in the past 7 days
5. There is **no suspicious post-sign-in activity** (no inbox rules, no app consents, no bulk downloads)

### Quick Escalation Conditions (any one triggers deep investigation):
- Sign-in from a country the user has NEVER signed in from before
- Sign-in without MFA or with MFA bypassed
- Multiple unfamiliar properties simultaneously (new IP + new device + new browser + new location)
- Other risk events present for the same user (especially if different types: leaked credentials + unfamiliar sign-in)
- Any post-sign-in activity within 30 minutes that modifies account settings, creates inbox rules, or accesses sensitive resources

---

## 5. Investigation Steps

### Step 1: Extract Alert Entities and Sign-In Details

**Purpose:** Pull the complete sign-in record that triggered the alert. Understand exactly which properties were unfamiliar and the full authentication context.

**Data needed from:**
- Table: AADUserRiskEvents - get the risk event details (RiskEventType, DetectionTimingType, RiskLevel, IpAddress, Location)
- Table: SigninLogs - get the full sign-in record (UserPrincipalName, IPAddress, Location, DeviceDetail, UserAgent, AppDisplayName, ConditionalAccessStatus, AuthenticationRequirement, MfaDetail, ResultType)

**What to extract:**
- User identity: UserPrincipalName, display name, object ID
- Source IP address and geographic location (city, country)
- Device information: OS, browser, device compliance status, managed/unmanaged
- Application being accessed
- Authentication details: MFA completed? Which MFA method? Conditional Access result?
- Risk assessment: Risk level, real-time vs offline detection
- Session ID and correlation ID for event chaining

#### Query 1: Extract Alert Entities and Sign-In Details

```kql
// ============================================================
// Query 1: Extract Alert Entities and Sign-In Details
// Purpose: Pull the risk event and full sign-in context for the
//          "Unfamiliar sign-in properties" alert
// Tables: AADUserRiskEvents, SigninLogs
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let alertIP = "198.51.100.42";
// Lookback window around the alert time to catch the matching sign-in
let lookbackWindow = 2h;
// --- Part 1: Get the risk event ---
let riskEvent = AADUserRiskEvents
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    | where RiskEventType == "unfamiliarFeatures"
    // IpAddress uses capital 'A' in this table (not IPAddress)
    | where IpAddress == alertIP
    | project
        RiskTimeGenerated = TimeGenerated,
        UserPrincipalName,
        RiskEventType,
        RiskLevel,
        DetectionTimingType,
        RiskIpAddress = IpAddress,
        RiskLocation = Location,
        CorrelationId,
        Id;
// --- Part 2: Get the full sign-in record ---
// Join on CorrelationId to find the exact sign-in that triggered the risk event
let signinDetails = SigninLogs
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    // ResultType is a STRING, not int (Hasan's gotcha)
    | project
        SigninTimeGenerated = TimeGenerated,
        UserPrincipalName,
        IPAddress,
        Location,
        // DeviceDetail is dynamic - access nested fields via dot notation
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceBrowser = tostring(DeviceDetail.browser),
        DeviceIsCompliant = tostring(DeviceDetail.isCompliant),
        DeviceIsManaged = tostring(DeviceDetail.isManaged),
        DeviceTrustType = tostring(DeviceDetail.trustType),
        UserAgent,
        AppDisplayName,
        ResourceDisplayName,
        ClientAppUsed,
        // Authentication context
        AuthenticationRequirement,
        // MfaDetail can be empty if MFA was not performed (Hasan's gotcha)
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA performed"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), ""),
        ConditionalAccessStatus,
        ResultType,
        ResultDescription = iff(ResultType == "0", "Success", ResultType),
        CorrelationId,
        SessionId;
// --- Combine risk event with sign-in details ---
riskEvent
| join kind=inner signinDetails on CorrelationId, UserPrincipalName
| project
    // Risk event context
    RiskTimeGenerated,
    DetectionTimingType,
    RiskLevel,
    RiskEventType,
    // User identity
    UserPrincipalName,
    // Source context
    IPAddress,
    LocationCity = tostring(Location.city),
    LocationCountry = tostring(Location.countryOrRegion),
    // Device context
    DeviceOS,
    DeviceBrowser,
    DeviceIsCompliant,
    DeviceIsManaged,
    DeviceTrustType,
    UserAgent,
    // Application context
    AppDisplayName,
    ResourceDisplayName,
    ClientAppUsed,
    // Authentication context
    AuthenticationRequirement,
    MfaAuthMethod,
    MfaAuthDetail,
    ConditionalAccessStatus,
    // Sign-in result
    ResultType,
    ResultDescription,
    // Tracking IDs
    CorrelationId,
    SessionId,
    SigninTimeGenerated
| order by RiskTimeGenerated desc
```

<details>
<summary>Expected Output Columns</summary>

| Column | Type | Description |
|---|---|---|
| RiskTimeGenerated | datetime | When the risk event was generated |
| DetectionTimingType | string | "realtime" or "offline" - realtime is higher confidence |
| RiskLevel | string | "low", "medium", "high" |
| RiskEventType | string | Should be "unfamiliarFeatures" |
| UserPrincipalName | string | Affected user |
| IPAddress | string | Source IP of the sign-in |
| LocationCity | string | City extracted from Location dynamic |
| LocationCountry | string | Country extracted from Location dynamic |
| DeviceOS | string | Operating system of the device |
| DeviceBrowser | string | Browser used |
| DeviceIsCompliant | string | "true"/"false" - Intune compliance |
| DeviceIsManaged | string | "true"/"false" - managed device |
| DeviceTrustType | string | Trust type (e.g., "AzureAd", "Workplace") |
| UserAgent | string | Raw user agent string |
| AppDisplayName | string | Application accessed |
| ResourceDisplayName | string | Target resource |
| ClientAppUsed | string | Client type (Browser, Mobile Apps, etc.) |
| AuthenticationRequirement | string | "singleFactorAuthentication" or "multiFactorAuthentication" |
| MfaAuthMethod | string | MFA method or "No MFA performed" |
| MfaAuthDetail | string | MFA detail or empty |
| ConditionalAccessStatus | string | "success", "failure", "notApplied" |
| ResultType | string | "0" = success, other = failure code |
| ResultDescription | string | Human-readable result |
| CorrelationId | string | Event correlation GUID |
| SessionId | string | Session identifier |
| SigninTimeGenerated | datetime | Sign-in timestamp |

</details>

**Performance Notes:**
- Query scans a narrow time window (2h around alert time) for both tables - very fast
- CorrelationId inner join ensures only matching records are returned
- Expected result: 1 row (single risk event matched to its sign-in)
- If the join returns 0 rows, the risk event may have been an offline detection where the CorrelationId does not match. In that case, try matching on UserPrincipalName + time proximity instead

**Tuning Guidance:**
- **lookbackWindow**: Default 2h. Increase to 6h if the risk event was an offline detection (DetectionTimingType == "offline"), as the TimeGenerated may lag significantly behind the actual sign-in
- **If no CorrelationId match**: Fall back to joining on UserPrincipalName + IPAddress within a 30-minute window

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Location | Country user has never signed in from | User's home country, known travel destination |
| Device | Unknown device, non-compliant | Corporate-managed device, recently enrolled |
| Browser | Unusual browser (e.g., Python requests, curl, old browser version) | Standard browser (Chrome, Edge, Safari) |
| MFA | Not challenged, or MFA failed, or legacy auth bypassed MFA | MFA successfully completed with standard method |
| Conditional Access | Not applied or failed | Successfully applied and passed |
| Detection timing | Real-time (suspicious enough to catch live) | Offline (lower confidence, detected in batch) |

**Next action:**
- If MFA passed + managed device + known location -> proceed to Step 2 with low concern, may quick close
- If MFA not completed OR unknown device + unknown location -> proceed to Step 2 with high concern
- If ResultType != 0 (sign-in failed) -> still investigate the IP and check for other attempts, but lower priority

---

### Step 2: Check User Context and Account Status

**Purpose:** Understand who this user is and whether the account is a high-value target. Check for recent account changes that might indicate the account was already compromised.

**Data needed from:**
- Table: IdentityInfo - get user metadata (Department, JobTitle, AssignedRoles, GroupMemberships)
- Table: AuditLogs - check for recent account changes (password reset, MFA method changes, new device registration)

**What to look for:**
- Is this a privileged account? (Global Admin, Security Admin, Exchange Admin, or member of sensitive groups)
- Is this an executive or finance team member? (high BEC risk)
- Has the password been changed recently? (could indicate password was reset after compromise, or attacker changed it)
- Were new MFA methods registered recently? (attacker registering their own MFA device)
- Were new devices registered recently? (T1098.005 - rogue device join)
- Is this a shared account or service account? (higher risk due to weaker controls)

#### Query 2A: User Context - Identity Lookup

```kql
// ============================================================
// Query 2A: User Context - Identity Lookup
// Purpose: Get user metadata to assess account value and risk
// Table: IdentityInfo (UEBA)
// Note: IdentityInfo requires Sentinel UEBA enabled. If empty,
//       use Query 2A-Fallback below
// Expected runtime: <3 seconds
// ============================================================
let targetUser = "user@contoso.com";
// IdentityInfo is a state table - get the latest record per user
IdentityInfo
| where AccountUPN == targetUser
| summarize arg_max(TimeGenerated, *) by AccountUPN
| project
    AccountUPN,
    Department,
    JobTitle,
    // AssignedRoles is a dynamic array - flag if any privileged role exists
    AssignedRoles,
    IsPrivileged = iff(
        AssignedRoles has_any ("Global Administrator", "Security Administrator", "Exchange Administrator",
            "SharePoint Administrator", "Privileged Role Administrator", "User Administrator",
            "Application Administrator", "Cloud Application Administrator", "Conditional Access Administrator"),
        "YES - PRIVILEGED",
        "Standard User"
    ),
    GroupMemberships,
    // Flag high-value targets for BEC
    IsHighValueBEC = iff(
        Department in ("Finance", "Accounting", "Treasury", "Executive", "C-Suite", "Legal") or
        JobTitle has_any ("CEO", "CFO", "CTO", "CIO", "CISO", "VP", "Director", "President", "Controller", "Treasurer"),
        "YES - HIGH BEC RISK",
        "Standard"
    ),
    LastUpdated = TimeGenerated
```

#### Query 2A-Fallback: User Privileged Role Check (No UEBA)

```kql
// ============================================================
// Query 2A-Fallback: User Privileged Role Check (No UEBA)
// Purpose: Check if user has privileged roles via AuditLogs
//          when IdentityInfo is unavailable
// Table: AuditLogs
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
AuditLogs
| where TimeGenerated > ago(90d)
| where Category == "RoleManagement"
| where OperationName has_any ("Add member to role", "Add eligible member to role")
// Extract the target user from TargetResources (dynamic array)
| mv-expand TargetResource = TargetResources
| where tostring(TargetResource.userPrincipalName) == targetUser
    or tostring(TargetResource.displayName) has targetUser
| project
    TimeGenerated,
    OperationName,
    RoleName = tostring(TargetResource.displayName),
    ModifiedProperties = TargetResource.modifiedProperties,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName)
| order by TimeGenerated desc
```

#### Query 2B: Recent Account Changes

```kql
// ============================================================
// Query 2B: Recent Account Changes
// Purpose: Check for account modifications in the 72 hours
//          surrounding the alert - password resets, MFA changes,
//          new device registrations, app consents
// Table: AuditLogs
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
// Check 72 hours before and after the alert
let changeWindow = 72h;
AuditLogs
| where TimeGenerated between ((alertTime - changeWindow) .. (alertTime + changeWindow))
// Filter for operations relevant to account compromise
| where OperationName in (
    // Password changes
    "Reset password (by admin)",
    "Reset user password",
    "Change password (self-service)",
    "Change user password",
    // MFA / security info changes
    "Register security info",
    "User registered security info",
    "User deleted security info",
    "Update StsRefreshTokenValidFrom",
    "Admin registered security info",
    // Device registration
    "Register device",
    "Add registered owner to device",
    "Add registered users to device",
    // Application consent
    "Consent to application",
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    // Account state changes
    "Update user",
    "Disable account",
    "Enable account",
    "Add user",
    "Delete user"
)
// Check if the target user is either the actor or the target
| mv-expand TargetResource = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) == targetUser
    or tostring(TargetResource.userPrincipalName) == targetUser
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
    // Flag operations occurring AFTER the alert as high priority
    TimingRelativeToAlert = iff(TimeGenerated > alertTime, "AFTER ALERT", "BEFORE ALERT"),
    // Flag suspicious patterns
    SuspiciousIndicator = case(
        OperationName has "security info" and TimeGenerated > alertTime,
            "CRITICAL - MFA change after alert",
        OperationName has "password" and TimeGenerated > alertTime,
            "CRITICAL - Password change after alert",
        OperationName has "Consent to application",
            "HIGH - App consent granted",
        OperationName has "Register device" and TimeGenerated > alertTime,
            "HIGH - New device registered after alert",
        ""
    ),
    CorrelationId
| order by TimeGenerated asc
```

**Performance Notes:**
- Query 2A: Single-row lookup from IdentityInfo - very fast
- Query 2B: Scans 144 hours (6 days) of AuditLogs filtered by specific OperationName values - fast due to narrow filter
- If the organization has high AuditLogs volume (>1M events/day), consider reducing changeWindow to 24h for initial triage

**Tuning Guidance:**
- **Privileged roles list**: Adjust the `has_any` list in Query 2A to match the organization's definition of privileged roles
- **High-value departments**: Adjust the `in` list in Query 2A based on the organization's structure
- **changeWindow**: Default 72h. Reduce to 24h for faster triage, expand to 7d for deeper historical analysis

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Role | Privileged role (Global Admin, etc.) | Standard user |
| Recent MFA change | New MFA method registered within last 72 hours from unfamiliar IP | No recent MFA changes, or change from known IP |
| Recent password change | Password changed within last 48 hours | No recent password change |
| New device registration | New device registered from unfamiliar location | No new devices |
| Account status | Account recently re-enabled after being disabled | Account has been active continuously |

**Next action:**
- If privileged account -> increase priority regardless of other findings
- If recent MFA/password changes detected -> proceed to Step 3 with high concern, likely attacker establishing persistence
- If standard user with no recent changes -> proceed to Step 3

---

### Step 3: Baseline Comparison - Establish Normal Behavior Pattern

**Purpose:** Determine what "normal" looks like for this specific user. Compare the flagged sign-in against 30 days of historical sign-in data. This is the most critical step - you cannot call something anomalous if you do not know what normal looks like.

**Label:** Step 3: Baseline Comparison - Establish Normal Behavior Pattern

**Data needed from:**
- Table: SigninLogs - pull 30 days of historical sign-ins for this specific user
- Table: AADNonInteractiveUserSignInLogs - pull 30 days of non-interactive sign-ins (for complete IP/location picture)

**Baseline metrics to calculate:**
- Average daily sign-in count (interactive + non-interactive)
- Distinct IP addresses per day (typical range)
- Distinct locations (countries, cities) over 30 days
- Distinct devices and browsers used
- Distinct applications accessed
- Typical sign-in hours (business hours vs off-hours pattern)
- Typical ISP/ASN values

#### Query 3A: Interactive Sign-In Baseline (30-day) - MANDATORY

```kql
// ============================================================
// Query 3A: Interactive Sign-In Baseline (30-day)
// Purpose: Calculate what "normal" looks like for this user's
//          interactive sign-ins over the past 30 days, then
//          compare the current sign-in against the baseline
// Table: SigninLogs
// MANDATORY - Do not skip this query
// Expected runtime: 5-15 seconds (depends on user's sign-in volume)
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let alertIP = "198.51.100.42";
let baselinePeriod = 30d;
// Baseline window: from 30d ago to 1d ago (exclude recent day to avoid contamination)
let baselineStart = alertTime - baselinePeriod;
let baselineEnd = alertTime - 1d;
// --- Part 1: Calculate daily aggregates over baseline period ---
let dailyBaseline = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    // Only successful sign-ins for behavior baseline (ResultType is STRING)
    | where ResultType == "0"
    | summarize
        DailySignins = count(),
        DistinctIPs = dcount(IPAddress),
        DistinctLocations = dcount(tostring(Location.countryOrRegion)),
        DistinctCities = dcount(tostring(Location.city)),
        DistinctApps = dcount(AppDisplayName),
        DistinctDevices = dcount(tostring(DeviceDetail.operatingSystem)),
        DistinctBrowsers = dcount(tostring(DeviceDetail.browser))
        by bin(TimeGenerated, 1d);
// --- Part 2: Calculate statistical baseline from daily aggregates ---
let baselineStats = dailyBaseline
    | summarize
        BaselineDays = count(),
        // Sign-in volume
        AvgDailySignins = avg(DailySignins),
        StdevDailySignins = stdev(DailySignins),
        MaxDailySignins = max(DailySignins),
        // IP diversity
        AvgDistinctIPs = avg(DistinctIPs),
        MaxDistinctIPs = max(DistinctIPs),
        // Location diversity
        AvgDistinctLocations = avg(DistinctLocations),
        MaxDistinctLocations = max(DistinctLocations);
// --- Part 3: Collect all known values from baseline ---
let knownIPs = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct IPAddress;
let knownCountries = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct tostring(Location.countryOrRegion);
let knownCities = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct tostring(Location.city);
let knownApps = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct AppDisplayName;
let knownDevices = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct tostring(DeviceDetail.operatingSystem);
let knownBrowsers = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct tostring(DeviceDetail.browser);
// --- Part 4: Analyze typical sign-in hours ---
let typicalHours = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | extend HourOfDay = hourofday(TimeGenerated)
    | summarize SigninsPerHour = count() by HourOfDay
    | order by HourOfDay asc;
// --- Part 5: Get the current sign-in details and compare ---
let currentSignin = SigninLogs
    | where TimeGenerated between ((alertTime - 2h) .. (alertTime + 1h))
    | where UserPrincipalName == targetUser
    | where IPAddress == alertIP
    | take 1
    | extend
        CurrentIP = IPAddress,
        CurrentCountry = tostring(Location.countryOrRegion),
        CurrentCity = tostring(Location.city),
        CurrentApp = AppDisplayName,
        CurrentDevice = tostring(DeviceDetail.operatingSystem),
        CurrentBrowser = tostring(DeviceDetail.browser),
        CurrentHour = hourofday(TimeGenerated);
// --- Part 6: Produce the comparison output ---
currentSignin
| extend
    IsIPNew = iff(CurrentIP in (knownIPs), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsCountryNew = iff(CurrentCountry in (knownCountries), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsCityNew = iff(CurrentCity in (knownCities), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsAppNew = iff(CurrentApp in (knownApps), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsDeviceNew = iff(CurrentDevice in (knownDevices), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsBrowserNew = iff(CurrentBrowser in (knownBrowsers), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS")
// Cross-join with baseline stats for statistical comparison
| extend placeholder = 1
| join kind=inner (baselineStats | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    // Count how many properties are new
    NewPropertyCount = toint(IsIPNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsCountryNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsCityNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsAppNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsDeviceNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsBrowserNew == "NEW - NEVER SEEN IN 30 DAYS"),
    // Overall anomaly assessment
    AnomalyAssessment = case(
        toint(IsIPNew == "NEW - NEVER SEEN IN 30 DAYS")
            + toint(IsCountryNew == "NEW - NEVER SEEN IN 30 DAYS")
            + toint(IsDeviceNew == "NEW - NEVER SEEN IN 30 DAYS")
            + toint(IsBrowserNew == "NEW - NEVER SEEN IN 30 DAYS") >= 3,
        "HIGH ANOMALY - 3+ new properties",
        toint(IsCountryNew == "NEW - NEVER SEEN IN 30 DAYS")
            + toint(IsDeviceNew == "NEW - NEVER SEEN IN 30 DAYS") >= 2,
        "MEDIUM ANOMALY - New country + new device",
        IsIPNew == "NEW - NEVER SEEN IN 30 DAYS",
        "LOW ANOMALY - Only new IP",
        "WITHIN BASELINE - All properties known"
    )
| project
    UserPrincipalName,
    // Current sign-in properties
    CurrentIP,
    CurrentCountry,
    CurrentCity,
    CurrentApp,
    CurrentDevice,
    CurrentBrowser,
    CurrentHour,
    // Baseline comparison
    IsIPNew,
    IsCountryNew,
    IsCityNew,
    IsAppNew,
    IsDeviceNew,
    IsBrowserNew,
    NewPropertyCount,
    // Baseline statistics
    BaselineDays,
    AvgDailySignins,
    StdevDailySignins,
    MaxDailySignins,
    AvgDistinctIPs,
    MaxDistinctIPs,
    AvgDistinctLocations,
    MaxDistinctLocations,
    // Final assessment
    AnomalyAssessment
```

#### Query 3B: Known Values Summary

```kql
// ============================================================
// Query 3B: Known Values Summary
// Purpose: List all known IPs, locations, devices, and apps
//          from the user's 30-day baseline for analyst reference
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let baselinePeriod = 30d;
let baselineStart = alertTime - baselinePeriod;
let baselineEnd = alertTime - 1d;
SigninLogs
| where TimeGenerated between (baselineStart .. baselineEnd)
| where UserPrincipalName == targetUser
| where ResultType == "0"
| summarize
    SigninCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by
        IPAddress,
        Country = tostring(Location.countryOrRegion),
        City = tostring(Location.city),
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        Browser = tostring(DeviceDetail.browser),
        AppDisplayName
| order by SigninCount desc
```

#### Query 3C: Non-Interactive Sign-In Baseline (Supplementary)

```kql
// ============================================================
// Query 3C: Non-Interactive Sign-In Baseline (summarized)
// Purpose: Supplementary baseline from non-interactive sign-ins
//          to capture token refresh patterns, app-based access
// Table: AADNonInteractiveUserSignInLogs
// License: Entra ID P1/P2 required
// Note: Summarized separately per Hasan's recommendation -
//       do NOT union raw data (volume can be enormous)
// Expected runtime: 10-30 seconds (high volume table)
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let alertIP = "198.51.100.42";
let baselinePeriod = 30d;
let baselineStart = alertTime - baselinePeriod;
let baselineEnd = alertTime - 1d;
// Summarize by day to control volume
AADNonInteractiveUserSignInLogs
| where TimeGenerated between (baselineStart .. baselineEnd)
| where UserPrincipalName == targetUser
| where ResultType == "0"
| summarize
    DailyNonInteractiveSignins = count(),
    DistinctIPs = dcount(IPAddress),
    DistinctApps = dcount(AppDisplayName)
    by bin(TimeGenerated, 1d)
| summarize
    BaselineDays = count(),
    AvgDailyNonInteractive = avg(DailyNonInteractiveSignins),
    MaxDailyNonInteractive = max(DailyNonInteractiveSignins),
    AvgDistinctIPsPerDay = avg(DistinctIPs),
    MaxDistinctIPsPerDay = max(DistinctIPs),
    TotalDistinctApps = dcount(DistinctApps)
| extend
    // Check if the alert IP appears in non-interactive history
    AlertIPInNonInteractiveBaseline = toscalar(
        AADNonInteractiveUserSignInLogs
        | where TimeGenerated between (baselineStart .. baselineEnd)
        | where UserPrincipalName == targetUser
        | where IPAddress == alertIP
        | count
    ) > 0
```

**Performance Notes:**
- Query 3A scans 30 days of SigninLogs for a single user - moderate volume
- The `distinct` subqueries (knownIPs, knownCountries, etc.) use materialized temp tables - efficient
- Query 3C scans AADNonInteractiveUserSignInLogs which can be 10-50x the volume of SigninLogs. The daily summarization pattern prevents memory pressure
- If the user is a service account or automation account with thousands of daily sign-ins, consider reducing baselinePeriod to 14d

**Tuning Guidance:**
- **baselinePeriod**: Default 30d. Use 14d for high-volume accounts or recent onboarding scenarios. Use 60d for infrequent users
- **AnomalyAssessment thresholds**: Adjust the case logic based on organizational tolerance
- **ResultType filter**: The baseline only uses successful sign-ins (ResultType == "0"). Include failed sign-ins if you want to see brute force patterns
- **Non-interactive baseline**: Query 3C is optional for E3 environments without P1/P2

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| IP history | IP never seen for this user in 30 days, and not in same ASN as known IPs | IP is in same ASN range as user's known IPs, or was seen weeks ago |
| Location history | Country never seen in 30-day history | User has signed in from this country before |
| Device/browser | Device fingerprint never seen AND browser never seen | User recently started using this device/browser (gradual transition visible) |
| Sign-in time | Sign-in at 3 AM local time when user only signs in during business hours | Sign-in during user's typical working hours |
| Application | User never accessed this application before | Application is in user's regular access pattern |
| Activity volume | Sudden spike in sign-in volume (>2 std dev above baseline) | Normal daily volume |

**Next action:**
- If all metrics are within normal range -> likely false positive, proceed to Step 4 for final verification then close
- If 1-2 metrics are anomalous -> proceed to Step 4 with moderate concern
- If 3+ metrics are anomalous -> proceed to Step 4 and Step 5 with high concern, prepare for containment

---

### Step 4: Check for Correlated Risk Events

**Purpose:** Determine if this unfamiliar sign-in is an isolated event or part of a pattern. Multiple risk events for the same user dramatically increase the probability of true compromise.

**Data needed from:**
- Table: AADUserRiskEvents - all risk events for this user in the past 7 days
- Table: AADRiskyUsers - current risk state of the user
- Table: SecurityAlert - any other alerts for entities associated with this sign-in (same IP, same user)

**What to look for:**
- Other risk detections for the same user (leaked credentials, anonymous IP, impossible travel, anomalous token, MFA fatigue)
- Other users with risk events from the same IP address (indicates shared attack infrastructure)
- Time clustering: multiple risk events within a short window (hours) vs spread over days
- Risk escalation pattern: events getting progressively more severe

#### Query 4A: All Risk Events for This User (7-day window)

```kql
// ============================================================
// Query 4A: All Risk Events for This User (7-day window)
// Purpose: Check if the unfamiliar sign-in is part of a pattern
//          of risk detections for this user
// Table: AADUserRiskEvents
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let correlationWindow = 7d;
AADUserRiskEvents
| where TimeGenerated between ((alertTime - correlationWindow) .. (alertTime + 1d))
| where UserPrincipalName == targetUser
| project
    TimeGenerated,
    UserPrincipalName,
    RiskEventType,
    RiskLevel,
    DetectionTimingType,
    // IpAddress (capital A) in this table
    IpAddress,
    LocationCountry = tostring(Location.countryOrRegion),
    LocationCity = tostring(Location.city),
    CorrelationId,
    Id
| order by TimeGenerated desc
| extend
    // Flag high-risk combinations
    RiskSignificance = case(
        RiskEventType == "leakedCredentials",
            "CRITICAL - Credentials exposed on dark web/paste site",
        RiskEventType == "anonymizedIPAddress",
            "HIGH - Sign-in from anonymizing service (Tor/VPN)",
        RiskEventType == "impossibleTravel",
            "HIGH - Impossible travel detected",
        RiskEventType == "maliciousIPAddress",
            "HIGH - Known malicious IP",
        RiskEventType == "mcasSuspiciousInboxManipulationRules",
            "CRITICAL - Suspicious inbox rule manipulation",
        RiskEventType == "suspiciousInboxForwardingRules",
            "CRITICAL - Suspicious email forwarding",
        RiskEventType == "unfamiliarFeatures",
            "MEDIUM - Unfamiliar sign-in properties (this alert)",
        RiskEventType == "anomalousToken",
            "HIGH - Token anomaly detected",
        RiskEventType == "tokenIssuerAnomaly",
            "CRITICAL - Token issuer anomaly (possible token forgery)",
        RiskEventType == "newCountry",
            "MEDIUM - New country",
        RiskEventType == "passwordSpray",
            "HIGH - Password spray detected",
        strcat("INFO - ", RiskEventType)
    )
```

#### Query 4B: Current User Risk State

```kql
// ============================================================
// Query 4B: Current User Risk State
// Purpose: Check the user's overall risk posture in Identity Protection
// Table: AADRiskyUsers
// Note: This is a STATE table - use arg_max for latest state
// Expected runtime: <3 seconds
// ============================================================
let targetUser = "user@contoso.com";
AADRiskyUsers
| where UserPrincipalName == targetUser
| summarize arg_max(TimeGenerated, *) by UserPrincipalName
| project
    UserPrincipalName,
    RiskLevel,
    RiskState,
    RiskDetail,
    LastUpdated = TimeGenerated,
    // Flag concerning states
    RiskAssessment = case(
        RiskState == "confirmedCompromised",
            "CRITICAL - Confirmed compromised by admin",
        RiskState == "atRisk" and RiskLevel in ("high", "medium"),
            "HIGH - User currently at risk",
        RiskState == "atRisk" and RiskLevel == "low",
            "MEDIUM - User at low risk",
        RiskState == "remediated",
            "INFO - Previously remediated",
        RiskState == "dismissed",
            "INFO - Risk dismissed by admin",
        "INFO - No active risk"
    )
```

#### Query 4C: Other Users Affected by Same IP

```kql
// ============================================================
// Query 4C: Other Users Affected by Same IP
// Purpose: Check if the alert IP was used against other users -
//          indicates shared attack infrastructure or password spray
// Table: AADUserRiskEvents
// Expected runtime: <5 seconds
// ============================================================
let alertIP = "198.51.100.42";
let alertTime = datetime(2026-02-21T14:30:00Z);
let correlationWindow = 7d;
AADUserRiskEvents
| where TimeGenerated between ((alertTime - correlationWindow) .. (alertTime + 1d))
// IpAddress (capital A) in this table
| where IpAddress == alertIP
| summarize
    RiskEventCount = count(),
    RiskEventTypes = make_set(RiskEventType),
    EarliestEvent = min(TimeGenerated),
    LatestEvent = max(TimeGenerated)
    by UserPrincipalName
| order by RiskEventCount desc
| extend
    MultiUserIndicator = iff(
        toscalar(
            AADUserRiskEvents
            | where TimeGenerated between ((alertTime - correlationWindow) .. (alertTime + 1d))
            | where IpAddress == alertIP
            | distinct UserPrincipalName
            | count
        ) > 1,
        "WARNING - Multiple users affected from same IP",
        "Single user affected"
    )
```

#### Query 4D: Correlated Security Alerts

```kql
// ============================================================
// Query 4D: Correlated Security Alerts
// Purpose: Check for other alerts involving the same user or IP
// Table: SecurityAlert
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertIP = "198.51.100.42";
let alertTime = datetime(2026-02-21T14:30:00Z);
let correlationWindow = 7d;
SecurityAlert
| where TimeGenerated between ((alertTime - correlationWindow) .. (alertTime + 1d))
// Extract user entities from the Entities JSON array
| mv-expand Entity = parse_json(Entities)
| where
    // Match user entities
    (Entity.Type == "account" and
        (tostring(Entity.Name) has targetUser or tostring(Entity.UPNSuffix) has targetUser))
    or
    // Match IP entities
    (Entity.Type == "ip" and tostring(Entity.Address) == alertIP)
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Tactics,
    ProviderName,
    // Which entity matched
    MatchedEntity = case(
        Entity.Type == "account", strcat("User: ", tostring(Entity.Name)),
        Entity.Type == "ip", strcat("IP: ", tostring(Entity.Address)),
        "Other"
    ),
    Description
| distinct *
| order by TimeGenerated desc
```

**Performance Notes:**
- All queries in this step scan narrow windows (7 days) with specific user/IP filters - very fast
- Query 4D extracts entities from a JSON array using mv-expand, which can increase row count. The `distinct` at the end deduplicates
- If SecurityAlert has high volume, the mv-expand on Entities can be expensive. Consider adding a pre-filter on AlertName or ProviderName

**Tuning Guidance:**
- **correlationWindow**: Default 7d. Reduce to 3d for faster triage, expand to 14d to catch slow-burn attacks
- **RiskSignificance mapping**: Add organization-specific risk types if custom detections are in use
- **Query 4C (multi-user)**: The toscalar subquery may time out on very large environments. If so, remove it and manually check the result count

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Other risk events | Multiple risk event types for same user in 7 days | This is the only risk event for the user |
| Same IP - other users | Same IP generated risk events for multiple users | IP only flagged for this one user |
| Risk state | User risk state is "atRisk" or "confirmedCompromised" | Risk state is "none" or previously "remediated" |
| Time clustering | Multiple events within 1-4 hours | Single isolated event |
| Leaked credentials | Leaked credential detection present | No leaked credential detections |

**Next action:**
- If multiple risk event types present -> HIGH confidence of compromise, proceed to Step 5 and prepare containment
- If leaked credentials + unfamiliar sign-in -> VERY HIGH confidence, this is classic credential compromise pattern
- If same IP flagged for multiple users -> potential password spray or shared attack infrastructure, escalate
- If isolated single event -> proceed to Step 5 for post-sign-in activity check

---

### Step 5: Analyze Post-Sign-In Activity (Blast Radius Assessment)

**Purpose:** Determine what the account did AFTER the suspicious sign-in. This is where you find evidence of actual compromise - attackers typically act quickly after gaining access. Check for persistence mechanisms, data access, and lateral movement indicators.

**Data needed from:**
- Table: AuditLogs - directory changes made by this user in the 4 hours following the sign-in
- Table: OfficeActivity - email, SharePoint, OneDrive, Teams activity in the 4 hours following the sign-in
- Table: CloudAppEvents - SaaS app activity in the 4 hours following the sign-in

#### Query 5A: Directory Changes After Sign-In (Persistence Detection)

```kql
// ============================================================
// Query 5A: Directory Changes After Sign-In
// Purpose: Check for persistence mechanisms created via
//          directory operations (MFA changes, app consents,
//          role assignments) after the suspicious sign-in
// Table: AuditLogs
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
// Use 4-hour window per Hasan's recommendation (accounts for latency)
let postSignInWindow = 4h;
AuditLogs
| where TimeGenerated between (alertTime .. (alertTime + postSignInWindow))
// Filter for high-risk operations
| where OperationName in (
    // MFA / authentication persistence
    "User registered security info",
    "User deleted security info",
    "Admin registered security info",
    "Register security info",
    "Update StsRefreshTokenValidFrom",
    // Application consent (OAuth abuse)
    "Consent to application",
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Add owner to application",
    "Add app role assignment grant to user",
    // Account manipulation
    "Update user",
    "Reset password (by admin)",
    "Reset user password",
    "Change user password",
    // Device registration
    "Register device",
    "Add registered owner to device",
    // Role escalation
    "Add member to role",
    "Add eligible member to role"
)
| mv-expand TargetResource = TargetResources
// Check if the target user initiated OR is the target of the operation
| where tostring(InitiatedBy.user.userPrincipalName) == targetUser
    or tostring(TargetResource.userPrincipalName) == targetUser
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
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, alertTime),
    // Severity classification for post-sign-in activity
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

#### Query 5B: Email and File Activity After Sign-In

```kql
// ============================================================
// Query 5B: Email and File Activity After Sign-In
// Purpose: Check for inbox rule creation, email forwarding,
//          bulk email access, and file exfiltration patterns
// Table: OfficeActivity
// Note: OfficeActivity has up to 60 min ingestion latency.
//       If the alert is <1 hour old, results may be incomplete.
//       Re-run this query after 1-2 hours for full coverage.
// Expected runtime: 5-10 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
// 4-hour window per Hasan's latency guidance
let postSignInWindow = 4h;
// IP normalization function - OfficeActivity.ClientIP can include port numbers
// and IPv6-mapped formats (Hasan's gotcha)
let cleanIPFromOffice = (rawIP: string) {
    extract(@"(\d+\.\d+\.\d+\.\d+)", 1, rawIP)
};
OfficeActivity
| where TimeGenerated between (alertTime .. (alertTime + postSignInWindow))
// UserId in OfficeActivity uses UPN format
| where UserId == targetUser
| extend CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
| project
    TimeGenerated,
    Operation,
    OfficeWorkload,
    UserId,
    CleanClientIP,
    // Include raw ClientIP for reference
    RawClientIP = ClientIP,
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, alertTime),
    // Classify operations by risk
    RiskCategory = case(
        // PERSISTENCE - Inbox rules
        Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule"),
            "CRITICAL - INBOX RULE",
        // PERSISTENCE - Email forwarding
        Operation in ("Set-Mailbox", "Set-TransportRule") and OfficeWorkload == "Exchange",
            "CRITICAL - MAILBOX FORWARDING",
        // PERSISTENCE - Delegate access
        Operation in ("Add-MailboxPermission", "Add-RecipientPermission"),
            "HIGH - DELEGATE ACCESS",
        // DATA ACCESS - Email
        Operation == "MailItemsAccessed",
            "MONITOR - EMAIL ACCESS",
        Operation == "Send",
            "MONITOR - EMAIL SENT",
        Operation in ("SearchQuery", "SearchStarted"),
            "MONITOR - EMAIL SEARCH",
        // DATA ACCESS - Files
        Operation in ("FileDownloaded", "FileSyncDownloadedFull"),
            "MONITOR - FILE DOWNLOAD",
        Operation in ("FileAccessed", "FileAccessedExtended"),
            "INFO - FILE ACCESS",
        Operation == "FileUploaded",
            "MONITOR - FILE UPLOAD",
        // OTHER
        "INFO"
    ),
    // Extract inbox rule details from Parameters if available
    Parameters
| order by TimeGenerated asc
```

#### Query 5C: Inbox Rule Deep Dive

```kql
// ============================================================
// Query 5C: Inbox Rule Deep Dive
// Purpose: Specifically extract inbox rule creation details -
//          the #1 persistence mechanism in BEC attacks
// Table: OfficeActivity
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let postSignInWindow = 4h;
OfficeActivity
| where TimeGenerated between (alertTime .. (alertTime + postSignInWindow))
| where UserId == targetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
// Parse the Parameters column to extract rule details
| mv-expand Parameter = parse_json(Parameters)
| summarize
    RuleParameters = make_bag(pack(tostring(Parameter.Name), tostring(Parameter.Value)))
    by TimeGenerated, Operation, UserId, ClientIP
| extend
    RuleName = tostring(RuleParameters.Name),
    // These are the critical indicators of malicious inbox rules
    ForwardTo = tostring(RuleParameters.ForwardTo),
    ForwardAsAttachmentTo = tostring(RuleParameters.ForwardAsAttachmentTo),
    RedirectTo = tostring(RuleParameters.RedirectTo),
    DeleteMessage = tostring(RuleParameters.DeleteMessage),
    MarkAsRead = tostring(RuleParameters.MarkAsRead),
    MoveToFolder = tostring(RuleParameters.MoveToFolder),
    SubjectContainsWords = tostring(RuleParameters.SubjectContainsWords),
    FromAddressContainsWords = tostring(RuleParameters.FromAddressContainsWords)
| extend
    // Flag malicious patterns
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

#### Query 5D: Bulk Data Access Summary

```kql
// ============================================================
// Query 5D: Bulk Data Access Summary
// Purpose: Summarize email and file access volumes to detect
//          bulk exfiltration patterns
// Table: OfficeActivity
// Expected runtime: 5-10 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let postSignInWindow = 4h;
OfficeActivity
| where TimeGenerated between (alertTime .. (alertTime + postSignInWindow))
| where UserId == targetUser
| where Operation in (
    "MailItemsAccessed", "FileDownloaded", "FileSyncDownloadedFull",
    "FileAccessed", "FileAccessedExtended", "Send"
)
| summarize
    EventCount = count(),
    EarliestAction = min(TimeGenerated),
    LatestAction = max(TimeGenerated),
    DistinctIPs = dcount(ClientIP)
    by Operation, OfficeWorkload
| extend
    // Flag bulk patterns
    BulkIndicator = case(
        Operation == "MailItemsAccessed" and EventCount > 100,
            "ALERT - Bulk email access (>100 items)",
        Operation == "MailItemsAccessed" and EventCount > 50,
            "WARNING - Elevated email access (>50 items)",
        Operation in ("FileDownloaded", "FileSyncDownloadedFull") and EventCount > 50,
            "ALERT - Bulk file download (>50 files)",
        Operation in ("FileDownloaded", "FileSyncDownloadedFull") and EventCount > 20,
            "WARNING - Elevated file download (>20 files)",
        Operation == "Send" and EventCount > 20,
            "WARNING - High volume email sent (>20) - possible internal phishing",
        "NORMAL"
    )
| order by EventCount desc
```

#### Query 5E: SaaS App Activity After Sign-In (Premium)

```kql
// ============================================================
// Query 5E: SaaS App Activity After Sign-In (Premium)
// Purpose: Check for cloud app activity via Defender for Cloud Apps
// Table: CloudAppEvents
// License: Defender for Cloud Apps required (E5 or standalone)
// Fallback: If unavailable, Queries 5A-5D cover the core checks
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let postSignInWindow = 4h;
CloudAppEvents
| where TimeGenerated between (alertTime .. (alertTime + postSignInWindow))
// AccountDisplayName is primary identifier (not AccountUPN)
// Hasan's gotcha: use display name or AccountObjectId for matching
| where AccountDisplayName has targetUser or AccountId has targetUser
| project
    TimeGenerated,
    ActionType,
    Application,
    AccountDisplayName,
    IPAddress,
    ActivityObjects,
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, alertTime),
    RiskCategory = case(
        ActionType has_any ("MailboxForwardingRuleCreated", "InboxRuleCreated"),
            "CRITICAL - RULE CREATION",
        ActionType has_any ("OAuthAppAuthorized", "AppPermissionGranted"),
            "CRITICAL - APP CONSENT",
        ActionType has_any ("FileDownloaded", "FileCopied"),
            "MONITOR - FILE ACCESS",
        ActionType has_any ("MailSent", "MailForwarded"),
            "MONITOR - EMAIL ACTIVITY",
        "INFO"
    )
| order by TimeGenerated asc
```

**Performance Notes:**
- Query 5B scans 4 hours of OfficeActivity for a single user - fast
- MailItemsAccessed can generate very high volume rows in E5 environments. Query 5D summarizes these to avoid output overflow
- Query 5C uses mv-expand on Parameters, then re-aggregates with make_bag - this handles the variable parameter structure of inbox rules
- If investigating within 1 hour of the alert, note that OfficeActivity data may still be ingesting. Re-run after 2 hours for complete coverage

**Tuning Guidance:**
- **postSignInWindow**: Default 4h (accounts for OfficeActivity latency). For fast triage use 2h but note potential data gaps. For thorough investigation expand to 24h
- **Bulk thresholds**: Query 5D uses >100 email items and >50 file downloads as alert thresholds. Adjust based on the user's typical activity volume from the baseline (Query 3)
- **CloudAppEvents**: Query 5E is optional for E3 environments. Skip if Defender for Cloud Apps is not licensed
- **Inbox rule keywords**: Query 5C checks for financial keywords in SubjectContainsWords. Add industry-specific keywords as needed

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Inbox rules | New rule created that forwards/deletes email | No new inbox rules |
| Email forwarding | Forwarding set to external address | No forwarding changes |
| OAuth apps | New app consent with broad permissions | No new app consents |
| File access | Bulk download of files from SharePoint/OneDrive (>50 in 1 hour) | Normal file access pattern |
| Email access | Mass mailbox access (MailItemsAccessed > 100 in 1 hour) | Normal email reading pattern |
| Sent emails | Phishing-like emails sent to multiple internal users | No unusual sent mail |
| MFA changes | New MFA method registered from unfamiliar IP | No MFA changes |

**Next action:**
- If ANY persistence mechanism found (inbox rule, forwarding, OAuth app, MFA change) -> CONFIRMED COMPROMISE, proceed to Containment immediately
- If bulk data access found -> CONFIRMED COMPROMISE with data exposure, proceed to Containment + Data Loss Assessment
- If no suspicious post-sign-in activity -> proceed to Step 6 for final determination
- If sign-in failed (ResultType != 0) -> limited post-sign-in activity expected, check for password spray pattern

---

### Step 6: Check Source IP Reputation and Context

**Purpose:** Gather intelligence about the source IP address. Determine if it belongs to known attack infrastructure, anonymous proxies, hosting providers, or legitimate ISPs.

#### Query 6A: Threat Intelligence IP Lookup

```kql
// ============================================================
// Query 6A: Threat Intelligence IP Lookup
// Purpose: Check if the alert IP appears in any configured
//          threat intelligence feeds
// Table: ThreatIntelligenceIndicator
// Note: If no TI feeds are configured, this table will be empty.
//       This is an optional enrichment step.
// Expected runtime: <3 seconds
// ============================================================
let alertIP = "198.51.100.42";
ThreatIntelligenceIndicator
| where isnotempty(NetworkIP)
// Only active indicators (Hasan's gotcha)
| where Active == true
| where ExpirationDateTime > now()
| where NetworkIP == alertIP
// Filter for reasonable confidence (Hasan recommends >= 50)
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
    LastUpdatedTimeUtc = TimeGenerated,
    // Classify threat intelligence result
    TIAssessment = case(
        ConfidenceScore >= 80, "HIGH CONFIDENCE - Known malicious IP",
        ConfidenceScore >= 50, "MEDIUM CONFIDENCE - Potentially malicious IP",
        "LOW CONFIDENCE - Weak indicator"
    )
| order by ConfidenceScore desc
```

#### Query 6B: Organizational IP Usage Check

```kql
// ============================================================
// Query 6B: Organizational IP Usage Check
// Purpose: Determine if this IP has been used by other legitimate
//          users in the organization - if yes, it's likely a
//          shared corporate exit IP (VPN, proxy, office)
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let alertIP = "198.51.100.42";
let targetUser = "user@contoso.com";
let lookbackPeriod = 30d;
SigninLogs
| where TimeGenerated > ago(lookbackPeriod)
| where IPAddress == alertIP
// Only successful sign-ins
| where ResultType == "0"
| summarize
    TotalSignins = count(),
    DistinctUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 20),
    EarliestSeen = min(TimeGenerated),
    LatestSeen = max(TimeGenerated),
    DistinctApps = make_set(AppDisplayName, 10)
| extend
    IPClassification = case(
        DistinctUsers > 10,
            "LIKELY CORPORATE - Used by 10+ users (shared exit IP)",
        DistinctUsers > 3,
            "POSSIBLY CORPORATE - Used by multiple users",
        DistinctUsers == 1 and UserList has targetUser,
            "SINGLE USER - Only used by the target user (may be personal IP)",
        DistinctUsers == 1 and not(UserList has targetUser),
            "SINGLE OTHER USER - Used by a different user only",
        DistinctUsers == 0,
            "NEVER SEEN - This IP has never been used for successful sign-ins",
        "UNKNOWN"
    ),
    IsTargetUserIncluded = iff(UserList has targetUser, "Yes", "No")
```

#### Query 6C: UEBA Insights for User and IP (Premium)

```kql
// ============================================================
// Query 6C: UEBA Insights for User and IP (Premium)
// Purpose: Check if Sentinel UEBA has flagged this user or IP
//          with behavioral anomalies
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Note: If UEBA is not enabled, this table will be empty.
//       Fallback: rely on Queries 6A and 6B for IP assessment.
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let lookbackPeriod = 7d;
BehaviorAnalytics
| where TimeGenerated between ((alertTime - lookbackPeriod) .. (alertTime + 1d))
| where UserPrincipalName == targetUser
// InvestigationPriority >= 5 is recommended threshold (Hasan's gotcha)
| where InvestigationPriority >= 5
| project
    TimeGenerated,
    UserPrincipalName,
    ActionType,
    ActivityInsights,
    InvestigationPriority,
    // Extract key insight flags from ActivityInsights dynamic
    FirstTimeISP = tostring(ActivityInsights.FirstTimeUserConnectedViaISP),
    FirstTimeCountry = tostring(ActivityInsights.FirstTimeUserConnectedFromCountry),
    ActivityUncommon = tostring(ActivityInsights.ActivityUncommonlyPerformedByUser),
    DeviceUncommon = tostring(ActivityInsights.FirstTimeUserUsedDevice),
    SourceIPAddress = tostring(ActivityInsights.SourceIPAddress)
| order by InvestigationPriority desc, TimeGenerated desc
```

**Performance Notes:**
- Query 6A: ThreatIntelligenceIndicator is typically a small table - very fast
- Query 6B: 30-day scan of SigninLogs filtered by a single IP address - fast
- Query 6C: BehaviorAnalytics with InvestigationPriority filter - fast. UEBA requires 14+ days of data before generating meaningful results

**Tuning Guidance:**
- **TI ConfidenceScore threshold**: Default >= 50. Increase to >= 80 for high-precision, decrease to >= 25 for maximum coverage with more false positives
- **Organizational IP check (6B) lookbackPeriod**: Default 30d. Expand to 90d to catch IPs used by seasonal workers or infrequent users
- **UEBA InvestigationPriority threshold**: Default >= 5. Decrease to >= 3 for broader coverage, increase to >= 7 for high-confidence anomalies only
- **If no TI feeds**: Skip Query 6A entirely. Perform manual IP enrichment (VirusTotal, AbuseIPDB, Shodan)

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| TI match | IP found in threat intelligence feeds | IP not in any TI feeds |
| IP type | VPS/hosting provider, Tor exit node, anonymous proxy | Residential or corporate ISP |
| Org usage | IP not used by any other user in the organization | IP used by multiple other users (corporate exit IP) |
| UEBA | First-time ISP flagged by UEBA | ISP seen before for this user |
| Geolocation | IP geolocates to high-risk country with no business presence | IP geolocates to country where organization operates |

**Next action:**
- If IP is in TI feeds -> HIGH confidence of compromise, proceed to Containment
- If IP is from hosting/VPN provider + other indicators -> HIGH confidence
- If IP is from legitimate ISP + used by other org users -> LOWER concern, likely false positive
- If inconclusive -> make final determination based on totality of Steps 1-6

---

### Step 7: Final Determination and Classification

**Purpose:** Based on all evidence gathered in Steps 1-6, make a final classification.

**Classification matrix:**

| Classification | Criteria | Action |
|---|---|---|
| **True Positive - Confirmed Compromise** | Post-sign-in persistence found (inbox rules, OAuth app, MFA changes) AND/OR multiple risk events AND/OR TI-matched IP | Immediate containment (see Containment Playbook) |
| **True Positive - Likely Compromise** | Multiple anomalous baseline metrics + suspicious IP + no MFA, but no confirmed post-sign-in abuse yet | Containment recommended, contact user for confirmation |
| **Benign True Positive** | Alert correctly fired (properties ARE unfamiliar) but verified as legitimate user activity (confirmed travel, new device, VPN change) | Close as BTP, document reason, consider tuning |
| **False Positive** | Alert fired due to routine change (ISP rotation, CDN IP, browser update) with all other indicators clean | Close as FP, add to tuning notes |

---

## 6. Containment Playbook

Execute in this order. IMPORTANT: Collect evidence (Section 7 checklist) BEFORE taking containment actions that could alert the attacker or destroy evidence.

### Immediate Actions (within 15 minutes of confirmed compromise):

1. **Revoke all active sessions** - Revoke the user's refresh tokens via Entra ID to immediately invalidate all active sessions. This forces re-authentication on all devices and applications.

2. **Reset password** - Reset the user's password to a strong temporary password. Do NOT communicate the new password via the potentially compromised email account - use an out-of-band channel (phone call, SMS, manager).

3. **Disable suspicious inbox rules** - If inbox rules were created for forwarding/deletion, disable them immediately before the attacker can use them for further compromise.

4. **Block the source IP** - Add the attacker's IP address to Conditional Access as a blocked location (if using named locations) or to the organization's firewall/proxy block list.

### Follow-up Actions (within 1 hour):

5. **Review and remove unauthorized MFA methods** - If the attacker registered a new MFA method, remove it. Verify remaining MFA methods with the user through out-of-band channel.

6. **Revoke OAuth application consents** - If unauthorized applications were granted consent, revoke the application permissions in Entra ID Enterprise Applications.

7. **Remove email forwarding rules** - Check and remove any mailbox forwarding rules (both inbox rules and mailbox-level forwarding via Set-Mailbox).

8. **Review mailbox delegate permissions** - Remove any unauthorized delegate or full-access permissions added to the mailbox.

### Extended Actions (within 24 hours):

9. **Notify the user** - Contact the user via out-of-band channel. Confirm the sign-in was not theirs. Instruct them to re-register MFA and change password.

10. **Check for data exposure** - Review what data was accessed during the compromise window. Determine if notification is required (PII exposure, regulated data).

11. **Hunt for related compromise** - Check if the same attacker IP/infrastructure was used against other accounts. Run the source IP against all sign-in logs.

12. **Review Conditional Access policies** - Determine if a CA policy gap allowed this access (e.g., no MFA requirement for the accessed application, legacy auth allowed).

---

## 7. Evidence Collection Checklist

Preserve the following BEFORE taking containment actions:

- [ ] Full sign-in record from SigninLogs (all columns, not just key columns)
- [ ] Risk event record from AADUserRiskEvents
- [ ] User risk state from AADRiskyUsers
- [ ] 30-day sign-in baseline for the user (SigninLogs + AADNonInteractiveUserSignInLogs)
- [ ] All AuditLogs entries for the user in the 72 hours surrounding the event
- [ ] All OfficeActivity records for the user in the 72 hours surrounding the event
- [ ] Inbox rules snapshot (current state before remediation)
- [ ] Mailbox forwarding configuration snapshot
- [ ] OAuth application consent list for the user
- [ ] MFA registration details for the user
- [ ] IP reputation and TI lookup results
- [ ] UEBA/BehaviorAnalytics records for the user
- [ ] Screenshot of the risk event in the Entra ID portal
- [ ] Timeline of all events (chronological reconstruction)

---

## 8. Escalation Criteria

### Escalate to Senior Analyst when:
- The compromised account is a Global Administrator or Security Administrator
- Multiple users appear compromised from the same attack infrastructure
- Evidence of data exfiltration is found (bulk downloads, email forwarding to external)
- The attacker has registered persistence mechanisms (OAuth apps with broad permissions)
- The compromise timeline exceeds 48 hours (attacker had extended access)

### Escalate to Customer/Management when:
- Confirmed credential compromise with verified post-sign-in abuse
- Any data exposure involving PII, financial data, or regulated information
- Compromise of executive or finance team accounts (high BEC risk)
- Evidence of internal phishing from the compromised account (other users may be affected)
- The attack pattern suggests a targeted campaign (not opportunistic)

### Escalate to Incident Response Team when:
- Evidence of nation-state or advanced persistent threat (APT) tactics
- Compromise has spread to multiple accounts
- Attacker has gained administrative privileges
- Evidence of Azure resource access or subscription-level changes
- Ransomware precursors detected (mass credential harvesting, lateral movement tools)

---

## 9. False Positive Documentation

### Common Benign Scenarios

**1. User traveling for business**
- Pattern: Unfamiliar location (different country/city) but sign-in time aligns with travel schedule
- How to confirm: Check calendar for travel events, ask user or manager via out-of-band channel
- Tuning note: Consider creating named locations for common travel destinations

**2. New corporate VPN or proxy deployment**
- Pattern: Multiple users trigger unfamiliar sign-in from the same new IP range simultaneously
- How to confirm: Check with IT if VPN/proxy infrastructure changed, verify IP belongs to known VPN provider
- Tuning note: Add new VPN IP ranges to named/trusted locations in Conditional Access

**3. User's ISP rotated IP addresses**
- Pattern: Only IP/ASN changed, device + browser + location all remain the same
- How to confirm: IP geolocates to user's known city, ISP matches user's known provider
- Tuning note: This is expected behavior, generally safe to close if only property is IP change within same location

**4. New device or browser**
- Pattern: User switched to new laptop/phone or updated browser, all other properties normal
- How to confirm: Device is managed/compliant in Intune, or user confirms new device through out-of-band channel
- Tuning note: Managed/compliant devices should be weighted lower for unfamiliar device alerts

**5. First sign-in after extended absence**
- Pattern: User returns from leave, sabbatical, or long absence. ML baseline has decayed
- How to confirm: Check HR records or manager confirmation of absence
- Tuning note: Accounts inactive for >30 days will trigger on first sign-in due to baseline expiration

**6. Seasonal workers or contractors**
- Pattern: Users who only sign in during specific periods (seasonal, project-based)
- How to confirm: Verify employment type and expected access pattern
- Tuning note: Consider separate risk policies for contractor/seasonal accounts

---

## 10. MITRE ATT&CK Mapping

### Primary Technique

**T1078.004 - Valid Accounts: Cloud Accounts** (Confirmed)

The "Unfamiliar sign-in properties" alert directly detects the use of valid cloud credentials from properties that deviate from the legitimate user's established pattern. This maps to T1078.004 across four tactics: Initial Access, Persistence, Defense Evasion, and Privilege Escalation.

### Detection Coverage Matrix

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

### Attack Chains

**Chain 1: AiTM Phishing -> BEC (Most Common)**

```
T1566.002 Spearphishing Link
    | User clicks phishing link
T1539 Steal Web Session Cookie (via AiTM proxy)
    | Attacker captures session cookie/token
T1078.004 Valid Accounts: Cloud Accounts  <-- THIS ALERT FIRES HERE
    | Attacker establishes persistence
T1098 Account Manipulation (MFA registration)
T1556.006 Modify Authentication Process: MFA
T1564.008 Email Hiding Rules (inbox rule)
T1114.003 Email Forwarding Rule
    | Attacker conducts BEC
T1114.002 Remote Email Collection
T1534 Internal Spearphishing
```

Coverage: 6/9 techniques detected, 2 partially, 1 not covered

**Chain 2: Password Spray -> Account Takeover**

```
T1110.003 Password Spraying
    | Valid credential found
T1078.004 Valid Accounts: Cloud Accounts  <-- THIS ALERT FIRES HERE
    | Attacker establishes persistence
T1098.003 Additional Cloud Roles
T1528 Steal Application Access Token (OAuth consent)
    | Attacker accesses resources
T1530 Data from Cloud Storage Object
```

Coverage: 5/9 techniques detected, 1 partially, 3 not covered

**Chain 3: Credential Stuffing -> BEC (Financially Motivated)**

```
T1110.004 Credential Stuffing (from breach database)
    | Valid credential confirmed
T1078.004 Valid Accounts: Cloud Accounts  <-- THIS ALERT FIRES HERE
    | Rapid persistence
T1564.008 Email Hiding Rules
T1114.003 Email Forwarding Rule
    | BEC execution
T1534 Internal Spearphishing
```

Coverage: 4/5 techniques detected, 1 partially. Best coverage of all three chains.

### Coverage Gaps

| Gap # | Technique | ID | Risk Level | Recommendation |
|---|---|---|---|---|
| 1 | Phishing: Spearphishing Link | T1566.002 | **High** | Create linked runbook "AiTM Phishing Investigation" using MDO data |
| 2 | MFA Request Generation (MFA fatigue) | T1621 | **Medium** | Add supplementary query for repeated MFA failures from alert IP |
| 3 | Exfiltration Over Web Service | T1567.002 | **Medium** | Requires Cloud App Security or DLP integration |
| 4 | Transfer Data to Cloud Account | T1537 | **Low** | Requires Azure resource logs (AzureDiagnostics) |
| 5 | Web Session Cookie replay | T1550.004 | **Medium** | Document as known limitation |

> For detailed threat actor profiles, per-technique analysis, and full confidence assessments, see [MITRE Coverage](../../mitre-coverage.md).
---

## 11. Query Summary

| Query | Step | Tables | Purpose | License | Required |
|---|---|---|---|---|---|
| 1 | Step 1 | AADUserRiskEvents, SigninLogs | Extract alert entities and sign-in context | Entra ID P2 | Yes |
| 2A | Step 2 | IdentityInfo | User context and privilege level | Sentinel UEBA | Optional (has fallback) |
| 2A-FB | Step 2 | AuditLogs | Fallback: privileged role check | Entra ID Free | Fallback |
| 2B | Step 2 | AuditLogs | Recent account changes (72h window) | Entra ID Free | Yes |
| 3A | Step 3 | SigninLogs | 30-day interactive sign-in baseline | Entra ID Free | **MANDATORY** |
| 3B | Step 3 | SigninLogs | Known values summary (reference) | Entra ID Free | Yes |
| 3C | Step 3 | AADNonInteractiveUserSignInLogs | Non-interactive baseline supplement | Entra ID P1/P2 | Recommended |
| 4A | Step 4 | AADUserRiskEvents | All risk events for user (7d) | Entra ID P2 | Yes |
| 4B | Step 4 | AADRiskyUsers | Current user risk state | Entra ID P2 | Yes |
| 4C | Step 4 | AADUserRiskEvents | Other users from same IP | Entra ID P2 | Yes |
| 4D | Step 4 | SecurityAlert | Correlated security alerts | Sentinel | Yes |
| 5A | Step 5 | AuditLogs | Directory changes (persistence) | Entra ID Free | Yes |
| 5B | Step 5 | OfficeActivity | Email and file activity | M365 E3+ | Yes |
| 5C | Step 5 | OfficeActivity | Inbox rule deep dive | M365 E3+ | Yes |
| 5D | Step 5 | OfficeActivity | Bulk data access summary | M365 E3+ | Yes |
| 5E | Step 5 | CloudAppEvents | SaaS app activity | MCAS / E5 | Optional |
| 6A | Step 6 | ThreatIntelligenceIndicator | IP reputation (TI feeds) | Sentinel + TI | Optional |
| 6B | Step 6 | SigninLogs | Organizational IP usage | Entra ID Free | Yes |
| 6C | Step 6 | BehaviorAnalytics | UEBA insights | Sentinel UEBA | Optional |

**Total: 18 queries (13 required, 2 recommended, 3 optional)**

**Minimum license for core investigation:** Entra ID P2 + M365 E3 + Sentinel (14 queries)
**Full investigation:** M365 E5 + Sentinel UEBA + TI feeds (all 18 queries)

---

## Appendix A: Datatable Tests

All queries include datatable-based inline tests with synthetic data. Each test has a minimum of 10 benign + 5 malicious rows to validate query logic without access to production data.

### Test 1: Query 1 - Extract Alert Entities

```kql
// ============================================================
// TEST: Query 1 - Extract Alert Entities and Sign-In Details
// Synthetic data: 5 malicious + 10 benign risk events / sign-ins
// ============================================================
let testRiskEvents = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    RiskEventType: string,
    RiskLevel: string,
    DetectionTimingType: string,
    IpAddress: string,
    Location: dynamic,
    CorrelationId: string,
    Id: string
) [
    // MALICIOUS 1: unfamiliar sign-in from suspicious IP (target - should match)
    datetime(2026-02-21T14:30:00Z), "user@contoso.com", "unfamiliarFeatures", "high", "realtime",
        "198.51.100.42", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "corr-001", "risk-001",
    // MALICIOUS 2: same user, different malicious IP, offline detection
    datetime(2026-02-21T06:00:00Z), "user@contoso.com", "unfamiliarFeatures", "medium", "offline",
        "198.51.100.99", dynamic({"city":"Beijing","countryOrRegion":"CN"}),
        "corr-010", "risk-010",
    // MALICIOUS 3: leaked credentials for same user (different risk type - should NOT match)
    datetime(2026-02-21T14:00:00Z), "user@contoso.com", "leakedCredentials", "high", "offline",
        "198.51.100.42", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "corr-003", "risk-003",
    // MALICIOUS 4: same IP targeting different user (spray indicator)
    datetime(2026-02-21T14:32:00Z), "victim2@contoso.com", "unfamiliarFeatures", "medium", "realtime",
        "198.51.100.42", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "corr-011", "risk-011",
    // MALICIOUS 5: anonymous IP for different user
    datetime(2026-02-21T13:00:00Z), "victim3@contoso.com", "anonymizedIPAddress", "high", "realtime",
        "198.51.100.50", dynamic({"city":"","countryOrRegion":""}),
        "corr-012", "risk-012",
    // BENIGN 1: user traveling (different user - should NOT match target)
    datetime(2026-02-21T10:15:00Z), "traveler@contoso.com", "unfamiliarFeatures", "low", "offline",
        "203.0.113.10", dynamic({"city":"Tokyo","countryOrRegion":"JP"}),
        "corr-002", "risk-002",
    // BENIGN 2: different user, normal unfamiliar sign-in
    datetime(2026-02-21T14:20:00Z), "other@contoso.com", "unfamiliarFeatures", "medium", "realtime",
        "10.0.0.1", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        "corr-004", "risk-004",
    // BENIGN 3: ISP rotation triggered alert for different user
    datetime(2026-02-21T09:00:00Z), "john.doe@contoso.com", "unfamiliarFeatures", "low", "offline",
        "85.100.50.30", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        "corr-005", "risk-005",
    // BENIGN 4: new device triggered alert for different user
    datetime(2026-02-21T08:30:00Z), "jane.smith@contoso.com", "unfamiliarFeatures", "low", "offline",
        "10.1.1.100", dynamic({"city":"Ankara","countryOrRegion":"TR"}),
        "corr-006", "risk-006",
    // BENIGN 5: VPN change triggered alert
    datetime(2026-02-21T11:00:00Z), "contractor@contoso.com", "unfamiliarFeatures", "low", "offline",
        "172.16.0.1", dynamic({"city":"London","countryOrRegion":"GB"}),
        "corr-007", "risk-007",
    // BENIGN 6: seasonal worker returning
    datetime(2026-02-20T09:00:00Z), "seasonal@contoso.com", "unfamiliarFeatures", "low", "offline",
        "85.100.50.40", dynamic({"city":"Izmir","countryOrRegion":"TR"}),
        "corr-008", "risk-008",
    // BENIGN 7: browser update triggered alert
    datetime(2026-02-21T07:45:00Z), "dev.user@contoso.com", "unfamiliarFeatures", "low", "offline",
        "10.1.1.50", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        "corr-009", "risk-009",
    // BENIGN 8: empty location (edge case - non-interactive sign-in)
    datetime(2026-02-21T12:00:00Z), "svc.account@contoso.com", "unfamiliarFeatures", "low", "offline",
        "10.1.1.200", dynamic(null),
        "corr-013", "risk-013",
    // BENIGN 9: mobile user on cellular network
    datetime(2026-02-21T16:00:00Z), "mobile.user@contoso.com", "unfamiliarFeatures", "low", "offline",
        "100.64.0.1", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        "corr-014", "risk-014",
    // BENIGN 10: outside lookback window (should NOT match any query)
    datetime(2026-02-20T02:00:00Z), "user@contoso.com", "unfamiliarFeatures", "low", "offline",
        "198.51.100.42", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "corr-015", "risk-015"
];
let testSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: dynamic,
    DeviceDetail: dynamic,
    UserAgent: string,
    AppDisplayName: string,
    ResourceDisplayName: string,
    ClientAppUsed: string,
    AuthenticationRequirement: string,
    MfaDetail: dynamic,
    ConditionalAccessStatus: string,
    ResultType: string,
    CorrelationId: string,
    SessionId: string
) [
    // MALICIOUS 1: unknown device, no MFA, suspicious browser (target - should match)
    datetime(2026-02-21T14:29:55Z), "user@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Linux","browser":"Python/3.9 aiohttp/3.8","isCompliant":"false","isManaged":"false","trustType":""}),
        "python-requests/2.28.1", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-001", "sess-001",
    // MALICIOUS 2: different malicious IP, offline
    datetime(2026-02-21T05:59:00Z), "user@contoso.com", "198.51.100.99",
        dynamic({"city":"Beijing","countryOrRegion":"CN"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Firefox 100.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 Firefox/100.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-010", "sess-010",
    // MALICIOUS 3: leaked credentials sign-in
    datetime(2026-02-21T13:58:00Z), "user@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Linux","browser":"curl/7.88","isCompliant":"false","isManaged":"false","trustType":""}),
        "curl/7.88.0", "Azure Portal", "Windows Azure Service Management API", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-003", "sess-003",
    // MALICIOUS 4: spray victim sign-in
    datetime(2026-02-21T14:31:55Z), "victim2@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Linux","browser":"Python/3.9 aiohttp/3.8","isCompliant":"false","isManaged":"false","trustType":""}),
        "python-requests/2.28.1", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-011", "sess-011",
    // MALICIOUS 5: anonymous IP sign-in
    datetime(2026-02-21T12:59:00Z), "victim3@contoso.com", "198.51.100.50",
        dynamic({"city":"","countryOrRegion":""}),
        dynamic({"operatingSystem":"Linux","browser":"Tor Browser 12.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 Tor/12.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-012", "sess-012",
    // BENIGN 1: traveler with MFA passed
    datetime(2026-02-21T10:14:50Z), "traveler@contoso.com", "203.0.113.10",
        dynamic({"city":"Tokyo","countryOrRegion":"JP"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0","isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-002", "sess-002",
    // BENIGN 2: normal user, managed device
    datetime(2026-02-21T14:19:00Z), "other@contoso.com", "10.0.0.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Edge 120.0","isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Edg/120.0", "Microsoft Teams", "Microsoft Teams", "Mobile Apps and Desktop clients",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppOTP","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-004", "sess-004",
    // BENIGN 3: ISP rotation
    datetime(2026-02-21T08:59:00Z), "john.doe@contoso.com", "85.100.50.30",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0","isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-005", "sess-005",
    // BENIGN 4: new device
    datetime(2026-02-21T08:29:00Z), "jane.smith@contoso.com", "10.1.1.100",
        dynamic({"city":"Ankara","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"macOS 14","browser":"Safari 17.0","isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Safari/17.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppOTP","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-006", "sess-006",
    // BENIGN 5: VPN change
    datetime(2026-02-21T10:59:00Z), "contractor@contoso.com", "172.16.0.1",
        dynamic({"city":"London","countryOrRegion":"GB"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0","isCompliant":"false","isManaged":"false","trustType":"Workplace"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-007", "sess-007",
    // BENIGN 6: seasonal worker
    datetime(2026-02-20T08:59:00Z), "seasonal@contoso.com", "85.100.50.40",
        dynamic({"city":"Izmir","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 119.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 Chrome/119.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"OneWaySMS","authDetail":"SMS"}),
        "success", "0", "corr-008", "sess-008",
    // BENIGN 7: browser update
    datetime(2026-02-21T07:44:00Z), "dev.user@contoso.com", "10.1.1.50",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Ubuntu 22.04","browser":"Chrome 121.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 Chrome/121.0", "Azure Portal", "Windows Azure Service Management API", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-009", "sess-009",
    // BENIGN 8: empty location edge case (service account)
    datetime(2026-02-21T11:59:00Z), "svc.account@contoso.com", "10.1.1.200",
        dynamic(null),
        dynamic({"operatingSystem":"","browser":"","isCompliant":"","isManaged":"","trustType":""}),
        "", "Microsoft Graph", "Microsoft Graph", "Mobile Apps and Desktop clients",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-013", "sess-013",
    // BENIGN 9: mobile user
    datetime(2026-02-21T15:59:00Z), "mobile.user@contoso.com", "100.64.0.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"iOS 17","browser":"Safari","isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Mobile Safari", "Microsoft Outlook", "Microsoft Office 365", "Mobile Apps and Desktop clients",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-014", "sess-014",
    // BENIGN 10: outside lookback window
    datetime(2026-02-20T01:59:00Z), "user@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Linux","browser":"Python/3.9","isCompliant":"false","isManaged":"false","trustType":""}),
        "python-requests/2.28.1", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-015", "sess-015"
];
// --- Test execution: should return 1 row for user@contoso.com unfamiliarFeatures ---
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let alertIP = "198.51.100.42";
let lookbackWindow = 2h;
let riskEvent = testRiskEvents
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    | where RiskEventType == "unfamiliarFeatures"
    | where IpAddress == alertIP
    | project
        RiskTimeGenerated = TimeGenerated,
        UserPrincipalName,
        RiskEventType,
        RiskLevel,
        DetectionTimingType,
        RiskIpAddress = IpAddress,
        RiskLocation = Location,
        CorrelationId,
        Id;
let signinDetails = testSigninLogs
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    | project
        SigninTimeGenerated = TimeGenerated,
        UserPrincipalName,
        IPAddress,
        Location,
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceBrowser = tostring(DeviceDetail.browser),
        DeviceIsCompliant = tostring(DeviceDetail.isCompliant),
        DeviceIsManaged = tostring(DeviceDetail.isManaged),
        DeviceTrustType = tostring(DeviceDetail.trustType),
        UserAgent,
        AppDisplayName,
        ResourceDisplayName,
        ClientAppUsed,
        AuthenticationRequirement,
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA performed"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), ""),
        ConditionalAccessStatus,
        ResultType,
        ResultDescription = iff(ResultType == "0", "Success", ResultType),
        CorrelationId,
        SessionId;
riskEvent
| join kind=inner signinDetails on CorrelationId, UserPrincipalName
| project
    RiskTimeGenerated,
    DetectionTimingType,
    RiskLevel,
    RiskEventType,
    UserPrincipalName,
    IPAddress,
    LocationCity = tostring(Location.city),
    LocationCountry = tostring(Location.countryOrRegion),
    DeviceOS,
    DeviceBrowser,
    DeviceIsCompliant,
    DeviceIsManaged,
    DeviceTrustType,
    UserAgent,
    AppDisplayName,
    ResourceDisplayName,
    ClientAppUsed,
    AuthenticationRequirement,
    MfaAuthMethod,
    MfaAuthDetail,
    ConditionalAccessStatus,
    ResultType,
    ResultDescription,
    CorrelationId,
    SessionId,
    SigninTimeGenerated
| order by RiskTimeGenerated desc
// Expected: 1 row - user@contoso.com, high risk, realtime, Moscow/RU,
//           Linux/Python browser, no MFA, single factor, notApplied CA
```

### Test 2: Query 2B - Recent Account Changes

```kql
// ============================================================
// TEST: Query 2B - Recent Account Changes
// Synthetic data: 6 malicious + 12 benign = 18 rows
// ============================================================
let testAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    Category: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    CorrelationId: string
) [
    // --- MALICIOUS 1: MFA method registered AFTER the alert ---
    datetime(2026-02-21T15:05:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User",
            "modifiedProperties":[{"displayName":"StrongAuthenticationMethod","oldValue":"[]","newValue":"[{\"MethodType\":6}]"}]}]),
        "audit-m01",
    // --- MALICIOUS 2: OAuth app consent AFTER the alert (broad permissions) ---
    datetime(2026-02-21T15:15:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"Suspicious Mail Reader App","modifiedProperties":[
            {"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"Mail.Read, Mail.ReadWrite, Files.ReadWrite.All"}]}]),
        "audit-m02",
    // --- MALICIOUS 3: Password reset by admin AFTER alert (containment or attacker) ---
    datetime(2026-02-21T16:00:00Z), "Reset password (by admin)", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User","modifiedProperties":[]}]),
        "audit-m03",
    // --- MALICIOUS 4: New device registration AFTER alert ---
    datetime(2026-02-21T15:30:00Z), "Register device", "DeviceManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"DESKTOP-UNKNOWN","modifiedProperties":[]}]),
        "audit-m04",
    // --- MALICIOUS 5: Delegated permission grant AFTER alert (API abuse) ---
    datetime(2026-02-21T15:40:00Z), "Add delegated permission grant", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"EvilApp","modifiedProperties":[
            {"displayName":"DelegatedPermissionGrant.Scope","oldValue":"","newValue":"Mail.ReadWrite User.Read.All Directory.Read.All"}]}]),
        "audit-m05",
    // --- MALICIOUS 6: Deleted existing MFA method AFTER alert (defense evasion) ---
    datetime(2026-02-21T15:50:00Z), "User deleted security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User",
            "modifiedProperties":[{"displayName":"StrongAuthenticationMethod","oldValue":"[{\"MethodType\":1}]","newValue":"[]"}]}]),
        "audit-m06",
    // --- BENIGN 1: Password self-service reset 2 days BEFORE alert ---
    datetime(2026-02-19T09:00:00Z), "Change password (self-service)", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User","modifiedProperties":[]}]),
        "audit-b01",
    // --- BENIGN 2: Security info registration 1 week BEFORE (onboarding) ---
    datetime(2026-02-14T11:00:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User","modifiedProperties":[]}]),
        "audit-b02",
    // --- BENIGN 3: Admin updating a different user ---
    datetime(2026-02-21T12:00:00Z), "Update user", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"other@contoso.com","displayName":"Other User","modifiedProperties":[]}]),
        "audit-b03",
    // --- BENIGN 4: Different user's app consent (Teams - standard app) ---
    datetime(2026-02-21T14:00:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"other@contoso.com"}}),
        dynamic([{"displayName":"Microsoft Teams","modifiedProperties":[]}]),
        "audit-b04",
    // --- BENIGN 5: Normal device registration 10 days BEFORE alert ---
    datetime(2026-02-11T10:00:00Z), "Register device", "DeviceManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"DESKTOP-CORP01","modifiedProperties":[]}]),
        "audit-b05",
    // --- BENIGN 6: Admin-initiated password reset for different user ---
    datetime(2026-02-20T08:00:00Z), "Reset password (by admin)", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"newuser@contoso.com","displayName":"New User","modifiedProperties":[]}]),
        "audit-b06",
    // --- BENIGN 7: Target user consented to Teams BEFORE alert (normal) ---
    datetime(2026-02-19T14:00:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"Microsoft Teams","modifiedProperties":[
            {"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"Chat.ReadWrite"}]}]),
        "audit-b07",
    // --- BENIGN 8: IT admin enabling account for new hire (different user) ---
    datetime(2026-02-21T09:00:00Z), "Enable account", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"newhire@contoso.com","displayName":"New Hire","modifiedProperties":[]}]),
        "audit-b08",
    // --- BENIGN 9: User profile update BEFORE alert (changed phone number) ---
    datetime(2026-02-20T16:00:00Z), "Update user", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User",
            "modifiedProperties":[{"displayName":"StrongAuthenticationPhoneAppDetail","oldValue":"old","newValue":"new"}]}]),
        "audit-b09",
    // --- BENIGN 10: App role assignment for different user ---
    datetime(2026-02-21T11:00:00Z), "Add app role assignment to service principal", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"displayName":"Contoso Internal Portal","modifiedProperties":[]}]),
        "audit-b10",
    // --- BENIGN 11: Security info registration by different user (same day) ---
    datetime(2026-02-21T10:00:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"colleague@contoso.com"}}),
        dynamic([{"userPrincipalName":"colleague@contoso.com","displayName":"Colleague","modifiedProperties":[]}]),
        "audit-b11",
    // --- BENIGN 12: Target user password change 3 days BEFORE alert (routine rotation) ---
    datetime(2026-02-18T08:30:00Z), "Change user password", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User","modifiedProperties":[]}]),
        "audit-b12"
];
// --- Test execution ---
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let changeWindow = 72h;
testAuditLogs
| where TimeGenerated between ((alertTime - changeWindow) .. (alertTime + changeWindow))
| where OperationName in (
    "Reset password (by admin)", "Reset user password", "Change password (self-service)",
    "Change user password", "Register security info", "User registered security info",
    "User deleted security info", "Update StsRefreshTokenValidFrom", "Admin registered security info",
    "Register device", "Add registered owner to device", "Add registered users to device",
    "Consent to application", "Add app role assignment to service principal",
    "Add delegated permission grant", "Update user", "Disable account", "Enable account",
    "Add user", "Delete user"
)
| mv-expand TargetResource = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) == targetUser
    or tostring(TargetResource.userPrincipalName) == targetUser
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
    TimingRelativeToAlert = iff(TimeGenerated > alertTime, "AFTER ALERT", "BEFORE ALERT"),
    SuspiciousIndicator = case(
        OperationName has "security info" and TimeGenerated > alertTime,
            "CRITICAL - MFA change after alert",
        OperationName has "password" and TimeGenerated > alertTime,
            "CRITICAL - Password change after alert",
        OperationName has "Consent to application",
            "HIGH - App consent granted",
        OperationName has "Register device" and TimeGenerated > alertTime,
            "HIGH - New device registered after alert",
        ""
    ),
    CorrelationId
| order by TimeGenerated asc
// Expected: 13 rows matching user@contoso.com (as initiator or target)
// BENIGN (7 rows - before alert or routine):
// - Change user password (BEFORE, no indicator)
// - Change password self-service (BEFORE, no indicator)
// - Security info registration (BEFORE, no indicator)
// - Register device DESKTOP-CORP01 (BEFORE, no indicator)
// - Consent to Microsoft Teams (BEFORE, indicator "HIGH" but legitimate app pre-alert)
// - Update user phone (BEFORE, no indicator)
// MALICIOUS (6 rows - post-alert attacker activity):
// - User registered security info (AFTER, "CRITICAL - MFA change after alert")
// - Consent to Suspicious Mail Reader App (AFTER, "HIGH - App consent granted")
// - Register device DESKTOP-UNKNOWN (AFTER, "HIGH - New device registered after alert")
// - Add delegated permission grant (AFTER, no specific indicator - app consent logic)
// - User deleted security info (AFTER, "CRITICAL - MFA change after alert")
// - Reset password by admin (AFTER, "CRITICAL - Password change after alert")
// Rows filtered out: 5 other-user rows (b03, b04, b06, b08, b10, b11) don't match targetUser
```

### Test 3: Query 3A - Baseline Comparison

```kql
// ============================================================
// TEST: Query 3A - Baseline Comparison
// Synthetic data: 12 benign baseline + 1 excluded failed + 5 anomalous = 18 rows
// ============================================================
let baselineSignins = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: dynamic,
    DeviceDetail: dynamic,
    AppDisplayName: string,
    ResultType: string
) [
    // --- BENIGN 1: Normal office sign-in (Windows/Chrome from Istanbul) ---
    datetime(2026-01-22T09:00:00Z), "user@contoso.com", "10.1.1.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "0",
    // --- BENIGN 2: Same pattern, next day ---
    datetime(2026-01-23T10:00:00Z), "user@contoso.com", "10.1.1.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "0",
    // --- BENIGN 3: Secondary office IP, Teams ---
    datetime(2026-01-24T08:30:00Z), "user@contoso.com", "10.1.1.2",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Teams", "0",
    // --- BENIGN 4: Regular weekday pattern ---
    datetime(2026-01-25T09:15:00Z), "user@contoso.com", "10.1.1.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "0",
    // --- BENIGN 5: Occasional Edge browser use (same location) ---
    datetime(2026-01-26T14:00:00Z), "user@contoso.com", "10.1.1.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Edge 120.0"}),
        "Azure Portal", "0",
    // --- BENIGN 6: Evening home IP (same city - WFH) ---
    datetime(2026-01-27T19:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "0",
    // --- BENIGN 7: Back to office ---
    datetime(2026-01-28T09:00:00Z), "user@contoso.com", "10.1.1.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "0",
    // --- BENIGN 8: Consistent pattern ---
    datetime(2026-01-29T09:30:00Z), "user@contoso.com", "10.1.1.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "0",
    // --- BENIGN 9: Mobile device usage (iPhone/Safari) ---
    datetime(2026-01-30T08:45:00Z), "user@contoso.com", "10.1.1.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"iPhone","browser":"Safari"}),
        "Microsoft Outlook", "0",
    // --- BENIGN 10: Secondary office IP ---
    datetime(2026-01-31T10:00:00Z), "user@contoso.com", "10.1.1.2",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "0",
    // --- BENIGN 11: SharePoint access from home IP ---
    datetime(2026-02-03T20:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "SharePoint Online", "0",
    // --- BENIGN 12: Power BI access during business hours ---
    datetime(2026-02-10T11:00:00Z), "user@contoso.com", "10.1.1.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Edge 120.0"}),
        "Power BI Service", "0",
    // --- EXCLUDED: Failed sign-in (should not contribute to baseline) ---
    datetime(2026-02-01T03:00:00Z), "user@contoso.com", "198.51.100.99",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Linux","browser":"Firefox"}),
        "Microsoft Office 365", "50126"
];
// Anomalous sign-ins to compare against baseline (5 malicious variants)
let currentSignin = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: dynamic,
    DeviceDetail: dynamic,
    AppDisplayName: string,
    ResultType: string
) [
    // --- MALICIOUS 1: Classic attack - new country, new device, bot-like browser ---
    datetime(2026-02-21T14:30:00Z), "user@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Linux","browser":"Python/3.9 aiohttp/3.8"}),
        "Microsoft Office 365", "0",
    // --- MALICIOUS 2: New country + known device (credential theft scenario) ---
    datetime(2026-02-21T14:35:00Z), "user@contoso.com", "203.0.113.10",
        dynamic({"city":"Lagos","countryOrRegion":"NG"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "0",
    // --- MALICIOUS 3: Known city but new IP + new browser (AiTM proxy) ---
    datetime(2026-02-21T14:40:00Z), "user@contoso.com", "192.0.2.50",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Headless Chrome/120.0"}),
        "Microsoft Office 365", "0",
    // --- MALICIOUS 4: Tor exit node accessing Graph API (unusual app) ---
    datetime(2026-02-21T14:45:00Z), "user@contoso.com", "185.220.101.1",
        dynamic({"city":"Frankfurt","countryOrRegion":"DE"}),
        dynamic({"operatingSystem":"Linux","browser":"curl/7.88"}),
        "Microsoft Graph", "0",
    // --- MALICIOUS 5: VPS IP with all-new properties (commodity attacker) ---
    datetime(2026-02-21T14:50:00Z), "user@contoso.com", "45.33.32.156",
        dynamic({"city":"Fremont","countryOrRegion":"US"}),
        dynamic({"operatingSystem":"macOS","browser":"Firefox 115.0"}),
        "Azure Portal", "0"
];
// --- Build known value sets from baseline ---
let knownIPs = baselineSignins | where ResultType == "0" | distinct IPAddress;
let knownCountries = baselineSignins | where ResultType == "0" | distinct tostring(Location.countryOrRegion);
let knownCities = baselineSignins | where ResultType == "0" | distinct tostring(Location.city);
let knownApps = baselineSignins | where ResultType == "0" | distinct AppDisplayName;
let knownDevices = baselineSignins | where ResultType == "0" | distinct tostring(DeviceDetail.operatingSystem);
let knownBrowsers = baselineSignins | where ResultType == "0" | distinct tostring(DeviceDetail.browser);
// --- Compare current sign-in ---
currentSignin
| extend
    CurrentIP = IPAddress,
    CurrentCountry = tostring(Location.countryOrRegion),
    CurrentCity = tostring(Location.city),
    CurrentApp = AppDisplayName,
    CurrentDevice = tostring(DeviceDetail.operatingSystem),
    CurrentBrowser = tostring(DeviceDetail.browser),
    CurrentHour = hourofday(TimeGenerated)
| extend
    IsIPNew = iff(CurrentIP in (knownIPs), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsCountryNew = iff(CurrentCountry in (knownCountries), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsCityNew = iff(CurrentCity in (knownCities), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsAppNew = iff(CurrentApp in (knownApps), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsDeviceNew = iff(CurrentDevice in (knownDevices), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsBrowserNew = iff(CurrentBrowser in (knownBrowsers), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS")
| extend
    NewPropertyCount = toint(IsIPNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsCountryNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsCityNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsAppNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsDeviceNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsBrowserNew == "NEW - NEVER SEEN IN 30 DAYS")
| extend
    AnomalyAssessment = case(
        NewPropertyCount >= 3, "HIGH ANOMALY - 3+ new properties",
        NewPropertyCount == 2, "MEDIUM ANOMALY - Multiple new properties",
        NewPropertyCount == 1, "LOW ANOMALY - Only 1 new property",
        "WITHIN BASELINE - All properties known"
    )
| project
    UserPrincipalName,
    CurrentIP, CurrentCountry, CurrentCity, CurrentApp, CurrentDevice, CurrentBrowser, CurrentHour,
    IsIPNew, IsCountryNew, IsCityNew, IsAppNew, IsDeviceNew, IsBrowserNew,
    NewPropertyCount,
    AnomalyAssessment
// Expected: 5 rows (one per anomalous sign-in), all evaluated against 12-row benign baseline:
// --- Row 1 (M1 - Moscow/Linux/Python): NewPropertyCount=5, HIGH ANOMALY ---
//   IP=NEW, Country=NEW(RU), City=NEW(Moscow), App=KNOWN(O365), Device=NEW(Linux), Browser=NEW(Python)
// --- Row 2 (M2 - Lagos/Windows/Chrome): NewPropertyCount=3, HIGH ANOMALY ---
//   IP=NEW, Country=NEW(NG), City=NEW(Lagos), App=KNOWN(O365), Device=KNOWN(Win11), Browser=KNOWN(Chrome)
// --- Row 3 (M3 - Istanbul/Headless Chrome): NewPropertyCount=2, MEDIUM ANOMALY ---
//   IP=NEW, Country=KNOWN(TR), City=KNOWN(Istanbul), App=KNOWN(O365), Device=KNOWN(Win11), Browser=NEW(Headless)
// --- Row 4 (M4 - Frankfurt/Linux/curl): NewPropertyCount=6, HIGH ANOMALY ---
//   IP=NEW, Country=NEW(DE), City=NEW(Frankfurt), App=NEW(Graph), Device=NEW(Linux), Browser=NEW(curl)
// --- Row 5 (M5 - Fremont/macOS/Firefox): NewPropertyCount=5, HIGH ANOMALY ---
//   IP=NEW, Country=NEW(US), City=NEW(Fremont), App=KNOWN(Azure Portal), Device=NEW(macOS), Browser=NEW(Firefox)
// Baseline known values: IPs={10.1.1.1, 10.1.1.2, 85.100.50.25}, Countries={TR}, Cities={Istanbul},
//   Apps={O365, Teams, Outlook, Azure Portal, SharePoint Online, Power BI}, Devices={Win11, iPhone}, Browsers={Chrome, Edge, Safari}
```

### Test 4: Query 4A - Correlated Risk Events

```kql
// ============================================================
// TEST: Query 4A - Correlated Risk Events
// Synthetic data: 7 malicious + 11 benign = 18 rows
// ============================================================
let testRiskEvents = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    RiskEventType: string,
    RiskLevel: string,
    DetectionTimingType: string,
    IpAddress: string,
    Location: dynamic,
    CorrelationId: string,
    Id: string
) [
    // === MALICIOUS: Attack chain for target user ===
    // --- M1: Leaked credentials detected (precursor event) ---
    datetime(2026-02-18T02:00:00Z), "user@contoso.com", "leakedCredentials", "high", "offline",
        "", dynamic({}), "corr-100", "risk-m01",
    // --- M2: Unfamiliar sign-in properties (THIS alert) ---
    datetime(2026-02-21T14:30:00Z), "user@contoso.com", "unfamiliarFeatures", "high", "realtime",
        "198.51.100.42", dynamic({"city":"Moscow","countryOrRegion":"RU"}), "corr-001", "risk-m02",
    // --- M3: Impossible travel triggered by same sign-in ---
    datetime(2026-02-21T14:35:00Z), "user@contoso.com", "impossibleTravel", "medium", "offline",
        "198.51.100.42", dynamic({"city":"Moscow","countryOrRegion":"RU"}), "corr-001", "risk-m03",
    // --- M4: Anonymous IP detection (same session, VPN/Tor exit) ---
    datetime(2026-02-21T14:31:00Z), "user@contoso.com", "anonymizedIPAddress", "medium", "realtime",
        "198.51.100.42", dynamic({"city":"Moscow","countryOrRegion":"RU"}), "corr-001", "risk-m04",
    // --- M5: Malware-linked IP (offline detection, delayed) ---
    datetime(2026-02-21T16:00:00Z), "user@contoso.com", "maliciousIPAddress", "high", "offline",
        "198.51.100.42", dynamic({"city":"Moscow","countryOrRegion":"RU"}), "corr-001", "risk-m05",
    // --- M6: Password spray targeting same user earlier ---
    datetime(2026-02-20T08:00:00Z), "user@contoso.com", "passwordSpray", "medium", "offline",
        "198.51.100.50", dynamic({"city":"Moscow","countryOrRegion":"RU"}), "corr-150", "risk-m06",
    // --- M7: Suspicious browser detected (same day, different session) ---
    datetime(2026-02-21T10:00:00Z), "user@contoso.com", "suspiciousBrowser", "low", "realtime",
        "198.51.100.42", dynamic({"city":"Moscow","countryOrRegion":"RU"}), "corr-160", "risk-m07",
    // === BENIGN: Other users and noise ===
    // --- B1: Same IP targeting victim2 (password spray indicator - different user) ---
    datetime(2026-02-21T14:32:00Z), "victim2@contoso.com", "unfamiliarFeatures", "medium", "realtime",
        "198.51.100.42", dynamic({"city":"Moscow","countryOrRegion":"RU"}), "corr-200", "risk-b01",
    // --- B2: Unrelated user, different IP, different time ---
    datetime(2026-02-20T10:00:00Z), "other@contoso.com", "unfamiliarFeatures", "low", "offline",
        "203.0.113.50", dynamic({"city":"London","countryOrRegion":"GB"}), "corr-300", "risk-b02",
    // --- B3: FP - user traveling for business (legitimate unfamiliar sign-in) ---
    datetime(2026-02-17T08:00:00Z), "traveler@contoso.com", "unfamiliarFeatures", "low", "realtime",
        "93.184.216.34", dynamic({"city":"London","countryOrRegion":"GB"}), "corr-400", "risk-b03",
    // --- B4: FP - VPN-triggered anonymous IP for different user ---
    datetime(2026-02-19T12:00:00Z), "vpnuser@contoso.com", "anonymizedIPAddress", "low", "realtime",
        "104.16.0.1", dynamic({"city":"San Francisco","countryOrRegion":"US"}), "corr-500", "risk-b04",
    // --- B5: Impossible travel FP - same user dual location (VPN + mobile) ---
    datetime(2026-02-18T15:00:00Z), "traveler@contoso.com", "impossibleTravel", "low", "offline",
        "93.184.216.34", dynamic({"city":"London","countryOrRegion":"GB"}), "corr-400", "risk-b05",
    // --- B6: Old risk event for target user (outside 7d window) ---
    datetime(2026-02-10T03:00:00Z), "user@contoso.com", "unfamiliarFeatures", "low", "offline",
        "172.16.0.100", dynamic({"city":"Ankara","countryOrRegion":"TR"}), "corr-600", "risk-b06",
    // --- B7: Password spray targeting different tenant user ---
    datetime(2026-02-21T08:00:00Z), "admin@contoso.com", "passwordSpray", "medium", "offline",
        "198.51.100.50", dynamic({"city":"Moscow","countryOrRegion":"RU"}), "corr-700", "risk-b07",
    // --- B8: Leaked credential for different user (unrelated breach) ---
    datetime(2026-02-16T00:00:00Z), "leaked@contoso.com", "leakedCredentials", "high", "offline",
        "", dynamic({}), "corr-800", "risk-b08",
    // --- B9: Low-risk unfamiliar feature for colleague (ISP change) ---
    datetime(2026-02-19T09:00:00Z), "colleague@contoso.com", "unfamiliarFeatures", "low", "realtime",
        "78.46.0.1", dynamic({"city":"Istanbul","countryOrRegion":"TR"}), "corr-900", "risk-b09",
    // --- B10: MFA fraud report for different user ---
    datetime(2026-02-20T14:00:00Z), "mfauser@contoso.com", "mcasSuspiciousInboxManipulationRules", "medium", "offline",
        "10.0.0.50", dynamic({"city":"Istanbul","countryOrRegion":"TR"}), "corr-950", "risk-b10",
    // --- B11: Benign risk event for target user (auto-dismissed) ---
    datetime(2026-02-15T11:00:00Z), "user@contoso.com", "unfamiliarFeatures", "low", "offline",
        "85.100.50.25", dynamic({"city":"Istanbul","countryOrRegion":"TR"}), "corr-110", "risk-b11"
];
// --- Test: All risk events for target user ---
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let correlationWindow = 7d;
testRiskEvents
| where TimeGenerated between ((alertTime - correlationWindow) .. (alertTime + 1d))
| where UserPrincipalName == targetUser
| project
    TimeGenerated,
    UserPrincipalName,
    RiskEventType,
    RiskLevel,
    DetectionTimingType,
    IpAddress,
    LocationCountry = tostring(Location.countryOrRegion),
    LocationCity = tostring(Location.city),
    CorrelationId,
    Id
| order by TimeGenerated desc
| extend
    RiskSignificance = case(
        RiskEventType == "leakedCredentials", "CRITICAL - Credentials exposed on dark web/paste site",
        RiskEventType == "impossibleTravel", "HIGH - Impossible travel detected",
        RiskEventType == "maliciousIPAddress", "HIGH - Known malicious IP",
        RiskEventType == "anonymizedIPAddress", "MEDIUM - Anonymous IP / proxy detected",
        RiskEventType == "passwordSpray", "HIGH - Password spray attack detected",
        RiskEventType == "unfamiliarFeatures", "MEDIUM - Unfamiliar sign-in properties (this alert)",
        RiskEventType == "suspiciousBrowser", "LOW - Suspicious browser fingerprint",
        strcat("INFO - ", RiskEventType)
    )
// Expected: 8 rows for user@contoso.com within 7d window:
// - M1: leakedCredentials (CRITICAL) - Feb 18
// - B11: unfamiliarFeatures low (MEDIUM) - Feb 15 ← within window, auto-dismissed
// - M6: passwordSpray (HIGH) - Feb 20
// - M7: suspiciousBrowser (LOW) - Feb 21 10:00
// - M2: unfamiliarFeatures high (MEDIUM - this alert) - Feb 21 14:30
// - M4: anonymizedIPAddress (MEDIUM) - Feb 21 14:31
// - M3: impossibleTravel (HIGH) - Feb 21 14:35
// - M5: maliciousIPAddress (HIGH) - Feb 21 16:00
// Filtered out: B6 (outside 7d window), all other-user events (B1-B5, B7-B10)
// Pattern: leaked creds → password spray → suspicious browser → unfamiliar + anon IP + impossible travel + malicious IP
// This strongly indicates coordinated credential theft campaign
```

### Test 5: Query 5A - Directory Changes (Persistence)

```kql
// ============================================================
// TEST: Query 5A - Directory Changes After Sign-In (Persistence)
// Synthetic data: 6 malicious + 12 benign = 18 rows
// ============================================================
let testAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    Category: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    CorrelationId: string
) [
    // === MALICIOUS: Post-sign-in persistence by attacker ===
    // --- M1: MFA method registered (attacker adding their own auth method) ---
    datetime(2026-02-21T14:40:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User",
            "modifiedProperties":[{"displayName":"StrongAuthenticationMethod","oldValue":"[{\"MethodType\":1}]",
            "newValue":"[{\"MethodType\":1},{\"MethodType\":6}]"}]}]),
        "audit-5a-m01",
    // --- M2: OAuth app consent with broad permissions (data exfil) ---
    datetime(2026-02-21T14:50:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"DataSync Pro","modifiedProperties":[
            {"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"Mail.Read Mail.ReadWrite Files.ReadWrite.All User.Read.All"}]}]),
        "audit-5a-m02",
    // --- M3: App role assignment to malicious service principal ---
    datetime(2026-02-21T14:55:00Z), "Add app role assignment to service principal", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"DataSync Pro SP","modifiedProperties":[
            {"displayName":"AppRole.Value","oldValue":"","newValue":"Application.ReadWrite.All"}]}]),
        "audit-5a-m03",
    // --- M4: Device registration (establishing device persistence) ---
    datetime(2026-02-21T15:00:00Z), "Register device", "DeviceManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"DESKTOP-ATKR01","modifiedProperties":[
            {"displayName":"DeviceTrustType","oldValue":"","newValue":"Workplace"}]}]),
        "audit-5a-m04",
    // --- M5: Role escalation (adding self to privileged role) ---
    datetime(2026-02-21T15:10:00Z), "Add member to role", "RoleManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User",
            "modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"","newValue":"Exchange Administrator"}]}]),
        "audit-5a-m05",
    // --- M6: Deleted existing MFA method (defense evasion) ---
    datetime(2026-02-21T15:20:00Z), "User deleted security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User",
            "modifiedProperties":[{"displayName":"StrongAuthenticationMethod",
            "oldValue":"[{\"MethodType\":1},{\"MethodType\":6}]","newValue":"[{\"MethodType\":6}]"}]}]),
        "audit-5a-m06",
    // === BENIGN: Normal organizational activity ===
    // --- B1: Different user's security info registration ---
    datetime(2026-02-21T14:45:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"colleague@contoso.com"}}),
        dynamic([{"userPrincipalName":"colleague@contoso.com","displayName":"Colleague",
            "modifiedProperties":[]}]),
        "audit-5a-b01",
    // --- B2: Admin updating different user's profile ---
    datetime(2026-02-21T15:00:00Z), "Update user", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"other@contoso.com","displayName":"Other User",
            "modifiedProperties":[{"displayName":"Department","oldValue":"Sales","newValue":"Marketing"}]}]),
        "audit-5a-b02",
    // --- B3: Normal app consent by different user (Teams) ---
    datetime(2026-02-21T14:35:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"other@contoso.com"}}),
        dynamic([{"displayName":"Microsoft Teams","modifiedProperties":[
            {"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"Chat.ReadWrite"}]}]),
        "audit-5a-b03",
    // --- B4: IT admin resetting password for new hire ---
    datetime(2026-02-21T15:15:00Z), "Reset password (by admin)", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"newhire@contoso.com","displayName":"New Hire",
            "modifiedProperties":[]}]),
        "audit-5a-b04",
    // --- B5: Regular device registration by IT (before alert) ---
    datetime(2026-02-21T10:00:00Z), "Register device", "DeviceManagement",
        dynamic({"user":{"userPrincipalName":"itadmin@contoso.com"}}),
        dynamic([{"displayName":"DESKTOP-CORP42","modifiedProperties":[
            {"displayName":"DeviceTrustType","oldValue":"","newValue":"AzureAd"}]}]),
        "audit-5a-b05",
    // --- B6: PIM role activation by different admin (normal) ---
    datetime(2026-02-21T14:00:00Z), "Add eligible member to role", "RoleManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"admin@contoso.com","displayName":"Admin",
            "modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"","newValue":"Global Reader"}]}]),
        "audit-5a-b06",
    // --- B7: App permission grant by service principal (automated) ---
    datetime(2026-02-21T15:05:00Z), "Add delegated permission grant", "ApplicationManagement",
        dynamic({"app":{"displayName":"Azure AD Provisioning"}}),
        dynamic([{"displayName":"HR Sync App","modifiedProperties":[
            {"displayName":"DelegatedPermissionGrant.Scope","oldValue":"","newValue":"User.Read"}]}]),
        "audit-5a-b07",
    // --- B8: User changing own password (before alert, routine) ---
    datetime(2026-02-21T08:00:00Z), "Change password (self-service)", "UserManagement",
        dynamic({"user":{"userPrincipalName":"other@contoso.com"}}),
        dynamic([{"userPrincipalName":"other@contoso.com","displayName":"Other User",
            "modifiedProperties":[]}]),
        "audit-5a-b08",
    // --- B9: Admin adding registered owner to corporate device ---
    datetime(2026-02-21T14:32:00Z), "Add registered owner to device", "DeviceManagement",
        dynamic({"user":{"userPrincipalName":"itadmin@contoso.com"}}),
        dynamic([{"displayName":"LAPTOP-CORP99","modifiedProperties":[]}]),
        "audit-5a-b09",
    // --- B10: Target user activity BEFORE alert (outside 4h post window) ---
    datetime(2026-02-21T09:00:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"Slack","modifiedProperties":[
            {"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"openid profile email"}]}]),
        "audit-5a-b10",
    // --- B11: StsRefreshToken update by system (automated rotation) ---
    datetime(2026-02-21T14:38:00Z), "Update StsRefreshTokenValidFrom", "UserManagement",
        dynamic({"app":{"displayName":"Microsoft Online Services"}}),
        dynamic([{"userPrincipalName":"serviceacct@contoso.com","displayName":"Service Account",
            "modifiedProperties":[]}]),
        "audit-5a-b11",
    // --- B12: Different user's device registration (same time window) ---
    datetime(2026-02-21T15:30:00Z), "Register device", "DeviceManagement",
        dynamic({"user":{"userPrincipalName":"newuser@contoso.com"}}),
        dynamic([{"displayName":"PHONE-SAMSUNG","modifiedProperties":[
            {"displayName":"DeviceTrustType","oldValue":"","newValue":"Workplace"}]}]),
        "audit-5a-b12"
];
// --- Test execution ---
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let postSignInWindow = 4h;
testAuditLogs
| where TimeGenerated between (alertTime .. (alertTime + postSignInWindow))
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
| where tostring(InitiatedBy.user.userPrincipalName) == targetUser
    or tostring(TargetResource.userPrincipalName) == targetUser
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
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, alertTime),
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
// Expected: 6 rows for user@contoso.com within 4h post-alert window:
// - M1: User registered security info (+10min) → "CRITICAL - MFA MANIPULATION"
// - M2: Consent to application (+20min) → "CRITICAL - OAUTH APP CONSENT"
// - M3: Add app role assignment to SP (+25min) → "INFO" (no specific has-match)
// - M4: Register device (+30min) → "HIGH - DEVICE REGISTRATION"
// - M5: Add member to role (+40min) → "CRITICAL - ROLE ESCALATION"
// - M6: User deleted security info (+50min) → "CRITICAL - MFA MANIPULATION"
// Filtered out:
//   B1,B3,B4,B8,B9,B12: different users (not initiator or target of targetUser)
//   B2: targets other@contoso.com, initiated by admin (no match to targetUser)
//   B5,B6: before alert window OR different user
//   B7: initiated by app (no user match), targets HR Sync App
//   B10: before alert window (09:00 < 14:30)
//   B11: initiated by app, targets serviceacct
// Attack pattern: MFA registration → OAuth consent → API permissions → device → role escalation → MFA deletion
// This is a textbook post-compromise persistence chain
```

### Test 6: Query 5B/5C/5D - Post-Sign-In Activity

```kql
// ============================================================
// TEST: Query 5B/5C/5D - Post-Sign-In Activity
// Synthetic data: 8 malicious + 12 benign = 20 rows
// ============================================================
let testOfficeActivity = datatable(
    TimeGenerated: datetime,
    Operation: string,
    OfficeWorkload: string,
    UserId: string,
    ClientIP: string,
    Parameters: dynamic
) [
    // === MALICIOUS: BEC attack pattern from compromised account ===
    // --- M1: Inbox rule created to forward and delete financial emails ---
    datetime(2026-02-21T14:45:00Z), "New-InboxRule", "Exchange", "user@contoso.com",
        "198.51.100.42:54321",
        dynamic([
            {"Name":"Name","Value":".."},
            {"Name":"SubjectContainsWords","Value":"invoice;payment;wire transfer"},
            {"Name":"ForwardTo","Value":"attacker@evil.com"},
            {"Name":"DeleteMessage","Value":"True"},
            {"Name":"MarkAsRead","Value":"True"}
        ]),
    // --- M2: Email forwarding set on mailbox (persistence) ---
    datetime(2026-02-21T14:48:00Z), "Set-Mailbox", "Exchange", "user@contoso.com",
        "198.51.100.42:54321",
        dynamic([{"Name":"ForwardingSmtpAddress","Value":"smtp:attacker@evil.com"}]),
    // --- M3: Bulk email access (reconnaissance) ---
    datetime(2026-02-21T15:00:00Z), "MailItemsAccessed", "Exchange", "user@contoso.com",
        "198.51.100.42:54321", dynamic([]),
    // --- M4: Continued bulk email access ---
    datetime(2026-02-21T15:01:00Z), "MailItemsAccessed", "Exchange", "user@contoso.com",
        "198.51.100.42:54321", dynamic([]),
    // --- M5: Third bulk email access (pattern of scraping) ---
    datetime(2026-02-21T15:02:00Z), "MailItemsAccessed", "Exchange", "user@contoso.com",
        "198.51.100.42:54321", dynamic([]),
    // --- M6: Files downloaded from SharePoint (exfiltration, IPv6-mapped) ---
    datetime(2026-02-21T15:30:00Z), "FileDownloaded", "SharePoint", "user@contoso.com",
        "[::ffff:198.51.100.42]:12345", dynamic([]),
    // --- M7: Second file download (bulk exfiltration) ---
    datetime(2026-02-21T15:31:00Z), "FileDownloaded", "SharePoint", "user@contoso.com",
        "[::ffff:198.51.100.42]:12345", dynamic([]),
    // --- M8: Internal phishing email sent (lateral movement) ---
    datetime(2026-02-21T15:45:00Z), "Send", "Exchange", "user@contoso.com",
        "198.51.100.42:54321", dynamic([]),
    // === BENIGN: Normal organizational activity ===
    // --- B1: Other user normal file access ---
    datetime(2026-02-21T14:35:00Z), "FileAccessed", "SharePoint", "other@contoso.com",
        "10.1.1.1", dynamic([]),
    // --- B2: Other user normal email send ---
    datetime(2026-02-21T15:00:00Z), "Send", "Exchange", "other@contoso.com",
        "10.1.1.1", dynamic([]),
    // --- B3: Target user normal email read BEFORE alert (legitimate activity) ---
    datetime(2026-02-21T10:00:00Z), "MailItemsAccessed", "Exchange", "user@contoso.com",
        "10.1.1.1:50000", dynamic([]),
    // --- B4: Target user sent email BEFORE alert (normal workday) ---
    datetime(2026-02-21T10:15:00Z), "Send", "Exchange", "user@contoso.com",
        "10.1.1.1:50000", dynamic([]),
    // --- B5: Colleague accessing shared document ---
    datetime(2026-02-21T14:40:00Z), "FileAccessed", "SharePoint", "colleague@contoso.com",
        "10.1.1.2", dynamic([]),
    // --- B6: Admin modifying Teams channel (different workload) ---
    datetime(2026-02-21T15:10:00Z), "ChannelUpdated", "MicrosoftTeams", "admin@contoso.com",
        "10.1.1.5", dynamic([]),
    // --- B7: Different user file download (legitimate) ---
    datetime(2026-02-21T15:20:00Z), "FileDownloaded", "SharePoint", "colleague@contoso.com",
        "10.1.1.2", dynamic([]),
    // --- B8: Target user file access from BEFORE alert window ---
    datetime(2026-02-21T09:00:00Z), "FileAccessed", "SharePoint", "user@contoso.com",
        "10.1.1.1:50000", dynamic([]),
    // --- B9: Different user inbox rule (legitimate filter) ---
    datetime(2026-02-21T14:50:00Z), "New-InboxRule", "Exchange", "colleague@contoso.com",
        "10.1.1.2:44000",
        dynamic([
            {"Name":"Name","Value":"Move Jira notifications"},
            {"Name":"MoveToFolder","Value":"JIRA"}
        ]),
    // --- B10: Other user mailbox setting change (signature) ---
    datetime(2026-02-21T15:05:00Z), "Set-Mailbox", "Exchange", "other@contoso.com",
        "10.1.1.1",
        dynamic([{"Name":"SignatureText","Value":"New signature"}]),
    // --- B11: Target user email read on mobile BEFORE alert ---
    datetime(2026-02-21T08:00:00Z), "MailItemsAccessed", "Exchange", "user@contoso.com",
        "85.100.50.25:60000", dynamic([]),
    // --- B12: Third user normal activity ---
    datetime(2026-02-21T16:00:00Z), "FileAccessed", "SharePoint", "manager@contoso.com",
        "10.1.1.3", dynamic([])
];
// --- Test 5B: All post-sign-in activity ---
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-21T14:30:00Z);
let postSignInWindow = 4h;
testOfficeActivity
| where TimeGenerated between (alertTime .. (alertTime + postSignInWindow))
| where UserId == targetUser
| extend CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
| project
    TimeGenerated,
    Operation,
    OfficeWorkload,
    UserId,
    CleanClientIP,
    RawClientIP = ClientIP,
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, alertTime),
    RiskCategory = case(
        Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule"),
            "CRITICAL - INBOX RULE",
        Operation in ("Set-Mailbox", "Set-TransportRule") and OfficeWorkload == "Exchange",
            "CRITICAL - MAILBOX FORWARDING",
        Operation == "MailItemsAccessed",
            "MONITOR - EMAIL ACCESS",
        Operation == "Send",
            "MONITOR - EMAIL SENT",
        Operation in ("FileDownloaded", "FileSyncDownloadedFull"),
            "MONITOR - FILE DOWNLOAD",
        "INFO"
    ),
    Parameters
| order by TimeGenerated asc
// Expected: 8 rows for user@contoso.com within post-alert window (14:30+4h):
// - M1: CRITICAL inbox rule (New-InboxRule, forwarding to attacker@evil.com, +15min)
// - M2: CRITICAL mailbox forwarding (Set-Mailbox, smtp:attacker@evil.com, +18min)
// - M3-M5: 3x MONITOR email access (MailItemsAccessed, +30/31/32min)
// - M6-M7: 2x MONITOR file download (FileDownloaded, IPv6-mapped IP normalized, +60/61min)
// - M8: MONITOR email sent (Send, internal phishing, +75min)
// All 8 malicious rows from same IP 198.51.100.42 = CONFIRMED BEC with persistence
// Filtered out: B1,B2,B5-B7,B9,B10,B12 (other users), B3,B4,B8,B11 (before alert window)
```

### Test 7: Query 6A/6B - IP Reputation and Context

```kql
// ============================================================
// TEST: Query 6A/6B - IP Reputation and Context
// Synthetic data: 5 malicious TI hits + 13 benign/filtered = 18 rows
// ============================================================
let testTI = datatable(
    TimeGenerated: datetime,
    NetworkIP: string,
    ThreatType: string,
    ConfidenceScore: int,
    Description: string,
    Tags: dynamic,
    ThreatSeverity: string,
    SourceSystem: string,
    ExpirationDateTime: datetime,
    Active: bool
) [
    // === MALICIOUS: TI indicators matching alert IP (pass all filters) ===
    // --- M1: High-confidence C2 from Defender TI ---
    datetime(2026-02-20T00:00:00Z), "198.51.100.42", "C2", 85,
        "Known command and control server associated with credential theft campaigns",
        dynamic(["APT","credential-theft"]), "High", "Microsoft Defender TI",
        datetime(2026-06-01T00:00:00Z), true,
    // --- M2: Medium-confidence phishing from TAXII feed ---
    datetime(2026-02-15T00:00:00Z), "198.51.100.42", "Phishing", 65,
        "IP associated with phishing infrastructure",
        dynamic(["phishing"]), "Medium", "TAXII Feed",
        datetime(2026-05-01T00:00:00Z), true,
    // --- M3: Botnet C2 from OSINT feed ---
    datetime(2026-02-18T00:00:00Z), "198.51.100.42", "Botnet", 75,
        "IP observed as botnet command and control node",
        dynamic(["botnet","credential-harvesting"]), "High", "Abuse.ch OSINT",
        datetime(2026-07-01T00:00:00Z), true,
    // --- M4: Brute force source from community intel ---
    datetime(2026-02-10T00:00:00Z), "198.51.100.42", "BruteForce", 60,
        "IP associated with brute force attacks against Azure AD endpoints",
        dynamic(["brute-force","azure-ad"]), "Medium", "Community Feed",
        datetime(2026-04-01T00:00:00Z), true,
    // --- M5: Credential theft from ISC feed ---
    datetime(2026-02-19T00:00:00Z), "198.51.100.42", "CredentialTheft", 70,
        "IP linked to token replay and session hijacking operations",
        dynamic(["AiTM","token-theft"]), "High", "ISC SANS",
        datetime(2026-08-01T00:00:00Z), true,
    // === BENIGN / FILTERED OUT ===
    // --- B1: Same alert IP but low confidence (below 50 threshold) ---
    datetime(2026-02-20T00:00:00Z), "198.51.100.42", "Suspicious", 30,
        "Low confidence suspicious activity", dynamic([]), "Low", "Community Feed",
        datetime(2026-06-01T00:00:00Z), true,
    // --- B2: Same alert IP but very low confidence (noise) ---
    datetime(2026-02-20T00:00:00Z), "198.51.100.42", "Scanning", 15,
        "Port scanning activity detected", dynamic(["scanner"]), "Low", "Greynoise",
        datetime(2026-06-01T00:00:00Z), true,
    // --- B3: Different IP - expired indicator ---
    datetime(2025-01-01T00:00:00Z), "198.51.100.99", "Malware", 90,
        "Expired indicator - no longer relevant", dynamic([]), "High", "TAXII Feed",
        datetime(2025-12-31T00:00:00Z), true,
    // --- B4: Different IP - inactive indicator ---
    datetime(2026-02-01T00:00:00Z), "203.0.113.10", "C2", 80,
        "Indicator marked inactive after remediation", dynamic(["remediated"]), "High", "Defender TI",
        datetime(2026-06-01T00:00:00Z), false,
    // --- B5: Different IP - legitimate CDN (known good) ---
    datetime(2026-02-15T00:00:00Z), "13.107.42.14", "Suspicious", 20,
        "Microsoft CDN IP - false positive in community feed", dynamic([]), "Low", "Community Feed",
        datetime(2026-06-01T00:00:00Z), true,
    // --- B6: Different IP - different attacker infrastructure ---
    datetime(2026-02-18T00:00:00Z), "45.33.32.156", "Malware", 88,
        "Different threat actor infrastructure", dynamic(["ransomware"]), "Critical", "Defender TI",
        datetime(2026-06-01T00:00:00Z), true,
    // --- B7: Same alert IP but expired indicator ---
    datetime(2025-06-01T00:00:00Z), "198.51.100.42", "Malware", 80,
        "Historical indicator - infrastructure recycled", dynamic([]), "High", "TAXII Feed",
        datetime(2025-12-01T00:00:00Z), true,
    // --- B8: Null NetworkIP (malformed indicator) ---
    datetime(2026-02-20T00:00:00Z), "", "Unknown", 50,
        "Indicator missing IP field", dynamic([]), "Medium", "Community Feed",
        datetime(2026-06-01T00:00:00Z), true,
    // --- B9: Different subnet - not the alert IP ---
    datetime(2026-02-20T00:00:00Z), "198.51.100.43", "C2", 90,
        "Adjacent IP in same /24 but not exact match", dynamic(["APT"]), "High", "Defender TI",
        datetime(2026-06-01T00:00:00Z), true,
    // --- B10: Legitimate VPN exit node (known FP) ---
    datetime(2026-02-20T00:00:00Z), "104.16.0.1", "Anonymizer", 55,
        "Cloudflare Warp VPN exit - commonly triggers FP", dynamic(["vpn"]), "Low", "Community Feed",
        datetime(2026-06-01T00:00:00Z), true,
    // --- B11: Old feed entry for alert IP, below confidence ---
    datetime(2026-01-01T00:00:00Z), "198.51.100.42", "Scanning", 40,
        "Historical scanning activity, low relevance", dynamic([]), "Low", "Shodan",
        datetime(2026-03-01T00:00:00Z), true,
    // --- B12: Well-known Microsoft IP (should not match alert) ---
    datetime(2026-02-20T00:00:00Z), "20.190.128.0", "Suspicious", 10,
        "FP - Azure AD authentication endpoint", dynamic([]), "Low", "Community Feed",
        datetime(2026-06-01T00:00:00Z), true,
    // --- B13: Different IP, high confidence but not our target ---
    datetime(2026-02-20T00:00:00Z), "185.220.101.1", "TorExitNode", 95,
        "Known Tor exit node", dynamic(["tor","anonymizer"]), "High", "Tor Project",
        datetime(2026-06-01T00:00:00Z), true
];
// --- Test TI lookup ---
let alertIP = "198.51.100.42";
testTI
| where isnotempty(NetworkIP)
| where Active == true
| where ExpirationDateTime > now()
| where NetworkIP == alertIP
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
    LastUpdatedTimeUtc = TimeGenerated,
    TIAssessment = case(
        ConfidenceScore >= 80, "HIGH CONFIDENCE - Known malicious IP",
        ConfidenceScore >= 50, "MEDIUM CONFIDENCE - Potentially malicious IP",
        "LOW CONFIDENCE - Weak indicator"
    )
| order by ConfidenceScore desc
// Expected: 5 rows for IP 198.51.100.42 (all active, not expired, confidence >= 50):
// - M1: C2, confidence 85 → "HIGH CONFIDENCE - Known malicious IP" (Defender TI)
// - M3: Botnet, confidence 75 → "MEDIUM CONFIDENCE - Potentially malicious IP" (Abuse.ch)
// - M5: CredentialTheft, confidence 70 → "MEDIUM CONFIDENCE" (ISC SANS)
// - M2: Phishing, confidence 65 → "MEDIUM CONFIDENCE" (TAXII Feed)
// - M4: BruteForce, confidence 60 → "MEDIUM CONFIDENCE" (Community Feed)
// Filtered out (13 rows):
//   B1,B2,B11: alert IP but confidence < 50
//   B7: alert IP but expired
//   B3: different IP, expired
//   B4: different IP, inactive (Active=false)
//   B5,B6,B9,B10,B12,B13: different IPs (don't match alertIP)
//   B8: empty NetworkIP
// Multiple TI sources confirming same IP = HIGH CONFIDENCE malicious infrastructure
```

---

## References

- [MITRE ATT&CK T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [Microsoft Entra ID Identity Protection Risk Detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [Microsoft Sentinel SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Investigating Risk - Microsoft Identity Protection](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk)
