---
title: "Conditional Access Policy Manipulation"
id: RB-0015
severity: critical
status: reviewed
description: >
  Investigation runbook for unauthorized Conditional Access (CA) policy
  modifications in Microsoft Entra ID. Covers detection of CA policy deletion,
  disablement, exclusion modification, and Security Defaults deactivation.
  Includes policy change attribution, actor compromise assessment, impact
  analysis of weakened security controls, gap analysis against the policy
  baseline, post-modification sign-in exploitation detection, and org-wide
  security configuration drift sweep. CA policies are the primary enforcement
  layer for MFA, device compliance, location restrictions, and session controls
  -- disabling them removes all conditional security protections from the tenant.
mitre_attack:
  tactics:
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
    - tactic_id: TA0003
      tactic_name: "Persistence"
    - tactic_id: TA0004
      tactic_name: "Privilege Escalation"
    - tactic_id: TA0040
      tactic_name: "Impact"
  techniques:
    - technique_id: T1562.001
      technique_name: "Impair Defenses: Disable or Modify Tools"
      confidence: confirmed
    - technique_id: T1556
      technique_name: "Modify Authentication Process"
      confidence: confirmed
    - technique_id: T1548
      technique_name: "Abuse Elevation Control Mechanism"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
threat_actors:
  - "Midnight Blizzard (APT29/Nobelium)"
  - "LAPSUS$ (DEV-0537)"
  - "Storm-0558"
  - "Scattered Spider (Octo Tempest)"
  - "APT28 (Fancy Bear)"
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
  - table: "AzureActivity"
    product: "Azure"
    license: "Azure Subscription"
    required: false
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-22
updated: 2026-02-22
version: "1.0"
tier: 2
category: identity
key_log_sources:
  - AuditLogs
  - SigninLogs
  - AADUserRiskEvents
  - AzureActivity
tactic_slugs:
  - defense-evasion
  - persistence
  - priv-esc
data_checks:
  - query: "AuditLogs | where OperationName has 'conditional access' | take 1"
    label: primary
    description: "Conditional Access policy change event detection"
  - query: "SigninLogs | take 1"
    description: "For actor sign-in context and post-modification exploitation"
  - query: "AADUserRiskEvents | take 1"
    label: optional
    description: "For risk events on the modifying admin account"
  - query: "AzureActivity | take 1"
    label: optional
    description: "For correlated Azure-level configuration changes"
---

# Conditional Access Policy Manipulation - Investigation Runbook

> **RB-0015** | Severity: Critical | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Audit Logs
> **Risk Detection Name:** `Update conditional access policy` / `Delete conditional access policy` / `Disable Security Defaults` audit events
> **Primary MITRE Technique:** T1562.001 - Impair Defenses: Disable or Modify Tools

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Policy Change Event Analysis](#step-1-policy-change-event-analysis)
   - [Step 2: Actor Compromise Assessment](#step-2-actor-compromise-assessment)
   - [Step 3: Policy Impact Analysis](#step-3-policy-impact-analysis)
   - [Step 4: Baseline Comparison - Establish Normal Policy Change Pattern](#step-4-baseline-comparison---establish-normal-policy-change-pattern)
   - [Step 5: Post-Modification Exploitation Detection](#step-5-post-modification-exploitation-detection)
   - [Step 6: Security Configuration Drift Sweep](#step-6-security-configuration-drift-sweep)
   - [Step 7: Correlated Attack Chain Detection](#step-7-correlated-attack-chain-detection)
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
Conditional Access policy manipulation is detected through AuditLogs events:

1. **Policy deletion:** `Delete conditional access policy` -- complete removal of a security policy. This is the most destructive action as there is no "undo" without backup.
2. **Policy disablement:** `Update conditional access policy` where the policy state changes from "enabled" to "disabled" or "reportOnly". This silently removes enforcement while keeping the policy visible.
3. **Exclusion modification:** `Update conditional access policy` where user/group/IP exclusions are added. Attackers add their own accounts or IPs to exclusion lists to bypass controls while leaving the policy active for everyone else.
4. **Security Defaults deactivation:** `Disable Security Defaults` -- removes baseline MFA enforcement for the entire tenant.
5. **Named locations manipulation:** `Update named location` or `Delete named location` -- modifying trusted network definitions to bypass location-based CA policies.

**Why it matters:**
Conditional Access policies are the **primary security enforcement layer** in Microsoft Entra ID. They control who can access what resources, from where, on what devices, and under what conditions. CA policies enforce:
- **MFA requirements** -- without CA, users can sign in with just a password
- **Device compliance** -- without CA, any device can access corporate resources
- **Location restrictions** -- without CA, any location is allowed
- **Session controls** -- without CA, sessions have default (long) lifetimes
- **Risk-based access** -- without CA, risky sign-ins are not blocked

When an attacker disables or modifies CA policies, they remove ALL of these protections. This is typically done AFTER gaining admin access (RB-0013) and BEFORE executing the primary attack objective (data exfiltration, BEC, lateral movement).

**Why this is CRITICAL severity:**
- Disabling CA policies removes MFA enforcement for the entire organization
- A single exclusion can allow the attacker to bypass all security controls
- Policy deletion is irreversible without backup -- the policy configuration is lost
- Security Defaults deactivation affects every user in the tenant
- CA policy changes take effect immediately -- there is no rollback window
- Without CA, compromised accounts face no additional authentication challenges
- An attacker who controls CA can make the environment permanently insecure

**However:** This alert has a **very low false positive rate** (~3-5%). Legitimate triggers include:
- IT admin modifying CA policies as part of documented change management
- Migrating from Security Defaults to Conditional Access (requires disabling defaults first)
- Temporary policy modification for troubleshooting authentication issues (with change ticket)
- Adding a new trusted location for a new office or VPN endpoint
- Policy state change from "enabled" to "reportOnly" for testing

**Worst case scenario if this is real:**
An attacker compromises a Conditional Access Administrator or Global Admin account. They disable the "Require MFA for all users" policy and the "Block legacy authentication" policy. Within minutes, the attacker signs in to multiple user accounts using passwords obtained from a credential database (no MFA challenge). They use legacy authentication protocols (IMAP, SMTP) that were previously blocked to access email without any modern auth controls. The attacker reads executive emails, modifies vendor payment instructions, and creates inbox forwarding rules to external email addresses -- all while bypassing every security control the organization had in place. When the SOC eventually notices the CA policy change, the attacker has already compromised dozens of accounts and initiated wire fraud.

**Key difference from other identity runbooks:**
- RB-0013 (Privileged Role): Investigates WHO gained admin access. CA manipulation often follows role escalation.
- RB-0014 (AiTM): Investigates session token theft. CA modifications can disable protections that would normally prevent AiTM exploitation.
- **RB-0015 (This runbook):** Investigates **security control sabotage**. The attacker is not trying to access data directly -- they are removing the barriers that protect access to data. This is a **force multiplier** attack: one CA policy change can expose thousands of accounts.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID Free + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID (AuditLogs, SigninLogs)
- **Permissions:** Security Reader (investigation), Conditional Access Administrator (containment)

### Recommended for Full Coverage
- **License:** Entra ID P2 + Microsoft Sentinel
- **Additional:** Identity Protection enabled, CA policy backup system
- **CA Policy Versioning:** Export CA policies to version control for baseline comparison

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | AuditLogs, SigninLogs | Steps 1, 3-7 |
| Above + Entra ID P2 | Above + AADUserRiskEvents | Steps 1-7 (full coverage) |
| Above + Azure Subscription | Above + AzureActivity | Steps 1-7 + Azure-level correlation |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let ActorUPN = "suspicious.admin@contoso.com";            // Admin who modified the policy
let PolicyName = "Require MFA for All Users";             // CA policy that was modified
let AlertTime = datetime(2026-02-22T14:00:00Z);           // Time of policy modification
let LookbackWindow = 24h;                                 // Window to analyze pre-change activity
let ForwardWindow = 12h;                                   // Window after change for exploitation
let BaselineDays = 30d;                                    // Baseline comparison window
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- CA policy DELETED (not just disabled -- irreversible without backup)
- "Require MFA for all users" or equivalent policy disabled
- "Block legacy authentication" policy disabled or deleted
- Security Defaults disabled without a documented migration to CA policies
- Exclusion added for a non-IT user account or external IP address
- CA policy change performed from a risky sign-in session (unfamiliar IP, anonymous IP)
- Multiple CA policies modified within a short time window (systematic sabotage)
- CA policy change followed by suspicious sign-in activity from other accounts

### Standard Investigation
- CA policy changed to "reportOnly" mode (still visible but not enforcing)
- Single exclusion added for a known IT user or service account
- Named location modified with new IP ranges
- Policy update by a known CA Admin during business hours

### Likely Benign
- CA policy modification with matching change management ticket
- Documented migration from Security Defaults to Conditional Access
- Temporary policy modification with documented start/end time for troubleshooting
- Policy update during a planned maintenance window
- New office/VPN IP range added to trusted locations with IT approval

---

## 5. Investigation Steps

### Step 1: Policy Change Event Analysis

**Purpose:** Identify exactly what changed in the Conditional Access policy. Determine the before and after state -- was the policy deleted, disabled, or were exclusions modified? What was the policy enforcing, and what security controls were lost as a result of the change?

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 1: Policy Change Event Analysis
// Purpose: Identify CA policy changes, what changed, before/after state
// Tables: AuditLogs
// Investigation Step: 1 - Policy Change Event Analysis
// ============================================================
let ActorUPN = "suspicious.admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- All CA policy and security configuration changes ---
AuditLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where OperationName in (
    "Update conditional access policy",
    "Delete conditional access policy",
    "Add conditional access policy",
    "Disable Security Defaults",
    "Enable Security Defaults",
    "Update named location",
    "Delete named location",
    "Add named location",
    "Update authorization policy",
    "Update policy"
)
| extend
    ModifyingUser = tostring(InitiatedBy.user.userPrincipalName),
    ModifyingIP = tostring(InitiatedBy.user.ipAddress),
    ModifyingApp = tostring(InitiatedBy.app.displayName),
    PolicyName = tostring(TargetResources[0].displayName),
    PolicyId = tostring(TargetResources[0].id),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    ChangeCategory = case(
        OperationName has "Delete", "DELETION - Policy permanently removed",
        OperationName has "Disable Security Defaults", "SECURITY DEFAULTS - Baseline protection disabled",
        PropertyName == "State" and NewValue has "disabled",
            "DISABLED - Policy enforcement turned off",
        PropertyName == "State" and NewValue has "enabledForReportingButNotEnforced",
            "REPORT-ONLY - Policy no longer enforcing",
        PropertyName has "ExcludeUsers" or PropertyName has "ExcludeGroups",
            "EXCLUSION - Users/groups excluded from policy",
        PropertyName has "ExcludeLocations" or PropertyName has "IncludeLocations",
            "LOCATION - Trusted location boundaries changed",
        PropertyName has "GrantControls" and OldValue has "mfa" and not(NewValue has "mfa"),
            "MFA REMOVED - MFA requirement removed from policy",
        PropertyName has "SessionControls",
            "SESSION - Session control settings modified",
        PropertyName has "Conditions",
            "CONDITIONS - Policy conditions modified",
        OperationName has "Add", "CREATION - New policy added",
        "MODIFICATION - Policy setting changed"
    ),
    SeverityLevel = case(
        OperationName has "Delete", "CRITICAL",
        OperationName has "Disable Security Defaults", "CRITICAL",
        PropertyName == "State" and NewValue has "disabled", "CRITICAL",
        PropertyName has "ExcludeUsers" or PropertyName has "ExcludeGroups", "HIGH",
        PropertyName has "GrantControls" and OldValue has "mfa" and not(NewValue has "mfa"), "CRITICAL",
        PropertyName == "State" and NewValue has "enabledForReportingButNotEnforced", "HIGH",
        PropertyName has "ExcludeLocations", "HIGH",
        "MEDIUM"
    )
| project
    TimeGenerated,
    OperationName,
    ModifyingUser,
    ModifyingIP,
    PolicyName,
    ChangeCategory,
    SeverityLevel,
    PropertyName,
    OldValue = substring(OldValue, 0, 500),
    NewValue = substring(NewValue, 0, 500),
    Result
| sort by SeverityLevel asc, TimeGenerated asc
```

**Performance Notes:**
- `ModifiedProperties` contains the before/after state of each changed property
- `OldValue` and `NewValue` are JSON strings that may be very long -- truncated to 500 chars for readability
- Policy deletion events have minimal `ModifiedProperties` -- the policy name in `TargetResources` is the key data

**Tuning Guidance:**
- Policy deletion is always CRITICAL -- there is no undo without backup
- State change from "enabled" to "disabled" is as impactful as deletion but reversible
- Exclusion additions are subtle -- the policy still appears active, but the excluded entities bypass it
- MFA requirement removal from GrantControls is equivalent to disabling MFA for all affected users
- Check if `ModifyingApp` shows "Microsoft Graph" or "Azure AD PowerShell" -- programmatic changes are higher risk

**Expected findings:**
- Exact policy changes: what was modified, before/after state
- Who made the change, from what IP, using what tool
- Severity classification of each change

**Next action:**
- If policy deleted or disabled, proceed immediately to containment and restoration
- If exclusions modified, identify who/what was excluded and check for compromise
- Proceed to Step 2 to assess whether the modifying admin is compromised

---

### Step 2: Actor Compromise Assessment

**Purpose:** Determine if the admin who modified the CA policy is compromised. Analyze their sign-in context, check for Identity Protection risk events, and evaluate whether the policy change aligns with legitimate administrative work. A compromised Conditional Access Administrator is the most dangerous threat -- they control all access policies.

**Data needed:** SigninLogs, AADUserRiskEvents

```kql
// ============================================================
// QUERY 2: Actor Compromise Assessment
// Purpose: Check if the modifying admin is compromised
// Tables: SigninLogs, AADUserRiskEvents
// Investigation Step: 2 - Actor Compromise Assessment
// ============================================================
let ActorUPN = "suspicious.admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Admin sign-in context around the policy change ---
let AdminSignIns = SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 2h)
| where UserPrincipalName =~ ActorUPN
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
    ConditionalAccessStatus,
    ResourceDisplayName
| extend
    SignInOutcome = iff(ResultType == "0", "SUCCESS", strcat("FAILURE-", ResultType)),
    SessionRisk = case(
        RiskLevelDuringSignIn in ("high"), "CRITICAL",
        RiskLevelDuringSignIn in ("medium"), "HIGH",
        "LOW"
    ),
    DeviceTrust = case(
        tobool(IsCompliant) == true and tobool(IsManaged) == true, "TRUSTED",
        tobool(IsManaged) == true, "PARTIAL",
        "UNTRUSTED"
    ),
    IsAdminTool = AppDisplayName in (
        "Azure Portal", "Microsoft Entra admin center",
        "Microsoft Graph PowerShell", "Azure Active Directory PowerShell",
        "Microsoft Graph", "Graph Explorer"
    );
// --- Risk events for the admin ---
let AdminRisk = AADUserRiskEvents
| where TimeGenerated between (AlertTime - 7d .. AlertTime + 1d)
| where UserPrincipalName =~ ActorUPN
| project
    TimeGenerated,
    UserPrincipalName,
    RiskEventType,
    RiskLevel,
    RiskState,
    IPAddress,
    Location = strcat(City, ", ", CountryOrRegion);
// --- Combine assessment ---
AdminSignIns
| extend DataSource = "SignIn"
| project TimeGenerated, DataSource, IPAddress, Location,
    Detail = strcat(AppDisplayName, " [", SignInOutcome, "] Risk:", SessionRisk, " Device:", DeviceTrust),
    RiskAssessment = case(
        SessionRisk == "CRITICAL" and IsAdminTool,
            "CRITICAL - Admin tool access from high-risk session",
        DeviceTrust == "UNTRUSTED" and IsAdminTool,
            "HIGH - Admin tool access from untrusted device",
        SessionRisk != "LOW",
            "HIGH - Risky sign-in for admin account",
        "LOW - Standard admin sign-in"
    )
| union (
    AdminRisk
    | extend DataSource = "RiskEvent"
    | project TimeGenerated, DataSource, IPAddress, Location,
        Detail = strcat(RiskEventType, " (", RiskLevel, ")"),
        RiskAssessment = case(
            RiskLevel in ("high", "medium"), "HIGH - Admin has active risk detections",
            "LOW - Minor risk event"
        )
)
| sort by RiskAssessment asc, TimeGenerated asc
```

**Performance Notes:**
- Combining sign-in logs and risk events provides comprehensive admin compromise assessment
- 7-day risk event lookback captures risks that may have preceded the policy change by days
- Admin tool identification (`IsAdminTool`) helps determine if the admin was in the right portal

**Tuning Guidance:**
- If the admin signed in from a risky session AND made policy changes, the admin is likely compromised
- If the admin used Graph API or PowerShell from an untrusted device, this may be scripted attack
- Cross-reference the admin's IP with known corporate ranges
- Check if the admin has any other risky activities (MFA registration, role assignments)

**Expected findings:**
- Admin sign-in context: was the session risky? Was the device trusted?
- Whether the admin has Identity Protection risk detections
- Overall compromise likelihood for the admin account

**Next action:**
- If admin is likely compromised, escalate to containment for BOTH the admin and the CA policy
- If admin appears legitimate, check Step 4 for change management validation
- Cross-reference with RB-0013 (was this admin recently given their role?)

---

### Step 3: Policy Impact Analysis

**Purpose:** Assess the security impact of the CA policy change. Determine how many users, apps, and scenarios were previously protected by the policy and are now exposed. This quantifies the blast radius and helps prioritize response.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 3: Policy Impact Analysis
// Purpose: Quantify the security impact of the policy change
// Tables: SigninLogs
// Investigation Step: 3 - Policy Impact Analysis
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let PolicyName = "Require MFA for All Users";
// --- How many sign-ins were previously protected by this policy? ---
let PreChangeProtection = SigninLogs
| where TimeGenerated between (AlertTime - 7d .. AlertTime)
| where ConditionalAccessStatus == "success"
| mv-expand ConditionalAccessPolicies
| extend
    CAPolicyName = tostring(ConditionalAccessPolicies.displayName),
    CAPolicyResult = tostring(ConditionalAccessPolicies.result),
    CAPolicyId = tostring(ConditionalAccessPolicies.id)
| where CAPolicyName =~ PolicyName
| where CAPolicyResult == "success"  // Policy was applied and enforced
| summarize
    ProtectedSignIns = count(),
    ProtectedUsers = dcount(UserPrincipalName),
    ProtectedApps = dcount(AppDisplayName),
    TopUsers = make_set(UserPrincipalName, 10),
    TopApps = make_set(AppDisplayName, 10),
    TopCountries = make_set(tostring(LocationDetails.countryOrRegion), 10)
| extend PolicyAssessment = strcat(
    "This policy was protecting ",
    ProtectedUsers, " unique users across ",
    ProtectedApps, " applications. ",
    "All these sign-ins will now proceed WITHOUT the policy's controls."
);
// --- Post-change: sign-ins that would have been blocked or required MFA ---
let PostChangeExposure = SigninLogs
| where TimeGenerated between (AlertTime .. AlertTime + 4h)
| where ConditionalAccessStatus in ("notApplied", "failure")
| mv-expand ConditionalAccessPolicies
| extend
    CAPolicyName = tostring(ConditionalAccessPolicies.displayName),
    CAPolicyResult = tostring(ConditionalAccessPolicies.result)
| where CAPolicyName =~ PolicyName
| where CAPolicyResult == "notApplied"
| summarize
    UnprotectedSignIns = count(),
    ExposedUsers = dcount(UserPrincipalName),
    ExposedApps = dcount(AppDisplayName),
    ExposedCountries = make_set(tostring(LocationDetails.countryOrRegion), 10)
| extend ExposureAssessment = strcat(
    "Since the policy change, ",
    UnprotectedSignIns, " sign-ins from ",
    ExposedUsers, " users bypassed the disabled policy."
);
// --- Combine ---
PreChangeProtection
| extend Metric = "PRE_CHANGE_PROTECTION"
| project Metric, ProtectedSignIns, ProtectedUsers, ProtectedApps, PolicyAssessment
| union (
    PostChangeExposure
    | extend Metric = "POST_CHANGE_EXPOSURE"
    | project Metric, ProtectedSignIns = UnprotectedSignIns,
        ProtectedUsers = ExposedUsers, ProtectedApps = ExposedApps,
        PolicyAssessment = ExposureAssessment
)
```

**Performance Notes:**
- `ConditionalAccessPolicies` is a nested array in SigninLogs -- use `mv-expand` to extract individual policies
- 7-day pre-change analysis shows the full scope of protection that was lost
- Post-change analysis (4h window) shows immediate exploitation of the gap

**Tuning Guidance:**
- If the policy protected > 100 users, this is a high-impact change affecting a significant portion of the org
- Focus on sign-ins from unusual countries post-change -- these may be attackers exploiting the gap
- Check `ConditionalAccessStatus == "notApplied"` post-change to find sign-ins that bypassed the disabled policy
- If `ProtectedApps` includes email (Exchange Online), the exposure is critical for BEC risk

**Expected findings:**
- Quantified impact: how many users/apps/sign-ins were previously protected
- Post-change exposure: how many sign-ins are now unprotected
- Scope of the security gap created by the policy change

**Next action:**
- Use the impact numbers to prioritize restoration urgency
- If email apps are exposed, check for immediate BEC activity
- Proceed to Step 4 for baseline comparison

---

### Step 4: Baseline Comparison - Establish Normal Policy Change Pattern

**Purpose:** Determine if CA policy changes are anomalous by comparing against historical policy change patterns. How frequently are CA policies modified? Who normally makes these changes? What time of day? This establishes whether the change is a deviation from organizational norms.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 4: Baseline Comparison - Normal Policy Change Pattern
// Purpose: Compare policy change against org baseline
// Tables: AuditLogs
// Investigation Step: 4 - Baseline Comparison
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 30d;
let ActorUPN = "suspicious.admin@contoso.com";
// --- Org-wide CA policy change baseline ---
AuditLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
| where OperationName in (
    "Update conditional access policy",
    "Delete conditional access policy",
    "Add conditional access policy",
    "Disable Security Defaults"
)
| summarize
    TotalChanges = count(),
    UniqueModifiers = dcount(tostring(InitiatedBy.user.userPrincipalName)),
    KnownModifiers = make_set(tostring(InitiatedBy.user.userPrincipalName), 20),
    DeleteCount = countif(OperationName has "Delete"),
    DisableCount = countif(OperationName has "Disable"),
    UpdateCount = countif(OperationName has "Update"),
    AddCount = countif(OperationName has "Add"),
    ChangeHours = make_list(hourofday(TimeGenerated), 100),
    ModifierIPs = make_set(tostring(InitiatedBy.user.ipAddress), 20)
| extend
    AvgChangesPerWeek = todouble(TotalChanges) / (todouble(datetime_diff("day", AlertTime, AlertTime - BaselineDays)) / 7.0),
    ActorInBaseline = KnownModifiers has ActorUPN,
    Assessment = case(
        not(KnownModifiers has ActorUPN),
            "ANOMALOUS - This admin has NEVER modified CA policies in the baseline period",
        DeleteCount > 0,
            "NOTE - Policy deletions have occurred before (verify they were authorized)",
        "WITHIN BASELINE - CA policy changes occur within normal patterns"
    )
| project
    TotalChanges,
    UniqueModifiers,
    KnownModifiers,
    DeleteCount,
    UpdateCount,
    AvgChangesPerWeek,
    ActorInBaseline,
    Assessment
```

**Performance Notes:**
- 30-day baseline captures typical CA change frequency
- CA policy changes should be infrequent in stable environments (< 5 per week)
- `KnownModifiers` identifies the authorized CA admins by their historical activity

**Tuning Guidance:**
- If the actor has never modified CA policies before, their account may be newly compromised
- If the org averages < 2 CA changes per week and suddenly sees 5+ in a day, this is a spike
- If `DeleteCount > 0` in baseline, verify those historical deletions were authorized
- Cross-reference `ModifierIPs` -- if all previous changes came from corporate IPs and this one doesn't, escalate

**Expected findings:**
- Org-wide CA change frequency and authorized modifiers
- Whether the current actor is in the normal modifier set
- Whether the change type (deletion) has precedent

**Next action:**
- If actor not in baseline, investigate their account (likely compromised)
- If change frequency is anomalous, check for coordinated attack
- Proceed to Step 5 for post-modification exploitation

---

### Step 5: Post-Modification Exploitation Detection

**Purpose:** Detect sign-ins and activities that exploit the weakened security controls. After a CA policy is disabled, attackers (or other compromised accounts) may immediately attempt sign-ins that would have previously been blocked. This step identifies those exploitation attempts.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 5: Post-Modification Exploitation Detection
// Purpose: Find sign-ins exploiting the disabled CA policy
// Tables: SigninLogs
// Investigation Step: 5 - Post-Modification Exploitation Detection
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 12h;
let PolicyName = "Require MFA for All Users";
// --- Sign-ins after policy change that bypass the disabled policy ---
SigninLogs
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where ResultType == "0"  // Successful sign-ins only
| mv-expand ConditionalAccessPolicies
| extend
    CAPolicyName = tostring(ConditionalAccessPolicies.displayName),
    CAPolicyResult = tostring(ConditionalAccessPolicies.result)
| where CAPolicyName =~ PolicyName and CAPolicyResult == "notApplied"
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    Country = tostring(LocationDetails.countryOrRegion),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    IsManaged = DeviceDetail.isManaged,
    AuthenticationRequirement,
    RiskLevelDuringSignIn,
    ClientAppUsed
| extend
    ExploitationIndicator = case(
        RiskLevelDuringSignIn in ("high", "medium"),
            "CRITICAL - Risky sign-in succeeded WITHOUT MFA (policy disabled)",
        ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Other clients"),
            "HIGH - Legacy auth sign-in succeeded (previously blocked by CA)",
        tobool(IsManaged) != true and AuthenticationRequirement == "singleFactorAuthentication",
            "HIGH - Unmanaged device with single-factor auth (no MFA enforced)",
        Country !in ("US"),  // Adjust to org's country
            "HIGH - Foreign sign-in without MFA (CA would have required MFA)",
        AuthenticationRequirement == "singleFactorAuthentication",
            "MEDIUM - Sign-in without MFA (policy would have required it)",
        "LOW - Sign-in that bypassed disabled policy"
    ),
    MinutesSinceChange = datetime_diff("minute", TimeGenerated, AlertTime)
| where ExploitationIndicator !startswith "LOW"
| summarize
    ExploitationCount = count(),
    AffectedUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 20),
    Countries = make_set(Country, 10),
    LegacyAuthCount = countif(ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "SMTP")),
    HighRiskCount = countif(RiskLevelDuringSignIn in ("high", "medium"))
    by ExploitationIndicator
| sort by ExploitationIndicator asc
```

**Performance Notes:**
- `ConditionalAccessPolicies[].result == "notApplied"` identifies sign-ins that bypassed the disabled policy
- `ClientAppUsed` identifies legacy authentication protocols that should be blocked
- `AuthenticationRequirement == "singleFactorAuthentication"` means no MFA was required

**Tuning Guidance:**
- Legacy auth sign-ins (IMAP, POP3, SMTP) after blocking policy disabled = immediate exploitation
- High-risk sign-ins without MFA = the CA policy was the only thing blocking these
- Foreign country sign-ins without MFA = possible credential stuffing exploiting the gap
- If `AffectedUsers > 10` within the first hour, this may be a coordinated attack

**Expected findings:**
- Sign-ins that succeeded without MFA because the CA policy was disabled
- Legacy auth protocols used that were previously blocked
- Countries and risk levels of exploiting sign-ins

**Next action:**
- If exploitation detected, restore the CA policy immediately (containment)
- For each exploiting user, check if their account is compromised
- If legacy auth exploitation, block legacy auth at the authentication policy level

---

### Step 6: Security Configuration Drift Sweep

**Purpose:** Perform a comprehensive sweep of all security configurations to detect drift from the expected baseline. Beyond the specific CA policy change, check if other security settings have been modified -- Security Defaults, authentication policies, named locations, and authorization policies.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 6: Security Configuration Drift Sweep
// Purpose: Find all security config changes across the tenant
// Tables: AuditLogs
// Investigation Step: 6 - Security Configuration Drift Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let SweepWindow = 7d;
// --- All security-related configuration changes ---
AuditLogs
| where TimeGenerated between (AlertTime - SweepWindow .. AlertTime + 1d)
| where OperationName in (
    // Conditional Access
    "Update conditional access policy",
    "Delete conditional access policy",
    "Add conditional access policy",
    // Security Defaults
    "Disable Security Defaults",
    "Enable Security Defaults",
    // Named Locations
    "Update named location",
    "Delete named location",
    "Add named location",
    // Authentication policies
    "Update authorization policy",
    "Update authentication methods policy",
    "Set password policy",
    // MFA settings
    "Update authentication strengths policy",
    "Update StsRefreshTokenValidFrom Timestamp",
    // Tenant settings
    "Set Company Information",
    "Set DirSync feature",
    "Set federation settings on domain"
)
| extend
    ModifyingUser = tostring(InitiatedBy.user.userPrincipalName),
    ModifyingIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    ConfigCategory = case(
        OperationName has "conditional access", "CONDITIONAL ACCESS",
        OperationName has "Security Defaults", "SECURITY DEFAULTS",
        OperationName has "named location", "NAMED LOCATIONS",
        OperationName has "authorization" or OperationName has "authentication", "AUTH POLICY",
        OperationName has "federation", "FEDERATION",
        OperationName has "password", "PASSWORD POLICY",
        "OTHER CONFIG"
    ),
    DriftSeverity = case(
        OperationName has "Delete conditional access" or OperationName has "Disable Security Defaults",
            "CRITICAL - Security control removed",
        OperationName has "federation",
            "CRITICAL - Federation change (Golden SAML risk)",
        OperationName has "Update conditional access" and ModifiedProperties has "disabled",
            "HIGH - CA policy disabled",
        OperationName has "Delete named location",
            "HIGH - Trusted location removed",
        OperationName has "authentication methods",
            "MEDIUM - Auth method policy changed",
        "LOW - Configuration modification"
    )
| where DriftSeverity !startswith "LOW"
| project
    TimeGenerated,
    ConfigCategory,
    OperationName,
    ModifyingUser,
    ModifyingIP,
    TargetResource,
    DriftSeverity
| sort by DriftSeverity asc, TimeGenerated asc
```

**Performance Notes:**
- 7-day sweep captures configuration drift that may have accumulated over the week
- Federation changes are included because they are the highest-impact security modification
- This query provides a holistic view of all security configuration changes, not just CA policies

**Tuning Guidance:**
- Multiple CRITICAL changes by the same user = systematic security sabotage
- Federation changes are extremely rare and always require investigation
- If named locations were modified, check if the attacker added their IP to a trusted location
- Cross-reference modifying users -- if they're all the same compromised admin, the scope is clear

**Expected findings:**
- All security configuration changes in the past 7 days
- Whether changes are isolated to CA or part of broader security sabotage
- Common actors across multiple configuration changes

**Next action:**
- If multiple CRITICAL changes found, this is a coordinated attack
- Restore all unauthorized configuration changes
- Proceed to Step 7 for attack chain correlation

---

### Step 7: Correlated Attack Chain Detection

**Purpose:** Determine if the CA policy change is part of a larger attack chain. CA policy manipulation rarely happens in isolation -- it is typically preceded by privilege escalation (RB-0013) and followed by exploitation (credential attacks, BEC, data exfiltration). This step maps the full attack timeline.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 7: Correlated Attack Chain Detection
// Purpose: Map the full attack chain around CA policy manipulation
// Tables: AuditLogs
// Investigation Step: 7 - Attack Chain Detection
// ============================================================
let ActorUPN = "suspicious.admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- All high-impact actions by the actor in a 48h window ---
AuditLogs
| where TimeGenerated between (AlertTime - 24h .. AlertTime + 24h)
| where InitiatedBy has ActorUPN
| where OperationName in (
    // Privilege escalation (pre-CA change)
    "Add member to role",
    "Add eligible member to role",
    // CA manipulation (the alert)
    "Update conditional access policy",
    "Delete conditional access policy",
    "Disable Security Defaults",
    // Persistence (during/after CA change)
    "User registered security info",
    "Consent to application",
    "Add service principal credentials",
    "Add application",
    "New-InboxRule",
    "Set-InboxRule",
    "Set-Mailbox",
    // Account creation (backdoors)
    "Add user",
    // Federation (Golden SAML)
    "Set federation settings on domain",
    // Evidence destruction
    "Update diagnostic setting",
    "Delete diagnostic setting",
    // Other high-impact
    "Reset password (by admin)",
    "Update named location",
    "Delete named location"
)
| extend
    TargetResource = tostring(TargetResources[0].displayName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    AttackPhase = case(
        OperationName has_any ("Add member to role", "Add eligible member to role"),
            "1-ESCALATION - Privilege gained",
        OperationName has_any ("conditional access", "Security Defaults", "named location"),
            "2-DEFENSE EVASION - Security controls disabled",
        OperationName has_any ("security info", "Consent", "service principal", "InboxRule", "Set-Mailbox"),
            "3-PERSISTENCE - Access maintained",
        OperationName == "Add user",
            "3-PERSISTENCE - Backdoor account created",
        OperationName has "federation",
            "3-PERSISTENCE - Federation trust (Golden SAML)",
        OperationName has_any ("diagnostic", "Reset password"),
            "4-CLEANUP - Evidence destruction / credential control",
        "5-OTHER"
    ),
    MinutesFromCAChange = datetime_diff("minute", TimeGenerated, AlertTime)
| project
    TimeGenerated,
    AttackPhase,
    OperationName,
    TargetResource,
    MinutesFromCAChange
| sort by TimeGenerated asc
```

**Performance Notes:**
- 48-hour window (24h before, 24h after) captures the full attack chain
- `AttackPhase` categorization maps to the typical attacker playbook
- `MinutesFromCAChange` shows timing relative to the CA modification for timeline analysis

**Tuning Guidance:**
- If Phase 1 (ESCALATION) events appear before Phase 2 (CA change), the attack chain is: compromise → escalate → disable controls
- If Phase 3 (PERSISTENCE) events appear after Phase 2, the attacker is establishing multiple footholds
- If Phase 4 (CLEANUP) events appear, the attacker is actively covering tracks
- A complete chain (1→2→3→4) indicates a sophisticated, planned attack -- likely nation-state or organized crime

**Expected findings:**
- Full attack timeline mapped to phases
- Whether the CA change was preceded by privilege escalation
- Whether persistence mechanisms were established after the CA change
- Whether evidence destruction occurred

**Next action:**
- Use the attack chain to guide complete remediation (address ALL phases)
- For each phase, follow the corresponding runbook (RB-0013, RB-0012, RB-0011, etc.)
- Brief SOC leadership on the full attack chain scope

---

## 6. Containment Playbook

### Immediate Actions (First 15 Minutes)

| Priority | Action | Command/Location | Who |
|---|---|---|---|
| P0 | Restore deleted/disabled CA policies | Re-create from backup or enable from "reportOnly"/disabled state | CA Admin |
| P0 | Re-enable Security Defaults (if disabled and no CA policies exist) | Entra Portal > Properties > Security Defaults | Global Admin |
| P0 | Revoke sessions for the modifying admin | `Revoke-MgUserSignInSession -UserId [UPN]` | Security Admin |
| P0 | Block sign-in for compromised admin | Entra Portal > Users > [Admin] > Block sign-in | User Admin |
| P0 | Reset admin password | Force change at next sign-in | Helpdesk Admin |
| P1 | Remove unauthorized CA policy exclusions | Entra Portal > Security > CA > [Policy] > Edit exclusions | CA Admin |
| P1 | Restore modified named locations | Re-add original IP ranges to named locations | CA Admin |

### Secondary Actions (First 4 Hours)

| Priority | Action | Details |
|---|---|---|
| P1 | Audit all CA policies for unauthorized changes | Compare current state against documented baseline |
| P1 | Review all admin accounts for compromise | Run RB-0013 for all Privileged Role Admin and CA Admin accounts |
| P2 | Block legacy authentication | Enable "Block legacy authentication" policy if it was disabled |
| P2 | Check for backdoor accounts | See Step 7 attack chain -- remove unauthorized accounts |
| P2 | Review federation configuration | Check for unauthorized federation trusts |
| P3 | Implement CA policy backup/versioning | Export CA policies to version control (Infrastructure as Code) |
| P3 | Enable CA policy change alerts | Configure Sentinel analytics rule for CA changes |
| P3 | Restrict CA Admin role | Use PIM with approval for CA Admin role |

### CA Policy Restoration Commands

```powershell
# Connect with Conditional Access Administrator
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# List all CA policies (check current state)
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State, Id

# Re-enable a disabled policy
Update-MgIdentityConditionalAccessPolicy `
    -ConditionalAccessPolicyId "POLICY_GUID" `
    -State "enabled"

# Remove an unauthorized exclusion
# First, get current policy details
$Policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId "POLICY_GUID"
# Then update conditions to remove the exclusion
# (Exact commands depend on what was excluded -- users, groups, or IPs)

# Revoke admin sessions
Revoke-MgUserSignInSession -UserId "suspicious.admin@contoso.com"
```

---

## 7. Evidence Collection Checklist

| Evidence | Source | Retention | Priority |
|---|---|---|---|
| CA policy change event (AuditLogs) | Microsoft Sentinel | Export query results | Critical |
| CA policy before/after state | AuditLogs ModifiedProperties | Export full JSON | Critical |
| Current CA policy configuration | Entra Portal / Graph API export | JSON export | Critical |
| Admin sign-in logs around change | Microsoft Sentinel | Export query results | Critical |
| Post-change exploitation sign-ins | Microsoft Sentinel | Export query results | Critical |
| Admin risk events | Microsoft Sentinel | Export query results | High |
| Security configuration drift report | Query results from Step 6 | Export CSV | High |
| Attack chain timeline | Query results from Step 7 | Export CSV | High |
| CA policy backup (if exists) | Version control / IaC repo | Retrieve baseline | High |
| Named locations configuration | Entra Portal | Screenshot + JSON | Medium |

---

## 8. Escalation Criteria

### Escalate to CISO / Incident Commander When:
- MFA-enforcing CA policy deleted or disabled
- Security Defaults disabled without documented CA migration
- Multiple CA policies modified by a single compromised admin
- Post-change exploitation detected (risky sign-ins without MFA)
- Attack chain confirms privilege escalation → CA change → exploitation
- Legacy authentication protocols accessed after blocking policy removed

### Escalate to Legal/Privacy When:
- Post-change exploitation resulted in data access (email, files)
- BEC activity detected during the exposure window
- Regulatory compliance controls (MFA, access controls) were compromised

### Escalate to Microsoft When:
- Suspected bypass of CA policy enforcement mechanism
- CA policy showing as enabled but not enforcing (platform bug)
- Contact: Microsoft Support or Premier Support

---

## 9. False Positive Documentation

| Scenario | How to Verify | Action |
|---|---|---|
| Planned CA policy modification | Check change management system for matching ticket | Document approval, update baseline |
| Migration from Security Defaults to CA | Verify documented migration plan exists | Ensure CA policies provide equivalent protection |
| Troubleshooting authentication issues | Verify IT ticket for the troubleshooting session | Confirm policy was restored after troubleshooting |
| Adding new office/VPN IP ranges | Verify network team request for new IP range | Confirm IP range belongs to organization |
| Policy moved to reportOnly for testing | Verify testing plan with documented revert timeline | Monitor and ensure policy is re-enabled |

---

## 10. MITRE ATT&CK Mapping

| Technique | ID | Tactic | How Detected |
|---|---|---|---|
| Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion | CA policy disabled/deleted in AuditLogs |
| Modify Authentication Process | T1556 | Persistence, Defense Evasion | MFA requirement removed from CA policy |
| Abuse Elevation Control Mechanism | T1548 | Privilege Escalation | CA exclusion added for attacker account |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence | Post-change exploitation via weakened controls |

---

## 11. Query Summary

| # | Query | Table | Purpose |
|---|---|---|---|
| 1 | Policy Change Event Analysis | AuditLogs | Identify CA changes, before/after state, severity |
| 2 | Actor Compromise Assessment | SigninLogs + AADUserRiskEvents | Check if modifying admin is compromised |
| 3 | Policy Impact Analysis | SigninLogs | Quantify security exposure from the change |
| 4 | Baseline Comparison | AuditLogs | Compare against normal policy change patterns |
| 5 | Post-Modification Exploitation | SigninLogs | Detect sign-ins exploiting disabled policy |
| 6 | Security Configuration Drift | AuditLogs | Sweep all security config changes |
| 7 | Attack Chain Detection | AuditLogs | Map full attack timeline and phases |

---

## Appendix A: Datatable Tests

### Test 1: Policy Change Detection

```kql
// ============================================================
// TEST 1: Policy Change Detection
// Validates: Query 1 - Detect CA policy changes and classify severity
// Expected: Delete MFA policy = "CRITICAL"
//           Disable legacy auth block = "CRITICAL"
//           Add exclusion = "HIGH"
//           Add new policy = "CREATION" (not critical)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Delete MFA policy (CRITICAL) ---
    datetime(2026-02-22T14:00:00Z), "Delete conditional access policy",
        dynamic({"user":{"userPrincipalName":"suspicious.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"Require MFA for All Users","id":"policy-001",
            "modifiedProperties":[]}]),
        "success",
    // --- Disable legacy auth block (CRITICAL) ---
    datetime(2026-02-22T14:05:00Z), "Update conditional access policy",
        dynamic({"user":{"userPrincipalName":"suspicious.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"Block Legacy Authentication","id":"policy-002",
            "modifiedProperties":[
                {"displayName":"State","oldValue":"\"enabled\"","newValue":"\"disabled\""}
            ]}]),
        "success",
    // --- Add exclusion (HIGH) ---
    datetime(2026-02-22T14:10:00Z), "Update conditional access policy",
        dynamic({"user":{"userPrincipalName":"suspicious.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"Require Compliant Device","id":"policy-003",
            "modifiedProperties":[
                {"displayName":"ExcludeUsers","oldValue":"[]","newValue":"[\"attacker@contoso.com\"]"}
            ]}]),
        "success",
    // --- Add new policy (not critical) ---
    datetime(2026-02-22T10:00:00Z), "Add conditional access policy",
        dynamic({"user":{"userPrincipalName":"security.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"displayName":"Test Policy","id":"policy-004",
            "modifiedProperties":[]}]),
        "success"
];
// --- Run detection ---
TestAuditLogs
| extend
    ModifyingUser = tostring(InitiatedBy.user.userPrincipalName),
    PolicyName = tostring(TargetResources[0].displayName),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    ChangeCategory = case(
        OperationName has "Delete", "DELETION - Policy permanently removed",
        PropertyName == "State" and NewValue has "disabled", "DISABLED - Policy enforcement turned off",
        PropertyName has "ExcludeUsers", "EXCLUSION - Users excluded from policy",
        OperationName has "Add", "CREATION - New policy added",
        "MODIFICATION"
    ),
    SeverityLevel = case(
        OperationName has "Delete", "CRITICAL",
        PropertyName == "State" and NewValue has "disabled", "CRITICAL",
        PropertyName has "ExcludeUsers", "HIGH",
        "MEDIUM"
    )
| project ModifyingUser, PolicyName, ChangeCategory, SeverityLevel, OperationName
// Expected: "Require MFA" deletion = "CRITICAL"
// Expected: "Block Legacy Auth" disabled = "CRITICAL"
// Expected: "Require Compliant Device" exclusion = "HIGH"
// Expected: "Test Policy" creation = "MEDIUM"
```

### Test 2: Post-Modification Exploitation

```kql
// ============================================================
// TEST 2: Post-Modification Exploitation
// Validates: Query 5 - Detect sign-ins exploiting disabled policies
// Expected: attacker from Russia without MFA = "CRITICAL"
//           legacy auth IMAP sign-in = "HIGH"
//           normal user from US = "MEDIUM"
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
    RiskLevelDuringSignIn: string,
    ClientAppUsed: string,
    ConditionalAccessStatus: string,
    ConditionalAccessPolicies: dynamic
) [
    // --- Risky sign-in without MFA from Russia ---
    datetime(2026-02-22T14:30:00Z), "attacker@contoso.com",
        "Microsoft Exchange Online", "203.0.113.100",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"isManaged":false}),
        "0", "singleFactorAuthentication", "high", "Browser", "notApplied",
        dynamic([{"displayName":"Require MFA for All Users","result":"notApplied","id":"policy-001"}]),
    // --- Legacy auth IMAP sign-in ---
    datetime(2026-02-22T14:45:00Z), "compromised.user@contoso.com",
        "Exchange Online", "198.51.100.80",
        dynamic({"city":"Lagos","countryOrRegion":"NG"}),
        dynamic({"isManaged":false}),
        "0", "singleFactorAuthentication", "none", "IMAP4", "notApplied",
        dynamic([{"displayName":"Require MFA for All Users","result":"notApplied","id":"policy-001"}]),
    // --- Normal user without MFA (still exploiting gap) ---
    datetime(2026-02-22T15:00:00Z), "normal.user@contoso.com",
        "Microsoft Teams", "10.0.0.50",
        dynamic({"city":"New York","countryOrRegion":"US"}),
        dynamic({"isManaged":true}),
        "0", "singleFactorAuthentication", "none", "Browser", "notApplied",
        dynamic([{"displayName":"Require MFA for All Users","result":"notApplied","id":"policy-001"}])
];
let AlertTime = datetime(2026-02-22T14:00:00Z);
let PolicyName = "Require MFA for All Users";
// --- Run exploitation detection ---
TestSigninLogs
| where TimeGenerated >= AlertTime and ResultType == "0"
| mv-expand ConditionalAccessPolicies
| extend
    CAPolicyName = tostring(ConditionalAccessPolicies.displayName),
    CAPolicyResult = tostring(ConditionalAccessPolicies.result)
| where CAPolicyName =~ PolicyName and CAPolicyResult == "notApplied"
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    ExploitationIndicator = case(
        RiskLevelDuringSignIn in ("high", "medium"),
            "CRITICAL - Risky sign-in succeeded WITHOUT MFA",
        ClientAppUsed in ("IMAP4", "POP3", "SMTP"),
            "HIGH - Legacy auth sign-in succeeded",
        Country !in ("US"),
            "HIGH - Foreign sign-in without MFA",
        AuthenticationRequirement == "singleFactorAuthentication",
            "MEDIUM - Sign-in without MFA",
        "LOW"
    )
| project UserPrincipalName, IPAddress, Country, ClientAppUsed, ExploitationIndicator
// Expected: attacker from RU with high risk = "CRITICAL"
// Expected: compromised.user via IMAP4 from NG = "HIGH - Legacy auth"
// Expected: normal.user from US = "MEDIUM - Sign-in without MFA"
```

### Test 3: Baseline Comparison

```kql
// ============================================================
// TEST 3: Baseline Comparison
// Validates: Query 4 - Compare CA change against org baseline
// Expected: suspicious.admin NOT in KnownModifiers = "ANOMALOUS"
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Known CA admin making changes (baseline) ---
    datetime(2026-01-20T10:00:00Z), "Update conditional access policy",
        dynamic({"user":{"userPrincipalName":"ca.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"displayName":"Policy A"}]), "success",
    datetime(2026-02-05T11:00:00Z), "Update conditional access policy",
        dynamic({"user":{"userPrincipalName":"ca.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"displayName":"Policy B"}]), "success",
    datetime(2026-02-10T09:00:00Z), "Add conditional access policy",
        dynamic({"user":{"userPrincipalName":"ca.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"displayName":"New Policy"}]), "success",
    // --- Suspicious admin making the change under investigation ---
    datetime(2026-02-22T14:00:00Z), "Delete conditional access policy",
        dynamic({"user":{"userPrincipalName":"suspicious.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"Require MFA for All Users"}]), "success"
];
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 30d;
let ActorUPN = "suspicious.admin@contoso.com";
TestAuditLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
| where OperationName in ("Update conditional access policy", "Delete conditional access policy", "Add conditional access policy")
| summarize
    TotalChanges = count(),
    KnownModifiers = make_set(tostring(InitiatedBy.user.userPrincipalName), 20),
    DeleteCount = countif(OperationName has "Delete")
| extend
    ActorInBaseline = KnownModifiers has ActorUPN,
    Assessment = iff(
        not(KnownModifiers has ActorUPN),
        "ANOMALOUS - This admin has NEVER modified CA policies in the baseline period",
        "WITHIN BASELINE"
    )
| project TotalChanges, KnownModifiers, DeleteCount, ActorInBaseline, Assessment
// Expected: KnownModifiers = ["ca.admin@contoso.com"] only
// Expected: ActorInBaseline = false
// Expected: Assessment = "ANOMALOUS"
```

### Test 4: Attack Chain Detection

```kql
// ============================================================
// TEST 4: Attack Chain Detection
// Validates: Query 7 - Map the full attack chain
// Expected: Phase 1 (role assignment) → Phase 2 (CA deletion) → Phase 3 (persistence)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Phase 1: Privilege escalation (30 min before CA change) ---
    datetime(2026-02-22T13:30:00Z), "Add member to role",
        dynamic({"user":{"userPrincipalName":"suspicious.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"suspicious.admin@contoso.com","modifiedProperties":[
            {"displayName":"Role.DisplayName","newValue":"Conditional Access Administrator"}
        ]}]), "success",
    // --- Phase 2: CA policy deletion (the alert) ---
    datetime(2026-02-22T14:00:00Z), "Delete conditional access policy",
        dynamic({"user":{"userPrincipalName":"suspicious.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"Require MFA for All Users"}]), "success",
    // --- Phase 2: Security Defaults disabled ---
    datetime(2026-02-22T14:02:00Z), "Disable Security Defaults",
        dynamic({"user":{"userPrincipalName":"suspicious.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"Security Defaults"}]), "success",
    // --- Phase 3: MFA registration (persistence) ---
    datetime(2026-02-22T14:10:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"suspicious.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"Suspicious Admin"}]), "success",
    // --- Phase 3: Inbox rule (BEC persistence) ---
    datetime(2026-02-22T14:15:00Z), "New-InboxRule",
        dynamic({"user":{"userPrincipalName":"suspicious.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"Auto-Forward Rule"}]), "success",
    // --- Phase 4: Audit log tampering ---
    datetime(2026-02-22T14:20:00Z), "Update diagnostic setting",
        dynamic({"user":{"userPrincipalName":"suspicious.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"AuditLog-Export"}]), "success"
];
let ActorUPN = "suspicious.admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
TestAuditLogs
| where InitiatedBy has ActorUPN
| extend
    AttackPhase = case(
        OperationName has "Add member to role", "1-ESCALATION",
        OperationName has_any ("conditional access", "Security Defaults"), "2-DEFENSE EVASION",
        OperationName has_any ("security info", "InboxRule"), "3-PERSISTENCE",
        OperationName has "diagnostic", "4-CLEANUP",
        "5-OTHER"
    ),
    MinutesFromCAChange = datetime_diff("minute", TimeGenerated, AlertTime)
| project TimeGenerated, AttackPhase, OperationName, MinutesFromCAChange
| sort by TimeGenerated asc
// Expected attack chain:
// -30 min: 1-ESCALATION (role assignment)
//   0 min: 2-DEFENSE EVASION (CA deletion)
//  +2 min: 2-DEFENSE EVASION (Security Defaults disabled)
// +10 min: 3-PERSISTENCE (MFA registration)
// +15 min: 3-PERSISTENCE (inbox rule)
// +20 min: 4-CLEANUP (audit log tampering)
```

---

## References

- [Microsoft: Conditional Access overview](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [Microsoft: Plan a Conditional Access deployment](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access)
- [Microsoft: Conditional Access policies and Security Defaults](https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults)
- [Microsoft: Block legacy authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy)
- [Microsoft: Named locations in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network)
- [Microsoft: Manage Conditional Access policies as code](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-apis)
- [MITRE ATT&CK T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- [Midnight Blizzard security control manipulation (2024)](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [CISA: Mitigating cloud-based identity threats](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
