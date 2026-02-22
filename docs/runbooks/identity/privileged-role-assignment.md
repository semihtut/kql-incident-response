---
title: "Privileged Role Assignment Anomaly"
id: RB-0013
severity: critical
status: reviewed
description: >
  Investigation runbook for anomalous privileged role assignments in Microsoft
  Entra ID and Privileged Identity Management (PIM). Covers detection of
  unauthorized Global Administrator, Exchange Administrator, Security
  Administrator, and other high-privilege directory role assignments. Includes
  permanent vs. eligible role analysis, PIM activation pattern review, role
  assignment actor attribution, post-assignment activity auditing, and org-wide
  privileged access sweep. Privileged role assignments are the primary mechanism
  for privilege escalation in cloud environments -- a single unauthorized Global
  Admin assignment grants full control over the entire Entra ID tenant.
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
    - tactic_id: TA0007
      tactic_name: "Discovery"
    - tactic_id: TA0040
      tactic_name: "Impact"
  techniques:
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: confirmed
    - technique_id: T1098.003
      technique_name: "Account Manipulation: Additional Cloud Roles"
      confidence: confirmed
    - technique_id: T1069.003
      technique_name: "Permission Groups Discovery: Cloud Groups"
      confidence: confirmed
    - technique_id: T1087.004
      technique_name: "Account Discovery: Cloud Account"
      confidence: confirmed
threat_actors:
  - "Midnight Blizzard (APT29/Nobelium)"
  - "LAPSUS$ (DEV-0537)"
  - "Scattered Spider (Octo Tempest)"
  - "Storm-0558"
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
  - table: "IdentityInfo"
    product: "Microsoft Sentinel UEBA"
    license: "Microsoft Sentinel"
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
  - IdentityInfo
tactic_slugs:
  - persistence
  - priv-esc
  - defense-evasion
  - cred-access
  - discovery
data_checks:
  - query: "AuditLogs | where OperationName has 'role' | take 1"
    label: primary
    description: "Directory role assignment event detection"
  - query: "SigninLogs | take 1"
    description: "For actor sign-in context and risk correlation"
  - query: "AADUserRiskEvents | take 1"
    label: optional
    description: "For risk detection on the assigning or assigned user"
  - query: "AzureActivity | take 1"
    label: optional
    description: "For Azure resource-level actions post-escalation"
---

# Privileged Role Assignment Anomaly - Investigation Runbook

> **RB-0013** | Severity: Critical | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Audit Logs + PIM Activation Logs
> **Risk Detection Name:** `Add member to role` / `Add eligible member to role` audit events + PIM role activation anomaly
> **Primary MITRE Technique:** T1098.003 - Account Manipulation: Additional Cloud Roles

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Role Assignment Event Analysis](#step-1-role-assignment-event-analysis)
   - [Step 2: Actor Attribution & Sign-In Context](#step-2-actor-attribution--sign-in-context)
   - [Step 3: PIM Activation Pattern Analysis](#step-3-pim-activation-pattern-analysis)
   - [Step 4: Baseline Comparison - Establish Normal Role Assignment Pattern](#step-4-baseline-comparison---establish-normal-role-assignment-pattern)
   - [Step 5: Post-Escalation Activity Audit](#step-5-post-escalation-activity-audit)
   - [Step 6: Target User Risk Assessment](#step-6-target-user-risk-assessment)
   - [Step 7: Org-Wide Privileged Role Sweep](#step-7-org-wide-privileged-role-sweep)
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
Privileged role assignment anomalies are detected through multiple complementary mechanisms:

1. **AuditLogs role assignment events:** The `Add member to role`, `Add eligible member to role`, and `Add scoped member to role` operations record every directory role assignment. Suspicious assignments include unexpected users receiving Global Administrator, granting permanent (not eligible) assignments to bypass PIM, and role assignments performed by non-privileged-role-admin users.
2. **PIM activation events:** Privileged Identity Management logs `Activate PIM role` events. Anomalous activations include first-time activations of critical roles, activations at unusual times, activations from unfamiliar IPs, and activations with unusually long durations or no justification.
3. **Cross-signal correlation:** A compromised account receiving a Global Admin role assignment followed by tenant-wide configuration changes (disabling security defaults, modifying Conditional Access, creating backdoor accounts) is the hallmark of a complete tenant takeover.

**Why it matters:**
Privileged role assignments are the **single highest-impact action** in Microsoft Entra ID. A Global Administrator has unrestricted access to every resource, every user, every application, and every configuration in the tenant. An attacker who obtains Global Admin can:
- Read all email in the organization via application permissions
- Disable all security controls (MFA, Conditional Access, Identity Protection)
- Create backdoor admin accounts for persistent access
- Modify federation settings to forge SAML tokens (Golden SAML attack)
- Access Azure subscriptions linked to the tenant
- Exfiltrate the entire directory (all users, groups, applications, credentials)

LAPSUS$ systematically escalated to Global Admin in every compromised tenant. Midnight Blizzard used OAuth applications with elevated roles during the Microsoft corporate breach. Storm-0558 exploited a signing key to access Exchange via elevated roles.

**Why this is CRITICAL severity:**
- Global Admin = full tenant ownership -- there is no higher privilege level
- A single unauthorized Global Admin assignment can compromise the entire organization
- Permanent role assignments bypass PIM just-in-time access controls
- Exchange Admin can access all mailboxes, Security Admin can disable protections
- Role assignments made by compromised accounts can go unnoticed for weeks
- If the attacker disables audit logging after escalation, forensic evidence is lost

**However:** This alert has a **low false positive rate** (~5-10%). Legitimate triggers include:
- Planned admin role assignments during IT staff onboarding or role changes
- Emergency break-glass account activation with documented change management
- PIM eligible role activation by authorized users for routine administration
- Temporary role assignments for specific projects with documented approval
- Azure AD Connect role assignments during hybrid identity setup

**Worst case scenario if this is real:**
An attacker compromises a user account with Privileged Role Administrator permissions (or a Global Admin account directly). They assign themselves (or another compromised account) the Global Administrator role as a permanent assignment, bypassing PIM. Within minutes, they: disable Conditional Access policies, disable security defaults, create three new admin accounts as backdoors, add a federation trust to forge SAML tokens, grant their OAuth application Directory.ReadWrite.All permissions, and begin mass email exfiltration. They then remove the original compromised account's role to cover tracks, but the backdoor accounts and federation trust persist. Even if the initial compromise is detected and the user's password is reset, the attacker maintains access through the backdoor admin accounts and the SAML token forgery capability. This is a complete tenant takeover scenario.

**Key difference from other identity runbooks:**
- RB-0001 through RB-0009 (Authentication-focused): Investigate credential and sign-in anomalies at the user level.
- RB-0010 (Service Principal): Investigates workload identity compromise -- non-human accounts.
- RB-0011 (Consent Grant): Investigates delegated permission abuse via OAuth.
- RB-0012 (MFA Registration): Investigates post-compromise persistence via MFA.
- **RB-0013 (This runbook):** Investigates **privilege escalation** -- the attacker elevating permissions to gain administrative control. This is the highest-impact attack in the identity attack chain because it transitions from "compromised user" to "compromised tenant." All other runbooks investigate individual account compromise; this runbook investigates organizational compromise.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID Free + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID (AuditLogs, SigninLogs)
- **Permissions:** Security Reader (investigation), Privileged Role Administrator (containment)

### Recommended for Full Coverage
- **License:** Entra ID P2 + Microsoft Sentinel + Azure Subscription
- **Additional:** Privileged Identity Management (PIM) enabled, Identity Protection enabled
- **Azure Activity:** Azure resource access logging for post-escalation correlation

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | AuditLogs, SigninLogs | Steps 1-2, 4-5, 7 |
| Above + Entra ID P2 | Above + AADUserRiskEvents, PIM events in AuditLogs | Steps 1-7 (full identity coverage) |
| Above + Azure Subscription | Above + AzureActivity | Steps 1-7 + Azure resource post-escalation |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let TargetUPN = "escalated.user@contoso.com";             // User who received the role
let ActorUPN = "assigning.admin@contoso.com";              // User who assigned the role (if known)
let SuspiciousRole = "Global Administrator";               // Role that was assigned
let AlertTime = datetime(2026-02-22T14:00:00Z);           // Time of role assignment
let LookbackWindow = 24h;                                 // Window to analyze pre-assignment activity
let ForwardWindow = 12h;                                   // Window after assignment for escalation activity
let BaselineDays = 30d;                                    // Baseline comparison window
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- Global Administrator assigned permanently (not via PIM eligible)
- Any privileged role assigned by a non-Privileged-Role-Administrator user
- Role assigned from an IP flagged by Identity Protection (anonymous IP, unfamiliar location)
- Multiple privileged roles assigned to the same user in a short window
- Role assigned to a newly created account (< 7 days old)
- Role assigned outside of change management window with no approval record
- Privileged role assigned followed by Conditional Access or security defaults modification

### Standard Investigation
- PIM eligible role activation with justification provided
- Role assigned by a known Privileged Role Administrator during business hours
- Temporary role assignment with documented IT ticket
- Role activation for a user who has been eligible for > 30 days (first activation)

### Likely Benign
- PIM eligible role activation by an authorized user with matching IT ticket
- Break-glass account activation with documented emergency procedure
- Azure AD Connect service account role assignment during hybrid setup
- Routine PIM role renewal by existing eligible administrator
- Role assignment by Global Admin as part of documented organizational change

---

## 5. Investigation Steps

### Step 1: Role Assignment Event Analysis

**Purpose:** Identify the exact role assignment event. Determine what role was assigned, to whom, by whom, whether it was permanent or eligible (PIM), from what IP, and the exact timing. This is the foundational evidence for the entire investigation.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 1: Role Assignment Event Analysis
// Purpose: Identify role assignment events, roles, actors, assignment type
// Tables: AuditLogs
// Investigation Step: 1 - Role Assignment Event Analysis
// ============================================================
let TargetUPN = "escalated.user@contoso.com";
let ActorUPN = "assigning.admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Role assignment events ---
AuditLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where OperationName in (
    "Add member to role",
    "Add eligible member to role",
    "Add scoped member to role",
    "Remove member from role",
    "Remove eligible member from role",
    "Add member to role in PIM requested (permanent)",
    "Add member to role in PIM requested (timebound)",
    "Add eligible member to role in PIM completed (permanent)",
    "Add member to role in PIM completed (timebound)"
)
| extend
    AssigningUser = tostring(InitiatedBy.user.userPrincipalName),
    AssigningIP = tostring(InitiatedBy.user.ipAddress),
    AssigningApp = tostring(InitiatedBy.app.displayName),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    TargetDisplayName = tostring(TargetResources[0].displayName),
    TargetId = tostring(TargetResources[0].id),
    ModifiedProps = TargetResources[0].modifiedProperties
| where TargetUser =~ TargetUPN
    or AssigningUser =~ ActorUPN
    or TargetDisplayName =~ TargetUPN
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    RoleName = case(
        PropertyName == "Role.DisplayName", NewValue,
        PropertyName == "Role.TemplateId", strcat("RoleTemplateId: ", NewValue),
        ""
    ),
    AssignmentType = case(
        OperationName has "eligible", "ELIGIBLE (PIM just-in-time)",
        OperationName has "permanent", "PERMANENT (always active)",
        OperationName has "timebound", "TIMEBOUND (PIM with expiry)",
        OperationName has "Remove", "REMOVAL",
        OperationName == "Add member to role", "PERMANENT (direct assignment)",
        "UNKNOWN"
    )
| where isnotempty(RoleName) or OperationName has "role"
| project
    TimeGenerated,
    OperationName,
    AssigningUser,
    AssigningIP,
    AssigningApp,
    TargetUser = coalesce(TargetUser, TargetDisplayName),
    RoleName,
    AssignmentType,
    Result
| extend
    SeverityAssessment = case(
        RoleName in ("Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator")
            and AssignmentType has "PERMANENT",
            "CRITICAL - Permanent assignment to highest-privilege role",
        RoleName in ("Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator"),
            "HIGH - Assignment to highest-privilege role",
        RoleName in ("Exchange Administrator", "SharePoint Administrator", "Security Administrator",
            "Compliance Administrator", "Application Administrator", "Cloud Application Administrator",
            "User Administrator", "Authentication Administrator", "Intune Administrator"),
            "HIGH - Assignment to sensitive administrative role",
        RoleName in ("Global Reader", "Security Reader", "Reports Reader"),
            "MEDIUM - Read-only privileged role",
        AssignmentType == "REMOVAL",
            "INFO - Role removal (check if covering tracks)",
        "MEDIUM - Review role permissions"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- `Role.DisplayName` in `ModifiedProperties` provides the human-readable role name
- `Role.TemplateId` provides the GUID -- use Microsoft's built-in role ID reference for mapping
- PIM events include separate request and completion entries -- both are relevant for timeline

**Tuning Guidance:**
- Permanent Global Admin assignments should NEVER occur in a mature environment -- always escalate
- If `AssigningApp` is populated instead of `AssigningUser`, the assignment was made programmatically (Graph API, PowerShell) -- higher risk
- Role removals immediately after a suspicious assignment may indicate the attacker covering tracks
- Cross-reference `AssigningIP` with known corporate IP ranges and the assigning user's normal locations

**Expected findings:**
- Complete role assignment event: who assigned, to whom, what role, permanent vs. eligible
- If a high-privilege role was permanently assigned from a suspicious IP, this confirms privilege escalation
- If the assigning user is not a known Privileged Role Administrator, the assigning account is likely compromised

**Next action:**
- If critical role permanently assigned, proceed immediately to containment
- If assigned by unknown actor, proceed to Step 2 for sign-in context
- Note all IPs and timestamps for correlation across subsequent queries

---

### Step 2: Actor Attribution & Sign-In Context

**Purpose:** Analyze the sign-in activity of the user who performed the role assignment. Determine if the assigning user's session was legitimate or potentially compromised. A compromised admin account assigning roles is the most common privilege escalation scenario.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 2: Actor Attribution & Sign-In Context
// Purpose: Analyze the assigning user's sign-in for compromise indicators
// Tables: SigninLogs
// Investigation Step: 2 - Actor Attribution & Sign-In Context
// ============================================================
let ActorUPN = "assigning.admin@contoso.com";
let TargetUPN = "escalated.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Assigning user's sign-in activity ---
SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 2h)
| where UserPrincipalName =~ ActorUPN or UserPrincipalName =~ TargetUPN
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
    ResultDescription,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    ResourceDisplayName,
    CorrelationId
| extend
    UserRole = case(
        UserPrincipalName =~ ActorUPN, "ACTOR (assigned role)",
        UserPrincipalName =~ TargetUPN, "TARGET (received role)",
        "OTHER"
    ),
    SignInOutcome = case(
        ResultType == "0", "SUCCESS",
        ResultType == "50074", "MFA REQUIRED",
        ResultType == "53003", "BLOCKED BY CA",
        ResultType == "50126", "WRONG PASSWORD",
        strcat("FAILURE - ", ResultType)
    ),
    SessionRisk = case(
        RiskLevelDuringSignIn in ("high"), "CRITICAL - High risk session",
        RiskLevelDuringSignIn in ("medium"), "HIGH - Medium risk session",
        "LOW - No risk detected"
    ),
    DeviceTrust = case(
        tobool(IsCompliant) == true and tobool(IsManaged) == true, "TRUSTED - Compliant managed device",
        tobool(IsManaged) == true, "PARTIAL - Managed but not compliant",
        "UNTRUSTED - Unmanaged/unknown device"
    ),
    IsAdminPortal = AppDisplayName in (
        "Azure Portal", "Microsoft Azure Management",
        "Microsoft Entra admin center", "Entra Admin Center",
        "Azure Active Directory PowerShell", "Microsoft Graph PowerShell",
        "Microsoft Graph", "Graph Explorer"
    )
| extend
    SuspicionLevel = case(
        UserRole == "ACTOR" and SessionRisk startswith "CRITICAL",
            "CRITICAL - Assigning user had a high-risk session",
        UserRole == "ACTOR" and DeviceTrust == "UNTRUSTED" and IsAdminPortal,
            "HIGH - Admin action from untrusted device",
        UserRole == "ACTOR" and Country != "US",  // Adjust to org's primary country
            "HIGH - Admin action from unusual country",
        UserRole == "TARGET" and SessionRisk != "LOW",
            "HIGH - Target user also has risky sign-ins",
        UserRole == "ACTOR" and IsAdminPortal,
            "REVIEW - Admin portal access by assigning user",
        "LOW"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- Query both the actor (who assigned) and the target (who received) to build complete context
- `AppDisplayName` identifies the admin tool used -- Azure Portal, PowerShell, Graph API
- If `ConditionalAccessStatus == "notApplied"`, check whether admin portals should have CA policies

**Tuning Guidance:**
- Adjust `Country != "US"` to your organization's primary operating countries
- If the actor used Graph API or PowerShell (not the Azure Portal), this may indicate scripted/automated escalation
- If both actor and target have risky sign-ins, this is a coordinated attack or both accounts are compromised
- Check if the actor's session satisfies Conditional Access for admin operations

**Expected findings:**
- Assigning user's session context: IP, location, device, risk level
- Whether the admin session was from a trusted device and expected location
- Whether the target user also shows signs of compromise

**Next action:**
- If assigning user's session is risky, the admin account is likely compromised
- If actor used PowerShell/Graph API from untrusted device, investigate the actor's account
- Proceed to Step 3 for PIM activation analysis

---

### Step 3: PIM Activation Pattern Analysis

**Purpose:** If the organization uses PIM, analyze role activation patterns. Determine if the role was activated through the proper PIM workflow (with justification and approval) or if it was assigned outside of PIM as a permanent role (bypassing just-in-time controls). Also review the target user's PIM activation history for anomalous patterns.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 3: PIM Activation Pattern Analysis
// Purpose: Analyze PIM role activation events and bypass indicators
// Tables: AuditLogs
// Investigation Step: 3 - PIM Activation Pattern Analysis
// ============================================================
let TargetUPN = "escalated.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- PIM role activation events ---
AuditLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where Category == "RoleManagement"
    or OperationName has_any (
        "PIM", "Activate", "eligible",
        "Add member to role", "Remove member from role"
    )
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetUser = coalesce(
        tostring(TargetResources[0].userPrincipalName),
        tostring(TargetResources[0].displayName)
    ),
    ModifiedProps = TargetResources[0].modifiedProperties
| where ActorUPN =~ TargetUPN
    or TargetUser =~ TargetUPN
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    RoleName = iff(PropertyName == "Role.DisplayName", NewValue, ""),
    Justification = iff(PropertyName == "Justification", NewValue, ""),
    TicketNumber = iff(PropertyName == "TicketNumber", NewValue, ""),
    ActivationDuration = iff(PropertyName == "ScheduleInfo.Duration", NewValue, "")
| summarize
    RoleNames = make_set_if(RoleName, isnotempty(RoleName)),
    Justifications = make_set_if(Justification, isnotempty(Justification)),
    TicketNumbers = make_set_if(TicketNumber, isnotempty(TicketNumber)),
    Durations = make_set_if(ActivationDuration, isnotempty(ActivationDuration))
    by TimeGenerated, OperationName, ActorUPN, ActorIP, TargetUser, Result
| extend
    PIMAssessment = case(
        OperationName has "permanent" and array_length(RoleNames) > 0,
            "CRITICAL - Permanent role assignment (bypasses PIM)",
        OperationName has "Add member to role" and not(OperationName has "PIM")
            and not(OperationName has "eligible"),
            "HIGH - Direct permanent assignment (outside PIM workflow)",
        array_length(Justifications) == 0 and OperationName has "Activate",
            "HIGH - PIM activation without justification",
        Justifications has_any ("test", "temp", "asdf", "xxx", "123"),
            "MEDIUM - PIM activation with suspicious justification",
        OperationName has "Activate" and array_length(Justifications) > 0,
            "LOW - PIM activation with justification provided",
        OperationName has "eligible",
            "REVIEW - Eligible role assignment (requires activation)",
        "REVIEW - Requires context"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- PIM events have `Category == "RoleManagement"` in AuditLogs
- `Justification` and `TicketNumber` fields indicate whether the activation followed proper workflow
- Permanent assignments (`Add member to role`) bypass PIM entirely -- these are the highest risk

**Tuning Guidance:**
- Any `Add member to role` (permanent) for a critical role should be immediately investigated
- Empty justifications for PIM activations may indicate automated or unauthorized activations
- Suspicious justifications ("test", "temp", "asdf") suggest an attacker providing minimal required fields
- Check `ActivationDuration` -- unusually long durations (8h+ for roles that normally need 1-2h) are suspicious

**Expected findings:**
- Whether the role was assigned through PIM (eligible + activation) or directly (permanent)
- Justification and ticket number for PIM activations
- Pattern of PIM activations by the target user

**Next action:**
- If permanent assignment bypassing PIM, escalate immediately
- If PIM activation with weak justification, investigate the activating user
- Proceed to Step 4 for baseline comparison

---

### Step 4: Baseline Comparison - Establish Normal Role Assignment Pattern

**Purpose:** Determine if the role assignment is anomalous by comparing against historical role assignment patterns. How frequently are privileged roles assigned? Who normally makes these assignments? What time of day? This establishes whether the assignment is a deviation from organizational norms.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 4: Baseline Comparison - Normal Role Assignment Pattern
// Purpose: Compare role assignment against org baseline
// Tables: AuditLogs
// Investigation Step: 4 - Baseline Comparison
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 30d;
let TargetUPN = "escalated.user@contoso.com";
let ActorUPN = "assigning.admin@contoso.com";
// --- Org-wide role assignment baseline ---
let OrgBaseline = AuditLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
| where OperationName in (
    "Add member to role",
    "Add eligible member to role",
    "Add member to role in PIM requested (permanent)",
    "Add member to role in PIM completed (timebound)"
)
| summarize
    TotalAssignments = count(),
    UniqueAssigners = dcount(tostring(InitiatedBy.user.userPrincipalName)),
    KnownAssigners = make_set(tostring(InitiatedBy.user.userPrincipalName), 20),
    UniqueRecipients = dcount(tostring(TargetResources[0].userPrincipalName)),
    RolesAssigned = make_set(tostring(TargetResources[0].modifiedProperties), 50),
    PermanentCount = countif(OperationName == "Add member to role"),
    EligibleCount = countif(OperationName has "eligible"),
    AvgPerDay = todouble(count()) / todouble(datetime_diff("day", AlertTime, AlertTime - BaselineDays)),
    AssignmentHours = make_list(hourofday(TimeGenerated), 1000)
| extend EntityType = "ORG_BASELINE";
// --- Has the actor ever assigned roles before? ---
let ActorBaseline = AuditLogs
| where TimeGenerated between (AlertTime - 90d .. AlertTime)
| where OperationName in (
    "Add member to role",
    "Add eligible member to role"
)
| where InitiatedBy has ActorUPN
| summarize
    ActorTotalAssignments = count(),
    RolesAssignedByActor = make_set(tostring(TargetResources[0].modifiedProperties), 20),
    ActorAssignmentIPs = make_set(tostring(InitiatedBy.user.ipAddress), 10),
    LastAssignment = max(TimeGenerated)
| extend EntityType = "ACTOR_BASELINE";
// --- Has the target ever had privileged roles? ---
let TargetHistory = AuditLogs
| where TimeGenerated between (AlertTime - 365d .. AlertTime)
| where OperationName in (
    "Add member to role", "Add eligible member to role",
    "Remove member from role", "Remove eligible member from role"
)
| where TargetResources has TargetUPN
| summarize
    TargetRoleEvents = count(),
    TargetRoles = make_set(tostring(TargetResources[0].modifiedProperties), 20),
    FirstRoleAssignment = min(TimeGenerated),
    LastRoleChange = max(TimeGenerated)
| extend EntityType = "TARGET_HISTORY";
// --- Assess anomaly ---
OrgBaseline
| extend
    Assessment = case(
        not(KnownAssigners has ActorUPN),
            "ANOMALOUS - Actor has never assigned roles in the last 30 days",
        PermanentCount > EligibleCount * 2,
            "SUSPICIOUS - Org has more permanent than eligible assignments (PIM bypass pattern)",
        "WITHIN BASELINE - Role assignments are within normal org patterns"
    )
| project EntityType, TotalAssignments, UniqueAssigners, KnownAssigners, PermanentCount, EligibleCount, AvgPerDay, Assessment
```

**Performance Notes:**
- 30-day org baseline captures normal assignment frequency; 90-day actor baseline captures infrequent assigners
- 365-day target history shows whether the user has ever held privileged roles
- `KnownAssigners` list helps identify whether the current actor is an authorized role assigner

**Tuning Guidance:**
- If the actor has never assigned roles in 90 days, they may not be an authorized Privileged Role Administrator
- If the org averages < 1 role assignment per day and suddenly sees 5+ in an hour, this is a spike
- If the target user has never held any privileged role in 365 days, a Global Admin assignment is highly anomalous
- Cross-reference `ActorAssignmentIPs` with the current assignment IP

**Expected findings:**
- Org-wide role assignment frequency and authorized assigners
- Whether the current actor and target are in the normal pattern
- Historical context for the target user's privilege level

**Next action:**
- If actor is not in `KnownAssigners`, investigate the actor's account (likely compromised)
- If target has never held privileged roles, treat the assignment as highly suspicious
- Proceed to Step 5 for post-escalation activity

---

### Step 5: Post-Escalation Activity Audit

**Purpose:** Determine what the user did AFTER receiving the privileged role. Track tenant-level configuration changes, new account creation, Conditional Access modifications, federation changes, and any other actions that indicate the elevated privileges are being abused. This is where the blast radius becomes apparent.

**Data needed:** AuditLogs, AzureActivity

```kql
// ============================================================
// QUERY 5: Post-Escalation Activity Audit
// Purpose: Track high-impact admin actions after role assignment
// Tables: AuditLogs
// Investigation Step: 5 - Post-Escalation Activity Audit
// ============================================================
let TargetUPN = "escalated.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 12h;
// --- High-impact admin actions after role assignment ---
AuditLogs
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where InitiatedBy has TargetUPN
| where OperationName in (
    // --- Tenant-level configuration changes ---
    "Set Company Information",
    "Set password policy",
    "Set federation settings on domain",
    "Set domain authentication",
    "Set DirSync feature",
    // --- Security controls modification ---
    "Update conditional access policy",
    "Delete conditional access policy",
    "Disable Security Defaults",
    "Update authorization policy",
    "Update authentication methods policy",
    // --- User/account creation and modification ---
    "Add user",
    "Add member to role",
    "Add eligible member to role",
    "Update user",
    "Reset password (by admin)",
    "Add owner to application",
    "Add service principal credentials",
    // --- Application and consent ---
    "Add application",
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to service principal",
    // --- Group and directory changes ---
    "Add member to group",
    "Add owner to group",
    "Update group",
    // --- Audit log tampering indicators ---
    "Update diagnostic setting",
    "Delete diagnostic setting"
)
| project
    TimeGenerated,
    OperationName,
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    TargetResourceType = tostring(TargetResources[0].type),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties),
    Result
| extend
    ImpactCategory = case(
        OperationName has_any ("federation", "domain authentication"),
            "CRITICAL - Federation/domain changes (Golden SAML risk)",
        OperationName has_any ("Disable Security Defaults", "Delete conditional access"),
            "CRITICAL - Security controls disabled",
        OperationName has_any ("diagnostic setting"),
            "CRITICAL - Audit logging modified (anti-forensics)",
        OperationName has_any ("Add member to role", "Add eligible member to role"),
            "HIGH - Additional role assignments (privilege spreading)",
        OperationName has_any ("Add user") and ModifiedProperties has "admin",
            "HIGH - New admin account created (backdoor)",
        OperationName == "Add user",
            "HIGH - New user account created",
        OperationName has_any ("Add service principal credentials", "Add application"),
            "HIGH - App/SP credential modification (persistence)",
        OperationName has_any ("Consent to application", "Add delegated permission"),
            "HIGH - OAuth consent grant (data access)",
        OperationName has_any ("Update conditional access", "authorization policy"),
            "MEDIUM - Security policy modification",
        OperationName has_any ("Reset password"),
            "MEDIUM - Password reset by admin",
        "REVIEW - Admin action requires context"
    ),
    MinutesSinceEscalation = datetime_diff("minute", TimeGenerated, AlertTime)
| sort by ImpactCategory asc, TimeGenerated asc
```

**Performance Notes:**
- The OperationName filter covers the highest-impact admin actions possible in Entra ID
- Federation changes are the most dangerous -- they enable Golden SAML token forgery
- Diagnostic setting changes may indicate the attacker trying to disable audit logging

**Tuning Guidance:**
- Federation/domain authentication changes are extremely rare in normal operations -- always escalate
- If `Disable Security Defaults` appears, the attacker is removing baseline MFA protection
- New user accounts created within minutes of escalation are almost certainly backdoor accounts
- If the attacker modifies Conditional Access to exclude their IP or device, this enables persistent unmonitored access
- Multiple high-impact actions within 30 minutes of escalation = active exploitation

**Expected findings:**
- Complete timeline of admin actions performed after the privilege escalation
- Whether security controls were modified or disabled
- Whether backdoor accounts, apps, or federation trusts were created
- Whether audit logging was tampered with

**Next action:**
- If federation changes detected, this is a tenant takeover -- maximum escalation
- If new admin accounts created, identify and disable them immediately
- If CA policies modified, restore from backup/documentation
- Proceed to Step 6 for target user risk assessment

---

### Step 6: Target User Risk Assessment

**Purpose:** Assess the risk profile of the user who received the privileged role. Check if this user has been flagged by Identity Protection, has recent risky sign-ins, or shows signs of compromise. A compromised user receiving a privileged role is the worst-case scenario.

**Data needed:** AADUserRiskEvents, SigninLogs

```kql
// ============================================================
// QUERY 6: Target User Risk Assessment
// Purpose: Check if the role recipient has risk indicators
// Tables: AADUserRiskEvents, SigninLogs
// Investigation Step: 6 - Target User Risk Assessment
// ============================================================
let TargetUPN = "escalated.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Risk events for the target user ---
let RiskEvents = AADUserRiskEvents
| where TimeGenerated between (AlertTime - 7d .. AlertTime + 1d)
| where UserPrincipalName =~ TargetUPN
| project
    TimeGenerated,
    UserPrincipalName,
    RiskEventType,
    RiskLevel,
    RiskState,
    IPAddress,
    Location = strcat(City, ", ", CountryOrRegion),
    DetectionTimingType,
    Source
| extend
    RelationToAssignment = case(
        TimeGenerated < AlertTime and datetime_diff("hour", AlertTime, TimeGenerated) <= 24,
            "PRE-ASSIGNMENT - Risk before role was assigned",
        TimeGenerated >= AlertTime,
            "POST-ASSIGNMENT - Risk after role was assigned",
        "HISTORICAL - Risk event > 24h before assignment"
    );
// --- Sign-in anomalies for the target user ---
let SignInRisk = SigninLogs
| where TimeGenerated between (AlertTime - 7d .. AlertTime + 1d)
| where UserPrincipalName =~ TargetUPN
| where RiskLevelDuringSignIn in ("high", "medium") or ResultType != "0"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    AppDisplayName,
    RiskLevelDuringSignIn,
    ResultType,
    ResultDescription
| extend
    SignInAssessment = case(
        RiskLevelDuringSignIn == "high", "CRITICAL - High-risk sign-in detected",
        RiskLevelDuringSignIn == "medium", "HIGH - Medium-risk sign-in detected",
        ResultType == "50126", "INFO - Failed password attempt",
        ResultType == "53003", "INFO - Blocked by Conditional Access",
        "INFO - Non-zero result type"
    );
// --- Combine risk and sign-in data ---
RiskEvents
| extend DataSource = "RiskEvent"
| project TimeGenerated, UserPrincipalName, DataSource,
    RiskType = RiskEventType, RiskLevel, IPAddress, Location,
    Assessment = RelationToAssignment
| union (
    SignInRisk
    | extend DataSource = "SignInLog"
    | project TimeGenerated, UserPrincipalName, DataSource,
        RiskType = strcat("SignIn-", ResultType), RiskLevel = RiskLevelDuringSignIn,
        IPAddress, Location, Assessment = SignInAssessment
)
| sort by TimeGenerated asc
| extend
    OverallRiskVerdict = case(
        DataSource == "RiskEvent" and Assessment startswith "PRE-ASSIGNMENT" and RiskLevel in ("high", "medium"),
            "CRITICAL - User was at risk BEFORE receiving privileged role",
        DataSource == "RiskEvent" and RiskLevel == "high",
            "HIGH - User has high-risk detections",
        DataSource == "SignInLog" and RiskLevel == "high",
            "HIGH - User has high-risk sign-ins",
        "REVIEW - Investigate risk context"
    )
```

**Performance Notes:**
- 7-day lookback captures risk events that may have preceded the role assignment by days
- Combining `AADUserRiskEvents` and `SigninLogs` provides both ML-based and behavioral risk indicators
- `RiskState == "atRisk"` means the user has unresolved risk -- the account may currently be compromised

**Tuning Guidance:**
- If the target user had risk events BEFORE the role assignment, the role was likely assigned to a compromised account
- If the target user has risk events AFTER the assignment, the attacker is actively using the escalated privileges
- Cross-reference risk event IPs with the role assignment IP from Step 1
- If `RiskState` is "remediated" but the role is still assigned, check if the remediation was complete

**Expected findings:**
- Whether the role recipient shows signs of compromise before or after the assignment
- Risk event correlation with the role assignment timeline
- Whether the target user is a high-risk entity

**Next action:**
- If pre-assignment risk detected, the scenario is: compromised user → privilege escalation
- If post-assignment risk detected, the escalated account is being actively abused
- Proceed to Step 7 for org-wide privileged access sweep

---

### Step 7: Org-Wide Privileged Role Sweep

**Purpose:** Scan the entire organization for other anomalous privileged role assignments. The attacker may have assigned roles to multiple accounts, or there may be dormant unauthorized admin accounts from previous incidents. This step provides a complete picture of the organization's privileged access posture.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 7: Org-Wide Privileged Role Sweep
// Purpose: Find all recent privileged role assignments and flag anomalies
// Tables: AuditLogs
// Investigation Step: 7 - Org-Wide Privileged Role Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let SweepWindow = 30d;
let CriticalRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator",
    "Privileged Authentication Administrator", "Security Administrator",
    "Exchange Administrator", "SharePoint Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "User Administrator", "Authentication Administrator",
    "Intune Administrator", "Compliance Administrator",
    "Conditional Access Administrator", "Hybrid Identity Administrator"
]);
// --- All privileged role assignments in sweep window ---
AuditLogs
| where TimeGenerated between (AlertTime - SweepWindow .. AlertTime + 1d)
| where OperationName in (
    "Add member to role",
    "Add eligible member to role",
    "Add member to role in PIM requested (permanent)",
    "Add member to role in PIM completed (timebound)"
)
| extend
    AssigningUser = tostring(InitiatedBy.user.userPrincipalName),
    AssigningIP = tostring(InitiatedBy.user.ipAddress),
    AssigningApp = tostring(InitiatedBy.app.displayName),
    TargetUser = coalesce(
        tostring(TargetResources[0].userPrincipalName),
        tostring(TargetResources[0].displayName)
    ),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    NewValue = tostring(ModifiedProps.newValue)
| where PropertyName == "Role.DisplayName"
| where NewValue in (CriticalRoles)
| project
    TimeGenerated,
    OperationName,
    AssigningUser,
    AssigningIP,
    AssigningApp,
    TargetUser,
    RoleName = NewValue,
    AssignmentType = case(
        OperationName has "eligible", "ELIGIBLE",
        OperationName has "permanent" or OperationName == "Add member to role", "PERMANENT",
        "OTHER"
    )
| summarize
    AssignmentCount = count(),
    RolesReceived = make_set(RoleName, 10),
    AssignedBy = make_set(AssigningUser, 10),
    AssignmentIPs = make_set(AssigningIP, 10),
    FirstAssignment = min(TimeGenerated),
    LastAssignment = max(TimeGenerated),
    PermanentCount = countif(AssignmentType == "PERMANENT"),
    EligibleCount = countif(AssignmentType == "ELIGIBLE")
    by TargetUser
| extend
    RiskScore = case(
        PermanentCount > 0 and RolesReceived has "Global Administrator",
            "CRITICAL - Permanent Global Admin assignment",
        AssignmentCount > 3,
            "HIGH - Multiple role assignments to same user",
        PermanentCount > EligibleCount and PermanentCount > 0,
            "HIGH - More permanent than eligible (PIM bypass)",
        RolesReceived has "Privileged Role Administrator",
            "HIGH - Can assign roles to others (privilege spreading)",
        RolesReceived has_any ("Exchange Administrator", "Security Administrator"),
            "MEDIUM - Sensitive admin role assigned",
        "LOW - Standard privileged role assignment"
    )
| where RiskScore !startswith "LOW"
| sort by RiskScore asc, PermanentCount desc
```

**Performance Notes:**
- 30-day sweep provides comprehensive coverage of recent privilege changes
- `CriticalRoles` list covers the most dangerous built-in Entra ID roles
- `PermanentCount > EligibleCount` pattern indicates PIM may be systematically bypassed

**Tuning Guidance:**
- Focus on CRITICAL and HIGH findings first -- these represent the highest risk
- If multiple users received permanent Global Admin in the sweep window, this is a major red flag
- Cross-reference `AssignedBy` -- if the same compromised admin assigned roles to multiple users, all are suspect
- If `AssigningApp` shows programmatic assignment (Microsoft Graph, PowerShell), investigate the automation source

**Expected findings:**
- All users who received critical role assignments in the last 30 days
- Pattern of permanent vs. eligible assignments (PIM health)
- Whether multiple suspicious assignments share the same assigning user or IP

**Next action:**
- For each CRITICAL finding, verify with the Privileged Role Administrator team
- Remove any unverified permanent assignments immediately
- Review PIM configuration to ensure just-in-time access is enforced
- Conduct a full privileged access review across the organization

---

## 6. Containment Playbook

### Immediate Actions (First 15 Minutes)

| Priority | Action | Command/Location | Who |
|---|---|---|---|
| P0 | Remove the unauthorized role assignment | `Remove-MgDirectoryRoleMemberByRef` or Entra Portal > Roles > [Role] > Remove member | Privileged Role Admin |
| P0 | Revoke all sessions for escalated user | `Revoke-MgUserSignInSession -UserId [UPN]` | Security Admin |
| P0 | Block sign-in for escalated user | Entra Portal > Users > [User] > Block sign-in | User Admin |
| P0 | Revoke sessions for assigning user (if compromised) | `Revoke-MgUserSignInSession -UserId [ActorUPN]` | Security Admin |
| P0 | Reset passwords for both actor and target | Force password change at next sign-in | Helpdesk Admin |
| P1 | Remove any backdoor accounts created post-escalation | Delete accounts identified in Step 5 | User Admin |

### Secondary Actions (First 2 Hours)

| Priority | Action | Details |
|---|---|---|
| P1 | Restore modified CA policies | Revert to documented CA policy configuration |
| P1 | Re-enable Security Defaults if disabled | Entra Portal > Properties > Security Defaults |
| P1 | Remove unauthorized federation trusts | `Remove-MgDomainFederationConfiguration` |
| P1 | Remove unauthorized SP credentials | See RB-0010 containment |
| P2 | Audit all MFA methods for both users | See RB-0012 containment |
| P2 | Review all OAuth consents by escalated user | See RB-0011 containment |
| P2 | Revoke all app credentials created by escalated user | Remove client secrets/certificates |
| P3 | Enforce PIM for all critical roles | Convert permanent to eligible where possible |
| P3 | Enable PIM approval workflow for Global Admin | Require approval for GA activation |
| P3 | Review break-glass account procedures | Ensure emergency access follows documented process |

### Role Removal Commands

```powershell
# Connect with Privileged Role Administrator permissions
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# Get the role definition ID for Global Administrator
$RoleId = (Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'").Id

# Remove the user from the role
$UserId = "ESCALATED_USER_OBJECT_ID"
Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $RoleId -DirectoryObjectId $UserId

# Revoke all sessions
Revoke-MgUserSignInSession -UserId "escalated.user@contoso.com"

# Block sign-in
Update-MgUser -UserId "escalated.user@contoso.com" -AccountEnabled:$false

# Reset password with force change
$PasswordProfile = @{
    Password = [System.Web.Security.Membership]::GeneratePassword(24, 6)
    ForceChangePasswordNextSignIn = $true
}
Update-MgUser -UserId "escalated.user@contoso.com" -PasswordProfile $PasswordProfile
```

---

## 7. Evidence Collection Checklist

| Evidence | Source | Retention | Priority |
|---|---|---|---|
| Role assignment event (AuditLogs) | Microsoft Sentinel | Export query results | Critical |
| Actor sign-in logs around assignment | Microsoft Sentinel | Export query results | Critical |
| Post-escalation admin actions | Microsoft Sentinel | Export query results | Critical |
| PIM activation records | Entra Portal > PIM > Audit | Screenshot + export | Critical |
| Current privileged role inventory | Entra Portal > Roles | Full export | Critical |
| Target user risk events | Microsoft Sentinel | Export query results | High |
| Backdoor accounts created | User creation audit events | Export + screenshot | High |
| CA policy change history | AuditLogs CA events | Export query results | High |
| Federation configuration state | `Get-MgDomainFederationConfiguration` | JSON export | High |
| Break-glass account access logs | Sign-in logs for emergency accounts | Export query results | Medium |

---

## 8. Escalation Criteria

### Escalate to CISO / Incident Commander When:
- Global Administrator permanently assigned without authorization
- Federation settings modified (Golden SAML risk)
- Security Defaults disabled or CA policies deleted
- New admin accounts created as backdoors
- Multiple privileged role assignments across different users (campaign)
- Evidence of audit log tampering (diagnostic settings modified)

### Escalate to Legal/Privacy When:
- Escalated user accessed email, files, or other sensitive data using admin privileges
- Tenant-wide data exfiltration is suspected
- Regulatory notification requirements may apply

### Escalate to Microsoft When:
- Federation trust forged (Golden SAML attack confirmed)
- Tenant-wide compromise requiring Microsoft Incident Response team engagement
- Contact: Microsoft Security Response Center or [microsoft.com/msrc](https://microsoft.com/msrc)

---

## 9. False Positive Documentation

| Scenario | How to Verify | Action |
|---|---|---|
| Planned IT admin onboarding | Check HR system + change management ticket | Document approval, add to baseline |
| Break-glass account activation | Verify documented emergency procedure was followed | Review break-glass access logs |
| PIM eligible activation with approval | Check PIM approval workflow, verify approver | Document as approved activation |
| Azure AD Connect role assignment | Verify during hybrid identity deployment | Check deployment timeline |
| Temporary project role assignment | Verify IT ticket + manager approval + expiry date | Confirm timebound with auto-removal |

---

## 10. MITRE ATT&CK Mapping

| Technique | ID | Tactic | How Detected |
|---|---|---|---|
| Account Manipulation: Additional Cloud Roles | T1098.003 | Persistence, Privilege Escalation | Role assignment event in AuditLogs |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence, Defense Evasion | Compromised account used with elevated role |
| Account Manipulation | T1098 | Persistence | Directory role changes, PIM bypass |
| Permission Groups Discovery: Cloud Groups | T1069.003 | Discovery | Enumeration of admin roles post-escalation |
| Account Discovery: Cloud Account | T1087.004 | Discovery | User enumeration using admin privileges |

---

## 11. Query Summary

| # | Query | Table | Purpose |
|---|---|---|---|
| 1 | Role Assignment Event Analysis | AuditLogs | Identify role assignment events, roles, actors, type |
| 2 | Actor Attribution & Sign-In Context | SigninLogs | Analyze assigning user's session for compromise |
| 3 | PIM Activation Pattern Analysis | AuditLogs | Check PIM workflow compliance or bypass |
| 4 | Baseline Comparison | AuditLogs | Compare against org role assignment baseline |
| 5 | Post-Escalation Activity Audit | AuditLogs | Track high-impact admin actions after escalation |
| 6 | Target User Risk Assessment | AADUserRiskEvents + SigninLogs | Check if role recipient is compromised |
| 7 | Org-Wide Privileged Role Sweep | AuditLogs | Find all recent privileged role assignments |

---

## Appendix A: Datatable Tests

### Test 1: Role Assignment Detection

```kql
// ============================================================
// TEST 1: Role Assignment Detection
// Validates: Query 1 - Detect role assignments and classify severity
// Expected: backdoor.admin permanent GA = "CRITICAL"
//           ops.engineer eligible Security Reader = "MEDIUM"
//           intern removal = "INFO"
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Permanent Global Admin assignment (suspicious) ---
    datetime(2026-02-22T14:00:00Z), "Add member to role",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"userPrincipalName":"backdoor.admin@contoso.com","displayName":"Backdoor Admin",
            "modifiedProperties":[
                {"displayName":"Role.DisplayName","oldValue":"","newValue":"Global Administrator"}
            ]}]),
        "success",
    // --- Eligible Security Reader (legitimate) ---
    datetime(2026-02-22T10:00:00Z), "Add eligible member to role",
        dynamic({"user":{"userPrincipalName":"pra.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"userPrincipalName":"ops.engineer@contoso.com","displayName":"Ops Engineer",
            "modifiedProperties":[
                {"displayName":"Role.DisplayName","oldValue":"","newValue":"Security Reader"}
            ]}]),
        "success",
    // --- Role removal (potential track covering) ---
    datetime(2026-02-22T14:30:00Z), "Remove member from role",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"userPrincipalName":"intern.user@contoso.com","displayName":"Intern User",
            "modifiedProperties":[
                {"displayName":"Role.DisplayName","oldValue":"Helpdesk Administrator","newValue":""}
            ]}]),
        "success"
];
// --- Run detection query ---
TestAuditLogs
| extend
    AssigningUser = tostring(InitiatedBy.user.userPrincipalName),
    AssigningIP = tostring(InitiatedBy.user.ipAddress),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    RoleName = iff(PropertyName == "Role.DisplayName", NewValue, ""),
    AssignmentType = case(
        OperationName has "eligible", "ELIGIBLE (PIM just-in-time)",
        OperationName has "Remove", "REMOVAL",
        OperationName == "Add member to role", "PERMANENT (direct assignment)",
        "UNKNOWN"
    )
| where isnotempty(RoleName) or OperationName has "Remove"
| extend
    SeverityAssessment = case(
        RoleName == "Global Administrator" and AssignmentType has "PERMANENT",
            "CRITICAL - Permanent assignment to highest-privilege role",
        RoleName in ("Security Reader", "Global Reader"),
            "MEDIUM - Read-only privileged role",
        AssignmentType == "REMOVAL",
            "INFO - Role removal (check if covering tracks)",
        "REVIEW - Requires context"
    )
| project TimeGenerated, AssigningUser, TargetUser, RoleName, AssignmentType, SeverityAssessment, AssigningIP
// Expected: backdoor.admin GA permanent = "CRITICAL - Permanent assignment to highest-privilege role"
// Expected: ops.engineer Security Reader eligible = "MEDIUM - Read-only privileged role"
// Expected: intern.user removal = "INFO - Role removal (check if covering tracks)"
```

### Test 2: Post-Escalation Activity Detection

```kql
// ============================================================
// TEST 2: Post-Escalation Activity Detection
// Validates: Query 5 - Detect high-impact admin actions after role assignment
// Expected: "Delete conditional access policy" = "CRITICAL - Security controls disabled"
//           "Add user" = "HIGH - New user account created"
//           "Set federation settings" = "CRITICAL - Federation/domain changes"
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Attacker disables CA policy ---
    datetime(2026-02-22T14:10:00Z), "Delete conditional access policy",
        dynamic({"user":{"userPrincipalName":"backdoor.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"Require MFA for Admins","type":"Policy"}]),
        "success",
    // --- Attacker creates backdoor account ---
    datetime(2026-02-22T14:15:00Z), "Add user",
        dynamic({"user":{"userPrincipalName":"backdoor.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"svc-backup-agent","userPrincipalName":"svc-backup-agent@contoso.com",
            "modifiedProperties":[]}]),
        "success",
    // --- Attacker modifies federation (Golden SAML) ---
    datetime(2026-02-22T14:20:00Z), "Set federation settings on domain",
        dynamic({"user":{"userPrincipalName":"backdoor.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"contoso.com","type":"Domain",
            "modifiedProperties":[{"displayName":"FederationBrandName","oldValue":"","newValue":"attacker-idp"}]}]),
        "success",
    // --- Legitimate admin action (for comparison) ---
    datetime(2026-02-22T11:00:00Z), "Update conditional access policy",
        dynamic({"user":{"userPrincipalName":"security.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"displayName":"Block Legacy Auth","type":"Policy"}]),
        "success"
];
let TargetUPN = "backdoor.admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- Run post-escalation audit ---
TestAuditLogs
| where TimeGenerated >= AlertTime
| where InitiatedBy has TargetUPN
| project
    TimeGenerated,
    OperationName,
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    ImpactCategory = case(
        OperationName has "federation",
            "CRITICAL - Federation/domain changes (Golden SAML risk)",
        OperationName has "Delete conditional access",
            "CRITICAL - Security controls disabled",
        OperationName == "Add user",
            "HIGH - New user account created",
        OperationName has "Update conditional access",
            "MEDIUM - Security policy modification",
        "REVIEW - Admin action requires context"
    ),
    MinutesSinceEscalation = datetime_diff("minute", TimeGenerated, AlertTime)
| project TimeGenerated, OperationName, TargetResource, ImpactCategory, MinutesSinceEscalation
// Expected: "Delete conditional access policy" = "CRITICAL" at +10 min
// Expected: "Add user" = "HIGH" at +15 min (svc-backup-agent backdoor)
// Expected: "Set federation settings" = "CRITICAL" at +20 min (Golden SAML)
```

### Test 3: Baseline Comparison

```kql
// ============================================================
// TEST 3: Baseline Comparison
// Validates: Query 4 - Compare role assignment against org baseline
// Expected: compromised.admin NOT in KnownAssigners = "ANOMALOUS"
//           pra.admin in KnownAssigners = "WITHIN BASELINE"
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Known PRA admin making assignments (baseline) ---
    datetime(2026-01-15T10:00:00Z), "Add eligible member to role",
        dynamic({"user":{"userPrincipalName":"pra.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"userPrincipalName":"analyst.a@contoso.com","modifiedProperties":[
            {"displayName":"Role.DisplayName","newValue":"Security Reader"}
        ]}]),
        "success",
    datetime(2026-02-01T09:00:00Z), "Add eligible member to role",
        dynamic({"user":{"userPrincipalName":"pra.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"userPrincipalName":"analyst.b@contoso.com","modifiedProperties":[
            {"displayName":"Role.DisplayName","newValue":"Security Reader"}
        ]}]),
        "success",
    datetime(2026-02-10T11:00:00Z), "Add eligible member to role",
        dynamic({"user":{"userPrincipalName":"pra.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"userPrincipalName":"analyst.c@contoso.com","modifiedProperties":[
            {"displayName":"Role.DisplayName","newValue":"Global Reader"}
        ]}]),
        "success",
    // --- Suspicious assignment by non-baseline actor ---
    datetime(2026-02-22T14:00:00Z), "Add member to role",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"userPrincipalName":"backdoor.admin@contoso.com","modifiedProperties":[
            {"displayName":"Role.DisplayName","newValue":"Global Administrator"}
        ]}]),
        "success"
];
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 30d;
let ActorUPN = "compromised.admin@contoso.com";
// --- Org baseline ---
TestAuditLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
| where OperationName in ("Add member to role", "Add eligible member to role")
| summarize
    TotalAssignments = count(),
    UniqueAssigners = dcount(tostring(InitiatedBy.user.userPrincipalName)),
    KnownAssigners = make_set(tostring(InitiatedBy.user.userPrincipalName), 20),
    PermanentCount = countif(OperationName == "Add member to role"),
    EligibleCount = countif(OperationName has "eligible")
| extend
    Assessment = case(
        not(KnownAssigners has ActorUPN),
            "ANOMALOUS - Actor has never assigned roles in the baseline period",
        PermanentCount > EligibleCount * 2,
            "SUSPICIOUS - More permanent than eligible assignments",
        "WITHIN BASELINE - Role assignments follow normal patterns"
    )
| project TotalAssignments, UniqueAssigners, KnownAssigners, PermanentCount, EligibleCount, Assessment
// Expected: KnownAssigners = ["pra.admin@contoso.com"] (only legitimate admin)
// Expected: Assessment = "ANOMALOUS - Actor has never assigned roles in the baseline period"
//           (compromised.admin is not in the KnownAssigners list)
// Expected: PermanentCount=1, EligibleCount=3 (suspicious permanent assignment stands out)
```

### Test 4: Org-Wide Privileged Role Sweep

```kql
// ============================================================
// TEST 4: Org-Wide Privileged Role Sweep
// Validates: Query 7 - Find all suspicious privileged role assignments
// Expected: backdoor.admin = "CRITICAL" (permanent GA)
//           shadow.admin = "HIGH" (multiple roles)
//           ops.engineer = filtered out (Security Reader = LOW)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- backdoor.admin: Permanent Global Admin ---
    datetime(2026-02-22T14:00:00Z), "Add member to role",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"userPrincipalName":"backdoor.admin@contoso.com",
            "modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"","newValue":"Global Administrator"}]}]),
        "success",
    // --- shadow.admin: Multiple eligible roles ---
    datetime(2026-02-20T10:00:00Z), "Add eligible member to role",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"userPrincipalName":"shadow.admin@contoso.com",
            "modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"","newValue":"Exchange Administrator"}]}]),
        "success",
    datetime(2026-02-20T10:05:00Z), "Add eligible member to role",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"userPrincipalName":"shadow.admin@contoso.com",
            "modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"","newValue":"User Administrator"}]}]),
        "success",
    datetime(2026-02-20T10:10:00Z), "Add eligible member to role",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"userPrincipalName":"shadow.admin@contoso.com",
            "modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"","newValue":"Security Administrator"}]}]),
        "success",
    datetime(2026-02-20T10:15:00Z), "Add member to role",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"userPrincipalName":"shadow.admin@contoso.com",
            "modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"","newValue":"Privileged Role Administrator"}]}]),
        "success",
    // --- ops.engineer: Legitimate Security Reader (should be LOW, filtered out) ---
    datetime(2026-02-15T09:00:00Z), "Add eligible member to role",
        dynamic({"user":{"userPrincipalName":"pra.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"userPrincipalName":"ops.engineer@contoso.com",
            "modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"","newValue":"Security Reader"}]}]),
        "success"
];
let CriticalRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator",
    "Security Administrator", "Exchange Administrator",
    "User Administrator"
]);
// --- Run sweep ---
TestAuditLogs
| where OperationName in ("Add member to role", "Add eligible member to role")
| extend
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    NewValue = tostring(ModifiedProps.newValue)
| where PropertyName == "Role.DisplayName" and NewValue in (CriticalRoles)
| summarize
    AssignmentCount = count(),
    RolesReceived = make_set(NewValue, 10),
    PermanentCount = countif(OperationName == "Add member to role"),
    EligibleCount = countif(OperationName has "eligible")
    by TargetUser
| extend
    RiskScore = case(
        PermanentCount > 0 and RolesReceived has "Global Administrator",
            "CRITICAL - Permanent Global Admin assignment",
        AssignmentCount > 3,
            "HIGH - Multiple role assignments to same user",
        RolesReceived has "Privileged Role Administrator",
            "HIGH - Can assign roles to others",
        "MEDIUM - Sensitive admin role"
    )
| where RiskScore !startswith "LOW"
| project TargetUser, RolesReceived, AssignmentCount, PermanentCount, EligibleCount, RiskScore
| sort by RiskScore asc
// Expected: backdoor.admin = "CRITICAL - Permanent Global Admin assignment" (1 permanent GA)
// Expected: shadow.admin = "HIGH - Multiple role assignments" (4 roles including PRA)
// Expected: ops.engineer NOT IN RESULTS (Security Reader filtered by CriticalRoles)
```

---

## References

- [Microsoft: Entra ID built-in roles reference](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [Microsoft: Privileged Identity Management (PIM) for Entra ID roles](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- [Microsoft: Best practices for Entra ID roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices)
- [Microsoft: Secure access practices for administrators](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning)
- [Microsoft: Emergency access (break-glass) accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [Microsoft: AuditLogs schema reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- [MITRE ATT&CK T1098.003 - Account Manipulation: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)
- [MITRE ATT&CK T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [Midnight Blizzard privilege escalation in Microsoft breach (2024)](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [CISA: Mitigating cloud-based identity threats](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- [CrowdStrike: Golden SAML attack chain analysis](https://www.crowdstrike.com/blog/how-adversaries-target-federated-identity-in-cloud-environments/)
