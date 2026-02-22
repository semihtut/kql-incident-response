---
title: "Security Default Disablement"
id: RB-0022
severity: critical
status: reviewed
description: >
  Investigation runbook for detecting when tenant-wide Security Defaults are
  disabled in Microsoft Entra ID. Security Defaults enforce baseline protections
  for the entire tenant: MFA for all users, blocking legacy authentication,
  protecting privileged accounts, and requiring MFA for Azure management.
  Disabling Security Defaults removes ALL of these protections simultaneously,
  exposing every user in the organization to password-only authentication.
  This is a high-priority defense evasion tactic used by threat actors who have
  gained Global Administrator or Security Administrator access and need to
  weaken the tenant before executing their primary attack objective. Unlike
  Conditional Access policy manipulation (RB-0015) which targets individual
  policies, Security Default disablement is a single toggle that removes all
  baseline protections at once. This runbook covers the exact change detection,
  actor compromise assessment, pre-change attack chain analysis, historical
  configuration baseline, post-disablement impact assessment, concurrent
  defense evasion detection, organization-wide security posture sweep, and
  UEBA behavioral enrichment.
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
    - technique_id: T1562.007
      technique_name: "Impair Defenses: Disable or Modify Cloud Firewall"
      confidence: probable
    - technique_id: T1556
      technique_name: "Modify Authentication Process"
      confidence: probable
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Storm-0558"
  - "Scattered Spider (Octo Tempest)"
  - "LAPSUS$ (DEV-0537)"
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
  - table: "AADNonInteractiveUserSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
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
  - query: "AuditLogs | where OperationName has 'organization' or OperationName has 'company' | take 1"
    label: primary
    description: "Organization-level configuration change audit logs"
  - query: "SigninLogs | take 1"
    description: "Sign-in context for the actor who made the change"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "Non-interactive sign-ins for automation and legacy auth detection"
  - query: "BehaviorAnalytics | take 1"
    label: optional
    description: "UEBA behavioral context for the actor (requires Sentinel UEBA)"
---

# Security Default Disablement - Investigation Runbook

> **RB-0022** | Severity: Critical | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Audit Logs
> **Detection Logic:** `Update organization settings` / `Set company information` with SecurityDefaultsEnabled changing to `false`
> **Primary MITRE Technique:** T1562.001 - Impair Defenses: Disable or Modify Tools

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Security Default Change Detection](#step-1-security-default-change-detection)
   - [Step 2: Actor Analysis — Who Disabled Security Defaults](#step-2-actor-analysis--who-disabled-security-defaults)
   - [Step 3: Pre-Change Risk Assessment](#step-3-pre-change-risk-assessment)
   - [Step 4: Baseline Comparison — Security Configuration Change History](#step-4-baseline-comparison--security-configuration-change-history)
   - [Step 5: Post-Disablement Impact Assessment](#step-5-post-disablement-impact-assessment)
   - [Step 6: Concurrent Defense Evasion Detection](#step-6-concurrent-defense-evasion-detection)
   - [Step 7: Organization-Wide Security Posture Sweep](#step-7-organization-wide-security-posture-sweep)
   - [Step 8: UEBA Enrichment — Behavioral Context Analysis](#step-8-ueba-enrichment--behavioral-context-analysis)
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
Security Default disablement is detected through AuditLogs events that indicate the tenant-wide security baseline toggle has been turned off:

1. **`Update organization settings`** — The primary operation name when Security Defaults are toggled via the Entra ID portal. The `TargetResources.modifiedProperties` array contains `SecurityDefaultsEnabled` changing from `"true"` to `"false"`.
2. **`Set company information`** — An alternative operation name observed in some tenant configurations when organization-level settings are modified. The same `SecurityDefaultsEnabled` property change appears in the modified properties payload.
3. **Graph API / PowerShell changes** — Programmatic disablement via `PATCH /policies/identitySecurityDefaultsEnforcementPolicy` generates the same audit event but with `InitiatedBy.app` populated instead of `InitiatedBy.user`.

**What Security Defaults protect — and what is lost when disabled:**

| Protection | When Enabled | When Disabled |
|---|---|---|
| **MFA for all users** | Every user must register for and use MFA | Users can sign in with password only |
| **Block legacy authentication** | IMAP, SMTP, POP3, ActiveSync basic auth blocked | Legacy protocols accepted (no MFA possible) |
| **Protect privileged actions** | Extra MFA challenge for Azure management | Azure Portal, PowerShell access with password only |
| **MFA registration enforcement** | Users prompted to register MFA within 14 days | No MFA registration requirement |
| **Block risky sign-ins** | Sign-ins from anonymous/Tor IPs challenged | Anonymous sign-ins proceed without challenge |

**Why this is CRITICAL severity:**

- Security Default disablement is a **single toggle that removes ALL baseline protections** simultaneously for every user in the tenant
- Unlike Conditional Access policy changes ([RB-0015](conditional-access-manipulation.md)) that affect individual policies, this removes the entire security floor
- After disablement, every user can authenticate with just a password — the attacker no longer needs to bypass MFA
- Legacy authentication protocols become available, allowing credential stuffing attacks that cannot be challenged with MFA
- Privileged actions (Azure management, PowerShell) no longer require MFA — the attacker can freely manage cloud resources
- The change takes effect **immediately** — there is no grace period or rollback window
- Organizations that rely solely on Security Defaults (no Conditional Access policies) lose **100% of their authentication protections** in one click

**However:** This alert has a **low-moderate false positive rate** (~10-15%). Legitimate triggers include:

- IT team migrating from Security Defaults to Conditional Access policies (requires disabling defaults first)
- Troubleshooting a widespread authentication issue where MFA is suspected as the cause
- Development/test tenant where Security Defaults interfere with automation

**Worst case scenario if this is real:**
An attacker compromises a Global Administrator account through AiTM phishing ([RB-0014](aitm-phishing-detection.md)). They disable Security Defaults as their first post-compromise action. Within minutes, the attacker uses credentials from a password spray database to sign in to dozens of user accounts that were previously protected by mandatory MFA. They use IMAP to access executive mailboxes (legacy auth, no MFA), create inbox forwarding rules, and exfiltrate sensitive email data — all while legacy authentication was blocked just moments earlier. The attacker also disables audit log diagnostic settings ([RB-0015](conditional-access-manipulation.md) Step 6) and modifies Conditional Access named locations to ensure their infrastructure remains trusted. By the time the SOC notices the Security Default change, the attacker has compromised multiple accounts, exfiltrated data, and established persistence through OAuth app consent ([RB-0011](consent-grant-attack.md)).

**Key relationship to other runbooks:**

- **[RB-0015](conditional-access-manipulation.md) (CA Manipulation):** RB-0015 covers individual CA policy changes. Security Default disablement is the **nuclear option** — it removes the entire baseline. If CA policies exist, they remain active after Security Defaults are disabled. If no CA policies exist, the tenant has zero authentication protections.
- **[RB-0013](privileged-role-assignment.md) (Privileged Role Assignment):** Check if the actor recently gained Global Admin or Security Admin. Security Default changes require one of these roles.
- **[RB-0014](aitm-phishing-detection.md) (AiTM Phishing):** The most common attack chain: AiTM -> admin compromise -> disable Security Defaults -> mass account compromise.
- **[RB-0006](password-spray-detection.md) (Password Spray):** After Security Defaults are disabled, password spray attacks succeed without MFA challenge.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID Free + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID (AuditLogs, SigninLogs)
- **Permissions:** Security Reader (investigation), Global Administrator (containment — re-enabling Security Defaults)

### Recommended for Full Coverage
- **License:** Entra ID P1/P2 + Microsoft Sentinel
- **Additional:** Identity Protection enabled for actor risk assessment, AADNonInteractiveUserSignInLogs for legacy auth detection
- **UEBA:** Microsoft Sentinel UEBA for behavioral context

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | AuditLogs, SigninLogs | Steps 1, 2, 4, 5 (partial), 6, 7 |
| Above + Entra ID P1/P2 | Above + AADNonInteractiveUserSignInLogs | Steps 1-7 (full coverage) |
| Above + Sentinel UEBA | Above + BehaviorAnalytics | Steps 1-8 (complete) |

---

## 3. Input Parameters

Set these values before running the investigation queries:

```kql
// === INVESTIGATION PARAMETERS ===
let AlertTime = datetime(2026-02-22T14:00:00Z);     // Time Security Defaults were disabled
let ActorUPN = "admin@contoso.com";                  // Admin who disabled Security Defaults
let LookbackWindow = 48h;                            // Pre-change analysis window
let ForwardWindow = 24h;                             // Post-change exploitation window
let BaselineWindow = 30d;                            // Historical baseline period
// Known hosting/VPS ASNs (attacker infrastructure indicators)
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
```

---

## 4. Quick Triage Criteria

Use this decision matrix for initial severity assessment:

### Immediate Escalation (Skip to Containment)

- Security Defaults disabled with no corresponding change management ticket
- Actor account shows Identity Protection risk events in the past 48 hours
- Security Defaults disabled from a hosting/VPS IP or anonymous proxy
- Security Defaults disabled outside of business hours
- Security Defaults disabled AND no Conditional Access policies exist (tenant has ZERO protections)
- Legacy authentication sign-ins appearing within minutes of disablement
- Multiple security configuration changes in the same time window (defaults + CA + diagnostics)

### Standard Investigation

- Security Defaults disabled by a known IT admin during business hours
- Security Defaults disabled as part of a documented migration to Conditional Access
- Tenant already has comprehensive Conditional Access policies in place

### Likely Benign

- Documented Conditional Access migration plan with change ticket referencing Security Default disablement
- Development/test tenant where Security Defaults are periodically toggled for testing
- Security Defaults re-enabled within a short window (< 30 min) indicating troubleshooting

---

## 5. Investigation Steps

### Step 1: Security Default Change Detection

**Objective:** Find the exact moment Security Defaults were toggled off. Identify the operation, parse the raw property change from `"true"` to `"false"`, determine who performed the change and from what IP/tool, and establish the precise timeline anchor for all subsequent investigation steps.

```kql
// Step 1: Security Default Change Detection
// Table: AuditLogs | Detects SecurityDefaultsEnabled toggled to false
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 48h;
// --- Detect Security Default toggle events ---
AuditLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where OperationName in (
    "Update organization settings",
    "Set company information",
    "Disable Security Defaults",
    "Enable Security Defaults",
    "Update policy"
)
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    ActorApp = tostring(InitiatedBy.app.displayName),
    ActorServicePrincipal = tostring(InitiatedBy.app.servicePrincipalId),
    ModifiedProps = TargetResources[0].modifiedProperties,
    TargetName = tostring(TargetResources[0].displayName),
    TargetId = tostring(TargetResources[0].id)
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
// Filter for Security Default changes specifically
| where PropertyName has_any (
    "SecurityDefaultsEnabled",
    "securityDefaults",
    "IsSecurityDefaultsEnabled",
    "isEnabled"
)
    or OperationName in ("Disable Security Defaults", "Enable Security Defaults")
| extend
    ChangeDirection = case(
        NewValue has "false" or NewValue has "False" or OperationName == "Disable Security Defaults",
            "DISABLED - Security Defaults turned OFF",
        NewValue has "true" or NewValue has "True" or OperationName == "Enable Security Defaults",
            "ENABLED - Security Defaults turned ON",
        "UNKNOWN - Unable to parse change direction"
    ),
    ChangeMethod = case(
        isnotempty(ActorApp) and isempty(ActorUPN),
            strcat("API/Automation via ", ActorApp),
        isnotempty(ActorUPN) and ActorApp has_any ("Azure Portal", "Entra"),
            "Entra ID Portal (manual)",
        isnotempty(ActorUPN) and ActorApp has_any ("PowerShell", "Graph"),
            strcat("Programmatic via ", ActorApp),
        isnotempty(ActorUPN),
            strcat("Portal/App: ", coalesce(ActorApp, "Unknown")),
        "Unknown method"
    ),
    SeverityLevel = case(
        NewValue has "false" or OperationName == "Disable Security Defaults",
            "CRITICAL - Baseline protections removed for entire tenant",
        NewValue has "true" or OperationName == "Enable Security Defaults",
            "INFO - Security Defaults re-enabled",
        "MEDIUM - Security Default setting modified"
    )
| project
    TimeGenerated,
    OperationName,
    ChangeDirection,
    SeverityLevel,
    ActorUPN = coalesce(ActorUPN, "Service Principal"),
    ActorIP,
    ActorApp = coalesce(ActorApp, "N/A"),
    ActorServicePrincipal,
    ChangeMethod,
    PropertyName,
    OldValue = substring(OldValue, 0, 500),
    NewValue = substring(NewValue, 0, 500),
    TargetName,
    Result,
    CorrelationId
| sort by TimeGenerated asc
```

**What to look for:**

- **ChangeDirection = "DISABLED"** = Security Defaults turned off -- this is the primary finding. Note the exact timestamp as the anchor for all subsequent queries.
- **ChangeMethod = "API/Automation"** = Change made via Graph API or service principal without human interaction -- potential automated attack or compromised automation account.
- **ChangeMethod = "Programmatic via Microsoft Graph PowerShell"** = Admin used PowerShell -- higher risk than portal changes as it may indicate scripted attack.
- **ActorIP from a hosting/VPS provider** = Change originated from attacker infrastructure -- cross-reference with `HostingASNs`.
- **Multiple changes in sequence** = DISABLED followed by ENABLED (or vice versa) may indicate testing, troubleshooting, or attacker toggling to avoid detection.
- **ActorUPN = "Service Principal"** = No human user associated -- check `ActorServicePrincipal` to identify the app registration. A compromised service principal with Directory.ReadWrite.All can disable Security Defaults programmatically.

---

### Step 2: Actor Analysis — Who Disabled Security Defaults

**Objective:** Deep analysis of the account that performed the change. Correlate the actor's sign-in context (IP, device, location, risk level) with the audit event. Determine if the actor's account was recently compromised through a recent password reset, MFA method change, anomalous sign-in, or risk event.

```kql
// Step 2: Actor Analysis — Who Disabled Security Defaults
// Table: SigninLogs + AuditLogs | Actor sign-in context and compromise indicators
let ActorUPN = "admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 48h;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// --- Actor sign-in context around the change ---
let ActorSignIns = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ ActorUPN
    | extend
        ParsedLocation = parse_json(LocationDetails),
        ParsedDevice = parse_json(DeviceDetail)
    | project
        TimeGenerated,
        IPAddress,
        AutonomousSystemNumber,
        Country = tostring(ParsedLocation.countryOrRegion),
        City = tostring(ParsedLocation.city),
        DeviceOS = tostring(ParsedDevice.operatingSystem),
        Browser = tostring(ParsedDevice.browser),
        IsManaged = tostring(ParsedDevice.isManaged),
        IsCompliant = tostring(ParsedDevice.isCompliant),
        DeviceTrust = tostring(ParsedDevice.trustType),
        AppDisplayName,
        ResourceDisplayName,
        ResultType,
        RiskLevelDuringSignIn,
        RiskLevelAggregated,
        ConditionalAccessStatus,
        AuthenticationRequirement,
        MFADetail = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod),
        UserAgent;
// --- Actor compromise indicators (account changes) ---
let ActorCompromiseSignals = AuditLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where TargetResources[0].userPrincipalName =~ ActorUPN
        or InitiatedBy has ActorUPN
    | where OperationName in (
        "Reset password", "Change user password", "Reset password (by admin)",
        "User registered security info", "User deleted security info",
        "User changed default security info",
        "Add member to role", "Add eligible member to role",
        "Update user", "Consent to application"
    )
    | project
        TimeGenerated,
        OperationName,
        InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
        InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
        TargetUser = tostring(TargetResources[0].userPrincipalName),
        Result;
// --- Sign-in risk assessment ---
ActorSignIns
| extend
    IsHostingIP = AutonomousSystemNumber in (HostingASNs),
    SignInOutcome = iff(ResultType == "0", "SUCCESS", strcat("FAILURE-", ResultType)),
    IsAdminTool = AppDisplayName in (
        "Azure Portal", "Microsoft Entra admin center",
        "Microsoft Graph PowerShell", "Azure Active Directory PowerShell",
        "Microsoft Graph", "Graph Explorer", "Azure CLI"
    ),
    RiskAssessment = case(
        RiskLevelDuringSignIn in ("high") and AutonomousSystemNumber in (HostingASNs),
            "CRITICAL - High-risk sign-in from hosting infrastructure",
        RiskLevelDuringSignIn in ("high"),
            "CRITICAL - High-risk sign-in detected",
        RiskLevelDuringSignIn in ("medium") and IsManaged != "true",
            "HIGH - Medium-risk from unmanaged device",
        RiskLevelDuringSignIn in ("medium"),
            "HIGH - Medium-risk sign-in detected",
        AutonomousSystemNumber in (HostingASNs),
            "HIGH - Sign-in from hosting/VPS provider",
        IsManaged != "true" and IsCompliant != "true",
            "MEDIUM - Unmanaged, non-compliant device",
        "LOW - Standard sign-in context"
    )
| project
    TimeGenerated,
    SignInOutcome,
    RiskAssessment,
    IPAddress,
    Country,
    City,
    DeviceOS,
    Browser,
    IsManaged,
    IsCompliant,
    IsHostingIP,
    AppDisplayName,
    IsAdminTool,
    RiskLevelDuringSignIn,
    AuthenticationRequirement,
    MFADetail
| union (
    ActorCompromiseSignals
    | extend
        SignInOutcome = "AUDIT_EVENT",
        RiskAssessment = case(
            OperationName has_any ("Reset password", "password"),
                "HIGH - Password change on actor account",
            OperationName has_any ("security info", "registered"),
                "HIGH - MFA method change on actor account",
            OperationName has_any ("role", "Role"),
                "HIGH - Role assignment to/by actor account",
            "MEDIUM - Account modification"
        ),
        IPAddress = InitiatedByIP,
        Country = "", City = "", DeviceOS = "", Browser = "",
        IsManaged = "", IsCompliant = "", IsHostingIP = false,
        AppDisplayName = OperationName, IsAdminTool = false,
        RiskLevelDuringSignIn = "", AuthenticationRequirement = "",
        MFADetail = ""
)
| sort by case(
    RiskAssessment has "CRITICAL", 1,
    RiskAssessment has "HIGH", 2,
    RiskAssessment has "MEDIUM", 3,
    4
) asc, TimeGenerated asc
```

**What to look for:**

- **RiskAssessment = "CRITICAL"** = The admin account that disabled Security Defaults was itself accessed from a high-risk or hosting IP -- strong indicator the admin account is compromised.
- **Password reset or MFA change BEFORE the Security Default change** = Attack chain: compromise admin -> reset password -> register attacker MFA -> disable Security Defaults. Cross-reference with [RB-0012](suspicious-mfa-registration.md).
- **Role assignment shortly before the change** = Account was recently elevated to Global Admin or Security Admin -- check [RB-0013](privileged-role-assignment.md) for unauthorized role escalation.
- **IsAdminTool = true from hosting IP** = Admin portal or PowerShell accessed from VPS infrastructure -- the admin session is almost certainly compromised.
- **AuthenticationRequirement = "singleFactorAuthentication"** = Admin signed in without MFA -- if Security Defaults were still active at that point, this is anomalous (Security Defaults require MFA for admin roles).
- **Multiple countries in actor sign-ins** = Admin account accessed from different countries in a short window -- potential token theft. See [RB-0021](session-token-theft.md).

---

### Step 3: Pre-Change Risk Assessment

**Objective:** Analyze what happened BEFORE Security Defaults were disabled. Was the actor account recently compromised? Were there AiTM attacks, password sprays, or other identity attacks in the 48 hours before the change? This step identifies the attack chain that led to the Security Default change.

```kql
// Step 3: Pre-Change Risk Assessment
// Table: SigninLogs + AuditLogs | Attack chain leading to Security Default disablement
let ActorUPN = "admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let PreChangeWindow = 48h;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// --- Failed sign-in attempts on actor account (brute force / spray) ---
let FailedSignIns = SigninLogs
    | where TimeGenerated between ((AlertTime - PreChangeWindow) .. AlertTime)
    | where UserPrincipalName =~ ActorUPN
    | where ResultType != "0"
    | summarize
        FailedAttempts = count(),
        FailedIPs = make_set(IPAddress, 20),
        FailedCountries = make_set(tostring(parse_json(LocationDetails).countryOrRegion), 10),
        ErrorCodes = make_set(ResultType, 10),
        FirstFailed = min(TimeGenerated),
        LastFailed = max(TimeGenerated)
    | extend FailedContext = "PRE_CHANGE_FAILED_SIGNINS";
// --- Successful sign-in from risky context BEFORE the change ---
let RiskySuccessfulSignIns = SigninLogs
    | where TimeGenerated between ((AlertTime - PreChangeWindow) .. AlertTime)
    | where UserPrincipalName =~ ActorUPN
    | where ResultType == "0"
    | where RiskLevelDuringSignIn in ("high", "medium")
        or AutonomousSystemNumber in (HostingASNs)
    | extend
        ParsedLocation = parse_json(LocationDetails),
        ParsedDevice = parse_json(DeviceDetail)
    | project
        TimeGenerated,
        IPAddress,
        Country = tostring(ParsedLocation.countryOrRegion),
        City = tostring(ParsedLocation.city),
        DeviceOS = tostring(ParsedDevice.operatingSystem),
        AppDisplayName,
        RiskLevelDuringSignIn,
        IsHostingIP = AutonomousSystemNumber in (HostingASNs),
        MFAResult = tostring(parse_json(AuthenticationDetails)[0].succeeded),
        UserAgent;
// --- Privileged actions by the actor before the change ---
let PreChangePrivilegedActions = AuditLogs
    | where TimeGenerated between ((AlertTime - PreChangeWindow) .. AlertTime)
    | where InitiatedBy has ActorUPN
    | where OperationName in (
        "Add member to role", "Add eligible member to role",
        "Update conditional access policy", "Delete conditional access policy",
        "Consent to application", "Add OAuth2PermissionGrant",
        "Update authorization policy", "Update policy",
        "Set company information", "Update organization settings",
        "Add named location", "Update named location", "Delete named location",
        "Update application", "Add service principal credentials",
        "Disable Security Defaults"
    )
    | project
        TimeGenerated,
        OperationName,
        TargetResource = tostring(TargetResources[0].displayName),
        InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
        Result;
// --- Combine into attack chain timeline ---
RiskySuccessfulSignIns
| extend
    EventType = "RISKY_SIGNIN",
    Detail = strcat("Risk:", RiskLevelDuringSignIn, " App:", AppDisplayName,
        " HostingIP:", IsHostingIP),
    ThreatLevel = case(
        RiskLevelDuringSignIn == "high" and IsHostingIP,
            "CRITICAL - High-risk sign-in from hosting IP before SD change",
        RiskLevelDuringSignIn == "high",
            "CRITICAL - High-risk sign-in before SD change",
        IsHostingIP,
            "HIGH - Hosting IP sign-in before SD change",
        RiskLevelDuringSignIn == "medium",
            "HIGH - Medium-risk sign-in before SD change",
        "MEDIUM"
    )
| project TimeGenerated, EventType, Detail, ThreatLevel, IPAddress, Country
| union (
    PreChangePrivilegedActions
    | extend
        EventType = "PRIVILEGED_ACTION",
        Detail = strcat(OperationName, " -> ", TargetResource),
        ThreatLevel = case(
            OperationName has_any ("role", "Role"),
                "HIGH - Role change before SD disablement",
            OperationName has_any ("conditional access", "named location"),
                "HIGH - CA/location change before SD disablement",
            OperationName has_any ("credentials", "application"),
                "HIGH - App credential change before SD disablement",
            "MEDIUM - Administrative action"
        ),
        Country = ""
    | project TimeGenerated, EventType, Detail, ThreatLevel,
        IPAddress = InitiatedByIP, Country
)
| union (
    FailedSignIns
    | extend
        EventType = "FAILED_SIGNINS_SUMMARY",
        TimeGenerated = FirstFailed,
        Detail = strcat(FailedAttempts, " failures from ", array_length(FailedIPs),
            " IPs in ", array_length(FailedCountries), " countries. Errors: ",
            tostring(ErrorCodes)),
        ThreatLevel = case(
            FailedAttempts > 20, "HIGH - Significant brute force before SD change",
            FailedAttempts > 5, "MEDIUM - Multiple failed attempts",
            "LOW - Minor failed attempts"
        ),
        IPAddress = tostring(FailedIPs[0]),
        Country = tostring(FailedCountries[0])
)
| sort by TimeGenerated asc
```

**What to look for:**

- **RISKY_SIGNIN with ThreatLevel = "CRITICAL" before the SecurityDefaults change** = The admin account was accessed from a high-risk session before disabling Security Defaults. This is the classic AiTM -> admin compromise -> disable protections attack chain. Cross-reference with [RB-0014](aitm-phishing-detection.md).
- **PRIVILEGED_ACTION events clustering before the change** = Multiple administrative actions (role assignment, CA modification, app consent) in the hours before Security Default disablement indicate systematic security control sabotage.
- **FAILED_SIGNINS_SUMMARY with > 20 failures** = Password spray or brute force targeting the admin account before a successful sign-in and Security Default change. Cross-reference with [RB-0006](password-spray-detection.md).
- **Role assignment ("Add member to role") shortly before** = The attacker escalated to Global Admin and then immediately disabled Security Defaults. See [RB-0013](privileged-role-assignment.md).
- **CA policy changes AND Security Default disablement** = Dual defense evasion -- the attacker is dismantling both CA policies and Security Defaults. Proceed immediately to Step 6.
- **Empty results (no pre-change risk signals)** = The admin account may have been compromised days earlier, with the attacker waiting before executing the Security Default change. Extend `PreChangeWindow` to 7d.

---

### Step 4: Baseline Comparison — Security Configuration Change History

**Objective:** Establish the historical baseline of all security-related configuration changes in the tenant over 30 days. Determine how frequently Security Defaults are toggled, who normally changes tenant settings, and compare the current change against this baseline. This is the mandatory baseline comparison step.

```kql
// Step 4: Baseline Comparison — Security Configuration Change History
// Table: AuditLogs | Historical configuration change baseline (30 days)
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineWindow = 30d;
let ActorUPN = "admin@contoso.com";
// --- All security configuration changes in baseline period ---
let SecurityConfigChanges = AuditLogs
    | where TimeGenerated between ((AlertTime - BaselineWindow) .. AlertTime)
    | where OperationName in (
        "Update organization settings",
        "Set company information",
        "Disable Security Defaults",
        "Enable Security Defaults",
        "Update conditional access policy",
        "Delete conditional access policy",
        "Add conditional access policy",
        "Update named location",
        "Delete named location",
        "Add named location",
        "Update authorization policy",
        "Update policy"
    )
    | extend
        ModifyingUser = coalesce(
            tostring(InitiatedBy.user.userPrincipalName),
            tostring(InitiatedBy.app.displayName),
            "Unknown"
        ),
        ModifyingIP = tostring(InitiatedBy.user.ipAddress),
        ChangeType = case(
            OperationName has_any ("Security Defaults", "organization settings", "company information"),
                "SECURITY_DEFAULTS",
            OperationName has "conditional access",
                "CONDITIONAL_ACCESS",
            OperationName has "named location",
                "NAMED_LOCATION",
            OperationName has "authorization",
                "AUTHORIZATION_POLICY",
            "OTHER_SECURITY_CONFIG"
        );
// --- Baseline summary ---
SecurityConfigChanges
| summarize
    TotalConfigChanges = count(),
    SecurityDefaultChanges = countif(ChangeType == "SECURITY_DEFAULTS"),
    CAChanges = countif(ChangeType == "CONDITIONAL_ACCESS"),
    LocationChanges = countif(ChangeType == "NAMED_LOCATION"),
    UniqueModifiers = dcount(ModifyingUser),
    KnownModifiers = make_set(ModifyingUser, 20),
    ModifierIPs = make_set(ModifyingIP, 30),
    ChangeHours = make_list(hourofday(TimeGenerated), 200),
    WeekdayChanges = countif(dayofweek(TimeGenerated) between (1d .. 5d)),
    WeekendChanges = countif(dayofweek(TimeGenerated) !between (1d .. 5d))
| extend
    AvgChangesPerWeek = round(toreal(TotalConfigChanges) / 4.0, 1),
    ActorInBaseline = KnownModifiers has ActorUPN,
    SecurityDefaultToggleFrequency = case(
        SecurityDefaultChanges == 0,
            "NEVER - Security Defaults have never been modified in 30 days",
        SecurityDefaultChanges == 1,
            "RARE - Only 1 Security Default change in 30 days",
        SecurityDefaultChanges <= 3,
            "OCCASIONAL - A few Security Default changes in 30 days",
        "FREQUENT - Multiple Security Default changes (unusual)"
    ),
    BaselineAssessment = case(
        not(KnownModifiers has ActorUPN) and SecurityDefaultChanges == 0,
            "HIGHLY ANOMALOUS - First-ever SD change by a never-seen modifier",
        not(KnownModifiers has ActorUPN),
            "ANOMALOUS - New modifier not in 30-day configuration change history",
        SecurityDefaultChanges == 0,
            "ANOMALOUS - Known admin but Security Defaults never previously modified",
        "WITHIN BASELINE - Modifier and change type seen in historical patterns"
    ),
    OffHoursIndicator = iff(
        WeekendChanges > 0 or array_length(
            set_intersect(
                dynamic([0, 1, 2, 3, 4, 5, 22, 23]),
                make_set(ChangeHours)
            )) > 0,
        "WARNING - Some baseline changes occurred off-hours",
        "NORMAL - All baseline changes during business hours"
    )
| project
    BaselineAssessment,
    SecurityDefaultToggleFrequency,
    TotalConfigChanges,
    SecurityDefaultChanges,
    CAChanges,
    LocationChanges,
    AvgChangesPerWeek,
    UniqueModifiers,
    KnownModifiers,
    ActorInBaseline,
    WeekdayChanges,
    WeekendChanges,
    OffHoursIndicator
```

**What to look for:**

- **BaselineAssessment = "HIGHLY ANOMALOUS"** = This is the first-ever Security Default modification AND the person who did it has never modified any security configuration before. Very strong indicator of compromised admin account.
- **SecurityDefaultToggleFrequency = "NEVER"** = Security Defaults have not been changed in 30 days. A sudden change is unusual and warrants investigation.
- **ActorInBaseline = false** = The admin who made this change has never modified security settings before. Their account may have been recently compromised. Cross-reference with Step 2.
- **SecurityDefaultChanges > 3 in 30 days** = Unusual toggling -- may indicate troubleshooting, or an attacker testing the change before committing.
- **AvgChangesPerWeek > 10** = High security configuration churn -- the environment may be less stable, making anomaly detection harder.
- **WeekendChanges > 0** = Security changes on weekends are less common and may indicate after-hours attacker activity.

---

### Step 5: Post-Disablement Impact Assessment

**Objective:** After Security Defaults are off, check for the three critical impacts: (a) legacy authentication attempts that are now succeeding, (b) users signing in without MFA who previously required it, (c) new sign-ins from risky locations that were previously blocked. This quantifies the immediate blast radius of the disablement.

```kql
// Step 5: Post-Disablement Impact Assessment
// Table: SigninLogs + AADNonInteractiveUserSignInLogs | Impact after SD disabled
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 24h;
let PreChangeWindow = 24h;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// --- Legacy authentication protocols appearing post-change ---
let LegacyProtocols = dynamic([
    "IMAP4", "POP3", "SMTP", "MAPI", "Authenticated SMTP",
    "Exchange ActiveSync", "Exchange Online PowerShell",
    "Exchange Web Services", "IMAP", "POP",
    "Other clients", "Older Office clients"
]);
// --- Post-disablement: legacy auth successes ---
let PostLegacyAuth = union
    (SigninLogs
    | where TimeGenerated between (AlertTime .. (AlertTime + ForwardWindow))
    | where ResultType == "0"
    | where ClientAppUsed in (LegacyProtocols) or IsLegacyAuth == true),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (AlertTime .. (AlertTime + ForwardWindow))
    | where ResultType == "0"
    | where ClientAppUsed in (LegacyProtocols))
| extend
    Country = tostring(parse_json(LocationDetails).countryOrRegion),
    City = tostring(parse_json(LocationDetails).city)
| summarize
    LegacySignIns = count(),
    LegacyUsers = dcount(UserPrincipalName),
    LegacyProtocolsUsed = make_set(ClientAppUsed, 10),
    LegacyIPs = make_set(IPAddress, 20),
    LegacyCountries = make_set(Country, 10),
    LegacyApps = make_set(AppDisplayName, 10),
    AffectedUsers = make_set(UserPrincipalName, 50),
    HasHostingIP = countif(AutonomousSystemNumber in (HostingASNs))
| extend ImpactType = "LEGACY_AUTH_POST_CHANGE";
// --- Post-disablement: sign-ins without MFA ---
let PostNoMFA = SigninLogs
    | where TimeGenerated between (AlertTime .. (AlertTime + ForwardWindow))
    | where ResultType == "0"
    | where AuthenticationRequirement == "singleFactorAuthentication"
    | extend
        Country = tostring(parse_json(LocationDetails).countryOrRegion),
        IsHostingIP = AutonomousSystemNumber in (HostingASNs)
    | summarize
        NoMFASignIns = count(),
        NoMFAUsers = dcount(UserPrincipalName),
        NoMFACountries = make_set(Country, 10),
        NoMFAHostingIPs = countif(IsHostingIP),
        NoMFARiskySignIns = countif(RiskLevelDuringSignIn in ("high", "medium")),
        TopNoMFAUsers = make_set(UserPrincipalName, 20)
    | extend ImpactType = "NO_MFA_POST_CHANGE";
// --- Pre-change comparison: how many legacy auth were BLOCKED ---
let PreLegacyBlocked = union
    (SigninLogs
    | where TimeGenerated between ((AlertTime - PreChangeWindow) .. AlertTime)
    | where ClientAppUsed in (LegacyProtocols) or IsLegacyAuth == true
    | where ResultType != "0"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between ((AlertTime - PreChangeWindow) .. AlertTime)
    | where ClientAppUsed in (LegacyProtocols)
    | where ResultType != "0")
| summarize
    BlockedLegacyAttempts = count(),
    BlockedLegacyUsers = dcount(UserPrincipalName),
    BlockedProtocols = make_set(ClientAppUsed, 10),
    BlockedIPs = make_set(IPAddress, 20)
| extend ImpactType = "LEGACY_AUTH_PREVIOUSLY_BLOCKED";
// --- Combine impact assessment ---
PostLegacyAuth
| project
    ImpactType,
    Metric1 = strcat("Legacy sign-ins: ", LegacySignIns),
    Metric2 = strcat("Affected users: ", LegacyUsers),
    Metric3 = strcat("Protocols: ", tostring(LegacyProtocolsUsed)),
    Metric4 = strcat("From hosting IPs: ", HasHostingIP),
    RiskLevel = case(
        HasHostingIP > 0, "CRITICAL - Legacy auth from hosting infrastructure",
        LegacySignIns > 10, "HIGH - Significant legacy auth activity",
        LegacySignIns > 0, "MEDIUM - Legacy auth detected",
        "LOW - No legacy auth yet"
    ),
    AffectedEntities = tostring(AffectedUsers)
| union (
    PostNoMFA
    | project
        ImpactType,
        Metric1 = strcat("No-MFA sign-ins: ", NoMFASignIns),
        Metric2 = strcat("Affected users: ", NoMFAUsers),
        Metric3 = strcat("Risky sign-ins without MFA: ", NoMFARiskySignIns),
        Metric4 = strcat("From hosting IPs: ", NoMFAHostingIPs),
        RiskLevel = case(
            NoMFARiskySignIns > 0, "CRITICAL - Risky sign-ins without MFA",
            NoMFAHostingIPs > 0, "HIGH - Hosting IP sign-ins without MFA",
            NoMFASignIns > 50, "HIGH - Many sign-ins without MFA",
            NoMFASignIns > 0, "MEDIUM - Some sign-ins without MFA",
            "LOW - No immediate impact detected"
        ),
        AffectedEntities = tostring(TopNoMFAUsers)
)
| union (
    PreLegacyBlocked
    | project
        ImpactType,
        Metric1 = strcat("Previously blocked legacy attempts: ", BlockedLegacyAttempts),
        Metric2 = strcat("Blocked users: ", BlockedLegacyUsers),
        Metric3 = strcat("Blocked protocols: ", tostring(BlockedProtocols)),
        Metric4 = strcat("Blocked IPs: ", tostring(array_length(BlockedIPs))),
        RiskLevel = iff(BlockedLegacyAttempts > 0,
            "WARNING - These attempts will NOW succeed",
            "INFO - No prior legacy auth attempts"),
        AffectedEntities = tostring(BlockedIPs)
)
| sort by case(
    RiskLevel has "CRITICAL", 1,
    RiskLevel has "HIGH", 2,
    RiskLevel has "WARNING", 3,
    RiskLevel has "MEDIUM", 4,
    5
) asc
```

**What to look for:**

- **LEGACY_AUTH_POST_CHANGE with hosting IPs** = Legacy authentication (IMAP, POP3, SMTP) succeeding from hosting/VPS infrastructure immediately after Security Defaults were disabled. This is the #1 exploitation pattern -- attackers use IMAP to read email without MFA.
- **LEGACY_AUTH_PREVIOUSLY_BLOCKED > 0** = There were legacy auth attempts being blocked by Security Defaults BEFORE the change. These same IPs/users will now succeed. Immediate containment required.
- **NO_MFA_POST_CHANGE with risky sign-ins** = Users signing in without MFA from risky sessions -- these would have been challenged by Security Defaults.
- **NoMFAHostingIPs > 0** = Sign-ins from hosting infrastructure without MFA challenge -- potential credential stuffing using compromised passwords.
- **LegacySignIns > 0 within minutes of disablement** = Automated exploitation -- the attacker pre-staged legacy auth attempts and executed immediately after disabling Security Defaults.
- **Empty post-change results** = No immediate exploitation yet, but the window is open. Re-run this query every 4 hours until Security Defaults are re-enabled.

---

### Step 6: Concurrent Defense Evasion Detection

**Objective:** Check if other defensive mechanisms were also modified around the same time. Attackers who disable Security Defaults often disable multiple defenses in sequence: Conditional Access policies, diagnostic settings, audit log configuration, MFA settings. This step detects systematic defense dismantlement.

```kql
// Step 6: Concurrent Defense Evasion Detection
// Table: AuditLogs | Detects multiple security configurations changed together
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ConcurrentWindow = 4h;
// --- All security-sensitive configuration changes in the window ---
AuditLogs
| where TimeGenerated between ((AlertTime - ConcurrentWindow) .. (AlertTime + ConcurrentWindow))
| where OperationName in (
    // Security Defaults
    "Update organization settings", "Set company information",
    "Disable Security Defaults", "Enable Security Defaults",
    // Conditional Access
    "Update conditional access policy", "Delete conditional access policy",
    "Add conditional access policy",
    // Named Locations
    "Update named location", "Delete named location", "Add named location",
    // Diagnostic settings (audit log tampering)
    "Update diagnostic setting", "Delete diagnostic setting",
    "Set diagnostic setting",
    // MFA settings
    "Update StrongAuthenticationPolicy", "Set MFA auth method",
    "Admin updated security info", "Delete StrongAuthenticationPolicy",
    // Authorization policy
    "Update authorization policy",
    // Password policy
    "Set password policy", "Update password policy",
    // Authentication methods
    "Update authentication methods policy",
    "Update authentication requirement",
    // Consent settings
    "Update consent settings", "Set consent settings"
)
| extend
    ActorUPN = coalesce(
        tostring(InitiatedBy.user.userPrincipalName),
        tostring(InitiatedBy.app.displayName),
        "Unknown"
    ),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    DefenseCategory = case(
        OperationName has_any ("Security Defaults", "organization settings", "company information"),
            "SECURITY_DEFAULTS",
        OperationName has_any ("conditional access"),
            "CONDITIONAL_ACCESS",
        OperationName has_any ("named location"),
            "NAMED_LOCATIONS",
        OperationName has_any ("diagnostic"),
            "DIAGNOSTIC_SETTINGS",
        OperationName has_any ("StrongAuthentication", "MFA", "authentication methods",
            "authentication requirement"),
            "MFA_CONFIGURATION",
        OperationName has_any ("authorization"),
            "AUTHORIZATION_POLICY",
        OperationName has_any ("password policy"),
            "PASSWORD_POLICY",
        OperationName has_any ("consent"),
            "CONSENT_SETTINGS",
        "OTHER"
    ),
    ChangeSeverity = case(
        OperationName has "Delete", "CRITICAL",
        OperationName has "Disable", "CRITICAL",
        OperationName has_any ("diagnostic") and OperationName has_any ("Delete", "Update"),
            "CRITICAL",
        "HIGH"
    )
| project
    TimeGenerated,
    OperationName,
    DefenseCategory,
    ChangeSeverity,
    ActorUPN,
    ActorIP,
    TargetResource,
    Result,
    MinutesFromAlert = round(datetime_diff('minute', TimeGenerated, AlertTime), 0)
| extend
    ConcurrencyAssessment = case(
        DefenseCategory == "DIAGNOSTIC_SETTINGS",
            "CRITICAL - Audit log tampering detected alongside SD change",
        DefenseCategory == "CONDITIONAL_ACCESS" and ChangeSeverity == "CRITICAL",
            "CRITICAL - CA policy deleted/disabled alongside SD change",
        DefenseCategory == "MFA_CONFIGURATION",
            "HIGH - MFA settings modified alongside SD change",
        DefenseCategory == "AUTHORIZATION_POLICY",
            "HIGH - Authorization policy changed alongside SD change",
        DefenseCategory == "CONSENT_SETTINGS",
            "HIGH - Consent settings changed alongside SD change",
        DefenseCategory == "NAMED_LOCATIONS",
            "MEDIUM - Named location changes alongside SD change",
        "MEDIUM - Concurrent security configuration change"
    )
| sort by TimeGenerated asc
```

**What to look for:**

- **DIAGNOSTIC_SETTINGS changes** = Attacker disabling audit logging alongside Security Defaults. This is evidence destruction -- the attacker is covering their tracks. Cross-reference with [RB-0015](conditional-access-manipulation.md) Step 6.
- **Multiple DefenseCategories in the same window** = Three or more different defense categories modified within 4 hours is systematic security control sabotage. This is almost certainly a compromised admin executing an attack playbook.
- **Same ActorUPN across all changes** = One admin account disabling everything -- either the admin is compromised or they are performing unauthorized maintenance.
- **Different ActorUPN values** = Multiple compromised admin accounts coordinating defense evasion -- indicates a larger campaign.
- **CONDITIONAL_ACCESS deletion alongside SD disablement** = The attacker is removing both CA policies AND Security Defaults, ensuring zero authentication protections remain. This is the most dangerous scenario.
- **MFA_CONFIGURATION changes** = Attacker modifying tenant-wide MFA settings in addition to disabling Security Defaults -- belt-and-suspenders defense evasion.
- **MinutesFromAlert close to 0** = Changes happening within minutes of each other indicate automated or scripted attack execution.

---

### Step 7: Organization-Wide Security Posture Sweep

**Objective:** Sweep for all security-relevant configuration changes in the past 7 days: Security Defaults, Conditional Access policies, diagnostic settings, audit settings, MFA settings, password policies, authentication methods. This provides the full picture of the tenant's security posture and identifies any other changes that may have gone unnoticed.

```kql
// Step 7: Organization-Wide Security Posture Sweep
// Table: AuditLogs | Comprehensive 7-day security configuration audit
let AlertTime = datetime(2026-02-22T14:00:00Z);
let SweepWindow = 7d;
AuditLogs
| where TimeGenerated between ((AlertTime - SweepWindow) .. (AlertTime + 1d))
| where OperationName in (
    // Security Defaults
    "Update organization settings", "Set company information",
    "Disable Security Defaults", "Enable Security Defaults",
    // Conditional Access
    "Update conditional access policy", "Delete conditional access policy",
    "Add conditional access policy",
    // Named Locations
    "Update named location", "Delete named location", "Add named location",
    // Diagnostic settings
    "Update diagnostic setting", "Delete diagnostic setting",
    // MFA and Auth settings
    "Update StrongAuthenticationPolicy", "Delete StrongAuthenticationPolicy",
    "Update authentication methods policy", "Update authentication requirement",
    // Authorization and consent
    "Update authorization policy", "Update consent settings",
    // Password policy
    "Set password policy", "Update password policy",
    // Role assignments (security relevant)
    "Add member to role", "Add eligible member to role",
    "Remove member from role"
)
| extend
    ActorUPN = coalesce(
        tostring(InitiatedBy.user.userPrincipalName),
        tostring(InitiatedBy.app.displayName),
        "Unknown"
    ),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    TargetId = tostring(TargetResources[0].id),
    ChangeCategory = case(
        OperationName has_any ("Security Defaults", "organization settings",
            "company information"),
            "Security Defaults",
        OperationName has "conditional access", "Conditional Access",
        OperationName has "named location", "Named Locations",
        OperationName has "diagnostic", "Diagnostic Settings",
        OperationName has_any ("StrongAuthentication", "authentication methods",
            "authentication requirement"),
            "Authentication/MFA",
        OperationName has "authorization", "Authorization Policy",
        OperationName has "password", "Password Policy",
        OperationName has "consent", "Consent Settings",
        OperationName has "role", "Role Assignments",
        "Other"
    )
| summarize
    ChangeCount = count(),
    Operations = make_set(OperationName, 10),
    Actors = make_set(ActorUPN, 10),
    ActorIPs = make_set(ActorIP, 10),
    FirstChange = min(TimeGenerated),
    LastChange = max(TimeGenerated),
    DeleteCount = countif(OperationName has "Delete"),
    DisableCount = countif(OperationName has "Disable")
    by ChangeCategory
| extend
    PostureRisk = case(
        ChangeCategory == "Security Defaults" and DisableCount > 0,
            "CRITICAL - Security Defaults disabled",
        ChangeCategory == "Conditional Access" and DeleteCount > 0,
            "CRITICAL - CA policies deleted",
        ChangeCategory == "Diagnostic Settings" and (DeleteCount > 0 or ChangeCount > 0),
            "CRITICAL - Audit logging modified",
        ChangeCategory == "Role Assignments" and ChangeCount > 3,
            "HIGH - Multiple role changes",
        ChangeCategory == "Authentication/MFA",
            "HIGH - MFA/Auth settings modified",
        ChangeCategory == "Conditional Access" and ChangeCount > 5,
            "HIGH - Significant CA policy churn",
        ChangeCategory == "Consent Settings",
            "MEDIUM - Consent settings changed",
        "MEDIUM - Configuration change"
    )
| project
    ChangeCategory,
    PostureRisk,
    ChangeCount,
    DeleteCount,
    DisableCount,
    Operations,
    Actors,
    FirstChange,
    LastChange,
    DaysSpan = datetime_diff('day', LastChange, FirstChange)
| sort by case(
    PostureRisk has "CRITICAL", 1,
    PostureRisk has "HIGH", 2,
    3
) asc
```

**What to look for:**

- **Multiple CRITICAL categories** = Security Defaults disabled AND CA policies deleted AND diagnostic settings modified. This is a comprehensive defense evasion campaign. Treat as a confirmed breach with immediate containment.
- **Diagnostic Settings modified** = Audit log tampering -- the attacker may be trying to prevent future detection. This is one of the most dangerous concurrent findings.
- **Role Assignments with ChangeCount > 3** = Multiple privilege escalations in 7 days. The attacker may have created multiple admin accounts for persistence. Cross-reference with [RB-0013](privileged-role-assignment.md).
- **Same Actor across multiple categories** = One admin account responsible for changes across Security Defaults, CA, diagnostics, and MFA settings. The account is almost certainly compromised.
- **DaysSpan = 0 for multiple categories** = All changes in the same day -- coordinated attack execution.
- **No Conditional Access policy results** = If there are zero CA policies AND Security Defaults are now disabled, the tenant has ZERO authentication protections. This is the worst possible outcome.

---

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Microsoft Sentinel's UEBA engine to assess whether the actor who disabled Security Defaults was exhibiting anomalous behavior. UEBA's `ActivityInsights` reveal first-time actions, uncommon operations, and behavioral deviation from the actor's historical pattern.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If UEBA is not configured in your environment, skip this step. The investigation remains valid without UEBA, but behavioral context significantly improves confidence in True/False Positive determination.

#### Query 8A: Actor UEBA — Comprehensive Behavioral Assessment

```kql
// Step 8A: UEBA Behavioral Assessment for Security Default Modifier
// Table: BehaviorAnalytics | Behavioral anomalies for the actor who disabled SD
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ActorUPN = "admin@contoso.com";
let LookbackWindow = 7d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
| where UserPrincipalName =~ ActorUPN
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
    // Action anomalies (primary indicators for compromised admin)
    FirstTimeActionPerformed = tostring(ActivityInsights.FirstTimeUserPerformedAction),
    ActionUncommonlyPerformed = tostring(ActivityInsights.ActionUncommonlyPerformedByUser),
    ActionUncommonAmongPeers = tostring(ActivityInsights.ActionUncommonlyPerformedAmongPeers),
    FirstTimeAppUsed = tostring(ActivityInsights.FirstTimeUserUsedApp),
    AppUncommonlyUsed = tostring(ActivityInsights.AppUncommonlyUsedByUser),
    // Location anomalies
    FirstTimeCountry = tostring(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommon = tostring(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    CountryUncommonAmongPeers = tostring(ActivityInsights.CountryUncommonlyConnectedFromAmongPeers),
    FirstTimeISP = tostring(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommon = tostring(ActivityInsights.ISPUncommonlyUsedByUser),
    ISPUncommonAmongPeers = tostring(ActivityInsights.ISPUncommonlyUsedAmongPeers),
    // Device anomalies
    FirstTimeDevice = tostring(ActivityInsights.FirstTimeUserUsedDevice),
    DeviceUncommon = tostring(ActivityInsights.DeviceUncommonlyUsedByUser),
    FirstTimeBrowser = tostring(ActivityInsights.FirstTimeUserUsedBrowser),
    BrowserUncommon = tostring(ActivityInsights.BrowserUncommonlyUsedByUser),
    // Volume anomalies
    UncommonHighVolume = tostring(ActivityInsights.UncommonHighVolumeOfActions),
    // Resource anomalies
    FirstTimeResource = tostring(ActivityInsights.FirstTimeUserAccessedResource),
    ResourceUncommon = tostring(ActivityInsights.ResourceUncommonlyAccessedByUser),
    // User profile
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tostring(UsersInsights.IsDormantAccount),
    IsNewAccount = tostring(UsersInsights.IsNewAccount),
    // Device threat intel
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| extend
    AnomalyCount = toint(FirstTimeActionPerformed == "True")
        + toint(ActionUncommonlyPerformed == "True")
        + toint(FirstTimeAppUsed == "True")
        + toint(FirstTimeCountry == "True")
        + toint(CountryUncommon == "True")
        + toint(FirstTimeISP == "True")
        + toint(ISPUncommon == "True")
        + toint(FirstTimeDevice == "True")
        + toint(FirstTimeBrowser == "True")
        + toint(UncommonHighVolume == "True")
        + toint(FirstTimeResource == "True")
        + toint(isnotempty(ThreatIndicator)),
    RiskLevel = case(
        InvestigationPriority >= 7, "HIGH",
        InvestigationPriority >= 4, "MEDIUM",
        "LOW"
    )
| order by InvestigationPriority desc, TimeGenerated desc
```

#### Query 8B: UEBA Anomaly Summary — Actor Compromise Confidence

```kql
// Step 8B: UEBA Anomaly Summary — Actor Compromise Confidence
// Table: BehaviorAnalytics | Aggregated behavioral assessment for the actor
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ActorUPN = "admin@contoso.com";
let LookbackWindow = 3d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
| where UserPrincipalName =~ ActorUPN
| extend
    ActivityInsights = parse_json(ActivityInsights),
    UsersInsights = parse_json(UsersInsights),
    DevicesInsights = parse_json(DevicesInsights)
| summarize
    MaxPriority = max(InvestigationPriority),
    AvgPriority = round(avg(InvestigationPriority), 1),
    HighPriorityEvents = countif(InvestigationPriority >= 7),
    TotalEvents = count(),
    // Admin compromise indicators
    FirstTimeActions = countif(tostring(ActivityInsights.FirstTimeUserPerformedAction) == "True"),
    UncommonActions = countif(tostring(ActivityInsights.ActionUncommonlyPerformedByUser) == "True"),
    NewCountryEvents = countif(tostring(ActivityInsights.FirstTimeUserConnectedFromCountry) == "True"),
    NewISPEvents = countif(tostring(ActivityInsights.FirstTimeUserConnectedViaISP) == "True"),
    NewDeviceEvents = countif(tostring(ActivityInsights.FirstTimeUserUsedDevice) == "True"),
    NewBrowserEvents = countif(tostring(ActivityInsights.FirstTimeUserUsedBrowser) == "True"),
    NewAppEvents = countif(tostring(ActivityInsights.FirstTimeUserUsedApp) == "True"),
    NewResourceEvents = countif(tostring(ActivityInsights.FirstTimeUserAccessedResource) == "True"),
    HighVolumeEvents = countif(tostring(ActivityInsights.UncommonHighVolumeOfActions) == "True"),
    ThreatIndicators = countif(isnotempty(tostring(DevicesInsights.ThreatIntelIndicatorType))),
    BlastRadius = take_any(tostring(UsersInsights.BlastRadius)),
    IsDormant = take_any(tostring(UsersInsights.IsDormantAccount)),
    IsNewAccount = take_any(tostring(UsersInsights.IsNewAccount))
    by UserPrincipalName
| extend
    CompromiseConfidence = case(
        MaxPriority >= 7 and NewCountryEvents > 0 and FirstTimeActions > 0,
            "VERY HIGH - High priority + new country + first-time actions",
        MaxPriority >= 7 and (NewCountryEvents > 0 or NewISPEvents > 0),
            "HIGH - High priority with new location indicators",
        IsDormant == "True" and TotalEvents > 0,
            "HIGH - Dormant admin account suddenly performing config changes",
        IsNewAccount == "True" and FirstTimeActions > 0,
            "HIGH - New account performing first-time admin actions",
        NewCountryEvents > 0 and NewDeviceEvents > 0,
            "HIGH - New country + new device (even without high priority)",
        ThreatIndicators > 0,
            "HIGH - Threat intelligence match on admin device",
        FirstTimeActions > 2,
            "MEDIUM - Multiple first-time actions (potential learning period or compromise)",
        MaxPriority >= 4 and HighVolumeEvents > 0,
            "MEDIUM - Moderate priority with unusual action volume",
        NewISPEvents > 0 or NewBrowserEvents > 0,
            "MEDIUM - New ISP or browser (could be VPN/update)",
        "LOW - Activity within behavioral norms for this admin"
    )
```

**Expected findings:**

| Indicator | Compromised Admin Signal | Legitimate Admin Signal |
|---|---|---|
| InvestigationPriority >= 7 | Significant behavioral deviation | Normal admin activity |
| FirstTimeActionPerformed = True | Admin performing Security Default changes for the first time | Expected for new admin or new responsibility |
| FirstTimeCountry + FirstTimeISP = True | Admin session from new location/ISP -- likely attacker infrastructure | Admin traveling or using new VPN |
| IsDormantAccount = True | Dormant admin suddenly active -- very suspicious | Account reactivated for planned work |
| UncommonHighVolume = True | Burst of admin actions -- automated attack | Large maintenance task |
| ThreatIndicator present | Malware on admin device -- likely credential theft source | False positive from security tool |
| BlastRadius = High | Admin has broad access -- compromise has wide impact | Expected for Global Admins |

**Decision guidance:**

- **CompromiseConfidence = "VERY HIGH"** -> Multiple first-time signals at high priority. The admin account is almost certainly compromised. Re-enable Security Defaults immediately and revoke the admin's sessions.
- **IsDormant = True** -> A dormant admin account suddenly disabling Security Defaults is extremely suspicious. Dormant accounts do not perform administrative actions spontaneously.
- **CompromiseConfidence = "LOW"** -> UEBA sees no significant deviation. If Steps 2-3 showed risk signals, this could mean the attacker is operating within the admin's normal patterns (sophisticated actor who compromised the account days ago and has been mimicking the admin's behavior).

---

## 6. Containment Playbook

### Immediate Actions (0-15 minutes)

- [ ] **Re-enable Security Defaults** immediately via Entra ID Portal > Properties > Manage Security Defaults > Yes
- [ ] **Revoke ALL sessions** for the actor admin account via `Revoke-MgUserSignInSession`
- [ ] **Reset the actor's password** to invalidate all tokens and credentials
- [ ] **Disable the actor's admin account** temporarily if compromise is confirmed (Steps 2-3)
- [ ] **Block the actor's IP** via Conditional Access Named Locations if it is a hosting/VPS IP (Step 1)

### Short-term Actions (15 min - 2 hours)

- [ ] **Audit all sign-ins that occurred while Security Defaults were off** (Step 5) -- identify any legacy auth or no-MFA sign-ins
- [ ] **Check for legacy auth abuse** -- if IMAP/POP/SMTP sign-ins succeeded, investigate those accounts for BEC/email compromise
- [ ] **Review MFA registration status** -- identify users who de-registered MFA while defaults were off
- [ ] **Check for concurrent CA policy changes** (Step 6) -- restore any deleted or disabled CA policies
- [ ] **Verify audit log integrity** -- if diagnostic settings were modified (Step 6), restore them immediately
- [ ] **Remove any MFA methods** registered by the actor from a suspicious IP/location
- [ ] **Cross-reference with [RB-0013](privileged-role-assignment.md)** -- verify the actor's admin role assignment was legitimate

### Recovery Actions (2-24 hours)

- [ ] **Migrate from Security Defaults to Conditional Access policies** if not already done -- CA provides granular control that Security Defaults lacks
- [ ] **Implement CA policy: Block legacy authentication** explicitly (do not rely solely on Security Defaults)
- [ ] **Implement CA policy: Require MFA for all users** explicitly
- [ ] **Implement CA policy: Require MFA for Azure management** explicitly
- [ ] **Enable Conditional Access policy protection** -- prevent CA policies from being modified without PIM elevation
- [ ] **Enable diagnostic settings** for all Entra ID log types to Microsoft Sentinel
- [ ] **Implement break-glass account procedure** -- ensure emergency admin accounts are excluded from CA but monitored with alerts
- [ ] **Review all accounts that signed in during the exposure window** for suspicious post-authentication activity
- [ ] **Run [RB-0006](password-spray-detection.md)** to check if password spray attacks succeeded during the exposure window

---

## 7. Evidence Collection Checklist

| Evidence Item | Source Table | Retention | Collection Query |
|---|---|---|---|
| Security Default change event | AuditLogs | 90 days | Step 1 query |
| Actor sign-in context | SigninLogs | 30 days | Step 2 query |
| Actor account modifications | AuditLogs | 90 days | Step 2 query |
| Pre-change attack chain | SigninLogs + AuditLogs | 30/90 days | Step 3 query |
| Historical configuration baseline | AuditLogs | 90 days | Step 4 query |
| Post-disablement legacy auth | SigninLogs + AADNonInteractive | 30 days | Step 5 query |
| Post-disablement no-MFA sign-ins | SigninLogs | 30 days | Step 5 query |
| Concurrent defense evasion | AuditLogs | 90 days | Step 6 query |
| 7-day security posture sweep | AuditLogs | 90 days | Step 7 query |
| UEBA behavioral assessment | BehaviorAnalytics | 30 days | Step 8 query |

---

## 8. Escalation Criteria

| Condition | Action |
|---|---|
| Security Defaults disabled + no CA policies in place (zero protections) | Escalate to **P1 Incident** -- tenant has no authentication protections |
| Security Defaults disabled from hosting/VPS IP (Step 1) + actor has risk events (Step 2) | Escalate to **P1 Incident** -- confirmed compromised admin |
| Legacy auth succeeding from hosting IPs after disablement (Step 5) | Escalate to **P1 Incident** -- active exploitation of disabled protections |
| Multiple defense categories modified concurrently (Step 6) | Escalate to **P1 Incident** -- systematic defense evasion campaign |
| Diagnostic settings deleted alongside SD disablement (Step 6) | Escalate to **P1 Incident** -- evidence destruction in progress |
| Security Defaults disabled by known admin + documented change ticket | Escalate to **P3** -- verify change management compliance |
| Security Defaults disabled + CA policies remain active and enforcing | Escalate to **P2 Incident** -- reduced risk but investigate actor |
| Security Defaults toggled off and back on within 30 minutes | Escalate to **P3** -- likely troubleshooting, verify with admin |

---

## 9. False Positive Documentation

| Scenario | How to Identify | Recommended Action |
|---|---|---|
| Migration to Conditional Access | Change ticket exists, CA policies created before/after SD disablement | Verify CA policies cover MFA + legacy auth block, close as planned change |
| IT troubleshooting | SD toggled off and back on within 30 min, during business hours | Verify with admin, document troubleshooting reason, close as benign |
| Development/test tenant | Tenant is non-production, no sensitive data | Document exception, exclude tenant from alerting |
| New admin performing first-time configuration | Admin role recently assigned through proper PIM process | Verify PIM approval, provide admin training, close as learning curve |
| Automated provisioning tool | Service principal makes the change as part of tenant bootstrapping | Verify the app registration, add to allowlist if legitimate |

---

## 10. MITRE ATT&CK Mapping

| Technique ID | Technique Name | How It Applies | Detection Query |
|---|---|---|---|
| **T1562.001** | **Impair Defenses: Disable or Modify Tools** | Security Defaults disabled to remove MFA enforcement and legacy auth blocking | **Steps 1, 6, 7** |
| **T1562.007** | **Impair Defenses: Disable or Modify Cloud Firewall** | Security Defaults act as a cloud-level authentication firewall; disabling removes network-level protections | **Steps 1, 5** |
| **T1556** | **Modify Authentication Process** | Disabling Security Defaults changes the authentication flow from MFA-required to password-only | **Steps 1, 5** |
| T1078.004 | Valid Accounts: Cloud Accounts | Attacker using compromised admin account to make the change | Steps 2, 3 |
| T1562.008 | Impair Defenses: Disable or Modify Cloud Logs | Concurrent diagnostic settings modification to hide the attack | Step 6 |
| T1098 | Account Manipulation | Post-disablement account compromise via password-only authentication | Step 5 |

---

## 11. Query Summary

| Step | Query | Purpose | Primary Table |
|---|---|---|---|
| 1 | Security Default Change Detection | Find exact disablement event and actor | AuditLogs |
| 2 | Actor Analysis | Actor sign-in context and compromise assessment | SigninLogs + AuditLogs |
| 3 | Pre-Change Risk Assessment | Attack chain leading to disablement | SigninLogs + AuditLogs |
| 4 | Baseline Comparison | 30-day configuration change history | AuditLogs |
| 5 | Post-Disablement Impact | Legacy auth, no-MFA sign-ins, exploitation | SigninLogs + AADNonInteractive |
| 6 | Concurrent Defense Evasion | Multiple defenses disabled together | AuditLogs |
| 7 | Security Posture Sweep | 7-day org-wide configuration audit | AuditLogs |
| 8A | UEBA Assessment | Behavioral anomaly context for actor | BehaviorAnalytics |
| 8B | UEBA Anomaly Summary | Aggregated actor compromise confidence | BehaviorAnalytics |

---

## Appendix A: Datatable Tests

### Test 1: Security Default Disablement Detection

```kql
// TEST 1: Verifies detection of SecurityDefaultsEnabled changing to false
let TestAuditLogs = datatable(
    TimeGenerated: datetime, OperationName: string,
    InitiatedBy: dynamic, TargetResources: dynamic, Result: string
)[
    // Security Defaults disabled
    datetime(2026-02-22T14:00:00Z), "Update organization settings",
        dynamic({"user":{"userPrincipalName":"evil.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Organization","id":"org-001",
            "modifiedProperties":[{"displayName":"SecurityDefaultsEnabled","oldValue":"\"true\"","newValue":"\"false\""}]}]),
        "success",
    // Security Defaults enabled (should be INFO, not CRITICAL)
    datetime(2026-02-22T16:00:00Z), "Update organization settings",
        dynamic({"user":{"userPrincipalName":"good.admin@contoso.com","ipAddress":"10.0.0.50"}}),
        dynamic([{"displayName":"Organization","id":"org-001",
            "modifiedProperties":[{"displayName":"SecurityDefaultsEnabled","oldValue":"\"false\"","newValue":"\"true\""}]}]),
        "success",
    // Unrelated org setting change (should be excluded)
    datetime(2026-02-22T15:00:00Z), "Update organization settings",
        dynamic({"user":{"userPrincipalName":"good.admin@contoso.com","ipAddress":"10.0.0.50"}}),
        dynamic([{"displayName":"Organization","id":"org-001",
            "modifiedProperties":[{"displayName":"DisplayName","oldValue":"\"OldName\"","newValue":"\"NewName\""}]}]),
        "success"
];
TestAuditLogs
| where OperationName in ("Update organization settings", "Disable Security Defaults")
| mv-expand ModifiedProps = TargetResources[0].modifiedProperties
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| where PropertyName has "SecurityDefaultsEnabled"
| extend
    ChangeDirection = case(
        NewValue has "false", "DISABLED",
        NewValue has "true", "ENABLED",
        "UNKNOWN"
    ),
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    SeverityLevel = case(
        NewValue has "false", "CRITICAL",
        NewValue has "true", "INFO",
        "MEDIUM"
    )
| summarize
    DisableEvents = countif(ChangeDirection == "DISABLED"),
    EnableEvents = countif(ChangeDirection == "ENABLED"),
    CriticalEvents = countif(SeverityLevel == "CRITICAL"),
    DisableActors = make_set_if(ActorUPN, ChangeDirection == "DISABLED"),
    DisableIPs = make_set_if(ActorIP, ChangeDirection == "DISABLED")
| where DisableEvents == 1
    and EnableEvents == 1
    and CriticalEvents == 1
    and set_has_element(DisableActors, "evil.admin@contoso.com")
    and set_has_element(DisableIPs, "198.51.100.50")
// EXPECTED: 1 row — 1 disable (CRITICAL) + 1 enable (INFO), unrelated change excluded
```

### Test 2: Post-Disablement Legacy Authentication Detection

```kql
// TEST 2: Verifies detection of legacy auth succeeding after SD disablement
let AlertTime = datetime(2026-02-22T14:00:00Z);
let TestSignIns = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, IPAddress: string,
    ResultType: string, ClientAppUsed: string, AppDisplayName: string,
    AuthenticationRequirement: string, AutonomousSystemNumber: int,
    LocationDetails: dynamic, IsLegacyAuth: bool
)[
    // Legacy auth success AFTER disablement (attacker using IMAP)
    datetime(2026-02-22T14:15:00Z), "cfo@contoso.com", "198.51.100.60",
        "0", "IMAP4", "Exchange Online", "singleFactorAuthentication",
        14061, dynamic({"countryOrRegion":"RU","city":"Moscow"}), true,
    // Legacy auth success AFTER disablement (attacker using SMTP)
    datetime(2026-02-22T14:20:00Z), "ceo@contoso.com", "198.51.100.61",
        "0", "Authenticated SMTP", "Exchange Online", "singleFactorAuthentication",
        14061, dynamic({"countryOrRegion":"RU","city":"Moscow"}), true,
    // Modern auth success (not legacy — should not be flagged as legacy)
    datetime(2026-02-22T14:30:00Z), "user@contoso.com", "10.0.0.100",
        "0", "Browser", "Office 365", "multiFactorAuthentication",
        1234, dynamic({"countryOrRegion":"US","city":"Seattle"}), false,
    // Legacy auth BEFORE disablement (should be excluded by time filter)
    datetime(2026-02-22T13:00:00Z), "user2@contoso.com", "10.0.0.101",
        "0", "IMAP4", "Exchange Online", "singleFactorAuthentication",
        1234, dynamic({"countryOrRegion":"US","city":"Seattle"}), true
];
let LegacyProtocols = dynamic(["IMAP4", "POP3", "SMTP", "Authenticated SMTP",
    "Exchange ActiveSync", "IMAP", "POP"]);
let HostingASNs = dynamic([14061, 16509, 14618, 15169]);
TestSignIns
| where TimeGenerated > AlertTime
| where ResultType == "0"
| where ClientAppUsed in (LegacyProtocols) or IsLegacyAuth == true
| summarize
    LegacySignIns = count(),
    LegacyUsers = dcount(UserPrincipalName),
    HostingIPCount = countif(AutonomousSystemNumber in (HostingASNs)),
    AffectedUsers = make_set(UserPrincipalName),
    Protocols = make_set(ClientAppUsed)
| where LegacySignIns == 2
    and LegacyUsers == 2
    and HostingIPCount == 2
    and set_has_element(AffectedUsers, "cfo@contoso.com")
    and set_has_element(AffectedUsers, "ceo@contoso.com")
    and set_has_element(Protocols, "IMAP4")
    and set_has_element(Protocols, "Authenticated SMTP")
// EXPECTED: 1 row — 2 legacy auth sign-ins from hosting IPs (cfo + ceo), modern auth excluded
```

### Test 3: Concurrent Defense Evasion Detection

```kql
// TEST 3: Verifies detection of multiple defenses disabled concurrently
let AlertTime = datetime(2026-02-22T14:00:00Z);
let TestAuditLogs = datatable(
    TimeGenerated: datetime, OperationName: string,
    InitiatedBy: dynamic, TargetResources: dynamic, Result: string
)[
    // Security Defaults disabled
    datetime(2026-02-22T14:00:00Z), "Disable Security Defaults",
        dynamic({"user":{"userPrincipalName":"evil.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Security Defaults"}]), "success",
    // CA policy deleted (concurrent)
    datetime(2026-02-22T14:05:00Z), "Delete conditional access policy",
        dynamic({"user":{"userPrincipalName":"evil.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Require MFA for All Users"}]), "success",
    // Diagnostic settings deleted (audit log tampering)
    datetime(2026-02-22T14:10:00Z), "Delete diagnostic setting",
        dynamic({"user":{"userPrincipalName":"evil.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"EntraID-to-Sentinel"}]), "success",
    // Unrelated change by different admin (should still appear but different actor)
    datetime(2026-02-22T15:00:00Z), "Add named location",
        dynamic({"user":{"userPrincipalName":"good.admin@contoso.com","ipAddress":"10.0.0.50"}}),
        dynamic([{"displayName":"New Office VPN"}]), "success"
];
let ConcurrentWindow = 4h;
TestAuditLogs
| where TimeGenerated between ((AlertTime - ConcurrentWindow) .. (AlertTime + ConcurrentWindow))
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    DefenseCategory = case(
        OperationName has_any ("Security Defaults"), "SECURITY_DEFAULTS",
        OperationName has "conditional access", "CONDITIONAL_ACCESS",
        OperationName has "diagnostic", "DIAGNOSTIC_SETTINGS",
        OperationName has "named location", "NAMED_LOCATIONS",
        "OTHER"
    )
| summarize
    TotalChanges = count(),
    Categories = make_set(DefenseCategory),
    CriticalChanges = countif(OperationName has_any ("Delete", "Disable")),
    Actors = make_set(ActorUPN),
    EvilAdminChanges = countif(ActorUPN == "evil.admin@contoso.com")
| where array_length(Categories) >= 3
    and CriticalChanges >= 3
    and EvilAdminChanges == 3
    and set_has_element(Categories, "SECURITY_DEFAULTS")
    and set_has_element(Categories, "CONDITIONAL_ACCESS")
    and set_has_element(Categories, "DIAGNOSTIC_SETTINGS")
// EXPECTED: 1 row — 3 critical defense evasion categories by evil.admin (SD + CA + Diagnostics)
```

### Test 4: Baseline Comparison — New Modifier Detection

```kql
// TEST 4: Verifies detection of a new modifier not in the 30-day baseline
let TestAuditLogs = datatable(
    TimeGenerated: datetime, OperationName: string,
    InitiatedBy: dynamic, TargetResources: dynamic, Result: string
)[
    // Historical changes by known admin (baseline)
    datetime(2026-01-25T10:00:00Z), "Update conditional access policy",
        dynamic({"user":{"userPrincipalName":"it.admin@contoso.com","ipAddress":"10.0.0.50"}}),
        dynamic([{"displayName":"Block Legacy Auth"}]), "success",
    datetime(2026-02-05T10:00:00Z), "Update conditional access policy",
        dynamic({"user":{"userPrincipalName":"it.admin@contoso.com","ipAddress":"10.0.0.50"}}),
        dynamic([{"displayName":"Require MFA"}]), "success",
    datetime(2026-02-10T10:00:00Z), "Add named location",
        dynamic({"user":{"userPrincipalName":"it.admin@contoso.com","ipAddress":"10.0.0.50"}}),
        dynamic([{"displayName":"Office VPN"}]), "success",
    // NEW actor disabling Security Defaults (not in baseline)
    datetime(2026-02-22T14:00:00Z), "Update organization settings",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Organization"}]), "success"
];
let ActorUPN = "compromised.admin@contoso.com";
TestAuditLogs
| extend ModifyingUser = tostring(InitiatedBy.user.userPrincipalName)
| summarize
    TotalChanges = count(),
    KnownModifiers = make_set(ModifyingUser),
    SecurityDefaultChanges = countif(OperationName has "organization settings")
| extend
    ActorInBaseline = KnownModifiers has ActorUPN,
    Assessment = case(
        not(KnownModifiers has ActorUPN),
            "ANOMALOUS - New modifier not in baseline",
        "WITHIN BASELINE"
    )
| where ActorInBaseline == false
    and Assessment == "ANOMALOUS - New modifier not in baseline"
    and array_length(KnownModifiers) == 2
// EXPECTED: 1 row — compromised.admin is NOT in the historical modifier set (only it.admin was known)
```

---

## References

- [Microsoft Entra Security Defaults](https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults)
- [Enabling Security Defaults](https://learn.microsoft.com/en-us/entra/fundamentals/concept-fundamentals-security-defaults)
- [Migrating from Security Defaults to Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-security-defaults-migration)
- [Conditional Access: Block Legacy Authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy)
- [Microsoft Entra ID Audit Logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs)
- [AuditLogs Table Reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- [SigninLogs Table Reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [AADNonInteractiveUserSignInLogs Reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
- [MITRE ATT&CK T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK T1562.007 - Impair Defenses: Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/)
- [MITRE ATT&CK T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- [Microsoft Incident Response: Protecting Cloud Identities](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app)
- [Scattered Spider Threat Analysis](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)
- [Midnight Blizzard Cloud Attack Techniques](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
