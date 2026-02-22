---
title: "Consent Grant Attack"
id: RB-0011
severity: high
status: reviewed
description: >
  Investigation runbook for illicit OAuth application consent grant attacks in
  Microsoft Entra ID. Covers detection of malicious or suspicious OAuth consent
  grants where users are tricked into authorizing rogue applications with access
  to their data (email, files, calendar). Includes consent event analysis, app
  risk profiling, phishing correlation, data access auditing via Microsoft Graph
  activity logs, blast radius assessment across the organization, and org-wide
  risky application sweep. Consent grant attacks bypass MFA because the user
  explicitly authorizes the application, and the resulting OAuth tokens persist
  even after password resets until the consent is revoked.
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
    - tactic_id: TA0009
      tactic_name: "Collection"
    - tactic_id: TA0010
      tactic_name: "Exfiltration"
  techniques:
    - technique_id: T1528
      technique_name: "Steal Application Access Token"
      confidence: confirmed
    - technique_id: T1550.001
      technique_name: "Use Alternate Authentication Material: Application Access Token"
      confidence: confirmed
    - technique_id: T1566.002
      technique_name: "Phishing: Spearphishing Link"
      confidence: confirmed
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: confirmed
    - technique_id: T1114.002
      technique_name: "Email Collection: Remote Email Collection"
      confidence: confirmed
    - technique_id: T1213
      technique_name: "Data from Information Repositories"
      confidence: confirmed
threat_actors:
  - "Storm-0324"
  - "Midnight Blizzard (APT29/Nobelium)"
  - "APT28 (Fancy Bear)"
  - "Storm-1283"
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
  - table: "CloudAppEvents"
    product: "Microsoft Defender for Cloud Apps"
    license: "Microsoft 365 E5 / Defender for Cloud Apps"
    required: true
    alternatives: []
  - table: "AADServicePrincipalSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: false
    alternatives: []
  - table: "OfficeActivity"
    product: "Office 365"
    license: "Office 365 E1+"
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
  - CloudAppEvents
  - AADServicePrincipalSignInLogs
  - OfficeActivity
tactic_slugs:
  - initial-access
  - persistence
  - defense-evasion
  - cred-access
  - collection
  - exfiltration
data_checks:
  - query: "AuditLogs | where OperationName == 'Consent to application' | take 1"
    label: primary
    description: "OAuth consent grant event detection"
  - query: "SigninLogs | take 1"
    description: "For user sign-in context and phishing correlation"
  - query: "CloudAppEvents | take 1"
    description: "For OAuth app activity and data access patterns"
  - query: "AADServicePrincipalSignInLogs | take 1"
    label: optional
    description: "For app sign-in patterns after consent (requires P1/P2)"
  - query: "OfficeActivity | take 1"
    label: optional
    description: "For Office 365 data access via consented app"
---

# Consent Grant Attack - Investigation Runbook

> **RB-0011** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Audit Logs + Defender for Cloud Apps OAuth App Governance
> **Risk Detection Name:** `Consent to application` audit event + Risky OAuth app alert
> **Primary MITRE Technique:** T1528 - Steal Application Access Token

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Consent Grant Event Analysis](#step-1-consent-grant-event-analysis)
   - [Step 2: Application Risk Profiling](#step-2-application-risk-profiling)
   - [Step 3: Phishing Correlation & User Context](#step-3-phishing-correlation--user-context)
   - [Step 4: Baseline Comparison - Establish Normal Consent Behavior](#step-4-baseline-comparison---establish-normal-consent-behavior)
   - [Step 5: Data Access Audit via Consented App](#step-5-data-access-audit-via-consented-app)
   - [Step 6: Blast Radius - Multi-User Consent Assessment](#step-6-blast-radius---multi-user-consent-assessment)
   - [Step 7: Org-Wide Risky OAuth App Sweep](#step-7-org-wide-risky-oauth-app-sweep)
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
Illicit consent grant attacks are detected through multiple complementary mechanisms:

1. **AuditLogs consent events:** The `Consent to application` operation in Entra ID AuditLogs records every OAuth consent grant. Suspicious grants include unknown publisher apps, apps requesting high-privilege permissions (Mail.Read, Files.ReadWrite.All, User.ReadWrite.All), and consent from users who were recently phished.
2. **Defender for Cloud Apps OAuth governance:** Microsoft Defender for Cloud Apps evaluates OAuth apps for risk indicators including unverified publishers, high permission levels, community prevalence, and anomalous activity patterns.
3. **Cross-signal correlation:** A phishing email containing an OAuth authorization URL, followed by a consent grant, followed by programmatic data access via the consented app -- this sequence is the hallmark of consent phishing.

**Why it matters:**
Consent grant attacks are one of the most dangerous identity attack vectors because they **completely bypass MFA**. The user is not sharing their password -- they are explicitly authorizing an application to act on their behalf via OAuth. Once consent is granted, the attacker's application receives a refresh token that remains valid even after the user changes their password. The only remediation is revoking the consent grant and the application's tokens. APT29/Midnight Blizzard used OAuth app abuse extensively during the Microsoft corporate breach (January 2024), creating malicious OAuth applications to access executive mailboxes.

**Why this is HIGH severity:**
- OAuth tokens persist across password resets -- revoking the app consent is the ONLY way to remove access
- The user explicitly authorized the app, so there is no brute force or credential stuffing to detect
- Consented apps can silently read email, access files, enumerate directory, and send messages on behalf of the user
- A single consented app with `Mail.ReadWrite` can exfiltrate months of email history in minutes
- Attacker-controlled apps with `User.ReadWrite.All` can modify user profiles, add auth methods, and escalate privileges
- Consent grants from admin users can result in tenant-wide application permissions (admin consent)

**However:** This alert has a **moderate false positive rate** (~15-25%). Legitimate triggers include:
- Users consenting to legitimate SaaS productivity tools (Zoom, Slack, Grammarly, etc.)
- IT-approved applications that require user consent before admin consent is configured
- Shadow IT -- users installing unapproved but non-malicious applications
- Application updates requiring re-consent for additional permissions
- Developer testing with custom app registrations in development tenants

**Worst case scenario if this is real:**
An attacker sends a phishing email containing an OAuth consent URL to a targeted user. The user clicks the link and is presented with a legitimate-looking Microsoft consent screen for a malicious app named something like "Microsoft Office Security" or "M365 Document Viewer." The user clicks "Accept," granting the app permissions to read their email and files. The attacker's backend immediately begins exfiltrating all email, OneDrive/SharePoint files, and contact lists via the Microsoft Graph API using the delegated permissions. Because the access is via OAuth, the user's password was never compromised, MFA was never bypassed, and no suspicious sign-in appears in the logs -- only the consent grant event in AuditLogs reveals the attack. If the user is a high-value target (executive, finance, HR), the attacker can read confidential communications, access financial documents, and use the email access for downstream BEC attacks against partners and vendors.

**Key difference from other identity runbooks:**
- RB-0001 through RB-0006 (Credential-focused): Investigate password/MFA-based attacks where credentials are compromised. Remediation: password reset + MFA enforcement.
- RB-0010 (Service Principal): Investigates workload identity compromise. The SP itself is abused.
- **RB-0011 (This runbook):** Investigates **delegated permission abuse via user consent**. The user is tricked into granting an attacker-controlled application access to their data. Remediation: revoke consent + revoke app tokens + block the app. Password reset alone does NOT fix this.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID Free + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID (AuditLogs, SigninLogs)
- **Permissions:** Security Reader (investigation), Cloud Application Administrator (containment)

### Recommended for Full Coverage
- **License:** Entra ID P2 + Microsoft 365 E5 + Defender for Cloud Apps + Sentinel
- **Additional:** Defender for Cloud Apps OAuth app governance enabled
- **App Governance Add-on:** For advanced OAuth app risk scoring and automated remediation

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | AuditLogs, SigninLogs | Steps 1-4, 6-7 |
| Above + M365 E5 / MDCA | Above + CloudAppEvents | Steps 1-7 (full coverage) |
| Above + Entra ID P1/P2 | Above + AADServicePrincipalSignInLogs | Steps 1-7 + SP sign-in correlation |
| Above + Office 365 E1+ | Above + OfficeActivity | Steps 1-7 + file/mail access audit |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let TargetUPN = "victim.user@contoso.com";               // User who granted consent
let SuspiciousAppName = "M365 Document Viewer";           // Suspicious app display name
let SuspiciousAppId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"; // Application (client) ID
let AlertTime = datetime(2026-02-22T14:00:00Z);           // Time consent was granted
let LookbackWindow = 24h;                                 // Window to analyze activity
let ForwardWindow = 4h;                                   // Window after consent for data access
let BaselineDays = 30d;                                    // Baseline comparison window
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- App requests `Mail.ReadWrite`, `Mail.Send`, `Files.ReadWrite.All`, or `User.ReadWrite.All` permissions
- App publisher is unverified AND the app was created within the last 7 days
- User who granted consent received a phishing email in the same session
- Multiple users granted consent to the same app within a short time window (mass consent phishing campaign)
- Admin consent was granted (tenant-wide permissions), especially by a non-IT admin user

### Standard Investigation
- App requests read-only permissions (Mail.Read, Files.Read) from an unverified publisher
- User granted consent from an unusual IP address or location
- App was created in a different tenant (multi-tenant app) with no organizational relationship
- Single user consent to an app with moderate permissions

### Likely Benign
- Consent to a well-known, verified publisher app (Microsoft, Google, Zoom, Slack, etc.)
- Consent to an app already approved in Defender for Cloud Apps app governance
- IT admin granting admin consent as part of a documented deployment
- Developer consenting to their own app registration during development/testing

---

## 5. Investigation Steps

### Step 1: Consent Grant Event Analysis

**Purpose:** Identify the exact consent grant event, determine what permissions were granted, who granted consent, from what IP, and whether it was user consent or admin consent. This is the starting point for the entire investigation.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 1: Consent Grant Event Analysis
// Purpose: Identify consent events, permissions granted, actor, IP
// Tables: AuditLogs
// Investigation Step: 1 - Consent Grant Event Analysis
// ============================================================
let TargetUPN = "victim.user@contoso.com";
let SuspiciousAppId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Consent grant events ---
AuditLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where OperationName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment grant to user",
    "Add OAuth2PermissionGrant",
    "Add app role assignment to service principal"
)
| extend
    ConsentingUser = tostring(InitiatedBy.user.userPrincipalName),
    ConsentingIP = tostring(InitiatedBy.user.ipAddress),
    ConsentingApp = tostring(InitiatedBy.app.displayName),
    TargetAppName = tostring(TargetResources[0].displayName),
    TargetAppId = tostring(TargetResources[0].id),
    TargetAppType = tostring(TargetResources[0].type),
    ModifiedProps = TargetResources[0].modifiedProperties
| where ConsentingUser =~ TargetUPN
    or TargetAppId == SuspiciousAppId
    or TargetAppName has SuspiciousAppId
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    PermissionsGranted = case(
        PropertyName == "DelegatedPermissionGrant.Scope", NewValue,
        PropertyName == "AppRole.Value", NewValue,
        PropertyName == "ConsentAction.Permissions", NewValue,
        ""
    ),
    ConsentType = case(
        PropertyName == "ConsentAction.Permissions" and NewValue has "AdminConsent",
            "ADMIN CONSENT (tenant-wide)",
        PropertyName == "ConsentAction.Permissions" and NewValue has "UserConsent",
            "USER CONSENT (single user)",
        PropertyName == "DelegatedPermissionGrant.Scope",
            "DELEGATED PERMISSION",
        PropertyName == "AppRole.Value",
            "APPLICATION PERMISSION",
        "UNKNOWN"
    )
| where isnotempty(PermissionsGranted)
| project
    TimeGenerated,
    OperationName,
    ConsentingUser,
    ConsentingIP,
    TargetAppName,
    TargetAppId,
    ConsentType,
    PermissionsGranted,
    Result
| extend
    RiskLevel = case(
        PermissionsGranted has_any ("Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "User.ReadWrite.All", "Directory.ReadWrite.All"),
            "CRITICAL - High-privilege permissions granted",
        PermissionsGranted has_any ("Mail.Read", "Files.Read", "Calendars.Read", "Contacts.Read"),
            "HIGH - Read access to sensitive data",
        ConsentType == "ADMIN CONSENT (tenant-wide)",
            "CRITICAL - Tenant-wide admin consent",
        "MEDIUM - Standard permissions"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- The `ModifiedProperties` array in AuditLogs contains the permission scopes -- use `mv-expand` to extract each
- `ConsentAction.Permissions` captures both admin and user consent with full scope details
- `DelegatedPermissionGrant.Scope` shows the specific OAuth scopes granted (e.g., "Mail.Read User.Read")

**Tuning Guidance:**
- Admin consent is always more critical than user consent -- admin consent grants permissions tenant-wide
- Watch for `Mail.ReadWrite` + `Mail.Send` combination -- this allows the attacker to read AND send email as the user
- `User.ReadWrite.All` is extremely dangerous -- it allows modifying any user's profile including authentication methods
- If `ConsentingIP` is from a known VPN provider or Tor exit node, escalate immediately

**Expected findings:**
- Complete consent event: who, when, from where, what permissions, what app
- If high-privilege permissions were granted to an unverified app, this confirms a consent phishing attack
- If admin consent was granted, the blast radius is the entire tenant

**Next action:**
- If suspicious permissions found, proceed to Step 2 to profile the app
- Note `ConsentingIP` for correlation with phishing analysis in Step 3
- If admin consent, immediately proceed to containment

---

### Step 2: Application Risk Profiling

**Purpose:** Analyze the OAuth application that received consent. Determine its publisher verification status, when it was created, who registered it, whether it's a multi-tenant app from an external tenant, and what permissions it has been granted across the organization. This step establishes whether the app is legitimate or malicious.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 2: Application Risk Profiling
// Purpose: Profile the OAuth app - publisher, creation, permissions, risk
// Tables: AuditLogs
// Investigation Step: 2 - Application Risk Profiling
// ============================================================
let SuspiciousAppId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let SuspiciousAppName = "M365 Document Viewer";
// --- Full app lifecycle from AuditLogs ---
AuditLogs
| where TimeGenerated >= ago(90d)
| where OperationName in (
    "Add application",
    "Add service principal",
    "Update application",
    "Add owner to application",
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to service principal",
    "Add service principal credentials",
    "Update service principal"
)
| where TargetResources has SuspiciousAppId
    or TargetResources has SuspiciousAppName
| project
    TimeGenerated,
    OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    TargetAppName = tostring(TargetResources[0].displayName),
    TargetAppId = tostring(TargetResources[0].id),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    EventCategory = case(
        OperationName has "Add application" or OperationName has "Add service principal",
            "CREATION - App registered",
        OperationName has "owner",
            "OWNERSHIP - Owner added",
        OperationName has "Consent" or OperationName has "permission" or OperationName has "role",
            "CONSENT - Permission grant",
        OperationName has "credentials",
            "CREDENTIAL - Secret/cert added",
        OperationName has "Update",
            "MODIFICATION - Configuration changed",
        "OTHER"
    )
| extend
    AppRiskIndicator = case(
        EventCategory == "CREATION" and TimeGenerated >= ago(7d),
            "HIGH RISK - App created within last 7 days",
        EventCategory == "CONSENT" and ModifiedProperties has "Mail.ReadWrite",
            "HIGH RISK - Mail write access granted",
        EventCategory == "CONSENT" and ModifiedProperties has "Directory.ReadWrite",
            "HIGH RISK - Directory write access",
        EventCategory == "CREDENTIAL" and InitiatedByUser !has "@contoso.com",
            "HIGH RISK - External user adding credentials",
        EventCategory == "CONSENT" and ModifiedProperties has "AllSites.FullControl",
            "HIGH RISK - SharePoint full control",
        "REVIEW - Requires context"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- Scanning 90 days captures the full lifecycle of recently created malicious apps
- Multi-tenant apps from external tenants will show `Add service principal` when first consented in your tenant
- The gap between `Add application` and first `Consent to application` reveals if the app was purpose-built for attack

**Tuning Guidance:**
- If the app was created and consented within the same day, this is highly suspicious
- If `InitiatedByUser` for `Add application` is from an external tenant, the app was created by an outsider
- Cross-reference `InitiatedByIP` across creation and consent events -- matching IPs suggest coordinated attack
- If `ModifiedProperties` shows publisher domain as unverified or absent, treat as high risk

**Expected findings:**
- Full app lifecycle: creation date, owners, permission grants, credential additions
- If the app was recently created, externally owned, and immediately consented with high privileges, this confirms consent phishing
- If the app is from a verified publisher and has been consented by multiple users over time, likely benign

**Next action:**
- If app is confirmed malicious, check Step 3 for the phishing vector
- If app creation date is very recent, check if the app creator is compromised
- Note the app creation IP and owner for incident report

---

### Step 3: Phishing Correlation & User Context

**Purpose:** Determine if the user who granted consent was phished. Correlate the consent event with sign-in logs to check the authentication context, and with email events to identify phishing emails containing OAuth consent URLs. This step establishes the initial access vector.

**Data needed:** SigninLogs, CloudAppEvents

```kql
// ============================================================
// QUERY 3: Phishing Correlation & User Context
// Purpose: Correlate consent with user sign-in context and phishing indicators
// Tables: SigninLogs
// Investigation Step: 3 - Phishing Correlation & User Context
// ============================================================
let TargetUPN = "victim.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- User sign-in activity around consent time ---
SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 2h)
| where UserPrincipalName =~ TargetUPN
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    AppId,
    IPAddress,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    DeviceDetail = strcat(tostring(DeviceDetail.operatingSystem), " / ", tostring(DeviceDetail.browser)),
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    MfaDetail = tostring(AuthenticationDetails),
    ResourceDisplayName,
    CorrelationId
| extend
    SignInOutcome = case(
        ResultType == "0", "SUCCESS",
        ResultType == "50074", "MFA REQUIRED",
        ResultType == "53003", "BLOCKED BY CA",
        ResultType == "50126", "WRONG PASSWORD",
        strcat("FAILURE - ", ResultType)
    ),
    IsConsentRelated = AppDisplayName has "consent" or ResourceDisplayName has "consent"
        or AppDisplayName has "authorization" or AppDisplayName =~ "Microsoft Graph"
        or AppDisplayName =~ "Microsoft Authentication Broker",
    SignInRisk = case(
        RiskLevelDuringSignIn in ("high", "medium"), "RISKY SIGN-IN DETECTED",
        RiskLevelAggregated in ("high", "medium"), "USER RISK ELEVATED",
        "No risk detected"
    )
| extend
    Suspicion = case(
        // Sign-in around consent time from unusual location
        ResultType == "0" and RiskLevelDuringSignIn in ("high", "medium"),
            "HIGH - Successful risky sign-in near consent time",
        // Sign-in from new device near consent time
        ResultType == "0" and TimeGenerated between (AlertTime - 1h .. AlertTime + 1h),
            "REVIEW - Sign-in within consent window",
        "LOW"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- The consent event in AuditLogs and the sign-in in SigninLogs may share a `CorrelationId` -- use this for precise matching
- `AppDisplayName` for consent flows often shows "Microsoft Authentication Broker" or "My Apps"
- `RiskLevelDuringSignIn` from Identity Protection captures real-time risk assessment at authentication time

**Tuning Guidance:**
- If the user signed in from a known corporate IP and device, the consent may be user error (shadow IT) rather than phishing
- If there are multiple failed sign-in attempts followed by a success, the user account may also be compromised
- Check if the sign-in used "Basic authentication" or "Legacy authentication" -- this bypasses MFA
- A risky sign-in (unfamiliar location, anonymous IP) immediately before consent is strong evidence of phishing

**Expected findings:**
- Sign-in context around consent: IP, location, device, risk level
- Correlation between phishing email arrival, user sign-in, and consent grant
- If sign-in was risky AND consent was to a high-privilege app, confirm consent phishing

**Next action:**
- If phishing is confirmed, identify the phishing campaign scope (Step 6)
- If user signed in from corporate IP with clean device, investigate as potential shadow IT
- Use the sign-in IP to search for other users who authenticated from the same IP

---

### Step 4: Baseline Comparison - Establish Normal Consent Behavior

**Purpose:** Determine if the consent event is anomalous by comparing it against the user's and organization's historical consent patterns. Has this user granted consent before? How does this app compare to previously consented apps? This establishes whether the consent is a deviation from normal behavior.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 4: Baseline Comparison - Normal Consent Behavior
// Purpose: Compare consent event against user and org baseline
// Tables: AuditLogs
// Investigation Step: 4 - Baseline Comparison
// ============================================================
let TargetUPN = "victim.user@contoso.com";
let SuspiciousAppName = "M365 Document Viewer";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 30d;
// --- User's historical consent behavior ---
let UserConsentBaseline = AuditLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| where InitiatedBy has TargetUPN
| summarize
    TotalConsents = count(),
    UniqueApps = dcount(tostring(TargetResources[0].displayName)),
    ConsentedApps = make_set(tostring(TargetResources[0].displayName), 20),
    ConsentIPs = make_set(tostring(InitiatedBy.user.ipAddress), 10),
    FirstConsent = min(TimeGenerated),
    LastConsent = max(TimeGenerated)
| extend EntityType = "USER_BASELINE";
// --- Org-wide consent behavior ---
let OrgConsentBaseline = AuditLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| summarize
    TotalConsents = count(),
    UniqueApps = dcount(tostring(TargetResources[0].displayName)),
    UniqueUsers = dcount(tostring(InitiatedBy.user.userPrincipalName)),
    TopApps = make_set(tostring(TargetResources[0].displayName), 50),
    AvgConsentsPerUser = todouble(count()) / todouble(dcount(tostring(InitiatedBy.user.userPrincipalName)))
| extend EntityType = "ORG_BASELINE";
// --- Check if the suspicious app has been seen before ---
let AppPreviouslySeen = AuditLogs
| where TimeGenerated between (AlertTime - 365d .. AlertTime)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| where TargetResources has SuspiciousAppName
| summarize
    PreviousConsents = count(),
    PreviousUsers = make_set(tostring(InitiatedBy.user.userPrincipalName), 20),
    FirstSeenInOrg = min(TimeGenerated)
| extend EntityType = "APP_HISTORY";
// --- Compare current consent against baselines ---
UserConsentBaseline
| extend
    Assessment = case(
        TotalConsents == 0, "ANOMALOUS - User has NEVER granted consent before",
        not(ConsentedApps has SuspiciousAppName) and UniqueApps < 3,
            "SUSPICIOUS - User rarely consents, and this app is new",
        not(ConsentedApps has SuspiciousAppName),
            "REVIEW - App not in user's consent history",
        "WITHIN BASELINE - User has consented to this app before"
    )
| project EntityType, TotalConsents, UniqueApps, ConsentedApps, Assessment
```

**Performance Notes:**
- The 30-day baseline captures typical consent frequency; extend to 90 days for users who rarely consent
- `make_set` with limit of 50 captures enough app names for comparison without performance impact
- Splitting into user vs. org baseline provides both individual and organizational context

**Tuning Guidance:**
- If the user has never consented to any app before, ANY consent is anomalous
- If the org averages < 5 consents per user per month, a sudden burst of consents is suspicious
- If the suspicious app has been seen in the org before with other users, check if those users were also phished
- Cross-reference `ConsentIPs` -- if the user always consents from corporate IP but this time used a residential IP, escalate

**Expected findings:**
- User consent history: frequency, apps, IPs used
- Whether the suspicious app has ever been consented to before in the organization
- Whether this consent is a statistical outlier from both user and org perspective

**Next action:**
- If consent is anomalous for this user, proceed to Step 5 to check what data the app accessed
- If the app was never seen in the org, treat as high risk
- If the app was previously consented by other users, check if those consents are also malicious (Step 6)

---

### Step 5: Data Access Audit via Consented App

**Purpose:** Determine what data the malicious application actually accessed after consent was granted. Track Microsoft Graph API calls, email reads, file downloads, and any other data access. This establishes the scope of data exfiltration and guides evidence collection.

**Data needed:** CloudAppEvents, AADServicePrincipalSignInLogs

```kql
// ============================================================
// QUERY 5: Data Access Audit via Consented App
// Purpose: Track what data the app accessed after consent was granted
// Tables: CloudAppEvents
// Investigation Step: 5 - Data Access Audit via Consented App
// ============================================================
let SuspiciousAppId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let SuspiciousAppName = "M365 Document Viewer";
let TargetUPN = "victim.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 4h;
// --- App activity in CloudAppEvents ---
CloudAppEvents
| where TimeGenerated between (AlertTime .. AlertTime + 72h)
| where Application has SuspiciousAppName
    or AccountId has SuspiciousAppId
    or RawEventData has SuspiciousAppId
| project
    TimeGenerated,
    ActionType,
    Application,
    AccountDisplayName,
    AccountId,
    IPAddress,
    City,
    CountryCode,
    ObjectName,
    ObjectType,
    ActivityObjects = tostring(ActivityObjects),
    RawEventData = tostring(RawEventData)
| extend
    DataAccessType = case(
        ActionType has_any ("MailItemsAccessed", "MailItemRead", "ReadMail"),
            "EMAIL - Mail items accessed",
        ActionType has_any ("FileDownloaded", "FileAccessed", "FilePreviewed"),
            "FILE - Files accessed/downloaded",
        ActionType has_any ("Send", "MailItemSent", "SendMail"),
            "EMAIL SEND - Sent email as user",
        ActionType has_any ("FolderBind", "FolderAccess"),
            "FOLDER - Mailbox folder access",
        ActionType has_any ("ContactAccessed", "ContactRead"),
            "CONTACTS - Contact list accessed",
        ActionType has_any ("CalendarItemRead", "CalendarItemAccess"),
            "CALENDAR - Calendar accessed",
        ActionType has_any ("UserRead", "UserList"),
            "DIRECTORY - User enumeration",
        ActionType has_any ("SearchQuery"),
            "SEARCH - Search query executed",
        strcat("OTHER - ", ActionType)
    )
| summarize
    EventCount = count(),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    UniqueActions = make_set(ActionType, 20),
    SampleObjects = make_set(ObjectName, 10),
    AccessIPs = make_set(IPAddress, 10)
    by DataAccessType
| extend
    ExfiltrationRisk = case(
        DataAccessType startswith "EMAIL" and EventCount > 50,
            "CRITICAL - Mass email access (likely exfiltration)",
        DataAccessType startswith "FILE" and EventCount > 20,
            "CRITICAL - Mass file access (likely exfiltration)",
        DataAccessType startswith "EMAIL SEND",
            "HIGH - App sent emails as user (potential BEC)",
        DataAccessType startswith "DIRECTORY",
            "HIGH - User/directory enumeration (reconnaissance)",
        DataAccessType startswith "CONTACTS",
            "HIGH - Contact list harvested",
        DataAccessType startswith "SEARCH",
            "MEDIUM - Search queries executed (targeted exfiltration)",
        "REVIEW - Activity requires context"
    )
| sort by EventCount desc
```

**Performance Notes:**
- Extend the time window to 72h after consent -- attackers may wait before accessing data to avoid detection
- `RawEventData` may contain the application client ID even when `Application` field doesn't match
- `CloudAppEvents` is only available with Microsoft 365 E5 or Defender for Cloud Apps license

**Tuning Guidance:**
- `MailItemsAccessed` events > 100 in a short period is almost always exfiltration
- `FileDownloaded` with `.pst`, `.xlsx`, or archive files indicates targeted data collection
- If the app sent emails (`MailItemSent`), check the recipients -- this could be BEC or internal phishing
- If no `CloudAppEvents` data is available, fall back to `OfficeActivity` table (see alternative query below)

**Alternative query for OfficeActivity (if CloudAppEvents unavailable):**

```kql
// --- Fallback: OfficeActivity for data access ---
let SuspiciousAppId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let AlertTime = datetime(2026-02-22T14:00:00Z);
OfficeActivity
| where TimeGenerated between (AlertTime .. AlertTime + 72h)
| where ClientAppId == SuspiciousAppId
    or ApplicationId == SuspiciousAppId
| project
    TimeGenerated,
    Operation,
    UserId,
    ClientIP,
    ResultStatus,
    ItemType = OfficeObjectId,
    Workload
| extend
    AccessCategory = case(
        Workload == "Exchange" and Operation has_any ("MailItemsAccessed", "Send"),
            "EMAIL ACCESS/SEND",
        Workload == "SharePoint" and Operation has_any ("FileDownloaded", "FileAccessed"),
            "FILE ACCESS",
        Workload == "OneDrive" and Operation has_any ("FileDownloaded", "FileAccessed"),
            "ONEDRIVE ACCESS",
        strcat("OTHER - ", Workload, " / ", Operation)
    )
| summarize
    Count = count(),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    Operations = make_set(Operation, 20)
    by AccessCategory, UserId
| sort by Count desc
```

**Expected findings:**
- Complete data access timeline: what types of data were accessed, volume, timing
- If mass email access or file downloads occurred, this confirms active exfiltration
- If the app sent emails, check for BEC or internal phishing propagation

**Next action:**
- If exfiltration confirmed, proceed immediately to containment
- If email sending detected, investigate recipients for secondary compromise
- If data access is minimal, the attack may still be in progress -- monitor closely

---

### Step 6: Blast Radius - Multi-User Consent Assessment

**Purpose:** Determine how many users in the organization granted consent to the same malicious application. Consent phishing campaigns typically target multiple users simultaneously. Understanding the full blast radius is critical for complete remediation.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 6: Blast Radius - Multi-User Consent Assessment
// Purpose: Find all users who consented to the suspicious app
// Tables: AuditLogs
// Investigation Step: 6 - Blast Radius Assessment
// ============================================================
let SuspiciousAppId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let SuspiciousAppName = "M365 Document Viewer";
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- All consent events for this app across the org ---
AuditLogs
| where TimeGenerated >= ago(90d)
| where OperationName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment grant to user"
)
| where TargetResources has SuspiciousAppId
    or TargetResources has SuspiciousAppName
| project
    TimeGenerated,
    ConsentingUser = tostring(InitiatedBy.user.userPrincipalName),
    ConsentingIP = tostring(InitiatedBy.user.ipAddress),
    TargetAppName = tostring(TargetResources[0].displayName),
    TargetAppId = tostring(TargetResources[0].id),
    OperationName,
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| summarize
    ConsentTime = min(TimeGenerated),
    LatestActivity = max(TimeGenerated),
    ConsentCount = count(),
    ConsentIPs = make_set(ConsentingIP, 10),
    PermissionGrants = make_set(OperationName, 5)
    by ConsentingUser, TargetAppName
| extend
    TimeSinceFirstConsent = datetime_diff("hour", now(), ConsentTime),
    ConsentRisk = case(
        ConsentCount > 1,
            "HIGH - Multiple consent grants (possible re-authorization or admin consent)",
        array_length(ConsentIPs) > 1,
            "HIGH - Consent from multiple IPs (possible account takeover)",
        "STANDARD - Single consent event"
    )
| sort by ConsentTime asc
| extend
    CampaignAssessment = case(
        // If found > 5 users, this is a mass campaign
        1 == 1, "Evaluate total user count in results below",
        ""
    )
```

**Post-query analysis:**

```kql
// --- Campaign scope summary ---
let SuspiciousAppId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let SuspiciousAppName = "M365 Document Viewer";
AuditLogs
| where TimeGenerated >= ago(90d)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| where TargetResources has SuspiciousAppId or TargetResources has SuspiciousAppName
| summarize
    TotalConsentEvents = count(),
    UniqueUsers = dcount(tostring(InitiatedBy.user.userPrincipalName)),
    AffectedUsers = make_set(tostring(InitiatedBy.user.userPrincipalName), 50),
    ConsentTimeSpan = max(TimeGenerated) - min(TimeGenerated),
    FirstConsent = min(TimeGenerated),
    LastConsent = max(TimeGenerated),
    UniqueIPs = dcount(tostring(InitiatedBy.user.ipAddress))
| extend
    CampaignScope = case(
        UniqueUsers > 10, "MASS CAMPAIGN - 10+ users affected",
        UniqueUsers > 5, "TARGETED CAMPAIGN - 5-10 users affected",
        UniqueUsers > 1, "LIMITED CAMPAIGN - 2-4 users affected",
        "SINGLE TARGET - 1 user affected"
    ),
    CampaignVelocity = case(
        ConsentTimeSpan < 1h and UniqueUsers > 3,
            "RAPID - Multiple consents within 1 hour (active phishing campaign)",
        ConsentTimeSpan < 24h and UniqueUsers > 1,
            "FAST - Multiple consents within 24 hours",
        "SLOW - Consents spread over time"
    )
```

**Performance Notes:**
- Scanning 90 days captures consent campaigns that may have started weeks before detection
- `make_set` with limit of 50 captures enough affected users for initial response
- The campaign velocity (how quickly consents occurred) indicates whether this is an active campaign

**Tuning Guidance:**
- If `UniqueUsers > 5` within the same hour, this is an active consent phishing campaign -- immediate SOC-wide response required
- Check if affected users share characteristics: same department, role, manager, location
- If all consent IPs are from the same subnet, the phishing may have been delivered internally
- Cross-reference affected users with email phishing data to identify the initial delivery vector

**Expected findings:**
- Total number of users who consented to the malicious app
- Campaign timeline: first consent to last consent
- Whether this is a targeted attack (1-2 users) or mass phishing campaign (10+ users)

**Next action:**
- For each affected user, repeat Steps 1 and 5 (consent details and data access audit)
- If mass campaign, escalate to SOC leadership for coordinated response
- Begin containment for ALL affected users simultaneously

---

### Step 7: Org-Wide Risky OAuth App Sweep

**Purpose:** Scan the entire organization for other potentially malicious OAuth applications. The same threat actor may have deployed multiple consent phishing apps, or there may be dormant malicious apps from previous campaigns that were never detected.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 7: Org-Wide Risky OAuth App Sweep
// Purpose: Find all potentially risky OAuth apps across the org
// Tables: AuditLogs
// Investigation Step: 7 - Org-Wide Risky OAuth App Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- All consent grants in the last 30 days ---
let AllConsents = AuditLogs
| where TimeGenerated >= ago(30d)
| where OperationName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to service principal"
)
| project
    TimeGenerated,
    ConsentingUser = tostring(InitiatedBy.user.userPrincipalName),
    ConsentingIP = tostring(InitiatedBy.user.ipAddress),
    AppName = tostring(TargetResources[0].displayName),
    AppId = tostring(TargetResources[0].id),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties),
    OperationName;
// --- App creation events for cross-reference ---
let RecentApps = AuditLogs
| where TimeGenerated >= ago(30d)
| where OperationName in ("Add application", "Add service principal")
| project
    AppCreatedTime = TimeGenerated,
    AppName = tostring(TargetResources[0].displayName),
    AppId = tostring(TargetResources[0].id),
    CreatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    CreatedByIP = tostring(InitiatedBy.user.ipAddress);
// --- Combine consent and creation data ---
AllConsents
| summarize
    ConsentCount = count(),
    UniqueUsers = dcount(ConsentingUser),
    ConsentingUsers = make_set(ConsentingUser, 20),
    ConsentIPs = make_set(ConsentingIP, 10),
    FirstConsent = min(TimeGenerated),
    LastConsent = max(TimeGenerated),
    Permissions = make_set(OperationName, 5),
    HasHighPriv = countif(ModifiedProperties has_any (
        "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All",
        "User.ReadWrite.All", "Directory.ReadWrite.All",
        "AllSites.FullControl", "full_access_as_app"
    ))
    by AppName, AppId
| join kind=leftouter RecentApps on AppName, AppId
| extend
    AppAge = datetime_diff("day", now(), AppCreatedTime),
    RiskScore = case(
        // Critical: High-priv permissions + recently created + multiple users
        HasHighPriv > 0 and AppAge < 7 and UniqueUsers > 1,
            "CRITICAL - New app with high privileges consented by multiple users",
        // High: High-priv permissions + recently created
        HasHighPriv > 0 and AppAge < 30,
            "HIGH - Recently created app with high-privilege permissions",
        // High: Multiple users consenting rapidly
        UniqueUsers > 5 and datetime_diff("hour", LastConsent, FirstConsent) < 24,
            "HIGH - Rapid multi-user consent (possible campaign)",
        // Medium: High-priv with single user
        HasHighPriv > 0,
            "MEDIUM - High-privilege permissions (review publisher)",
        // Medium: External app creation
        isnotempty(CreatedByUser) and CreatedByUser !has "@contoso.com",
            "MEDIUM - App created by external user",
        "LOW - Standard OAuth app"
    )
| where RiskScore !startswith "LOW"
| project
    AppName,
    AppId,
    RiskScore,
    UniqueUsers,
    ConsentingUsers,
    HasHighPrivPermissions = HasHighPriv > 0,
    AppAge,
    CreatedByUser,
    FirstConsent,
    LastConsent
| sort by RiskScore asc, UniqueUsers desc
```

**Performance Notes:**
- This query scans all consent and app creation events in the last 30 days
- The `has_any` operator for high-privilege permission detection is efficient for this pattern
- Join with `RecentApps` may not find matches for multi-tenant apps created in external tenants

**Tuning Guidance:**
- Adjust `@contoso.com` to your organization's domain for external user detection
- The `has_any` list of high-privilege permissions should include any custom permissions relevant to your org
- Consider extending the scan period to 90 days for thorough sweeps after a confirmed incident
- Whitelist known-good apps to reduce noise in the results

**Expected findings:**
- All risky OAuth apps in the organization ranked by risk score
- Apps that were recently created AND consented with high privileges are primary suspects
- Multi-user consent patterns that indicate active phishing campaigns

**Next action:**
- For each CRITICAL or HIGH risk app, perform a full investigation (Steps 1-6)
- Block identified malicious apps at the tenant level
- Review and update the organization's consent policy (restrict user consent, require admin consent)

---

## 6. Containment Playbook

### Immediate Actions (First 30 Minutes)

| Priority | Action | Command/Location | Who |
|---|---|---|---|
| P0 | Revoke consent grant | Entra Portal > Enterprise Apps > [App] > Properties > Delete OR `Remove-MgServicePrincipal` | Cloud App Admin |
| P0 | Revoke all refresh tokens for affected users | `Revoke-MgUserSignInSession -UserId [UPN]` | Security Admin |
| P0 | Block the malicious app tenant-wide | Entra Portal > Enterprise Apps > [App] > Properties > "Enabled for users to sign in" = No | Cloud App Admin |
| P1 | Disable the app registration (if in your tenant) | Entra Portal > App Registrations > [App] > Properties > Enabled = No | Application Admin |
| P1 | Reset passwords for affected users | Entra Portal > Users > [User] > Reset Password | Helpdesk Admin |
| P1 | Re-register MFA for affected users | Entra Portal > Users > [User] > Authentication methods > Require re-register MFA | Auth Admin |

### Secondary Actions (First 4 Hours)

| Priority | Action | Details |
|---|---|---|
| P2 | Review all OAuth apps consented by affected users | Remove any other suspicious consents |
| P2 | Block consent phishing URLs in email gateway | Add OAuth consent URLs to block list |
| P2 | Search for and quarantine phishing emails | Use Defender for Office 365 Threat Explorer |
| P2 | Update Conditional Access policies | Require admin consent for all OAuth apps |
| P3 | Enable app governance in Defender for Cloud Apps | Automated OAuth app risk monitoring |
| P3 | Configure consent workflow | Require admin approval for user consent requests |
| P3 | Review and update app consent policies | Restrict to verified publishers only |

### Consent Revocation Commands

```powershell
# Revoke consent using Microsoft Graph PowerShell
# Connect with appropriate permissions
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Remove the enterprise app (service principal) - this revokes all consent
$SPId = "SERVICE_PRINCIPAL_OBJECT_ID"
Remove-MgServicePrincipal -ServicePrincipalId $SPId

# Revoke all user sessions
$UserId = "victim.user@contoso.com"
Revoke-MgUserSignInSession -UserId $UserId

# Block the app from being consented again
# Set the app to disabled
Update-MgServicePrincipal -ServicePrincipalId $SPId -AccountEnabled:$false
```

---

## 7. Evidence Collection Checklist

| Evidence | Source | Retention | Priority |
|---|---|---|---|
| Consent grant event (AuditLogs) | Microsoft Sentinel | Export query results | Critical |
| App registration details | Entra Portal > App Registrations | Screenshot + JSON export | Critical |
| Granted permissions list | Entra Portal > Enterprise Apps > Permissions | Screenshot | Critical |
| Phishing email (if identified) | Defender for Office 365 | Export .eml | Critical |
| Data access logs (CloudAppEvents) | Microsoft Sentinel | Export query results | Critical |
| User sign-in logs around consent | Microsoft Sentinel | Export query results | High |
| Affected user list | Query results from Step 6 | Export CSV | High |
| App creator audit trail | AuditLogs export | Export query results | High |
| OAuth consent URL from phishing | Email headers / URL analysis | Screenshot + archived URL | Medium |
| Defender for Cloud Apps app risk report | MDCA Portal | PDF export | Medium |

---

## 8. Escalation Criteria

### Escalate to Incident Commander When:
- Admin consent was granted (tenant-wide permission exposure)
- More than 5 users consented to the same malicious app (active campaign)
- App accessed executive or finance mailboxes
- App sent emails as the user (BEC / downstream phishing)
- Data exfiltration confirmed (mass email or file access)

### Escalate to Legal/Privacy When:
- Personal or customer data was accessed via the consented app
- Email containing financial, legal, or M&A information was exfiltrated
- Regulatory notification requirements may apply (GDPR, HIPAA, PCI)

### Escalate to Microsoft When:
- The malicious app is a multi-tenant app that needs to be blocked globally
- Publisher verification was fraudulently obtained
- The consent phishing campaign uses Microsoft infrastructure (Azure tenant)
- Report the app via: Entra Portal > Enterprise Apps > Report app, or via Microsoft Security Response Center

---

## 9. False Positive Documentation

| Scenario | How to Verify | Action |
|---|---|---|
| Legitimate SaaS onboarding | Verify publisher is verified in Entra, check IT approval records | Document as approved, add to allowlist |
| IT-approved app requiring user consent | Check with IT admin, verify app is in approved app catalog | Configure pre-consent for the app |
| Developer testing with custom app | Verify the developer created the app in a dev/test tenant | Restrict consent to admin-only in production |
| App update requiring re-consent | Check app version history, verify publisher | Review new permissions, approve if appropriate |
| User installing browser extension with OAuth | Verify extension is from a trusted source | Educate user, evaluate extension risk |

---

## 10. MITRE ATT&CK Mapping

| Technique | ID | Tactic | How Detected |
|---|---|---|---|
| Steal Application Access Token | T1528 | Credential Access | Consent grant event in AuditLogs for high-privilege permissions |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Defense Evasion | App using delegated tokens to access data in CloudAppEvents |
| Phishing: Spearphishing Link | T1566.002 | Initial Access | OAuth consent URL in phishing email correlated with consent event |
| Account Manipulation | T1098 | Persistence | Consent grant creates persistent OAuth token surviving password reset |
| Email Collection: Remote Email Collection | T1114.002 | Collection | App accessing Mail.Read/Mail.ReadWrite after consent |
| Data from Information Repositories | T1213 | Collection | App accessing SharePoint/OneDrive files after consent |

---

## 11. Query Summary

| # | Query | Table | Purpose |
|---|---|---|---|
| 1 | Consent Grant Event Analysis | AuditLogs | Identify consent events, permissions, actor, risk level |
| 2 | Application Risk Profiling | AuditLogs | Profile the OAuth app lifecycle, publisher, permissions |
| 3 | Phishing Correlation & User Context | SigninLogs | Correlate consent with sign-in risk and phishing |
| 4 | Baseline Comparison | AuditLogs | Compare consent against user/org historical behavior |
| 5 | Data Access Audit | CloudAppEvents / OfficeActivity | Track data accessed by the consented app |
| 6 | Blast Radius Assessment | AuditLogs | Find all users who consented to the malicious app |
| 7 | Org-Wide Risky App Sweep | AuditLogs | Scan for other risky OAuth apps across the org |

---

## Appendix A: Datatable Tests

### Test 1: Consent Grant Detection

```kql
// ============================================================
// TEST 1: Consent Grant Detection
// Validates: Query 1 - Detect consent events and classify risk
// Expected: M365 Document Viewer = "CRITICAL" (Mail.ReadWrite + Mail.Send)
//           Contoso HR Portal = "MEDIUM" (standard permissions)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Malicious app: M365 Document Viewer with high-priv consent ---
    datetime(2026-02-22T14:00:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"victim.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"M365 Document Viewer","id":"app-malicious-001","type":"ServicePrincipal",
            "modifiedProperties":[
                {"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"[{\"Scope\":\"Mail.ReadWrite Mail.Send Files.ReadWrite.All User.Read\",\"ClientId\":\"app-malicious-001\",\"ConsentType\":\"UserConsent\"}]"}
            ]}]),
        "success",
    // --- Legitimate app: Contoso HR Portal with standard consent ---
    datetime(2026-02-22T10:00:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"hr.admin@contoso.com","ipAddress":"10.0.0.15"}}),
        dynamic([{"displayName":"Contoso HR Portal","id":"app-legit-001","type":"ServicePrincipal",
            "modifiedProperties":[
                {"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"[{\"Scope\":\"User.Read profile openid\",\"ClientId\":\"app-legit-001\",\"ConsentType\":\"UserConsent\"}]"}
            ]}]),
        "success",
    // --- Admin consent event: Tenant-wide permission ---
    datetime(2026-02-22T15:00:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"global.admin@contoso.com","ipAddress":"10.0.0.1"}}),
        dynamic([{"displayName":"Suspicious Analytics Tool","id":"app-malicious-002","type":"ServicePrincipal",
            "modifiedProperties":[
                {"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"[{\"Scope\":\"Directory.ReadWrite.All User.ReadWrite.All\",\"ClientId\":\"app-malicious-002\",\"ConsentType\":\"AdminConsent\"}]"}
            ]}]),
        "success"
];
// --- Run detection query ---
TestAuditLogs
| where OperationName in (
    "Consent to application",
    "Add delegated permission grant"
)
| extend
    ConsentingUser = tostring(InitiatedBy.user.userPrincipalName),
    ConsentingIP = tostring(InitiatedBy.user.ipAddress),
    TargetAppName = tostring(TargetResources[0].displayName),
    TargetAppId = tostring(TargetResources[0].id),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    PermissionsGranted = case(
        PropertyName == "ConsentAction.Permissions", NewValue,
        ""
    ),
    ConsentType = case(
        PropertyName == "ConsentAction.Permissions" and NewValue has "AdminConsent",
            "ADMIN CONSENT (tenant-wide)",
        PropertyName == "ConsentAction.Permissions" and NewValue has "UserConsent",
            "USER CONSENT (single user)",
        "UNKNOWN"
    )
| where isnotempty(PermissionsGranted)
| extend
    RiskLevel = case(
        PermissionsGranted has_any ("Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All"),
            "CRITICAL - High-privilege permissions granted",
        ConsentType == "ADMIN CONSENT (tenant-wide)",
            "CRITICAL - Tenant-wide admin consent",
        PermissionsGranted has_any ("Mail.Read", "Files.Read", "Calendars.Read"),
            "HIGH - Read access to sensitive data",
        "MEDIUM - Standard permissions"
    )
| project ConsentingUser, TargetAppName, ConsentType, RiskLevel, PermissionsGranted
// Expected: M365 Document Viewer = "CRITICAL - High-privilege permissions granted"
// Expected: Contoso HR Portal = "MEDIUM - Standard permissions"
// Expected: Suspicious Analytics Tool = "CRITICAL - Tenant-wide admin consent"
```

### Test 2: Application Risk Profiling

```kql
// ============================================================
// TEST 2: Application Risk Profiling
// Validates: Query 2 - Profile app lifecycle and assign risk indicators
// Expected: M365 Document Viewer = "HIGH RISK - App created within last 7 days"
//           Contoso Internal App = "REVIEW - Requires context"
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Malicious app: Recently created ---
    datetime(2026-02-21T08:00:00Z), "Add application",
        dynamic({"user":{"userPrincipalName":"attacker@evil-tenant.com","ipAddress":"203.0.113.99"}}),
        dynamic([{"displayName":"M365 Document Viewer","id":"app-malicious-001","type":"Application",
            "modifiedProperties":[]}]),
        "success",
    datetime(2026-02-21T08:05:00Z), "Add service principal",
        dynamic({"user":{"userPrincipalName":"attacker@evil-tenant.com","ipAddress":"203.0.113.99"}}),
        dynamic([{"displayName":"M365 Document Viewer","id":"app-malicious-001","type":"ServicePrincipal",
            "modifiedProperties":[]}]),
        "success",
    datetime(2026-02-22T14:00:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"victim.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"M365 Document Viewer","id":"app-malicious-001","type":"ServicePrincipal",
            "modifiedProperties":[{"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"Mail.ReadWrite"}]}]),
        "success",
    // --- Legitimate app: Created months ago ---
    datetime(2025-11-01T10:00:00Z), "Add application",
        dynamic({"user":{"userPrincipalName":"devops.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"displayName":"Contoso Internal App","id":"app-legit-002","type":"Application",
            "modifiedProperties":[]}]),
        "success",
    datetime(2025-11-01T10:05:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"devops.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"displayName":"Contoso Internal App","id":"app-legit-002","type":"ServicePrincipal",
            "modifiedProperties":[{"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"User.Read"}]}]),
        "success"
];
// --- Run app profiling ---
TestAuditLogs
| where OperationName in (
    "Add application", "Add service principal", "Consent to application",
    "Add delegated permission grant", "Update application"
)
| project
    TimeGenerated,
    OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    TargetAppName = tostring(TargetResources[0].displayName),
    TargetAppId = tostring(TargetResources[0].id),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    EventCategory = case(
        OperationName has "Add application" or OperationName has "Add service principal",
            "CREATION - App registered",
        OperationName has "Consent" or OperationName has "permission",
            "CONSENT - Permission grant",
        "OTHER"
    ),
    AppRiskIndicator = case(
        OperationName has "Add application" and TimeGenerated >= ago(7d),
            "HIGH RISK - App created within last 7 days",
        OperationName has "Consent" and ModifiedProperties has "Mail.ReadWrite",
            "HIGH RISK - Mail write access granted",
        OperationName has "Add application" and InitiatedByUser !has "@contoso.com",
            "HIGH RISK - External user created app",
        "REVIEW - Requires context"
    )
| sort by TargetAppName asc, TimeGenerated asc
// Expected: M365 Document Viewer creation = "HIGH RISK - App created within last 7 days"
// Expected: M365 Document Viewer consent = "HIGH RISK - Mail write access granted"
// Expected: Contoso Internal App = "REVIEW - Requires context" (created months ago, low permissions)
```

### Test 3: Baseline Comparison

```kql
// ============================================================
// TEST 3: Baseline Comparison
// Validates: Query 4 - Compare consent against user baseline
// Expected: victim.user = "ANOMALOUS - User has NEVER granted consent before"
//           regular.user = "WITHIN BASELINE" (frequently consents)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- regular.user: Has consented to 3 apps in the past ---
    datetime(2026-01-15T10:00:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"regular.user@contoso.com","ipAddress":"10.0.0.20"}}),
        dynamic([{"displayName":"Zoom","id":"zoom-app","type":"ServicePrincipal"}]),
        "success",
    datetime(2026-02-01T11:00:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"regular.user@contoso.com","ipAddress":"10.0.0.20"}}),
        dynamic([{"displayName":"Slack","id":"slack-app","type":"ServicePrincipal"}]),
        "success",
    datetime(2026-02-10T14:00:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"regular.user@contoso.com","ipAddress":"10.0.0.20"}}),
        dynamic([{"displayName":"Grammarly","id":"grammarly-app","type":"ServicePrincipal"}]),
        "success",
    // --- victim.user: NEW consent to suspicious app (no prior history) ---
    datetime(2026-02-22T14:00:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"victim.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"M365 Document Viewer","id":"app-malicious-001","type":"ServicePrincipal"}]),
        "success",
    // --- regular.user: Also consents to suspicious app ---
    datetime(2026-02-22T14:30:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"regular.user@contoso.com","ipAddress":"10.0.0.20"}}),
        dynamic([{"displayName":"M365 Document Viewer","id":"app-malicious-001","type":"ServicePrincipal"}]),
        "success"
];
let SuspiciousAppName = "M365 Document Viewer";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 30d;
// --- Per-user consent baseline ---
TestAuditLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
| where OperationName == "Consent to application"
| summarize
    TotalConsents = count(),
    UniqueApps = dcount(tostring(TargetResources[0].displayName)),
    ConsentedApps = make_set(tostring(TargetResources[0].displayName), 20)
    by User = tostring(InitiatedBy.user.userPrincipalName)
| extend
    Assessment = case(
        TotalConsents == 0, "ANOMALOUS - User has NEVER granted consent before",
        not(ConsentedApps has SuspiciousAppName) and UniqueApps < 3,
            "SUSPICIOUS - User rarely consents, and this app is new",
        not(ConsentedApps has SuspiciousAppName),
            "REVIEW - App not in user's consent history",
        "WITHIN BASELINE - User has consented to this app before"
    )
| project User, TotalConsents, UniqueApps, ConsentedApps, Assessment
// Expected: victim.user - TotalConsents=0 in baseline, Assessment = "ANOMALOUS"
//           (no consent events in baseline period for victim.user)
// Expected: regular.user - TotalConsents=3, Assessment = "REVIEW - App not in user's consent history"
//           (has consented before, but not to this specific app)
```

### Test 4: Blast Radius Assessment

```kql
// ============================================================
// TEST 4: Blast Radius Assessment
// Validates: Query 6 - Find all users who consented to the same app
// Expected: 3 users affected, CampaignScope = "LIMITED CAMPAIGN"
//           CampaignVelocity = "FAST" (all within 2 hours)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Three users consented to the same malicious app ---
    datetime(2026-02-22T14:00:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"victim.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"M365 Document Viewer","id":"app-malicious-001","type":"ServicePrincipal"}]),
        "success",
    datetime(2026-02-22T14:15:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"finance.manager@contoso.com","ipAddress":"198.51.100.51"}}),
        dynamic([{"displayName":"M365 Document Viewer","id":"app-malicious-001","type":"ServicePrincipal"}]),
        "success",
    datetime(2026-02-22T15:30:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"exec.assistant@contoso.com","ipAddress":"192.0.2.100"}}),
        dynamic([{"displayName":"M365 Document Viewer","id":"app-malicious-001","type":"ServicePrincipal"}]),
        "success",
    // --- Unrelated app consent (should not appear in results) ---
    datetime(2026-02-22T12:00:00Z), "Consent to application",
        dynamic({"user":{"userPrincipalName":"it.admin@contoso.com","ipAddress":"10.0.0.1"}}),
        dynamic([{"displayName":"Zoom","id":"zoom-app","type":"ServicePrincipal"}]),
        "success"
];
let SuspiciousAppName = "M365 Document Viewer";
// --- Campaign scope assessment ---
TestAuditLogs
| where OperationName == "Consent to application"
| where tostring(TargetResources[0].displayName) == SuspiciousAppName
| summarize
    TotalConsentEvents = count(),
    UniqueUsers = dcount(tostring(InitiatedBy.user.userPrincipalName)),
    AffectedUsers = make_set(tostring(InitiatedBy.user.userPrincipalName), 50),
    ConsentTimeSpan = max(TimeGenerated) - min(TimeGenerated),
    FirstConsent = min(TimeGenerated),
    LastConsent = max(TimeGenerated),
    UniqueIPs = dcount(tostring(InitiatedBy.user.ipAddress))
| extend
    CampaignScope = case(
        UniqueUsers > 10, "MASS CAMPAIGN - 10+ users affected",
        UniqueUsers > 5, "TARGETED CAMPAIGN - 5-10 users affected",
        UniqueUsers > 1, "LIMITED CAMPAIGN - 2-4 users affected",
        "SINGLE TARGET - 1 user affected"
    ),
    CampaignVelocity = case(
        ConsentTimeSpan < 1h and UniqueUsers > 3,
            "RAPID - Multiple consents within 1 hour",
        ConsentTimeSpan < 24h and UniqueUsers > 1,
            "FAST - Multiple consents within 24 hours",
        "SLOW - Consents spread over time"
    )
| project TotalConsentEvents, UniqueUsers, AffectedUsers, CampaignScope, CampaignVelocity, FirstConsent, LastConsent
// Expected: TotalConsentEvents=3, UniqueUsers=3
// Expected: AffectedUsers=["victim.user@contoso.com","finance.manager@contoso.com","exec.assistant@contoso.com"]
// Expected: CampaignScope = "LIMITED CAMPAIGN - 2-4 users affected"
// Expected: CampaignVelocity = "FAST - Multiple consents within 24 hours"
```

---

## References

- [Microsoft: Detect and remediate illicit consent grants](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants)
- [Microsoft: Manage consent to applications in Entra ID](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-consent-requests)
- [Microsoft: Configure user consent settings](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent)
- [Microsoft: App governance in Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-manage-app-governance)
- [Microsoft: Investigate risky OAuth apps](https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth)
- [MITRE ATT&CK T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK T1550.001 - Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [MITRE ATT&CK T1566.002 - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [Midnight Blizzard OAuth app abuse in Microsoft breach (2024)](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [CISA: Detecting and mitigating consent phishing attacks](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- [Proofpoint: OAuth consent phishing campaign analysis](https://www.proofpoint.com/us/blog/cloud-security/oauthorize-illicit-consent-grant-attacks)
