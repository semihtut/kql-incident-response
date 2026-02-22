---
title: "Suspicious Service Principal Activity"
id: RB-0010
severity: high
status: reviewed
description: >
  Investigation runbook for suspicious service principal (app registration) activity
  in Microsoft Entra ID. Covers compromised or abused service principal credentials,
  anomalous sign-in patterns from AADServicePrincipalSignInLogs, credential lifecycle
  analysis, permission and API access auditing, blast radius assessment across Azure
  resources, and org-wide credential hygiene sweeps. Service principals often have
  elevated permissions and do not require MFA, making them a high-value target for
  attackers seeking persistent, stealthy access to cloud environments.
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
    - tactic_id: TA0009
      tactic_name: "Collection"
  techniques:
    - technique_id: T1098.001
      technique_name: "Account Manipulation: Additional Cloud Credentials"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1550.001
      technique_name: "Use Alternate Authentication Material: Application Access Token"
      confidence: confirmed
    - technique_id: T1528
      technique_name: "Steal Application Access Token"
      confidence: confirmed
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: confirmed
threat_actors:
  - "Midnight Blizzard (APT29/Nobelium)"
  - "Storm-0558"
  - "LAPSUS$ (DEV-0537)"
  - "Scattered Spider (Octo Tempest)"
log_sources:
  - table: "AADServicePrincipalSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: true
    alternatives: []
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
  - table: "AzureActivity"
    product: "Azure"
    license: "Azure Subscription"
    required: true
    alternatives: []
  - table: "AzureDiagnostics"
    product: "Azure Key Vault"
    license: "Azure Subscription + Diagnostic Settings"
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
category: identity
key_log_sources:
  - AADServicePrincipalSignInLogs
  - AuditLogs
  - SigninLogs
  - AzureActivity
  - AzureDiagnostics
tactic_slugs:
  - persistence
  - priv-esc
  - defense-evasion
  - cred-access
  - lateral-movement
  - collection
data_checks:
  - query: "AADServicePrincipalSignInLogs | take 1"
    label: primary
    description: "Service principal sign-in pattern analysis"
  - query: "AuditLogs | take 1"
    description: "For credential additions, permission changes, app modifications"
  - query: "SigninLogs | take 1"
    description: "For identifying who performed admin actions on the app registration"
  - query: "AzureActivity | take 1"
    description: "For Azure resource access via service principal"
  - query: "AzureDiagnostics | take 1"
    label: optional
    description: "For Key Vault access patterns (requires diagnostic settings enabled)"
---

# Suspicious Service Principal Activity - Investigation Runbook

> **RB-0010** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Audit Logs + AADServicePrincipalSignInLogs Pattern Analysis
> **Risk Detection Name:** Anomalous SP sign-in + `AddServicePrincipalCredentials` audit events
> **Primary MITRE Technique:** T1098.001 - Account Manipulation: Additional Cloud Credentials

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Service Principal Risk Assessment & Context](#step-1-service-principal-risk-assessment--context)
   - [Step 2: Service Principal Sign-In Pattern Analysis](#step-2-service-principal-sign-in-pattern-analysis)
   - [Step 3: Credential Lifecycle Timeline](#step-3-credential-lifecycle-timeline)
   - [Step 4: Baseline Comparison - Establish Normal Service Principal Behavior](#step-4-baseline-comparison---establish-normal-service-principal-behavior)
   - [Step 5: Permission & API Access Audit](#step-5-permission--api-access-audit)
   - [Step 6: Blast Radius Assessment](#step-6-blast-radius-assessment)
   - [Step 7: Org-Wide Service Principal Credential Sweep](#step-7-org-wide-service-principal-credential-sweep)
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
Suspicious service principal activity is detected through multiple complementary mechanisms:

1. **AADServicePrincipalSignInLogs anomaly detection:** Service principal sign-ins from new IP addresses, unusual geographic locations, or against resources the SP has never accessed before. Unlike user sign-ins, SP sign-ins are programmatic and should follow highly predictable patterns.
2. **AuditLogs credential lifecycle events:** Detection of `Add service principal credentials` operations, especially when performed by unexpected users or outside of change windows. New client secrets or certificates added to existing app registrations are the primary persistence mechanism.
3. **Cross-signal correlation:** Combination of credential addition followed by sign-in from a new IP, or permission escalation followed by access to sensitive resources like Key Vault or Microsoft Graph API.

**Why it matters:**
Service principals (app registrations) are the workload identities of cloud environments. They authenticate via client secrets or certificates, **never require MFA**, and often have broadly scoped permissions (Mail.ReadWrite, Directory.ReadWrite.All, Key Vault access). Attackers who compromise SP credentials gain persistent, silent access that bypasses all user-focused security controls. Midnight Blizzard (APT29/Nobelium) used compromised OAuth applications and service principals extensively during the SolarWinds campaign and the 2023-2024 Microsoft corporate breach. Storm-0558 leveraged a compromised signing key to forge tokens for service principals.

**Why this is HIGH severity:**
- Service principals do NOT require MFA -- a leaked client secret provides immediate, unrestricted access
- SP credentials (client secrets) are often long-lived (1-2 years default expiry) and rarely rotated
- SPs frequently have privileged API permissions (Mail.ReadWrite.All, Directory.ReadWrite.All) that grant tenant-wide access
- SP sign-ins generate less visibility than user sign-ins -- many SOCs do not monitor AADServicePrincipalSignInLogs
- A single compromised SP with Microsoft Graph permissions can read all email, enumerate all users, and access all files in the tenant
- Attackers can add new credentials to existing legitimate SPs, hiding within trusted application identity

**However:** This alert has a **low-to-moderate false positive rate** (~10-20%). Legitimate triggers include:
- DevOps teams performing scheduled credential rotation
- CI/CD pipelines using service principals from cloud-hosted runners with changing IP ranges (GitHub Actions, Azure DevOps)
- Multi-region application deployments causing geographic spread in SP sign-in locations
- New application deployments or infrastructure migrations changing SP usage patterns
- Third-party SaaS integrations that authenticate via SP from vendor infrastructure

**Worst case scenario if this is real:**
An attacker compromises a service principal credential (via exposed secret in code repository, stolen from Key Vault, or phished from a developer). They add a new client secret to maintain persistence, then use the SP's existing permissions to read all corporate email via Microsoft Graph, access Azure Key Vault secrets (database connection strings, API keys, certificates), enumerate and exfiltrate data from Azure Storage accounts, and establish further persistence by creating new app registrations or modifying existing ones. Because SPs don't trigger MFA and sign-ins are purely programmatic, the attacker can maintain access for months without detection unless AADServicePrincipalSignInLogs are actively monitored.

**Key difference from other identity runbooks:**
- RB-0001 through RB-0006 (User-focused): Investigate interactive user sign-ins, MFA, password attacks. All rely on user authentication patterns.
- **RB-0010 (This runbook):** Investigates **workload identity** -- non-human accounts that authenticate programmatically. There is no MFA, no device compliance, no location-based conditional access (by default). The investigation focuses on **credential lifecycle** (who added secrets, when, from where), **sign-in pattern anomaly** (new IPs, new resources), and **permission scope** (what can this SP access). This is the only runbook where the entity under investigation is an application, not a user.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID P1 + Azure Subscription + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID (includes AADServicePrincipalSignInLogs), Azure Activity
- **Permissions:** Security Reader (investigation), Application Administrator (containment)

### Recommended for Full Coverage
- **License:** Entra ID P2 + Microsoft 365 E5 + Sentinel
- **Additional:** Azure Key Vault diagnostic settings enabled (sends to Log Analytics)
- **Workload Identity Protection:** Entra Workload ID Premium for SP risk detections

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID P1 + Sentinel | AADServicePrincipalSignInLogs, AuditLogs, SigninLogs | Steps 1-5, 7 |
| Above + Azure Subscription | Above + AzureActivity | Steps 1-7 (excluding Key Vault deep dive) |
| Above + Key Vault Diagnostics | Above + AzureDiagnostics | Steps 1-7 (full investigation) |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let TargetSPName = "contoso-api-prod";             // Service principal display name
let TargetSPId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"; // Service principal object ID
let TargetAppId = "12345678-abcd-ef01-2345-6789abcdef01"; // Application (client) ID
let AlertTime = datetime(2026-02-22T14:00:00Z);    // Time suspicious activity was detected
let LookbackWindow = 24h;                          // Window to analyze recent activity
let ForwardWindow = 4h;                            // Window after alert for blast radius
let BaselineDays = 30d;                            // Baseline comparison window
let TargetIP = "203.0.113.50";                     // Suspicious IP from the alert (if known)
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- New client secret or certificate added to a high-privilege SP by an unfamiliar user
- SP sign-in from a new country or IP range that has never been seen in baseline
- SP accessing Microsoft Graph mail/file endpoints it has never accessed before
- SP credential added outside of change management window followed by immediate sign-in
- SP used to access Key Vault secrets from an IP not in the application's known infrastructure

### Standard Investigation
- SP sign-in from a new IP within the same cloud provider (GitHub Actions, Azure DevOps runner pool)
- Credential rotation detected but performed by a known DevOps user
- SP accessing a new Azure resource in an existing resource group

### Likely Benign
- Credential rotation by the app registration owner during a documented change window
- CI/CD pipeline IP changes matching known runner pool CIDR ranges
- Multi-region deployment causing new geographic sign-in locations from known Azure regions
- SP accessing resources consistent with its documented purpose

---

## 5. Investigation Steps

### Step 1: Service Principal Risk Assessment & Context

**Purpose:** Identify the service principal, its app registration, who owns it, when it was created, and what permissions it holds. This establishes the context needed for all subsequent investigation steps. Understanding what the SP is supposed to do is critical for determining if activity is anomalous.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 1: Service Principal Risk Assessment & Context
// Purpose: Identify the SP, its app registration, owner, creation date, permissions
// Tables: AuditLogs
// Investigation Step: 1 - Service Principal Risk Assessment & Context
// ============================================================
let TargetSPName = "contoso-api-prod";
let TargetSPId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let TargetAppId = "12345678-abcd-ef01-2345-6789abcdef01";
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- App registration and SP lifecycle events ---
AuditLogs
| where TimeGenerated >= ago(365d)
| where OperationName in (
    "Add application",
    "Add service principal",
    "Add owner to application",
    "Add owner to service principal",
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Add application certificate",
    "Update application",
    "Update service principal",
    "Add service principal credentials",
    "Remove service principal credentials",
    "Consent to application"
)
| where TargetResources has TargetSPName
    or TargetResources has TargetSPId
    or TargetResources has TargetAppId
| project
    TimeGenerated,
    OperationName,
    Category,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    TargetResourceType = tostring(TargetResources[0].type),
    TargetResourceId = tostring(TargetResources[0].id),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties),
    Result
| extend
    EventCategory = case(
        OperationName has "Add application" or OperationName has "Add service principal",
            "CREATION - App/SP created",
        OperationName has "owner",
            "OWNERSHIP - Owner assignment",
        OperationName has "credentials" or OperationName has "certificate",
            "CREDENTIAL - Secret/cert lifecycle",
        OperationName has "role" or OperationName has "permission" or OperationName == "Consent to application",
            "PERMISSION - Role/permission change",
        OperationName has "Update",
            "MODIFICATION - Configuration change",
        "OTHER"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- Scanning 365 days of AuditLogs may be slow -- narrow the range if the SP creation date is known
- Focus on `CREDENTIAL` and `PERMISSION` events for security-critical changes
- `InitiatedByUser` identifies WHO made changes -- unfamiliar users adding credentials is the top indicator

**Tuning Guidance:**
- If the SP was created recently (< 30 days) AND has high-privilege permissions, treat as suspicious
- If `InitiatedByUser` is empty and `InitiatedByApp` is populated, the change was made programmatically -- check what app made it
- Cross-reference `InitiatedByIP` with known corporate IP ranges

**Expected findings:**
- Complete lifecycle: Creation date, owners, credential additions, permission grants
- If recent credential additions by unexpected users are found, this confirms potential compromise
- If no audit trail exists for the SP, it may have been created before logging was enabled -- higher risk

**Next action:**
- Note the owners, creation date, and all credential events
- If suspicious credential addition found, proceed to Step 2 to check sign-in patterns
- If SP has high-privilege permissions (Directory.ReadWrite.All, Mail.ReadWrite), prioritize investigation

---

### Step 2: Service Principal Sign-In Pattern Analysis

**Purpose:** Analyze AADServicePrincipalSignInLogs for the target service principal to identify anomalous sign-in patterns. SP sign-ins should be highly predictable -- same IPs, same resources, same timing. Any deviation is significant.

**Data needed:** AADServicePrincipalSignInLogs

```kql
// ============================================================
// QUERY 2: Service Principal Sign-In Pattern Analysis
// Purpose: Analyze SP sign-in logs for anomalous IPs, locations, resources
// Tables: AADServicePrincipalSignInLogs
// Investigation Step: 2 - Service Principal Sign-In Pattern Analysis
// ============================================================
let TargetSPId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let TargetAppId = "12345678-abcd-ef01-2345-6789abcdef01";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Recent SP sign-in activity ---
AADServicePrincipalSignInLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where ServicePrincipalId == TargetSPId or AppId == TargetAppId
| project
    TimeGenerated,
    ServicePrincipalName,
    ServicePrincipalId,
    AppId,
    IPAddress,
    Location = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    ResourceDisplayName,
    ResourceId,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    CorrelationId
| extend
    SignInOutcome = case(
        ResultType == "0", "SUCCESS",
        ResultType == "7000215", "FAILURE - Invalid client secret",
        ResultType == "7000222", "FAILURE - Expired client secret",
        ResultType == "700016", "FAILURE - App not found in tenant",
        ResultType == "700027", "FAILURE - Invalid certificate",
        ResultType == "70021", "FAILURE - No matching signing key",
        strcat("FAILURE - ResultType ", ResultType)
    ),
    IsFailure = ResultType != "0"
| summarize
    TotalSignIns = count(),
    Successes = countif(ResultType == "0"),
    Failures = countif(ResultType != "0"),
    FailureTypes = make_set_if(ResultType, ResultType != "0", 10),
    UniqueIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 20),
    UniqueResources = dcount(ResourceDisplayName),
    ResourceList = make_set(ResourceDisplayName, 20),
    Countries = make_set(Country, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ServicePrincipalName, ServicePrincipalId
| extend
    RiskAssessment = case(
        Failures > 0 and Successes > 0 and UniqueIPs > 3,
            "HIGH - Mixed success/failure from multiple IPs (credential testing)",
        UniqueIPs > 5,
            "HIGH - Sign-ins from many IPs (potential credential compromise)",
        Failures > Successes and Failures > 5,
            "MEDIUM - Predominantly failing (brute force or stale credential)",
        UniqueResources > 5,
            "MEDIUM - Accessing many resources (potential enumeration)",
        "LOW - Standard activity pattern"
    )
```

**Performance Notes:**
- `ResultType 7000215` (invalid client secret) is the golden indicator for credential abuse -- someone has the AppId but wrong secret
- `ResultType 7000222` (expired secret) may indicate an attacker using a stolen but expired credential
- `UniqueIPs > 3` for a service principal is unusual -- most SPs authenticate from 1-2 IPs

**Tuning Guidance:**
- Compare `IPList` against known infrastructure IPs for the application
- If `ResultType == "0"` from a new IP AND `ResultType == "7000215"` from other IPs, the attacker may be testing stolen credentials from multiple locations
- Check `ResourceDisplayName` -- SPs accessing "Microsoft Graph" for the first time is suspicious if they normally access "Azure Key Vault"

**Expected findings:**
- **HIGH**: Mixed success/failure from multiple IPs -- credential being tested from attacker infrastructure
- **MEDIUM**: Accessing new resources -- compromised SP being used for lateral movement
- **LOW**: Consistent pattern from known IPs -- normal application behavior

**Next action:**
- If anomalous IPs found, proceed to Step 3 to check credential lifecycle
- If new resources accessed, proceed to Step 6 for blast radius
- Note all suspicious IPs for correlation across subsequent queries

---

### Step 3: Credential Lifecycle Timeline

**Purpose:** Build a timeline of all credential additions and removals for the target service principal. Identify who added credentials, when, from what IP, and whether the timing correlates with anomalous sign-in activity from Step 2. This is the **core forensic query** for SP compromise investigations.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 3: Credential Lifecycle Timeline
// Purpose: Timeline of credential additions/removals with actor attribution
// Tables: AuditLogs
// Investigation Step: 3 - Credential Lifecycle Timeline
// ============================================================
let TargetSPName = "contoso-api-prod";
let TargetSPId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let TargetAppId = "12345678-abcd-ef01-2345-6789abcdef01";
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- Credential lifecycle events (90-day window) ---
AuditLogs
| where TimeGenerated >= ago(90d)
| where OperationName in (
    "Add service principal credentials",
    "Remove service principal credentials",
    "Update application – Certificates and secrets management",
    "Update application",
    "Add application certificate"
)
| where TargetResources has TargetSPName
    or TargetResources has TargetSPId
    or TargetResources has TargetAppId
| project
    TimeGenerated,
    OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    TargetResourceId = tostring(TargetResources[0].id),
    ModifiedProperties = TargetResources[0].modifiedProperties,
    Result,
    CorrelationId
| mv-expand ModifiedProperty = ModifiedProperties
| where tostring(ModifiedProperty.displayName) in ("KeyDescription", "FederatedIdentityCredentials")
    or isempty(ModifiedProperty)
| extend
    PropertyName = tostring(ModifiedProperty.displayName),
    OldValue = tostring(ModifiedProperty.oldValue),
    NewValue = tostring(ModifiedProperty.newValue)
| extend
    CredentialAction = case(
        OperationName has "Add" and OperationName has "credentials", "SECRET ADDED",
        OperationName has "Remove" and OperationName has "credentials", "SECRET REMOVED",
        OperationName has "certificate", "CERTIFICATE ADDED",
        OperationName has "Update" and NewValue has "KeyCredential", "CERTIFICATE UPDATED",
        OperationName has "Update" and NewValue has "PasswordCredential", "SECRET UPDATED",
        "MODIFICATION"
    ),
    Severity = case(
        OperationName has "Add" and OperationName has "credentials"
            and isempty(InitiatedByUser), "CRITICAL - Credential added programmatically",
        OperationName has "Add" and OperationName has "credentials",
            "HIGH - New credential added",
        OperationName has "certificate",
            "HIGH - Certificate added",
        OperationName has "Remove",
            "MEDIUM - Credential removed",
        "LOW - Standard modification"
    )
| project
    TimeGenerated,
    CredentialAction,
    OperationName,
    InitiatedByUser,
    InitiatedByApp,
    InitiatedByIP,
    TargetResource,
    PropertyName,
    Severity,
    Result,
    CorrelationId
| sort by TimeGenerated asc
```

**Performance Notes:**
- `Add service principal credentials` is the #1 persistence technique for service principal compromise
- `InitiatedByUser` being empty means the credential was added by an application, not a human -- investigate which app
- `InitiatedByIP` outside corporate ranges for credential additions is extremely suspicious
- Multiple credential additions in a short window = attacker creating backup access

**Tuning Guidance:**
- Correlate credential addition timestamps with sign-in anomalies from Step 2
- If a credential was added AND a sign-in from a new IP occurred within hours, this is strong evidence of compromise
- Check if `InitiatedByUser` is the documented app owner -- if not, investigate the user account

**Expected findings:**
- **CRITICAL**: Credential added programmatically by an unknown app -- automated persistence
- **HIGH**: New secret added by a user who is NOT the documented app owner -- potential compromise
- **MEDIUM**: Credential removed -- may be legitimate rotation or attacker covering tracks

**Next action:**
- If suspicious credential addition found, correlate the timestamp with Step 2 sign-in data
- If the initiating user is unfamiliar, investigate that user account (may also be compromised)
- Proceed to Step 4 for baseline comparison

#### Query 3B: Workload Identity Federation (WIF) Credential Analysis

```kql
// ============================================================
// QUERY 3B: Workload Identity Federation Abuse Detection
// Purpose: Detect unauthorized federated identity credentials on service principals
// Tables: AuditLogs
// Investigation Step: 3B - WIF-specific credential analysis
// ============================================================
let TargetSPId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let TargetAppId = "12345678-abcd-ef01-2345-6789abcdef01";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 90d;
// --- WIF credential events ---
AuditLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where OperationName in (
    "Update application",
    "Update application – Certificates and secrets management",
    "Add service principal credentials",
    "Update service principal"
)
| extend
    TargetApp = tostring(TargetResources[0].displayName),
    TargetAppId_Event = tostring(TargetResources[0].id),
    ModifiedProps = TargetResources[0].modifiedProperties,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| where TargetAppId_Event == TargetAppId
    or TargetApp has TargetSPId
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
// Filter for federated identity credential changes
| where PropertyName in ("FederatedIdentityCredentials", "KeyDescription")
    and (NewValue has "federated" or NewValue has "Federated"
        or NewValue has "issuer" or NewValue has "subject"
        or NewValue has "audience")
| extend
    // Extract WIF configuration details
    FederatedIssuer = extract(@'"issuer"\s*:\s*"([^"]+)"', 1, NewValue),
    FederatedSubject = extract(@'"subject"\s*:\s*"([^"]+)"', 1, NewValue),
    FederatedAudience = extract(@'"audience"\s*:\s*"([^"]+)"', 1, NewValue),
    CredentialName = extract(@'"name"\s*:\s*"([^"]+)"', 1, NewValue)
| extend
    WIFRisk = case(
        // Known legitimate issuers
        FederatedIssuer has "token.actions.githubusercontent.com",
            "REVIEW - GitHub Actions federation (verify repo/workflow)",
        FederatedIssuer has "sts.windows.net",
            "REVIEW - Azure AD federation (verify tenant)",
        FederatedIssuer has "accounts.google.com",
            "HIGH - Google Cloud federation (verify authorization)",
        FederatedIssuer has "cognito-identity.amazonaws.com" or FederatedIssuer has "sts.amazonaws.com",
            "HIGH - AWS federation (verify authorization)",
        isnotempty(FederatedIssuer) and isempty(InitiatedByUser),
            "CRITICAL - WIF added programmatically (no human actor)",
        isnotempty(FederatedIssuer),
            "HIGH - External IdP federation added (verify issuer)",
        NewValue has "federated" or NewValue has "Federated",
            "MEDIUM - Possible federated credential change",
        "LOW"
    )
| where WIFRisk != "LOW"
| project
    TimeGenerated,
    OperationName,
    TargetApp,
    InitiatedByUser = coalesce(InitiatedByUser, InitiatedByApp),
    InitiatedByIP,
    CredentialName,
    FederatedIssuer,
    FederatedSubject,
    FederatedAudience,
    WIFRisk,
    Result
| sort by TimeGenerated desc
```

**Why Workload Identity Federation abuse is the next-generation persistence threat:**

- WIF allows **secretless authentication** from external identity providers (GitHub Actions, AWS, GCP) to Azure AD service principals
- Unlike client secrets, WIF credentials have **no expiry** unless explicitly removed — perfect for persistent access
- An attacker adds their own external IdP (e.g., their own Azure AD tenant or GitHub repo) as a federated credential → they can authenticate as the SP without any secret
- WIF abuse is **harder to detect** than secret/certificate addition because there's no credential to rotate — the trust relationship itself is the backdoor
- There is no `ResultType` or `RiskLevel` signal — the sign-in appears legitimate because the federation trust validates correctly

**Decision guidance:**
- **FederatedIssuer pointing to unknown Azure AD tenant** → Attacker's own tenant federating into your SP. Check the tenant ID against known partner tenants.
- **FederatedSubject containing an unknown GitHub repo** → Attacker's repo gets to authenticate as your SP. Verify the repo with the DevOps team.
- **WIF added programmatically (no InitiatedByUser)** → Automated persistence. Check which app made the change and whether it's authorized.
- **Multiple WIF credentials on a high-privilege SP** → Redundant persistence — attacker creates multiple federation paths.

---

### Step 4: Baseline Comparison - Establish Normal Service Principal Behavior

**Purpose:** Establish what "normal" sign-in behavior looks like for this service principal over 30 days. SP sign-ins are highly predictable -- the same IPs, same resources, same hourly patterns. Compare current activity against this baseline to determine if behavior is truly anomalous. **This step is MANDATORY per project quality standards.**

**Data needed:** AADServicePrincipalSignInLogs

```kql
// ============================================================
// QUERY 4: Baseline Comparison - Normal SP Behavior Pattern
// Purpose: Establish 30-day baseline for SP sign-in patterns
// Tables: AADServicePrincipalSignInLogs
// Investigation Step: 4 - Baseline Comparison [MANDATORY]
// ============================================================
let TargetSPId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let TargetAppId = "12345678-abcd-ef01-2345-6789abcdef01";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 30d;
// --- 30-day SP sign-in baseline ---
let SPBaseline = AADServicePrincipalSignInLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime - 1h)
| where ServicePrincipalId == TargetSPId or AppId == TargetAppId
| where ResultType == "0"  // Successful sign-ins only for baseline
| summarize
    DailySignIns = count(),
    DailyUniqueIPs = dcount(IPAddress),
    DailyUniqueResources = dcount(ResourceDisplayName),
    DailyIPList = make_set(IPAddress, 20),
    DailyResourceList = make_set(ResourceDisplayName, 10),
    DailyCountries = make_set(tostring(LocationDetails.countryOrRegion), 5)
    by Day = bin(TimeGenerated, 1d);
// --- Aggregate baseline statistics ---
let BaselineStats = SPBaseline
| summarize
    BaselineDays_Observed = count(),
    AvgDailySignIns = round(avg(DailySignIns), 1),
    MaxDailySignIns = max(DailySignIns),
    StdDevDailySignIns = round(stdev(DailySignIns), 1),
    AvgDailyUniqueIPs = round(avg(DailyUniqueIPs), 1),
    MaxDailyUniqueIPs = max(DailyUniqueIPs),
    AllBaselineIPs = make_set(DailyIPList),
    AllBaselineResources = make_set(DailyResourceList),
    AllBaselineCountries = make_set(DailyCountries);
// --- Today's activity for comparison ---
let TodayStats = AADServicePrincipalSignInLogs
| where TimeGenerated between (AlertTime - 24h .. AlertTime + 4h)
| where ServicePrincipalId == TargetSPId or AppId == TargetAppId
| where ResultType == "0"
| summarize
    TodaySignIns = count(),
    TodayUniqueIPs = dcount(IPAddress),
    TodayIPList = make_set(IPAddress, 20),
    TodayUniqueResources = dcount(ResourceDisplayName),
    TodayResourceList = make_set(ResourceDisplayName, 10),
    TodayCountries = make_set(tostring(LocationDetails.countryOrRegion), 5);
// --- Compare baseline vs today ---
BaselineStats
| extend placeholder = 1
| join kind=inner (TodayStats | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    SignInDeviation = iff(StdDevDailySignIns > 0,
        round((TodaySignIns - AvgDailySignIns) / StdDevDailySignIns, 1),
        iff(TodaySignIns > 0, 999.0, 0.0)),
    NewIPs = set_difference(TodayIPList, AllBaselineIPs),
    NewResources = set_difference(TodayResourceList, AllBaselineResources),
    NewCountries = set_difference(TodayCountries, AllBaselineCountries),
    HasNewIPs = array_length(set_difference(TodayIPList, AllBaselineIPs)) > 0,
    HasNewResources = array_length(set_difference(TodayResourceList, AllBaselineResources)) > 0,
    HasNewCountries = array_length(set_difference(TodayCountries, AllBaselineCountries)) > 0
| extend
    Assessment = case(
        BaselineDays_Observed == 0 and TodaySignIns > 0,
            "NEW SP - No baseline history, ANY activity requires validation",
        HasNewCountries,
            "ANOMALOUS - Sign-in from new country never seen in 30-day baseline",
        HasNewIPs and HasNewResources,
            "ANOMALOUS - New IPs AND new resources accessed",
        HasNewIPs,
            "SUSPICIOUS - Sign-in from IPs not seen in 30-day baseline",
        HasNewResources,
            "SUSPICIOUS - Accessing resources not seen in 30-day baseline",
        TodaySignIns > AvgDailySignIns + 3 * StdDevDailySignIns,
            "SUSPICIOUS - Sign-in volume exceeds 3 standard deviations",
        "WITHIN NORMAL RANGE - Activity consistent with baseline"
    )
```

**Performance Notes:**
- `set_difference` is the critical function -- it reveals IPs and resources today that were NEVER seen in 30 days
- SP sign-ins should be extremely predictable -- any new IP or resource is meaningful (unlike user sign-ins)
- `HasNewCountries` is the strongest anomaly indicator for SPs -- legitimate apps rarely change geographic origin

**Tuning Guidance:**
- For SPs used by CI/CD pipelines, `HasNewIPs` may be expected -- cross-reference with known runner CIDR ranges
- If `Assessment == "NEW SP"`, the SP was recently created -- check Step 1 for creation context
- SPs with `AllBaselineIPs` containing only 1-2 IPs that suddenly show 5+ are highly suspicious

**Expected findings:**
- **NEW SP**: No historical data -- recently created SP needs full permission and owner validation
- **ANOMALOUS**: New country or new IPs + new resources -- strong indicator of credential compromise
- **SUSPICIOUS**: New IPs only -- could be infrastructure change or compromise, correlate with Step 3
- **WITHIN NORMAL RANGE**: Activity matches baseline -- investigate other signals or close as FP

**Next action:**
- If anomalous, proceed to Steps 5 and 6 with high confidence of compromise
- If within normal range but Step 3 showed suspicious credential addition, still investigate
- Document all new IPs and resources for evidence collection

---

### Step 5: Permission & API Access Audit

**Purpose:** Audit the service principal's permissions to understand the blast radius potential. Check what Microsoft Graph API permissions, Azure RBAC roles, and OAuth scopes the SP holds. Over-permissioned SPs are the highest-risk targets.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 5: Permission & API Access Audit
// Purpose: Audit SP Graph permissions, Azure roles, OAuth scopes
// Tables: AuditLogs
// Investigation Step: 5 - Permission & API Access Audit
// ============================================================
let TargetSPName = "contoso-api-prod";
let TargetSPId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let TargetAppId = "12345678-abcd-ef01-2345-6789abcdef01";
// --- Permission grants and role assignments ---
AuditLogs
| where TimeGenerated >= ago(365d)
| where OperationName in (
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Add app role assignment grant to user",
    "Consent to application",
    "Add member to role",
    "Add eligible member to role",
    "Add application permission to service principal"
)
| where TargetResources has TargetSPName
    or TargetResources has TargetSPId
    or TargetResources has TargetAppId
| project
    TimeGenerated,
    OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    TargetResource = tostring(TargetResources[0].displayName),
    ModifiedProperties = TargetResources[0].modifiedProperties,
    Result
| mv-expand ModifiedProperty = ModifiedProperties
| extend
    PropertyName = tostring(ModifiedProperty.displayName),
    NewValue = tostring(ModifiedProperty.newValue)
| where PropertyName in ("AppRole.Value", "DelegatedPermissionGrant.Scope",
    "Role.DisplayName", "AppRole.DisplayName")
    or isempty(PropertyName)
| extend
    PermissionType = case(
        OperationName has "app role", "APPLICATION",
        OperationName has "delegated", "DELEGATED",
        OperationName has "Consent", "CONSENT",
        OperationName has "member to role", "DIRECTORY_ROLE",
        "OTHER"
    ),
    PermissionRisk = case(
        NewValue has_any ("Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
            "Application.ReadWrite.All"), "CRITICAL - Tenant-wide directory write access",
        NewValue has_any ("Mail.ReadWrite", "Mail.ReadWrite.All", "Mail.Read.All",
            "MailboxSettings.ReadWrite"), "CRITICAL - Email read/write access",
        NewValue has_any ("Files.ReadWrite.All", "Sites.ReadWrite.All"), "HIGH - File/SharePoint write access",
        NewValue has_any ("User.ReadWrite.All", "Group.ReadWrite.All"), "HIGH - User/Group management",
        NewValue has_any ("KeyVault", "Storage"), "HIGH - Azure resource access",
        NewValue has_any (".Read", "User.Read.All"), "MEDIUM - Read-only access",
        "LOW - Standard permission"
    )
| project
    TimeGenerated,
    OperationName,
    PermissionType,
    PropertyName,
    PermissionValue = NewValue,
    PermissionRisk,
    InitiatedByUser,
    InitiatedByApp,
    Result
| sort by TimeGenerated asc
```

**Performance Notes:**
- `Application` permissions (app-only) are more dangerous than `Delegated` -- they don't require user context
- `Directory.ReadWrite.All` + `Application.ReadWrite.All` combination = tenant takeover capability
- `Mail.ReadWrite.All` as an application permission = read ANY user's email without their knowledge

**Tuning Guidance:**
- Focus on `CRITICAL` and `HIGH` risk permissions first -- these define the maximum blast radius
- If permissions were granted recently (< 30 days) AND credential addition is suspicious, this is an escalation
- Check if `Consent to application` was admin consent (tenant-wide) vs user consent (single user)

**Expected findings:**
- **CRITICAL**: SP has Mail.ReadWrite.All or Directory.ReadWrite.All -- compromised SP can access all email or modify directory
- **HIGH**: SP has broad file or user management access -- data exfiltration possible
- **LOW**: SP has appropriately scoped read-only permissions -- blast radius is limited

**Next action:**
- If CRITICAL permissions found, proceed to Step 6 with urgency -- the blast radius is potentially tenant-wide
- Document all permissions for the containment phase (least-privilege remediation)
- Cross-reference permission grant dates with credential addition dates from Step 3

---

### Step 6: Blast Radius Assessment

**Purpose:** For a confirmed or suspected compromised service principal, assess what Azure resources were actually accessed. Check AzureActivity for management plane operations and AzureDiagnostics for data plane access (Key Vault secrets, Storage blobs).

#### Step 6A: Azure Resource Access via Service Principal

**Data needed:** AzureActivity

```kql
// ============================================================
// QUERY 6A: Azure Resource Access via Service Principal
// Purpose: Identify Azure resources accessed by the SP
// Tables: AzureActivity
// Investigation Step: 6A - Azure Resource Access
// ============================================================
let TargetSPId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let TargetAppId = "12345678-abcd-ef01-2345-6789abcdef01";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
let ForwardWindow = 4h;
// --- Azure resource operations by SP ---
AzureActivity
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + ForwardWindow)
| where Caller == TargetSPId or Caller == TargetAppId
    or tostring(Claims_d.appid) == TargetAppId
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ResourceGroup,
    Resource = _ResourceId,
    SubscriptionId,
    ActivityStatusValue,
    CategoryValue,
    Level,
    Properties = tostring(Properties)
| extend
    OperationCategory = case(
        OperationNameValue has_any ("listkeys", "listsecrets", "listkeys", "getsecret"),
            "CRITICAL - Secret/key retrieval",
        OperationNameValue has_any ("write", "create", "delete"),
            "HIGH - Resource modification",
        OperationNameValue has_any ("roleAssignments/write"),
            "CRITICAL - Role assignment change",
        OperationNameValue has_any ("read", "list", "get"),
            "LOW - Read/list operation",
        "MEDIUM - Other operation"
    ),
    ResourceType = case(
        Resource has "Microsoft.KeyVault", "Key Vault",
        Resource has "Microsoft.Storage", "Storage Account",
        Resource has "Microsoft.Sql", "SQL Database",
        Resource has "Microsoft.Compute", "Virtual Machine",
        Resource has "Microsoft.Web", "App Service",
        Resource has "Microsoft.Authorization", "RBAC / Authorization",
        extract(@"Microsoft\.(\w+)", 1, tostring(Resource))
    )
| summarize
    OperationCount = count(),
    UniqueOperations = make_set(OperationNameValue, 20),
    ResourceGroups = make_set(ResourceGroup, 10),
    ResourceTypes = make_set(ResourceType, 10),
    HighRiskOps = countif(OperationCategory has "CRITICAL" or OperationCategory has "HIGH"),
    SourceIPs = make_set(CallerIpAddress, 10),
    FirstActivity = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by Caller, OperationCategory
| sort by HighRiskOps desc, OperationCount desc
```

**Performance Notes:**
- `listkeys` and `listsecrets` operations on Key Vault are the highest-risk indicators
- `roleAssignments/write` means the SP is assigning Azure RBAC roles -- privilege escalation
- `CallerIpAddress` should match the application's known infrastructure -- new IPs are suspicious

**Expected findings:**
- **CRITICAL**: Key retrieval, role assignment changes from unexpected IPs
- **HIGH**: Resource modifications (create/delete) outside normal patterns
- **LOW**: Standard read operations consistent with application purpose

---

#### Step 6B: Key Vault Access Analysis

**Data needed:** AzureDiagnostics

```kql
// ============================================================
// QUERY 6B: Key Vault Access via Service Principal
// Purpose: Detect Key Vault secret/key access by the compromised SP
// Tables: AzureDiagnostics
// Investigation Step: 6B - Key Vault Access Analysis
// ============================================================
let TargetSPId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
let ForwardWindow = 4h;
// --- Key Vault operations by the SP ---
AzureDiagnostics
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + ForwardWindow)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where identity_claim_appid_g == TargetSPId
    or identity_claim_oid_g == TargetSPId
| project
    TimeGenerated,
    OperationName,
    CallerIPAddress,
    Resource,
    ResultType,
    ResultDescription = resultDescription_s,
    RequestUri = requestUri_s,
    SecretName = id_s,
    ClientInfo = clientInfo_s,
    HttpStatusCode = httpStatusCode_d
| extend
    OperationRisk = case(
        OperationName in ("SecretGet", "SecretList"), "CRITICAL - Secret access",
        OperationName in ("KeyGet", "KeyList", "KeyDecrypt"), "CRITICAL - Key access",
        OperationName in ("CertificateGet", "CertificateList"), "HIGH - Certificate access",
        OperationName in ("VaultGet", "VaultList"), "MEDIUM - Vault enumeration",
        "LOW - Other operation"
    )
| summarize
    TotalOperations = count(),
    UniqueSecrets = dcount(SecretName),
    SecretNames = make_set(SecretName, 50),
    OperationTypes = make_set(OperationName, 10),
    SourceIPs = make_set(CallerIPAddress, 10),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by OperationRisk, Resource
| sort by TotalOperations desc
```

**Performance Notes:**
- `SecretGet` with high `UniqueSecrets` count = mass secret retrieval (see also RB-0007)
- `CallerIPAddress` from unexpected ranges = compromised SP being used from attacker infrastructure
- `identity_claim_appid_g` maps to the SP's AppId in Key Vault diagnostic logs

**Expected findings:**
- **CRITICAL**: Secrets accessed from new IPs -- attacker harvesting credentials from Key Vault
- **HIGH**: Certificate retrieval -- attacker may be stealing signing certificates for token forging

**Next action:**
- If Key Vault secrets accessed, identify WHAT secrets were retrieved (connection strings, API keys)
- Those downstream systems are now also potentially compromised -- cascade investigation
- Proceed to Step 7 for org-wide sweep

---

### Step 7: Org-Wide Service Principal Credential Sweep

**Purpose:** Sweep the entire tenant for service principals with recently added credentials, expired credentials still in use, or excessive permissions. A compromised SP is often not isolated -- attackers may have added credentials to multiple SPs for redundant access.

**Data needed:** AuditLogs, AADServicePrincipalSignInLogs

```kql
// ============================================================
// QUERY 7: Org-Wide Service Principal Credential Sweep
// Purpose: Find all SPs with recently added credentials and excessive permissions
// Tables: AuditLogs, AADServicePrincipalSignInLogs
// Investigation Step: 7 - Org-Wide SP Credential Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let SweepWindow = 30d;
// --- All credential additions in the last 30 days ---
let RecentCredentialAdditions = AuditLogs
| where TimeGenerated between (AlertTime - SweepWindow .. AlertTime)
| where OperationName in (
    "Add service principal credentials",
    "Update application – Certificates and secrets management",
    "Add application certificate"
)
| project
    CredentialAddedTime = TimeGenerated,
    OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    TargetSP = tostring(TargetResources[0].displayName),
    TargetSPId = tostring(TargetResources[0].id),
    Result;
// --- Correlate with sign-in activity from new IPs ---
let SPSignIns = AADServicePrincipalSignInLogs
| where TimeGenerated between (AlertTime - SweepWindow .. AlertTime)
| where ResultType == "0"
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 10),
    Resources = make_set(ResourceDisplayName, 10),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 5)
    by ServicePrincipalName, ServicePrincipalId;
// --- Join credential additions with sign-in data ---
RecentCredentialAdditions
| join kind=leftouter (SPSignIns) on $left.TargetSPId == $right.ServicePrincipalId
| extend
    HasSignIns = isnotempty(SignInCount),
    RiskLevel = case(
        isempty(InitiatedByUser) and isnotempty(SignInCount) and UniqueIPs > 3,
            "CRITICAL - Programmatic cred addition + multi-IP sign-ins",
        isnotempty(SignInCount) and UniqueIPs > 3,
            "HIGH - Cred addition + sign-ins from many IPs",
        isempty(InitiatedByUser),
            "HIGH - Programmatic credential addition",
        isnotempty(SignInCount) and array_length(Countries) > 2,
            "HIGH - Multi-country sign-ins after cred addition",
        isnotempty(SignInCount),
            "MEDIUM - Credential added with subsequent sign-ins",
        "LOW - Credential added but no sign-in activity"
    )
| project
    CredentialAddedTime,
    TargetSP,
    TargetSPId,
    OperationName,
    InitiatedByUser,
    InitiatedByApp,
    InitiatedByIP,
    SignInCount,
    UniqueIPs,
    IPList,
    Resources,
    Countries,
    RiskLevel
| sort by RiskLevel asc, CredentialAddedTime desc
```

**Performance Notes:**
- This is a tenant-wide query -- may be slow in large organizations with many SPs
- Focus on `CRITICAL` and `HIGH` results first -- these indicate potential compromise of other SPs
- `isempty(InitiatedByUser)` means programmatic credential addition -- automated persistence

**Tuning Guidance:**
- Filter out known DevOps users/service accounts that perform legitimate credential rotation
- Cross-reference `InitiatedByIP` across all results -- same IP adding credentials to multiple SPs = attacker
- If multiple SPs show credential additions from the same user within a short window, that user account may be compromised

**Expected findings:**
- **CRITICAL**: Multiple SPs with programmatic credential additions and multi-IP sign-ins -- widespread compromise
- **HIGH**: Single SP with unexpected credential addition -- isolated compromise
- **LOW**: Credential rotation by known admin -- standard operations

**Next action:**
- For each CRITICAL/HIGH SP, run Steps 1-6 to investigate individually
- If a common `InitiatedByUser` is found across multiple SPs, investigate that user account
- If a common `InitiatedByIP` is found, block the IP immediately

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to assess whether the service principal's activity pattern deviates from its established baseline. While UEBA primarily tracks user entities, service principal sign-ins logged via `AADServicePrincipalSignInLogs` can still generate `BehaviorAnalytics` entries for associated users who manage or created the service principal. This step checks the managing user's behavioral context.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 4. Note: UEBA has limited coverage for service principals — focus on the managing user's behavioral patterns.

#### Query 8A: Managing User Behavioral Assessment

```kql
// ============================================================
// Query 8A: UEBA Assessment for Service Principal's Managing User
// Purpose: Check if the user who manages/created the service
//          principal shows anomalous behavior patterns
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T12:00:00Z);
let TargetUser = "admin@contoso.com";
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
    FirstTimeResource = tobool(ActivityInsights.FirstTimeUserAccessedResource),
    ResourceUncommonForUser = tobool(ActivityInsights.ResourceUncommonlyAccessedByUser),
    FirstTimeISP = tobool(ActivityInsights.FirstTimeUserConnectedViaISP),
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| order by InvestigationPriority desc, TimeGenerated desc
```

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| InvestigationPriority | >= 7 | < 4 |
| FirstTimeAction | true — new SP management action | false — regular DevOps task |
| ActionUncommonAmongPeers | true — peers don't manage SPs | false — normal for team |
| FirstTimeResource | true — accessing new resources | false — routine |
| IsDormantAccount | true — dormant admin managing SP | false |

**Decision guidance:**

- **Managing user InvestigationPriority >= 7 + FirstTimeAction** → Compromised admin creating/modifying service principals. High risk of persistence mechanism
- **ActionUncommonAmongPeers = false** → SP management is normal for this user's role (DevOps/platform team). Lower concern
- **IsDormantAccount = true** → Dormant admin managing SPs is critical — account likely compromised

---

## 6. Containment Playbook

### Priority Actions (Based on Investigation Findings)

#### Immediate (Within 15 minutes of confirmed compromise)

!!! danger "Action Required - For Each Compromised Service Principal"

1. **Remove all compromised credentials** -- Delete the suspicious client secret or certificate from the app registration. If unsure which credential is compromised, remove ALL secrets and certificates.
2. **Disable the service principal** -- If the application can tolerate downtime, disable the SP via Entra ID > Enterprise Applications > Properties > Enabled for users to sign in = No.
3. **Block suspicious IPs** -- Add attacker IPs to Conditional Access named locations (if workload identity Conditional Access is available) or Azure Firewall/NSG rules.
4. **Revoke existing tokens** -- Use `Revoke-AzureADServicePrincipalPasswordCredential` and restart dependent services to force re-authentication.
5. **Alert the application owner** -- Contact the SP owner via phone to confirm whether credential changes were authorized.

#### If Credential Theft Confirmed

6. **Remove ALL existing secrets and certificates** -- Generate completely new credentials.
7. **Migrate to managed identity** -- If the workload runs on Azure, replace the SP with a managed identity (system-assigned preferred) to eliminate credential management entirely.
8. **Rotate downstream secrets** -- If the SP accessed Key Vault, rotate ALL secrets that were retrieved during the compromise window.
9. **Review and remediate Key Vault access policies** -- Remove the compromised SP from Key Vault access policies.

#### Follow-Up (Within 4 hours)

10. **Reduce permissions to least privilege** -- Remove any permissions that exceed what the application needs (especially Mail.ReadWrite.All, Directory.ReadWrite.All).
11. **Enable workload identity protection** -- Deploy Entra Workload ID Premium for SP risk detection.
12. **Review all app registration owners** -- Remove owners who should not have access. Limit to 2 owners maximum.
13. **Implement credential governance** -- Set short-lived secrets (90 days max), require certificate-based authentication where possible.
14. **Enable Conditional Access for workload identities** -- Restrict SP sign-ins by IP range and location.

#### Extended (Within 24 hours)

15. **Run org-wide credential sweep** (Step 7) -- Check all SPs for similar compromise indicators.
16. **Audit all SPs with high-privilege permissions** -- Identify and remediate over-permissioned SPs.
17. **Implement certificate-based authentication only** -- Deprecate client secrets in favor of certificates.
18. **Deploy secrets scanning** -- Ensure CI/CD pipelines and code repositories are scanned for leaked credentials (GitHub Advanced Security, Azure DevOps credential scanning).
19. **Brief the security team** on SP compromise indicators and update monitoring playbooks.

---

## 7. Evidence Collection Checklist

Preserve these artifacts before any remediation actions:

- [ ] Full AADServicePrincipalSignInLogs for the SP (AlertTime +/- 30 days)
- [ ] AuditLogs for all credential lifecycle events (Add/Remove credentials, permission changes)
- [ ] AuditLogs for app registration creation and owner assignments
- [ ] AzureActivity for all operations performed by the SP (AlertTime +/- 7 days)
- [ ] AzureDiagnostics for Key Vault access by the SP (if applicable)
- [ ] Complete list of SP permissions (Graph API, Azure RBAC, OAuth scopes)
- [ ] App registration owner list and their sign-in history
- [ ] IP reputation and ASN lookups for suspicious IPs in SP sign-in logs
- [ ] List of all secrets/keys retrieved from Key Vault during compromise window
- [ ] Current credential inventory (all active secrets, certificates, federated credentials)
- [ ] Screenshot of app registration configuration (permissions, certificates, owners)

---

## 8. Escalation Criteria

### Escalate to Incident Commander
- SP with tenant-wide permissions (Directory.ReadWrite.All, Mail.ReadWrite.All) confirmed compromised
- Multiple SPs show credential additions from the same attacker IP
- Key Vault secrets accessed by compromised SP -- downstream systems may be affected
- SP used to modify Azure RBAC role assignments (privilege escalation across subscriptions)

### Escalate to Threat Intelligence
- SP sign-in IPs match known threat actor infrastructure (APT29, Storm-0558)
- Attack pattern matches Midnight Blizzard TTP (OAuth app abuse, token forging)
- Compromised SP was used to create new app registrations (cascading persistence)
- Evidence of federated identity credential abuse (external IdP trust manipulation)

### Escalate to Legal/Compliance
- Customer data accessed via compromised SP (Graph API mail/file access)
- Key Vault secrets include third-party API keys or database credentials (breach notification)
- SP accessed resources in regulated subscriptions (PCI, HIPAA, SOX environments)

---

## 9. False Positive Documentation

### FP Scenario 1: Legitimate Credential Rotation by DevOps Teams (~35% of FPs)

**Pattern:** Credential addition event followed by sign-ins from known CI/CD infrastructure IPs.

**How to confirm:**
- Check if `InitiatedByUser` is a known DevOps team member
- Verify the credential rotation is documented in a change management ticket
- Confirm that the `InitiatedByIP` is from corporate infrastructure or VPN
- Check if the rotation follows a predictable schedule (e.g., every 90 days)

**Tuning note:** Maintain an allowlist of DevOps users authorized for credential rotation. Credential additions by allowlisted users from corporate IPs can be auto-closed.

### FP Scenario 2: CI/CD Pipeline IP Changes (~30% of FPs)

**Pattern:** SP sign-ins from new IP addresses that belong to cloud-hosted CI/CD runner pools (GitHub Actions, Azure DevOps, GitLab CI).

**How to confirm:**
- Check if the new IPs belong to known cloud provider CIDR ranges (GitHub Actions IPs, Azure DevOps pool ranges)
- Verify the SP is documented as a CI/CD integration
- Check if the sign-in resources match the CI/CD pipeline's expected targets

**Tuning note:** GitHub Actions publishes its IP ranges via API (`https://api.github.com/meta`). Azure DevOps provides geographic IP ranges in documentation. Maintain these ranges as exclusions.

### FP Scenario 3: Multi-Region Deployments (~20% of FPs)

**Pattern:** SP sign-ins from multiple geographic regions that correspond to application deployment regions (e.g., US East + EU West + Southeast Asia).

**How to confirm:**
- Verify the application is documented as multi-region
- Check if sign-in locations match known Azure region IPs
- Confirm that resources accessed from each location are in the corresponding Azure region

**Tuning note:** Map application deployment regions to expected SP sign-in locations. Flag only sign-ins from countries/regions NOT in the deployment map.

---

## 10. MITRE ATT&CK Mapping

### Detection Coverage Matrix

| Technique ID | Technique Name | Tactic | Confidence | Query |
|---|---|---|---|---|
| **T1098.001** | **Account Manipulation: Additional Cloud Credentials** | **Persistence** | <span class="severity-badge severity-info">Confirmed</span> | **Q1, Q3, Q7** |
| T1078.004 | Valid Accounts: Cloud Accounts | Persistence, Defense Evasion | <span class="severity-badge severity-info">Confirmed</span> | Q2, Q4 |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Defense Evasion, Lateral Movement | <span class="severity-badge severity-info">Confirmed</span> | Q2, Q6A |
| T1528 | Steal Application Access Token | Credential Access | <span class="severity-badge severity-info">Confirmed</span> | Q3, Q6B |
| T1098 | Account Manipulation | Persistence | <span class="severity-badge severity-info">Confirmed</span> | Q1, Q5 |

### Attack Chains

**Chain 1: Credential Theft --> Persistent SP Access --> Data Exfiltration**
```
Developer commits client secret to public repo (T1528)
  --> Attacker discovers secret via GitHub search
  --> Authenticates as SP from attacker IP (T1078.004)
  --> Accesses Microsoft Graph Mail API (T1550.001)
  --> Reads all corporate email without MFA challenge
  --> Adds new client secret for persistence (T1098.001)
  --> Exfiltrates sensitive data for months
```

**Chain 2: Compromised Admin --> SP Credential Addition --> Lateral Movement**
```
Admin account compromised via phishing
  --> Attacker adds new secret to high-privilege SP (T1098.001)
  --> Authenticates as SP from attacker infrastructure (T1078.004)
  --> SP has Key Vault access -- retrieves database credentials (T1528)
  --> Accesses SQL databases, storage accounts (T1550.001)
  --> Creates new app registration for redundant access (T1098)
```

**Chain 3: Supply Chain --> OAuth App Abuse (Midnight Blizzard)**
```
Compromise third-party OAuth application
  --> Add credentials to existing trusted SP (T1098.001)
  --> SP already has admin-consented permissions
  --> Access Microsoft Graph with existing permissions (T1550.001)
  --> Enumerate users, read mail, access SharePoint (T1528)
  --> Create additional SPs for persistence (T1098)
  --> Maintain access across credential rotations
```

### Threat Actor Attribution

| Actor | Confidence | Key TTPs |
|---|---|---|
| **Midnight Blizzard (APT29/Nobelium)** | **HIGH** | Extensively abuses OAuth apps and SPs. Added credentials to Microsoft corporate SPs in 2023-2024. |
| **Storm-0558** | **HIGH** | Used compromised signing key to forge SP tokens. Accessed government email via SP authentication. |
| **LAPSUS$ (DEV-0537)** | **MEDIUM** | Targeted developer accounts to access SP credentials. Code repository mining for secrets. |
| **Scattered Spider (Octo Tempest)** | **MEDIUM** | Abuses SP permissions post-admin account compromise for lateral movement. |

---

## 11. Query Summary

| Query | Purpose | Tables | Step |
|---|---|---|---|
| Q1 | Service principal risk assessment and context | AuditLogs | 1 |
| Q2 | Service principal sign-in pattern analysis | AADServicePrincipalSignInLogs | 2 |
| Q3 | Credential lifecycle timeline | AuditLogs | 3 |
| Q3B | Workload Identity Federation abuse | AuditLogs | 3 |
| Q4 | 30-day SP behavior baseline [MANDATORY] | AADServicePrincipalSignInLogs | 4 |
| Q5 | Permission and API access audit | AuditLogs | 5 |
| Q6A | Azure resource access via SP | AzureActivity | 6A |
| Q6B | Key Vault access analysis | AzureDiagnostics | 6B |
| Q7 | Org-wide SP credential sweep | AuditLogs, AADServicePrincipalSignInLogs | 7 |

---

## Appendix A: Datatable Tests

### Test 1: Service Principal Sign-In Anomaly Detection

```kql
// ============================================================
// TEST 1: SP Sign-In Anomaly Detection
// Validates: Query 2 - Service principal sign-in pattern analysis
// Expected: contoso-api-prod flagged HIGH (mixed success/failure, 3 IPs)
//           contoso-backup-svc NOT flagged (single IP, all success)
// ============================================================
let TestSPSignInLogs = datatable(
    TimeGenerated: datetime,
    ServicePrincipalName: string,
    ServicePrincipalId: string,
    AppId: string,
    IPAddress: string,
    LocationDetails: dynamic,
    ResourceDisplayName: string,
    ResourceId: string,
    ResultType: string,
    ResultDescription: string,
    ConditionalAccessStatus: string,
    CorrelationId: string
) [
    // --- Malicious: contoso-api-prod sign-ins from 3 IPs, mixed success/failure ---
    datetime(2026-02-22T14:00:00Z), "contoso-api-prod", "sp-001", "app-001",
        "203.0.113.50", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "Microsoft Graph", "graph-001", "0", "Success", "notApplied", "corr-001",
    datetime(2026-02-22T14:05:00Z), "contoso-api-prod", "sp-001", "app-001",
        "198.51.100.10", dynamic({"city":"Bucharest","countryOrRegion":"RO"}),
        "Microsoft Graph", "graph-001", "7000215", "Invalid client secret", "notApplied", "corr-002",
    datetime(2026-02-22T14:10:00Z), "contoso-api-prod", "sp-001", "app-001",
        "192.0.2.100", dynamic({"city":"Lagos","countryOrRegion":"NG"}),
        "Microsoft Graph", "graph-001", "7000215", "Invalid client secret", "notApplied", "corr-003",
    datetime(2026-02-22T14:15:00Z), "contoso-api-prod", "sp-001", "app-001",
        "203.0.113.50", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "Azure Key Vault", "kv-001", "0", "Success", "notApplied", "corr-004",
    datetime(2026-02-22T14:20:00Z), "contoso-api-prod", "sp-001", "app-001",
        "203.0.113.50", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "Azure Storage", "storage-001", "0", "Success", "notApplied", "corr-005",
    // --- Benign: contoso-backup-svc from single IP, all success ---
    datetime(2026-02-22T14:00:00Z), "contoso-backup-svc", "sp-002", "app-002",
        "10.0.0.5", dynamic({"city":"Seattle","countryOrRegion":"US"}),
        "Azure Storage", "storage-002", "0", "Success", "notApplied", "corr-010",
    datetime(2026-02-22T14:30:00Z), "contoso-backup-svc", "sp-002", "app-002",
        "10.0.0.5", dynamic({"city":"Seattle","countryOrRegion":"US"}),
        "Azure Storage", "storage-002", "0", "Success", "notApplied", "corr-011",
    datetime(2026-02-22T15:00:00Z), "contoso-backup-svc", "sp-002", "app-002",
        "10.0.0.5", dynamic({"city":"Seattle","countryOrRegion":"US"}),
        "Azure Storage", "storage-002", "0", "Success", "notApplied", "corr-012"
];
// --- Run sign-in pattern analysis ---
TestSPSignInLogs
| summarize
    TotalSignIns = count(),
    Successes = countif(ResultType == "0"),
    Failures = countif(ResultType != "0"),
    UniqueIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 20),
    UniqueResources = dcount(ResourceDisplayName),
    ResourceList = make_set(ResourceDisplayName, 20),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 10)
    by ServicePrincipalName, ServicePrincipalId
| extend
    RiskAssessment = case(
        Failures > 0 and Successes > 0 and UniqueIPs > 3,
            "HIGH - Mixed success/failure from multiple IPs",
        UniqueIPs > 5,
            "HIGH - Sign-ins from many IPs",
        Failures > Successes and Failures > 5,
            "MEDIUM - Predominantly failing",
        UniqueResources > 5,
            "MEDIUM - Accessing many resources",
        "LOW - Standard activity pattern"
    )
// Expected: contoso-api-prod = HIGH (3 successes, 2 failures, 3 IPs, 3 countries)
// Expected: contoso-backup-svc = LOW (3 successes, 0 failures, 1 IP)
```

### Test 2: Credential Lifecycle Anomaly Detection

```kql
// ============================================================
// TEST 2: Credential Lifecycle Anomaly Detection
// Validates: Query 3 - Credential additions with actor attribution
// Expected: contoso-api-prod flagged HIGH (credential added by unknown user)
//           contoso-internal-app flagged LOW (credential added by known admin)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    Category: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string,
    CorrelationId: string
) [
    // --- Suspicious: Credential added by unknown user from external IP ---
    datetime(2026-02-22T13:00:00Z), "Add service principal credentials", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"compromised.user@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"contoso-api-prod","id":"sp-001","type":"ServicePrincipal",
            "modifiedProperties":[{"displayName":"KeyDescription","oldValue":"[]",
            "newValue":"[{\"DisplayName\":\"attacker-key\",\"Type\":2,\"Usage\":\"Verify\"}]"}]}]),
        "success", "corr-100",
    // --- Benign: Credential rotated by known admin from corporate IP ---
    datetime(2026-02-22T10:00:00Z), "Add service principal credentials", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"devops.admin@contoso.com","ipAddress":"10.0.0.1"}}),
        dynamic([{"displayName":"contoso-internal-app","id":"sp-003","type":"ServicePrincipal",
            "modifiedProperties":[{"displayName":"KeyDescription","oldValue":"[{\"DisplayName\":\"old-key\"}]",
            "newValue":"[{\"DisplayName\":\"rotated-key-2026\",\"Type\":2,\"Usage\":\"Verify\"}]"}]}]),
        "success", "corr-101",
    // --- Suspicious: Credential removed (covering tracks) ---
    datetime(2026-02-22T13:30:00Z), "Remove service principal credentials", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"compromised.user@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"contoso-api-prod","id":"sp-001","type":"ServicePrincipal",
            "modifiedProperties":[]}]),
        "success", "corr-102"
];
// --- Run credential lifecycle analysis ---
TestAuditLogs
| where OperationName in (
    "Add service principal credentials",
    "Remove service principal credentials"
)
| project
    TimeGenerated,
    OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    TargetSP = tostring(TargetResources[0].displayName),
    TargetSPId = tostring(TargetResources[0].id),
    Result
| extend
    CredentialAction = case(
        OperationName has "Add", "SECRET ADDED",
        OperationName has "Remove", "SECRET REMOVED",
        "OTHER"
    ),
    Severity = case(
        OperationName has "Add" and isempty(InitiatedByUser),
            "CRITICAL - Programmatic credential addition",
        OperationName has "Add",
            "HIGH - New credential added",
        OperationName has "Remove",
            "MEDIUM - Credential removed",
        "LOW"
    )
| sort by TimeGenerated asc
// Expected: contoso-api-prod shows HIGH (Add) and MEDIUM (Remove) by compromised.user from 203.0.113.50
// Expected: contoso-internal-app shows HIGH (Add) by devops.admin from 10.0.0.1 (known admin = FP)
```

### Test 3: Baseline Comparison

```kql
// ============================================================
// TEST 3: SP Baseline Comparison
// Validates: Query 4 - 30-day SP behavior baseline
// Expected: contoso-api-prod = "ANOMALOUS" (new country RU, new IPs)
//           contoso-backup-svc = "WITHIN NORMAL RANGE" (same IP, same resource)
// ============================================================
let TestSPSignInLogs = datatable(
    TimeGenerated: datetime,
    ServicePrincipalName: string,
    ServicePrincipalId: string,
    AppId: string,
    IPAddress: string,
    LocationDetails: dynamic,
    ResourceDisplayName: string,
    ResultType: string
) [
    // --- contoso-api-prod: 30-day baseline from US IPs only ---
    datetime(2026-01-25T09:00:00Z), "contoso-api-prod", "sp-001", "app-001",
        "10.0.0.10", dynamic({"countryOrRegion":"US"}), "Microsoft Graph", "0",
    datetime(2026-01-26T09:00:00Z), "contoso-api-prod", "sp-001", "app-001",
        "10.0.0.10", dynamic({"countryOrRegion":"US"}), "Microsoft Graph", "0",
    datetime(2026-02-10T09:00:00Z), "contoso-api-prod", "sp-001", "app-001",
        "10.0.0.10", dynamic({"countryOrRegion":"US"}), "Microsoft Graph", "0",
    datetime(2026-02-15T09:00:00Z), "contoso-api-prod", "sp-001", "app-001",
        "10.0.0.11", dynamic({"countryOrRegion":"US"}), "Microsoft Graph", "0",
    // Today: NEW IP from Russia + accessing Key Vault (never accessed before)
    datetime(2026-02-22T14:00:00Z), "contoso-api-prod", "sp-001", "app-001",
        "203.0.113.50", dynamic({"countryOrRegion":"RU"}), "Azure Key Vault", "0",
    datetime(2026-02-22T14:15:00Z), "contoso-api-prod", "sp-001", "app-001",
        "203.0.113.50", dynamic({"countryOrRegion":"RU"}), "Microsoft Graph", "0",
    // --- contoso-backup-svc: Consistent baseline, same today ---
    datetime(2026-01-25T02:00:00Z), "contoso-backup-svc", "sp-002", "app-002",
        "10.0.0.5", dynamic({"countryOrRegion":"US"}), "Azure Storage", "0",
    datetime(2026-01-26T02:00:00Z), "contoso-backup-svc", "sp-002", "app-002",
        "10.0.0.5", dynamic({"countryOrRegion":"US"}), "Azure Storage", "0",
    datetime(2026-02-10T02:00:00Z), "contoso-backup-svc", "sp-002", "app-002",
        "10.0.0.5", dynamic({"countryOrRegion":"US"}), "Azure Storage", "0",
    datetime(2026-02-15T02:00:00Z), "contoso-backup-svc", "sp-002", "app-002",
        "10.0.0.5", dynamic({"countryOrRegion":"US"}), "Azure Storage", "0",
    // Today: Same pattern
    datetime(2026-02-22T02:00:00Z), "contoso-backup-svc", "sp-002", "app-002",
        "10.0.0.5", dynamic({"countryOrRegion":"US"}), "Azure Storage", "0"
];
// --- Baseline comparison ---
let AlertTime = datetime(2026-02-22T14:30:00Z);
let BaselineDays = 30d;
let SPList = dynamic(["sp-001", "sp-002"]);
// Baseline: 30 days before alert
let BaselineData = TestSPSignInLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime - 1h)
| where ServicePrincipalId in (SPList) and ResultType == "0"
| summarize
    AllBaselineIPs = make_set(IPAddress),
    AllBaselineResources = make_set(ResourceDisplayName),
    AllBaselineCountries = make_set(tostring(LocationDetails.countryOrRegion))
    by ServicePrincipalName, ServicePrincipalId;
// Today
let TodayData = TestSPSignInLogs
| where TimeGenerated >= AlertTime - 24h and ResultType == "0"
| where ServicePrincipalId in (SPList)
| summarize
    TodayIPs = make_set(IPAddress),
    TodayResources = make_set(ResourceDisplayName),
    TodayCountries = make_set(tostring(LocationDetails.countryOrRegion))
    by ServicePrincipalName, ServicePrincipalId;
BaselineData
| join kind=inner TodayData on ServicePrincipalId
| extend
    NewIPs = set_difference(TodayIPs, AllBaselineIPs),
    NewResources = set_difference(TodayResources, AllBaselineResources),
    NewCountries = set_difference(TodayCountries, AllBaselineCountries)
| extend Assessment = case(
    array_length(NewCountries) > 0,
        "ANOMALOUS - Sign-in from new country never seen in baseline",
    array_length(NewIPs) > 0 and array_length(NewResources) > 0,
        "ANOMALOUS - New IPs AND new resources",
    array_length(NewIPs) > 0,
        "SUSPICIOUS - New IPs not seen in baseline",
    "WITHIN NORMAL RANGE"
)
| project ServicePrincipalName, NewIPs, NewResources, NewCountries, Assessment
// Expected: contoso-api-prod = "ANOMALOUS" (NewCountries=["RU"], NewIPs=["203.0.113.50"], NewResources=["Azure Key Vault"])
// Expected: contoso-backup-svc = "WITHIN NORMAL RANGE" (no new IPs, resources, or countries)
```

### Test 4: Org-Wide Credential Sweep

```kql
// ============================================================
// TEST 4: Org-Wide Credential Sweep
// Validates: Query 7 - Find all SPs with recently added credentials
// Expected: contoso-api-prod = HIGH (cred added + multi-IP sign-ins)
//           contoso-internal-app = LOW (cred added by admin, no sign-ins)
//           contoso-shadow-app = CRITICAL (programmatic cred addition + sign-ins)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- contoso-api-prod: Credential added by suspicious user ---
    datetime(2026-02-22T13:00:00Z), "Add service principal credentials",
        dynamic({"user":{"userPrincipalName":"compromised.user@contoso.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"contoso-api-prod","id":"sp-001","type":"ServicePrincipal"}]),
        "success",
    // --- contoso-internal-app: Credential added by known admin ---
    datetime(2026-02-20T10:00:00Z), "Add service principal credentials",
        dynamic({"user":{"userPrincipalName":"devops.admin@contoso.com","ipAddress":"10.0.0.1"}}),
        dynamic([{"displayName":"contoso-internal-app","id":"sp-003","type":"ServicePrincipal"}]),
        "success",
    // --- contoso-shadow-app: Credential added programmatically (no user) ---
    datetime(2026-02-22T12:00:00Z), "Add service principal credentials",
        dynamic({"app":{"displayName":"Unknown Automation Tool"}}),
        dynamic([{"displayName":"contoso-shadow-app","id":"sp-004","type":"ServicePrincipal"}]),
        "success"
];
let TestSPSignInLogs = datatable(
    TimeGenerated: datetime,
    ServicePrincipalName: string,
    ServicePrincipalId: string,
    IPAddress: string,
    LocationDetails: dynamic,
    ResourceDisplayName: string,
    ResultType: string
) [
    // --- contoso-api-prod: Sign-ins from 4 IPs ---
    datetime(2026-02-22T14:00:00Z), "contoso-api-prod", "sp-001", "203.0.113.50", dynamic({"countryOrRegion":"RU"}), "Microsoft Graph", "0",
    datetime(2026-02-22T14:10:00Z), "contoso-api-prod", "sp-001", "198.51.100.10", dynamic({"countryOrRegion":"RO"}), "Microsoft Graph", "0",
    datetime(2026-02-22T14:20:00Z), "contoso-api-prod", "sp-001", "192.0.2.100", dynamic({"countryOrRegion":"NG"}), "Microsoft Graph", "0",
    datetime(2026-02-22T14:30:00Z), "contoso-api-prod", "sp-001", "10.0.0.10", dynamic({"countryOrRegion":"US"}), "Microsoft Graph", "0",
    // --- contoso-shadow-app: Sign-ins from 5 IPs ---
    datetime(2026-02-22T13:00:00Z), "contoso-shadow-app", "sp-004", "203.0.113.51", dynamic({"countryOrRegion":"CN"}), "Microsoft Graph", "0",
    datetime(2026-02-22T13:10:00Z), "contoso-shadow-app", "sp-004", "203.0.113.52", dynamic({"countryOrRegion":"CN"}), "Azure Key Vault", "0",
    datetime(2026-02-22T13:20:00Z), "contoso-shadow-app", "sp-004", "198.51.100.20", dynamic({"countryOrRegion":"IR"}), "Microsoft Graph", "0",
    datetime(2026-02-22T13:30:00Z), "contoso-shadow-app", "sp-004", "192.0.2.200", dynamic({"countryOrRegion":"KP"}), "Azure Storage", "0"
    // --- contoso-internal-app: No sign-ins (dormant app) ---
];
// --- Run org-wide sweep ---
let CredAdditions = TestAuditLogs
| where OperationName == "Add service principal credentials"
| project
    CredentialAddedTime = TimeGenerated,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    TargetSP = tostring(TargetResources[0].displayName),
    TargetSPId = tostring(TargetResources[0].id);
let SPActivity = TestSPSignInLogs
| where ResultType == "0"
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 5)
    by ServicePrincipalName, ServicePrincipalId;
CredAdditions
| join kind=leftouter SPActivity on $left.TargetSPId == $right.ServicePrincipalId
| extend RiskLevel = case(
    isempty(InitiatedByUser) and isnotempty(SignInCount) and UniqueIPs > 3,
        "CRITICAL - Programmatic cred addition + multi-IP sign-ins",
    isnotempty(SignInCount) and UniqueIPs > 3,
        "HIGH - Cred addition + sign-ins from many IPs",
    isempty(InitiatedByUser),
        "HIGH - Programmatic credential addition",
    isnotempty(SignInCount),
        "MEDIUM - Credential added with subsequent sign-ins",
    "LOW - Credential added but no sign-in activity"
)
| project TargetSP, TargetSPId, InitiatedByUser, InitiatedByApp, SignInCount, UniqueIPs, Countries, RiskLevel
// Expected: contoso-shadow-app = "CRITICAL" (programmatic + 4 IPs from CN/IR/KP)
// Expected: contoso-api-prod = "HIGH" (cred addition + 4 IPs)
// Expected: contoso-internal-app = "LOW" (cred added by admin, no sign-ins)
```

---

## References

- [Microsoft: Securing workload identities](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview)
- [Microsoft: Application and service principal objects in Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals)
- [Microsoft: Manage app registrations - Certificates and secrets](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal)
- [Microsoft: AADServicePrincipalSignInLogs schema reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs)
- [Microsoft: Workload identity protection with Entra Workload ID](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-protection)
- [MITRE ATT&CK T1098.001 - Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
- [MITRE ATT&CK T1550.001 - Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [Midnight Blizzard Microsoft breach via OAuth app abuse (2024)](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [Storm-0558 token forging attack (2023)](https://www.microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/)
- [CISA: Detecting and responding to identity threats in cloud environments](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
