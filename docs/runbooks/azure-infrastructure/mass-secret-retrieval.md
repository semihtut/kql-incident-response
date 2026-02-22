---
title: "Mass Secret Retrieval from Key Vault"
id: RB-0007
severity: critical
status: reviewed
description: >
  Investigation runbook for mass enumeration and retrieval of secrets,
  keys, and certificates from Azure Key Vault. Covers AzureDiagnostics
  data plane analysis, caller identity resolution, access policy change
  detection, and org-wide vault sweep. Mass secret retrieval is a primary
  post-compromise technique — after gaining access to a subscription or
  service principal, attackers enumerate Key Vaults and dump all stored
  credentials to escalate privileges, move laterally, and access
  additional systems. This runbook targets Defender for Key Vault alerts
  and custom Sentinel analytics rules.
mitre_attack:
  tactics:
    - tactic_id: TA0006
      tactic_name: "Credential Access"
    - tactic_id: TA0009
      tactic_name: "Collection"
    - tactic_id: TA0010
      tactic_name: "Exfiltration"
    - tactic_id: TA0007
      tactic_name: "Discovery"
    - tactic_id: TA0008
      tactic_name: "Lateral Movement"
    - tactic_id: TA0003
      tactic_name: "Persistence"
  techniques:
    - technique_id: T1555
      technique_name: "Credentials from Password Stores"
      confidence: confirmed
    - technique_id: T1555.006
      technique_name: "Credentials from Password Stores: Cloud Secrets Management Stores"
      confidence: confirmed
    - technique_id: T1528
      technique_name: "Steal Application Access Token"
      confidence: confirmed
    - technique_id: T1087.004
      technique_name: "Account Discovery: Cloud Account"
      confidence: probable
    - technique_id: T1580
      technique_name: "Cloud Infrastructure Discovery"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: probable
    - technique_id: T1552.001
      technique_name: "Unsecured Credentials: Credentials in Files"
      confidence: probable
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Storm-0558"
  - "LAPSUS$ (DEV-0537)"
  - "Scattered Spider (Octo Tempest)"
  - "Storm-0501"
log_sources:
  - table: "AzureDiagnostics"
    product: "Azure Key Vault"
    license: "Free (diagnostic settings configured)"
    required: true
    alternatives: []
  - table: "AzureActivity"
    product: "Azure Resource Manager"
    license: "Free"
    required: true
    alternatives: []
  - table: "SecurityAlert"
    product: "Defender for Key Vault"
    license: "Microsoft Defender for Key Vault"
    required: false
    alternatives: ["AzureDiagnostics"]
  - table: "SigninLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "AADServicePrincipalSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: false
    alternatives: ["SigninLogs"]
  - table: "AuditLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-22
updated: 2026-02-22
version: "1.0"
tier: 3
category: azure-infrastructure
data_checks:
  - query: "AzureDiagnostics | where ResourceType == &quot;VAULTS&quot; | take 1"
    label: primary
    description: "Key Vault data plane operations"
  - query: "AzureActivity | take 1"
    description: "For control plane operations (access policy changes, vault creation/deletion)"
  - query: "SecurityAlert | where ProductName has &quot;Key Vault&quot; | take 1"
    label: optional
    description: "Defender for Key Vault alerts"
  - query: "SigninLogs | take 1"
    description: "For user identity context"
  - query: "AADServicePrincipalSignInLogs | take 1"
    description: "For service principal identity context"
  - query: "AuditLogs | take 1"
    description: "For directory changes (role assignments, app registrations)"
---

# Mass Secret Retrieval from Key Vault - Investigation Runbook

> **RB-0007** | Severity: Critical | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Defender for Key Vault + Sentinel Analytics (AzureDiagnostics)
>
> **Detection Operations:** `SecretGet`, `SecretList`, `KeyGet`, `KeyList`, `CertificateGet` volume anomalies
>
> **Primary MITRE Technique:** T1555.006 - Credentials from Password Stores: Cloud Secrets Management Stores

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Extract Defender for Key Vault Alert](#step-1-extract-defender-for-key-vault-alert)
   - [Step 2: Mass Secret Access Pattern Analysis](#step-2-mass-secret-access-pattern-analysis)
   - [Step 3: Caller Identity Resolution](#step-3-caller-identity-resolution)
   - [Step 4: Baseline Comparison - Establish Normal Secret Access Pattern](#step-4-baseline-comparison---establish-normal-secret-access-pattern)
   - [Step 5: Key Vault Access Policy and RBAC Changes](#step-5-key-vault-access-policy-and-rbac-changes)
   - [Step 6: Authentication Context and Lateral Movement](#step-6-authentication-context-and-lateral-movement)
   - [Step 7: Org-Wide Key Vault Sweep](#step-7-org-wide-key-vault-sweep)
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
Mass secret retrieval from Azure Key Vault is detected through two complementary mechanisms:

1. **Defender for Key Vault alert:** Microsoft Defender for Key Vault generates alerts when it detects unusual patterns of secret, key, or certificate access — including high-volume `SecretGet` operations, access from unusual IP addresses or identities, and access to secrets that have never been read before. These appear in the SecurityAlert table with `ProductName == "Azure Security Center"` and alert names like "Unusual access to Key Vault", "High volume of Key Vault operations", or "Access from a suspicious IP address".
2. **AzureDiagnostics pattern analysis:** Sentinel analytics rules monitor the AzureDiagnostics table (where `ResourceType == "VAULTS"`) for anomalous volume spikes in `SecretGet`, `SecretList`, `KeyGet`, `KeyList`, and `CertificateGet` operations. The defining pattern is: **many secrets accessed in rapid succession by a single identity, especially when that identity has not previously accessed those secrets.**

**Why it matters:**
Azure Key Vault is the centralized secrets store for cloud infrastructure. It holds database connection strings, API keys, storage account keys, service principal credentials, TLS certificates, and encryption keys. A successful mass retrieval gives the attacker credentials to access every system those secrets protect — databases, storage accounts, APIs, third-party services, and other Azure subscriptions. This is often the pivot point where a single compromised identity becomes a full environment breach.

**Why this is CRITICAL severity (the highest severity in this project):**
- Key Vault secrets typically grant direct access to production databases, storage accounts, and external APIs
- A single compromised service principal with Key Vault access can dump ALL secrets in ALL vaults it can reach
- Retrieved secrets remain valid even after the attacker's Azure access is revoked — every leaked secret must be individually rotated
- Attackers can use retrieved secrets to move laterally to systems outside Azure (on-premises databases, third-party SaaS, partner APIs)
- Storm-0558 used stolen signing keys (originally stored in Key Vault infrastructure) to forge authentication tokens for US government email accounts
- The blast radius is often enormous — a single vault can hold hundreds of secrets affecting dozens of production systems

**However:** This alert has a **low false positive rate** (~5-10%). Legitimate triggers include:
- Deployment pipelines (CI/CD) that retrieve multiple secrets during automated deployments
- Secret rotation scripts that read and write all secrets during a rotation cycle
- Backup or disaster recovery processes that copy secrets between vaults
- Application startup sequences that load multiple configuration secrets at boot time
- Security audits or compliance scans that enumerate vault contents

**Worst case scenario if this is real:**
An attacker has compromised a service principal, managed identity, or user account with Key Vault access permissions. They enumerate all Key Vaults in the subscription (via `az keyvault list`), then systematically dump every secret from every vault they can access. The retrieved credentials include: production database connection strings (direct access to customer data), storage account keys (access to blob containers with PII/financial data), API keys for third-party services (payment processors, email providers), and service principal credentials for other subscriptions. The attacker now has persistent, credential-based access to the entire infrastructure — independent of their original Azure foothold. Even after the original compromise is contained and the attacker's Azure access revoked, every retrieved secret remains valid until individually rotated. In the worst case, the attacker uses database credentials to exfiltrate customer data, storage keys to download sensitive files, and service principal credentials to pivot to other subscriptions or tenants.

**Key difference from other runbooks:**
- RB-0001 through RB-0006 and RB-0008 investigate identity-layer or email-layer threats. The assets at risk are user accounts, mailboxes, and sessions.
- **RB-0007 (This runbook):** The investigation targets the **Azure data plane** — specifically, secrets and credentials stored in Key Vault. The attacker has already passed the identity layer (they have a valid token). The focus is on **what infrastructure secrets they accessed and what those secrets unlock.** The critical question is: **"Which secrets were retrieved, what systems do they protect, and have those systems been accessed using the stolen credentials?"** This is the first runbook where the primary data source is AzureDiagnostics, not SigninLogs or OfficeActivity.

---

## 2. Prerequisites

### Minimum Required
- **License:** Azure subscription + Microsoft Sentinel
- **Diagnostic Settings:** Key Vault diagnostic logs enabled and sent to Log Analytics workspace (AuditEvent category)
- **Sentinel Connectors:** Azure Activity, Azure Diagnostics
- **Permissions:** Security Reader (investigation), Key Vault Administrator or Contributor (containment, secret rotation)

### Recommended for Full Coverage
- **License:** Microsoft Defender for Key Vault enabled on all subscriptions
- **Additional Connectors:** Microsoft Entra ID (SigninLogs, AADServicePrincipalSignInLogs), Defender for Cloud (SecurityAlert)
- **Key Vault Configuration:** Purge protection and soft-delete enabled, RBAC authorization model preferred over access policy model
- **Networking:** Key Vault firewall enabled with private endpoints for production vaults

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Azure + Sentinel (KV diagnostics enabled) | AzureDiagnostics, AzureActivity | Steps 2, 4, 5, 7 |
| Above + Defender for Key Vault | Above + SecurityAlert | Steps 1-2, 4-5, 7 |
| Above + Entra ID P1/P2 | Above + SigninLogs, AADServicePrincipalSignInLogs, AuditLogs | Steps 1-7 (full investigation) |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let TargetVault = "contoso-prod-kv";          // Key Vault name from the alert
let TargetSubscription = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"; // Subscription ID
let AlertTime = datetime(2026-02-22T08:15:00Z);  // Time the mass retrieval was detected
let LookbackWindow = 24h;                     // Window before alert for access analysis
let ForwardWindow = 24h;                      // Window after alert for lateral movement detection
let BaselineDays = 30d;                       // Baseline comparison window
let SecretGetThreshold = 10;                  // Minimum SecretGet operations to flag as "mass"
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- Defender for Key Vault alert for a production vault AND caller is an unfamiliar service principal or user
- 50+ `SecretGet` operations within 5 minutes from a single caller identity
- `SecretList` followed by `SecretGet` for every listed secret (full vault dump pattern)
- Caller IP address is outside of known corporate or Azure service IP ranges
- Access from a Tor exit node, VPN provider, or known malicious IP
- Caller identity is a user account (not a service principal) accessing an infrastructure vault

### Standard Investigation
- 10-49 `SecretGet` operations from a recognized service principal during non-deployment hours
- Defender for Key Vault alert with medium severity for a non-production vault
- Access from an unusual but not obviously malicious IP address

### Likely Benign
- Access occurs during a known deployment window and the caller is a CI/CD service principal
- Secret rotation script (identifiable by `SecretSet` operations accompanying `SecretGet`)
- Backup process that consistently accesses the same secrets on a daily/weekly schedule
- Application startup burst of 5-15 `SecretGet` operations from a known managed identity
- Security compliance scan from a recognized scanning tool identity

---

## 5. Investigation Steps

### Step 1: Extract Defender for Key Vault Alert

**Purpose:** Retrieve the Defender for Key Vault alert that triggered this investigation. The alert contains pre-analyzed information including the caller identity, accessed resource, alert severity, and detection reasoning. If no Defender alert exists (custom Sentinel rule triggered), skip to Step 2.

**Data needed:** SecurityAlert

```kql
// ============================================================
// QUERY 1: Defender for Key Vault Alert Extraction
// Purpose: Retrieve the original Defender for Key Vault alert details
// Tables: SecurityAlert
// Investigation Step: 1 - Extract Defender for Key Vault Alert
// ============================================================
let TargetVault = "contoso-prod-kv";
let AlertTime = datetime(2026-02-22T08:15:00Z);
let LookbackWindow = 24h;
// --- Find Defender for Key Vault alerts ---
SecurityAlert
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where ProductName has "Key Vault" or ProductName == "Azure Security Center"
| where AlertType has "KeyVault" or CompromisedEntity has TargetVault
// --- Extract alert details ---
| extend AlertDetails = parse_json(ExtendedProperties)
| extend
    CallerIdentity = tostring(AlertDetails["Caller"]),
    CallerIP = tostring(AlertDetails["Client IP Address"]),
    VaultName = tostring(AlertDetails["Key Vault Name"]),
    OperationCount = tostring(AlertDetails["Operation Count"]),
    AnomalyType = tostring(AlertDetails["Anomaly Type"]),
    ResourceId = tostring(AlertDetails["resourceId"])
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    CallerIdentity,
    CallerIP,
    VaultName,
    OperationCount,
    AnomalyType,
    Status,
    Tactics,
    Techniques,
    Entities = tostring(Entities),
    CompromisedEntity,
    RemediationSteps
| sort by TimeGenerated desc
```

**Performance Notes:**
- SecurityAlert table is typically small; queries are fast
- If no Defender for Key Vault license, this query returns empty results — proceed to Step 2

**Expected findings:**
- Alert with the specific vault name, caller identity, and operation count
- `AlertSeverity = "High"` or `"Medium"` depending on the anomaly type
- `CallerIdentity` reveals whether the accessor was a user, service principal, or managed identity
- `Tactics` and `Techniques` provide pre-mapped MITRE ATT&CK context from Defender

**Next action:**
- If alert found → Use CallerIdentity and CallerIP as pivot points for Steps 2-3
- If no alert (Sentinel custom rule) → Proceed to Step 2 to identify the anomalous access pattern directly

---

### Step 2: Mass Secret Access Pattern Analysis

**Purpose:** Analyze the AzureDiagnostics data plane logs to identify the exact pattern of secret, key, and certificate access. This reveals: how many secrets were accessed, what type of operations were performed (list vs. get), the timing pattern (burst vs. distributed), and whether the full vault was enumerated.

**Data needed:** AzureDiagnostics

```kql
// ============================================================
// QUERY 2: Mass Secret Access Pattern Analysis
// Purpose: Identify volume, timing, and scope of secret access operations
// Tables: AzureDiagnostics
// Investigation Step: 2 - Mass Secret Access Pattern Analysis
// ============================================================
let TargetVault = "contoso-prod-kv";
let AlertTime = datetime(2026-02-22T08:15:00Z);
let LookbackWindow = 24h;
let SecretGetThreshold = 10;
// --- Analyze Key Vault data plane operations ---
AzureDiagnostics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where ResourceType == "VAULTS"
| where Resource =~ TargetVault or ResourceId has TargetVault
| where OperationName in (
    "SecretGet", "SecretList", "SecretSet",
    "KeyGet", "KeyList", "KeySign", "KeyDecrypt",
    "CertificateGet", "CertificateList",
    "VaultGet", "VaultAccessPolicyChangedEventGridV2"
)
// --- Extract caller and operation details ---
| extend
    CallerObjectId = tostring(identity_claim_oid_s),
    CallerUPN = tostring(identity_claim_upn_s),
    CallerAppId = tostring(identity_claim_appid_s),
    CallerIPAddress = CallerIPAddress,
    SecretName = tostring(id_s),
    HttpStatus = httpStatusCode_d,
    ResultType
// --- Summarize access pattern per caller ---
| summarize
    TotalOperations = count(),
    SecretGets = countif(OperationName == "SecretGet"),
    SecretLists = countif(OperationName == "SecretList"),
    KeyGets = countif(OperationName == "KeyGet"),
    KeyLists = countif(OperationName == "KeyList"),
    CertGets = countif(OperationName == "CertificateGet"),
    UniqueSecretsAccessed = dcount(id_s),
    SuccessCount = countif(httpStatusCode_d == 200),
    FailureCount = countif(httpStatusCode_d != 200),
    SecretNames = make_set(id_s, 20),
    SourceIPs = make_set(CallerIPAddress, 5),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    Operations = make_set(OperationName)
    by CallerObjectId, CallerAppId, CallerUPN
// --- Flag mass retrieval ---
| extend
    AccessDuration = LastAccess - FirstAccess,
    HasListThenGet = SecretLists > 0 and SecretGets > 0,
    IsFullDump = SecretLists > 0 and SecretGets >= SecretGetThreshold
| extend Severity = case(
    IsFullDump and AccessDuration < 5m, "CRITICAL - Rapid full vault dump (List+Get pattern)",
    SecretGets >= 50, "CRITICAL - Mass secret retrieval (50+ secrets)",
    IsFullDump, "HIGH - List+Get pattern detected",
    SecretGets >= SecretGetThreshold, "HIGH - Elevated secret access volume",
    SecretGets >= 5, "MEDIUM - Moderate secret access",
    "LOW"
)
| where SecretGets >= 5 or SecretLists > 0
| sort by SecretGets desc
```

**Tuning Guidance:**
- Adjust `SecretGetThreshold` based on your environment. CI/CD pipelines may legitimately access 5-15 secrets per deployment
- The `SecretList + SecretGet` pattern (enumerate all, then retrieve all) is the strongest indicator of malicious intent
- `AccessDuration < 5m` with high volume strongly suggests automated/scripted access (not manual)

**Expected findings:**
- CRITICAL: A single caller reading 50+ secrets in rapid succession with a List-then-Get pattern
- HIGH: A caller accessing secrets they've never accessed before (cross-reference with baseline in Step 4)
- Failed operations (403 Forbidden) indicate the caller tried to access secrets beyond their permissions — still suspicious as it shows intent
- `CallerObjectId` is the primary pivot for identity resolution in Step 3

**Next action:**
- If CRITICAL/HIGH severity callers found → Note the `CallerObjectId` and `CallerAppId` for identity resolution
- If only LOW/MEDIUM → Check baseline in Step 4 to confirm this is expected behavior

---

### Step 3: Caller Identity Resolution

**Purpose:** Resolve the Key Vault caller identity (ObjectId/AppId) to a human-readable name and determine whether this is a user, service principal, managed identity, or application. Understanding the caller type determines the investigation path — a compromised user requires different containment than a compromised service principal.

**Data needed:** SigninLogs, AADServicePrincipalSignInLogs, AuditLogs

```kql
// ============================================================
// QUERY 3: Caller Identity Resolution
// Purpose: Resolve Key Vault caller ObjectId/AppId to identity details
// Tables: SigninLogs, AADServicePrincipalSignInLogs
// Investigation Step: 3 - Caller Identity Resolution
// ============================================================
let CallerObjectId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"; // From Step 2
let CallerAppId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";    // From Step 2
let AlertTime = datetime(2026-02-22T08:15:00Z);
let LookbackWindow = 24h;
// --- Part A: Check if caller is a user (interactive sign-in) ---
let UserIdentity = SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where UserId == CallerObjectId or AppId == CallerAppId
| summarize
    IdentityType = "User",
    DisplayName = take_any(UserDisplayName),
    UPN = take_any(UserPrincipalName),
    AppName = take_any(AppDisplayName),
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 5),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 5),
    RiskLevels = make_set(RiskLevelDuringSignIn),
    MfaUsed = make_set(tostring(MfaDetail.authMethod)),
    ClientApps = make_set(ClientAppUsed)
    by UserId;
// --- Part B: Check if caller is a service principal ---
let SPIdentity = AADServicePrincipalSignInLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where ServicePrincipalId == CallerObjectId or AppId == CallerAppId
| summarize
    IdentityType = "ServicePrincipal",
    DisplayName = take_any(ServicePrincipalName),
    UPN = "",
    AppName = take_any(AppDisplayName),
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 5),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 5),
    RiskLevels = make_set(RiskLevelDuringSignIn),
    MfaUsed = dynamic([]),
    ClientApps = dynamic([])
    by ServicePrincipalId
| project-rename UserId = ServicePrincipalId;
// --- Combine identity results ---
UserIdentity
| union SPIdentity
| extend
    RiskAssessment = case(
        IdentityType == "User" and tostring(RiskLevels) has "high", "CRITICAL - Human user with high risk sign-in accessing Key Vault",
        IdentityType == "User", "HIGH - Human user accessing infrastructure vault (unusual)",
        IdentityType == "ServicePrincipal" and UniqueIPs > 3, "HIGH - Service principal accessed from multiple IPs",
        IdentityType == "ServicePrincipal", "MEDIUM - Service principal access (verify legitimacy)",
        "UNKNOWN - Identity not found in sign-in logs"
    )
```

**Expected findings:**
- **User identity:** Human users accessing Key Vault directly is inherently suspicious for production vaults. Check if the user has a legitimate reason (DevOps, platform team).
- **Service principal:** Most legitimate Key Vault access comes from service principals. Check if the AppId corresponds to a known application in your environment.
- **Managed identity:** If CallerObjectId maps to a managed identity, the access came from an Azure resource (VM, App Service, Function). This is typically legitimate but could indicate a compromised workload.
- **No identity found:** If neither SigninLogs nor AADServicePrincipalSignInLogs contain the caller, it may be a managed identity (check AzureDiagnostics `identity_claim_xms_mirid_s` field) or a first-party Microsoft service.

**Next action:**
- User identity accessing production vault → High-priority investigation; check sign-in risk, MFA status, location
- Unfamiliar service principal → Check when it was created (Step 6), who created it, and what permissions it has
- Known CI/CD service principal → Proceed to baseline comparison (Step 4) to verify this is normal deployment behavior

---

### Step 4: Baseline Comparison - Establish Normal Secret Access Pattern

**Purpose:** Determine whether this volume and pattern of Key Vault access is normal for the identified caller. This is mandatory — you cannot distinguish a legitimate deployment pipeline from an attacker without understanding the historical access pattern.

**Data needed:** AzureDiagnostics

```kql
// ============================================================
// QUERY 4: Key Vault Access Baseline Comparison (MANDATORY)
// Purpose: Establish normal secret access pattern per caller identity
// Tables: AzureDiagnostics
// Investigation Step: 4 - Baseline Comparison
// ============================================================
let TargetVault = "contoso-prod-kv";
let CallerObjectId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"; // From Step 2
let AlertTime = datetime(2026-02-22T08:15:00Z);
let BaselineDays = 30d;
// --- Historical access pattern for this caller on this vault ---
let HistoricalAccess = AzureDiagnostics
| where TimeGenerated between ((AlertTime - BaselineDays) .. AlertTime)
| where ResourceType == "VAULTS"
| where Resource =~ TargetVault
| where identity_claim_oid_s == CallerObjectId
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "CertificateGet")
| extend IsAlertDay = TimeGenerated > (AlertTime - 24h);
// --- Baseline: Daily access pattern (excluding alert day) ---
let Baseline = HistoricalAccess
| where not(IsAlertDay)
| summarize
    DailyOps = count(),
    DailySecretGets = countif(OperationName == "SecretGet"),
    DailyUniqueSecrets = dcount(id_s)
    by bin(TimeGenerated, 1d)
| summarize
    AvgDailyOps = round(avg(DailyOps), 1),
    MaxDailyOps = max(DailyOps),
    AvgDailySecretGets = round(avg(DailySecretGets), 1),
    MaxDailySecretGets = max(DailySecretGets),
    AvgDailyUniqueSecrets = round(avg(DailyUniqueSecrets), 1),
    MaxDailyUniqueSecrets = max(DailyUniqueSecrets),
    DaysWithAccess = count(),
    BaselineSecrets = make_set_if(tostring(HistoricalAccess | where not(IsAlertDay) | distinct id_s), true);
// --- Alert day: What happened today ---
let AlertDay = HistoricalAccess
| where IsAlertDay
| summarize
    TodayOps = count(),
    TodaySecretGets = countif(OperationName == "SecretGet"),
    TodayUniqueSecrets = dcount(id_s),
    TodaySecrets = make_set(id_s, 50);
// --- Compute all baseline secrets for "new secret" detection ---
let BaselineSecretSet = HistoricalAccess
| where not(IsAlertDay)
| distinct id_s;
let NewSecrets = HistoricalAccess
| where IsAlertDay
| where OperationName == "SecretGet"
| distinct id_s
| join kind=leftanti BaselineSecretSet on id_s
| summarize NewSecretCount = count(), NewSecretNames = make_set(id_s, 20);
// --- Compare ---
Baseline
| join kind=cross AlertDay
| join kind=cross NewSecrets
| extend Assessment = case(
    isempty(AvgDailyOps) or AvgDailyOps == 0, "NEW CALLER - Never accessed this vault before (CRITICAL)",
    TodaySecretGets > MaxDailySecretGets * 5, "ANOMALOUS - 5x above maximum historical access (CRITICAL)",
    TodaySecretGets > MaxDailySecretGets * 2, "ELEVATED - 2x above maximum historical access (HIGH)",
    NewSecretCount > 5, "NEW SECRETS - Accessing secrets never accessed before (HIGH)",
    TodaySecretGets > MaxDailySecretGets, "ABOVE NORMAL - Exceeds historical maximum",
    "WITHIN NORMAL RANGE"
)
| project
    Assessment,
    TodayOps, TodaySecretGets, TodayUniqueSecrets,
    AvgDailyOps, MaxDailyOps, AvgDailySecretGets, MaxDailySecretGets,
    DaysWithAccess,
    NewSecretCount, NewSecretNames
```

**Performance Notes:**
- 30-day AzureDiagnostics lookback scoped to a single vault and single caller is lightweight
- The "new secrets" join identifies secrets the caller has never accessed before — a strong indicator of exploration/enumeration

**Expected findings:**
- `NEW CALLER` is the strongest indicator — an identity that never accessed this vault before is now mass-retrieving secrets
- `ANOMALOUS` combined with `NewSecretCount > 5` indicates the caller is accessing secrets outside their normal pattern
- `WITHIN NORMAL RANGE` from a known CI/CD pipeline during a deployment window is likely benign
- Check `NewSecretNames` for secrets that are outside the caller's expected scope (e.g., a web app SP accessing database credentials it doesn't normally use)

**Next action:**
- `NEW CALLER` or `ANOMALOUS` → Escalate and continue to Step 5 to check for access policy changes
- `WITHIN NORMAL RANGE` → Likely benign; verify with the application team and close
- `NEW SECRETS` → Even if the volume is normal, accessing new secrets suggests scope expansion; investigate further

---

### Step 5: Key Vault Access Policy and RBAC Changes

**Purpose:** Determine whether the attacker modified Key Vault access policies or Azure RBAC role assignments to grant themselves secret access before the mass retrieval. Access policy changes are a strong pre-attack indicator — the attacker first grants themselves permissions, then retrieves secrets.

**Data needed:** AzureActivity, AuditLogs

```kql
// ============================================================
// QUERY 5: Key Vault Access Policy and RBAC Changes
// Purpose: Detect access policy or role assignment changes preceding secret access
// Tables: AzureActivity, AuditLogs
// Investigation Step: 5 - Key Vault Access Policy and RBAC Changes
// ============================================================
let TargetVault = "contoso-prod-kv";
let AlertTime = datetime(2026-02-22T08:15:00Z);
let LookbackWindow = 72h;
// --- Part A: Key Vault access policy changes (control plane) ---
let AccessPolicyChanges = AzureActivity
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where ResourceProviderValue =~ "MICROSOFT.KEYVAULT"
| where OperationNameValue has_any (
    "MICROSOFT.KEYVAULT/VAULTS/WRITE",
    "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE",
    "MICROSOFT.KEYVAULT/VAULTS/DELETE"
)
| where _ResourceId has TargetVault or Properties has TargetVault
| extend
    Caller = tostring(parse_json(Claims).http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn),
    CallerIP = CallerIpAddress,
    ChangeDetails = tostring(Properties)
| project
    TimeGenerated,
    OperationType = OperationNameValue,
    Caller,
    CallerIP,
    ActivityStatusValue,
    ChangeDetails,
    CorrelationId,
    Category = "AccessPolicyChange";
// --- Part B: RBAC role assignments for Key Vault ---
let RBACChanges = AzureActivity
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where OperationNameValue has "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where Properties has "Microsoft.KeyVault" or Properties has TargetVault
| extend
    Caller = tostring(parse_json(Claims).http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn),
    CallerIP = CallerIpAddress,
    ChangeDetails = tostring(Properties)
| project
    TimeGenerated,
    OperationType = OperationNameValue,
    Caller,
    CallerIP,
    ActivityStatusValue,
    ChangeDetails,
    CorrelationId,
    Category = "RBACAssignment";
// --- Part C: Service principal creation/modification (attacker may have created a new SP) ---
let SPChanges = AuditLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where OperationName in (
    "Add service principal",
    "Add service principal credentials",
    "Add app role assignment to service principal",
    "Update application - Certificates and secrets management"
)
| extend
    Caller = tostring(InitiatedBy.user.userPrincipalName),
    TargetSP = tostring(TargetResources[0].displayName),
    TargetSPId = tostring(TargetResources[0].id)
| project
    TimeGenerated,
    OperationType = OperationName,
    Caller,
    CallerIP = "",
    ActivityStatusValue = Result,
    ChangeDetails = tostring(TargetResources[0].modifiedProperties),
    CorrelationId,
    Category = "ServicePrincipalChange";
// --- Combine all pre-attack changes ---
AccessPolicyChanges
| union RBACChanges
| union SPChanges
| sort by TimeGenerated asc
| extend
    RiskIndicator = case(
        Category == "AccessPolicyChange" and TimeGenerated < AlertTime, "CRITICAL - Access policy modified before secret access",
        Category == "RBACAssignment" and ChangeDetails has "Key Vault", "HIGH - Key Vault RBAC role assigned",
        Category == "ServicePrincipalChange" and OperationType has "credentials", "HIGH - New credentials added to service principal",
        Category == "ServicePrincipalChange" and OperationType has "Add service principal", "MEDIUM - New service principal created",
        "INFO - Change detected"
    )
```

**Expected findings:**
- Access policy change shortly before mass retrieval = attacker granted themselves access, then dumped secrets
- New service principal with Key Vault RBAC role assignment = attacker created a dedicated identity for secret access
- Credential addition to existing service principal = attacker added their own key/certificate to an existing SP
- If NO changes found → The caller already had permissions; investigate how those permissions were originally granted

**Next action:**
- If pre-attack access policy changes found → The caller who made those changes is likely the attacker (or their compromised identity)
- If new SP created → This is the attacker's infrastructure; revoke immediately
- If no changes → Check Step 6 for authentication context of the existing identity

---

### Step 6: Authentication Context and Lateral Movement

**Purpose:** Analyze how the caller identity authenticated to Azure and check whether retrieved secrets have already been used to access other systems. This step traces the full attack chain: initial access → Key Vault compromise → lateral movement via stolen secrets.

**Data needed:** SigninLogs, AADServicePrincipalSignInLogs, AzureDiagnostics

```kql
// ============================================================
// QUERY 6: Authentication Context and Lateral Movement Detection
// Purpose: Trace how the caller authenticated and if stolen secrets were used
// Tables: SigninLogs, AADServicePrincipalSignInLogs, AzureDiagnostics
// Investigation Step: 6 - Authentication Context and Lateral Movement
// ============================================================
let CallerObjectId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"; // From Step 2
let CallerAppId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";    // From Step 2
let AlertTime = datetime(2026-02-22T08:15:00Z);
let ForwardWindow = 24h;
// --- Part A: How did the caller authenticate? ---
let AuthContext = SigninLogs
| where TimeGenerated between ((AlertTime - 4h) .. (AlertTime + 1h))
| where UserId == CallerObjectId or AppId == CallerAppId
| project
    TimeGenerated,
    AuthType = "UserSignIn",
    Identity = UserPrincipalName,
    IPAddress,
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    AppDisplayName,
    ClientAppUsed,
    MfaMethod = tostring(MfaDetail.authMethod),
    RiskLevel = RiskLevelDuringSignIn,
    ConditionalAccessStatus,
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged)
| union (
    AADServicePrincipalSignInLogs
    | where TimeGenerated between ((AlertTime - 4h) .. (AlertTime + 1h))
    | where ServicePrincipalId == CallerObjectId or AppId == CallerAppId
    | project
        TimeGenerated,
        AuthType = "ServicePrincipalSignIn",
        Identity = ServicePrincipalName,
        IPAddress,
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        AppDisplayName = "",
        ClientAppUsed = "",
        MfaMethod = "",
        RiskLevel = RiskLevelDuringSignIn,
        ConditionalAccessStatus = "",
        IsCompliant = "",
        IsManaged = ""
)
| sort by TimeGenerated asc;
// --- Part B: Post-secret-retrieval activity across ALL vaults ---
// Check if the attacker moved to other Key Vaults after the initial dump
let PostRetrievalActivity = AzureDiagnostics
| where TimeGenerated between (AlertTime .. (AlertTime + ForwardWindow))
| where ResourceType == "VAULTS"
| where identity_claim_oid_s == CallerObjectId
    or identity_claim_appid_s == CallerAppId
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "KeyList", "CertificateGet")
| summarize
    OpsCount = count(),
    UniqueSecrets = dcount(id_s),
    Vaults = make_set(Resource, 10)
    by identity_claim_oid_s, CallerIPAddress, bin(TimeGenerated, 1h)
| sort by TimeGenerated asc;
// --- Output combined view ---
AuthContext
```

**Expected findings:**
- Part A: Authentication from an unusual IP/country, or without MFA, suggests compromised credentials
- Part A: Service principal authenticating from an IP outside known Azure service ranges suggests stolen credentials
- Part B: Access to multiple vaults after the initial vault dump confirms the attacker is systematically sweeping the environment
- Part B: Look for vault access from new IPs that appeared after the initial compromise

**Next action:**
- If attacker accessed multiple vaults → Scope the incident to all affected vaults; each vault's secrets need rotation
- If authentication came from a compromised user → Cross-reference with identity runbooks (RB-0001 through RB-0006) for the user compromise vector
- If service principal credentials were stolen → Check where those credentials are stored (another Key Vault? CI/CD pipeline? Code repository?)

---

### Step 7: Org-Wide Key Vault Sweep

**Purpose:** Determine if this incident is isolated to a single vault or part of a broader campaign targeting multiple Key Vaults across the subscription or tenant. Also detect other identities performing similar mass retrieval patterns in the same timeframe.

**Data needed:** AzureDiagnostics

```kql
// ============================================================
// QUERY 7: Org-Wide Key Vault Mass Retrieval Sweep
// Purpose: Detect mass retrieval across ALL Key Vaults in the environment
// Tables: AzureDiagnostics
// Investigation Step: 7 - Org-Wide Key Vault Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T08:15:00Z);
let SweepWindow = 7d;
let SecretGetThreshold = 10;
// --- Find all Key Vault access across the environment ---
AzureDiagnostics
| where TimeGenerated between ((AlertTime - SweepWindow) .. (AlertTime + 1d))
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "KeyList", "CertificateGet", "CertificateList")
// --- Summarize per vault per caller per day ---
| summarize
    TotalOps = count(),
    SecretGets = countif(OperationName == "SecretGet"),
    SecretLists = countif(OperationName == "SecretList"),
    UniqueSecretsAccessed = dcount(id_s),
    SourceIPs = make_set(CallerIPAddress, 5),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by Resource, identity_claim_oid_s, identity_claim_appid_s, bin(TimeGenerated, 1d)
// --- Flag anomalous patterns ---
| where SecretGets >= SecretGetThreshold or SecretLists > 0
| extend
    CallerKey = strcat(identity_claim_oid_s, " / ", identity_claim_appid_s),
    HasListGetPattern = SecretLists > 0 and SecretGets > 0
| extend CampaignRisk = case(
    HasListGetPattern and SecretGets >= 50, "CRITICAL - Full vault dump detected",
    SecretGets >= 50, "CRITICAL - Mass secret retrieval",
    HasListGetPattern and SecretGets >= SecretGetThreshold, "HIGH - Suspicious List+Get pattern",
    SecretGets >= SecretGetThreshold, "MEDIUM - Elevated secret access",
    "LOW"
)
| where CampaignRisk in ("CRITICAL", "HIGH", "MEDIUM")
// --- Look for cross-vault campaigns (same caller hitting multiple vaults) ---
| summarize
    AffectedVaults = dcount(Resource),
    VaultNames = make_set(Resource, 20),
    TotalSecretGets = sum(SecretGets),
    MaxSingleVaultGets = max(SecretGets),
    HighestRisk = max(CampaignRisk),
    SourceIPs = make_set(SourceIPs, 10)
    by CallerKey
| extend ScopeAssessment = case(
    AffectedVaults >= 3, "CRITICAL - Cross-vault campaign (3+ vaults targeted)",
    AffectedVaults == 2, "HIGH - Multiple vaults targeted by same identity",
    "ISOLATED - Single vault affected"
)
| sort by AffectedVaults desc, TotalSecretGets desc
```

**Expected findings:**
- `CRITICAL - Cross-vault campaign`: Same identity systematically dumping secrets from multiple vaults — this is a full environment compromise
- Multiple different identities showing mass retrieval patterns in the same timeframe suggests the attacker compromised multiple accounts
- Time clustering of high-volume access across vaults reveals the attacker's operational window
- If only the originally alerted vault is affected → Isolated incident with limited blast radius

**Next action:**
- If cross-vault campaign → Full incident response: all affected vaults' secrets must be rotated, all involved identities must be disabled
- If isolated → Focus containment on the single vault; rotate only those secrets

---

## 6. Containment Playbook

### Immediate Actions (Within 15 Minutes)

1. **Disable the caller identity** — If it's a user: disable the Entra ID account. If it's a service principal: disable the application registration or remove its credentials.
   - User: `Set-AzureADUser -ObjectId <ObjectId> -AccountEnabled $false`
   - Service Principal: `Remove-AzureADServicePrincipalKeyCredential` / `Remove-AzureADServicePrincipalPasswordCredential`
2. **Revoke Key Vault access** — Remove the caller's access policy or RBAC role assignment from ALL affected vaults:
   - Access Policy: `Remove-AzKeyVaultAccessPolicy -VaultName <vault> -ObjectId <callerObjectId>`
   - RBAC: `Remove-AzRoleAssignment -ObjectId <callerObjectId> -RoleDefinitionName "Key Vault Secrets User"`
3. **Enable Key Vault firewall** — If not already enabled, immediately restrict network access to the vault to only known IP ranges or private endpoints
4. **Revoke all active sessions** for the caller identity

### Conditional Actions

5. **If access policy was modified by attacker** → Revert to the previous access policy configuration from Azure Activity logs
6. **If attacker created a new service principal** → Delete the service principal entirely: `Remove-AzureADServicePrincipal`
7. **If production database connection strings were retrieved** → Immediately rotate database passwords and connection strings
8. **If storage account keys were retrieved** → Regenerate storage account keys: `New-AzStorageAccountKey`
9. **If API keys for third-party services were retrieved** → Contact each service provider to revoke and reissue keys

### Follow-up (Within 4 Hours)

10. **Rotate ALL secrets in affected vaults** — Every secret that could have been retrieved must be rotated. Use the `SecretNames` list from Step 2 to prioritize, but assume all secrets in the vault are compromised
11. **Audit all systems accessed by stolen credentials** — Check logs of every system whose credentials were stored in the compromised vault
12. **Review Key Vault access policies** across the environment — Remove unnecessary access, enforce least-privilege
13. **Enable Defender for Key Vault** if not already active on all subscriptions

### Extended (Within 24 Hours)

14. **Implement Key Vault network restrictions** — Private endpoints for all production vaults, firewall rules for non-production
15. **Enable soft-delete and purge protection** on all Key Vaults (prevents attackers from deleting vaults to cover tracks)
16. **Review service principal lifecycle** — Remove unused SPs, rotate credentials on a schedule, implement credential expiration policies
17. **Configure Key Vault diagnostic settings** for any vaults not currently sending logs to Sentinel
18. **Incident retrospective** — Document the attack chain, update detection rules, improve access controls

---

## 7. Evidence Collection Checklist

- [ ] Full AzureDiagnostics export for the affected vault(s) (30-day window)
- [ ] List of all secrets accessed (names, access times, caller identities)
- [ ] AzureActivity log showing any access policy or RBAC changes in the 72 hours before the incident
- [ ] Caller identity details: ObjectId, AppId, type (user/SP/managed identity), creation date
- [ ] Authentication logs for the caller identity (SigninLogs or AADServicePrincipalSignInLogs)
- [ ] Key Vault access policy snapshot (current and before the incident): `Get-AzKeyVaultAccessPolicy`
- [ ] Service principal credential inventory: what key/certificate was used to authenticate
- [ ] Network context: CallerIPAddress geolocation, ASN, VPN/proxy indicators
- [ ] List of all systems whose credentials were stored in the compromised vault
- [ ] Evidence of whether stolen secrets were subsequently used (check target system logs)
- [ ] SecurityAlert records from Defender for Key Vault (if applicable)
- [ ] If SP was compromised: how were its credentials stored? (code repo, pipeline, another vault)

---

## 8. Escalation Criteria

### Escalate to Incident Commander
- Multiple Key Vaults compromised across the environment (cross-vault campaign)
- Production database credentials or customer-data storage keys were retrieved
- The caller identity has Owner or Contributor role at the subscription level
- Evidence that stolen secrets have already been used to access target systems

### Escalate to Threat Intelligence
- The caller IP appears in threat intelligence feeds or matches known APT infrastructure
- The attack pattern matches known cloud-native TTPs (e.g., Storm-0558 signing key theft)
- A new service principal was created with characteristics matching known attacker tooling
- The compromised identity was accessed via token theft or adversary-in-the-middle techniques

### Escalate to Legal/Compliance
- Customer data was accessible via stolen credentials (database connection strings, storage keys)
- Encryption keys were retrieved (potential data confidentiality breach)
- The compromised vault stored secrets for regulated systems (PCI, HIPAA, SOX, GDPR)
- The incident may require breach notification to customers or regulators
- Third-party API keys were compromised (contractual notification obligations)

---

## 9. False Positive Documentation

### FP Scenario 1: CI/CD Deployment Pipeline
**Pattern:** Automated deployment pipeline (Azure DevOps, GitHub Actions) retrieves multiple secrets during application deployment. Access occurs during known deployment windows, from a recognized service connection IP, and the same secrets are accessed every deployment.
**How to confirm:** Correlate the access time with deployment pipeline runs. Verify the caller AppId matches the known deployment service connection. Check that the same secrets are accessed in every deployment (no new secrets).
**Tuning note:** Create a Sentinel watchlist of known CI/CD service principal ObjectIds and exclude them from the mass retrieval alert, or raise the threshold for these identities.

### FP Scenario 2: Secret Rotation Script
**Pattern:** Automated secret rotation reads current secret values before writing new ones. This produces a burst of `SecretGet` operations followed by `SecretSet` operations. Typically runs on a schedule (weekly/monthly).
**How to confirm:** Verify `SecretSet` operations follow `SecretGet` operations within the same session. Check the caller is a known rotation automation identity. Confirm the schedule matches known rotation cadence.
**Tuning note:** Alert on `SecretGet` without corresponding `SecretSet` (retrieval without rotation is more suspicious).

### FP Scenario 3: Application Startup / Scale-Out
**Pattern:** Application instances loading configuration secrets at startup. When an App Service, AKS cluster, or VM scale set scales out, each new instance reads its secrets from Key Vault, creating a burst of `SecretGet` operations from the same managed identity.
**How to confirm:** Correlate the burst timing with auto-scale events or deployment slot swaps. Verify the caller is the application's managed identity. Check that only the expected secrets are accessed.
**Tuning note:** Set per-identity thresholds based on the maximum expected scale-out. Application managed identities typically access 3-10 specific secrets consistently.

### FP Scenario 4: Disaster Recovery / Vault Replication
**Pattern:** DR process copies secrets from primary vault to secondary vault in another region. Produces a full vault read (SecretList + SecretGet for all secrets) on a scheduled basis.
**How to confirm:** Verify the caller is the DR automation identity. Check that access corresponds to DR testing or failover schedules. Confirm the destination vault is in the expected DR region.
**Tuning note:** Whitelist the DR service principal and expected schedule. Alert only if DR runs outside the scheduled window.

---

## 10. MITRE ATT&CK Mapping

### Detection Coverage Matrix

| Technique ID | Technique Name | Tactic | Confidence | Query |
|---|---|---|---|---|
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | Credential Access | **Confirmed** | Q2, Q4, Q7 |
| T1555 | Credentials from Password Stores | Credential Access | **Confirmed** | Q2 |
| T1528 | Steal Application Access Token | Credential Access | **Confirmed** | Q3, Q6 |
| T1580 | Cloud Infrastructure Discovery | Discovery | **Confirmed** | Q2 (SecretList), Q7 |
| T1087.004 | Account Discovery: Cloud Account | Discovery | **Probable** | Q5 |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | **Confirmed** | Q3, Q6 |
| T1098 | Account Manipulation | Persistence | **Probable** | Q5 |
| T1552.001 | Unsecured Credentials: Credentials in Files | Credential Access | **Probable** | Q6 |

### Attack Chains

**Chain 1: Compromised User → Key Vault Dump → Database Exfiltration**
```
Phishing / credential theft targeting cloud admin (T1078.004)
  → Attacker enumerates subscriptions and Key Vaults (T1580)
  → SecretList + SecretGet on all vaults (T1555.006)
  → Retrieved: production SQL connection strings, storage keys
  → Direct database access via stolen connection string
  → Customer data exfiltration (T1530)
```

**Chain 2: Compromised Service Principal → Multi-Vault Sweep → Full Environment Access**
```
Stolen SP credentials from code repository / CI pipeline (T1552.001)
  → SP authenticates to Azure with stored credentials (T1078.004)
  → Enumerate all Key Vaults across subscriptions (T1580)
  → Mass secret retrieval from each accessible vault (T1555.006)
  → Use retrieved SP credentials to pivot to other subscriptions (T1528)
  → Persistent access via multiple credential sets
```

**Chain 3: Access Policy Modification → Privilege Escalation → Key Theft**
```
Attacker with limited Azure access (Reader role) (T1078.004)
  → Escalates to Contributor via RBAC misconfiguration (T1098)
  → Modifies Key Vault access policy to add themselves (T1098)
  → Retrieves all secrets, keys, and certificates (T1555.006)
  → Exports encryption keys for offline decryption
  → Long-term persistent access to encrypted data stores
```

### Threat Actor Attribution

| Actor | Confidence | Key TTPs |
|---|---|---|
| **Midnight Blizzard (APT29)** | **HIGH** | Targeted OAuth app permissions and Key Vault access in Microsoft corporate tenant breach (2023-2024). |
| **Storm-0558** | **HIGH** | Stole MSA signing key from Azure infrastructure — the most consequential Key Vault-adjacent attack. Forged tokens for US government email. |
| **LAPSUS$ (DEV-0537)** | **MEDIUM** | Targeted cloud infrastructure credentials and secrets in multiple large technology company breaches. |
| **Scattered Spider (Octo Tempest)** | **MEDIUM** | Known to enumerate cloud resources including Key Vaults after gaining initial access via social engineering. |
| **Storm-0501** | **MEDIUM** | Ransomware actor known to target Azure environments and exfiltrate Key Vault secrets before deploying ransomware. |

---

## 11. Query Summary

| Query | Purpose | Tables | Step |
|---|---|---|---|
| Q1 | Defender for Key Vault alert extraction | SecurityAlert | 1 |
| Q2 | Mass secret access pattern analysis | AzureDiagnostics | 2 |
| Q3 | Caller identity resolution | SigninLogs, AADServicePrincipalSignInLogs | 3 |
| Q4 | 30-day secret access baseline [MANDATORY] | AzureDiagnostics | 4 |
| Q5 | Key Vault access policy and RBAC changes | AzureActivity, AuditLogs | 5 |
| Q6 | Authentication context and lateral movement | SigninLogs, AADServicePrincipalSignInLogs, AzureDiagnostics | 6 |
| Q7 | Org-wide Key Vault mass retrieval sweep | AzureDiagnostics | 7 |

---

## Appendix A: Datatable Tests

### Test 1: Mass Secret Access Pattern Detection

```kql
// ============================================================
// TEST 1: Mass Secret Access Pattern Detection
// Validates: Query 2 - Identifies mass retrieval vs normal access
// Expected: attacker-sp = CRITICAL (List+Get, 15 secrets in 2 minutes)
//           deploy-sp = LOW (5 secrets, normal deployment pattern)
// ============================================================
let TestAzureDiagnostics = datatable(
    TimeGenerated: datetime,
    ResourceType: string,
    Resource: string,
    OperationName: string,
    identity_claim_oid_s: string,
    identity_claim_appid_s: string,
    identity_claim_upn_s: string,
    CallerIPAddress: string,
    id_s: string,
    httpStatusCode_d: double,
    ResultType: string
) [
    // --- Malicious: Attacker SP does SecretList then SecretGet on all secrets ---
    datetime(2026-02-22T08:15:00Z), "VAULTS", "contoso-prod-kv", "SecretList", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "", 200, "Success",
    datetime(2026-02-22T08:15:02Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "db-connection-string", 200, "Success",
    datetime(2026-02-22T08:15:04Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "storage-account-key", 200, "Success",
    datetime(2026-02-22T08:15:06Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "redis-password", 200, "Success",
    datetime(2026-02-22T08:15:08Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "api-key-stripe", 200, "Success",
    datetime(2026-02-22T08:15:10Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "api-key-sendgrid", 200, "Success",
    datetime(2026-02-22T08:15:12Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "jwt-signing-key", 200, "Success",
    datetime(2026-02-22T08:15:14Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "sp-client-secret-01", 200, "Success",
    datetime(2026-02-22T08:15:16Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "sp-client-secret-02", 200, "Success",
    datetime(2026-02-22T08:15:18Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "cosmos-db-key", 200, "Success",
    datetime(2026-02-22T08:15:20Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "eventhub-connection", 200, "Success",
    datetime(2026-02-22T08:15:22Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "servicebus-key", 200, "Success",
    datetime(2026-02-22T08:15:24Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "encryption-master-key", 200, "Success",
    datetime(2026-02-22T08:15:26Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "backup-storage-key", 200, "Success",
    datetime(2026-02-22T08:15:28Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "partner-api-key", 200, "Success",
    datetime(2026-02-22T08:15:30Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "", "203.0.113.50", "ldap-bind-password", 200, "Success",
    // --- Benign: Deploy SP reads 5 known secrets during deployment ---
    datetime(2026-02-22T09:00:00Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "app-deploy", "", "10.0.0.100", "db-connection-string", 200, "Success",
    datetime(2026-02-22T09:00:01Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "app-deploy", "", "10.0.0.100", "redis-password", 200, "Success",
    datetime(2026-02-22T09:00:02Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "app-deploy", "", "10.0.0.100", "api-key-stripe", 200, "Success",
    datetime(2026-02-22T09:00:03Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "app-deploy", "", "10.0.0.100", "storage-account-key", 200, "Success",
    datetime(2026-02-22T09:00:04Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "app-deploy", "", "10.0.0.100", "cosmos-db-key", 200, "Success"
];
// --- Run mass retrieval detection ---
let SecretGetThreshold = 10;
TestAzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "CertificateGet")
| summarize
    TotalOps = count(),
    SecretGets = countif(OperationName == "SecretGet"),
    SecretLists = countif(OperationName == "SecretList"),
    UniqueSecretsAccessed = dcount(id_s),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    SourceIPs = make_set(CallerIPAddress, 5)
    by identity_claim_oid_s, identity_claim_appid_s
| extend
    AccessDuration = LastAccess - FirstAccess,
    HasListThenGet = SecretLists > 0 and SecretGets > 0,
    IsFullDump = SecretLists > 0 and SecretGets >= SecretGetThreshold
| extend Severity = case(
    IsFullDump and AccessDuration < 5m, "CRITICAL - Rapid full vault dump",
    SecretGets >= 50, "CRITICAL - Mass secret retrieval",
    IsFullDump, "HIGH - List+Get pattern detected",
    SecretGets >= SecretGetThreshold, "HIGH - Elevated secret access volume",
    "LOW"
)
| project identity_claim_appid_s, Severity, SecretGets, SecretLists, UniqueSecretsAccessed, AccessDuration, SourceIPs
// Expected: app-evil = "CRITICAL - Rapid full vault dump" (List+15 Gets in 30 seconds)
// Expected: app-deploy = "LOW" (5 Gets, no List, normal deployment)
```

### Test 2: Baseline Comparison

```kql
// ============================================================
// TEST 2: Key Vault Access Baseline Comparison
// Validates: Query 4 - Compares current access to 30-day baseline
// Expected: attacker-sp = "NEW CALLER" (never accessed vault before)
//           deploy-sp = "WITHIN NORMAL RANGE" (consistent daily access)
// ============================================================
let TestAzureDiagnostics = datatable(
    TimeGenerated: datetime,
    ResourceType: string,
    Resource: string,
    OperationName: string,
    identity_claim_oid_s: string,
    id_s: string,
    httpStatusCode_d: double
) [
    // --- deploy-sp: Consistent daily access for 30 days (5 secrets/day) ---
    datetime(2026-01-25T09:00:00Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "db-connection-string", 200,
    datetime(2026-01-25T09:00:01Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "redis-password", 200,
    datetime(2026-01-25T09:00:02Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "api-key-stripe", 200,
    datetime(2026-01-25T09:00:03Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "storage-account-key", 200,
    datetime(2026-01-25T09:00:04Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "cosmos-db-key", 200,
    datetime(2026-02-10T09:00:00Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "db-connection-string", 200,
    datetime(2026-02-10T09:00:01Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "redis-password", 200,
    datetime(2026-02-10T09:00:02Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "api-key-stripe", 200,
    datetime(2026-02-10T09:00:03Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "storage-account-key", 200,
    datetime(2026-02-10T09:00:04Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "cosmos-db-key", 200,
    // Today: deploy-sp does same 5 secrets (normal)
    datetime(2026-02-22T09:00:00Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "db-connection-string", 200,
    datetime(2026-02-22T09:00:01Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "redis-password", 200,
    datetime(2026-02-22T09:00:02Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "api-key-stripe", 200,
    datetime(2026-02-22T09:00:03Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "storage-account-key", 200,
    datetime(2026-02-22T09:00:04Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "cosmos-db-key", 200,
    // --- attacker-sp: NEVER accessed this vault before ---
    // Today: first ever access, dumps 15 secrets
    datetime(2026-02-22T08:15:00Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "db-connection-string", 200,
    datetime(2026-02-22T08:15:02Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "storage-account-key", 200,
    datetime(2026-02-22T08:15:04Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "redis-password", 200,
    datetime(2026-02-22T08:15:06Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "api-key-stripe", 200,
    datetime(2026-02-22T08:15:08Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "jwt-signing-key", 200,
    datetime(2026-02-22T08:15:10Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "sp-client-secret-01", 200,
    datetime(2026-02-22T08:15:12Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "sp-client-secret-02", 200,
    datetime(2026-02-22T08:15:14Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "cosmos-db-key", 200,
    datetime(2026-02-22T08:15:16Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "eventhub-connection", 200,
    datetime(2026-02-22T08:15:18Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "encryption-master-key", 200
];
let AlertTime = datetime(2026-02-22T12:00:00Z);
let Callers = dynamic(["aaaa-aaaa", "bbbb-bbbb"]);
// --- Baseline per caller ---
let Baseline = TestAzureDiagnostics
| where TimeGenerated < (AlertTime - 24h)
| where identity_claim_oid_s in (Callers)
| where OperationName == "SecretGet"
| summarize BaselineGets = count(), BaselineDays = dcount(bin(TimeGenerated, 1d)),
    BaselineSecrets = dcount(id_s) by identity_claim_oid_s;
let Today = TestAzureDiagnostics
| where TimeGenerated >= (AlertTime - 24h)
| where identity_claim_oid_s in (Callers)
| where OperationName == "SecretGet"
| summarize TodayGets = count(), TodaySecrets = dcount(id_s) by identity_claim_oid_s;
Today
| join kind=leftouter Baseline on identity_claim_oid_s
| extend Assessment = case(
    isempty(BaselineGets) or BaselineGets == 0, "NEW CALLER - Never accessed this vault (CRITICAL)",
    TodayGets > BaselineGets * 2, "ANOMALOUS - Significantly above baseline",
    "WITHIN NORMAL RANGE"
)
| project identity_claim_oid_s, TodayGets, TodaySecrets, BaselineGets, BaselineDays, BaselineSecrets, Assessment
// Expected: aaaa-aaaa = "NEW CALLER" (0 baseline, 10 today)
// Expected: bbbb-bbbb = "WITHIN NORMAL RANGE" (10 baseline over 2 days, 5 today)
```

### Test 3: Access Policy Change Detection

```kql
// ============================================================
// TEST 3: Pre-Attack Access Policy Changes
// Validates: Query 5 - Detects access policy modification before secret retrieval
// Expected: Attacker user modified access policy 1 hour before mass retrieval
//           Normal admin change flagged as INFO
// ============================================================
let TestAzureActivity = datatable(
    TimeGenerated: datetime,
    ResourceProviderValue: string,
    OperationNameValue: string,
    _ResourceId: string,
    Claims: string,
    CallerIpAddress: string,
    ActivityStatusValue: string,
    Properties: string
) [
    // --- Malicious: Attacker modifies access policy before secret dump ---
    datetime(2026-02-22T07:15:00Z), "MICROSOFT.KEYVAULT",
    "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE",
    "/subscriptions/sub-001/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/contoso-prod-kv",
    '{"http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn": "attacker@contoso.com"}',
    "203.0.113.50", "Succeeded",
    '{"addedAccessPolicy": {"objectId": "aaaa-aaaa", "permissions": {"secrets": ["get","list"]}}}',
    // --- Normal: Admin creates a vault in a different time window ---
    datetime(2026-02-20T14:00:00Z), "MICROSOFT.KEYVAULT",
    "MICROSOFT.KEYVAULT/VAULTS/WRITE",
    "/subscriptions/sub-001/resourceGroups/rg-dev/providers/Microsoft.KeyVault/vaults/contoso-dev-kv",
    '{"http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn": "admin@contoso.com"}',
    "10.0.0.1", "Succeeded",
    '{"vaultProperties": {"sku": "standard"}}'
];
let AlertTime = datetime(2026-02-22T08:15:00Z);
let TargetVault = "contoso-prod-kv";
// --- Detect pre-attack changes ---
TestAzureActivity
| where ResourceProviderValue =~ "MICROSOFT.KEYVAULT"
| where OperationNameValue has_any ("ACCESSPOLICIES/WRITE", "VAULTS/WRITE")
| extend
    Caller = extract('"http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn":\\s*"([^"]+)"', 1, Claims),
    IsTargetVault = _ResourceId has TargetVault
| extend
    TimeDiffToAlert = AlertTime - TimeGenerated,
    RiskIndicator = case(
        IsTargetVault and OperationNameValue has "ACCESSPOLICIES" and TimeDiffToAlert between (0h .. 4h),
        "CRITICAL - Access policy modified shortly before mass retrieval",
        IsTargetVault and OperationNameValue has "ACCESSPOLICIES",
        "HIGH - Access policy modified on target vault",
        "INFO - Vault change on different resource"
    )
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, IsTargetVault, TimeDiffToAlert, RiskIndicator
// Expected: attacker@contoso.com = "CRITICAL" (access policy change 1h before alert on target vault)
// Expected: admin@contoso.com = "INFO" (different vault, different time)
```

### Test 4: Cross-Vault Campaign Detection

```kql
// ============================================================
// TEST 4: Cross-Vault Campaign Detection
// Validates: Query 7 - Detects same attacker hitting multiple vaults
// Expected: attacker-sp = CRITICAL (3 vaults, 45 total SecretGets)
//           deploy-sp = ISOLATED (1 vault, 5 SecretGets)
// ============================================================
let TestAzureDiagnostics = datatable(
    TimeGenerated: datetime,
    ResourceType: string,
    Resource: string,
    OperationName: string,
    identity_claim_oid_s: string,
    identity_claim_appid_s: string,
    CallerIPAddress: string,
    id_s: string,
    httpStatusCode_d: double
) [
    // --- Attacker SP: Hits 3 vaults in sequence ---
    // Vault 1
    datetime(2026-02-22T08:15:00Z), "VAULTS", "contoso-prod-kv", "SecretList", "aaaa-aaaa", "app-evil", "203.0.113.50", "", 200,
    datetime(2026-02-22T08:15:02Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "db-conn", 200,
    datetime(2026-02-22T08:15:04Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "storage-key", 200,
    datetime(2026-02-22T08:15:06Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "redis-pw", 200,
    datetime(2026-02-22T08:15:08Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "api-key-1", 200,
    datetime(2026-02-22T08:15:10Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "api-key-2", 200,
    datetime(2026-02-22T08:15:12Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "api-key-3", 200,
    datetime(2026-02-22T08:15:14Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "api-key-4", 200,
    datetime(2026-02-22T08:15:16Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "api-key-5", 200,
    datetime(2026-02-22T08:15:18Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "api-key-6", 200,
    datetime(2026-02-22T08:15:20Z), "VAULTS", "contoso-prod-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "api-key-7", 200,
    // Vault 2
    datetime(2026-02-22T08:20:00Z), "VAULTS", "contoso-staging-kv", "SecretList", "aaaa-aaaa", "app-evil", "203.0.113.50", "", 200,
    datetime(2026-02-22T08:20:02Z), "VAULTS", "contoso-staging-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "staging-db", 200,
    datetime(2026-02-22T08:20:04Z), "VAULTS", "contoso-staging-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "staging-redis", 200,
    datetime(2026-02-22T08:20:06Z), "VAULTS", "contoso-staging-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "staging-api-1", 200,
    datetime(2026-02-22T08:20:08Z), "VAULTS", "contoso-staging-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "staging-api-2", 200,
    datetime(2026-02-22T08:20:10Z), "VAULTS", "contoso-staging-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "staging-api-3", 200,
    datetime(2026-02-22T08:20:12Z), "VAULTS", "contoso-staging-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "staging-api-4", 200,
    datetime(2026-02-22T08:20:14Z), "VAULTS", "contoso-staging-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "staging-api-5", 200,
    datetime(2026-02-22T08:20:16Z), "VAULTS", "contoso-staging-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "staging-api-6", 200,
    datetime(2026-02-22T08:20:18Z), "VAULTS", "contoso-staging-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "staging-api-7", 200,
    datetime(2026-02-22T08:20:20Z), "VAULTS", "contoso-staging-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "staging-api-8", 200,
    // Vault 3
    datetime(2026-02-22T08:25:00Z), "VAULTS", "contoso-shared-kv", "SecretList", "aaaa-aaaa", "app-evil", "203.0.113.50", "", 200,
    datetime(2026-02-22T08:25:02Z), "VAULTS", "contoso-shared-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "shared-cert", 200,
    datetime(2026-02-22T08:25:04Z), "VAULTS", "contoso-shared-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "shared-signing-key", 200,
    datetime(2026-02-22T08:25:06Z), "VAULTS", "contoso-shared-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "shared-master-key", 200,
    datetime(2026-02-22T08:25:08Z), "VAULTS", "contoso-shared-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "shared-backup-key", 200,
    datetime(2026-02-22T08:25:10Z), "VAULTS", "contoso-shared-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "shared-api-1", 200,
    datetime(2026-02-22T08:25:12Z), "VAULTS", "contoso-shared-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "shared-api-2", 200,
    datetime(2026-02-22T08:25:14Z), "VAULTS", "contoso-shared-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "shared-api-3", 200,
    datetime(2026-02-22T08:25:16Z), "VAULTS", "contoso-shared-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "shared-api-4", 200,
    datetime(2026-02-22T08:25:18Z), "VAULTS", "contoso-shared-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "shared-api-5", 200,
    datetime(2026-02-22T08:25:20Z), "VAULTS", "contoso-shared-kv", "SecretGet", "aaaa-aaaa", "app-evil", "203.0.113.50", "shared-api-6", 200,
    // --- Benign: Deploy SP reads 5 secrets from 1 vault ---
    datetime(2026-02-22T09:00:00Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "app-deploy", "10.0.0.100", "db-conn", 200,
    datetime(2026-02-22T09:00:01Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "app-deploy", "10.0.0.100", "redis-pw", 200,
    datetime(2026-02-22T09:00:02Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "app-deploy", "10.0.0.100", "api-key-1", 200,
    datetime(2026-02-22T09:00:03Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "app-deploy", "10.0.0.100", "storage-key", 200,
    datetime(2026-02-22T09:00:04Z), "VAULTS", "contoso-prod-kv", "SecretGet", "bbbb-bbbb", "app-deploy", "10.0.0.100", "cosmos-key", 200
];
// --- Cross-vault campaign detection ---
let SecretGetThreshold = 10;
TestAzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "SecretList")
| summarize
    SecretGets = countif(OperationName == "SecretGet"),
    SecretLists = countif(OperationName == "SecretList"),
    UniqueSecrets = dcount(id_s)
    by Resource, identity_claim_oid_s, identity_claim_appid_s
| where SecretGets >= 5 or SecretLists > 0
| extend CallerKey = strcat(identity_claim_oid_s, " / ", identity_claim_appid_s)
| summarize
    AffectedVaults = dcount(Resource),
    VaultNames = make_set(Resource, 10),
    TotalSecretGets = sum(SecretGets),
    TotalSecretLists = sum(SecretLists)
    by CallerKey
| extend ScopeAssessment = case(
    AffectedVaults >= 3, "CRITICAL - Cross-vault campaign (3+ vaults)",
    AffectedVaults == 2, "HIGH - Multiple vaults targeted",
    "ISOLATED - Single vault"
)
| sort by AffectedVaults desc
// Expected: aaaa-aaaa / app-evil = "CRITICAL - Cross-vault campaign" (3 vaults, 30 SecretGets)
// Expected: bbbb-bbbb / app-deploy = "ISOLATED - Single vault" (1 vault, 5 SecretGets)
```

---

## References

- [Microsoft: Defender for Key Vault overview](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-key-vault-introduction)
- [Microsoft: Azure Key Vault logging and monitoring](https://learn.microsoft.com/en-us/azure/key-vault/general/logging)
- [Microsoft: Azure Key Vault security overview](https://learn.microsoft.com/en-us/azure/key-vault/general/security-features)
- [Microsoft: Best practices for Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices)
- [Microsoft: Azure Key Vault access policy vs RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)
- [MITRE ATT&CK T1555.006 - Credentials from Password Stores: Cloud Secrets Management Stores](https://attack.mitre.org/techniques/T1555/006/)
- [MITRE ATT&CK T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)
- [Microsoft: Storm-0558 investigation (signing key theft)](https://www.microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/)
- [CISA: Enhanced monitoring to detect APT activity targeting Outlook Online](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-193a)
- [Microsoft: Midnight Blizzard Microsoft corporate breach guidance](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
