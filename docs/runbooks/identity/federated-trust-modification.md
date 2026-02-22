---
title: "Federated Trust Modification (Golden SAML)"
id: RB-0024
severity: critical
status: reviewed
description: >
  Investigation runbook for detecting unauthorized modifications to federated
  trust configurations in Microsoft Entra ID, including the Golden SAML attack
  technique. Covers detection of federation setting changes (signing certificate
  replacement, issuer URI modification, federation protocol updates), actor
  attribution and compromise assessment for the admin who made the change,
  federation certificate forensic analysis, historical baseline comparison of
  federation configuration changes, suspicious SAML token detection for forged
  authentication, post-compromise activity assessment, organization-wide
  federation and trust sweep across all tenant domains, and UEBA behavioral
  enrichment. Golden SAML was the primary persistence mechanism in the SolarWinds
  supply chain attack (Midnight Blizzard/APT29) -- an attacker who modifies the
  federation trust or steals the SAML signing certificate can forge authentication
  tokens for ANY user in the tenant, including Global Administrators, without
  knowing their credentials or triggering MFA.
mitre_attack:
  tactics:
    - tactic_id: TA0003
      tactic_name: "Persistence"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
    - tactic_id: TA0006
      tactic_name: "Credential Access"
    - tactic_id: TA0004
      tactic_name: "Privilege Escalation"
    - tactic_id: TA0008
      tactic_name: "Lateral Movement"
  techniques:
    - technique_id: T1484.002
      technique_name: "Domain Policy Modification: Trust Modification"
      confidence: confirmed
    - technique_id: T1606.002
      technique_name: "Forge Web Credentials: SAML Tokens"
      confidence: confirmed
    - technique_id: T1552.004
      technique_name: "Unsecured Credentials: Private Keys"
      confidence: probable
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
threat_actors:
  - "Midnight Blizzard (APT29/Nobelium)"
  - "Storm-0558"
  - "Scattered Spider (Octo Tempest)"
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
  - table: "AADServicePrincipalSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: false
    alternatives: []
  - table: "AzureActivity"
    product: "Azure"
    license: "Azure Subscription"
    required: false
    alternatives: []
  - table: "OfficeActivity"
    product: "Office 365"
    license: "Office 365 E1+"
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
category: identity
key_log_sources:
  - AuditLogs
  - SigninLogs
  - AADServicePrincipalSignInLogs
  - AzureActivity
  - OfficeActivity
tactic_slugs:
  - persistence
  - defense-evasion
  - cred-access
  - priv-esc
  - lateral-movement
data_checks:
  - query: "AuditLogs | where OperationName has_any ('federation', 'domain authentication', 'domain federation') | take 1"
    label: primary
    description: "Federation trust modification audit events"
  - query: "SigninLogs | where TokenIssuerType == 'ADFederationServices' | take 1"
    description: "Federated sign-ins for SAML token analysis"
  - query: "AuditLogs | take 1"
    description: "General audit log for actor activity analysis"
  - query: "AADServicePrincipalSignInLogs | take 1"
    label: optional
    description: "Service principal sign-ins via federated tokens (requires P1/P2)"
  - query: "AzureActivity | take 1"
    label: optional
    description: "Azure control plane activity for post-compromise actions"
---

# Federated Trust Modification (Golden SAML) - Investigation Runbook

> **RB-0024** | Severity: Critical | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Audit Logs
> **Risk Detection Name:** `Set domain authentication` / `Set federation settings on domain` / `Set DomainFederationSettings` audit events
> **Primary MITRE Technique:** T1484.002 - Domain Policy Modification: Trust Modification

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Federation Trust Change Detection](#step-1-federation-trust-change-detection)
   - [Step 2: Actor Attribution and Compromise Assessment](#step-2-actor-attribution-and-compromise-assessment)
   - [Step 3: Federation Certificate Analysis](#step-3-federation-certificate-analysis)
   - [Step 4: Baseline Comparison - Historical Federation Configuration](#step-4-baseline-comparison---historical-federation-configuration)
   - [Step 5: Suspicious SAML Token Detection](#step-5-suspicious-saml-token-detection)
   - [Step 6: Post-Compromise Activity Assessment](#step-6-post-compromise-activity-assessment)
   - [Step 7: Organization-Wide Federation and Trust Sweep](#step-7-organization-wide-federation-and-trust-sweep)
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
Federated trust modification detection is triggered through audit log events that record changes to domain federation configuration in Microsoft Entra ID:

1. **AuditLogs federation events:** The `Set domain authentication`, `Set federation settings on domain`, `Set DomainFederationSettings`, `Update domain`, `Add unverified domain`, and `Verify domain` operations capture every change to the federation trust configuration. Critical changes include signing certificate replacement (new thumbprint or serial number), issuer URI modification, federation protocol updates (WS-Federation to SAML 2.0 or vice versa), and metadata endpoint changes.
2. **Certificate modification detection:** When the SAML signing certificate is replaced, the `ModifiedProperties` field in AuditLogs contains both the old and new certificate values. A certificate change that does not match the organization's PKI infrastructure is the primary indicator of a Golden SAML attack.
3. **Cross-signal correlation:** A federation trust modification followed by SAML-authenticated sign-ins from unexpected IPs, with those sign-ins accessing high-privilege resources or Global Admin functionality, is the hallmark of a Golden SAML attack chain.

**Why it matters:**
Federated trust modification is one of the **most devastating identity attack techniques** in cloud environments. In a Golden SAML attack, the adversary either steals the SAML signing certificate from the on-premises AD FS server or modifies the federation trust configuration in Entra ID to point to an attacker-controlled signing certificate. Once they possess the signing key, they can forge SAML tokens for **any user** in the tenant -- including Global Administrators -- without knowing the user's password, without triggering MFA, and without generating any sign-in anomaly in Identity Protection.

This was the primary persistence and lateral movement technique used by Midnight Blizzard (APT29/Nobelium) in the SolarWinds supply chain attack (2020-2021). After compromising the SolarWinds Orion build system, the attackers used their access to on-premises environments to steal the AD FS token-signing certificate, then forged SAML tokens to access cloud resources as any federated user. This technique was undetectable at the time because the forged tokens were cryptographically valid -- they were signed with the legitimate organization's certificate.

**Why this is CRITICAL severity:**
- The attacker can impersonate **ANY user** in the tenant, including Global Administrators, without their credentials
- Forged SAML tokens are cryptographically valid and bypass all MFA controls
- Identity Protection does not flag forged SAML tokens because they appear to come from the legitimate federation provider
- A single federation trust compromise grants access to the entire tenant: all mailboxes, all files, all Azure subscriptions
- The attack is extremely difficult to detect because the forged tokens look identical to legitimate federated sign-ins
- If the attacker steals the signing key rather than modifying the trust, there may be NO audit trail at all
- Recovery requires rotating the SAML signing certificate, which causes a service disruption for all federated users

**However:** This alert has a **very low false positive rate** (~1-3%). Legitimate triggers include:
- Planned migration from AD FS to cloud authentication (Password Hash Sync or Pass-Through Auth)
- Scheduled SAML signing certificate rotation (certificates expire and must be renewed)
- Initial federation setup during hybrid identity deployment
- Federation configuration changes during disaster recovery or infrastructure migration
- Adding a new verified domain with federation settings during M&A activity

**Worst case scenario if this is real:**
An attacker who has compromised the on-premises AD FS server (via SolarWinds-style supply chain attack, on-prem domain compromise, or admin credential theft) extracts the SAML token-signing certificate private key. They then set up a custom Security Token Service (STS) and modify the federation trust in Entra ID to use their attacker-controlled signing certificate. From that point forward, the attacker can generate a SAML assertion for any user -- they craft a token claiming to be the CEO, the CFO, the Global Admin, or any service account. The forged token is signed with the legitimate (stolen or replaced) certificate, so Entra ID accepts it without question. The attacker accesses the CEO's email, reads board communications, downloads financial documents from SharePoint, grants themselves permanent Global Admin through a backdoor account, modifies Conditional Access policies to create exceptions for their infrastructure, and establishes multiple persistence mechanisms across the tenant. Because the forged tokens never trigger MFA or risk detections, the compromise can persist for months. In the SolarWinds breach, Midnight Blizzard maintained access to victim organizations for over 9 months using this exact technique.

**Key difference from other identity runbooks:**
- RB-0001 through RB-0006 (Credential-focused): Investigate password/MFA-based attacks at the individual user level.
- RB-0013 (Privileged Role Assignment): Investigates individual role escalation within Entra ID.
- RB-0015 (Conditional Access Manipulation): Investigates security policy changes.
- RB-0021 (Session Token Theft): Investigates stolen session tokens from individual users.
- **RB-0024 (This runbook):** Investigates **trust infrastructure compromise** -- the attacker compromises the federation trust itself, gaining the ability to impersonate ANY user without targeting individual accounts. This is not an individual account compromise; this is an entire identity infrastructure compromise. If the federation trust is compromised, every user, every admin, every service principal that authenticates via federation is at risk.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID Free + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID (AuditLogs, SigninLogs)
- **Permissions:** Security Reader (investigation), Global Administrator or Domain Name Administrator (containment)

### Recommended for Full Coverage
- **License:** Entra ID P2 + Microsoft 365 E5 + Microsoft Sentinel
- **Additional:** AD FS audit logging enabled (on-premises), Azure AD Connect Health monitoring
- **Permissions:** Global Administrator for federation trust remediation (certificate rotation, domain conversion)

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | AuditLogs, SigninLogs | Steps 1-5, 7 |
| Above + Entra ID P1/P2 | Above + AADServicePrincipalSignInLogs | Steps 1-7 (SP SAML analysis) |
| Above + Azure Subscription | Above + AzureActivity | Steps 1-7 (Azure control plane) |
| Above + Sentinel UEBA | Above + BehaviorAnalytics | Steps 1-8 (full coverage) |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let TargetDomain = "contoso.com";                             // Federated domain that was modified
let SuspiciousActorUPN = "admin@contoso.com";                 // Admin who modified federation settings
let AlertTime = datetime(2026-02-22T14:00:00Z);               // Time of federation change
let LookbackWindow = 24h;                                     // Window to analyze activity before change
let ForwardWindow = 72h;                                      // Window after change for post-compromise
let BaselineDays = 90d;                                       // Baseline window (federation changes are rare)
let ExpectedIssuerUri = "http://sts.contoso.com/adfs/services/trust";  // Expected federation issuer URI
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)

- Federation signing certificate was replaced with a certificate not from the organization's PKI
- Issuer URI was changed to an unknown or external endpoint
- Federation settings were modified by an account that was recently compromised (password reset, new MFA, anomalous sign-in)
- Domain was converted from managed to federated outside of a planned migration
- Multiple federation-related changes occurred in rapid succession
- The actor who made the change has never performed federation operations before

### Standard Investigation

- Federation certificate rotation by a known infrastructure admin during scheduled maintenance
- Federation settings updated as part of a documented AD FS migration project
- Domain verification events for a known organizational domain during M&A activity
- Federation metadata endpoint URL updated to match a new AD FS farm deployment

### Likely Benign

- Scheduled AD FS certificate auto-rollover with matching organizational PKI certificate
- Federation configuration change by the designated AD FS administrator from a known corporate IP
- Domain operations during a planned Azure AD Connect deployment with documented change ticket
- Token signing certificate renewal that matches the expiration date of the previous certificate

---

## 5. Investigation Steps

### Step 1: Federation Trust Change Detection

**Purpose:** Detect any modification to federation trust settings in Entra ID. This includes changes to the signing certificate, issuer URI, federation protocol, metadata endpoint, and domain authentication type. Any change to federation configuration is significant because it is extremely rare in production environments -- most organizations configure federation once and do not modify it for years.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 1: Federation Trust Change Detection
// Purpose: Detect all federation trust configuration modifications
// Tables: AuditLogs
// Investigation Step: 1 - Federation Trust Change Detection
// ============================================================
let TargetDomain = "contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Federation trust modification events ---
AuditLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where OperationName in (
    "Set domain authentication",
    "Set federation settings on domain",
    "Set DomainFederationSettings",
    "Update domain",
    "Add unverified domain",
    "Verify domain",
    "Add domain to company",
    "Remove unverified domain",
    "Remove domain from company"
)
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    ActorAppName = tostring(InitiatedBy.app.displayName),
    ActorAppId = tostring(InitiatedBy.app.appId),
    TargetDomainName = tostring(TargetResources[0].displayName),
    TargetResourceType = tostring(TargetResources[0].type),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    ChangeCategory = case(
        PropertyName has_any ("SigningCertificate", "NextSigningCertificate", "SigningCertificateRevocationCheck"),
            "CERTIFICATE - Signing certificate modified",
        PropertyName has_any ("IssuerUri", "FederationMetadataUrl", "MetadataExchangeUri", "PassiveLogOnUri"),
            "ENDPOINT - Federation endpoint modified",
        PropertyName has_any ("FederationBrandName", "ActiveLogOnUri", "LogOffUri"),
            "CONFIG - Federation configuration changed",
        PropertyName has_any ("Authentication", "AuthenticationType"),
            "AUTH_TYPE - Domain authentication type changed",
        PropertyName has_any ("FederatedIdpMfaBehavior", "PromptLoginBehavior", "SigningCertificateUpdateStatus"),
            "POLICY - Federation policy modified",
        strcat("OTHER - ", PropertyName)
    ),
    RiskLevel = case(
        PropertyName has "SigningCertificate" and isnotempty(NewValue),
            "CRITICAL - Signing certificate replaced (Golden SAML indicator)",
        PropertyName has "IssuerUri" and isnotempty(NewValue) and isnotempty(OldValue),
            "CRITICAL - Issuer URI changed (federation redirected)",
        PropertyName has "Authentication" and NewValue has "Federated",
            "CRITICAL - Domain converted to federated authentication",
        PropertyName has "MetadataExchangeUri" and isnotempty(NewValue),
            "HIGH - Metadata exchange endpoint modified",
        PropertyName has "PassiveLogOnUri" and isnotempty(NewValue),
            "HIGH - Passive logon URI modified",
        PropertyName has "Authentication" and NewValue has "Managed",
            "MEDIUM - Domain converted to managed (possible remediation)",
        "REVIEW - Federation property changed"
    )
| project
    TimeGenerated,
    OperationName,
    ActorUPN,
    ActorIP,
    ActorAppName,
    TargetDomainName,
    ChangeCategory,
    PropertyName,
    OldValue,
    NewValue,
    RiskLevel,
    Result
| sort by TimeGenerated asc
```

**Performance Notes:**
- `ModifiedProperties` is the critical field -- it contains the old and new values for every property that changed
- Federation changes generate multiple `ModifiedProperties` entries per event (certificate, issuer URI, endpoints may all change together)
- Use `mv-expand` to extract each property individually for detailed analysis
- The `OldValue` field is essential for forensics -- it captures the legitimate configuration before the attacker's modification

**Tuning Guidance:**
- Any `SigningCertificate` change outside of a scheduled rotation is an immediate escalation
- An `IssuerUri` change is extremely suspicious -- legitimate orgs rarely change their federation endpoint
- A domain converting from `Managed` to `Federated` is the highest-risk change -- this means someone enabled federation, possibly to deploy a Golden SAML attack
- If `ActorAppName` is populated instead of `ActorUPN`, the change was made programmatically (PowerShell, Graph API) -- this is common for both legitimate automation and attacker tools
- Cross-reference `ActorIP` with known admin workstation IPs and VPN ranges

**Expected findings:**
- Complete record of all federation trust modifications: what changed, from what value to what value, who made the change, from where
- If the signing certificate was replaced with an unknown certificate, this confirms a Golden SAML attack setup
- If the issuer URI was changed to an external or unknown endpoint, the federation has been redirected to an attacker-controlled STS

**Next action:**
- If signing certificate was changed, immediately proceed to Step 3 (Certificate Analysis) for forensic comparison
- If any CRITICAL risk finding, proceed in parallel to Step 2 (Actor Attribution) and containment preparation
- Note the `OldValue` for every changed property -- this is needed for restoration during containment

---

### Step 2: Actor Attribution and Compromise Assessment

**Purpose:** Identify WHO changed the federation settings and assess whether that admin account was compromised before making the change. Federation modifications require Global Administrator or Domain Name Administrator privileges. If the admin account was recently compromised (new password, new MFA method, anomalous sign-in from a new location), the federation change is almost certainly malicious.

**Data needed:** SigninLogs, AuditLogs

```kql
// ============================================================
// QUERY 2: Actor Attribution and Compromise Assessment
// Purpose: Determine if the admin who modified federation was compromised
// Tables: SigninLogs, AuditLogs
// Investigation Step: 2 - Actor Attribution and Compromise Assessment
// ============================================================
let SuspiciousActorUPN = "admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Actor sign-in activity before and during the federation change ---
let ActorSignIns = SigninLogs
| where TimeGenerated between (AlertTime - 7d .. AlertTime + 4h)
| where UserPrincipalName =~ SuspiciousActorUPN
| project
    TimeGenerated,
    EventType = "SIGN_IN",
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    TokenIssuerType,
    IsInteractive,
    MfaDetail = tostring(AuthenticationDetails)
| extend
    SignInOutcome = case(
        ResultType == "0", "SUCCESS",
        ResultType == "50074", "MFA REQUIRED",
        ResultType == "53003", "BLOCKED BY CA",
        strcat("FAILURE - ", ResultType)
    ),
    CompromiseIndicator = case(
        RiskLevelDuringSignIn in ("high", "medium"),
            "HIGH RISK - Risky sign-in detected by Identity Protection",
        TokenIssuerType != "AzureAD" and TokenIssuerType != "",
            "REVIEW - Non-standard token issuer",
        ""
    );
// --- Actor account modification events (password reset, MFA change) ---
let ActorAccountChanges = AuditLogs
| where TimeGenerated between (AlertTime - 7d .. AlertTime + 4h)
| where OperationName in (
    "Reset password",
    "Change password",
    "Reset password (by admin)",
    "Update user",
    "User registered security info",
    "User registered all required security info",
    "User deleted security info",
    "User started security info registration",
    "Admin registered security info",
    "Add member to role",
    "Add eligible member to role"
)
| where TargetResources has SuspiciousActorUPN
    or InitiatedBy has SuspiciousActorUPN
| project
    TimeGenerated,
    EventType = "ACCOUNT_CHANGE",
    UserPrincipalName = SuspiciousActorUPN,
    OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties),
    Result
| extend
    CompromiseIndicator = case(
        OperationName has "Reset password" and InitiatedByUser != SuspiciousActorUPN,
            "HIGH - Password reset by different admin (possible takeover prep)",
        OperationName has "security info" and TimeGenerated between (AlertTime - 48h .. AlertTime),
            "HIGH - MFA method changed shortly before federation modification",
        OperationName has "member to role" and ModifiedProperties has "Global",
            "CRITICAL - Global Admin role assigned before federation change",
        OperationName has "member to role" and ModifiedProperties has "Domain Name",
            "HIGH - Domain Name Admin role assigned before federation change",
        "REVIEW"
    );
// --- Combine sign-in and account change timeline ---
union
    (ActorSignIns | project TimeGenerated, EventType, UserPrincipalName, Detail = strcat(AppDisplayName, " from ", IPAddress, " (", Location, ")"), CompromiseIndicator),
    (ActorAccountChanges | project TimeGenerated, EventType, UserPrincipalName, Detail = strcat(OperationName, " by ", InitiatedByUser, " from ", InitiatedByIP), CompromiseIndicator)
| sort by TimeGenerated asc
```

**Performance Notes:**
- The 7-day lookback captures compromise chains where the attacker compromises the admin account days before modifying federation
- Combining `SigninLogs` and `AuditLogs` provides the complete timeline: how the attacker accessed the account AND what they changed
- `TokenIssuerType` reveals whether the admin authenticated via federation themselves -- if so, this could be a recursive attack

**Tuning Guidance:**
- A password reset followed by an MFA change followed by a federation modification within 48 hours is the classic attack chain
- If the admin was assigned Global Admin or Domain Name Admin role shortly before the federation change, the escalation itself may be unauthorized
- Cross-reference the admin's sign-in IP with the IP used for the federation change (Step 1) -- they should match
- If the admin normally signs in from corporate IP but the federation change came from a VPN or residential IP, escalate immediately
- Check if the admin has a history of making federation changes -- `FirstTimeActionPerformed` from UEBA (Step 8) is directly relevant

**Expected findings:**
- Complete admin account timeline: sign-ins, password changes, MFA changes, role assignments
- Whether the admin account was recently compromised (new IP, new device, password reset by another admin)
- Whether the admin has legitimate authority and history of making federation changes

**Next action:**
- If admin account was recently compromised, confirm Golden SAML attack and proceed to immediate containment
- If admin is legitimate and the change correlates with a planned migration, de-escalate after verifying certificate
- Note all IPs used by the actor -- these are needed for scope assessment

---

### Step 3: Federation Certificate Analysis

**Purpose:** Extract and analyze the signing certificate details from the federation configuration change. Compare the new certificate against the previous certificate and the organization's PKI infrastructure. A certificate change that introduces a certificate not issued by the organization's Certificate Authority is the definitive indicator of a Golden SAML attack. This step also detects the subtler attack where the attacker adds a SECONDARY signing certificate rather than replacing the primary one.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 3: Federation Certificate Analysis
// Purpose: Extract and compare old vs new signing certificates
// Tables: AuditLogs
// Investigation Step: 3 - Federation Certificate Analysis
// ============================================================
let TargetDomain = "contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Extract certificate-related federation changes ---
AuditLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where OperationName in (
    "Set domain authentication",
    "Set federation settings on domain",
    "Set DomainFederationSettings",
    "Update domain"
)
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetDomainName = tostring(TargetResources[0].displayName),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| where PropertyName has_any (
    "SigningCertificate",
    "NextSigningCertificate",
    "IssuerUri",
    "MetadataExchangeUri",
    "PassiveLogOnUri",
    "ActiveLogOnUri",
    "FederationMetadataUrl",
    "SigningCertificateRevocationCheck"
)
| extend
    CertificateChanged = PropertyName has "SigningCertificate"
        and isnotempty(OldValue) and isnotempty(NewValue)
        and OldValue != NewValue,
    IssuerChanged = PropertyName has "IssuerUri"
        and isnotempty(OldValue) and isnotempty(NewValue)
        and OldValue != NewValue,
    EndpointChanged = PropertyName has_any ("MetadataExchangeUri", "PassiveLogOnUri", "ActiveLogOnUri", "FederationMetadataUrl")
        and isnotempty(NewValue)
| extend
    ForensicAnalysis = case(
        // Certificate replacement detection
        CertificateChanged,
            strcat("CERTIFICATE REPLACED - Old thumbprint/value differs from new. ",
                   "VERIFY: Does the new certificate match the organization's PKI? ",
                   "Compare Subject, Issuer, and Serial Number against AD FS certificate store."),
        // New certificate added where none existed
        PropertyName has "SigningCertificate" and isempty(OldValue) and isnotempty(NewValue),
            "NEW CERTIFICATE ADDED - No previous certificate existed. Federation was newly configured or secondary cert added.",
        // Certificate removed
        PropertyName has "SigningCertificate" and isnotempty(OldValue) and isempty(NewValue),
            "CERTIFICATE REMOVED - Signing certificate was deleted. Federation authentication will fail.",
        // Issuer URI change
        IssuerChanged,
            strcat("ISSUER URI CHANGED - Federation redirected from [", OldValue, "] to [", NewValue,
                   "]. VERIFY: Does the new issuer match a known organizational STS?"),
        // Endpoint change
        EndpointChanged,
            strcat("ENDPOINT MODIFIED - Federation endpoint changed. ",
                   "VERIFY: Does the new endpoint resolve to an organizational AD FS server?"),
        "Property modified - review context"
    ),
    GoldenSAMLRisk = case(
        CertificateChanged,
            "CRITICAL - Certificate replacement is the PRIMARY Golden SAML indicator",
        PropertyName has "NextSigningCertificate" and isnotempty(NewValue),
            "HIGH - Secondary certificate added (attacker may use this for token forgery while primary remains unchanged)",
        IssuerChanged,
            "CRITICAL - Issuer URI change redirects all federation authentication",
        EndpointChanged,
            "HIGH - Federation endpoint change may redirect token exchange to attacker infrastructure",
        "MEDIUM - Review context"
    )
| project
    TimeGenerated,
    ActorUPN,
    ActorIP,
    TargetDomainName,
    PropertyName,
    OldValue = iff(strlen(OldValue) > 100, strcat(substring(OldValue, 0, 100), "...[TRUNCATED]"), OldValue),
    NewValue = iff(strlen(NewValue) > 100, strcat(substring(NewValue, 0, 100), "...[TRUNCATED]"), NewValue),
    CertificateChanged,
    IssuerChanged,
    ForensicAnalysis,
    GoldenSAMLRisk
| sort by TimeGenerated asc
```

**Performance Notes:**
- Certificate values in `ModifiedProperties` can be very long (base64-encoded X.509 certificates) -- the query truncates display values to 100 characters for readability
- The full certificate values should be exported separately for PKI validation
- `NextSigningCertificate` is used during AD FS automatic certificate rollover -- adding a next certificate is the subtler attack vector

**Tuning Guidance:**
- **Certificate replacement**: Export the full `NewValue` for the `SigningCertificate` property and decode the base64 to extract Subject, Issuer, Serial Number, Thumbprint, and Validity Period. Compare against certificates in the AD FS certificate store and the organization's Certificate Authority
- **NextSigningCertificate addition**: This is a particularly subtle attack -- the attacker adds a secondary certificate, which AD FS will eventually roll over to. The primary certificate continues to work normally, masking the attack
- **IssuerUri change**: The issuer URI must match the organization's AD FS farm. Any external URI (cloud-hosted, IP address, unknown domain) is an immediate escalation
- **Self-signed certificate**: If the new certificate is self-signed (Subject == Issuer) and the organization uses a CA-issued certificate, this is strong evidence of an attack

**Expected findings:**
- Detailed comparison of old vs new certificate properties
- Whether the certificate was replaced, added, or a secondary certificate was injected
- Whether the issuer URI or federation endpoints were redirected

**Next action:**
- If certificate does not match organizational PKI, confirm Golden SAML attack and proceed to immediate containment
- Export full certificate values for the incident response report and forensic analysis
- Contact the AD FS infrastructure team to verify the certificate against the AD FS server's certificate store

---

### Step 4: Baseline Comparison - Historical Federation Configuration

**Purpose:** Establish how often federation settings change in this tenant. In most organizations, federation trust is configured once during initial deployment and rarely modified afterward. Any change outside of a planned infrastructure migration is inherently suspicious. This step provides the statistical context needed to determine if the current change is anomalous.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 4: Baseline Comparison - Historical Federation Configuration
// Purpose: Compare current federation change against 90-day baseline
// Tables: AuditLogs
// Investigation Step: 4 - Baseline Comparison
// ============================================================
let TargetDomain = "contoso.com";
let SuspiciousActorUPN = "admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 90d;
// --- Historical federation change frequency ---
let FederationBaseline = AuditLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
| where OperationName in (
    "Set domain authentication",
    "Set federation settings on domain",
    "Set DomainFederationSettings",
    "Update domain",
    "Add unverified domain",
    "Verify domain",
    "Add domain to company",
    "Remove unverified domain",
    "Remove domain from company"
)
| summarize
    TotalFederationChanges = count(),
    UniqueActors = dcount(tostring(InitiatedBy.user.userPrincipalName)),
    Actors = make_set(tostring(InitiatedBy.user.userPrincipalName), 20),
    ActorIPs = make_set(tostring(InitiatedBy.user.ipAddress), 20),
    Operations = make_set(OperationName, 20),
    AffectedDomains = make_set(tostring(TargetResources[0].displayName), 10),
    FirstChange = min(TimeGenerated),
    LastChange = max(TimeGenerated),
    ChangesByWeek = make_list(bin(TimeGenerated, 7d), 20)
| extend EntityType = "FEDERATION_BASELINE";
// --- Actor-specific baseline: has this admin ever modified federation? ---
let ActorBaseline = AuditLogs
| where TimeGenerated between (AlertTime - 365d .. AlertTime)
| where OperationName in (
    "Set domain authentication",
    "Set federation settings on domain",
    "Set DomainFederationSettings",
    "Update domain"
)
| where InitiatedBy has SuspiciousActorUPN
| summarize
    PreviousFederationChanges = count(),
    PreviousChangeOperations = make_set(OperationName, 20),
    PreviousChangeDomains = make_set(tostring(TargetResources[0].displayName), 10),
    FirstFederationChange = min(TimeGenerated),
    LastFederationChange = max(TimeGenerated)
| extend EntityType = "ACTOR_BASELINE";
// --- Domain-specific baseline: how often does THIS domain's federation change? ---
let DomainBaseline = AuditLogs
| where TimeGenerated between (AlertTime - 365d .. AlertTime)
| where OperationName in (
    "Set domain authentication",
    "Set federation settings on domain",
    "Set DomainFederationSettings",
    "Update domain"
)
| where TargetResources has TargetDomain
| summarize
    DomainChanges = count(),
    DomainChangeActors = make_set(tostring(InitiatedBy.user.userPrincipalName), 20),
    DomainChangeTimeline = make_list(TimeGenerated, 50),
    FirstDomainChange = min(TimeGenerated),
    LastDomainChange = max(TimeGenerated)
| extend EntityType = "DOMAIN_BASELINE";
// --- Compare against baseline ---
FederationBaseline
| extend
    Assessment = case(
        TotalFederationChanges == 0,
            "HIGHLY ANOMALOUS - ZERO federation changes in the last 90 days. Current change is unprecedented.",
        TotalFederationChanges <= 2,
            "ANOMALOUS - Federation changes are extremely rare (1-2 in 90 days). Every change requires investigation.",
        TotalFederationChanges <= 5,
            "SUSPICIOUS - Moderate federation activity. Verify against change management records.",
        "WITHIN BASELINE - Federation changes occur regularly (possible active migration project)"
    ),
    ExpectedFrequency = case(
        TotalFederationChanges == 0,
            "Expected: 0 changes in 90 days. This change breaks the pattern completely.",
        strcat("Expected: ~", tostring(round(todouble(TotalFederationChanges) / 13.0, 1)), " changes per week based on 90-day history")
    )
| project
    EntityType,
    TotalFederationChanges,
    UniqueActors,
    Actors,
    Assessment,
    ExpectedFrequency,
    FirstChange,
    LastChange
```

**Performance Notes:**
- The 90-day baseline for the tenant captures enough history to establish a pattern
- The 365-day actor baseline determines if this specific admin has ever touched federation before
- The 365-day domain baseline shows the full history of changes to this specific domain
- `make_list(bin(TimeGenerated, 7d))` provides a visual distribution of when changes occurred

**Tuning Guidance:**
- **Zero changes in 90 days**: This is the expected state for most production tenants. Federation is a "set once, forget" configuration. Any change is anomalous by definition
- **1-2 changes in 90 days**: Could be a scheduled certificate rotation. Cross-reference with change management tickets
- **Actor never modified federation before**: If `PreviousFederationChanges == 0`, the admin performing this change has never done it before -- strong anomaly signal even if the admin is legitimate
- **Multiple domains affected**: If the same actor modified federation for multiple domains, this could indicate a broader attack or a planned migration
- **Changes clustered in time**: If `ChangesByWeek` shows all changes in the same week, this is likely a planned migration. If the current change is isolated, it is more suspicious

**Expected findings:**
- Whether federation changes are normal for this tenant (almost certainly they are not)
- Whether the actor who made the change has ever modified federation before
- The historical change pattern for the affected domain

**Next action:**
- If zero or near-zero baseline, this change is definitionally anomalous -- proceed with high-priority investigation
- If a migration project is in progress, verify the change against the migration runbook and change management tickets
- Cross-reference the actor baseline with Step 2 findings

---

### Step 5: Suspicious SAML Token Detection

**Purpose:** After a federation trust compromise, the attacker forges SAML tokens to authenticate as any user. This step detects suspicious federated sign-ins that may indicate forged SAML tokens. Look for: sign-ins with `TokenIssuerType = "ADFederationServices"` from unexpected IPs, SAML-based sign-ins to resources the user has never accessed, sign-ins from federated users during off-hours or from unusual locations, and sign-ins where the token issuer does not match the expected federation endpoint.

**Data needed:** SigninLogs, AADServicePrincipalSignInLogs

```kql
// ============================================================
// QUERY 5: Suspicious SAML Token Detection
// Purpose: Detect potentially forged SAML tokens after trust compromise
// Tables: SigninLogs
// Investigation Step: 5 - Suspicious SAML Token Detection
// ============================================================
let TargetDomain = "contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 72h;
let ExpectedIssuerUri = "http://sts.contoso.com/adfs/services/trust";
// --- Federated sign-ins after federation trust modification ---
let FederatedSignIns = SigninLogs
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where TokenIssuerType == "ADFederationServices"
    or TokenIssuerName has "adfs"
    or TokenIssuerName has "federation"
    or AuthenticationProtocol has "saml"
| where UserPrincipalName has TargetDomain
    or HomeTenantId != "" // Include cross-tenant federated sign-ins
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    ResourceDisplayName,
    IPAddress,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    Country = tostring(LocationDetails.countryOrRegion),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    TokenIssuerType,
    TokenIssuerName,
    AuthenticationProtocol,
    ResultType,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    ConditionalAccessStatus,
    IsInteractive,
    CorrelationId
| extend
    IsExpectedIssuer = TokenIssuerName =~ ExpectedIssuerUri
        or TokenIssuerName has "contoso",
    SignInRisk = case(
        RiskLevelDuringSignIn in ("high", "medium"), "RISKY",
        "NORMAL"
    );
// --- Establish baseline of normal federated sign-in patterns ---
let BaselineFederated = SigninLogs
| where TimeGenerated between (AlertTime - 30d .. AlertTime)
| where TokenIssuerType == "ADFederationServices"
| where UserPrincipalName has TargetDomain
| summarize
    BaselineIPs = make_set(IPAddress, 100),
    BaselineCountries = make_set(tostring(LocationDetails.countryOrRegion), 20),
    BaselineApps = make_set(AppDisplayName, 50),
    BaselineUsers = make_set(UserPrincipalName, 200),
    BaselineDailyAvg = todouble(count()) / 30.0;
// --- Identify anomalous federated sign-ins ---
FederatedSignIns
| extend
    IsSuspicious = case(
        // Issuer mismatch -- token signed by unexpected STS
        not(IsExpectedIssuer) and isnotempty(TokenIssuerName),
            "CRITICAL - Token issuer does NOT match expected federation endpoint",
        // High-risk sign-in via federation
        SignInRisk == "RISKY",
            "HIGH - Federated sign-in flagged as risky by Identity Protection",
        // Admin resource access via federation
        ResourceDisplayName has_any ("Azure Portal", "Microsoft Graph", "Azure Active Directory", "Windows Azure Service Management API"),
            "HIGH - Federated sign-in accessing admin resources",
        // Off-hours sign-in via federation (UTC-based, adjust for timezone)
        hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) > 22,
            "MEDIUM - Federated sign-in during off-hours (UTC)",
        "REVIEW - Federated sign-in requires context"
    )
| extend
    ForgedTokenIndicator = case(
        not(IsExpectedIssuer), "YES - Token issuer mismatch is definitive Golden SAML indicator",
        SignInRisk == "RISKY" and ResourceDisplayName has "Azure", "PROBABLE - Risky federated access to Azure admin",
        "POSSIBLE - Requires correlation with Steps 1-4"
    )
| sort by TimeGenerated asc
```

```kql
// ============================================================
// QUERY 5B: Service Principal Federated Sign-Ins
// Purpose: Detect SPs using potentially forged SAML tokens
// Tables: AADServicePrincipalSignInLogs
// Investigation Step: 5 - Suspicious SAML Token Detection
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 72h;
AADServicePrincipalSignInLogs
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where ResultType == "0"
| project
    TimeGenerated,
    ServicePrincipalName,
    ServicePrincipalId,
    AppId,
    IPAddress,
    Location = tostring(LocationDetails.countryOrRegion),
    ResourceDisplayName,
    ResultType
| extend
    SPRisk = case(
        ResourceDisplayName has_any ("Microsoft Graph", "Azure Active Directory", "Windows Azure Service Management"),
            "HIGH - SP accessing admin resources post-federation-change",
        "REVIEW"
    )
| where SPRisk != "REVIEW"
| sort by TimeGenerated asc
```

**Performance Notes:**
- `TokenIssuerType == "ADFederationServices"` isolates all federated sign-ins from password-hash-sync or cloud-native sign-ins
- `TokenIssuerName` contains the actual STS endpoint that issued the token -- comparing this against `ExpectedIssuerUri` detects issuer impersonation
- The 72-hour forward window captures delayed exploitation -- sophisticated attackers may wait before using forged tokens
- `AuthenticationProtocol` can distinguish SAML from WS-Federation tokens

**Tuning Guidance:**
- **Issuer mismatch is the strongest signal**: If `TokenIssuerName` does not match the expected AD FS endpoint, the token was forged by a different STS
- **Admin resource access via federation**: In the SolarWinds attack, the attackers used forged SAML tokens to access Azure AD and Microsoft Graph. Any federated sign-in to admin resources deserves scrutiny
- **Volume anomaly**: Compare the number of federated sign-ins in the forward window against the `BaselineDailyAvg`. A sudden spike in federated sign-ins after a federation change may indicate automated token forgery
- **New users appearing**: If `UserPrincipalName` values appear in federated sign-ins that were never in `BaselineUsers`, the attacker may be impersonating users who do not normally use federation
- Adjust off-hours thresholds based on the organization's timezone and work patterns

**Expected findings:**
- All federated sign-ins after the federation trust modification
- Whether any tokens were issued by an unexpected STS (issuer mismatch)
- Whether forged tokens were used to access administrative resources
- Whether the volume or pattern of federated sign-ins changed after the modification

**Next action:**
- If issuer mismatch found, confirm Golden SAML attack -- proceed to containment immediately
- If admin resource access detected via federation, cross-reference with Step 6 for post-compromise actions
- If no suspicious federated sign-ins found, the attacker may not have used forged tokens yet -- continue monitoring

---

### Step 6: Post-Compromise Activity Assessment

**Purpose:** If the federation trust was modified maliciously, determine what the attacker did after gaining the ability to forge tokens. In the SolarWinds attack, Midnight Blizzard used forged SAML tokens to: create new admin accounts, assign Global Admin roles, grant application permissions, access executive mailboxes, and modify security configurations. This step checks for all of these post-compromise activities.

**Data needed:** AuditLogs, OfficeActivity, AzureActivity

```kql
// ============================================================
// QUERY 6: Post-Compromise Activity Assessment
// Purpose: Detect attacker actions after federation trust compromise
// Tables: AuditLogs, OfficeActivity, AzureActivity
// Investigation Step: 6 - Post-Compromise Activity Assessment
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 72h;
let TargetDomain = "contoso.com";
// --- Post-compromise Entra ID actions ---
let PostCompromiseAudit = AuditLogs
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where OperationName in (
    // Admin account creation and role assignment
    "Add user",
    "Add member to role",
    "Add eligible member to role",
    "Add owner to application",
    "Add owner to service principal",
    // Application permission grants
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to service principal",
    "Add service principal credentials",
    "Add application",
    "Add service principal",
    // Security configuration changes
    "Set domain authentication",
    "Set federation settings on domain",
    "Update conditional access policy",
    "Delete conditional access policy",
    "Disable Strong Authentication",
    // Additional persistence
    "User registered security info",
    "Update user",
    "Set Company Information",
    "Set directory setting"
)
| project
    TimeGenerated,
    Source = "AuditLogs",
    OperationName,
    ActorUPN = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetResource = tostring(TargetResources[0].displayName),
    TargetType = tostring(TargetResources[0].type),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties),
    Result
| extend
    ActionCategory = case(
        OperationName has_any ("Add user", "Add member to role", "Add eligible member to role"),
            "PRIVILEGE_ESCALATION",
        OperationName has_any ("Consent to application", "delegated permission", "app role assignment", "Add application", "Add service principal"),
            "APP_ABUSE",
        OperationName has_any ("credentials", "owner"),
            "PERSISTENCE",
        OperationName has_any ("conditional access", "Strong Authentication", "federation", "domain authentication"),
            "SECURITY_BYPASS",
        OperationName has_any ("security info", "Update user"),
            "ACCOUNT_MODIFICATION",
        "OTHER"
    ),
    PostCompromiseRisk = case(
        OperationName has "member to role" and ModifiedProperties has_any ("Global", "Security Admin", "Exchange"),
            "CRITICAL - Admin role assigned post-compromise (backdoor admin)",
        OperationName has "conditional access" and OperationName has_any ("Delete", "Update"),
            "CRITICAL - Conditional Access modified to weaken security",
        OperationName has "Consent to application" and ModifiedProperties has_any ("Mail.ReadWrite", "Directory.ReadWrite"),
            "CRITICAL - High-privilege app consent (data exfiltration path)",
        OperationName has "service principal credentials",
            "HIGH - Service principal credential added (persistent API access)",
        OperationName has "Add user",
            "HIGH - New user created (potential backdoor account)",
        OperationName has "Strong Authentication",
            "HIGH - MFA disabled on account",
        OperationName has "security info",
            "HIGH - Authentication method modified",
        "MEDIUM - Review in context"
    );
// --- Post-compromise email access ---
let PostCompromiseEmail = OfficeActivity
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where Operation in (
    "MailItemsAccessed",
    "Send",
    "SendAs",
    "SendOnBehalf",
    "New-InboxRule",
    "Set-InboxRule",
    "UpdateInboxRules",
    "Set-Mailbox",
    "Add-MailboxPermission",
    "Add-RecipientPermission"
)
| project
    TimeGenerated,
    Source = "OfficeActivity",
    OperationName = Operation,
    ActorUPN = UserId,
    ActorIP = ClientIP,
    TargetResource = coalesce(OfficeObjectId, SourceFileName),
    TargetType = OfficeWorkload,
    ModifiedProperties = "",
    Result = ResultStatus
| extend
    ActionCategory = case(
        OperationName in ("MailItemsAccessed", "Send", "SendAs", "SendOnBehalf"),
            "EMAIL_ACCESS",
        OperationName has_any ("InboxRule", "Mailbox", "MailboxPermission", "RecipientPermission"),
            "EMAIL_PERSISTENCE",
        "OTHER"
    ),
    PostCompromiseRisk = case(
        OperationName in ("SendAs", "SendOnBehalf"),
            "CRITICAL - Impersonation email sent (BEC)",
        OperationName has_any ("InboxRule", "Set-Mailbox"),
            "HIGH - Email rule created (exfiltration/hiding)",
        OperationName has_any ("MailboxPermission", "RecipientPermission"),
            "HIGH - Mailbox permissions modified",
        "MEDIUM - Email access"
    );
// --- Post-compromise Azure control plane actions ---
let PostCompromiseAzure = AzureActivity
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where OperationNameValue has_any (
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
    "MICROSOFT.AUTHORIZATION/ROLEDEFINITIONS/WRITE",
    "MICROSOFT.KEYVAULT/VAULTS/READ",
    "MICROSOFT.KEYVAULT/VAULTS/SECRETS/READ",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
    "MICROSOFT.RESOURCES/SUBSCRIPTIONS/PROVIDERS/REGISTER"
)
| project
    TimeGenerated,
    Source = "AzureActivity",
    OperationName = OperationNameValue,
    ActorUPN = Caller,
    ActorIP = CallerIpAddress,
    TargetResource = tostring(parse_json(Properties).resource),
    TargetType = ResourceGroup,
    ModifiedProperties = "",
    Result = ActivityStatusValue
| extend
    ActionCategory = "AZURE_CONTROL_PLANE",
    PostCompromiseRisk = case(
        OperationName has "ROLEASSIGNMENTS/WRITE",
            "CRITICAL - Azure role assignment (subscription takeover)",
        OperationName has "KEYVAULT",
            "HIGH - Key Vault access (credential harvesting)",
        OperationName has "LISTKEYS",
            "HIGH - Storage account keys accessed",
        "MEDIUM - Azure resource modification"
    );
// --- Combine all post-compromise activity ---
union PostCompromiseAudit, PostCompromiseEmail, PostCompromiseAzure
| sort by TimeGenerated asc
| extend
    HoursAfterCompromise = round(datetime_diff('minute', TimeGenerated, AlertTime) / 60.0, 1)
```

**Performance Notes:**
- The 72-hour forward window matches the SolarWinds attack pattern where Midnight Blizzard waited hours to days before using forged tokens
- Combining AuditLogs, OfficeActivity, and AzureActivity provides visibility across the entire Microsoft ecosystem
- `OperationNameValue` in AzureActivity uses uppercase -- the `has_any` operator handles case-insensitive matching

**Tuning Guidance:**
- **Backdoor admin account creation**: If a new user is created and immediately assigned Global Admin within hours of the federation change, this is the SolarWinds playbook
- **Conditional Access deletion/modification**: Attackers disable security controls to ensure their forged tokens are not blocked by CA policies
- **Service principal credential addition**: Adding credentials (secrets/certificates) to existing service principals provides persistent API access independent of user tokens
- **Email access patterns**: In the SolarWinds attack, the attackers targeted specific executives' mailboxes. Check if mail access targets C-suite, legal, or security team members
- **Azure role assignments**: If the attacker assigns themselves Owner or Contributor at the subscription level, they can access all Azure resources

**Expected findings:**
- Timeline of all suspicious actions following the federation trust modification
- Whether backdoor admin accounts or persistent access mechanisms were created
- Whether email or files were accessed (data exfiltration)
- Whether Azure control plane actions indicate subscription-level compromise

**Next action:**
- If multiple CRITICAL findings, this is an active Golden SAML attack -- execute containment playbook immediately
- For each backdoor account identified, add to the containment action list
- Document the complete post-compromise timeline for the incident report

---

### Step 7: Organization-Wide Federation and Trust Sweep

**Purpose:** Sweep all domains in the tenant for their current federation status. Check all verified and unverified domains for unexpected federation configurations. Identify all federated domains with their issuer URIs and signing certificates. An attacker may have modified federation for a secondary or less-monitored domain in the tenant.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 7: Organization-Wide Federation and Trust Sweep
// Purpose: Audit all domain federation configurations across the tenant
// Tables: AuditLogs
// Investigation Step: 7 - Organization-Wide Federation and Trust Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- All domain-related operations in the last 90 days ---
let DomainOperations = AuditLogs
| where TimeGenerated >= ago(90d)
| where OperationName in (
    "Set domain authentication",
    "Set federation settings on domain",
    "Set DomainFederationSettings",
    "Update domain",
    "Add unverified domain",
    "Verify domain",
    "Add domain to company",
    "Remove unverified domain",
    "Remove domain from company"
)
| project
    TimeGenerated,
    OperationName,
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    DomainName = tostring(TargetResources[0].displayName),
    DomainId = tostring(TargetResources[0].id),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties),
    Result;
// --- Per-domain federation audit summary ---
DomainOperations
| summarize
    TotalChanges = count(),
    LastChange = max(TimeGenerated),
    FirstChange = min(TimeGenerated),
    UniqueActors = dcount(ActorUPN),
    Actors = make_set(ActorUPN, 20),
    ActorIPs = make_set(ActorIP, 20),
    Operations = make_set(OperationName, 20),
    HasFederationChange = countif(OperationName has_any ("federation", "domain authentication", "DomainFederationSettings")),
    HasCertificateChange = countif(ModifiedProperties has "SigningCertificate"),
    HasIssuerChange = countif(ModifiedProperties has "IssuerUri"),
    HasAuthTypeChange = countif(ModifiedProperties has_any ("Authentication", "AuthenticationType")),
    LatestModifiedProperties = take_any(ModifiedProperties)
    by DomainName
| extend
    DomainRisk = case(
        HasCertificateChange > 0 and HasIssuerChange > 0,
            "CRITICAL - Both certificate AND issuer changed (full federation takeover)",
        HasCertificateChange > 0,
            "HIGH - Signing certificate was modified",
        HasIssuerChange > 0,
            "HIGH - Issuer URI was modified",
        HasAuthTypeChange > 0 and LatestModifiedProperties has "Federated",
            "HIGH - Domain converted to federated authentication",
        HasFederationChange > 0,
            "MEDIUM - Federation settings were modified",
        OperationName has_any ("Add unverified", "Add domain") and array_length(Actors) == 1,
            "MEDIUM - New domain added (verify legitimacy)",
        "LOW - Domain management operations only"
    ),
    DayssinceLastChange = datetime_diff("day", now(), LastChange)
| where DomainRisk != "LOW"
| project
    DomainName,
    DomainRisk,
    TotalChanges,
    UniqueActors,
    Actors,
    HasCertificateChange,
    HasIssuerChange,
    HasAuthTypeChange,
    LastChange,
    DayssinceLastChange,
    ActorIPs
| sort by case(
    DomainRisk has "CRITICAL", 1,
    DomainRisk has "HIGH", 2,
    3
) asc, LastChange desc
```

```kql
// ============================================================
// QUERY 7B: Recently Added Domains (Potential Shadow Federation)
// Purpose: Detect newly added domains that may have been
//          configured for federation by an attacker
// Tables: AuditLogs
// Investigation Step: 7 - Organization-Wide Federation Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
AuditLogs
| where TimeGenerated >= ago(30d)
| where OperationName in (
    "Add unverified domain",
    "Verify domain",
    "Add domain to company"
)
| project
    TimeGenerated,
    OperationName,
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    DomainName = tostring(TargetResources[0].displayName),
    Result
| extend
    ShadowFederationRisk = case(
        // Domain added AND verified by the same actor in quick succession
        OperationName == "Verify domain",
            "HIGH - Domain verified (attacker may configure federation on this domain)",
        OperationName == "Add unverified domain",
            "MEDIUM - New domain added (watch for subsequent federation configuration)",
        "REVIEW"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- Scanning 90 days captures all recent domain and federation changes across the tenant
- The per-domain summary using `summarize by DomainName` provides a consolidated view of each domain's change history
- `HasCertificateChange` and `HasIssuerChange` are computed from `ModifiedProperties` content analysis
- Query 7B specifically targets newly added domains, which is a separate attack vector where the attacker adds their own domain and configures federation on it

**Tuning Guidance:**
- **CRITICAL: Certificate + Issuer change on any domain**: This is a full federation takeover -- the attacker replaced both the signing certificate and the endpoint
- **Shadow domain attack**: An attacker may add a new domain (e.g., `contoso-backup.com`), verify it using DNS, and then configure federation on that domain. This creates a completely new federation trust that does not affect the primary domain's configuration
- **Multiple domains with changes from the same actor**: If the same admin modified federation for multiple domains, check if this is a migration or an attack spreading across domains
- **Cross-reference with Step 2**: Ensure the actors listed in the sweep results are not compromised accounts

**Expected findings:**
- Complete audit of all domains with federation-related changes in the last 90 days
- Identification of any domains with unexpected federation configurations
- Detection of newly added domains that may have been set up for shadow federation

**Next action:**
- For each CRITICAL or HIGH risk domain, perform a detailed investigation (Steps 1-3) specific to that domain
- For newly added domains, verify DNS ownership and organizational legitimacy
- If shadow domains are found, remove them and block the actor

---

### Step 8: UEBA Enrichment - Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to assess whether the federation trust modification is anomalous for the actor who performed it. Federation changes are extraordinarily rare actions -- `FirstTimeActionPerformed` should almost certainly be `True` for any user, and `ActionUncommonlyPerformedAmongPeers` should be `True` for all but dedicated infrastructure administrators. UEBA provides critical context for distinguishing a planned change from an attacker's actions.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 4. UEBA needs approximately **one week** after activation before generating meaningful insights.

#### Query 8A: Federation Change Actor Anomaly Assessment

```kql
// ============================================================
// Query 8A: UEBA Anomaly Assessment for Federation Change Actor
// Purpose: Check if UEBA flagged the federation modification
//          as anomalous for the actor who performed it
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let SuspiciousActorUPN = "admin@contoso.com";
let LookbackWindow = 7d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
| where UserPrincipalName =~ SuspiciousActorUPN
| project
    TimeGenerated,
    ActivityType,
    ActionType,
    InvestigationPriority,
    SourceIPAddress,
    SourceIPLocation,
    // Action analysis -- federation changes are extremely rare actions
    FirstTimeAction = tobool(ActivityInsights.FirstTimeUserPerformedAction),
    ActionUncommonForUser = tobool(ActivityInsights.ActionUncommonlyPerformedByUser),
    ActionUncommonAmongPeers = tobool(ActivityInsights.ActionUncommonlyPerformedAmongPeers),
    ActionUncommonInTenant = tobool(ActivityInsights.ActionUncommonlyPerformedInTenant),
    // Application context
    FirstTimeApp = tobool(ActivityInsights.FirstTimeUserUsedApp),
    AppUncommonForUser = tobool(ActivityInsights.AppUncommonlyUsedByUser),
    AppUncommonAmongPeers = tobool(ActivityInsights.AppUncommonlyUsedAmongPeers),
    // Source context -- where did the actor connect from
    FirstTimeISP = tobool(ActivityInsights.FirstTimeUserConnectedViaISP),
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommon = tobool(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    ISPUncommon = tobool(ActivityInsights.ISPUncommonlyUsedByUser),
    // User profile
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    IsNewAccount = tobool(UsersInsights.IsNewAccount),
    // Threat intel
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| order by InvestigationPriority desc, TimeGenerated desc
```

#### Query 8B: Post-Federation-Change Activity Anomalies

```kql
// ============================================================
// Query 8B: Post-Federation-Change Behavioral Analysis
// Purpose: Assess whether activity AFTER the federation change
//          deviates from normal patterns (forged token usage)
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <10 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let SuspiciousActorUPN = "admin@contoso.com";
let PostChangeWindow = 72h;
BehaviorAnalytics
| where TimeGenerated between (AlertTime .. (AlertTime + PostChangeWindow))
| where UserPrincipalName =~ SuspiciousActorUPN
| summarize
    TotalActivities = count(),
    HighAnomalyCount = countif(InvestigationPriority >= 7),
    MediumAnomalyCount = countif(InvestigationPriority >= 4 and InvestigationPriority < 7),
    MaxPriority = max(InvestigationPriority),
    // Action anomalies (federation-related)
    FirstTimeActionCount = countif(tobool(ActivityInsights.FirstTimeUserPerformedAction)),
    UncommonActionAmongPeers = countif(tobool(ActivityInsights.ActionUncommonlyPerformedAmongPeers)),
    UncommonActionInTenant = countif(tobool(ActivityInsights.ActionUncommonlyPerformedInTenant)),
    // Resource access anomalies (forged token accessing new resources)
    FirstTimeResourceCount = countif(tobool(ActivityInsights.FirstTimeUserAccessedResource)),
    ResourceUncommonForUser = countif(tobool(ActivityInsights.ResourceUncommonlyAccessedByUser)),
    ResourceUncommonAmongPeers = countif(tobool(ActivityInsights.ResourceUncommonlyAccessedAmongPeers)),
    // Volume anomalies (automated exploitation)
    HighVolumeEvents = countif(tobool(ActivityInsights.UncommonHighVolumeOfActions)),
    // Location anomalies
    NewCountryEvents = countif(tobool(ActivityInsights.FirstTimeUserConnectedFromCountry)),
    NewISPEvents = countif(tobool(ActivityInsights.FirstTimeUserConnectedViaISP)),
    UniqueIPs = dcount(SourceIPAddress),
    Countries = make_set(SourceIPLocation),
    ActivityTypes = make_set(ActivityType),
    BlastRadius = take_any(tostring(UsersInsights.BlastRadius))
| extend
    AnomalyRatio = round(todouble(HighAnomalyCount + MediumAnomalyCount) / TotalActivities * 100, 1),
    FederationCompromiseSignals = FirstTimeActionCount + UncommonActionInTenant
        + FirstTimeResourceCount + HighVolumeEvents + NewCountryEvents
```

**Tuning Guidance:**

- **InvestigationPriority threshold**: `>= 7` = high-confidence anomaly, `>= 4` = moderate, `< 4` = likely normal
- **FirstTimeAction = true**: Federation changes are so rare that this should be `True` for almost every user. If `False`, the user regularly makes federation changes -- likely the designated AD FS administrator
- **ActionUncommonInTenant = true**: If NO ONE in the entire tenant typically performs this action, it is a strong anomaly. This is expected for federation changes
- **Post-change resource access**: After a Golden SAML attack, the attacker accesses high-value resources (executive mailboxes, Azure subscriptions, Global Admin portal). Multiple `FirstTimeResource` flags indicate the attacker is exploring the tenant with forged tokens
- **HighVolumeEvents**: Automated token forgery generates a high volume of actions in a short time -- this is a strong indicator of systematic exploitation

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| InvestigationPriority | >= 7 (high anomaly) | < 4 (normal behavior for AD FS admin) |
| FirstTimeAction | true -- first time modifying federation | false -- regularly manages federation |
| ActionUncommonAmongPeers | true -- peers do not modify federation | false -- other admins do this regularly |
| ActionUncommonInTenant | true -- nobody does this in the org | false -- routine for infrastructure team |
| FirstTimeCountry + FirstTimeISP | true -- actor from new location | false -- known admin workstation |
| Post-change FirstTimeResource | Multiple new resources accessed (exploitation) | No unusual resource access |
| UncommonHighVolume | true -- automated exploitation | false -- normal activity volume |
| BlastRadius | High -- Global Admin account | Low -- limited admin role |
| IsDormantAccount | true -- dormant admin performing federation change | false -- active admin account |

**Decision guidance:**

- **FirstTimeAction = true + ActionUncommonInTenant = true + certificate change (Step 3)** --> Highest risk. An actor who has never performed federation changes, performing an action no one in the org does, and replacing the signing certificate. This is almost certainly a Golden SAML attack. Execute containment immediately.
- **InvestigationPriority >= 7 + post-change resource access** --> The federation change actor's subsequent activities are highly anomalous. Strong evidence of exploitation with forged tokens.
- **FirstTimeAction = false + known admin IP + scheduled change** --> The designated AD FS administrator performing a routine certificate rotation. Combined with clean findings from Steps 1-4, consider closing as planned maintenance.
- **IsDormantAccount = true** --> A dormant admin account suddenly performing federation changes is a critical indicator of account takeover via credential theft.
- **FederationCompromiseSignals >= 3** --> Multiple anomalous signals post-change indicate active exploitation. Proceed to Containment.

---

## 6. Containment Playbook

### Immediate Actions (First 30 Minutes)

| Priority | Action | Command/Location | Who |
|---|---|---|---|
| P0 | Restore previous federation certificate | `Set-MsolDomainFederationSettings` or MS Graph API -- restore the old signing certificate from Step 1/3 `OldValue` | Global Admin |
| P0 | Revoke ALL sessions tenant-wide | Entra Portal > Protection > Conditional Access > Session controls OR `Revoke-MgUserSignInSession` for all users | Global Admin |
| P0 | Disable the compromised admin account | Entra Portal > Users > [Admin] > Block sign-in | Security Admin |
| P0 | Rotate SAML signing certificate on AD FS | AD FS Management Console > Service > Certificates > Set new token-signing certificate | AD FS Admin |
| P1 | Force password reset for ALL Global Admins | Entra Portal > Users > All Global Admins > Reset Password | Global Admin |
| P1 | Review and disable any backdoor admin accounts | Check Step 6 results for newly created admin accounts | Security Admin |
| P1 | Re-verify all federation configurations | PowerShell: `Get-MsolDomainFederationSettings` for all federated domains | Global Admin |

### Secondary Actions (First 4 Hours)

| Priority | Action | Details |
|---|---|---|
| P2 | Audit all federated sign-ins since the change | Export Step 5 results, identify all users who authenticated via federation after the change |
| P2 | Review all role assignments made since the change | Check for unauthorized admin role grants from Step 6 |
| P2 | Review all application consent grants since the change | Check for unauthorized OAuth app consents from Step 6 |
| P2 | Check AD FS server for compromise | Audit AD FS server logs, check for unauthorized access, verify no additional certificates were exported |
| P3 | Evaluate domain conversion to managed auth | Consider migrating from AD FS federation to Password Hash Sync (PHS) to eliminate the Golden SAML attack surface |
| P3 | Implement certificate rotation monitoring | Deploy Azure AD Connect Health alerting for AD FS certificate changes |
| P3 | Enable federation change alerting in Sentinel | Create analytics rule for all federation-related AuditLog events |

### Federation Restoration Commands

```powershell
# Restore federation settings using Microsoft Graph PowerShell
# Connect with Global Administrator credentials
Connect-MgGraph -Scopes "Domain.ReadWrite.All"

# Step 1: Get current federation configuration (document before changing)
$domain = "contoso.com"
Get-MgDomainFederationConfiguration -DomainId $domain

# Step 2: Update the signing certificate back to the legitimate certificate
# Use the OldValue from Step 1/3 query results
Update-MgDomainFederationConfiguration `
    -DomainId $domain `
    -InternalDomainFederationId "federation-config-id" `
    -SigningCertificate "LEGITIMATE_BASE64_CERTIFICATE_FROM_OLDVALUE"

# Step 3: Revoke all user sessions tenant-wide
# WARNING: This will sign out ALL users in the tenant
Get-MgUser -All | ForEach-Object {
    Revoke-MgUserSignInSession -UserId $_.Id
}

# Step 4: If converting to managed authentication (eliminating federation)
# WARNING: This is a major change -- all federated users will need to use PHS or PTA
Update-MgDomain -DomainId $domain -AuthenticationType "Managed"
```

### SolarWinds-Specific Remediation

If this incident matches the SolarWinds/Midnight Blizzard pattern:

1. **Assume full AD FS compromise** -- the on-premises AD FS server is compromised
2. **Rebuild AD FS infrastructure** -- do not trust the existing AD FS farm; rebuild from scratch
3. **Rotate ALL signing certificates** -- both primary and secondary (NextSigningCertificate)
4. **Audit on-premises Active Directory** -- check for Golden Ticket, Silver Ticket, and DCSync indicators
5. **Consider eliminating federation entirely** -- migrate to Password Hash Sync + Conditional Access to remove the AD FS dependency and the Golden SAML attack surface

---

## 7. Evidence Collection Checklist

| Evidence | Source | Retention | Priority |
|---|---|---|---|
| Federation trust modification event (AuditLogs) | Microsoft Sentinel | Export full query results with ModifiedProperties | Critical |
| Old and new signing certificate values | AuditLogs ModifiedProperties field | Export full base64 certificate values | Critical |
| Admin account compromise timeline | SigninLogs + AuditLogs | Export Step 2 query results | Critical |
| Federated sign-ins after modification | SigninLogs | Export Step 5 query results | Critical |
| Post-compromise actions | AuditLogs + OfficeActivity + AzureActivity | Export Step 6 query results | Critical |
| AD FS server event logs | On-premises AD FS (Event ID 307, 510) | Export Windows Event Logs | Critical |
| Current domain federation configurations | `Get-MgDomainFederationConfiguration` output | JSON export | High |
| All domain configurations in tenant | `Get-MgDomain` output | JSON export | High |
| AD FS certificate store | AD FS Management Console | Screenshot + certificate export | High |
| Organization PKI CA records | Internal CA infrastructure | Certificate audit trail | High |
| UEBA behavioral assessment | BehaviorAnalytics | Export Step 8 query results | Medium |

---

## 8. Escalation Criteria

### Escalate to Incident Commander When:
- Federation signing certificate was replaced with an unknown certificate (confirmed Golden SAML)
- Federation issuer URI was changed to an external or unknown endpoint
- The admin who modified federation was recently compromised (password reset, new MFA, anomalous sign-in)
- Post-compromise activity detected: new admin accounts, role assignments, app consents (Step 6)
- Multiple domains in the tenant have unexpected federation configurations (Step 7)

### Escalate to Legal/Privacy When:
- Forged SAML tokens were used to access executive mailboxes (SolarWinds pattern)
- Data exfiltration from SharePoint, OneDrive, or Exchange confirmed via post-compromise analysis
- The attack matches the SolarWinds/Midnight Blizzard TTP pattern, indicating potential nation-state actor
- Regulatory notification may be required (GDPR, HIPAA, SOX, SEC disclosure requirements)

### Escalate to Microsoft When:
- The attack involves a Microsoft-managed signing key (Storm-0558 pattern)
- Multiple tenants may be affected via shared federation infrastructure
- AD FS infrastructure hosted in Azure may have been compromised via Azure-level attack
- Report via: Microsoft Security Response Center (MSRC) or Microsoft 365 Defender portal
- Reference: Microsoft emergency response for federation compromise

### Escalate to National CERT/CISA When:
- The attack pattern matches SolarWinds/Midnight Blizzard (APT29) TTPs
- The organization is in a critical infrastructure sector
- The federation compromise may be part of a broader supply chain attack
- Reference: CISA Emergency Directive 21-01 (SolarWinds response)

---

## 9. False Positive Documentation

| Scenario | How to Verify | Action |
|---|---|---|
| Scheduled AD FS certificate rotation | Verify against certificate expiration date and change management ticket; new certificate should match org PKI CA | Document as planned rotation, confirm certificate issuer matches organizational CA |
| Planned migration from AD FS to PHS/PTA | Verify against migration project plan and change management records | Document as planned migration, verify the domain authentication type change is expected |
| AD FS farm rebuild or disaster recovery | Verify against DR runbook and infrastructure team communication | Document as DR activity, confirm new certificates were generated from org CA |
| Initial federation setup during hybrid deployment | Verify against Azure AD Connect deployment project | Document as initial setup, confirm all certificates and endpoints are legitimate |
| M&A domain addition with federation | Verify against M&A integration plan and legal/IT team communication | Document as planned, verify the acquired organization's federation configuration |

---

## 10. MITRE ATT&CK Mapping

| Technique | ID | Tactic | How Detected |
|---|---|---|---|
| **Domain Policy Modification: Trust Modification** | **T1484.002** | **Persistence, Privilege Escalation** | **Federation trust settings modified in AuditLogs (Step 1)** |
| **Forge Web Credentials: SAML Tokens** | **T1606.002** | **Credential Access** | **Forged SAML tokens detected in SigninLogs (Step 5)** |
| Unsecured Credentials: Private Keys | T1552.004 | Credential Access | Certificate replacement indicates private key compromise (Step 3) |
| Valid Accounts: Cloud Accounts | T1078.004 | Defense Evasion, Lateral Movement | Forged tokens used to access cloud resources as legitimate users (Steps 5, 6) |

---

## 11. Query Summary

| # | Query | Table | Purpose |
|---|---|---|---|
| 1 | Federation Trust Change Detection | AuditLogs | Detect all federation configuration modifications |
| 2 | Actor Attribution and Compromise Assessment | SigninLogs, AuditLogs | Determine if the admin was compromised before making the change |
| 3 | Federation Certificate Analysis | AuditLogs | Compare old vs new certificates, detect Golden SAML indicators |
| 4 | Baseline Comparison | AuditLogs | Compare federation changes against 90-day historical baseline |
| 5 | Suspicious SAML Token Detection | SigninLogs, AADServicePrincipalSignInLogs | Detect forged SAML tokens after trust compromise |
| 5B | SP Federated Sign-Ins | AADServicePrincipalSignInLogs | Detect service principals using potentially forged tokens |
| 6 | Post-Compromise Activity Assessment | AuditLogs, OfficeActivity, AzureActivity | Detect attacker actions after federation compromise |
| 7 | Org-Wide Federation Sweep | AuditLogs | Audit all domains for unexpected federation configurations |
| 7B | Recently Added Domains | AuditLogs | Detect shadow domains configured for attacker federation |
| 8A | UEBA Actor Assessment | BehaviorAnalytics | Behavioral anomaly context for federation change actor |
| 8B | UEBA Post-Change Anomalies | BehaviorAnalytics | Post-change activity deviation analysis |

---

## Appendix A: Datatable Tests

### Test 1: Federation Trust Change Detection

```kql
// ============================================================
// TEST 1: Federation Trust Change Detection
// Validates: Query 1 - Detect federation modifications and classify risk
// Expected: Certificate change = "CRITICAL - Signing certificate replaced"
//           Auth type change = "CRITICAL - Domain converted to federated"
//           Domain added = "REVIEW"
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Golden SAML: Signing certificate replaced ---
    datetime(2026-02-22T14:00:00Z), "Set federation settings on domain",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"contoso.com","id":"domain-001","type":"Domain",
            "modifiedProperties":[
                {"displayName":"SigningCertificate","oldValue":"MIIC8jCCAdqgAwIBAgIQOLDEgOLD...","newValue":"MIIDxjCCAq6gAwIBAgIQATTACKER..."},
                {"displayName":"IssuerUri","oldValue":"http://sts.contoso.com/adfs/services/trust","newValue":"http://evil-sts.attacker.com/adfs/services/trust"}
            ]}]),
        "success",
    // --- Legitimate: Domain authentication type change (managed to federated) ---
    datetime(2026-02-22T10:00:00Z), "Set domain authentication",
        dynamic({"user":{"userPrincipalName":"infra.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"displayName":"subsidiary.contoso.com","id":"domain-002","type":"Domain",
            "modifiedProperties":[
                {"displayName":"Authentication","oldValue":"Managed","newValue":"Federated"}
            ]}]),
        "success",
    // --- Low risk: New domain added ---
    datetime(2026-02-22T09:00:00Z), "Add unverified domain",
        dynamic({"user":{"userPrincipalName":"it.admin@contoso.com","ipAddress":"10.0.0.10"}}),
        dynamic([{"displayName":"newbrand.contoso.com","id":"domain-003","type":"Domain",
            "modifiedProperties":[]}]),
        "success"
];
// --- Run detection query ---
TestAuditLogs
| where OperationName in (
    "Set domain authentication",
    "Set federation settings on domain",
    "Set DomainFederationSettings",
    "Update domain",
    "Add unverified domain",
    "Verify domain"
)
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetDomainName = tostring(TargetResources[0].displayName),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    RiskLevel = case(
        PropertyName has "SigningCertificate" and isnotempty(NewValue),
            "CRITICAL - Signing certificate replaced (Golden SAML indicator)",
        PropertyName has "IssuerUri" and isnotempty(NewValue) and isnotempty(OldValue),
            "CRITICAL - Issuer URI changed (federation redirected)",
        PropertyName has "Authentication" and NewValue has "Federated",
            "CRITICAL - Domain converted to federated authentication",
        "REVIEW - Federation property changed"
    )
| project ActorUPN, TargetDomainName, PropertyName, RiskLevel, OldValue, NewValue
// Expected: contoso.com SigningCertificate = "CRITICAL - Signing certificate replaced"
// Expected: contoso.com IssuerUri = "CRITICAL - Issuer URI changed"
// Expected: subsidiary.contoso.com Authentication = "CRITICAL - Domain converted to federated"
```

### Test 2: Actor Compromise Assessment

```kql
// ============================================================
// TEST 2: Actor Compromise Assessment
// Validates: Query 2 - Detect if the admin who modified federation was compromised
// Expected: compromised.admin shows password reset + MFA change + role assignment
//           = multiple HIGH/CRITICAL compromise indicators
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Attacker resets admin password ---
    datetime(2026-02-21T08:00:00Z), "Reset password (by admin)",
        dynamic({"user":{"userPrincipalName":"attacker.helpdesk@contoso.com","ipAddress":"203.0.113.99"}}),
        dynamic([{"userPrincipalName":"compromised.admin@contoso.com","displayName":"Compromised Admin","type":"User",
            "modifiedProperties":[]}]),
        "success",
    // --- Attacker registers new MFA method on compromised admin ---
    datetime(2026-02-21T08:30:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"203.0.113.99"}}),
        dynamic([{"userPrincipalName":"compromised.admin@contoso.com","displayName":"Compromised Admin","type":"User",
            "modifiedProperties":[{"displayName":"StrongAuthenticationMethod","oldValue":"","newValue":"PhoneAppNotification"}]}]),
        "success",
    // --- Attacker assigns Global Admin role ---
    datetime(2026-02-21T09:00:00Z), "Add member to role",
        dynamic({"user":{"userPrincipalName":"attacker.helpdesk@contoso.com","ipAddress":"203.0.113.99"}}),
        dynamic([{"userPrincipalName":"compromised.admin@contoso.com","displayName":"Compromised Admin","type":"User",
            "modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"","newValue":"Global Administrator"}]}]),
        "success",
    // --- Compromised admin modifies federation (the actual attack) ---
    datetime(2026-02-22T14:00:00Z), "Set federation settings on domain",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"203.0.113.99"}}),
        dynamic([{"displayName":"contoso.com","id":"domain-001","type":"Domain",
            "modifiedProperties":[
                {"displayName":"SigningCertificate","oldValue":"MIIC8jCCAdqgAwIB...","newValue":"MIIDxjCCAq6gAwIB..."}
            ]}]),
        "success"
];
let SuspiciousActorUPN = "compromised.admin@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- Detect compromise chain ---
TestAuditLogs
| where OperationName in (
    "Reset password",
    "Reset password (by admin)",
    "User registered security info",
    "Add member to role",
    "Set federation settings on domain"
)
| where TargetResources has SuspiciousActorUPN
    or InitiatedBy has SuspiciousActorUPN
| project
    TimeGenerated,
    OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    CompromiseIndicator = case(
        OperationName has "Reset password" and InitiatedByUser != SuspiciousActorUPN,
            "HIGH - Password reset by different admin (possible takeover prep)",
        OperationName has "security info" and TimeGenerated between (AlertTime - 48h .. AlertTime),
            "HIGH - MFA method changed shortly before federation modification",
        OperationName has "member to role" and ModifiedProperties has "Global",
            "CRITICAL - Global Admin role assigned before federation change",
        OperationName has "federation",
            "CRITICAL - Federation trust modified by this actor",
        "REVIEW"
    )
| sort by TimeGenerated asc
// Expected: 4 events in chronological order showing the full compromise chain
// Expected: Reset password = "HIGH - Password reset by different admin"
// Expected: MFA registration = "HIGH - MFA method changed shortly before federation modification"
// Expected: Role assignment = "CRITICAL - Global Admin role assigned before federation change"
// Expected: Federation change = "CRITICAL - Federation trust modified by this actor"
```

### Test 3: Baseline Comparison - Federation Change Frequency

```kql
// ============================================================
// TEST 3: Baseline Comparison - Federation Change Frequency
// Validates: Query 4 - Compare current change against historical baseline
// Expected: Tenant with 0 prior federation changes = "HIGHLY ANOMALOUS"
//           Active migration tenant = "WITHIN BASELINE"
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Scenario A: Tenant with NO prior federation changes ---
    // (Only the current suspicious change exists)
    datetime(2026-02-22T14:00:00Z), "Set federation settings on domain",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"contoso.com","id":"domain-001","type":"Domain"}]),
        "success"
];
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 90d;
// --- Federation change baseline (should be zero for Scenario A) ---
TestAuditLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
| where OperationName in (
    "Set domain authentication",
    "Set federation settings on domain",
    "Set DomainFederationSettings",
    "Update domain"
)
// Exclude the current alert event from baseline
| where TimeGenerated < AlertTime
| summarize
    TotalFederationChanges = count(),
    UniqueActors = dcount(tostring(InitiatedBy.user.userPrincipalName)),
    Actors = make_set(tostring(InitiatedBy.user.userPrincipalName), 20)
| extend
    Assessment = case(
        TotalFederationChanges == 0,
            "HIGHLY ANOMALOUS - ZERO federation changes in the last 90 days. Current change is unprecedented.",
        TotalFederationChanges <= 2,
            "ANOMALOUS - Federation changes are extremely rare (1-2 in 90 days).",
        TotalFederationChanges <= 5,
            "SUSPICIOUS - Moderate federation activity.",
        "WITHIN BASELINE - Federation changes occur regularly."
    )
| project TotalFederationChanges, UniqueActors, Actors, Assessment
// Expected: TotalFederationChanges = 0
// Expected: Assessment = "HIGHLY ANOMALOUS - ZERO federation changes in the last 90 days."
```

### Test 4: Post-Compromise Activity Detection

```kql
// ============================================================
// TEST 4: Post-Compromise Activity Detection
// Validates: Query 6 - Detect attacker actions after federation compromise
// Expected: Backdoor admin creation = "CRITICAL"
//           CA policy deletion = "CRITICAL"
//           SP credential addition = "HIGH"
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Attacker creates backdoor admin account ---
    datetime(2026-02-22T15:00:00Z), "Add user",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"svc_backup_sync","userPrincipalName":"svc_backup_sync@contoso.com","type":"User",
            "modifiedProperties":[]}]),
        "success",
    // --- Attacker assigns Global Admin to backdoor account ---
    datetime(2026-02-22T15:05:00Z), "Add member to role",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"svc_backup_sync","userPrincipalName":"svc_backup_sync@contoso.com","type":"User",
            "modifiedProperties":[{"displayName":"Role.DisplayName","oldValue":"","newValue":"Global Administrator"}]}]),
        "success",
    // --- Attacker deletes Conditional Access policy ---
    datetime(2026-02-22T15:10:00Z), "Delete conditional access policy",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Require MFA for All Users","id":"ca-policy-001","type":"Policy",
            "modifiedProperties":[]}]),
        "success",
    // --- Attacker adds credential to existing service principal ---
    datetime(2026-02-22T15:20:00Z), "Add service principal credentials",
        dynamic({"user":{"userPrincipalName":"compromised.admin@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Contoso Production API","id":"sp-001","type":"ServicePrincipal",
            "modifiedProperties":[{"displayName":"KeyDescription","oldValue":"","newValue":"Added by admin"}]}]),
        "success",
    // --- Legitimate activity (should be lower risk) ---
    datetime(2026-02-22T16:00:00Z), "Update user",
        dynamic({"user":{"userPrincipalName":"hr.admin@contoso.com","ipAddress":"10.0.0.15"}}),
        dynamic([{"displayName":"New Employee","userPrincipalName":"new.employee@contoso.com","type":"User",
            "modifiedProperties":[{"displayName":"Department","oldValue":"","newValue":"Engineering"}]}]),
        "success"
];
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 72h;
// --- Post-compromise detection ---
TestAuditLogs
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where OperationName in (
    "Add user",
    "Add member to role",
    "Delete conditional access policy",
    "Update conditional access policy",
    "Add service principal credentials",
    "Consent to application",
    "Update user"
)
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    TargetResource = tostring(TargetResources[0].displayName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    PostCompromiseRisk = case(
        OperationName has "member to role" and ModifiedProperties has_any ("Global", "Security Admin", "Exchange"),
            "CRITICAL - Admin role assigned post-compromise (backdoor admin)",
        OperationName has "conditional access" and OperationName has_any ("Delete", "Update"),
            "CRITICAL - Conditional Access modified to weaken security",
        OperationName has "service principal credentials",
            "HIGH - Service principal credential added (persistent API access)",
        OperationName has "Add user",
            "HIGH - New user created (potential backdoor account)",
        "MEDIUM - Review in context"
    ),
    HoursAfterCompromise = round(datetime_diff('minute', TimeGenerated, AlertTime) / 60.0, 1)
| project TimeGenerated, ActorUPN, OperationName, TargetResource, PostCompromiseRisk, HoursAfterCompromise
| sort by TimeGenerated asc
// Expected: Add user = "HIGH - New user created (potential backdoor account)"
// Expected: Add member to role (Global Admin) = "CRITICAL - Admin role assigned post-compromise"
// Expected: Delete CA policy = "CRITICAL - Conditional Access modified to weaken security"
// Expected: Add SP credentials = "HIGH - Service principal credential added"
// Expected: Update user (by hr.admin) = "MEDIUM - Review in context"
```

---

## References

- [Microsoft: Protecting Microsoft 365 from on-premises attacks](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks)
- [Microsoft: Security operations for Active Directory Federation Services](https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure#active-directory-federation-services)
- [Microsoft: Securing privileged access for hybrid and cloud deployments](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning)
- [Microsoft: Best practices for securing AD FS and Web Application Proxy](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs)
- [Microsoft: Migrate from federation to cloud authentication](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/migrate-from-federation-to-cloud-authentication)
- [Microsoft: AuditLogs reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- [CISA Emergency Directive 21-01: SolarWinds Orion Code Compromise](https://www.cisa.gov/news-events/directives/emergency-directive-21-01)
- [CISA: Detecting Post-Compromise Threat Activity Using SAML (AA21-008A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a)
- [NSA: Detecting Abuse of Authentication Mechanisms](https://media.defense.gov/2020/Dec/17/2002554125/-1/-1/0/AUTHENTICATION_MECHANISMS_CSA_U_OO_198854_20.PDF)
- [Mandiant: Remediation and Hardening Strategies for SolarWinds (UNC2452)](https://cloud.google.com/blog/topics/threat-intelligence/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452/)
- [MITRE ATT&CK T1484.002 - Domain Policy Modification: Trust Modification](https://attack.mitre.org/techniques/T1484/002/)
- [MITRE ATT&CK T1606.002 - Forge Web Credentials: SAML Tokens](https://attack.mitre.org/techniques/T1606/002/)
- [MITRE ATT&CK T1552.004 - Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/)
- [MITRE ATT&CK T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [Microsoft: SolarWinds post-compromise hunting guidance](https://www.microsoft.com/en-us/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/)
- [Sygnia: Golden SAML Technical Analysis](https://www.sygnia.co/golden-saml-advisory)
