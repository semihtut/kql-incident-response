---
title: "Emergency Access (Break-Glass) Account Activity"
id: RB-0023
severity: critical
status: reviewed
description: >
  Investigation runbook for detecting ANY activity from emergency access
  (break-glass) accounts in Microsoft Entra ID. Break-glass accounts are
  designed exclusively for catastrophic emergency scenarios -- they bypass
  MFA and Conditional Access policies by design. Any sign-in to a break-glass
  account is an alert-worthy event that demands immediate investigation.
  Covers interactive and non-interactive sign-in detection across a
  parameter-driven list of break-glass UPNs, authentication method
  verification, authorization cross-referencing with maintenance windows,
  historical usage baseline analysis (expected: near-zero), complete
  post-login audit trail of all actions taken with Global Admin privileges,
  credential security assessment, concurrent administrative activity
  correlation, and UEBA behavioral context enrichment. Break-glass accounts
  are the highest-privilege, lowest-oversight accounts in any tenant -- their
  compromise grants unrestricted, unmonitored access to the entire
  organization.
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
  techniques:
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1078
      technique_name: "Valid Accounts"
      confidence: confirmed
    - technique_id: T1556
      technique_name: "Modify Authentication Process"
      confidence: probable
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: probable
threat_actors:
  - "Midnight Blizzard (APT29/Nobelium)"
  - "Storm-0558"
  - "Scattered Spider (Octo Tempest)"
  - "LAPSUS$ (DEV-0537)"
  - "Volt Typhoon"
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
  - table: "AzureActivity"
    product: "Azure"
    license: "Azure Subscription"
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
  - SigninLogs
  - AADNonInteractiveUserSignInLogs
  - AuditLogs
  - AzureActivity
tactic_slugs:
  - persistence
  - priv-esc
  - defense-evasion
  - cred-access
data_checks:
  - query: "SigninLogs | take 1"
    label: primary
    description: "Interactive sign-in logs for break-glass login detection"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "Non-interactive sign-ins for token-based break-glass access"
  - query: "AuditLogs | take 1"
    description: "Audit logs for actions performed by break-glass account"
---

# Emergency Access (Break-Glass) Account Activity - Investigation Runbook

> **RB-0023** | Severity: Critical | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID SigninLogs + AADNonInteractiveUserSignInLogs
> **Detection Logic:** Any successful sign-in event from a designated break-glass account UPN
> **Primary MITRE Technique:** T1078.004 - Valid Accounts: Cloud Accounts

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Break-Glass Account Sign-In Detection](#step-1-break-glass-account-sign-in-detection)
   - [Step 2: Authentication Method and MFA Analysis](#step-2-authentication-method-and-mfa-analysis)
   - [Step 3: Authorization Verification -- Was This Login Expected?](#step-3-authorization-verification----was-this-login-expected)
   - [Step 4: Baseline Comparison -- Historical Break-Glass Usage](#step-4-baseline-comparison----historical-break-glass-usage)
   - [Step 5: Post-Login Activity Audit](#step-5-post-login-activity-audit)
   - [Step 6: Credential Security Assessment](#step-6-credential-security-assessment)
   - [Step 7: Concurrent Administrative Activity](#step-7-concurrent-administrative-activity)
   - [Step 8: UEBA Enrichment -- Behavioral Context Analysis](#step-8-ueba-enrichment----behavioral-context-analysis)
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
ANY sign-in event -- interactive or non-interactive -- to a designated emergency access (break-glass) account. Unlike other identity runbooks where the alert requires anomalous behavior to fire, break-glass account activity is **alert-by-existence**: every single sign-in is an alert because these accounts should almost never be used.

Detection sources:

1. **SigninLogs (Interactive):** A human user opened a browser, navigated to the Azure Portal or Microsoft 365 portal, and authenticated with the break-glass account credentials. This is the expected emergency usage pattern.
2. **AADNonInteractiveUserSignInLogs (Non-Interactive):** A token refresh, background SSO, or automated process is using the break-glass account's credentials. Non-interactive sign-ins are MORE suspicious than interactive ones because break-glass accounts should not be used for automation.
3. **Custom Sentinel Analytics Rule:** A scheduled query runs every 5-15 minutes checking for any sign-in event matching the break-glass UPN list.

**What are break-glass accounts:**
Emergency access (break-glass) accounts are highly privileged accounts in Microsoft Entra ID that are intentionally designed to bypass normal security controls:

- **Permanent Global Administrator** role assignment (not PIM-eligible -- always active)
- **Excluded from ALL Conditional Access policies** (no MFA requirement, no device compliance, no location restriction)
- **No MFA registered** (or FIDO2 security key stored in a physical safe)
- **Extremely long, complex password** stored in a physical safe or split-knowledge vault
- **Cloud-only account** (not synced from on-premises AD -- survives federation failures)
- **Purpose:** Regain access to the tenant when all other admin accounts are locked out (e.g., CA policy misconfiguration, MFA provider outage, federation service failure)

**Why this is CRITICAL severity:**
Break-glass accounts are the **most dangerous accounts in any Microsoft tenant** because:

- They have **permanent Global Administrator** rights -- unrestricted access to everything
- They **bypass MFA** -- authentication requires only the password (or FIDO2 key)
- They **bypass Conditional Access** -- no location, device, or risk-based restrictions
- They are **excluded from Identity Protection** risk policies -- risky sign-ins are not blocked
- Their activity is **less monitored** than regular admin accounts because they are expected to be dormant
- A compromised break-glass account gives the attacker **complete, unimpeded tenant control** with no security checkpoints

If an attacker obtains break-glass credentials, they have the most powerful, least restricted account in the organization. There is no MFA challenge, no CA policy enforcement, no device compliance check, and no risk-based blocking. The attacker can sign in from any device, any location, any network -- and immediately have Global Administrator access.

**However:** This alert has a **very low false positive rate** (~1-2%). The only legitimate triggers are:

- Genuine emergency: CA policy locked out all admins, federation service failure, MFA provider outage
- Scheduled quarterly break-glass account testing (should be documented with change ticket)
- Initial account setup or credential rotation (should be documented)

**Worst case scenario if this is real:**
An attacker discovers the break-glass account UPN through directory enumeration or social engineering, then obtains the password through physical safe compromise, insider threat, or a previously stored password in an insecure location. The attacker signs in -- no MFA challenge, no CA policy, no device check. Within minutes, the attacker: creates three new Global Admin accounts as backdoors, disables all Conditional Access policies, adds a federation trust for Golden SAML token forgery, grants Directory.ReadWrite.All to a malicious OAuth application, modifies diagnostic settings to disable audit logging, and begins mass data exfiltration. Because the break-glass account is excluded from all monitoring policies, the attack continues undetected until the SOC notices the downstream impact.

**Key difference from other identity runbooks:**
- RB-0013 (Privileged Role Assignment): Investigates when a user receives admin privileges. Break-glass accounts ALREADY have permanent GA -- no escalation needed.
- RB-0015 (Conditional Access Manipulation): Investigates disabling security controls. Break-glass accounts are ALREADY excluded from CA -- no manipulation needed.
- RB-0019 (Inactive Account Reactivation): Investigates dormant accounts. Break-glass accounts are a SPECIFIC class of dormant account with unique handling requirements.
- **RB-0023 (This runbook):** Investigates the **single most privileged, least restricted account** in the tenant. The investigation model is inverted: instead of "is this activity anomalous?", the question is "was this login authorized?" because ANY activity is suspicious by default.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID Free + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID (SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs)
- **Permissions:** Security Reader (investigation), Global Administrator (containment)
- **Requirement:** Break-glass account UPN(s) must be known and documented

### Recommended for Full Coverage
- **License:** Entra ID P2 + Microsoft Sentinel + Azure Subscription
- **Additional:** UEBA enabled, Azure Activity connector, Sentinel Analytics Rule for break-glass monitoring
- **Monitoring:** Dedicated Sentinel watchlist or analytics rule for break-glass UPN list

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | SigninLogs, AuditLogs | Steps 1-3, 5-7 |
| Above + Entra ID P1/P2 | Above + AADNonInteractiveUserSignInLogs | Steps 1-7 (full identity coverage) |
| Above + Azure Subscription | Above + AzureActivity | Steps 1-7 + Azure management plane |
| Above + Sentinel UEBA | Above + BehaviorAnalytics | Steps 1-8 (full coverage) |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
// CRITICAL: Add ALL break-glass account UPNs in your tenant
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);           // Time of break-glass sign-in
let LookbackWindow = 24h;                                 // Window to analyze surrounding activity
let ForwardWindow = 12h;                                   // Window after login for post-login audit
let BaselineDays = 90d;                                    // Historical baseline (90 days for break-glass)
// Known IT admin IP ranges (adjust to your organization)
let KnownAdminIPs = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
// ============================================================
```

!!! warning "Break-Glass UPN Identification"
    Break-glass accounts do not have a standard naming convention. Common patterns include `BreakGlass@`, `EmergencyAccess@`, `BG-Admin@`, `emergency@`, `bg1@`, `glass@`. Your organization's break-glass accounts may use any naming convention. **You must know your break-glass account UPNs before running this runbook.** Check your emergency access documentation, PIM configuration, or Entra ID role assignments for accounts with permanent Global Administrator that are excluded from CA policies.

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage. Remember: **every break-glass sign-in is suspicious until proven otherwise.**

### Immediate Escalation (Skip to Containment)
- Break-glass sign-in with NO corresponding emergency documented (no change ticket, no known outage)
- Sign-in from an IP address outside of known IT admin ranges
- Sign-in from an unexpected country or via VPN/hosting/anonymizing infrastructure
- Non-interactive sign-in (token refresh) from the break-glass account -- these accounts should not have active sessions
- Authentication method differs from expected (e.g., password used when FIDO2 key is the only authorized method)
- Multiple break-glass accounts used simultaneously (both bg1 AND bg2 signed in)
- Any AuditLog activity after the sign-in that is not part of the documented emergency procedure
- Break-glass credentials changed without following the documented rotation procedure

### Standard Investigation
- Break-glass sign-in during a known outage (CA lockout, federation failure) with change ticket
- Sign-in from a known IT admin IP during business hours
- Scheduled quarterly break-glass testing with documented test plan

### Likely Benign
- Quarterly break-glass test with matching change management ticket AND documented test plan AND IT manager approval
- Break-glass sign-in during a documented Microsoft Entra outage with corresponding service health alert
- Initial break-glass account setup or credential rotation by authorized Global Admin with change ticket

---

## 5. Investigation Steps

### Step 1: Break-Glass Account Sign-In Detection

**Purpose:** Detect ANY sign-in (interactive or non-interactive) to any break-glass account. Every login is an alert. Show the IP address, device details, location, authentication method, Conditional Access status, and risk level. Use a dynamic list of break-glass UPNs as input parameter. Union SigninLogs and AADNonInteractiveUserSignInLogs to capture all authentication events.

**Data needed:** SigninLogs, AADNonInteractiveUserSignInLogs

```kql
// ============================================================
// QUERY 1: Break-Glass Account Sign-In Detection
// Purpose: Detect ANY sign-in to break-glass accounts (interactive + non-interactive)
// Tables: SigninLogs, AADNonInteractiveUserSignInLogs
// Investigation Step: 1 - Break-Glass Account Sign-In Detection
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Union interactive and non-interactive sign-ins ---
let AllBreakGlassSignIns = union
    (SigninLogs
    | where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
    | where UserPrincipalName in~ (BreakGlassAccounts)
    | extend SignInType = "Interactive"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
    | where UserPrincipalName in~ (BreakGlassAccounts)
    | extend SignInType = "NonInteractive");
// --- Enrich and classify ---
AllBreakGlassSignIns
| extend
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    IsCompliant = DeviceDetail.isCompliant,
    IsManaged = DeviceDetail.isManaged,
    DeviceTrust = tostring(DeviceDetail.trustType)
| extend
    SignInOutcome = case(
        ResultType == "0", "SUCCESS",
        ResultType == "50074", "MFA REQUIRED",
        ResultType == "53003", "BLOCKED BY CA",
        ResultType == "50076", "MFA CHALLENGE",
        ResultType == "50126", "WRONG PASSWORD",
        ResultType == "50053", "ACCOUNT LOCKED",
        strcat("FAILURE - ", ResultType)
    ),
    DevicePosture = case(
        tobool(IsCompliant) == true and tobool(IsManaged) == true, "TRUSTED - Compliant managed device",
        tobool(IsManaged) == true, "PARTIAL - Managed but not compliant",
        "UNTRUSTED - Unmanaged/unknown device"
    ),
    CAStatus = case(
        ConditionalAccessStatus == "notApplied", "NOT APPLIED (expected for break-glass)",
        ConditionalAccessStatus == "success", "APPLIED (unexpected - BG should be excluded)",
        ConditionalAccessStatus == "failure", "BLOCKED (unexpected - BG should be excluded)",
        tostring(ConditionalAccessStatus)
    ),
    AlertSeverity = case(
        ResultType == "0" and SignInType == "NonInteractive",
            "CRITICAL - Non-interactive sign-in (token reuse/automation)",
        ResultType == "0" and SignInType == "Interactive",
            "HIGH - Interactive sign-in (possible emergency or compromise)",
        ResultType != "0" and ResultType in ("50126", "50053"),
            "HIGH - Failed auth attempt (brute force/credential testing)",
        ResultType != "0",
            "MEDIUM - Failed sign-in attempt",
        "REVIEW"
    )
| project
    TimeGenerated,
    UserPrincipalName,
    SignInType,
    SignInOutcome,
    AlertSeverity,
    IPAddress,
    Location,
    Country,
    DeviceOS,
    Browser,
    DevicePosture,
    CAStatus,
    AppDisplayName,
    ResourceDisplayName,
    AuthenticationRequirement,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    CorrelationId,
    SessionId,
    ResultType
| sort by AlertSeverity asc, TimeGenerated asc
```

**Performance Notes:**
- `union` of both sign-in tables ensures complete coverage -- break-glass accounts can appear in either
- `in~` performs case-insensitive UPN matching
- Non-interactive sign-ins are MORE suspicious than interactive for break-glass accounts because they indicate an active session or token reuse
- `ConditionalAccessStatus == "notApplied"` is EXPECTED for break-glass accounts (they should be excluded from CA)

**Tuning Guidance:**
- If `ConditionalAccessStatus == "success"` or `"failure"`, the break-glass account may have been accidentally included in CA policies -- this is a misconfiguration that needs immediate attention
- Failed sign-in attempts (ResultType 50126, 50053) to break-glass accounts indicate credential testing -- someone knows the UPN and is trying passwords
- Non-interactive sign-ins when no human used the account indicate token theft or unauthorized automation
- Multiple break-glass accounts signing in within the same window is almost always unauthorized

**Expected findings:**
- Complete list of all break-glass sign-in events: who, when, from where, how
- Classification of each event by severity
- CA policy status (should be "notApplied" for properly configured break-glass accounts)

**Next action:**
- If successful sign-in detected, proceed to Step 2 for auth method analysis
- If failed attempts detected, investigate as credential attack (password spray targeting break-glass)
- If non-interactive sign-in detected, escalate immediately -- possible token theft

---

### Step 2: Authentication Method and MFA Analysis

**Purpose:** Analyze HOW the break-glass account authenticated. Break-glass accounts typically use either a very long password without MFA or a FIDO2 security key stored in a physical safe. If MFA was used, if the authentication method differs from the expected method, or if a new authentication method was recently registered, it could indicate the credentials were obtained by an attacker who registered their own MFA method.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 2: Authentication Method and MFA Analysis
// Purpose: Analyze how the break-glass account authenticated
// Tables: SigninLogs
// Investigation Step: 2 - Authentication Method and MFA Analysis
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Authentication details for break-glass sign-ins ---
SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where UserPrincipalName in~ (BreakGlassAccounts)
| where ResultType == "0"  // Successful sign-ins only
| extend
    AuthDetails = todynamic(AuthenticationDetails)
| mv-expand AuthDetails
| extend
    AuthMethod = tostring(AuthDetails.authenticationMethod),
    AuthDetail = tostring(AuthDetails.authenticationMethodDetail),
    AuthSuccess = tostring(AuthDetails.succeeded),
    AuthStepNum = tostring(AuthDetails.authenticationStepRequirement)
| extend
    AuthMethodAssessment = case(
        // Expected methods for break-glass
        AuthMethod == "FIDO2 security key" and AuthSuccess == "true",
            "EXPECTED - FIDO2 key used (verify it is the authorized key)",
        AuthMethod == "Password" and AuthSuccess == "true" and AuthenticationRequirement == "singleFactorAuthentication",
            "EXPECTED - Password-only (typical for no-MFA break-glass)",
        // Suspicious methods
        AuthMethod in ("Microsoft Authenticator (push notification)", "Phone call", "Text message")
            and AuthSuccess == "true",
            "SUSPICIOUS - MFA method used (break-glass should not have MFA registered)",
        AuthMethod in ("Passwordless phone sign-in", "Windows Hello for Business")
            and AuthSuccess == "true",
            "SUSPICIOUS - Modern auth method (unexpected for break-glass)",
        AuthMethod == "Password" and AuthSuccess == "true"
            and AuthenticationRequirement == "multiFactorAuthentication",
            "SUSPICIOUS - MFA was required (CA policy may apply to break-glass)",
        AuthMethod == "Previously satisfied" and AuthSuccess == "true",
            "SUSPICIOUS - Previously satisfied auth (active session exists)",
        // Failed methods
        AuthSuccess != "true",
            strcat("FAILED - ", AuthMethod, " authentication failed"),
        strcat("REVIEW - ", AuthMethod)
    )
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AuthMethod,
    AuthDetail,
    AuthSuccess,
    AuthStepNum,
    AuthenticationRequirement,
    AuthMethodAssessment,
    MfaDetail,
    TokenIssuerType,
    AppDisplayName
| sort by TimeGenerated asc
```

**Performance Notes:**
- `AuthenticationDetails` is a JSON array containing each authentication step (factor 1, factor 2)
- `AuthenticationRequirement` shows whether single-factor or multi-factor was required
- `MfaDetail` contains the specific MFA method used if MFA was performed
- `TokenIssuerType` shows whether the token was issued by Azure AD or a federated IdP

**Tuning Guidance:**
- Break-glass accounts should authenticate with EITHER password-only OR FIDO2 key -- nothing else
- If `AuthenticationRequirement == "multiFactorAuthentication"`, the break-glass account may be incorrectly included in a CA policy that requires MFA
- If `AuthMethod` is "Microsoft Authenticator", "Phone call", or "Text message", someone registered MFA on the break-glass account -- investigate immediately (Step 6)
- `"Previously satisfied"` means the session was already authenticated -- this indicates token reuse or an already-active session, which is unexpected for break-glass accounts
- If `TokenIssuerType` is not "AzureAD", the break-glass account may be federated -- break-glass MUST be cloud-only

**Expected findings:**
- Exact authentication method used for the break-glass sign-in
- Whether MFA was required and what MFA method was used
- Whether the authentication method matches the expected break-glass procedure

**Next action:**
- If unexpected auth method, investigate how it was registered (Step 6)
- If MFA was used, check if break-glass account has MFA methods registered (should not)
- Proceed to Step 3 to verify whether the login was authorized

---

### Step 3: Authorization Verification -- Was This Login Expected?

**Purpose:** Cross-reference the break-glass sign-in with known maintenance windows, documented emergencies, and IT operations. Provide a structured checklist for the analyst to verify legitimacy. Check whether the sign-in originated from a known IT admin IP range versus unknown infrastructure.

**Data needed:** SigninLogs (for IP context), manual verification steps

```kql
// ============================================================
// QUERY 3: Authorization Verification - IP and Context Analysis
// Purpose: Check if break-glass sign-in came from known IT infrastructure
// Tables: SigninLogs
// Investigation Step: 3 - Authorization Verification
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// Known hosting/VPS ASNs (attacker infrastructure indicators)
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// --- Break-glass sign-in network context ---
SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where UserPrincipalName in~ (BreakGlassAccounts)
| where ResultType == "0"
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    ISP = tostring(NetworkLocationDetails)
| extend
    NetworkAssessment = case(
        AutonomousSystemNumber in (HostingASNs),
            "CRITICAL - Sign-in from VPS/hosting provider (attacker infrastructure)",
        ipv4_is_private(IPAddress),
            "EXPECTED - Sign-in from private/internal IP range",
        Country !in ("US"),  // Adjust to org's country
            "HIGH - Sign-in from unexpected country",
        "REVIEW - Sign-in from public IP (verify against known admin IPs)"
    ),
    TimeContext = case(
        hourofday(TimeGenerated) between (9 .. 17) and dayofweek(TimeGenerated) between (1d .. 5d),
            "BUSINESS HOURS - Weekday business hours",
        hourofday(TimeGenerated) between (9 .. 17),
            "WEEKEND - Business hours but weekend",
        "OFF-HOURS - Outside business hours"
    )
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AutonomousSystemNumber,
    Country,
    City,
    NetworkAssessment,
    TimeContext,
    AppDisplayName,
    ResourceDisplayName,
    UserAgent
| sort by NetworkAssessment asc, TimeGenerated asc
```

**Authorization Verification Checklist:**

After running the query above, the analyst must manually verify each of the following items. If ANY item cannot be verified, treat the sign-in as unauthorized.

| # | Verification Item | How to Check | Status |
|---|---|---|---|
| 1 | Is there a documented emergency requiring break-glass access? | Check incident management system (ServiceNow, Jira, PagerDuty) | [ ] Verified / [ ] Not Found |
| 2 | Is there a change management ticket for this break-glass usage? | Check ITSM system for matching change request | [ ] Verified / [ ] Not Found |
| 3 | Was the sign-in performed by an authorized IT administrator? | Contact the on-call admin team, verify via out-of-band channel (phone) | [ ] Verified / [ ] Not Found |
| 4 | Does the sign-in IP match a known IT admin location? | Compare against corporate VPN, IT admin workstation IPs | [ ] Verified / [ ] Not Found |
| 5 | Was the break-glass password retrieved from the authorized physical safe? | Contact physical security, check safe access logs | [ ] Verified / [ ] Not Found |
| 6 | Is the Microsoft Entra service health dashboard showing an outage? | Check [status.microsoft.com](https://status.microsoft.com) | [ ] Verified / [ ] Not Found |
| 7 | Are other admin accounts locked out of the tenant? | Verify that normal admin access is blocked (justifying break-glass use) | [ ] Verified / [ ] Not Found |

**Performance Notes:**
- `AutonomousSystemNumber` identifies the network provider -- hosting ASNs are a strong indicator of attacker infrastructure
- `ipv4_is_private()` identifies sign-ins from internal networks (most legitimate break-glass usage)
- Adjust the `Country` check to your organization's primary operating countries

**Tuning Guidance:**
- Break-glass sign-ins from VPS/hosting providers are almost always malicious
- Sign-ins outside business hours without a documented emergency are highly suspicious
- If the sign-in came from a known corporate IP but no emergency is documented, it may be an unauthorized test
- The checklist above is the most critical part of this step -- technical analysis alone cannot confirm authorization

**Expected findings:**
- Network context: whether the sign-in came from expected or unexpected infrastructure
- Time context: business hours vs. off-hours
- Authorization status: documented emergency vs. undocumented access

**Next action:**
- If ANY checklist item fails, treat as unauthorized and proceed to containment
- If all items verified, document the authorized usage and proceed with remaining steps as a validation exercise
- Proceed to Step 4 for historical baseline

---

### Step 4: Baseline Comparison -- Historical Break-Glass Usage

**Purpose:** Determine how often break-glass accounts have been used in the past 90 days. The answer should typically be "never" or "very rarely" (quarterly testing only). Any recent increase in usage frequency is suspicious. Show historical login frequency, IP patterns, and timing. This establishes whether the current sign-in is a deviation from the account's expected dormancy pattern.

**Data needed:** SigninLogs, AADNonInteractiveUserSignInLogs

```kql
// ============================================================
// QUERY 4: Baseline Comparison - Historical Break-Glass Usage
// Purpose: Establish historical break-glass usage pattern (expected: near-zero)
// Tables: SigninLogs, AADNonInteractiveUserSignInLogs
// Investigation Step: 4 - Baseline Comparison
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 90d;
// --- All break-glass sign-in activity in baseline window ---
let BaselineSignIns = union
    (SigninLogs
    | where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
    | where UserPrincipalName in~ (BreakGlassAccounts)
    | extend SignInType = "Interactive"),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
    | where UserPrincipalName in~ (BreakGlassAccounts)
    | extend SignInType = "NonInteractive");
// --- Baseline summary per account ---
BaselineSignIns
| summarize
    TotalSignIns = count(),
    SuccessfulSignIns = countif(ResultType == "0"),
    FailedSignIns = countif(ResultType != "0"),
    InteractiveCount = countif(SignInType == "Interactive"),
    NonInteractiveCount = countif(SignInType == "NonInteractive"),
    DistinctIPs = dcount(IPAddress),
    KnownIPs = make_set(IPAddress, 20),
    DistinctCountries = dcount(tostring(LocationDetails.countryOrRegion)),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 10),
    DistinctApps = dcount(AppDisplayName),
    Apps = make_set(AppDisplayName, 10),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated),
    SignInDates = make_set(format_datetime(TimeGenerated, "yyyy-MM-dd"), 50)
    by UserPrincipalName
| extend
    DaysInBaseline = datetime_diff("day", AlertTime, AlertTime - BaselineDays),
    AvgSignInsPerMonth = round(todouble(TotalSignIns) / (todouble(datetime_diff("day", AlertTime, AlertTime - BaselineDays)) / 30.0), 2),
    DaysSinceLastSignIn = iff(isnotempty(LastSignIn), datetime_diff("day", AlertTime, LastSignIn), -1),
    BaselineAssessment = case(
        TotalSignIns == 0,
            "EXPECTED - No break-glass usage in 90 days (dormant as intended)",
        SuccessfulSignIns <= 1 and DistinctIPs == 1,
            "ACCEPTABLE - Single authorized usage (likely quarterly test)",
        SuccessfulSignIns <= 4 and DistinctIPs <= 2,
            "REVIEW - Multiple usages (verify all were authorized quarterly tests)",
        SuccessfulSignIns > 4,
            "ANOMALOUS - Frequent break-glass usage (should be near-zero)",
        NonInteractiveCount > 0 and InteractiveCount == 0,
            "SUSPICIOUS - Only non-interactive sign-ins (possible token theft)",
        "REVIEW - Requires manual verification"
    )
| project
    UserPrincipalName,
    BaselineAssessment,
    TotalSignIns,
    SuccessfulSignIns,
    FailedSignIns,
    InteractiveCount,
    NonInteractiveCount,
    DistinctIPs,
    KnownIPs,
    Countries,
    Apps,
    AvgSignInsPerMonth,
    DaysSinceLastSignIn,
    SignInDates
| sort by BaselineAssessment asc
```

**Performance Notes:**
- 90-day baseline is used instead of the standard 30 days because break-glass accounts are tested quarterly
- `make_set(format_datetime(...))` provides the exact dates of each sign-in for manual verification against change tickets
- `DaysSinceLastSignIn == -1` means no sign-in was ever recorded in the 90-day window (expected)

**Tuning Guidance:**
- **TotalSignIns == 0** is the EXPECTED state -- break-glass accounts should be dormant
- **SuccessfulSignIns == 1** per quarter is acceptable if it matches a documented quarterly test
- **SuccessfulSignIns > 4** in 90 days is anomalous -- break-glass accounts should not be used this frequently
- **NonInteractiveCount > 0** without corresponding InteractiveCount means tokens are being used without a human login -- highly suspicious
- Cross-reference `SignInDates` with documented change management tickets to verify each usage was authorized

**Expected findings:**
- Historical break-glass usage frequency (expected: 0-1 per quarter)
- Whether the current sign-in breaks the dormancy pattern
- Historical IPs and locations for comparison with current sign-in

**Next action:**
- If baseline shows zero usage and current sign-in is undocumented, escalate to containment
- If baseline shows regular quarterly tests, compare current sign-in context against test pattern
- Proceed to Step 5 for post-login activity audit

---

### Step 5: Post-Login Activity Audit

**Purpose:** Complete audit of EVERYTHING the break-glass account did after logging in. Because break-glass accounts have permanent Global Administrator rights, every action they take is a high-impact administrative operation. Catalog all role assignments, CA policy changes, user management operations, app registrations, password resets, and Azure resource operations. Every action must be documented because the blast radius is the entire tenant.

**Data needed:** AuditLogs, AzureActivity

```kql
// ============================================================
// QUERY 5: Post-Login Activity Audit
// Purpose: Complete audit of all actions performed by break-glass account
// Tables: AuditLogs
// Investigation Step: 5 - Post-Login Activity Audit
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 12h;
// --- ALL actions by break-glass accounts after sign-in ---
AuditLogs
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where InitiatedBy has_any (BreakGlassAccounts)
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    ActorApp = tostring(InitiatedBy.app.displayName),
    TargetResource = tostring(TargetResources[0].displayName),
    TargetType = tostring(TargetResources[0].type),
    TargetUPN = tostring(TargetResources[0].userPrincipalName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| extend
    ActionCategory = case(
        // --- CRITICAL: Security control changes ---
        OperationName has_any ("Delete conditional access policy", "Disable Security Defaults"),
            "CRITICAL - Security controls removed",
        OperationName has_any ("Set federation settings on domain", "Set domain authentication"),
            "CRITICAL - Federation/domain change (Golden SAML risk)",
        OperationName has_any ("Update diagnostic setting", "Delete diagnostic setting"),
            "CRITICAL - Audit logging modified (anti-forensics)",
        // --- HIGH: Privilege changes ---
        OperationName has_any ("Add member to role", "Add eligible member to role"),
            "HIGH - Role assignment (privilege spreading)",
        OperationName has_any ("Add user"),
            "HIGH - User account created (potential backdoor)",
        OperationName has_any ("Add service principal credentials", "Add application"),
            "HIGH - Application/SP credential change (persistence)",
        OperationName has_any ("Consent to application", "Add delegated permission grant",
            "Add app role assignment to service principal"),
            "HIGH - OAuth consent/permission grant (persistent access)",
        OperationName has_any ("Reset password", "Change user password"),
            "HIGH - Password reset by break-glass (credential control)",
        // --- MEDIUM: Security policy changes ---
        OperationName has_any ("Update conditional access policy"),
            "MEDIUM - CA policy modification",
        OperationName has_any ("Update authorization policy", "Update authentication methods policy"),
            "MEDIUM - Authentication policy change",
        OperationName has_any ("User registered security info", "User deleted security info"),
            "MEDIUM - MFA method change on break-glass account",
        // --- EXPECTED: Emergency recovery operations ---
        OperationName has_any ("Add conditional access policy", "Enable Security Defaults"),
            "EXPECTED - Security policy restoration",
        OperationName has_any ("Update user", "Add member to group"),
            "LOW - Standard admin operation",
        "REVIEW - Requires context"
    ),
    MinutesAfterLogin = datetime_diff("minute", TimeGenerated, AlertTime)
| project
    TimeGenerated,
    OperationName,
    ActionCategory,
    ActorUPN,
    ActorIP,
    TargetResource,
    TargetType,
    TargetUPN,
    MinutesAfterLogin,
    Result,
    ModifiedProperties = substring(ModifiedProperties, 0, 500)
| sort by ActionCategory asc, TimeGenerated asc
```

**Azure Management Plane Activity:**

```kql
// ============================================================
// QUERY 5B: Azure Resource Operations by Break-Glass Account
// Purpose: Track Azure-level operations (subscriptions, resources)
// Tables: AzureActivity
// Investigation Step: 5 - Post-Login Activity Audit (Azure)
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 12h;
// --- Azure management plane operations by break-glass accounts ---
AzureActivity
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where Caller in~ (BreakGlassAccounts)
| extend
    AzureImpact = case(
        OperationNameValue has_any ("Microsoft.Authorization/roleAssignments/write"),
            "CRITICAL - Azure RBAC role assignment",
        OperationNameValue has_any ("Microsoft.Authorization/policyAssignments/delete"),
            "CRITICAL - Azure Policy deleted",
        OperationNameValue has_any ("Microsoft.KeyVault/vaults/secrets"),
            "HIGH - Key Vault secret access",
        OperationNameValue has_any ("Microsoft.Storage/storageAccounts"),
            "HIGH - Storage account operation",
        OperationNameValue has_any ("Microsoft.Compute/virtualMachines"),
            "MEDIUM - VM operation",
        "REVIEW - Azure resource operation"
    )
| project
    TimeGenerated,
    OperationNameValue,
    AzureImpact,
    Caller,
    CallerIpAddress,
    ResourceGroup,
    Resource = _ResourceId,
    ActivityStatusValue,
    SubscriptionId
| sort by AzureImpact asc, TimeGenerated asc
```

**Performance Notes:**
- `InitiatedBy has_any (BreakGlassAccounts)` matches both user.userPrincipalName and app.displayName fields
- `ModifiedProperties` is truncated to 500 chars for readability -- full JSON should be exported for evidence
- `AzureActivity` captures Azure management plane operations (ARM) that are not visible in AuditLogs
- `MinutesAfterLogin` provides a timeline relative to the break-glass sign-in

**Tuning Guidance:**
- ANY action categorized as "CRITICAL" requires immediate investigation regardless of other context
- Federation changes are the highest-risk operation -- they enable Golden SAML token forgery
- If the break-glass account creates new user accounts, check if they receive admin roles (backdoor pattern)
- If diagnostic settings are modified, the attacker may be disabling audit logging to cover tracks
- For legitimate emergency recovery, you would expect to see: CA policy re-creation, user unblocking, password resets for locked-out admins -- NOT federation changes or new app registrations

**Expected findings:**
- Complete timeline of every action performed by the break-glass account
- Classification of each action by severity and expected vs. unexpected
- Azure resource-level operations (subscriptions, Key Vault, storage)

**Next action:**
- If CRITICAL actions detected, proceed immediately to containment
- For each "HIGH" action, determine if it was part of the documented emergency procedure
- Proceed to Step 6 for credential security assessment

---

### Step 6: Credential Security Assessment

**Purpose:** Check if the break-glass account's credentials were recently changed, if new authentication methods were registered, if the account was targeted by password spray or brute force attacks, and if the account's exclusion from Conditional Access policies was recently modified. This step answers: "How did the attacker get the break-glass credentials?" and "Was the account weakened before the sign-in?"

**Data needed:** AuditLogs, SigninLogs

```kql
// ============================================================
// QUERY 6: Credential Security Assessment
// Purpose: Check break-glass credential changes, auth method registration,
//          failed login attempts, and CA exclusion modifications
// Tables: AuditLogs, SigninLogs
// Investigation Step: 6 - Credential Security Assessment
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);
let CredentialLookback = 30d;
// --- Part A: Credential and auth method changes ---
let CredentialChanges = AuditLogs
| where TimeGenerated between (AlertTime - CredentialLookback .. AlertTime + 1d)
| where TargetResources has_any (BreakGlassAccounts)
| where OperationName in (
    "Reset password (by admin)",
    "Reset password (self-service)",
    "Change user password",
    "Change password (self-service)",
    "User registered security info",
    "User registered all required security info",
    "User deleted security info",
    "User changed default security info",
    "User started security info registration",
    "Update user",
    "Set force change password flag"
)
| extend
    ModifyingUser = coalesce(
        tostring(InitiatedBy.user.userPrincipalName),
        tostring(InitiatedBy.app.displayName)
    ),
    ModifyingIP = tostring(InitiatedBy.user.ipAddress),
    TargetUser = coalesce(
        tostring(TargetResources[0].userPrincipalName),
        tostring(TargetResources[0].displayName)
    ),
    ModifiedProps = tostring(TargetResources[0].modifiedProperties)
| extend
    CredentialRisk = case(
        OperationName has "registered security info",
            "CRITICAL - MFA method registered on break-glass (should have none)",
        OperationName has "Reset password" and ModifyingUser !in~ (BreakGlassAccounts),
            "HIGH - Password reset by external admin (verify authorization)",
        OperationName has "Change password" and OperationName has "self-service",
            "CRITICAL - Self-service password change (someone knows current password)",
        OperationName has "deleted security info",
            "HIGH - MFA method removed from break-glass",
        "MEDIUM - Credential-related change"
    )
| project
    TimeGenerated,
    OperationName,
    CredentialRisk,
    ModifyingUser,
    ModifyingIP,
    TargetUser,
    ModifiedProps = substring(ModifiedProps, 0, 300),
    Result;
// --- Part B: Failed sign-in attempts (brute force/spray targeting break-glass) ---
let FailedAttempts = SigninLogs
| where TimeGenerated between (AlertTime - CredentialLookback .. AlertTime)
| where UserPrincipalName in~ (BreakGlassAccounts)
| where ResultType != "0"
| summarize
    TotalFailedAttempts = count(),
    DistinctSourceIPs = dcount(IPAddress),
    SourceIPs = make_set(IPAddress, 20),
    SourceCountries = make_set(tostring(LocationDetails.countryOrRegion), 10),
    FailureCodes = make_set(ResultType, 10),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    PasswordErrors = countif(ResultType in ("50126", "50053")),
    MFAErrors = countif(ResultType in ("50074", "50076"))
    by UserPrincipalName
| extend
    AttackAssessment = case(
        PasswordErrors > 10 and DistinctSourceIPs > 5,
            "CRITICAL - Distributed password spray targeting break-glass",
        PasswordErrors > 10 and DistinctSourceIPs <= 2,
            "HIGH - Brute force targeting break-glass from concentrated IPs",
        PasswordErrors > 3,
            "MEDIUM - Multiple failed password attempts (credential testing)",
        MFAErrors > 0,
            "SUSPICIOUS - MFA challenges on break-glass (should not have MFA)",
        "LOW - Minimal failed attempts"
    );
// --- Part C: CA policy exclusion changes affecting break-glass ---
let CAExclusionChanges = AuditLogs
| where TimeGenerated between (AlertTime - CredentialLookback .. AlertTime + 1d)
| where OperationName == "Update conditional access policy"
| extend ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| where PropertyName has_any ("ExcludeUsers", "ExcludeGroups", "IncludeUsers")
| where OldValue has_any (BreakGlassAccounts) or NewValue has_any (BreakGlassAccounts)
| extend
    ExclusionRisk = case(
        OldValue has_any (BreakGlassAccounts) and not(NewValue has_any (BreakGlassAccounts)),
            "CRITICAL - Break-glass REMOVED from CA exclusion (now subject to CA policies)",
        not(OldValue has_any (BreakGlassAccounts)) and NewValue has_any (BreakGlassAccounts),
            "INFO - Break-glass ADDED to CA exclusion (expected configuration)",
        "REVIEW - CA exclusion change involving break-glass"
    )
| project
    TimeGenerated,
    OperationName,
    ExclusionRisk,
    PolicyName = tostring(TargetResources[0].displayName),
    ModifyingUser = tostring(InitiatedBy.user.userPrincipalName);
// --- Combine all credential security findings ---
CredentialChanges
| extend DataSource = "CredentialChange"
| project TimeGenerated, DataSource, Assessment = CredentialRisk,
    Detail = strcat(OperationName, " by ", ModifyingUser)
| union (
    FailedAttempts
    | extend DataSource = "FailedAttempts"
    | project TimeGenerated = FirstAttempt, DataSource, Assessment = AttackAssessment,
        Detail = strcat(TotalFailedAttempts, " failed from ", DistinctSourceIPs, " IPs: ", tostring(SourceIPs))
)
| union (
    CAExclusionChanges
    | extend DataSource = "CAExclusion"
    | project TimeGenerated, DataSource, Assessment = ExclusionRisk,
        Detail = strcat(OperationName, " on ", PolicyName, " by ", ModifyingUser)
)
| sort by Assessment asc, TimeGenerated asc
```

**Performance Notes:**
- 30-day lookback for credential changes captures slow-burn attacks where credentials are modified weeks before exploitation
- Password spray detection uses `ResultType in ("50126", "50053")` for password-related failures
- CA exclusion analysis checks if break-glass accounts were removed from exclusion lists (making them subject to CA)

**Tuning Guidance:**
- ANY MFA method registration on a break-glass account is CRITICAL -- these accounts should have NO MFA methods (or only a documented FIDO2 key)
- Self-service password changes on break-glass accounts indicate someone already knows the current password
- Password spray targeting break-glass accounts specifically suggests the attacker knows the UPN (directory enumeration)
- If break-glass was removed from CA exclusions, the account is no longer functioning as break-glass -- this could be either a misconfiguration or deliberate sabotage

**Expected findings:**
- Whether break-glass credentials were changed before the sign-in
- Whether new auth methods were registered on the break-glass account
- Whether the account was targeted by credential attacks
- Whether CA exclusions were modified to affect the break-glass account

**Next action:**
- If MFA registered on break-glass, remove it immediately and rotate credentials
- If password spray detected, investigate the source IPs across other accounts
- If CA exclusions changed, restore the break-glass exclusion
- Proceed to Step 7 for concurrent admin activity

---

### Step 7: Concurrent Administrative Activity

**Purpose:** Check what other admin accounts were doing at the same time as the break-glass sign-in. If the break-glass login was authorized (e.g., CA lockout recovery), there should be correlated admin activity -- other admins encountering lockouts, helpdesk tickets, or escalation communications. If the break-glass login is isolated with no concurrent admin activity and no documented emergency, it is significantly more suspicious.

**Data needed:** SigninLogs, AuditLogs

```kql
// ============================================================
// QUERY 7: Concurrent Administrative Activity
// Purpose: Correlate break-glass usage with other admin activity
// Tables: SigninLogs, AuditLogs
// Investigation Step: 7 - Concurrent Administrative Activity
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);
let CorrelationWindow = 2h;
// --- Admin sign-ins around the break-glass event ---
let AdminSignIns = SigninLogs
| where TimeGenerated between (AlertTime - CorrelationWindow .. AlertTime + CorrelationWindow)
| where UserPrincipalName !in~ (BreakGlassAccounts)
| where AppDisplayName in (
    "Azure Portal", "Microsoft Azure Management",
    "Microsoft Entra admin center", "Entra Admin Center",
    "Microsoft Graph PowerShell", "Azure Active Directory PowerShell",
    "Microsoft Graph", "Graph Explorer"
)
| summarize
    AdminSignInCount = count(),
    SuccessfulAdminSignIns = countif(ResultType == "0"),
    FailedAdminSignIns = countif(ResultType != "0"),
    CABlockedSignIns = countif(ResultType == "53003"),
    LockoutEvents = countif(ResultType == "50053"),
    AdminUsers = make_set(UserPrincipalName, 20),
    AdminIPs = make_set(IPAddress, 20),
    FailureCodes = make_set_if(ResultType, ResultType != "0", 10)
| extend
    AdminActivityContext = case(
        CABlockedSignIns > 3,
            "SUPPORTS EMERGENCY - Multiple admins blocked by CA (possible CA lockout)",
        LockoutEvents > 2,
            "SUPPORTS EMERGENCY - Multiple admin lockouts (possible credential issue)",
        FailedAdminSignIns > SuccessfulAdminSignIns,
            "SUPPORTS EMERGENCY - Admin sign-in failures exceed successes",
        SuccessfulAdminSignIns > 0 and FailedAdminSignIns == 0,
            "NO EMERGENCY EVIDENCE - Other admins signing in normally",
        AdminSignInCount == 0,
            "ISOLATED - No other admin activity during break-glass usage",
        "REVIEW - Mixed admin activity pattern"
    );
// --- Admin audit actions around the break-glass event ---
let AdminAuditActivity = AuditLogs
| where TimeGenerated between (AlertTime - CorrelationWindow .. AlertTime + CorrelationWindow)
| where not(InitiatedBy has_any (BreakGlassAccounts))
| where Category == "RoleManagement"
    or OperationName has_any (
        "conditional access", "Security Defaults",
        "Update user", "Reset password",
        "Add user", "Delete user"
    )
| summarize
    AdminAuditActions = count(),
    AdminOperations = make_set(OperationName, 20),
    AdminActors = make_set(tostring(InitiatedBy.user.userPrincipalName), 20)
| extend
    AuditContext = case(
        AdminAuditActions > 10,
            "HIGH ADMIN ACTIVITY - Many admin changes during break-glass window",
        AdminAuditActions > 0,
            "SOME ADMIN ACTIVITY - Other admins also performing changes",
        "NO ADMIN AUDIT ACTIVITY - Break-glass is the only admin actor"
    );
// --- Combine ---
AdminSignIns
| extend p = 1
| join kind=fullouter (AdminAuditActivity | extend p = 1) on p
| project-away p, p1
| extend
    OverallCorrelation = case(
        AdminActivityContext has "SUPPORTS EMERGENCY",
            "CORROBORATED - Other admin failures support emergency scenario",
        AdminActivityContext has "ISOLATED" and AuditContext has "NO ADMIN",
            "UNCORROBORATED - Break-glass usage with zero concurrent admin activity (SUSPICIOUS)",
        AdminActivityContext has "NO EMERGENCY" and AuditContext has "SOME",
            "MIXED - Other admins active normally (no emergency evidence)",
        "REVIEW - Manual correlation required"
    )
| project
    OverallCorrelation,
    AdminActivityContext,
    AdminSignInCount,
    SuccessfulAdminSignIns,
    FailedAdminSignIns,
    CABlockedSignIns,
    LockoutEvents,
    AdminUsers,
    AuditContext,
    AdminAuditActions,
    AdminOperations,
    AdminActors
```

**Performance Notes:**
- 2-hour correlation window captures admin activity immediately before and after the break-glass sign-in
- `ResultType == "53003"` (CA blocked) and `ResultType == "50053"` (locked out) are the key indicators of an emergency scenario
- Admin portal application names filter for users who were actively trying to manage the tenant

**Tuning Guidance:**
- If multiple admins were blocked by CA (53003) around the same time as break-glass usage, this supports a legitimate CA lockout emergency
- If NO other admins had issues and break-glass was used, the emergency is undocumented -- highly suspicious
- "ISOLATED" + "NO ADMIN AUDIT ACTIVITY" is the strongest signal of unauthorized break-glass usage
- If other admins were active normally (successful sign-ins, normal audit trail), there was no emergency requiring break-glass

**Expected findings:**
- Whether the break-glass usage is corroborated by concurrent admin failures
- Whether other admins were locked out (supporting emergency narrative)
- Whether the break-glass usage is isolated (no concurrent admin activity)

**Next action:**
- If "UNCORROBORATED", escalate to incident commander -- break-glass used without evidence of emergency
- If "CORROBORATED", document the emergency and verify resolution
- Proceed to Step 8 for UEBA enrichment

---

### Step 8: UEBA Enrichment -- Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to assess the behavioral context of the break-glass account activity. Since break-glass accounts are designed to be dormant, UEBA should flag almost everything as "FirstTime". Focus on IsDormantAccount (should be True), BlastRadius (should be High), InvestigationPriority (should be elevated for any activity), and whether the source IP or ISP is known to the organization.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 4.

#### Query 8A: Break-Glass Behavioral Anomaly Assessment

```kql
// ============================================================
// Query 8A: UEBA Anomaly Assessment for Break-Glass Activity
// Purpose: Check if break-glass usage triggers expected behavioral anomalies
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 7d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
| where UserPrincipalName in~ (BreakGlassAccounts)
| project
    TimeGenerated,
    UserPrincipalName,
    ActivityType,
    ActionType,
    InvestigationPriority,
    SourceIPAddress,
    SourceIPLocation,
    // Dormancy indicators (critical for break-glass)
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    IsNewAccount = tobool(UsersInsights.IsNewAccount),
    BlastRadius = tostring(UsersInsights.BlastRadius),
    // First-time indicators (all should be True for break-glass)
    FirstTimeAction = tobool(ActivityInsights.FirstTimeUserPerformedAction),
    ActionUncommonForUser = tobool(ActivityInsights.ActionUncommonlyPerformedByUser),
    ActionUncommonAmongPeers = tobool(ActivityInsights.ActionUncommonlyPerformedAmongPeers),
    ActionUncommonInTenant = tobool(ActivityInsights.ActionUncommonlyPerformedInTenant),
    // Source anomalies
    FirstTimeISP = tobool(ActivityInsights.FirstTimeUserConnectedViaISP),
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    ISPUncommon = tobool(ActivityInsights.ISPUncommonlyUsedByUser),
    CountryUncommon = tobool(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    // Device anomalies
    FirstTimeDevice = tobool(ActivityInsights.FirstTimeUserUsedDevice),
    FirstTimeBrowser = tobool(ActivityInsights.FirstTimeUserUsedBrowser),
    // Resource access
    FirstTimeResource = tobool(ActivityInsights.FirstTimeUserAccessedResource),
    ResourceUncommon = tobool(ActivityInsights.ResourceUncommonlyAccessedByUser),
    // Volume
    UncommonHighVolume = tobool(ActivityInsights.UncommonHighVolumeOfActions),
    // Threat intel
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| extend
    // For break-glass, IsDormant=True + BlastRadius=High is EXPECTED
    // If IsDormant=False, the account has been used recently (suspicious)
    DormancyAssessment = case(
        IsDormantAccount == true and BlastRadius == "High",
            "EXPECTED - Dormant high-privilege account (normal for break-glass)",
        IsDormantAccount == false and BlastRadius == "High",
            "ANOMALOUS - Account is NOT dormant (has been active recently)",
        IsDormantAccount == true and BlastRadius != "High",
            "UNEXPECTED - Dormant but not high blast radius (check role assignment)",
        "REVIEW - Manual assessment needed"
    ),
    FirstTimeCount = toint(FirstTimeAction == true)
        + toint(FirstTimeISP == true)
        + toint(FirstTimeCountry == true)
        + toint(FirstTimeDevice == true)
        + toint(FirstTimeBrowser == true)
        + toint(FirstTimeResource == true)
| order by InvestigationPriority desc, TimeGenerated desc
```

**Expected findings:**

| Finding | Expected for Break-Glass | Suspicious Indicator |
|---|---|---|
| IsDormantAccount | true -- account should be dormant | false -- account has been active recently (investigate) |
| BlastRadius | High -- Global Admin has max blast radius | Low/Medium -- role may have been removed |
| InvestigationPriority | >= 5 for any activity (dormant account) | < 3 -- UEBA sees this as normal (account too active) |
| FirstTimeAction | true -- first action in UEBA window | false -- account has recent activity baseline |
| FirstTimeISP | true -- ISP should be new | false -- same ISP as previous usage |
| FirstTimeCountry | true if not from org's country | false -- from expected location |
| UncommonHighVolume | Depends on post-login actions | true -- bulk operations after login |
| ThreatIndicator | empty -- no malware on source | Present -- source IP/device has threat intel match |

**Decision guidance:**

- **IsDormantAccount = false** is a red flag for break-glass accounts. If UEBA does not consider the account dormant, it means the account has been used recently. Investigate ALL recent activity.
- **BlastRadius = High + IsDormantAccount = true + InvestigationPriority >= 7** is the EXPECTED pattern for unauthorized break-glass usage. The severity is appropriate -- react accordingly.
- **FirstTimeCountry = true + FirstTimeISP = true + ThreatIndicator present** = Break-glass credentials used from a new location on compromised infrastructure. Immediate containment.
- **IsDormantAccount = true + InvestigationPriority < 4** = UEBA not flagging high anomaly despite dormant account being active. This may indicate UEBA needs more training data or the account has not been dormant long enough. Rely on Steps 1-7 for verdict.
- **FirstTimeCount >= 4** (4+ first-time indicators) = Nearly everything about this activity is new. Combined with dormant status, this strongly supports unauthorized access.

---

## 6. Containment Playbook

### Immediate Actions (First 15 Minutes) -- If Unauthorized

| Priority | Action | Command/Location | Who |
|---|---|---|---|
| P0 | Revoke ALL break-glass sessions | `Revoke-MgUserSignInSession -UserId [BG-UPN]` | Global Admin (use second BG or other GA) |
| P0 | Disable the compromised break-glass account | Entra Portal > Users > [BG Account] > Block sign-in | Global Admin |
| P0 | Block the attacker's IP address | Add to Conditional Access Named Locations (blocked) or NSG | Security Admin |
| P0 | Rotate break-glass password immediately | Generate new 24+ character password, store in physical safe | Global Admin + Physical Security |
| P1 | Remove any MFA methods registered on break-glass | Entra Portal > Users > [BG Account] > Authentication methods | Authentication Admin |
| P1 | Audit and reverse ALL actions from Step 5 | Undo role assignments, delete backdoor accounts, restore CA policies | Incident Response Team |

### Secondary Actions (First 4 Hours)

| Priority | Action | Details |
|---|---|---|
| P1 | Full audit of all actions performed (Step 5) | Export complete AuditLogs and AzureActivity results |
| P1 | Reverse unauthorized changes | Remove any role assignments, delete backdoor accounts, restore CA policies, remove federation trusts |
| P1 | Check other break-glass accounts | If one is compromised, assess ALL break-glass accounts |
| P2 | Investigate credential access vector | How did the attacker get the break-glass password? Physical safe breach? Insider? Stored in insecure location? |
| P2 | Review break-glass CA exclusions | Verify break-glass accounts are still correctly excluded from CA |
| P2 | Check for persistent access | Service principal credentials, OAuth apps, federation trusts created during the session |
| P3 | Review break-glass account configuration | Ensure cloud-only, permanent GA, excluded from all CA, no MFA (or documented FIDO2 only) |

### Recovery Actions (First 24 Hours)

| Priority | Action | Details |
|---|---|---|
| P1 | Generate and store new break-glass credentials | New 24+ character password stored in physical safe with split-knowledge |
| P2 | Update emergency access procedures | Document the incident, update the break-glass usage policy |
| P2 | Implement enhanced break-glass monitoring | Create or update Sentinel analytics rule for break-glass sign-ins |
| P3 | Conduct tabletop exercise | Test the updated emergency access procedure with IT team |
| P3 | Review break-glass account naming | Consider obscuring UPNs to prevent targeted attacks |

### Break-Glass Credential Rotation Commands

```powershell
# Connect with a DIFFERENT Global Admin account (not break-glass)
Connect-MgGraph -Scopes "User.ReadWrite.All"

# Revoke all sessions for the compromised break-glass account
Revoke-MgUserSignInSession -UserId "breakglass1@company.com"

# Generate a new password (24+ characters, high complexity)
$NewPassword = [System.Web.Security.Membership]::GeneratePassword(32, 8)

# Reset the break-glass password
$PasswordProfile = @{
    Password = $NewPassword
    ForceChangePasswordNextSignIn = $false  # Break-glass should not be forced to change
}
Update-MgUser -UserId "breakglass1@company.com" -PasswordProfile $PasswordProfile

# IMPORTANT: Store $NewPassword in the physical safe immediately
# Print the password, seal in an envelope, and store in the authorized safe
Write-Host "NEW PASSWORD (store in physical safe):" -ForegroundColor Red
Write-Host $NewPassword

# Remove any unauthorized MFA methods
$AuthMethods = Get-MgUserAuthenticationMethod -UserId "breakglass1@company.com"
# Review and remove any methods that should not be present

# Verify account is still excluded from CA policies
# (Manual step: review all CA policies for break-glass exclusion)
```

---

## 7. Evidence Collection Checklist

| Evidence | Source | Retention | Priority |
|---|---|---|---|
| Break-glass sign-in events (all) | SigninLogs + AADNonInteractive | Export query results | Critical |
| Authentication method details | SigninLogs AuthenticationDetails | Export full JSON | Critical |
| Post-login audit trail (complete) | AuditLogs | Export query results | Critical |
| Azure resource operations | AzureActivity | Export query results | Critical |
| Historical break-glass usage (90 days) | SigninLogs + AADNonInteractive | Export query results | High |
| Credential change history | AuditLogs | Export query results | High |
| Failed login attempts (spray/brute force) | SigninLogs | Export query results | High |
| Concurrent admin activity | SigninLogs + AuditLogs | Export query results | High |
| CA policy exclusion configuration | Entra Portal | Screenshot + JSON export | High |
| Break-glass account configuration | Entra Portal | Screenshot (roles, MFA, status) | High |
| Physical safe access logs | Physical security system | Request from physical security | Medium |
| Change management tickets | ITSM system | Export relevant tickets | Medium |
| UEBA behavioral assessment | BehaviorAnalytics | Export query results | Medium |

---

## 8. Escalation Criteria

### Escalate to CISO / Incident Commander When:
- Break-glass account signed in without documented emergency
- Post-login actions include federation changes, CA policy deletion, or backdoor account creation
- Break-glass credentials were compromised (password known to unauthorized party)
- Both break-glass accounts used simultaneously without documented procedure
- Break-glass account used from VPS/hosting infrastructure or foreign country
- Break-glass session lasted more than 1 hour (emergency operations should be brief)
- Evidence of credential theft vector: physical safe breach, insider threat

### Escalate to Legal/Privacy When:
- Break-glass account used to access email, files, or sensitive data beyond emergency recovery
- Post-login actions include data exfiltration or unauthorized data access
- Physical security breach (safe compromise) involved in credential theft

### Escalate to Microsoft When:
- Suspected bypass of Entra ID authentication for break-glass accounts
- Break-glass account compromised as part of a larger tenant takeover
- Contact: Microsoft Security Response Center or [microsoft.com/msrc](https://microsoft.com/msrc)

### Escalate to Physical Security When:
- Break-glass credentials may have been physically compromised
- Physical safe access logs show unauthorized access
- Credential rotation requires new physical safe storage

---

## 9. False Positive Documentation

| Scenario | How to Verify | Action |
|---|---|---|
| Quarterly break-glass test | Verify change management ticket + test plan document + IT manager approval | Document test results, update last-test date |
| CA lockout emergency | Verify other admins were locked out (Step 7), check service health | Document the emergency, review CA policy configuration |
| Federation service failure | Verify federation provider outage, check service health dashboard | Document the federation failure, review disaster recovery plan |
| MFA provider outage | Verify MFA service disruption, check Microsoft service health | Document the outage, consider backup MFA provider |
| Initial account setup | Verify account creation date matches, check IT project plan | Document setup, ensure proper configuration before going dormant |
| Credential rotation | Verify rotation schedule, check change management ticket | Document rotation, verify new credentials stored in physical safe |

---

## 10. MITRE ATT&CK Mapping

| Technique | ID | Tactic | How Detected |
|---|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence, Defense Evasion, Privilege Escalation | Break-glass sign-in in SigninLogs (Step 1) |
| Valid Accounts | T1078 | Initial Access, Persistence | Any authentication to break-glass UPN (Step 1) |
| Modify Authentication Process | T1556 | Credential Access, Defense Evasion | MFA method registered on break-glass (Step 6) |
| Account Manipulation | T1098 | Persistence | Break-glass credential changes, role assignments post-login (Steps 5, 6) |

---

## 11. Query Summary

| # | Query | Table | Purpose |
|---|---|---|---|
| 1 | Break-Glass Sign-In Detection | SigninLogs + AADNonInteractive | Detect ANY sign-in to break-glass accounts |
| 2 | Authentication Method Analysis | SigninLogs | Verify auth method matches expected (password/FIDO2) |
| 3 | Authorization Verification | SigninLogs | Check IP context, provide verification checklist |
| 4 | Baseline Comparison | SigninLogs + AADNonInteractive | Historical usage (expected: near-zero in 90 days) |
| 5 | Post-Login Activity Audit | AuditLogs + AzureActivity | Complete audit of all actions by break-glass account |
| 6 | Credential Security Assessment | AuditLogs + SigninLogs | Credential changes, brute force, CA exclusion changes |
| 7 | Concurrent Admin Activity | SigninLogs + AuditLogs | Correlate with other admin activity (emergency evidence) |
| 8A | UEBA Behavioral Assessment | BehaviorAnalytics | Dormancy, blast radius, first-time indicators |

---

## Appendix A: Datatable Tests

### Test 1: Break-Glass Sign-In Detection

```kql
// ============================================================
// TEST 1: Break-Glass Sign-In Detection
// Validates: Query 1 - Detect any sign-in to break-glass accounts
// Expected: breakglass1 interactive SUCCESS = "HIGH"
//           breakglass1 non-interactive SUCCESS = "CRITICAL"
//           breakglass2 failed attempt = "HIGH" (brute force)
//           normal.admin successful = NOT in results
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let TestSignIns = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    ResultType: string,
    IPAddress: string,
    LocationDetails: dynamic,
    DeviceDetail: dynamic,
    ConditionalAccessStatus: string,
    AppDisplayName: string,
    ResourceDisplayName: string,
    AuthenticationRequirement: string,
    RiskLevelDuringSignIn: string,
    RiskLevelAggregated: string,
    CorrelationId: string,
    SessionId: string,
    SignInType: string
) [
    // --- Break-glass 1: Interactive successful sign-in ---
    datetime(2026-02-22T14:00:00Z), "breakglass1@company.com", "0",
        "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","isManaged":false}),
        "notApplied", "Azure Portal", "Windows Azure Service Management API",
        "singleFactorAuthentication", "none", "none", "corr-001", "sess-001", "Interactive",
    // --- Break-glass 1: Non-interactive token refresh (CRITICAL) ---
    datetime(2026-02-22T14:30:00Z), "breakglass1@company.com", "0",
        "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows","browser":"Chrome","isManaged":false}),
        "notApplied", "Azure Portal", "Microsoft Graph",
        "singleFactorAuthentication", "none", "none", "corr-002", "sess-001", "NonInteractive",
    // --- Break-glass 2: Failed password attempt (brute force) ---
    datetime(2026-02-22T13:55:00Z), "breakglass2@company.com", "50126",
        "198.51.100.80",
        dynamic({"city":"Lagos","countryOrRegion":"NG"}),
        dynamic({"operatingSystem":"Linux","browser":"Firefox","isManaged":false}),
        "notApplied", "Azure Portal", "Windows Azure Service Management API",
        "singleFactorAuthentication", "none", "none", "corr-003", "sess-002", "Interactive",
    // --- Normal admin (should NOT be in results) ---
    datetime(2026-02-22T14:00:00Z), "normal.admin@company.com", "0",
        "10.0.0.5",
        dynamic({"city":"Seattle","countryOrRegion":"US"}),
        dynamic({"operatingSystem":"Windows","browser":"Edge","isManaged":true}),
        "success", "Azure Portal", "Windows Azure Service Management API",
        "multiFactorAuthentication", "none", "none", "corr-004", "sess-003", "Interactive"
];
// --- Run detection ---
TestSignIns
| where UserPrincipalName in~ (BreakGlassAccounts)
| extend
    SignInOutcome = iff(ResultType == "0", "SUCCESS", strcat("FAILURE - ", ResultType)),
    AlertSeverity = case(
        ResultType == "0" and SignInType == "NonInteractive",
            "CRITICAL - Non-interactive sign-in (token reuse/automation)",
        ResultType == "0" and SignInType == "Interactive",
            "HIGH - Interactive sign-in (possible emergency or compromise)",
        ResultType != "0" and ResultType in ("50126", "50053"),
            "HIGH - Failed auth attempt (brute force/credential testing)",
        "MEDIUM - Failed sign-in attempt"
    ),
    CAStatus = case(
        ConditionalAccessStatus == "notApplied", "NOT APPLIED (expected for break-glass)",
        "UNEXPECTED"
    )
| project UserPrincipalName, SignInType, SignInOutcome, AlertSeverity, IPAddress,
    Country = tostring(LocationDetails.countryOrRegion), CAStatus
// Expected: breakglass1 Interactive SUCCESS = "HIGH - Interactive sign-in"
// Expected: breakglass1 NonInteractive SUCCESS = "CRITICAL - Non-interactive sign-in"
// Expected: breakglass2 FAILURE-50126 = "HIGH - Failed auth attempt"
// Expected: normal.admin NOT IN RESULTS (filtered out by BreakGlassAccounts)
```

### Test 2: Authentication Method Verification

```kql
// ============================================================
// TEST 2: Authentication Method Verification
// Validates: Query 2 - Verify break-glass auth method matches expected
// Expected: FIDO2 key = "EXPECTED"
//           Password-only = "EXPECTED"
//           Authenticator push = "SUSPICIOUS"
//           Previously satisfied = "SUSPICIOUS"
// ============================================================
let TestAuthData = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    AuthMethod: string,
    AuthDetail: string,
    AuthSuccess: string,
    AuthenticationRequirement: string,
    AppDisplayName: string,
    MfaDetail: string,
    TokenIssuerType: string
) [
    // --- FIDO2 key (expected for break-glass) ---
    datetime(2026-02-22T14:00:00Z), "breakglass1@company.com", "10.0.0.5",
        "FIDO2 security key", "YubiKey 5", "true",
        "singleFactorAuthentication", "Azure Portal", "", "AzureAD",
    // --- Password-only (expected for no-MFA break-glass) ---
    datetime(2026-02-22T14:05:00Z), "breakglass2@company.com", "10.0.0.5",
        "Password", "", "true",
        "singleFactorAuthentication", "Azure Portal", "", "AzureAD",
    // --- Authenticator push (suspicious - should not have MFA) ---
    datetime(2026-02-22T14:10:00Z), "breakglass1@company.com", "203.0.113.50",
        "Microsoft Authenticator (push notification)", "", "true",
        "multiFactorAuthentication", "Azure Portal", "Authenticator", "AzureAD",
    // --- Previously satisfied (suspicious - active session) ---
    datetime(2026-02-22T14:15:00Z), "breakglass1@company.com", "203.0.113.50",
        "Previously satisfied", "", "true",
        "singleFactorAuthentication", "Microsoft Graph", "", "AzureAD"
];
// --- Run auth method assessment ---
TestAuthData
| extend
    AuthMethodAssessment = case(
        AuthMethod == "FIDO2 security key" and AuthSuccess == "true",
            "EXPECTED - FIDO2 key used (verify it is the authorized key)",
        AuthMethod == "Password" and AuthSuccess == "true"
            and AuthenticationRequirement == "singleFactorAuthentication",
            "EXPECTED - Password-only (typical for no-MFA break-glass)",
        AuthMethod in ("Microsoft Authenticator (push notification)", "Phone call", "Text message")
            and AuthSuccess == "true",
            "SUSPICIOUS - MFA method used (break-glass should not have MFA registered)",
        AuthMethod == "Previously satisfied" and AuthSuccess == "true",
            "SUSPICIOUS - Previously satisfied auth (active session exists)",
        "REVIEW"
    )
| project UserPrincipalName, AuthMethod, AuthenticationRequirement, AuthMethodAssessment
// Expected: FIDO2 = "EXPECTED - FIDO2 key used"
// Expected: Password = "EXPECTED - Password-only"
// Expected: Authenticator = "SUSPICIOUS - MFA method used"
// Expected: Previously satisfied = "SUSPICIOUS - Previously satisfied auth"
```

### Test 3: Historical Baseline and Concurrent Activity

```kql
// ============================================================
// TEST 3: Historical Baseline and Concurrent Activity
// Validates: Query 4 - Break-glass usage should be near-zero
//            Query 7 - Concurrent admin activity correlation
// Expected: breakglass1 with 0 historical usage = "EXPECTED - dormant"
//           breakglass2 with 5 historical usages = "ANOMALOUS - frequent"
//           Admin lockouts during BG usage = "SUPPORTS EMERGENCY"
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
// --- Part A: Baseline test ---
let TestBaselineSignIns = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    ResultType: string,
    IPAddress: string,
    LocationDetails: dynamic,
    AppDisplayName: string,
    SignInType: string
) [
    // --- breakglass2 has suspicious frequent usage ---
    datetime(2026-01-15T10:00:00Z), "breakglass2@company.com", "0", "203.0.113.60",
        dynamic({"countryOrRegion":"US"}), "Azure Portal", "Interactive",
    datetime(2026-01-22T11:00:00Z), "breakglass2@company.com", "0", "203.0.113.60",
        dynamic({"countryOrRegion":"US"}), "Azure Portal", "Interactive",
    datetime(2026-02-01T09:00:00Z), "breakglass2@company.com", "0", "203.0.113.60",
        dynamic({"countryOrRegion":"US"}), "Azure Portal", "Interactive",
    datetime(2026-02-10T14:00:00Z), "breakglass2@company.com", "0", "203.0.113.61",
        dynamic({"countryOrRegion":"DE"}), "Azure Portal", "Interactive",
    datetime(2026-02-18T16:00:00Z), "breakglass2@company.com", "0", "198.51.100.50",
        dynamic({"countryOrRegion":"RU"}), "Azure Portal", "Interactive"
    // --- breakglass1 has NO historical usage (expected) ---
];
TestBaselineSignIns
| where UserPrincipalName in~ (BreakGlassAccounts)
| summarize
    TotalSignIns = count(),
    SuccessfulSignIns = countif(ResultType == "0"),
    DistinctIPs = dcount(IPAddress),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 10)
    by UserPrincipalName
| union (
    // Add breakglass1 with zero rows
    datatable(UserPrincipalName: string, TotalSignIns: long, SuccessfulSignIns: long,
        DistinctIPs: long, Countries: dynamic)
    ["breakglass1@company.com", 0, 0, 0, dynamic([])]
)
| extend
    BaselineAssessment = case(
        TotalSignIns == 0,
            "EXPECTED - No break-glass usage in 90 days (dormant as intended)",
        SuccessfulSignIns > 4,
            "ANOMALOUS - Frequent break-glass usage (should be near-zero)",
        "REVIEW"
    )
| project UserPrincipalName, BaselineAssessment, TotalSignIns, SuccessfulSignIns, DistinctIPs, Countries
// Expected: breakglass1 = "EXPECTED - No break-glass usage in 90 days"
// Expected: breakglass2 = "ANOMALOUS - Frequent break-glass usage"

// --- Part B: Concurrent admin activity test ---
let TestAdminSignIns = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    ResultType: string,
    AppDisplayName: string
) [
    // Admins blocked by CA (supporting emergency)
    datetime(2026-02-22T13:50:00Z), "admin1@company.com", "53003", "Azure Portal",
    datetime(2026-02-22T13:52:00Z), "admin2@company.com", "53003", "Azure Portal",
    datetime(2026-02-22T13:55:00Z), "admin3@company.com", "53003", "Azure Portal",
    datetime(2026-02-22T14:01:00Z), "admin1@company.com", "53003", "Azure Portal"
];
TestAdminSignIns
| where UserPrincipalName !in~ (BreakGlassAccounts)
| summarize
    CABlockedSignIns = countif(ResultType == "53003"),
    AdminUsers = make_set(UserPrincipalName, 20)
| extend
    AdminActivityContext = case(
        CABlockedSignIns > 3,
            "SUPPORTS EMERGENCY - Multiple admins blocked by CA (possible CA lockout)",
        "REVIEW"
    )
| project AdminActivityContext, CABlockedSignIns, AdminUsers
// Expected: "SUPPORTS EMERGENCY - Multiple admins blocked by CA"
// Expected: 4 CA blocked sign-ins from 3 distinct admins
```

### Test 4: Post-Login Activity Classification

```kql
// ============================================================
// TEST 4: Post-Login Activity Classification
// Validates: Query 5 - Classify post-login actions by severity
// Expected: Federation change = "CRITICAL"
//           Role assignment = "HIGH"
//           CA policy restoration = "EXPECTED"
//           User update = "LOW"
// ============================================================
let BreakGlassAccounts = dynamic([
    "breakglass1@company.com",
    "breakglass2@company.com"
]);
let AlertTime = datetime(2026-02-22T14:00:00Z);
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string,
    Category: string
) [
    // --- CRITICAL: Federation change (Golden SAML risk) ---
    datetime(2026-02-22T14:05:00Z), "Set federation settings on domain",
        dynamic({"user":{"userPrincipalName":"breakglass1@company.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"company.com","type":"Domain","modifiedProperties":[
            {"displayName":"FederationBrandName","oldValue":"","newValue":"attacker-idp"}
        ]}]),
        "success", "ApplicationManagement",
    // --- HIGH: Role assignment (privilege spreading) ---
    datetime(2026-02-22T14:10:00Z), "Add member to role",
        dynamic({"user":{"userPrincipalName":"breakglass1@company.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"backdoor.admin@company.com","modifiedProperties":[
            {"displayName":"Role.DisplayName","newValue":"Global Administrator"}
        ]}]),
        "success", "RoleManagement",
    // --- EXPECTED: CA policy restoration (emergency recovery) ---
    datetime(2026-02-22T14:15:00Z), "Add conditional access policy",
        dynamic({"user":{"userPrincipalName":"breakglass1@company.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"Require MFA for All Users","type":"Policy"}]),
        "success", "Policy",
    // --- LOW: Standard user update ---
    datetime(2026-02-22T14:20:00Z), "Update user",
        dynamic({"user":{"userPrincipalName":"breakglass1@company.com","ipAddress":"203.0.113.50"}}),
        dynamic([{"displayName":"locked.user@company.com","modifiedProperties":[
            {"displayName":"AccountEnabled","oldValue":"False","newValue":"True"}
        ]}]),
        "success", "UserManagement"
];
// --- Run post-login activity classification ---
TestAuditLogs
| where InitiatedBy has_any (BreakGlassAccounts)
| extend
    ActionCategory = case(
        OperationName has_any ("Set federation settings on domain"),
            "CRITICAL - Federation/domain change (Golden SAML risk)",
        OperationName has_any ("Add member to role"),
            "HIGH - Role assignment (privilege spreading)",
        OperationName has_any ("Add conditional access policy", "Enable Security Defaults"),
            "EXPECTED - Security policy restoration",
        OperationName has_any ("Update user"),
            "LOW - Standard admin operation",
        "REVIEW"
    ),
    MinutesAfterLogin = datetime_diff("minute", TimeGenerated, AlertTime)
| project TimeGenerated, OperationName, ActionCategory, MinutesAfterLogin,
    TargetResource = tostring(TargetResources[0].displayName)
// Expected: "Set federation settings" = "CRITICAL - Federation/domain change" at +5 min
// Expected: "Add member to role" = "HIGH - Role assignment" at +10 min
// Expected: "Add conditional access policy" = "EXPECTED - Security policy restoration" at +15 min
// Expected: "Update user" = "LOW - Standard admin operation" at +20 min
```

---

## References

- [Microsoft: Manage emergency access accounts in Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [Microsoft: Secure access practices for administrators](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning)
- [Microsoft: Monitor emergency access accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access#monitor-sign-in-and-audit-logs)
- [Microsoft: Conditional Access exclusions for emergency access accounts](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups#exclude-users)
- [Microsoft: Entra ID built-in roles reference](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [Microsoft: AuditLogs schema reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- [Microsoft: SigninLogs schema reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [MITRE ATT&CK T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- [MITRE ATT&CK T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [Midnight Blizzard guidance for responders on nation-state attack (2024)](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [CISA: Mitigating cloud-based identity threats](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
