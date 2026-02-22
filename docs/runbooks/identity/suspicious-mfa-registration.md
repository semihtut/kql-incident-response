---
title: "Suspicious MFA Method Registration"
id: RB-0012
severity: high
status: reviewed
description: >
  Investigation runbook for suspicious MFA authentication method registrations
  in Microsoft Entra ID. Covers detection of attacker-added MFA methods
  (phone, authenticator app, FIDO2 key, passkey) on compromised accounts,
  registration timing correlation with suspicious sign-ins, auth method
  enumeration across the organization, and post-registration access pattern
  analysis. After compromising credentials, attackers register their own MFA
  method to maintain persistent access that survives password resets. This is
  a critical persistence mechanism because the attacker's MFA method allows
  them to pass future MFA challenges even after the original compromise vector
  is remediated.
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
    - technique_id: T1556.006
      technique_name: "Modify Authentication Process: Multi-Factor Authentication"
      confidence: confirmed
    - technique_id: T1098.005
      technique_name: "Account Manipulation: Device Registration"
      confidence: confirmed
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: confirmed
threat_actors:
  - "Scattered Spider (Octo Tempest)"
  - "LAPSUS$ (DEV-0537)"
  - "Storm-0875"
  - "Midnight Blizzard (APT29/Nobelium)"
  - "Star Blizzard (SEABORGIUM)"
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
    required: true
    alternatives: []
  - table: "AADRiskyUsers"
    product: "Entra ID Identity Protection"
    license: "Entra ID P2"
    required: false
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
tier: 2
category: identity
key_log_sources:
  - AuditLogs
  - SigninLogs
  - AADUserRiskEvents
  - AADRiskyUsers
  - AADNonInteractiveUserSignInLogs
tactic_slugs:
  - persistence
  - priv-esc
  - defense-evasion
  - cred-access
data_checks:
  - query: "AuditLogs | where OperationName has 'authentication method' | take 1"
    label: primary
    description: "MFA method registration event detection"
  - query: "SigninLogs | take 1"
    description: "For sign-in context and IP correlation"
  - query: "AADUserRiskEvents | take 1"
    description: "For risk detection correlation with MFA registration"
  - query: "AADRiskyUsers | take 1"
    label: optional
    description: "For current user risk state assessment"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    label: optional
    description: "For token-based access after MFA registration"
---

# Suspicious MFA Method Registration - Investigation Runbook

> **RB-0012** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Audit Logs + Identity Protection Risk Detections
> **Risk Detection Name:** `User registered security info` / `Update user` (StrongAuthenticationMethod) audit events
> **Primary MITRE Technique:** T1556.006 - Modify Authentication Process: Multi-Factor Authentication

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: MFA Registration Event Analysis](#step-1-mfa-registration-event-analysis)
   - [Step 2: Pre-Registration Sign-In Context](#step-2-pre-registration-sign-in-context)
   - [Step 3: Risk Event Correlation](#step-3-risk-event-correlation)
   - [Step 4: Baseline Comparison - Establish Normal MFA Registration Pattern](#step-4-baseline-comparison---establish-normal-mfa-registration-pattern)
   - [Step 5: Post-Registration Access Pattern Analysis](#step-5-post-registration-access-pattern-analysis)
   - [Step 6: Auth Method Inventory for Target User](#step-6-auth-method-inventory-for-target-user)
   - [Step 7: Org-Wide Suspicious MFA Registration Sweep](#step-7-org-wide-suspicious-mfa-registration-sweep)
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
Suspicious MFA method registration is detected through multiple complementary mechanisms:

1. **AuditLogs registration events:** The `User registered security info` and `User registered all required security info` operations in Entra ID AuditLogs record every MFA method registration. Suspicious registrations include new methods added from unfamiliar IPs, methods added shortly after a risky sign-in, and registrations from IPs or locations different from the user's normal pattern.
2. **Identity Protection correlation:** Entra ID Identity Protection may flag the session as risky. When a risk detection (unfamiliar sign-in, anonymous IP, password spray success) occurs in the same session as an MFA registration, the combination is highly suspicious.
3. **Temporal pattern analysis:** MFA registration immediately after a password reset, credential compromise detection, or from a session with anomalous properties (new device, new location, Tor/VPN IP) indicates an attacker establishing persistence.

**Why it matters:**
MFA method registration is the **single most critical persistence mechanism** in cloud identity attacks. After compromising credentials (via phishing, password spray, token theft, or AiTM), the attacker's first action is typically to register their own MFA method -- a phone number, authenticator app, or FIDO2 key. Once their MFA method is registered, the attacker can:
- Pass all future MFA challenges, even after the password is reset
- Complete Conditional Access policies that require MFA
- Reset the user's password themselves using self-service password reset (SSPR)
- Survive all standard remediation steps that don't include MFA method cleanup

Scattered Spider (Octo Tempest) systematically registers MFA methods on compromised accounts as their standard operating procedure. LAPSUS$ used social engineering against helpdesk staff to trigger MFA resets, then registered their own methods.

**Why this is HIGH severity:**
- Password reset ALONE does not fix this -- the attacker's MFA method remains registered
- The attacker can re-compromise the account at will using their registered MFA method
- If the attacker registers a passkey or FIDO2 key, they have phishing-resistant access to the account
- Registered authenticator apps generate TOTP codes offline -- no network connection needed for the attacker
- The attacker can use their MFA to trigger self-service password reset, re-compromising the account after remediation
- Most SOC playbooks include "reset password" but forget to audit and remove rogue MFA methods

**However:** This alert has a **low-to-moderate false positive rate** (~10-15%). Legitimate triggers include:
- New employees setting up MFA during onboarding (first 7 days)
- Users switching to a new phone and re-registering their authenticator app
- IT helpdesk-initiated MFA resets followed by user re-registration
- Organization-wide MFA enrollment campaigns (e.g., mandating authenticator app)
- Users adding a backup MFA method (adding phone as backup to authenticator)

**Worst case scenario if this is real:**
An attacker compromises a user's credentials via AiTM phishing. They sign in from an anonymous IP, register their own Microsoft Authenticator app as an MFA method, and add a phone number as a backup. The SOC detects the suspicious sign-in and resets the user's password. However, the attacker's MFA methods remain registered. The next day, the attacker uses self-service password reset with their registered phone number, sets a new password, and regains full access. They now have persistent, self-sustaining access that survives password resets indefinitely. If the user is an administrator, the attacker can use this foothold to escalate privileges, create new admin accounts, and maintain persistent access to the entire tenant.

**Key difference from other identity runbooks:**
- RB-0001 through RB-0006 (Sign-in focused): Investigate the initial compromise -- suspicious sign-in patterns, credential attacks. These detect the breach.
- RB-0010 (Service Principal): Investigates workload identity compromise -- non-human accounts.
- RB-0011 (Consent Grant): Investigates OAuth app abuse -- data access via delegated permissions.
- **RB-0012 (This runbook):** Investigates **post-compromise persistence** -- the attacker's next action after gaining access. This runbook focuses on what happens AFTER the initial sign-in: the attacker registering their own MFA method to ensure they can return. Remediation requires removing the rogue MFA method, not just resetting the password.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID Free + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID (AuditLogs, SigninLogs)
- **Permissions:** Security Reader (investigation), Authentication Administrator (containment)

### Recommended for Full Coverage
- **License:** Entra ID P2 + Microsoft Sentinel
- **Additional:** Identity Protection enabled for risk-based correlation
- **Authentication Methods Policy:** Configured to log all registration events

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | AuditLogs, SigninLogs | Steps 1-2, 4-7 |
| Above + Entra ID P2 | Above + AADUserRiskEvents, AADRiskyUsers | Steps 1-7 (full coverage) |
| Above + Entra ID P1/P2 | Above + AADNonInteractiveUserSignInLogs | Steps 1-7 + token access patterns |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let TargetUPN = "compromised.user@contoso.com";           // User who registered new MFA
let AlertTime = datetime(2026-02-22T14:00:00Z);           // Time of MFA registration event
let LookbackWindow = 24h;                                 // Window to analyze pre-registration activity
let ForwardWindow = 12h;                                   // Window after registration for access analysis
let BaselineDays = 30d;                                    // Baseline comparison window
let SuspiciousIP = "198.51.100.50";                       // IP from registration event (if known)
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- MFA method registered from an IP flagged by Identity Protection (anonymous IP, unfamiliar location, malware-linked IP)
- MFA registration within 30 minutes of a risky sign-in or password spray success
- MFA registered from a different country than the user's normal location
- Multiple MFA methods registered in quick succession (phone + authenticator + FIDO2)
- MFA registered immediately after a password reset that the user didn't request
- Admin account with new MFA method from non-corporate IP

### Standard Investigation
- MFA method registered from a new but not flagged IP address
- Registration during off-hours for the user's timezone
- MFA registered from a mobile network IP (could be legitimate phone change)
- Single new authenticator app registration from an existing device

### Likely Benign
- MFA registration during first 7 days of employment (onboarding)
- Registration from corporate IP on enrolled device
- IT helpdesk ticket correlating with MFA reset + re-registration
- Registration during a documented organization-wide MFA enrollment campaign
- User reported new phone to IT and re-registered from known corporate location

---

## 5. Investigation Steps

### Step 1: MFA Registration Event Analysis

**Purpose:** Identify all MFA method registration events for the target user. Determine what methods were registered, from which IP, using what device, and the exact timing. This is the foundational evidence for the entire investigation.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 1: MFA Registration Event Analysis
// Purpose: Identify all MFA registration events, methods, IPs, timing
// Tables: AuditLogs
// Investigation Step: 1 - MFA Registration Event Analysis
// ============================================================
let TargetUPN = "compromised.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- MFA registration events ---
AuditLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where OperationName in (
    "User registered security info",
    "User registered all required security info",
    "User started security info registration",
    "Admin registered security info",
    "Update user",
    "User deleted security info",
    "Admin deleted security info of user",
    "Reset password (by admin)",
    "Reset password (self-service)",
    "Change password (self-service)"
)
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    ActorApp = tostring(InitiatedBy.app.displayName),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    TargetResourceName = tostring(TargetResources[0].displayName),
    ModifiedProps = TargetResources[0].modifiedProperties
| where ActorUPN =~ TargetUPN
    or TargetUser =~ TargetUPN
    or TargetResourceName =~ TargetUPN
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    MFAMethodRegistered = case(
        PropertyName == "StrongAuthenticationMethod" and NewValue has "PhoneAppNotification",
            "Microsoft Authenticator (Push Notification)",
        PropertyName == "StrongAuthenticationMethod" and NewValue has "PhoneAppOTP",
            "Authenticator App (TOTP Code)",
        PropertyName == "StrongAuthenticationMethod" and NewValue has "OneWaySMS",
            "SMS Text Message",
        PropertyName == "StrongAuthenticationMethod" and NewValue has "TwoWayVoiceMobile",
            "Phone Call (Mobile)",
        PropertyName == "StrongAuthenticationMethod" and NewValue has "TwoWayVoiceOffice",
            "Phone Call (Office)",
        PropertyName == "StrongAuthenticationMethod" and NewValue has "FIDO2",
            "FIDO2 Security Key",
        PropertyName has "AuthenticationMethod" and NewValue has "passkey",
            "Passkey",
        OperationName has "security info" and PropertyName == "MethodType",
            strcat("Security Info: ", NewValue),
        OperationName has "password",
            strcat("PASSWORD EVENT: ", OperationName),
        ""
    ),
    IsAdminAction = ActorUPN != TargetUser and isnotempty(ActorUPN)
| where isnotempty(MFAMethodRegistered) or OperationName has "security info" or OperationName has "password"
| project
    TimeGenerated,
    OperationName,
    ActorUPN,
    ActorIP,
    TargetUser,
    MFAMethodRegistered,
    IsAdminAction,
    PropertyName,
    NewValue,
    Result
| extend
    RiskIndicator = case(
        IsAdminAction and OperationName has "Admin registered",
            "REVIEW - Admin-initiated MFA registration",
        OperationName has "password" and OperationName has "self-service",
            "HIGH - Self-service password reset (check if user-initiated)",
        OperationName has "password" and OperationName has "admin",
            "REVIEW - Admin password reset (check helpdesk ticket)",
        MFAMethodRegistered has "Microsoft Authenticator" or MFAMethodRegistered has "Authenticator App",
            "HIGH - Authenticator app registered (most common attacker method)",
        MFAMethodRegistered has "SMS" or MFAMethodRegistered has "Phone Call",
            "HIGH - Phone-based MFA registered (attacker can use burner phone)",
        MFAMethodRegistered has "FIDO2" or MFAMethodRegistered has "Passkey",
            "CRITICAL - Hardware key/passkey registered (phishing-resistant persistence)",
        "REVIEW - Requires context"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- `StrongAuthenticationMethod` in `ModifiedProperties` captures the exact MFA type registered
- Admin-initiated registrations (`Admin registered security info`) show the admin's UPN as `ActorUPN` and the target user as `TargetUser`
- Password reset events are included to build a complete timeline: compromise → password reset → MFA registration

**Tuning Guidance:**
- Multiple MFA methods registered within 10 minutes is extremely suspicious -- legitimate users typically register one method at a time
- If `ActorIP` doesn't match the user's known corporate IP ranges, escalate immediately
- FIDO2/Passkey registration is the most dangerous -- it gives the attacker phishing-resistant access
- If a password reset occurred just before MFA registration from a different IP, this confirms account takeover

**Expected findings:**
- Complete MFA registration timeline: what methods, when, from where, by whom
- Correlation with password events (reset before registration = takeover pattern)
- Admin vs. self-service registration distinction

**Next action:**
- If suspicious MFA registration found, proceed to Step 2 for sign-in context
- Note the registration IP for correlation across all subsequent queries
- If FIDO2/Passkey registered, treat as highest priority

---

### Step 2: Pre-Registration Sign-In Context

**Purpose:** Analyze the sign-in activity that preceded the MFA registration. Determine if the session used to register MFA was itself suspicious -- unfamiliar location, anonymous IP, new device, risky sign-in detection. This establishes whether the person who registered MFA is the legitimate user or an attacker.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 2: Pre-Registration Sign-In Context
// Purpose: Analyze sign-ins before MFA registration for suspicious context
// Tables: SigninLogs
// Investigation Step: 2 - Pre-Registration Sign-In Context
// ============================================================
let TargetUPN = "compromised.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
let SuspiciousIP = "198.51.100.50";
// --- Sign-in activity before and during MFA registration ---
SigninLogs
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 2h)
| where UserPrincipalName =~ TargetUPN
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    Country = tostring(LocationDetails.countryOrRegion),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    DeviceId = tostring(DeviceDetail.deviceId),
    IsCompliant = DeviceDetail.isCompliant,
    IsManaged = DeviceDetail.isManaged,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    RiskState,
    MfaDetail = tostring(AuthenticationDetails),
    ResourceDisplayName,
    CorrelationId,
    OriginalRequestId
| extend
    SignInOutcome = case(
        ResultType == "0", "SUCCESS",
        ResultType == "50074", "MFA REQUIRED",
        ResultType == "50076", "MFA COMPLETED",
        ResultType == "53003", "BLOCKED BY CA",
        ResultType == "50126", "WRONG PASSWORD",
        ResultType == "50053", "ACCOUNT LOCKED",
        ResultType == "500121", "MFA FAILED",
        strcat("FAILURE - ", ResultType)
    ),
    IsRegistrationSession = AppDisplayName in (
        "Security Info", "My Security Info", "My Sign-Ins",
        "Microsoft Authentication Broker", "My Apps", "My Account"
    ),
    IPMatchesSuspicious = IPAddress == SuspiciousIP,
    DeviceRisk = case(
        tobool(IsCompliant) == true and tobool(IsManaged) == true, "LOW - Compliant managed device",
        tobool(IsManaged) == true, "MEDIUM - Managed but not compliant",
        isnotempty(DeviceId), "MEDIUM - Registered but unmanaged device",
        "HIGH - Unregistered/unknown device"
    ),
    SessionRisk = case(
        RiskLevelDuringSignIn in ("high"), "CRITICAL - High risk sign-in",
        RiskLevelDuringSignIn in ("medium"), "HIGH - Medium risk sign-in",
        RiskLevelAggregated in ("high", "medium"), "HIGH - Elevated user risk",
        "LOW - No risk detected"
    )
| extend
    OverallSuspicion = case(
        SessionRisk startswith "CRITICAL" and IsRegistrationSession,
            "CRITICAL - Risky sign-in used to register MFA",
        IPMatchesSuspicious and IsRegistrationSession,
            "HIGH - MFA registration from suspicious IP",
        DeviceRisk startswith "HIGH" and IsRegistrationSession,
            "HIGH - MFA registration from unknown device",
        IsRegistrationSession and Country != "US",  // Adjust to your org's primary country
            "HIGH - MFA registration from unusual country",
        IsRegistrationSession,
            "REVIEW - MFA registration session detected",
        SignInOutcome == "SUCCESS" and SessionRisk != "LOW",
            "REVIEW - Risky successful sign-in",
        "LOW"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- `AppDisplayName` for MFA registration sessions typically shows "Security Info", "My Security Info", or "My Account"
- `DeviceDetail.isCompliant` and `DeviceDetail.isManaged` indicate device trust level -- unmanaged devices are higher risk
- `RiskLevelDuringSignIn` from Identity Protection provides real-time ML-based risk assessment

**Tuning Guidance:**
- If the MFA registration session is from a different IP than all previous sign-ins, this is the strongest indicator
- Adjust the country check (`Country != "US"`) to match your organization's primary operating countries
- If the sign-in used legacy authentication (no MFA challenge), the attacker may have bypassed MFA entirely
- Look for sign-ins to "Security Info" or "My Account" -- these are the portals used to register MFA methods

**Expected findings:**
- Sign-in context for the MFA registration session: IP, location, device, risk level
- Whether the registration session was from a known or unknown device/location
- Whether Identity Protection flagged the session as risky

**Next action:**
- If registration session is risky, proceed to Step 3 for risk event correlation
- If the IP is from a VPN/proxy service, check for AiTM indicators
- Note the device and IP for correlation with post-registration access (Step 5)

---

### Step 3: Risk Event Correlation

**Purpose:** Correlate the MFA registration with Identity Protection risk detections. If the user had a risk event (unfamiliar sign-in, anonymous IP, password spray) in the same time window as the MFA registration, the combination strongly indicates account takeover with persistence establishment.

**Data needed:** AADUserRiskEvents

```kql
// ============================================================
// QUERY 3: Risk Event Correlation
// Purpose: Correlate MFA registration with Identity Protection risk events
// Tables: AADUserRiskEvents
// Investigation Step: 3 - Risk Event Correlation
// ============================================================
let TargetUPN = "compromised.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Risk events around MFA registration time ---
AADUserRiskEvents
| where TimeGenerated between (AlertTime - LookbackWindow .. AlertTime + 4h)
| where UserPrincipalName =~ TargetUPN
| project
    TimeGenerated,
    UserPrincipalName,
    RiskEventType,
    RiskLevel,
    RiskState,
    RiskDetail,
    DetectionTimingType,
    IPAddress,
    Location = strcat(City, ", ", CountryOrRegion),
    Source,
    Activity,
    AdditionalInfo = tostring(AdditionalInfo),
    CorrelationId
| extend
    RiskCategory = case(
        RiskEventType in ("unfamiliarFeatures", "unlikelyTravel", "newCountry"),
            "LOCATION ANOMALY - Sign-in from unusual location",
        RiskEventType in ("anonymizedIPAddress", "maliciousIPAddress", "suspiciousIPAddress"),
            "SUSPICIOUS IP - Sign-in from flagged IP",
        RiskEventType in ("passwordSpray", "leakedCredentials", "investigationsThreatIntelligence"),
            "CREDENTIAL COMPROMISE - Credentials known to be compromised",
        RiskEventType in ("tokenIssuerAnomaly", "anomalousToken"),
            "TOKEN ANOMALY - Suspicious token characteristics",
        RiskEventType in ("mcasImpossibleTravel", "mcasSuspiciousInboxManipulationRules"),
            "CLOUD APPS - Defender for Cloud Apps detection",
        RiskEventType in ("riskyUser", "userReportedSuspiciousActivity"),
            "USER FLAGGED - User or admin reported risk",
        strcat("OTHER - ", RiskEventType)
    ),
    TimeDeltaMinutes = datetime_diff("minute", AlertTime, TimeGenerated),
    ProximityToRegistration = case(
        abs(datetime_diff("minute", AlertTime, TimeGenerated)) <= 30,
            "CRITICAL - Risk event within 30 min of MFA registration",
        abs(datetime_diff("minute", AlertTime, TimeGenerated)) <= 120,
            "HIGH - Risk event within 2 hours of MFA registration",
        abs(datetime_diff("minute", AlertTime, TimeGenerated)) <= 720,
            "MEDIUM - Risk event within 12 hours of MFA registration",
        "LOW - Risk event > 12 hours from MFA registration"
    )
| extend
    AttackChainAssessment = case(
        RiskEventType in ("passwordSpray", "leakedCredentials") and ProximityToRegistration startswith "CRITICAL",
            "CONFIRMED ATTACK CHAIN - Credential compromise → immediate MFA registration",
        RiskEventType in ("anonymizedIPAddress", "maliciousIPAddress") and ProximityToRegistration startswith "CRITICAL",
            "CONFIRMED ATTACK CHAIN - Suspicious IP sign-in → immediate MFA registration",
        RiskEventType in ("unfamiliarFeatures", "unlikelyTravel") and ProximityToRegistration startswith "HIGH",
            "PROBABLE ATTACK CHAIN - Location anomaly near MFA registration",
        "REQUIRES INVESTIGATION - Context needed"
    )
| sort by TimeGenerated asc
```

**Performance Notes:**
- `DetectionTimingType` can be "realtime" or "offline" -- realtime detections are more reliable for timing correlation
- `CorrelationId` may link the risk event to the exact sign-in session used for MFA registration
- `RiskState` shows current remediation status -- "atRisk" means no remediation has occurred yet

**Tuning Guidance:**
- Risk events within 30 minutes of MFA registration are the strongest indicators
- `passwordSpray` + MFA registration = classic Scattered Spider/LAPSUS$ attack pattern
- `leakedCredentials` + MFA registration = attacker using credentials from a data breach
- If `RiskState` is "remediated" but MFA methods were not removed, the remediation is incomplete

**Expected findings:**
- Risk events correlated with MFA registration timing
- Attack chain identification: what risk event preceded the registration
- Whether the risk was detected in realtime or offline

**Next action:**
- If attack chain confirmed, proceed directly to containment
- If no risk events found, proceed to Step 4 for baseline comparison
- Note all risk event IPs for cross-reference with registration IP

---

### Step 4: Baseline Comparison - Establish Normal MFA Registration Pattern

**Purpose:** Determine if MFA registration activity is anomalous by comparing against the user's and organization's historical registration patterns. When was the user's last MFA registration? How frequently do users in the org register new MFA methods? This establishes whether the registration is expected or a deviation.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 4: Baseline Comparison - Normal MFA Registration Pattern
// Purpose: Compare MFA registration against user and org baseline
// Tables: AuditLogs
// Investigation Step: 4 - Baseline Comparison
// ============================================================
let TargetUPN = "compromised.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 30d;
// --- User's historical MFA registration behavior ---
let UserMFABaseline = AuditLogs
| where TimeGenerated between (AlertTime - 90d .. AlertTime)
| where OperationName in (
    "User registered security info",
    "User registered all required security info",
    "Admin registered security info",
    "User deleted security info",
    "Admin deleted security info of user"
)
| where InitiatedBy has TargetUPN or TargetResources has TargetUPN
| summarize
    TotalRegistrations = count(),
    RegistrationDates = make_set(format_datetime(TimeGenerated, "yyyy-MM-dd HH:mm"), 20),
    RegistrationIPs = make_set(tostring(InitiatedBy.user.ipAddress), 10),
    MethodsRegistered = make_set(tostring(TargetResources[0].modifiedProperties), 10),
    LastRegistration = max(TimeGenerated)
| extend
    DaysSinceLastRegistration = datetime_diff("day", AlertTime, LastRegistration),
    EntityType = "USER_BASELINE";
// --- Org-wide MFA registration baseline (last 30 days) ---
let OrgMFABaseline = AuditLogs
| where TimeGenerated between (AlertTime - BaselineDays .. AlertTime)
| where OperationName in (
    "User registered security info",
    "User registered all required security info"
)
| summarize
    TotalRegistrations = count(),
    UniqueUsers = dcount(tostring(InitiatedBy.user.userPrincipalName)),
    AvgRegistrationsPerDay = todouble(count()) / todouble(datetime_diff("day", AlertTime, AlertTime - BaselineDays)),
    RegistrationsByHour = make_list(hourofday(TimeGenerated), 1000)
| extend
    AvgRegistrationsPerUser = todouble(TotalRegistrations) / todouble(UniqueUsers),
    EntityType = "ORG_BASELINE";
// --- Assess current registration against baselines ---
UserMFABaseline
| extend
    Assessment = case(
        TotalRegistrations == 0,
            "ANOMALOUS - User has NEVER registered MFA before (impossible if MFA is enforced -- check if first-time setup)",
        DaysSinceLastRegistration < 7,
            "SUSPICIOUS - User registered MFA within last 7 days (recent change)",
        DaysSinceLastRegistration > 180,
            "SUSPICIOUS - User hasn't registered MFA in 6+ months (unusual to add new method now)",
        "WITHIN BASELINE - User has recent MFA registration history"
    )
| project EntityType, TotalRegistrations, DaysSinceLastRegistration, RegistrationIPs, Assessment
```

**Performance Notes:**
- 90-day lookback for user baseline captures MFA registration patterns comprehensively
- `DaysSinceLastRegistration > 180` means the user hasn't touched MFA in 6 months -- a new registration is unusual
- Org-wide baseline provides context for whether MFA registration is generally active (enrollment campaign) or rare

**Tuning Guidance:**
- If the user has never registered MFA and the org enforces MFA, this may be a new account or a registration bypass
- If the user's last registration was years ago and they suddenly register again, this is anomalous
- Check if the org is running an MFA enrollment campaign -- this context changes the assessment entirely
- Compare registration IPs: if previous registrations were from corporate IPs and this one is from an external IP, escalate

**Expected findings:**
- User's MFA registration history: frequency, recency, IPs used
- Whether this registration is a statistical outlier
- Org-wide registration rate for context

**Next action:**
- If registration is anomalous, proceed to Step 5 for post-registration access
- If registration is within baseline, check Step 2 results for session-level risk
- If org-wide registration spike detected, check for enrollment campaign or mass compromise

---

### Step 5: Post-Registration Access Pattern Analysis

**Purpose:** Analyze what the user (or attacker) did AFTER registering the new MFA method. Track resource access, email activity, privilege escalation, and any lateral movement that occurred using sessions authenticated with the newly registered MFA method. This determines the blast radius of the compromise.

**Data needed:** SigninLogs, AADNonInteractiveUserSignInLogs

```kql
// ============================================================
// QUERY 5: Post-Registration Access Pattern Analysis
// Purpose: Track activity after MFA registration for blast radius
// Tables: SigninLogs
// Investigation Step: 5 - Post-Registration Access Pattern Analysis
// ============================================================
let TargetUPN = "compromised.user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 12h;
let SuspiciousIP = "198.51.100.50";
// --- Post-registration sign-in activity ---
SigninLogs
| where TimeGenerated between (AlertTime .. AlertTime + ForwardWindow)
| where UserPrincipalName =~ TargetUPN
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    ResultType,
    ConditionalAccessStatus,
    ResourceDisplayName,
    AuthenticationMethodsUsed = tostring(AuthenticationDetails),
    RiskLevelDuringSignIn,
    CorrelationId
| extend
    SignInOutcome = case(
        ResultType == "0", "SUCCESS",
        ResultType == "50074", "MFA REQUIRED",
        strcat("FAILURE - ", ResultType)
    ),
    IPMatchesSuspicious = IPAddress == SuspiciousIP,
    AccessCategory = case(
        AppDisplayName in ("Microsoft Teams", "Outlook", "SharePoint Online", "OneDrive"),
            "PRODUCTIVITY - Standard M365 apps",
        AppDisplayName in ("Azure Portal", "Microsoft Azure Management", "Azure Resource Manager"),
            "ADMIN - Azure management access",
        AppDisplayName in ("Microsoft Graph", "Microsoft Graph Explorer"),
            "API - Direct Graph API access (high risk)",
        AppDisplayName in ("My Security Info", "My Account", "Security Info"),
            "SECURITY SETTINGS - Authentication method management",
        AppDisplayName in ("Exchange Online PowerShell", "Azure Active Directory PowerShell"),
            "POWERSHELL - Administrative tooling",
        AppDisplayName has_any ("Azure AD", "Entra"),
            "DIRECTORY - Entra ID management",
        strcat("OTHER - ", AppDisplayName)
    )
| extend
    PostRegRisk = case(
        AccessCategory startswith "ADMIN" and IPMatchesSuspicious,
            "CRITICAL - Admin access from suspicious IP after MFA registration",
        AccessCategory startswith "API" and IPMatchesSuspicious,
            "CRITICAL - Graph API access from suspicious IP (potential exfiltration)",
        AccessCategory startswith "POWERSHELL",
            "HIGH - PowerShell access after MFA registration",
        AccessCategory startswith "SECURITY SETTINGS",
            "HIGH - Additional security setting changes",
        IPMatchesSuspicious and SignInOutcome == "SUCCESS",
            "HIGH - Continued access from suspicious IP",
        SignInOutcome == "SUCCESS",
            "REVIEW - Successful access post-registration",
        "LOW"
    )
| summarize
    EventCount = count(),
    SuccessCount = countif(ResultType == "0"),
    UniqueApps = make_set(AppDisplayName, 20),
    UniqueIPs = make_set(IPAddress, 10),
    Categories = make_set(AccessCategory, 10),
    HighestRisk = max(PostRegRisk),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by AccessCategory
| sort by HighestRisk asc
```

**Performance Notes:**
- 12-hour forward window captures immediate post-compromise actions
- `AuthenticationDetails` may reveal which MFA method was used -- if the newly registered method was used, this confirms attacker access
- `AppDisplayName` categorization helps prioritize investigation focus

**Tuning Guidance:**
- Graph API or PowerShell access from the suspicious IP is the highest-priority finding
- If the attacker accessed "My Security Info" again, they may be registering additional MFA methods
- Check if the attacker accessed email (Outlook/Exchange) -- this is the most common exfiltration target
- If Azure Portal access is detected, check for privilege escalation (role assignments)

**Expected findings:**
- Post-registration activity timeline: apps accessed, IPs used, success/failure
- Whether the suspicious IP was used for further access after MFA registration
- Types of resources accessed: productivity vs. admin vs. API

**Next action:**
- If admin or API access detected, escalate immediately
- If email access detected, perform email forwarding rule check (see RB-0008)
- Proceed to Step 6 for auth method inventory

---

### Step 6: Auth Method Inventory for Target User

**Purpose:** Build a complete inventory of all authentication methods currently registered for the target user by examining AuditLogs for all registration and deletion events. This identifies which methods are potentially attacker-controlled and must be removed during containment.

**Data needed:** AuditLogs

```kql
// ============================================================
// QUERY 6: Auth Method Inventory for Target User
// Purpose: List all MFA method registrations and deletions to identify rogue methods
// Tables: AuditLogs
// Investigation Step: 6 - Auth Method Inventory
// ============================================================
let TargetUPN = "compromised.user@contoso.com";
// --- Full MFA method lifecycle ---
AuditLogs
| where TimeGenerated >= ago(365d)
| where OperationName in (
    "User registered security info",
    "User registered all required security info",
    "Admin registered security info",
    "User deleted security info",
    "Admin deleted security info of user",
    "Update user"
)
| where InitiatedBy has TargetUPN or TargetResources has TargetUPN
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    OldValue = tostring(ModifiedProps.oldValue),
    NewValue = tostring(ModifiedProps.newValue)
| where PropertyName in (
    "StrongAuthenticationMethod",
    "StrongAuthenticationPhoneAppDetail",
    "MethodType",
    "StrongAuthenticationUserDetails"
) or OperationName has "security info"
| project
    TimeGenerated,
    OperationName,
    ActorUPN,
    ActorIP,
    PropertyName,
    OldValue,
    NewValue,
    EventType = case(
        OperationName has "registered", "REGISTERED",
        OperationName has "deleted", "DELETED",
        OperationName == "Update user", "UPDATED",
        "OTHER"
    )
| extend
    MethodDetail = case(
        NewValue has "PhoneAppNotification", "Microsoft Authenticator (Push)",
        NewValue has "PhoneAppOTP", "Authenticator App (TOTP)",
        NewValue has "OneWaySMS", "SMS",
        NewValue has "TwoWayVoiceMobile", "Phone Call (Mobile)",
        NewValue has "FIDO2", "FIDO2 Security Key",
        NewValue has "Passkey", "Passkey",
        isnotempty(NewValue), strcat("Method: ", substring(NewValue, 0, 100)),
        "Details in audit event"
    ),
    IsCurrentlyActive = EventType == "REGISTERED" or EventType == "UPDATED"
| sort by TimeGenerated asc
| extend
    AgeInDays = datetime_diff("day", now(), TimeGenerated),
    RiskAssessment = case(
        AgeInDays < 7 and ActorIP !in ("10.0.0.0/8"),  // Adjust to corporate ranges
            "HIGH RISK - Recently registered from non-corporate IP",
        AgeInDays < 1,
            "CRITICAL - Registered within last 24 hours",
        AgeInDays < 30,
            "REVIEW - Registered within last 30 days",
        "ESTABLISHED - Registered > 30 days ago"
    )
```

**Performance Notes:**
- 365-day lookback provides complete MFA method lifecycle
- Matching REGISTERED and DELETED events reveals the current active method inventory
- `StrongAuthenticationPhoneAppDetail` contains device-specific information for authenticator apps

**Tuning Guidance:**
- Methods registered within the last 7 days from non-corporate IPs are primary suspects
- If multiple methods were registered on the same day from different IPs, the attacker registered backups
- Cross-reference registration IPs with known corporate IP ranges
- Methods with no corresponding deletion event are still active

**Expected findings:**
- Complete inventory of all MFA methods registered over the past year
- Identification of recently added methods that may be attacker-controlled
- Timeline showing when each method was added and from what IP

**Next action:**
- Flag all methods registered from suspicious IPs for removal during containment
- If FIDO2/Passkey found among recent registrations, prioritize removal
- Proceed to Step 7 for org-wide sweep

---

### Step 7: Org-Wide Suspicious MFA Registration Sweep

**Purpose:** Scan the entire organization for other accounts that may have had MFA methods registered under suspicious circumstances. The same attacker may have compromised multiple accounts and registered persistence mechanisms on all of them. This step catches coordinated attacks and identifies the full scope of compromise.

**Data needed:** AuditLogs, SigninLogs

```kql
// ============================================================
// QUERY 7: Org-Wide Suspicious MFA Registration Sweep
// Purpose: Find all suspicious MFA registrations across the org
// Tables: AuditLogs, SigninLogs
// Investigation Step: 7 - Org-Wide MFA Registration Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let SweepWindow = 7d;
// --- All MFA registrations in the last 7 days ---
let AllRegistrations = AuditLogs
| where TimeGenerated between (AlertTime - SweepWindow .. AlertTime + 1d)
| where OperationName in (
    "User registered security info",
    "User registered all required security info"
)
| project
    RegistrationTime = TimeGenerated,
    UserUPN = coalesce(
        tostring(TargetResources[0].userPrincipalName),
        tostring(InitiatedBy.user.userPrincipalName)
    ),
    RegistrationIP = tostring(InitiatedBy.user.ipAddress),
    OperationName;
// --- All risky sign-ins in the same window ---
let RiskySignIns = SigninLogs
| where TimeGenerated between (AlertTime - SweepWindow .. AlertTime + 1d)
| where RiskLevelDuringSignIn in ("high", "medium") and ResultType == "0"
| project
    SignInTime = TimeGenerated,
    UserUPN = UserPrincipalName,
    SignInIP = IPAddress,
    RiskLevel = RiskLevelDuringSignIn,
    RiskDetail = RiskLevelAggregated,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion));
// --- Correlate: Find MFA registrations that follow risky sign-ins ---
AllRegistrations
| join kind=inner RiskySignIns on UserUPN
| where RegistrationTime > SignInTime
    and datetime_diff("hour", RegistrationTime, SignInTime) <= 24
| extend
    TimeBetweenMinutes = datetime_diff("minute", RegistrationTime, SignInTime),
    IPMatch = RegistrationIP == SignInIP
| extend
    ThreatAssessment = case(
        TimeBetweenMinutes <= 30 and IPMatch,
            "CRITICAL - MFA registered within 30 min of risky sign-in from same IP",
        TimeBetweenMinutes <= 30,
            "HIGH - MFA registered within 30 min of risky sign-in (different IP)",
        TimeBetweenMinutes <= 120,
            "HIGH - MFA registered within 2 hours of risky sign-in",
        TimeBetweenMinutes <= 720,
            "MEDIUM - MFA registered within 12 hours of risky sign-in",
        "LOW - MFA registered > 12 hours after risky sign-in"
    )
| project
    UserUPN,
    SignInTime,
    SignInIP,
    RiskLevel,
    Location,
    RegistrationTime,
    RegistrationIP,
    TimeBetweenMinutes,
    IPMatch,
    ThreatAssessment
| where ThreatAssessment !startswith "LOW"
| sort by ThreatAssessment asc, TimeBetweenMinutes asc
```

**Performance Notes:**
- 7-day sweep window balances coverage with query performance
- Inner join correlates risky sign-ins with MFA registrations for the same user
- `TimeBetweenMinutes` provides precise timing for attack chain analysis

**Tuning Guidance:**
- Focus on CRITICAL and HIGH assessments first -- these have the strongest correlation
- If multiple users show the same pattern (risky sign-in → MFA registration), this is a coordinated campaign
- Check if affected users share characteristics: same department, same phishing email, same IP ranges
- Expand the sweep window to 30 days for thorough post-incident analysis

**Expected findings:**
- All users who had MFA registered shortly after a risky sign-in
- Whether this is an isolated incident or part of a broader campaign
- Common IPs or patterns across affected users

**Next action:**
- For each affected user, perform full investigation (Steps 1-6)
- If multiple users affected, escalate to SOC leadership
- Begin containment for ALL affected users simultaneously

---

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to assess whether the MFA method registration is anomalous. UEBA's `FirstTimeUserPerformedAction` and peer group comparison reveal whether MFA registration is a normal activity for this user. Critical account context — `IsDormantAccount`, `IsNewAccount`, and `BlastRadius` — helps determine if the registration represents an account takeover attempt.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 4. UEBA needs approximately **one week** after activation before generating meaningful insights.

#### Query 8A: MFA Registration Anomaly Assessment

```kql
// ============================================================
// Query 8A: UEBA Anomaly Assessment for MFA Registration
// Purpose: Check if the MFA method registration is anomalous
//          and assess account status (dormant, new, blast radius)
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T11:00:00Z);
let TargetUser = "user@contoso.com";
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
    // Action analysis — MFA registration as an action
    FirstTimeAction = tobool(ActivityInsights.FirstTimeUserPerformedAction),
    ActionUncommonForUser = tobool(ActivityInsights.ActionUncommonlyPerformedByUser),
    ActionUncommonAmongPeers = tobool(ActivityInsights.ActionUncommonlyPerformedAmongPeers),
    // Source analysis — registration from unusual location?
    FirstTimeISP = tobool(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommonForUser = tobool(ActivityInsights.ISPUncommonlyUsedByUser),
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    FirstTimeDevice = tobool(ActivityInsights.FirstTimeUserConnectedFromDevice),
    // Account context — critical for MFA takeover assessment
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    IsNewAccount = tobool(UsersInsights.IsNewAccount),
    // Threat intel
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| order by InvestigationPriority desc, TimeGenerated desc
```

#### Query 8B: Post-Registration Access Pattern

```kql
// ============================================================
// Query 8B: Post-MFA-Registration Behavioral Analysis
// Purpose: Detect anomalous access patterns after MFA method
//          was registered — attacker may use new MFA to persist
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <10 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T11:00:00Z);
let TargetUser = "user@contoso.com";
let PostRegistrationWindow = 12h;
BehaviorAnalytics
| where TimeGenerated between (AlertTime .. (AlertTime + PostRegistrationWindow))
| where UserPrincipalName =~ TargetUser
| summarize
    TotalActivities = count(),
    HighAnomalyCount = countif(InvestigationPriority >= 7),
    MediumAnomalyCount = countif(InvestigationPriority >= 4 and InvestigationPriority < 7),
    MaxPriority = max(InvestigationPriority),
    FirstTimeActionCount = countif(tobool(ActivityInsights.FirstTimeUserPerformedAction)),
    FirstTimeResourceCount = countif(tobool(ActivityInsights.FirstTimeUserAccessedResource)),
    FirstTimeAppCount = countif(tobool(ActivityInsights.FirstTimeUserUsedApp)),
    UncommonActionAmongPeers = countif(tobool(ActivityInsights.ActionUncommonlyPerformedAmongPeers)),
    UniqueIPs = dcount(SourceIPAddress),
    Countries = make_set(SourceIPLocation),
    BlastRadius = take_any(tostring(UsersInsights.BlastRadius)),
    IsDormant = take_any(tobool(UsersInsights.IsDormantAccount)),
    IsNew = take_any(tobool(UsersInsights.IsNewAccount))
| extend
    AnomalyRatio = round(todouble(HighAnomalyCount + MediumAnomalyCount) / TotalActivities * 100, 1),
    TakeoverSignals = FirstTimeActionCount + FirstTimeResourceCount + FirstTimeAppCount + UncommonActionAmongPeers,
    AccountRisk = case(
        IsDormant == true, "CRITICAL — Dormant account",
        IsNew == true and BlastRadius == "High", "HIGH — New privileged account",
        BlastRadius == "High", "HIGH — Privileged account",
        IsNew == true, "MEDIUM — New account",
        "STANDARD"
    )
```

**Tuning Guidance:**

- **InvestigationPriority threshold**: `>= 7` = high-confidence anomaly, `>= 4` = moderate, `< 4` = likely normal
- **IsDormantAccount**: A dormant account (180+ days inactive) suddenly registering a new MFA method is a **critical indicator** of account takeover. The attacker gained credentials and is registering their own MFA to maintain persistence
- **IsNewAccount**: Combined with unusual MFA registration patterns, may indicate a honeytoken or test account being abused
- **FirstTimeAction**: If MFA registration is a first-time action for this user AND they've been active for months, this is suspicious — legitimate users register MFA during onboarding, not months later
- **Post-registration analysis**: Focus on whether the user accesses new resources or performs unusual actions after registering the new MFA method

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| InvestigationPriority | >= 7 (high anomaly) | < 4 (normal behavior) |
| IsDormantAccount | true — dormant account registering MFA | false — active user |
| IsNewAccount | true + suspicious timing | true during onboarding |
| FirstTimeAction | true — MFA reg is new for this user | false — registered before |
| ActionUncommonAmongPeers | true — peers don't register MFA | false — normal during rollout |
| FirstTimeISP | true — registration from new ISP | false — user's normal ISP |
| FirstTimeCountry | true — from unusual location | false — user's location |
| Post-registration TakeoverSignals | >= 3 — attacker establishing persistence | 0 — no unusual activity |
| BlastRadius | High — privileged account | Low — standard user |
| AccountRisk | CRITICAL or HIGH | STANDARD |

**Decision guidance:**

- **IsDormantAccount = true + MFA registration** → **CRITICAL**: Dormant account registering MFA is near-certain account takeover. The attacker is establishing persistence. Proceed to Containment immediately — remove the new MFA method and disable the account
- **FirstTimeAction = true + FirstTimeISP = true + FirstTimeCountry = true** → Registration from a completely new location on a user who has never performed this action. Very high confidence of compromise
- **Post-registration TakeoverSignals >= 3** → Attacker registered MFA and is now actively exploring the environment. Multiple first-time actions confirm takeover
- **InvestigationPriority < 4 + normal ISP/country** → Likely legitimate MFA re-registration (device change, app update). Combined with clean findings from Steps 1-7, consider closing
- **BlastRadius = High** → Any suspicious MFA registration on a privileged account requires immediate investigation regardless of other indicators

---

## 6. Containment Playbook

### Immediate Actions (First 30 Minutes)

| Priority | Action | Command/Location | Who |
|---|---|---|---|
| P0 | Remove attacker's MFA methods | Entra Portal > Users > [User] > Authentication methods > Delete suspicious methods | Auth Admin |
| P0 | Revoke all sessions | `Revoke-MgUserSignInSession -UserId [UPN]` | Security Admin |
| P0 | Reset password | Entra Portal > Users > [User] > Reset Password (force change at next sign-in) | Helpdesk Admin |
| P0 | Block sign-in temporarily | Entra Portal > Users > [User] > Properties > Block sign-in = Yes | User Admin |
| P1 | Confirm user risk as compromised | Entra Portal > Identity Protection > Risky users > Confirm compromised | Security Admin |
| P1 | Require re-registration of all MFA methods | `Revoke-MgUserAuthenticationMethodsSignInState -UserId [UPN]` | Auth Admin |

### Secondary Actions (First 4 Hours)

| Priority | Action | Details |
|---|---|---|
| P2 | Audit all MFA methods for affected user | Remove any method not confirmed by the user verbally |
| P2 | Check for email forwarding rules | Run RB-0008 investigation for the same user |
| P2 | Check for OAuth consent grants | Run RB-0011 investigation for the same user |
| P2 | Review Conditional Access bypass | Check if attacker used the new MFA to bypass CA policies |
| P3 | Enforce Authentication Strengths | Require phishing-resistant MFA for privileged accounts |
| P3 | Enable MFA registration policy | Require MFA for MFA registration (break the attack chain) |
| P3 | Implement Temporary Access Pass | Use TAP for secure MFA re-enrollment instead of SMS fallback |

### MFA Method Removal Commands

```powershell
# Connect with Authentication Administrator permissions
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"

# List all auth methods for the user
$UserId = "compromised.user@contoso.com"
Get-MgUserAuthenticationMethod -UserId $UserId

# Remove a specific phone method
$PhoneMethodId = "PHONE_METHOD_ID"
Remove-MgUserAuthenticationPhoneMethod -UserId $UserId -PhoneAuthenticationMethodId $PhoneMethodId

# Remove a specific authenticator app
$AppMethodId = "APP_METHOD_ID"
Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $UserId -MicrosoftAuthenticatorAuthenticationMethodId $AppMethodId

# Remove a FIDO2 key
$Fido2MethodId = "FIDO2_METHOD_ID"
Remove-MgUserAuthenticationFido2Method -UserId $UserId -Fido2AuthenticationMethodId $Fido2MethodId

# Revoke all sessions after cleanup
Revoke-MgUserSignInSession -UserId $UserId
```

---

## 7. Evidence Collection Checklist

| Evidence | Source | Retention | Priority |
|---|---|---|---|
| MFA registration event (AuditLogs) | Microsoft Sentinel | Export query results | Critical |
| Sign-in logs around registration time | Microsoft Sentinel | Export query results | Critical |
| Risk events correlated with registration | Microsoft Sentinel | Export query results | Critical |
| Current auth method inventory | Entra Portal / Graph API | Screenshot + JSON export | Critical |
| User's device list | Entra Portal > Users > Devices | Screenshot | High |
| Conditional Access evaluation logs | Sign-in logs CA details | Export query results | High |
| Post-registration activity timeline | Microsoft Sentinel | Export query results | High |
| Phishing email (if identified) | Defender for Office 365 | Export .eml | High |
| Org-wide MFA sweep results | Query results from Step 7 | Export CSV | Medium |
| Identity Protection risk user profile | Entra Portal > Identity Protection | Screenshot | Medium |

---

## 8. Escalation Criteria

### Escalate to Incident Commander When:
- Multiple users have MFA registered following risky sign-ins (coordinated campaign)
- Admin/privileged account has rogue MFA methods registered
- Attacker accessed admin tools (Azure Portal, PowerShell, Graph API) post-registration
- MFA registration followed by email forwarding rule creation (BEC chain)
- FIDO2/Passkey registered by attacker (phishing-resistant persistence)

### Escalate to Legal/Privacy When:
- Compromised account accessed sensitive data (email, files, HR systems) post-registration
- Account belongs to executive, legal, finance, or HR personnel
- Evidence of data exfiltration via authenticated sessions using rogue MFA

### Escalate to Identity Team When:
- Conditional Access policies did not prevent MFA registration from risky session
- MFA registration policy does not require MFA for registration (attack chain unbroken)
- Authentication Strengths not enforced for privileged roles
- Temporary Access Pass policy needs configuration for secure re-enrollment

---

## 9. False Positive Documentation

| Scenario | How to Verify | Action |
|---|---|---|
| New employee MFA onboarding | Check hire date in HR system, verify within first 7 days | Document as onboarding, no action |
| User switched to new phone | Verify with user directly (not via potentially compromised account) | Confirm via out-of-band channel |
| IT helpdesk MFA reset | Check helpdesk ticket system for matching ticket | Verify ticket was opened by legitimate user |
| Org-wide MFA enrollment campaign | Check IT communications for enrollment mandate | Verify timing matches campaign window |
| User adding backup MFA method | Verify from corporate IP, compliant device, during business hours | Document if context matches |

---

## 10. MITRE ATT&CK Mapping

| Technique | ID | Tactic | How Detected |
|---|---|---|---|
| Modify Authentication Process: MFA | T1556.006 | Persistence, Defense Evasion | New MFA method registered in AuditLogs |
| Account Manipulation: Device Registration | T1098.005 | Persistence | FIDO2 key or device registered to account |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence, Defense Evasion | Attacker using registered MFA to authenticate |
| Account Manipulation | T1098 | Persistence | Auth method changes in account configuration |

---

## 11. Query Summary

| # | Query | Table | Purpose |
|---|---|---|---|
| 1 | MFA Registration Event Analysis | AuditLogs | Identify registration events, methods, IPs, timing |
| 2 | Pre-Registration Sign-In Context | SigninLogs | Analyze sign-in risk before MFA registration |
| 3 | Risk Event Correlation | AADUserRiskEvents | Correlate registration with Identity Protection risks |
| 4 | Baseline Comparison | AuditLogs | Compare against user/org MFA registration history |
| 5 | Post-Registration Access | SigninLogs | Track activity after MFA registration |
| 6 | Auth Method Inventory | AuditLogs | List all MFA methods to identify rogue ones |
| 7 | Org-Wide MFA Sweep | AuditLogs + SigninLogs | Find other users with suspicious MFA registrations |

---

## Appendix A: Datatable Tests

### Test 1: MFA Registration Detection

```kql
// ============================================================
// TEST 1: MFA Registration Detection
// Validates: Query 1 - Detect MFA registration events and classify risk
// Expected: compromised.user Authenticator = "HIGH - Authenticator app registered"
//           compromised.user FIDO2 = "CRITICAL - Hardware key/passkey registered"
//           new.employee = "REVIEW" (admin-initiated)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- Attacker registers Authenticator app ---
    datetime(2026-02-22T14:00:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"compromised.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"userPrincipalName":"compromised.user@contoso.com","displayName":"Compromised User",
            "modifiedProperties":[
                {"displayName":"StrongAuthenticationMethod","oldValue":"[]","newValue":"[{\"MethodType\":\"PhoneAppNotification\"}]"}
            ]}]),
        "success",
    // --- Attacker also registers FIDO2 key ---
    datetime(2026-02-22T14:05:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"compromised.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"userPrincipalName":"compromised.user@contoso.com","displayName":"Compromised User",
            "modifiedProperties":[
                {"displayName":"StrongAuthenticationMethod","oldValue":"[]","newValue":"[{\"MethodType\":\"FIDO2\"}]"}
            ]}]),
        "success",
    // --- Admin registers MFA for new employee (legitimate) ---
    datetime(2026-02-22T10:00:00Z), "Admin registered security info",
        dynamic({"user":{"userPrincipalName":"it.admin@contoso.com","ipAddress":"10.0.0.5"}}),
        dynamic([{"userPrincipalName":"new.employee@contoso.com","displayName":"New Employee",
            "modifiedProperties":[
                {"displayName":"StrongAuthenticationMethod","oldValue":"[]","newValue":"[{\"MethodType\":\"PhoneAppNotification\"}]"}
            ]}]),
        "success",
    // --- Password reset before MFA registration (attack chain) ---
    datetime(2026-02-22T13:45:00Z), "Reset password (self-service)",
        dynamic({"user":{"userPrincipalName":"compromised.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"userPrincipalName":"compromised.user@contoso.com","displayName":"Compromised User",
            "modifiedProperties":[]}]),
        "success"
];
// --- Run detection query ---
TestAuditLogs
| where OperationName in (
    "User registered security info",
    "Admin registered security info",
    "Reset password (self-service)"
)
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend
    PropertyName = tostring(ModifiedProps.displayName),
    NewValue = tostring(ModifiedProps.newValue)
| extend
    MFAMethodRegistered = case(
        PropertyName == "StrongAuthenticationMethod" and NewValue has "PhoneAppNotification",
            "Microsoft Authenticator (Push Notification)",
        PropertyName == "StrongAuthenticationMethod" and NewValue has "FIDO2",
            "FIDO2 Security Key",
        OperationName has "password", strcat("PASSWORD EVENT: ", OperationName),
        ""
    ),
    IsAdminAction = ActorUPN != TargetUser and isnotempty(ActorUPN)
| where isnotempty(MFAMethodRegistered)
| extend
    RiskIndicator = case(
        IsAdminAction, "REVIEW - Admin-initiated MFA registration",
        MFAMethodRegistered has "FIDO2", "CRITICAL - Hardware key/passkey registered",
        MFAMethodRegistered has "Authenticator", "HIGH - Authenticator app registered",
        MFAMethodRegistered has "PASSWORD", "HIGH - Self-service password reset",
        "REVIEW - Requires context"
    )
| project TimeGenerated, ActorUPN, TargetUser, MFAMethodRegistered, IsAdminAction, RiskIndicator, ActorIP
// Expected: compromised.user Authenticator = "HIGH - Authenticator app registered" from 198.51.100.50
// Expected: compromised.user FIDO2 = "CRITICAL - Hardware key/passkey registered" from 198.51.100.50
// Expected: compromised.user password reset = "HIGH - Self-service password reset" from 198.51.100.50
// Expected: new.employee = "REVIEW - Admin-initiated MFA registration" from 10.0.0.5
```

### Test 2: Risk Event Correlation

```kql
// ============================================================
// TEST 2: Risk Event Correlation
// Validates: Query 3 - Correlate MFA registration with risk events
// Expected: compromised.user = "CONFIRMED ATTACK CHAIN" (password spray + MFA reg within 30 min)
//           normal.user = "REQUIRES INVESTIGATION" (risk event > 12h from any MFA reg)
// ============================================================
let TestRiskEvents = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    RiskEventType: string,
    RiskLevel: string,
    RiskState: string,
    RiskDetail: string,
    DetectionTimingType: string,
    IPAddress: string,
    City: string,
    CountryOrRegion: string,
    Source: string,
    Activity: string,
    AdditionalInfo: string,
    CorrelationId: string
) [
    // --- Password spray detected for compromised.user 15 min before MFA reg ---
    datetime(2026-02-22T13:45:00Z), "compromised.user@contoso.com",
        "passwordSpray", "high", "atRisk", "detectedSuspiciousActivity",
        "realtime", "198.51.100.50", "Unknown", "RU",
        "IdentityProtection", "signin", "", "corr-001",
    // --- Unfamiliar sign-in for normal.user (hours before, no MFA reg) ---
    datetime(2026-02-22T06:00:00Z), "normal.user@contoso.com",
        "unfamiliarFeatures", "medium", "atRisk", "detectedSuspiciousActivity",
        "realtime", "10.0.0.50", "New York", "US",
        "IdentityProtection", "signin", "", "corr-002"
];
let AlertTime = datetime(2026-02-22T14:00:00Z);
// --- Run correlation ---
TestRiskEvents
| project
    TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel,
    RiskState, IPAddress,
    Location = strcat(City, ", ", CountryOrRegion),
    DetectionTimingType
| extend
    TimeDeltaMinutes = datetime_diff("minute", AlertTime, TimeGenerated),
    ProximityToRegistration = case(
        abs(datetime_diff("minute", AlertTime, TimeGenerated)) <= 30,
            "CRITICAL - Risk event within 30 min of MFA registration",
        abs(datetime_diff("minute", AlertTime, TimeGenerated)) <= 120,
            "HIGH - Risk event within 2 hours of MFA registration",
        abs(datetime_diff("minute", AlertTime, TimeGenerated)) <= 720,
            "MEDIUM - Risk event within 12 hours of MFA registration",
        "LOW - Risk event > 12 hours from MFA registration"
    ),
    AttackChainAssessment = case(
        RiskEventType in ("passwordSpray", "leakedCredentials")
            and abs(datetime_diff("minute", AlertTime, TimeGenerated)) <= 30,
            "CONFIRMED ATTACK CHAIN - Credential compromise then immediate MFA registration",
        RiskEventType in ("anonymizedIPAddress", "maliciousIPAddress")
            and abs(datetime_diff("minute", AlertTime, TimeGenerated)) <= 30,
            "CONFIRMED ATTACK CHAIN - Suspicious IP sign-in then immediate MFA registration",
        "REQUIRES INVESTIGATION - Context needed"
    )
| project UserPrincipalName, RiskEventType, RiskLevel, IPAddress, TimeDeltaMinutes, ProximityToRegistration, AttackChainAssessment
// Expected: compromised.user = "CONFIRMED ATTACK CHAIN" (passwordSpray, 15 min before MFA reg)
// Expected: normal.user = "REQUIRES INVESTIGATION" (unfamiliarFeatures, 8 hours before)
```

### Test 3: Baseline Comparison

```kql
// ============================================================
// TEST 3: Baseline Comparison
// Validates: Query 4 - Compare MFA registration against user baseline
// Expected: compromised.user = "ANOMALOUS - User has NEVER registered MFA before"
//           regular.user = "WITHIN BASELINE" (recent MFA registration history)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- regular.user: Has registered MFA twice in the past ---
    datetime(2026-01-10T09:00:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"regular.user@contoso.com","ipAddress":"10.0.0.20"}}),
        dynamic([{"userPrincipalName":"regular.user@contoso.com","modifiedProperties":[]}]),
        "success",
    datetime(2026-02-05T11:00:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"regular.user@contoso.com","ipAddress":"10.0.0.20"}}),
        dynamic([{"userPrincipalName":"regular.user@contoso.com","modifiedProperties":[]}]),
        "success",
    // --- compromised.user: Current suspicious registration (NO prior history) ---
    datetime(2026-02-22T14:00:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"compromised.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"userPrincipalName":"compromised.user@contoso.com","modifiedProperties":[]}]),
        "success"
];
let AlertTime = datetime(2026-02-22T14:00:00Z);
let BaselineDays = 30d;
// --- Per-user MFA registration baseline ---
TestAuditLogs
| where TimeGenerated between (AlertTime - 90d .. AlertTime)
| where OperationName in ("User registered security info", "User registered all required security info")
| summarize
    TotalRegistrations = count(),
    RegistrationIPs = make_set(tostring(InitiatedBy.user.ipAddress), 10),
    LastRegistration = max(TimeGenerated)
    by User = tostring(InitiatedBy.user.userPrincipalName)
| extend
    DaysSinceLastRegistration = datetime_diff("day", AlertTime, LastRegistration),
    Assessment = case(
        TotalRegistrations == 0,
            "ANOMALOUS - User has NEVER registered MFA before",
        DaysSinceLastRegistration < 7,
            "SUSPICIOUS - User registered MFA within last 7 days",
        DaysSinceLastRegistration > 180,
            "SUSPICIOUS - No MFA registration in 6+ months",
        "WITHIN BASELINE - User has recent MFA registration history"
    )
| project User, TotalRegistrations, DaysSinceLastRegistration, RegistrationIPs, Assessment
// Expected: regular.user - TotalRegistrations=2, Assessment = "WITHIN BASELINE"
// Expected: compromised.user - Not in baseline results (no prior registrations)
//           When this user appears with current registration and no baseline, assessment = "ANOMALOUS"
```

### Test 4: Org-Wide MFA Registration Sweep

```kql
// ============================================================
// TEST 4: Org-Wide MFA Registration Sweep
// Validates: Query 7 - Find MFA registrations following risky sign-ins
// Expected: compromised.user = "CRITICAL" (MFA reg 15 min after password spray)
//           finance.director = "HIGH" (MFA reg 90 min after unfamiliar sign-in)
//           intern = no match (MFA reg but no risky sign-in)
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    Result: string
) [
    // --- compromised.user: MFA reg ---
    datetime(2026-02-22T14:00:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"compromised.user@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"userPrincipalName":"compromised.user@contoso.com"}]),
        "success",
    // --- finance.director: MFA reg ---
    datetime(2026-02-22T16:30:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"finance.director@contoso.com","ipAddress":"203.0.113.99"}}),
        dynamic([{"userPrincipalName":"finance.director@contoso.com"}]),
        "success",
    // --- intern: MFA reg (no risky sign-in, should not appear) ---
    datetime(2026-02-22T09:00:00Z), "User registered security info",
        dynamic({"user":{"userPrincipalName":"intern@contoso.com","ipAddress":"10.0.0.100"}}),
        dynamic([{"userPrincipalName":"intern@contoso.com"}]),
        "success"
];
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    LocationDetails: dynamic,
    RiskLevelDuringSignIn: string,
    ResultType: string,
    AppDisplayName: string
) [
    // --- compromised.user: Risky sign-in 15 min before MFA reg ---
    datetime(2026-02-22T13:45:00Z), "compromised.user@contoso.com",
        "198.51.100.50", dynamic({"city":"Unknown","countryOrRegion":"RU"}),
        "high", "0", "My Security Info",
    // --- finance.director: Risky sign-in 90 min before MFA reg ---
    datetime(2026-02-22T15:00:00Z), "finance.director@contoso.com",
        "203.0.113.99", dynamic({"city":"Lagos","countryOrRegion":"NG"}),
        "medium", "0", "My Account",
    // --- intern: Normal sign-in (no risk) ---
    datetime(2026-02-22T08:50:00Z), "intern@contoso.com",
        "10.0.0.100", dynamic({"city":"New York","countryOrRegion":"US"}),
        "none", "0", "My Security Info"
];
// --- Correlate MFA registrations with risky sign-ins ---
let AllRegistrations = TestAuditLogs
| where OperationName has "security info"
| project
    RegistrationTime = TimeGenerated,
    UserUPN = tostring(InitiatedBy.user.userPrincipalName),
    RegistrationIP = tostring(InitiatedBy.user.ipAddress);
let RiskySignIns = TestSigninLogs
| where RiskLevelDuringSignIn in ("high", "medium") and ResultType == "0"
| project
    SignInTime = TimeGenerated,
    UserUPN = UserPrincipalName,
    SignInIP = IPAddress,
    RiskLevel = RiskLevelDuringSignIn,
    Location = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion));
AllRegistrations
| join kind=inner RiskySignIns on UserUPN
| where RegistrationTime > SignInTime
    and datetime_diff("hour", RegistrationTime, SignInTime) <= 24
| extend
    TimeBetweenMinutes = datetime_diff("minute", RegistrationTime, SignInTime),
    IPMatch = RegistrationIP == SignInIP
| extend
    ThreatAssessment = case(
        TimeBetweenMinutes <= 30 and IPMatch,
            "CRITICAL - MFA registered within 30 min of risky sign-in from same IP",
        TimeBetweenMinutes <= 30,
            "HIGH - MFA registered within 30 min of risky sign-in",
        TimeBetweenMinutes <= 120,
            "HIGH - MFA registered within 2 hours of risky sign-in",
        "MEDIUM - MFA registered > 2 hours after risky sign-in"
    )
| project UserUPN, SignInTime, SignInIP, RiskLevel, Location, RegistrationTime, RegistrationIP, TimeBetweenMinutes, IPMatch, ThreatAssessment
// Expected: compromised.user = "CRITICAL" (15 min, same IP 198.51.100.50)
// Expected: finance.director = "HIGH" (90 min, same IP 203.0.113.99)
// Expected: intern = NOT IN RESULTS (no risky sign-in to correlate)
```

---

## References

- [Microsoft: Manage authentication methods for Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage)
- [Microsoft: Combined security information registration](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-registration-mfa-sspr-combined)
- [Microsoft: Investigate risk with Identity Protection](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk)
- [Microsoft: Authentication methods activity dashboard](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)
- [Microsoft: Conditional Access - Require MFA for security info registration](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-registration)
- [Microsoft: Temporary Access Pass](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass)
- [MITRE ATT&CK T1556.006 - Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)
- [MITRE ATT&CK T1098.005 - Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- [Scattered Spider MFA registration persistence (Microsoft Threat Intelligence)](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)
- [CISA: Phishing-resistant MFA implementation guide](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf)
