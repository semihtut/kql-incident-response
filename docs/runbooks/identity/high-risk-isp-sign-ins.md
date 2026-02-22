---
title: "High-Risk ISP/Hosting Provider Sign-Ins"
id: RB-0017
severity: high
status: reviewed
description: >
  Investigation runbook for detecting sign-ins originating from suspicious
  infrastructure such as VPS providers, cloud hosting platforms, Tor exit
  nodes, and residential proxy networks. Covers ASN-based infrastructure
  classification, successful authentication from hosting providers,
  geolocation anomaly correlation, known threat infrastructure matching,
  and organization-wide hosting-sourced sign-in sweep. Enterprise users
  virtually never authenticate from DigitalOcean, AWS, Linode, or Tor —
  traffic from these sources is a strong indicator of attacker-controlled
  infrastructure.
mitre_attack:
  tactics:
    - tactic_id: TA0001
      tactic_name: "Initial Access"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
    - tactic_id: TA0006
      tactic_name: "Credential Access"
    - tactic_id: TA0011
      tactic_name: "Command and Control"
  techniques:
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1090.002
      technique_name: "Proxy: External Proxy"
      confidence: confirmed
    - technique_id: T1090.003
      technique_name: "Proxy: Multi-hop Proxy"
      confidence: probable
    - technique_id: T1071.001
      technique_name: "Application Layer Protocol: Web Protocols"
      confidence: probable
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Storm-0558"
  - "Scattered Spider (Octo Tempest)"
  - "Star Blizzard (SEABORGIUM)"
  - "Forest Blizzard (APT28)"
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
  - table: "AADUserRiskEvents"
    product: "Entra ID Identity Protection"
    license: "Entra ID P2"
    required: false
    alternatives: []
  - table: "AADServicePrincipalSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: false
    alternatives: []
  - table: "AuditLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-22
updated: 2026-02-22
version: "1.0"
tier: 2
data_checks:
  - query: "SigninLogs | take 1"
    label: primary
    description: "Sign-in events with ASN and IP data"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "For non-interactive sign-ins from hosting IPs"
  - query: "AADUserRiskEvents | take 1"
    description: "For correlated Identity Protection risk events"
  - query: "AuditLogs | take 1"
    description: "For post-authentication persistence actions"
---

# High-Risk ISP/Hosting Provider Sign-Ins - Investigation Runbook

> **RB-0017** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Custom Detection via SigninLogs ASN Analysis
> **Detection Logic:** Sign-ins from known VPS, hosting, Tor, and proxy infrastructure ASNs
> **Primary MITRE Technique:** T1090.002 - Proxy: External Proxy

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Hosting Provider Sign-In Detection](#step-1-hosting-provider-sign-in-detection)
   - [Step 2: User Sign-In History and Infrastructure Comparison](#step-2-user-sign-in-history-and-infrastructure-comparison)
   - [Step 3: Risk Event and Conditional Access Correlation](#step-3-risk-event-and-conditional-access-correlation)
   - [Step 4: Baseline Comparison - Establish Normal Infrastructure Pattern](#step-4-baseline-comparison---establish-normal-infrastructure-pattern)
   - [Step 5: Post-Authentication Activity Audit](#step-5-post-authentication-activity-audit)
   - [Step 6: Non-Interactive and Token-Based Access from Hosting IPs](#step-6-non-interactive-and-token-based-access-from-hosting-ips)
   - [Step 7: Organization-Wide Hosting Infrastructure Sign-In Sweep](#step-7-organization-wide-hosting-infrastructure-sign-in-sweep)
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
This detection fires when a user successfully authenticates (or attempts to authenticate) from an IP address belonging to a known VPS provider, cloud hosting platform, Tor exit node, or commercial proxy/VPN service. The detection uses the `AutonomousSystemNumber` (ASN) field in SigninLogs to classify the source infrastructure.

High-risk infrastructure categories:
1. **Cloud/VPS Providers:** DigitalOcean (AS14061), AWS (AS16509/AS14618), Google Cloud (AS15169/AS396982), Azure (AS8075), Linode/Akamai (AS63949), Vultr (AS20473), OVH (AS16276), Hetzner (AS24940)
2. **Tor Exit Nodes:** Various ASNs, identifiable by known exit node IP lists
3. **Commercial Proxy/VPN:** NordVPN, ExpressVPN, Surfshark — while not inherently malicious, combined with other risk signals they indicate obfuscation
4. **Residential Proxy Networks:** Luminati/BrightData, Oxylabs — particularly dangerous as they appear as residential ISPs

**Why it matters:**
Enterprise users authenticate from corporate networks, home ISPs, or mobile carriers — virtually never from DigitalOcean droplets or AWS EC2 instances. When an attacker compromises credentials (via phishing, spray, or stuffing), they typically operate from cloud infrastructure because it's:
- **Cheap and disposable** — $5/month VPS, destroy after use
- **Geographic flexibility** — spin up instances in the target's country to avoid geo-anomaly detection
- **IP rotation** — easily deploy multiple IPs to avoid IP-based blocks
- **Automation-friendly** — run attack tools directly on the VPS

Microsoft Identity Protection flags some hosting-sourced sign-ins as `anonymizedIPAddress` or `unfamiliarFeatures`, but the coverage is inconsistent. Explicit ASN-based detection provides a stronger, more deterministic signal.

**Why this is HIGH severity:**
- Successful auth from hosting infrastructure is strong evidence of compromised credentials
- Attackers specifically choose VPS providers to avoid residential IP reputation checks
- Hosting IPs have no legitimate business reason to appear in enterprise sign-in logs
- Nation-state actors (APT29, APT28) routinely use cloud infrastructure for credential replay

---

## 2. Prerequisites

{{ data_check_timeline(page.meta.data_checks) }}

---

## 3. Input Parameters

Set these values before running the investigation queries:

```kql
// === INVESTIGATION PARAMETERS ===
let InvestigationTarget = "user@company.com";   // UPN of affected user
let AlertTime = datetime(2026-02-22T14:30:00Z); // Time of suspicious sign-in
let LookbackWindow = 24h;                       // Analysis window
let BaselineWindow = 30d;                        // Historical baseline period
```

---

## 4. Quick Triage Criteria

Use this decision matrix for initial severity assessment:

| Indicator | True Positive Signal | False Positive Signal |
|---|---|---|
| Source ASN | Known hosting/VPS (DigitalOcean, AWS, etc.) | Corporate cloud egress, known VPN vendor |
| Auth result | Successful (ResultType 0) | Failed (ResultType 50126) |
| User type | Regular user, executive, admin | Developer with legitimate cloud access |
| Sign-in pattern | First-ever from this ASN | Consistent pattern over 30+ days |
| Post-auth activity | MFA registration, inbox rules, app consent | Normal email/Teams usage |
| Risk level | Identity Protection flagged risk | No risk events correlated |

---

## 5. Investigation Steps

### Step 1: Hosting Provider Sign-In Detection

**Objective:** Identify all sign-ins from known hosting/VPS infrastructure for the target user and classify the risk level.

```kql
// Step 1: Hosting Provider Sign-In Detection
// Table: SigninLogs | Identifies sign-ins from hosting/VPS infrastructure
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
// Comprehensive hosting/VPS ASN list
let HostingASNs = dynamic([
    14061,   // DigitalOcean
    16509,   // Amazon AWS
    14618,   // Amazon AWS
    15169,   // Google Cloud
    396982,  // Google Cloud
    8075,    // Microsoft Azure
    13335,   // Cloudflare
    24940,   // Hetzner
    16276,   // OVHcloud
    63949,   // Linode/Akamai
    20473,   // Vultr/Choopa
    46606,   // Unified Layer
    36352,   // ColoCrossing
    55286,   // ServerMania
    51167,   // Contabo
    4785,    // xTom
    9009,    // M247 (VPN provider infrastructure)
    62904,   // Eonix
    212238,  // Datacamp/Proxy
    174,     // Cogent (often used for VPS)
    6939     // Hurricane Electric
]);
// Known anonymization service ASNs
let AnonymizationASNs = dynamic([
    60068,   // CDN77 (used by various VPN providers)
    209854,  // NordVPN/Surfshark infrastructure
    212238,  // Datacamp/residential proxy
    40676,   // Psychz Networks
    398101,  // GoDaddy proxy
    30633    // Leaseweb
]);
SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where UserPrincipalName =~ InvestigationTarget
| extend ParsedLocation = parse_json(LocationDetails)
| extend
    City = tostring(ParsedLocation.city),
    Country = tostring(ParsedLocation.countryOrRegion),
    Latitude = toreal(ParsedLocation.geoCoordinates.latitude),
    Longitude = toreal(ParsedLocation.geoCoordinates.longitude)
| extend
    InfrastructureType = case(
        AutonomousSystemNumber in (HostingASNs), "Hosting/VPS",
        AutonomousSystemNumber in (AnonymizationASNs), "VPN/Proxy",
        "Other"
    ),
    AuthResult = case(
        ResultType == "0", "Success",
        ResultType == "50126", "Wrong Password",
        ResultType == "50053", "Smart Lockout",
        ResultType == "50074", "MFA Required",
        ResultType == "53003", "Blocked by CA",
        strcat("Error: ", ResultType)
    )
| where InfrastructureType != "Other"
| project
    TimeGenerated,
    IPAddress,
    AutonomousSystemNumber,
    InfrastructureType,
    AuthResult,
    Country, City,
    UserAgent,
    ClientAppUsed,
    AppDisplayName,
    ResourceDisplayName,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskState
| sort by TimeGenerated asc
```

**What to look for:**

- **AuthResult = "Success"** from Hosting/VPS = **CRITICAL** — confirmed credential use from attacker infrastructure
- **AuthResult = "MFA Required"** = password is compromised, MFA is the only defense
- **InfrastructureType = "VPN/Proxy"** with success = potential obfuscation but less conclusive than hosting
- **UserAgent** = automated tooling (python-requests, curl) vs browser = indicates tooling vs manual access
- **ConditionalAccessStatus = "notApplied"** = no CA policy protecting against this — gap in coverage
- **RiskLevelDuringSignIn** = check if Identity Protection also flagged this sign-in

---

### Step 2: User Sign-In History and Infrastructure Comparison

**Objective:** Compare the hosting-sourced sign-in against the user's established sign-in infrastructure pattern to determine if this is truly anomalous.

```kql
// Step 2: User Sign-In History and Infrastructure Comparison
// Table: SigninLogs | Compares current infrastructure against historical pattern
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let BaselineWindow = 30d;
SigninLogs
| where TimeGenerated between ((AlertTime - BaselineWindow) .. AlertTime)
| where UserPrincipalName =~ InvestigationTarget
| where ResultType == "0"  // Only successful sign-ins
| extend ParsedLocation = parse_json(LocationDetails)
| summarize
    TotalSignIns = count(),
    DistinctIPs = dcount(IPAddress),
    DistinctASNs = dcount(AutonomousSystemNumber),
    ASNList = make_set(AutonomousSystemNumber, 50),
    IPList = make_set(IPAddress, 100),
    CountryList = make_set(tostring(ParsedLocation.countryOrRegion), 20),
    CityList = make_set(tostring(ParsedLocation.city), 50),
    UserAgentList = make_set(UserAgent, 30),
    AppList = make_set(AppDisplayName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
| extend
    AccountAge = datetime_diff('day', LastSeen, FirstSeen),
    AvgDailySignIns = round(toreal(TotalSignIns) / max_of(datetime_diff('day', LastSeen, FirstSeen), 1), 1)
```

**What to look for:**

- **ASNList** = check if any hosting ASNs appear in the user's historical sign-in pattern. If the hosting ASN is new, it's highly suspicious
- **CountryList** = if the hosting sign-in comes from a country never seen for this user, double anomaly
- **UserAgentList** = if the attacker's UserAgent differs from all historical UAs, confirms foreign access
- **AccountAge** and **AvgDailySignIns** = newer accounts with low activity are higher risk
- **If hosting ASN IS in history** = may be a developer legitimately using cloud infrastructure — check with user

---

### Step 3: Risk Event and Conditional Access Correlation

**Objective:** Correlate the hosting-sourced sign-in with Identity Protection risk events and Conditional Access policy evaluations.

```kql
// Step 3: Risk Event and Conditional Access Correlation
// Table: AADUserRiskEvents + SigninLogs | Correlates risk events with hosting sign-ins
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
// Get hosting IPs from Step 1
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
let SuspiciousIPs = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where AutonomousSystemNumber in (HostingASNs)
    | distinct IPAddress;
// Check Identity Protection risk events
let RiskEvents = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | project
        TimeGenerated,
        Source = "IdentityProtection",
        EventType = RiskEventType,
        Detail = RiskDetail,
        Level = RiskLevel,
        State = RiskState,
        IPAddress = IpAddress,
        LocationInfo = Location;
// Check CA policy evaluation for hosting sign-ins
let CAPolicyEval = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where IPAddress in (SuspiciousIPs)
    | mv-expand ConditionalAccessPolicies
    | extend
        PolicyName = tostring(ConditionalAccessPolicies.displayName),
        PolicyResult = tostring(ConditionalAccessPolicies.result)
    | project
        TimeGenerated,
        Source = "ConditionalAccess",
        EventType = PolicyName,
        Detail = PolicyResult,
        Level = ConditionalAccessStatus,
        State = "",
        IPAddress,
        LocationInfo = tostring(parse_json(LocationDetails).countryOrRegion);
union RiskEvents, CAPolicyEval
| sort by TimeGenerated asc
```

**What to look for:**

- **RiskEventType containing "anonymizedIPAddress"** = Identity Protection also detected this as suspicious
- **RiskEventType containing "unfamiliarFeatures"** = ML model flagged unusual sign-in properties
- **PolicyResult = "failure"** = CA policy blocked the sign-in — defense is working
- **PolicyResult = "success"** or no CA policies = sign-in was allowed — potential gap
- **No risk events at all** = Identity Protection missed this — your ASN-based detection caught what ML didn't

---

### Step 4: Baseline Comparison - Establish Normal Infrastructure Pattern

**Objective:** Determine whether the user has any legitimate history of signing in from hosting/VPS infrastructure.

```kql
// Step 4: Baseline Comparison - Establish Normal Infrastructure Pattern
// Table: SigninLogs | Compares hosting sign-ins against 30-day infrastructure baseline
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let BaselineWindow = 30d;
let CurrentWindow = 24h;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// Historical: any sign-ins from hosting infrastructure
let HistoricalHosting = SigninLogs
    | where TimeGenerated between ((AlertTime - BaselineWindow) .. (AlertTime - CurrentWindow))
    | where UserPrincipalName =~ InvestigationTarget
    | where AutonomousSystemNumber in (HostingASNs)
    | summarize
        BaselineHostingSignIns = count(),
        BaselineHostingASNs = make_set(AutonomousSystemNumber, 20),
        BaselineHostingIPs = make_set(IPAddress, 50),
        BaselineHostingApps = make_set(AppDisplayName, 20),
        BaselineHostingCountries = make_set(
            tostring(parse_json(LocationDetails).countryOrRegion), 10
        ),
        BaselineDays = datetime_diff('day', max(TimeGenerated), min(TimeGenerated));
// Current: hosting sign-ins in the alert window
let CurrentHosting = SigninLogs
    | where TimeGenerated between ((AlertTime - CurrentWindow) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where AutonomousSystemNumber in (HostingASNs)
    | summarize
        CurrentHostingSignIns = count(),
        CurrentHostingASNs = make_set(AutonomousSystemNumber, 20),
        CurrentHostingIPs = make_set(IPAddress, 50),
        CurrentHostingApps = make_set(AppDisplayName, 20),
        CurrentHostingCountries = make_set(
            tostring(parse_json(LocationDetails).countryOrRegion), 10
        ),
        CurrentSuccesses = countif(ResultType == "0");
HistoricalHosting
| extend placeholder = 1
| join kind=inner (CurrentHosting | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    NewHostingASNs = set_difference(CurrentHostingASNs, BaselineHostingASNs),
    NewHostingCountries = set_difference(CurrentHostingCountries, BaselineHostingCountries),
    AnomalyVerdict = case(
        BaselineHostingSignIns == 0 and CurrentHostingSignIns > 0,
            "HIGH ANOMALY - First-ever hosting infrastructure sign-in",
        array_length(set_difference(CurrentHostingASNs, BaselineHostingASNs)) > 0,
            "MODERATE ANOMALY - New hosting provider not seen in baseline",
        CurrentSuccesses > 0 and BaselineHostingSignIns == 0,
            "HIGH ANOMALY - First-ever successful auth from hosting",
        CurrentHostingSignIns > BaselineHostingSignIns * 3,
            "MODERATE ANOMALY - Hosting sign-in volume spike",
        "LOW ANOMALY - Within established hosting usage pattern"
    )
```

**What to look for:**

- **"First-ever hosting infrastructure sign-in"** = This user has NEVER signed in from VPS/hosting — highly suspicious
- **NewHostingASNs not empty** = Even if user has some hosting history, this is a new provider
- **CurrentSuccesses > 0 with no baseline** = First-ever successful auth from infrastructure — likely compromise
- **"LOW ANOMALY"** = User legitimately uses hosting/VPS (developer, cloud admin) — may be FP but still review

---

### Step 5: Post-Authentication Activity Audit

**Objective:** If successful authentication from hosting infrastructure occurred, audit all subsequent actions for indicators of compromise.

```kql
// Step 5: Post-Authentication Activity Audit
// Table: AuditLogs | Checks for post-compromise actions after hosting sign-in
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// Get the timestamp of first successful hosting sign-in
let CompromiseTime = toscalar(
    SigninLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where UserPrincipalName =~ InvestigationTarget
    | where AutonomousSystemNumber in (HostingASNs)
    | where ResultType == "0"
    | summarize min(TimeGenerated)
);
// High-value operations to monitor post-compromise
AuditLogs
| where TimeGenerated between (CompromiseTime .. (CompromiseTime + 72h))
| where InitiatedBy has InvestigationTarget
| extend
    ActionCategory = case(
        OperationName in ("Register security info", "User registered security info",
            "Update security info", "User started security info registration"),
            "MFA_PERSISTENCE",
        OperationName in ("Consent to application", "Add OAuth2PermissionGrant",
            "Add delegated permission grant", "Add app role assignment to service principal"),
            "APP_CONSENT",
        OperationName in ("Add member to role", "Add eligible member to role",
            "Add member to group"),
            "PRIVILEGE_ESCALATION",
        OperationName has_any ("inbox", "forwarding", "redirect", "transport rule"),
            "EMAIL_MANIPULATION",
        OperationName in ("Update user", "Reset password", "Change user password",
            "Update application", "Add service principal credentials"),
            "ACCOUNT_MANIPULATION",
        OperationName has_any ("conditional access", "policy"),
            "POLICY_CHANGE",
        "OTHER"
    )
| where ActionCategory != "OTHER"
| project
    TimeGenerated,
    ActionCategory,
    OperationName,
    TargetResource = tostring(TargetResources[0].displayName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    Result
| sort by TimeGenerated asc
```

**What to look for:**

- **MFA_PERSISTENCE** actions = Attacker registering their own MFA method (see [RB-0012](suspicious-mfa-registration.md))
- **APP_CONSENT** actions = Attacker granting OAuth app access (see [RB-0011](consent-grant-attack.md))
- **PRIVILEGE_ESCALATION** actions = Attacker elevating privileges (see [RB-0013](privileged-role-assignment.md))
- **EMAIL_MANIPULATION** actions = BEC-style operations (see [RB-0008](../email/suspicious-inbox-forwarding-rule.md))
- **POLICY_CHANGE** actions = Defense evasion (see [RB-0015](conditional-access-manipulation.md))
- **Multiple categories in sequence** = full attack chain: access → persist → escalate → exfiltrate

---

### Step 6: Non-Interactive and Token-Based Access from Hosting IPs

**Objective:** Check for non-interactive sign-ins (token replay, app-based access) from hosting infrastructure that may indicate stolen session tokens or OAuth abuse.

```kql
// Step 6: Non-Interactive and Token-Based Access from Hosting IPs
// Table: AADNonInteractiveUserSignInLogs | Detects token replay and app-based access
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
AADNonInteractiveUserSignInLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 72h))
| where UserPrincipalName =~ InvestigationTarget
| where AutonomousSystemNumber in (HostingASNs)
| extend ParsedLocation = parse_json(LocationDetails)
| project
    TimeGenerated,
    IPAddress,
    AutonomousSystemNumber,
    Country = tostring(ParsedLocation.countryOrRegion),
    City = tostring(ParsedLocation.city),
    UserAgent,
    AppDisplayName,
    ResourceDisplayName,
    ResultType,
    AuthResult = case(
        ResultType == "0", "Success",
        ResultType == "50126", "Invalid Creds",
        strcat("Error: ", ResultType)
    ),
    TokenIssuerType,
    IsInteractive
| summarize
    TotalNonInteractive = count(),
    SuccessCount = countif(ResultType == "0"),
    DistinctApps = dcount(AppDisplayName),
    DistinctResources = dcount(ResourceDisplayName),
    Apps = make_set(AppDisplayName, 20),
    Resources = make_set(ResourceDisplayName, 20),
    SourceIPs = make_set(IPAddress, 20),
    TimeRange = strcat(format_datetime(min(TimeGenerated), 'yyyy-MM-dd HH:mm'),
        " → ", format_datetime(max(TimeGenerated), 'yyyy-MM-dd HH:mm'))
    by AutonomousSystemNumber
| extend
    TokenAbuseIndicator = case(
        SuccessCount > 10 and DistinctResources > 3, "HIGH - Multi-resource token abuse",
        SuccessCount > 0 and DistinctApps > 2, "HIGH - Multi-app token use",
        SuccessCount > 0, "MEDIUM - Token-based access detected",
        "LOW - Failed attempts only"
    )
| sort by SuccessCount desc
```

**What to look for:**

- **TokenAbuseIndicator = "HIGH"** = Attacker using stolen tokens to access multiple resources from hosting IP
- **Apps containing "Microsoft Graph"** or **"Exchange Online"** = Data access via API from infrastructure
- **High SuccessCount with non-interactive sign-ins** = Automated data exfiltration using tokens
- **DistinctResources > 3** = Attacker enumerating multiple services — lateral movement phase
- **TimeRange spanning 24+ hours** = Persistent access, not a one-time event

---

### Step 7: Organization-Wide Hosting Infrastructure Sign-In Sweep

**Objective:** Determine if other accounts are being accessed from the same hosting infrastructure, indicating a broader campaign.

```kql
// Step 7: Organization-Wide Hosting Infrastructure Sign-In Sweep
// Table: SigninLogs | Finds all accounts accessed from hosting infrastructure
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 7d;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. AlertTime)
| where AutonomousSystemNumber in (HostingASNs)
| where ResultType == "0"  // Successful only
| extend ParsedLocation = parse_json(LocationDetails)
| summarize
    SuccessfulSignIns = count(),
    DistinctDays = dcount(bin(TimeGenerated, 1d)),
    SourceIPs = make_set(IPAddress, 20),
    Countries = make_set(tostring(ParsedLocation.countryOrRegion), 10),
    Apps = make_set(AppDisplayName, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, AutonomousSystemNumber
| extend
    RiskScore = case(
        DistinctDays == 1 and SuccessfulSignIns > 5, 90,   // Burst of access, single day
        DistinctDays <= 2 and SuccessfulSignIns > 3, 75,    // Short duration, multiple sign-ins
        DistinctDays >= 7, 30,                               // Consistent over a week (likely legitimate)
        DistinctDays >= 3 and DistinctDays < 7, 50,          // Medium duration
        60  // Default
    ),
    AccessPattern = case(
        DistinctDays >= 7, "Consistent - Likely Legitimate",
        DistinctDays <= 2 and SuccessfulSignIns > 5, "Burst - Suspicious",
        DistinctDays <= 2, "Recent - Needs Review",
        "Intermittent - Investigate"
    )
| where RiskScore >= 50
| sort by RiskScore desc, SuccessfulSignIns desc
```

**What to look for:**

- **RiskScore >= 75** = High-risk accounts needing immediate investigation
- **AccessPattern = "Burst - Suspicious"** = Multiple sign-ins in a short window from hosting — likely compromise
- **Multiple users from same ASN with "Burst" pattern** = coordinated campaign using same infrastructure
- **AccessPattern = "Consistent - Likely Legitimate"** = probably developers or cloud admins — still confirm
- **Shared SourceIPs across different users** = same attacker IP accessing multiple accounts

---

## 6. Containment Playbook

### Immediate Actions (0-30 minutes)
- [ ] **Revoke all sessions** for accounts with confirmed hosting sign-ins (ResultType = 0)
- [ ] **Reset passwords** for all confirmed compromised accounts
- [ ] **Block attacker IPs** as Named Locations in Conditional Access
- [ ] **Enable sign-in risk policy** in Conditional Access to block high-risk sign-ins requiring MFA
- [ ] **Verify with user** via out-of-band channel: "Did you sign in from [City, Country] on [Date]?"

### Short-term Actions (30 min - 4 hours)
- [ ] **Create Conditional Access policy** blocking sign-ins from known hosting ASNs for non-developer roles
- [ ] **Review all MFA changes** made within 24 hours of the hosting sign-in
- [ ] **Check for OAuth app consents** granted during the suspicious session
- [ ] **Audit inbox rules** for mail forwarding/redirect added post-compromise
- [ ] **Review Conditional Access gap**: why wasn't this sign-in blocked by existing policies?

### Recovery Actions (4-24 hours)
- [ ] Implement Named Location policies for known hosting/VPS IP ranges
- [ ] Enable "sign-in from atypical location" risk policy in Identity Protection
- [ ] Consider implementing Conditional Access for workload identities if service principals are affected
- [ ] Deploy monitoring rule for ongoing hosting infrastructure sign-ins

---

## 7. Evidence Collection Checklist

| Evidence Item | Source Table | Retention | Collection Query |
|---|---|---|---|
| Hosting sign-in events | SigninLogs | 30 days | Step 1 query |
| User's historical sign-in infrastructure | SigninLogs | 30 days | Step 2 query |
| Identity Protection risk events | AADUserRiskEvents | 90 days | Step 3 query |
| Post-auth audit trail | AuditLogs | 30 days | Step 5 query |
| Non-interactive token access | AADNonInteractiveUserSignInLogs | 30 days | Step 6 query |
| Org-wide hosting sign-in campaign | SigninLogs | 30 days | Step 7 query |

---

## 8. Escalation Criteria

| Condition | Action |
|---|---|
| Successful auth from hosting IP + post-compromise actions (Step 5) | Escalate to **P1 Incident** — active compromise |
| Multiple accounts accessed from same hosting infrastructure (Step 7) | Escalate to **P1 Incident** — coordinated attack |
| Executive or admin account signed in from hosting | Escalate to **P1 Incident** — high-value target |
| Token-based multi-resource access from hosting (Step 6) | Escalate to **P2 Incident** — data exfiltration risk |
| Hosting sign-in with no CA policy evaluation | Escalate to **P3** — Conditional Access coverage gap |

---

## 9. False Positive Documentation

| Scenario | How to Identify | Recommended Action |
|---|---|---|
| Developer accessing from cloud VM | Consistent pattern over 30+ days, dev role, same ASN | Whitelist specific ASN for developer group |
| Corporate VPN using cloud egress | Same IP used by multiple users, known VPN provider | Add VPN IP range to Named Locations as trusted |
| Automated CI/CD pipeline | Service account, consistent UserAgent, same app | Exclude service account from detection |
| Third-party SaaS with cloud egress | Known app name, consistent IP, documented integration | Document and whitelist specific IP/app combo |
| User traveling with mobile hotspot via VPN | Known VPN app, short duration, user confirmed travel | Document and close |

---

## 10. MITRE ATT&CK Mapping

| Technique ID | Technique Name | How It Applies | Detection Query |
|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Using compromised credentials from hosting infrastructure | Steps 1, 7 |
| T1090.002 | Proxy: External Proxy | Using VPS/hosting as attack proxy to obscure origin | Steps 1, 2, 4 |
| T1090.003 | Proxy: Multi-hop Proxy | Tor exit nodes and multi-layer proxy chains | Step 1 (Tor ASNs) |
| T1071.001 | Application Layer Protocol: Web | Using standard web protocols from infrastructure for C2 | Step 6 |

---

## 11. Query Summary

| Step | Query | Purpose | Primary Table |
|---|---|---|---|
| 1 | Hosting Provider Sign-In Detection | Identify all sign-ins from VPS/hosting ASNs | SigninLogs |
| 2 | User Sign-In History Comparison | Compare against established infrastructure pattern | SigninLogs |
| 3 | Risk Event & CA Correlation | Correlate with Identity Protection and CA policies | AADUserRiskEvents + SigninLogs |
| 4 | Baseline Comparison | Determine if hosting sign-ins are first-ever or habitual | SigninLogs |
| 5 | Post-Authentication Activity | Audit actions taken after hosting sign-in | AuditLogs |
| 6 | Non-Interactive Token Access | Detect token replay and API abuse from hosting | AADNonInteractiveUserSignInLogs |
| 7 | Org-Wide Hosting Sweep | Find all accounts accessed from hosting infrastructure | SigninLogs |

---

## Appendix A: Datatable Tests

### Test 1: Hosting ASN Classification

```kql
// TEST 1: Verifies correct classification of hosting vs residential ASNs
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473]);
let TestSigninLogs = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, ResultType: string,
    IPAddress: string, AutonomousSystemNumber: int, UserAgent: string,
    AppDisplayName: string, LocationDetails: dynamic
)[
    // DigitalOcean - hosting
    datetime(2026-02-22T14:00:00Z), "alice@contoso.com", "0", "198.51.100.50", 14061,
        "Mozilla/5.0", "Outlook", dynamic({"countryOrRegion":"NL","city":"Amsterdam"}),
    // AWS - hosting
    datetime(2026-02-22T14:01:00Z), "alice@contoso.com", "0", "203.0.113.10", 16509,
        "python-requests/2.28", "Microsoft Graph", dynamic({"countryOrRegion":"US","city":"Ashburn"}),
    // Comcast - residential (legitimate)
    datetime(2026-02-22T14:02:00Z), "alice@contoso.com", "0", "192.0.2.100", 7922,
        "Mozilla/5.0", "Outlook", dynamic({"countryOrRegion":"US","city":"Chicago"}),
    // AT&T - residential (legitimate)
    datetime(2026-02-22T14:03:00Z), "alice@contoso.com", "0", "192.0.2.200", 7018,
        "Mozilla/5.0", "Teams", dynamic({"countryOrRegion":"US","city":"Dallas"})
];
TestSigninLogs
| extend IsHostingProvider = AutonomousSystemNumber in (HostingASNs)
| summarize
    HostingCount = countif(IsHostingProvider),
    ResidentialCount = countif(not(IsHostingProvider))
| where HostingCount == 2 and ResidentialCount == 2
// EXPECTED: 1 row — 2 hosting (DigitalOcean, AWS), 2 residential (Comcast, AT&T)
```

### Test 2: First-Ever Hosting Sign-In Detection

```kql
// TEST 2: Verifies detection of first-ever hosting sign-in for a user
let HostingASNs = dynamic([14061, 16509, 15169]);
// Baseline: 30 days of residential-only sign-ins
let TestBaseline = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, ResultType: string,
    AutonomousSystemNumber: int, IPAddress: string, LocationDetails: dynamic
)[
    datetime(2026-01-23T09:00:00Z), "alice@contoso.com", "0", 7922, "192.0.2.100",
        dynamic({"countryOrRegion":"US"}),
    datetime(2026-01-25T09:00:00Z), "alice@contoso.com", "0", 7922, "192.0.2.100",
        dynamic({"countryOrRegion":"US"}),
    datetime(2026-02-10T09:00:00Z), "alice@contoso.com", "0", 7018, "192.0.2.200",
        dynamic({"countryOrRegion":"US"})
];
// Current: hosting sign-in appears
let TestCurrent = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, ResultType: string,
    AutonomousSystemNumber: int, IPAddress: string, LocationDetails: dynamic
)[
    datetime(2026-02-22T14:00:00Z), "alice@contoso.com", "0", 14061, "198.51.100.50",
        dynamic({"countryOrRegion":"NL"})
];
let BaselineHostingCount = toscalar(
    TestBaseline
    | where AutonomousSystemNumber in (HostingASNs)
    | count
);
let CurrentHostingCount = toscalar(
    TestCurrent
    | where AutonomousSystemNumber in (HostingASNs)
    | count
);
print
    BaselineHosting = BaselineHostingCount,
    CurrentHosting = CurrentHostingCount,
    Verdict = iff(BaselineHostingCount == 0 and CurrentHostingCount > 0,
        "HIGH ANOMALY - First-ever hosting sign-in", "Normal")
| where Verdict == "HIGH ANOMALY - First-ever hosting sign-in"
// EXPECTED: 1 row — baseline has 0 hosting sign-ins, current has 1 (DigitalOcean)
```

### Test 3: Post-Authentication Persistence Detection

```kql
// TEST 3: Verifies detection of persistence actions after hosting sign-in
let TestAuditLogs = datatable(
    TimeGenerated: datetime, OperationName: string, InitiatedBy: dynamic,
    TargetResources: dynamic, Result: string
)[
    // MFA registration after hosting sign-in
    datetime(2026-02-22T14:30:00Z), "Register security info",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Phone","modifiedProperties":[]}]), "success",
    // Inbox rule creation
    datetime(2026-02-22T14:45:00Z), "Set inbox rule",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Forward to external","modifiedProperties":[]}]), "success",
    // Normal admin operation (different user)
    datetime(2026-02-22T15:00:00Z), "Update user",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com","ipAddress":"10.0.0.1"}}),
        dynamic([{"displayName":"bob@contoso.com","modifiedProperties":[]}]), "success"
];
let InvestigationTarget = "alice@contoso.com";
TestAuditLogs
| where InitiatedBy has InvestigationTarget
| extend ActionCategory = case(
    OperationName has_any ("security info", "Register"), "MFA_PERSISTENCE",
    OperationName has_any ("inbox", "forwarding", "redirect"), "EMAIL_MANIPULATION",
    "OTHER"
)
| where ActionCategory != "OTHER"
| summarize ActionCount = count(), Actions = make_set(ActionCategory)
| where ActionCount == 2 and set_has_element(Actions, "MFA_PERSISTENCE")
    and set_has_element(Actions, "EMAIL_MANIPULATION")
// EXPECTED: 1 row — both MFA persistence and email manipulation detected for alice
```

### Test 4: Org-Wide Campaign Detection

```kql
// TEST 4: Verifies detection of multi-account hosting sign-in campaign
let HostingASNs = dynamic([14061, 16509, 15169]);
let TestSigninLogs = datatable(
    TimeGenerated: datetime, UserPrincipalName: string, ResultType: string,
    IPAddress: string, AutonomousSystemNumber: int,
    AppDisplayName: string, LocationDetails: dynamic
)[
    // Burst pattern from DigitalOcean - suspicious
    datetime(2026-02-22T14:00:00Z), "alice@contoso.com", "0", "198.51.100.50", 14061,
        "Outlook", dynamic({"countryOrRegion":"NL"}),
    datetime(2026-02-22T14:05:00Z), "bob@contoso.com", "0", "198.51.100.51", 14061,
        "Outlook", dynamic({"countryOrRegion":"NL"}),
    datetime(2026-02-22T14:10:00Z), "charlie@contoso.com", "0", "198.51.100.52", 14061,
        "Microsoft Graph", dynamic({"countryOrRegion":"NL"}),
    datetime(2026-02-22T14:15:00Z), "dave@contoso.com", "0", "198.51.100.50", 14061,
        "Outlook", dynamic({"countryOrRegion":"NL"}),
    // Legitimate developer on AWS - consistent pattern
    datetime(2026-02-22T09:00:00Z), "dev@contoso.com", "0", "203.0.113.10", 16509,
        "Azure Portal", dynamic({"countryOrRegion":"US"})
];
TestSigninLogs
| where AutonomousSystemNumber in (HostingASNs)
| where ResultType == "0"
| summarize
    TargetedAccounts = dcount(UserPrincipalName),
    AccountsList = make_set(UserPrincipalName, 100),
    DistinctIPs = dcount(IPAddress)
    by AutonomousSystemNumber
| where TargetedAccounts >= 3
// EXPECTED: 1 row — ASN 14061 (DigitalOcean) with 4 targeted accounts
```

---

## References

- [Entra ID Sign-in Logs - AutonomousSystemNumber field](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)
- [Conditional Access: Named Locations](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network)
- [Identity Protection risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [MITRE ATT&CK T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)
- [Midnight Blizzard attack methodology - Microsoft](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [Star Blizzard phishing from cloud infrastructure](https://www.microsoft.com/en-us/security/blog/2023/12/07/star-blizzard-increases-sophistication-and-evasion-in-ongoing-attacks/)
