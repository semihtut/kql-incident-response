---
title: "Anonymous IP Address Sign-In"
id: RB-0004
severity: medium
status: reviewed
description: >
  Investigation runbook for Microsoft Entra ID Identity Protection
  "Anonymous IP address" risk detection. Covers sign-ins from Tor exit nodes,
  anonymizing proxies, and VPN services. Includes IP classification (Tor vs
  commercial VPN vs cloud proxy), session analysis, and post-access blast
  radius assessment.
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
    - tactic_id: TA0008
      tactic_name: "Lateral Movement"
    - tactic_id: TA0009
      tactic_name: "Collection"
    - tactic_id: TA0011
      tactic_name: "Command and Control"
  techniques:
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1090.003
      technique_name: "Proxy: Multi-hop Proxy"
      confidence: confirmed
    - technique_id: T1090
      technique_name: "Proxy"
      confidence: confirmed
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: confirmed
    - technique_id: T1098.005
      technique_name: "Account Manipulation: Device Registration"
      confidence: confirmed
    - technique_id: T1114.003
      technique_name: "Email Collection: Email Forwarding Rule"
      confidence: confirmed
    - technique_id: T1528
      technique_name: "Steal Application Access Token"
      confidence: confirmed
    - technique_id: T1556.006
      technique_name: "Modify Authentication Process: MFA"
      confidence: confirmed
    - technique_id: T1564.008
      technique_name: "Hide Artifacts: Email Hiding Rules"
      confidence: confirmed
    - technique_id: T1534
      technique_name: "Internal Spearphishing"
      confidence: confirmed
    - technique_id: T1530
      technique_name: "Data from Cloud Storage Object"
      confidence: confirmed
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Sandworm (APT44)"
  - "Storm-1152"
  - "Scattered Spider (Octo Tempest)"
log_sources:
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
  - table: "OfficeActivity"
    product: "Office 365"
    license: "M365 E3+"
    required: true
    alternatives: []
  - table: "ThreatIntelligenceIndicator"
    product: "Microsoft Sentinel"
    license: "Sentinel + TI feeds"
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
  - query: "AADUserRiskEvents | take 1"
    label: primary
    description: "If empty, Entra ID P2 or the connector is missing"
  - query: "SigninLogs | take 1"
    description: "Must be present for sign-in analysis"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "Required for token usage check"
  - query: "OfficeActivity | take 1"
    description: "If empty, the Office 365 connector is not configured"
  - query: "ThreatIntelligenceIndicator | take 1"
    label: optional
    description: "Enhances IP classification"
---

# Anonymous IP Address Sign-In - Investigation Runbook

> **RB-0004** | Severity: Medium | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Identity Protection
>
> **Risk Detection Name:** `anonymizedIPAddress`
>
> **Primary MITRE Technique:** T1090.003 - Proxy: Multi-hop Proxy

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Extract Risk Event and Anonymous IP Sign-In](#step-1-extract-risk-event-and-anonymous-ip-sign-in)
   - [Step 2: Anonymous IP Classification](#step-2-anonymous-ip-classification)
   - [Step 3: Baseline Comparison - Establish Normal Sign-In Pattern](#step-3-baseline-comparison---establish-normal-sign-in-pattern)
   - [Step 4: Sign-In Session Analysis from Anonymous IP](#step-4-sign-in-session-analysis-from-anonymous-ip)
   - [Step 5: Non-Interactive Sign-In Check from Anonymous IP](#step-5-non-interactive-sign-in-check-from-anonymous-ip)
   - [Step 6: Analyze Post-Sign-In Activity (Blast Radius Assessment)](#step-6-analyze-post-sign-in-activity-blast-radius-assessment)
   - [Step 7: IP Reputation and Context](#step-7-ip-reputation-and-context)
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
The "Anonymous IP address" risk detection is generated by Entra ID Identity Protection when a user signs in from an IP address that has been identified as an anonymous proxy IP address. Microsoft Threat Intelligence maintains a continuously updated database of IP addresses associated with anonymization services, including Tor exit nodes, public anonymizing proxies, and known VPN services that provide anonymity. The `anonymizedIPAddress` risk event fires in **real-time** when the sign-in IP matches an entry in this database.

**Why it matters:**
Attackers routinely use anonymizing infrastructure to hide their true location and identity when accessing compromised cloud accounts. Tor, in particular, is favored by both nation-state actors (APT29/Midnight Blizzard, Sandworm) and cybercriminal groups because it provides strong source IP obfuscation. A sign-in from an anonymous IP combined with valid credentials is a strong signal that stolen credentials are being tested or exploited from infrastructure designed to evade geographic attribution.

**However:** This alert has a **very high false positive rate** (~70-80% in typical environments). Legitimate triggers include:
- Employees using commercial VPN services (NordVPN, ExpressVPN, Surfshark) for personal privacy
- Security researchers or journalists using Tor Browser for legitimate research
- Developers working from cloud-hosted VMs or cloud shells (AWS CloudShell, Azure Cloud Shell, GitHub Codespaces) whose IPs may appear in anonymization databases
- Employees traveling and using airport/hotel VPN services
- Mobile carriers whose NAT infrastructure shares IP space with known proxies
- Privacy-conscious employees using Mullvad VPN, iCloud Private Relay, or similar services

**Worst case scenario if this is real:**
An attacker has obtained the user's credentials (via phishing, credential stuffing, info-stealer malware, or dark web purchase) and is using Tor or an anonymizing proxy to hide their origin while accessing the account. The use of anonymizing infrastructure suggests sophistication - the attacker is deliberately evading geographic detection that would trigger impossible travel or unfamiliar location alerts. This is particularly dangerous because it indicates operational security awareness, suggesting a targeted rather than opportunistic attack.

**Key difference from RB-0001, RB-0002, and RB-0003:**
- RB-0001 (Unfamiliar Sign-In Properties): Detects sign-ins with unusual device/location combinations. The IP is visible but unfamiliar.
- RB-0002 (Impossible Travel): Detects two geographically incompatible sign-ins. Requires two IPs.
- RB-0003 (Leaked Credentials): Offline detection with NO associated IP - must hunt for evidence of usage.
- **RB-0004 (This runbook):** The sign-in has an IP, but the IP is intentionally anonymized. The unique challenge is **classifying the type of anonymization** (Tor, VPN, proxy) because this dramatically changes the risk assessment. A Tor exit node is far more suspicious than a NordVPN server. This runbook adds an **IP classification step** not present in other runbooks.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID P2 + Microsoft 365 E3 + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID, Office 365
- **Permissions:** Security Reader (investigation), Security Operator (containment)

### Recommended for Full Coverage
- **License:** Microsoft 365 E5 + Sentinel with TI feeds
- **Additional Connectors:** Threat Intelligence (TAXII/Platform)

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | SigninLogs, AuditLogs | Steps 3, 4 (partial) |
| Entra ID P2 + Sentinel | Above + AADUserRiskEvents, AADRiskyUsers, AADNonInteractiveUserSignInLogs | Steps 1-5, 7 (partial) |
| M365 E3 + Entra ID P2 + Sentinel | Above + OfficeActivity | Steps 1-7 (core investigation) |
| M365 E5 + Sentinel + TI | ALL tables | Steps 1-7 (full investigation) |

---

## 3. Input Parameters

All queries in this runbook use the following shared input parameters. Replace these values with the actual alert data before running. Unlike RB-0003 (no IP), this alert DOES have an associated IP address - the anonymous IP that triggered the detection.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Set these before running any query
// ============================================================
let TargetUser = "user@contoso.com";          // UserPrincipalName from the alert
let AlertTime = datetime(2026-02-22T14:30:00Z); // TimeGenerated of the risk event
let AnonIP = "185.220.101.42";               // The anonymous IP address from the risk event
```

---

## 4. Quick Triage Criteria

The goal of quick triage is to determine within 2-3 steps whether this alert is a legitimate VPN user or requires deep investigation. Given the ~70-80% false positive rate, efficient triage is critical.

### Quick Close Conditions (all must be true to close as FP):
1. The anonymous IP is classified as a **known commercial VPN** (NordVPN, ExpressVPN, Surfshark, etc.) - NOT Tor
2. The sign-in device matches the user's **known DeviceId** (same managed device)
3. The user has a **history of sign-ins from VPN IPs** in the 30-day baseline
4. **MFA was completed** successfully during the sign-in
5. There is **no suspicious post-sign-in activity** (no inbox rules, no app consents, no MFA changes)
6. There is **no other risk event** for this user in the past 7 days

### Quick Escalation Conditions (any one triggers deep investigation):
- The anonymous IP is classified as a **Tor exit node**
- The sign-in is from an **unmanaged/non-compliant device** that the user has never used
- The user has **never** signed in from anonymous IPs in the 30-day baseline
- MFA was **not required** or was **bypassed** during the sign-in
- **Multiple users** signed in from the same anonymous IP (coordinated attack)
- Post-sign-in activity detected within 60 minutes (directory changes, inbox rules, OAuth consents)
- The user holds **privileged roles** (Global Admin, Security Admin, Exchange Admin)

---

## 5. Investigation Steps

### Step 1: Extract Risk Event and Anonymous IP Sign-In

**Purpose:** Pull the anonymizedIPAddress risk event from AADUserRiskEvents and the corresponding sign-in from SigninLogs. Unlike RB-0003 (leakedCredentials) where the risk event has no IP, this detection includes the anonymous IP address and location. However, the location may be unreliable because anonymous IP geolocation is frequently inaccurate.

**Data needed from:**
- Table: AADUserRiskEvents - get the risk event details (RiskEventType == "anonymizedIPAddress", IpAddress, Location)
- Table: SigninLogs - get the full sign-in record with device, authentication, and session details

**What to extract:**
- User identity: UserPrincipalName, display name, object ID
- Risk event: RiskLevel, DetectionTimingType (realtime), anonymous IP, location
- Sign-in: DeviceDetail, AuthenticationRequirement, MFA status, ConditionalAccess
- Additional risk events for compound risk assessment

#### Query 1: Extract Anonymous IP Risk Event and Sign-In

```kql
// ============================================================
// Query 1: Extract Anonymous IP Risk Event and Sign-In
// Purpose: Pull the risk event and the corresponding sign-in
//          that triggered the anonymizedIPAddress detection
// Tables: AADUserRiskEvents, SigninLogs
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let AnonIP = "185.220.101.42";
let LookbackWindow = 4h;
// --- Part 1: Get the risk event ---
let RiskEvent = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + LookbackWindow))
    | where UserPrincipalName == TargetUser
    | where RiskEventType == "anonymizedIPAddress"
    | project
        RiskTimeGenerated = TimeGenerated,
        UserPrincipalName,
        RiskEventType,
        RiskLevel,
        RiskState,
        DetectionTimingType,
        RiskIpAddress = IpAddress,
        RiskLocation = Location,
        AdditionalInfo,
        CorrelationId,
        Id
    | top 1 by RiskTimeGenerated desc;
// --- Part 2: Get the corresponding sign-in ---
let SignIn = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1h))
    | where UserPrincipalName == TargetUser
    | where IPAddress == AnonIP
    | where ResultType == "0"
    | project
        SigninTime = TimeGenerated,
        UserPrincipalName,
        IPAddress,
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        State = tostring(LocationDetails.state),
        DeviceId = tostring(DeviceDetail.deviceId),
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceBrowser = tostring(DeviceDetail.browser),
        DeviceIsCompliant = tostring(DeviceDetail.isCompliant),
        DeviceIsManaged = tostring(DeviceDetail.isManaged),
        DeviceTrustType = tostring(DeviceDetail.trustType),
        UserAgent,
        AppDisplayName,
        ResourceDisplayName,
        ClientAppUsed,
        AuthenticationRequirement,
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA performed"),
        ConditionalAccessStatus,
        ResultType,
        CorrelationId,
        SessionId
    | top 1 by SigninTime desc;
// --- Part 3: Check for compound risk ---
let OtherRiskEvents = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - 7d) .. (AlertTime + 1d))
    | where UserPrincipalName == TargetUser
    | where RiskEventType != "anonymizedIPAddress"
    | summarize
        OtherRiskEventCount = count(),
        OtherRiskTypes = make_set(RiskEventType),
        OtherRiskLevels = make_set(RiskLevel);
// --- Part 4: Combined output ---
RiskEvent
| extend placeholder = 1
| join kind=leftouter (SignIn | extend placeholder = 1) on placeholder
| join kind=leftouter (OtherRiskEvents | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1, placeholder2
| extend
    CompoundRiskAssessment = case(
        OtherRiskEventCount > 0 and OtherRiskTypes has "leakedCredentials",
            "CRITICAL - Anonymous IP + leaked credentials (compromised account using proxy)",
        OtherRiskEventCount > 0 and OtherRiskTypes has "impossibleTravel",
            "CRITICAL - Anonymous IP + impossible travel (multi-location compromise)",
        OtherRiskEventCount > 0 and OtherRiskTypes has "unfamiliarFeatures",
            "HIGH - Anonymous IP + unfamiliar sign-in properties",
        OtherRiskEventCount > 0,
            strcat("ELEVATED - Anonymous IP + ", tostring(OtherRiskEventCount), " other risk events"),
        "SINGLE RISK - Only anonymizedIPAddress detected"
    ),
    DeviceAssessment = case(
        DeviceIsManaged == "true" and DeviceIsCompliant == "true",
            "MANAGED - Known corporate device (lower risk)",
        isnotempty(DeviceId) and DeviceIsManaged == "false",
            "UNMANAGED - Device registered but not managed",
        isempty(DeviceId),
            "UNKNOWN - No device ID (higher risk)",
        "REVIEW"
    )
```

<details>
<summary>Expected Output Columns</summary>

| Column | Type | Description |
|---|---|---|
| RiskTimeGenerated | datetime | When the anonymous IP detection fired |
| UserPrincipalName | string | Affected user |
| RiskEventType | string | "anonymizedIPAddress" |
| RiskLevel | string | Risk level assigned |
| RiskIpAddress | string | The anonymous IP address |
| SigninTime | datetime | Timestamp of the actual sign-in |
| IPAddress | string | Same anonymous IP from SigninLogs |
| City | string | Reported city (may be unreliable for anonymous IPs) |
| Country | string | Reported country (may be unreliable) |
| DeviceId | string | Device identifier (empty = unknown device) |
| DeviceOS | string | Operating system |
| DeviceBrowser | string | Browser used |
| DeviceIsManaged | string | Managed device status |
| AuthenticationRequirement | string | SFA or MFA |
| MfaAuthMethod | string | MFA method or "No MFA performed" |
| ConditionalAccessStatus | string | CA policy result |
| CompoundRiskAssessment | string | Assessment of combined risk events |
| DeviceAssessment | string | Device risk classification |

</details>

**Performance Notes:**
- Query scans a 4h window around the alert time - very fast
- The compound risk check scans 7 days of risk events for the user
- Expected result: 1 row with risk event, sign-in details, and compound risk assessment
- If sign-in row is empty (no match for AnonIP), try expanding LookbackWindow or check failed sign-ins

**Tuning Guidance:**
- **LookbackWindow**: Default 4h. Increase to 12h if the risk event and sign-in have significant time lag
- **AnonIP filter**: If the risk event IP doesn't match any successful sign-in, the sign-in may have failed. Remove `ResultType == "0"` to check for failed attempts

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Device | Unknown/unmanaged device | Known managed/compliant device |
| MFA | No MFA or SFA only | MFA completed successfully |
| Compound risk | Other risk events present | Single anonymizedIPAddress event |
| CA status | Not applied or bypassed | Successfully applied |
| Browser | Unusual (Tor Browser, Python, curl) | Standard browser (Chrome, Edge, Safari) |

**Next action:**
- If compound risk is CRITICAL -> proceed directly to Containment, complete investigation afterward
- If managed device + MFA + no compound risk -> likely BTP, verify with Steps 2-3 before closing
- Otherwise -> proceed to Step 2 for IP classification

---

### Step 2: Anonymous IP Classification

**Purpose:** Determine what TYPE of anonymization service the IP belongs to. This is the most critical triage step because it dramatically changes the risk assessment. A Tor exit node is far more suspicious than a NordVPN server. This step is unique to RB-0004 and does not appear in other runbooks.

**Classification categories:**
1. **Tor Exit Node** - Highest risk. Used by APT groups and sophisticated attackers
2. **Known Anonymizing Proxy** - High risk. Public proxy services used for anonymization
3. **Commercial VPN** - Medium risk. NordVPN, ExpressVPN, Surfshark, etc. Common among privacy-conscious users
4. **Cloud Provider IP** - Medium risk. AWS, Azure, GCP IPs that may appear in anonymization databases
5. **Privacy Service** - Lower risk. iCloud Private Relay, Mullvad, etc.

**Data needed from:**
- Table: SigninLogs - UserAgent analysis for Tor Browser fingerprinting
- Table: ThreatIntelligenceIndicator - check if IP is in TI feeds as Tor/proxy

#### Query 2: Anonymous IP Classification

```kql
// ============================================================
// Query 2: Anonymous IP Classification
// Purpose: Determine if the IP is Tor, commercial VPN, cloud
//          proxy, or other anonymization service
// Tables: SigninLogs, ThreatIntelligenceIndicator
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let AnonIP = "185.220.101.42";
let LookbackWindow = 4h;
// --- Part 1: Get the sign-in details for UA analysis ---
let SignInDetails = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1h))
    | where UserPrincipalName == TargetUser
    | where IPAddress == AnonIP
    | where ResultType == "0"
    | top 1 by TimeGenerated desc
    | project
        IPAddress,
        UserAgent,
        DeviceBrowser = tostring(DeviceDetail.browser),
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        ClientAppUsed,
        AppDisplayName,
        AutonomousSystemNumber = tostring(AutonomousSystemNumber);
// --- Part 2: TI lookup for the anonymous IP ---
let TiMatch = ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP)
    | where Active == true
    | where ExpirationDateTime > now()
    | where NetworkIP == AnonIP
    | project
        ThreatType,
        ConfidenceScore,
        Description,
        Tags,
        SourceSystem
    | top 1 by ConfidenceScore desc;
// --- Part 3: Check how many org users use this IP ---
let OrgUsage = SigninLogs
    | where TimeGenerated > ago(30d)
    | where IPAddress == AnonIP
    | where ResultType == "0"
    | summarize
        OrgUsersFromIP = dcount(UserPrincipalName),
        OrgUserList = make_set(UserPrincipalName, 10),
        TotalSigninsFromIP = count();
// --- Part 4: Classification ---
SignInDetails
| extend placeholder = 1
| join kind=leftouter (TiMatch | extend placeholder = 1) on placeholder
| join kind=leftouter (OrgUsage | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1, placeholder2
| extend
    // Tor Browser detection via UserAgent
    IsTorBrowser = iff(
        UserAgent has "Tor" or UserAgent has "tbb"
        or (DeviceBrowser has "Firefox" and UserAgent has "Windows NT" and UserAgent !has "Gecko/20100101"),
        true, false
    ),
    // Classification logic
    IPClassification = case(
        // Tor detection
        UserAgent has "Tor" or UserAgent has "tbb",
            "TOR EXIT NODE - Highest risk",
        ThreatType has "tor" or Description has "Tor" or Tags has "tor",
            "TOR EXIT NODE - Identified via threat intelligence",
        // Known anonymizing proxy patterns
        ThreatType has "proxy" or ThreatType has "anonymizer",
            "ANONYMIZING PROXY - High risk",
        // Cloud provider IPs
        AutonomousSystemNumber in ("16509", "14618", "8075", "15169", "396982"),
            "CLOUD PROVIDER - AWS/Azure/GCP (medium risk)",
        // High org usage = likely corporate VPN
        OrgUsersFromIP > 5,
            "LIKELY CORPORATE VPN - Used by multiple org users (lower risk)",
        OrgUsersFromIP > 1,
            "POSSIBLY SHARED VPN - Used by a few org users",
        // Default
        isnotempty(ThreatType),
            strcat("TI FLAGGED - ", ThreatType),
        "UNKNOWN ANONYMIZER - Requires manual classification"
    ),
    RiskLevel = case(
        UserAgent has "Tor" or ThreatType has "tor",
            "CRITICAL",
        ThreatType has "proxy" or ThreatType has "anonymizer",
            "HIGH",
        OrgUsersFromIP > 5,
            "LOW",
        OrgUsersFromIP > 1,
            "MEDIUM",
        "HIGH"
    )
```

**Performance Notes:**
- ThreatIntelligenceIndicator lookup is very fast (small table)
- The org usage check scans 30 days of SigninLogs for a single IP - fast
- Tor Browser detection via UserAgent is heuristic-based - Tor Browser typically shows as Firefox on Windows with specific version patterns
- ASN numbers: 16509/14618 = AWS, 8075 = Microsoft/Azure, 15169/396982 = Google

**Tuning Guidance:**
- **Tor detection**: The UserAgent check is not 100% reliable. Tor Browser can be configured to mimic standard Firefox. Combine with TI data for higher confidence
- **ASN check**: The AutonomousSystemNumber field may not be populated in all environments. If empty, skip the cloud provider classification
- **Org usage threshold**: Default >5 users = likely corporate. Adjust based on organization size

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| IP type | Tor exit node or anonymizing proxy | Commercial VPN or corporate proxy |
| TI match | IP in threat intelligence feeds | Not in TI feeds |
| Tor Browser | UserAgent matches Tor Browser pattern | Standard browser (Chrome, Edge) |
| Org usage | IP never used by other org users | Multiple org users use same IP |
| ASN | Unknown or residential ASN | Known VPN provider or cloud provider ASN |

**Next action:**
- If TOR EXIT NODE -> escalate severity, proceed with full investigation
- If COMMERCIAL VPN + managed device + MFA -> likely BTP, verify with Step 3
- If UNKNOWN -> proceed to Step 3 for baseline comparison

---

### Step 3: Baseline Comparison - Establish Normal Sign-In Pattern

**Purpose:** Determine if the user has a history of signing in from anonymous IPs or VPN services. This is the **MANDATORY** baseline step required by all runbooks. A user who regularly uses VPNs is far less suspicious than one who has never used anonymous infrastructure.

**Data needed from:**
- Table: SigninLogs - 30-day historical sign-in patterns

#### Query 3: 30-Day Sign-In Baseline

```kql
// ============================================================
// Query 3: 30-Day Sign-In Baseline
// Purpose: MANDATORY - Establish normal sign-in pattern to
//          determine if anonymous IP usage is anomalous
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let BaselinePeriod = 30d;
let AnonIP = "185.220.101.42";
SigninLogs
| where TimeGenerated between ((AlertTime - BaselinePeriod) .. AlertTime)
| where UserPrincipalName == TargetUser
| where ResultType == "0"
| summarize
    // Volume metrics
    TotalSignins = count(),
    DistinctIPs = dcount(IPAddress),
    DistinctCities = dcount(tostring(LocationDetails.city)),
    DistinctCountries = dcount(tostring(LocationDetails.countryOrRegion)),
    // Location patterns
    KnownIPs = make_set(IPAddress, 50),
    KnownCities = make_set(tostring(LocationDetails.city), 20),
    KnownCountries = make_set(tostring(LocationDetails.countryOrRegion)),
    // Device patterns
    KnownDeviceIds = make_set(tostring(DeviceDetail.deviceId), 10),
    KnownBrowsers = make_set(tostring(DeviceDetail.browser), 10),
    KnownOSes = make_set(tostring(DeviceDetail.operatingSystem), 10),
    // App patterns
    KnownApps = make_set(AppDisplayName, 20),
    // Auth patterns
    MFACount = countif(AuthenticationRequirement == "multiFactorAuthentication"),
    SFACount = countif(AuthenticationRequirement == "singleFactorAuthentication"),
    // Time patterns
    BusinessHourSignins = countif(hourofday(TimeGenerated) between (8 .. 18)),
    OffHourSignins = countif(hourofday(TimeGenerated) !between (8 .. 18)),
    WeekdaySignins = countif(dayofweek(TimeGenerated) between (1d .. 5d)),
    WeekendSignins = countif(dayofweek(TimeGenerated) in (0d, 6d)),
    // Anonymous IP history
    AnonIPSignins = countif(IPAddress == AnonIP),
    EarliestSignin = min(TimeGenerated),
    LatestSignin = max(TimeGenerated)
| extend
    // Check if anonymous IP is in baseline
    AnonIPInBaseline = iff(AnonIPSignins > 0, "YES - User has used this IP before", "NO - First time from this IP"),
    // MFA coverage
    MFACoverage = round(100.0 * MFACount / TotalSignins, 1),
    // Work pattern
    PrimaryWorkPattern = iff(BusinessHourSignins > OffHourSignins, "Business hours", "Off-hours"),
    // Overall baseline assessment
    BaselineAssessment = case(
        AnonIPSignins > 5,
            "REGULAR USER - Frequently uses this anonymous IP (likely personal VPN)",
        AnonIPSignins > 0,
            "OCCASIONAL USER - Has used this anonymous IP before",
        DistinctIPs > 20,
            "MOBILE/VPN USER - Uses many IPs, anonymous IP less anomalous",
        DistinctIPs <= 3,
            "STATIC USER - Very few IPs, anonymous IP is highly anomalous",
        "MODERATE - Some IP diversity, anonymous IP is moderately anomalous"
    )
```

**Performance Notes:**
- Query scans 30 days of SigninLogs for a single user - moderate volume
- The `make_set` aggregations create a comprehensive profile of the user's normal behavior
- Expected result: 1 row with full 30-day baseline profile

**Tuning Guidance:**
- **BaselinePeriod**: Default 30d. For new employees with <30 days of sign-in history, this query may show limited data. Flag as "insufficient baseline"
- **Business hours**: Default 8-18. Adjust for the user's timezone and work schedule
- **IP diversity threshold**: DistinctIPs > 20 suggests a mobile/VPN user. Adjust based on org patterns

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Anonymous IP history | First time ever from this IP (AnonIPSignins = 0) | User regularly uses this IP |
| IP diversity | User normally uses 1-3 IPs (static) | User uses 10+ IPs (mobile/VPN) |
| Work hours | Sign-in occurred outside normal hours | Sign-in during normal work pattern |
| MFA coverage | MFA rarely enforced | MFA always enforced |
| Device | Sign-in from unknown device vs baseline | Same device as baseline |

**Next action:**
- If REGULAR USER with managed device + MFA -> close as BTP
- If STATIC USER + first time anonymous IP -> proceed to Step 4
- Otherwise -> proceed to Step 4 for session analysis

---

### Step 4: Sign-In Session Analysis from Anonymous IP

**Purpose:** Analyze what happened during the sign-in session from the anonymous IP. Check which applications were accessed, how many sign-in events occurred, and whether the session shows signs of automated activity or manual browsing.

**Data needed from:**
- Table: SigninLogs - all sign-in events from the anonymous IP for this user

#### Query 4: Sign-In Session Analysis

```kql
// ============================================================
// Query 4: Sign-In Session Analysis from Anonymous IP
// Purpose: Analyze all sign-in activity from the anonymous IP
//          for this user - check apps, frequency, and patterns
// Table: SigninLogs
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let AnonIP = "185.220.101.42";
let SessionWindow = 4h;
// Get all sign-ins from the anonymous IP
SigninLogs
| where TimeGenerated between ((AlertTime - SessionWindow) .. (AlertTime + SessionWindow))
| where UserPrincipalName == TargetUser
| where IPAddress == AnonIP
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    ResourceDisplayName,
    ClientAppUsed,
    AuthenticationRequirement,
    MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA performed"),
    ConditionalAccessStatus,
    ResultType,
    ResultDescription = case(
        ResultType == "0", "Success",
        ResultType == "50126", "Invalid password",
        ResultType == "50074", "MFA required",
        ResultType == "50076", "MFA not completed",
        ResultType == "53003", "Blocked by CA",
        ResultType == "530032", "Blocked - Security defaults",
        strcat("Error: ", ResultType)
    ),
    DeviceId = tostring(DeviceDetail.deviceId),
    DeviceBrowser = tostring(DeviceDetail.browser),
    UserAgent,
    SessionId,
    CorrelationId
| order by TimeGenerated asc
| extend
    SessionAssessment = case(
        ResultType != "0", strcat("BLOCKED - ", ResultDescription),
        AuthenticationRequirement == "singleFactorAuthentication",
            "WARNING - Signed in without MFA",
        ConditionalAccessStatus == "notApplied",
            "WARNING - No Conditional Access policy applied",
        "OK - Sign-in with expected controls"
    )
```

**Performance Notes:**
- Narrow window (4h) with user + IP filter - very fast
- Shows both successful AND failed sign-ins from the anonymous IP
- Failed sign-ins (ResultType != "0") are important - they may indicate credential testing before a successful sign-in

**Tuning Guidance:**
- **SessionWindow**: Default 4h. Expand to 24h for thorough investigation
- **Failed sign-ins**: Multiple failed attempts followed by success is a classic credential testing pattern
- **Multiple apps**: Accessing many different apps in rapid succession suggests automated enumeration

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Failed attempts | Multiple failures before success | No failed attempts |
| Apps accessed | Multiple sensitive apps in rapid succession | Single app (e.g., Outlook, Teams) |
| MFA | Not required or bypassed | MFA completed |
| Session duration | Very short session (quick data grab) | Normal session duration |
| Client app | Unusual client (Python, curl, PowerShell) | Standard browser or mobile app |

**Next action:**
- If credential testing pattern detected -> escalate, proceed to Step 5
- If blocked by CA/MFA -> lower risk, document and check Step 5
- If normal single-app session with MFA -> likely BTP, verify with Steps 5-6

---

### Step 5: Non-Interactive Sign-In Check from Anonymous IP

**Purpose:** Check for non-interactive sign-ins from the anonymous IP. These indicate token-based access and are particularly important because they show the anonymous IP is being used for ongoing resource access, not just initial authentication.

**Data needed from:**
- Table: AADNonInteractiveUserSignInLogs - non-interactive sign-in events from the anonymous IP

#### Query 5: Non-Interactive Sign-Ins from Anonymous IP

```kql
// ============================================================
// Query 5: Non-Interactive Sign-Ins from Anonymous IP
// Purpose: Check for token-based access from the anonymous IP
//          indicating ongoing session usage
// Table: AADNonInteractiveUserSignInLogs
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let AnonIP = "185.220.101.42";
let TokenWindow = 8h;
AADNonInteractiveUserSignInLogs
| where TimeGenerated between ((AlertTime - 1h) .. (AlertTime + TokenWindow))
| where UserPrincipalName == TargetUser
| where IPAddress == AnonIP
| summarize
    TotalNonInteractiveEvents = count(),
    SuccessfulEvents = countif(ResultType == "0"),
    FailedEvents = countif(ResultType != "0"),
    DistinctApps = make_set(AppDisplayName, 20),
    DistinctResources = make_set(ResourceDisplayName, 20),
    EarliestEvent = min(TimeGenerated),
    LatestEvent = max(TimeGenerated),
    SessionDurationMinutes = datetime_diff("minute", max(TimeGenerated), min(TimeGenerated))
| extend
    TokenUsageAssessment = case(
        SuccessfulEvents > 20,
            "HIGH VOLUME - Extensive token usage from anonymous IP (automated access likely)",
        SuccessfulEvents > 5,
            "MODERATE - Multiple token refreshes from anonymous IP",
        SuccessfulEvents > 0,
            "LOW VOLUME - Some token usage from anonymous IP",
        TotalNonInteractiveEvents > 0 and FailedEvents > 0,
            "ATTEMPTED - Token refresh attempted but failed from anonymous IP",
        "NO EVIDENCE - No non-interactive activity from anonymous IP"
    ),
    SensitiveAppAccess = iff(
        DistinctApps has_any ("Microsoft Graph", "Exchange Online", "SharePoint Online", "Azure Portal", "Azure Resource Manager"),
        "YES - Sensitive apps accessed via token",
        "No sensitive app access detected"
    )
```

**Performance Notes:**
- AADNonInteractiveUserSignInLogs can be high volume. The IP + user filter narrows efficiently
- Token window is 8h (longer than sign-in window) because tokens persist after initial auth
- Expected result: 1 summary row with token usage assessment

**Tuning Guidance:**
- **TokenWindow**: Default 8h. Expand to 24h for long-running sessions
- **Volume thresholds**: >20 events suggests automated access. Adjust based on normal app usage patterns
- **Sensitive apps**: Customize the list based on which apps are most critical in your environment

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Token usage | High-volume automated access from anonymous IP | No or minimal non-interactive events |
| Apps accessed | Sensitive apps (Graph, Exchange, SharePoint) | Standard apps only |
| Session duration | Extended session (hours) | Brief session |
| Failed tokens | Token refresh failures (stolen token expired) | No failures |

**Next action:**
- If HIGH VOLUME automated access -> CONFIRMED malicious activity, proceed to Containment
- If ATTEMPTED but failed -> attacker tried but token expired, check Step 6
- If no evidence -> proceed to Step 6

---

### Step 6: Analyze Post-Sign-In Activity (Blast Radius Assessment)

**Purpose:** Determine what the account did AFTER signing in from the anonymous IP. Check for persistence mechanisms, data access, and lateral movement indicators. This step reuses the same patterns as RB-0001 Step 5 and RB-0002 Step 6.

**Data needed from:**
- Table: AuditLogs - directory changes made by this user after the alert
- Table: OfficeActivity - email, SharePoint, OneDrive activity after the alert

#### Query 6A: Directory Changes After Anonymous Sign-In

```kql
// ============================================================
// Query 6A: Directory Changes After Anonymous Sign-In
// Purpose: Check for persistence mechanisms created via
//          directory operations after the anonymous IP sign-in
// Table: AuditLogs
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let PostSignInWindow = 4h;
AuditLogs
| where TimeGenerated between (AlertTime .. (AlertTime + PostSignInWindow))
| where OperationName in (
    "User registered security info",
    "User deleted security info",
    "Admin registered security info",
    "Register security info",
    "Update StsRefreshTokenValidFrom",
    "Consent to application",
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Add owner to application",
    "Add app role assignment grant to user",
    "Update user",
    "Reset password (by admin)",
    "Reset user password",
    "Change user password",
    "Register device",
    "Add registered owner to device",
    "Add member to role",
    "Add eligible member to role"
)
| mv-expand TargetResource = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) == TargetUser
    or tostring(TargetResource.userPrincipalName) == TargetUser
| extend
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    TargetUPN = tostring(TargetResource.userPrincipalName),
    TargetDisplayName = tostring(TargetResource.displayName),
    ModifiedProperties = TargetResource.modifiedProperties
| project
    TimeGenerated,
    OperationName,
    Category,
    InitiatedByUser,
    InitiatedByApp,
    TargetUPN,
    TargetDisplayName,
    ModifiedProperties,
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, AlertTime),
    Severity = case(
        OperationName has "security info", "CRITICAL - MFA MANIPULATION",
        OperationName has "Consent to application", "CRITICAL - OAUTH APP CONSENT",
        OperationName has "delegated permission", "CRITICAL - API PERMISSION GRANT",
        OperationName has "owner to application", "CRITICAL - APP OWNERSHIP CHANGE",
        OperationName has "member to role", "CRITICAL - ROLE ESCALATION",
        OperationName has "password", "HIGH - PASSWORD CHANGE",
        OperationName has "Register device", "HIGH - DEVICE REGISTRATION",
        OperationName has "Update user", "MEDIUM - USER MODIFICATION",
        "INFO"
    ),
    CorrelationId
| order by TimeGenerated asc
```

#### Query 6B: Email and File Activity After Anonymous Sign-In

```kql
// ============================================================
// Query 6B: Email and File Activity After Anonymous Sign-In
// Purpose: Check for inbox rule creation, email forwarding,
//          bulk email access, and file exfiltration patterns
// Table: OfficeActivity
// Expected runtime: 5-10 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let PostSignInWindow = 4h;
OfficeActivity
| where TimeGenerated between (AlertTime .. (AlertTime + PostSignInWindow))
| where UserId == TargetUser
| extend CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
| project
    TimeGenerated,
    Operation,
    OfficeWorkload,
    UserId,
    CleanClientIP,
    RawClientIP = ClientIP,
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, AlertTime),
    RiskCategory = case(
        Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule"),
            "CRITICAL - INBOX RULE",
        Operation in ("Set-Mailbox", "Set-TransportRule") and OfficeWorkload == "Exchange",
            "CRITICAL - MAILBOX FORWARDING",
        Operation in ("Add-MailboxPermission", "Add-RecipientPermission"),
            "HIGH - DELEGATE ACCESS",
        Operation == "MailItemsAccessed",
            "MONITOR - EMAIL ACCESS",
        Operation == "Send",
            "MONITOR - EMAIL SENT",
        Operation in ("FileDownloaded", "FileSyncDownloadedFull"),
            "MONITOR - FILE DOWNLOAD",
        Operation in ("FileAccessed", "FileAccessedExtended"),
            "INFO - FILE ACCESS",
        "INFO"
    ),
    Parameters
| order by TimeGenerated asc
```

#### Query 6C: Inbox Rule Deep Dive

```kql
// ============================================================
// Query 6C: Inbox Rule Deep Dive
// Purpose: Extract inbox rule creation details - the #1
//          persistence mechanism in BEC attacks
// Table: OfficeActivity
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let PostSignInWindow = 4h;
OfficeActivity
| where TimeGenerated between (AlertTime .. (AlertTime + PostSignInWindow))
| where UserId == TargetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| mv-expand Parameter = parse_json(Parameters)
| summarize
    RuleParameters = make_bag(pack(tostring(Parameter.Name), tostring(Parameter.Value)))
    by TimeGenerated, Operation, UserId, ClientIP
| extend
    RuleName = tostring(RuleParameters.Name),
    ForwardTo = tostring(RuleParameters.ForwardTo),
    ForwardAsAttachmentTo = tostring(RuleParameters.ForwardAsAttachmentTo),
    RedirectTo = tostring(RuleParameters.RedirectTo),
    DeleteMessage = tostring(RuleParameters.DeleteMessage),
    MarkAsRead = tostring(RuleParameters.MarkAsRead),
    MoveToFolder = tostring(RuleParameters.MoveToFolder),
    SubjectContainsWords = tostring(RuleParameters.SubjectContainsWords),
    FromAddressContainsWords = tostring(RuleParameters.FromAddressContainsWords)
| extend
    IsMalicious = iff(
        isnotempty(ForwardTo) or isnotempty(ForwardAsAttachmentTo) or isnotempty(RedirectTo)
        or DeleteMessage == "True" or MarkAsRead == "True"
        or SubjectContainsWords has_any ("invoice", "payment", "wire", "transfer", "urgent", "password", "security"),
        "LIKELY MALICIOUS",
        "REVIEW REQUIRED"
    )
| project
    TimeGenerated,
    Operation,
    UserId,
    RuleName,
    ForwardTo,
    ForwardAsAttachmentTo,
    RedirectTo,
    DeleteMessage,
    MarkAsRead,
    MoveToFolder,
    SubjectContainsWords,
    FromAddressContainsWords,
    IsMalicious,
    CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
```

**Performance Notes:**
- All queries in this step scan narrow windows (4 hours) with specific user filters - very fast
- OfficeActivity has up to 60 min ingestion latency. If the alert is <1 hour old, results may be incomplete
- IP normalization is needed for OfficeActivity.ClientIP which may include port numbers and IPv6-mapped formats
- Match CleanClientIP against AnonIP to determine if post-sign-in activity came from the anonymous IP

**Tuning Guidance:**
- **PostSignInWindow**: Default 4h. For fast triage use 2h, for thorough investigation expand to 24h
- **IP correlation**: If CleanClientIP matches AnonIP, the post-sign-in activity is definitively from the anonymous session

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Inbox rules | New rule forwarding/deleting email | No new inbox rules |
| MFA changes | New MFA method registered after alert | No MFA changes |
| OAuth apps | New app consent with broad permissions | No new app consents |
| File access | Bulk downloads from anonymous IP | Normal file access patterns |
| Email | Mass email access or sends | No unusual email activity |

**Next action:**
- If ANY persistence found from anonymous IP -> CONFIRMED COMPROMISE, proceed to Containment
- If bulk data access from anonymous IP -> CONFIRMED COMPROMISE with data exposure
- If no suspicious activity -> proceed to Step 7 for IP reputation

---

### Step 7: IP Reputation and Context

**Purpose:** Gather intelligence about the anonymous IP address. Check threat intelligence feeds and determine if the same IP has been used against other accounts in the organization.

#### Query 7A: Threat Intelligence Lookup

```kql
// ============================================================
// Query 7A: Threat Intelligence Lookup
// Purpose: Check the anonymous IP against configured threat
//          intelligence feeds
// Table: ThreatIntelligenceIndicator
// Expected runtime: <3 seconds
// ============================================================
let AnonIP = "185.220.101.42";
ThreatIntelligenceIndicator
| where isnotempty(NetworkIP)
| where Active == true
| where ExpirationDateTime > now()
| where NetworkIP == AnonIP
| where ConfidenceScore >= 50
| project
    NetworkIP,
    ThreatType,
    ConfidenceScore,
    Description,
    Tags,
    ThreatSeverity,
    SourceSystem,
    ExpirationDateTime,
    LastUpdated = TimeGenerated,
    TIAssessment = case(
        ConfidenceScore >= 80 and (ThreatType has "tor" or Tags has "tor"),
            "CRITICAL - Confirmed Tor exit node in TI feeds",
        ConfidenceScore >= 80,
            "HIGH CONFIDENCE - Known malicious/anonymous IP",
        ConfidenceScore >= 50,
            "MEDIUM CONFIDENCE - Potentially malicious IP",
        "LOW CONFIDENCE - Weak indicator"
    )
| order by ConfidenceScore desc
```

#### Query 7B: Organizational IP Usage Check

```kql
// ============================================================
// Query 7B: Organizational IP Usage Check
// Purpose: Determine if the anonymous IP has been used by other
//          users in the organization - multi-user usage from
//          same anonymous IP indicates either shared VPN or
//          coordinated attack
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let AnonIP = "185.220.101.42";
let TargetUser = "user@contoso.com";
let LookbackPeriod = 30d;
SigninLogs
| where TimeGenerated > ago(LookbackPeriod)
| where IPAddress == AnonIP
| summarize
    TotalSignins = count(),
    SuccessfulSignins = countif(ResultType == "0"),
    FailedSignins = countif(ResultType != "0"),
    DistinctUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 20),
    DistinctApps = make_set(AppDisplayName, 10),
    EarliestSeen = min(TimeGenerated),
    LatestSeen = max(TimeGenerated)
| extend
    IPClassification = case(
        DistinctUsers > 10,
            "LIKELY CORPORATE VPN - Used by 10+ users (shared exit IP)",
        DistinctUsers > 3,
            "POSSIBLY SHARED VPN - Used by multiple users",
        DistinctUsers == 1 and UserList has TargetUser,
            "SINGLE USER - Only used by the target user (higher risk)",
        DistinctUsers == 1 and not(UserList has TargetUser),
            "SINGLE OTHER USER - Used by a different user only",
        DistinctUsers == 0,
            "NEVER SEEN - IP has never been used for sign-ins",
        "UNKNOWN"
    ),
    AttackIndicator = case(
        FailedSignins > 10 and DistinctUsers > 3,
            "CREDENTIAL SPRAY - Multiple failed attempts across users from this IP",
        FailedSignins > 5 and DistinctUsers == 1,
            "CREDENTIAL TESTING - Multiple failed attempts for single user",
        "NO ATTACK PATTERN"
    ),
    IsTargetUserIncluded = iff(UserList has TargetUser, "Yes", "No")
```

**Performance Notes:**
- Query 7A: ThreatIntelligenceIndicator is typically a small table - very fast
- Query 7B: 30-day scan filtered by single IP - fast
- The multi-user analysis from the same anonymous IP is critical for identifying coordinated attacks

**Tuning Guidance:**
- **TI ConfidenceScore**: Default >= 50. Increase to >= 80 for high precision
- **Attack pattern**: Failed sign-ins from the same anonymous IP across multiple users indicates password spray through anonymizing infrastructure

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| TI match | IP flagged as Tor/proxy in TI feeds | Not in TI feeds |
| Org usage | Single user or credential spray pattern | Multiple org users (shared VPN) |
| Failed sign-ins | High failure rate from this IP | No failed sign-ins |
| Time range | First time seen in organization | Seen regularly over weeks |

---

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to determine whether the anonymous IP sign-in represents genuinely anomalous behavior or fits within the user's established behavioral patterns. UEBA's ML-based anomaly scoring provides context that raw logs cannot — particularly whether this ISP/country combination is new for the user and their peer group.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 3. UEBA needs approximately **one week** after activation before generating meaningful insights.

#### Query 8A: User Behavioral Anomaly Assessment

```kql
// ============================================================
// Query 8A: UEBA Behavioral Anomaly Assessment
// Purpose: Check if UEBA has flagged anomalous ISP/country/device
//          usage for this user around the alert time
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T14:30:00Z);
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
    // ISP analysis — critical for anonymous IP investigation
    FirstTimeISP = tobool(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommonForUser = tobool(ActivityInsights.ISPUncommonlyUsedByUser),
    ISPUncommonAmongPeers = tobool(ActivityInsights.ISPUncommonlyUsedAmongPeers),
    ISPUncommonInTenant = tobool(ActivityInsights.ISPUncommonlyUsedInTenant),
    // Country analysis
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommonForUser = tobool(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    CountryUncommonAmongPeers = tobool(ActivityInsights.CountryUncommonlyConnectedFromAmongPeers),
    // Device/Browser analysis
    FirstTimeDevice = tobool(ActivityInsights.FirstTimeUserConnectedFromDevice),
    FirstTimeBrowser = tobool(ActivityInsights.FirstTimeUserConnectedViaBrowser),
    // User context
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    IsNewAccount = tobool(UsersInsights.IsNewAccount),
    // Threat intel from IP
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| order by InvestigationPriority desc, TimeGenerated desc
```

#### Query 8B: Peer Group ISP Comparison

```kql
// ============================================================
// Query 8B: Peer Group ISP and Country Usage
// Purpose: Compare user's ISP/country patterns against their
//          organizational peer group to determine if the
//          anonymous IP usage is normal for similar roles
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <10 seconds
// ============================================================
let AlertTime = datetime(2026-02-22T14:30:00Z);
let TargetUser = "user@contoso.com";
let LookbackWindow = 30d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. AlertTime)
| where UserPrincipalName =~ TargetUser
| where ActivityType == "LogOn"
| summarize
    TotalActivities = count(),
    HighAnomalyCount = countif(InvestigationPriority >= 7),
    MediumAnomalyCount = countif(InvestigationPriority >= 4 and InvestigationPriority < 7),
    MaxPriority = max(InvestigationPriority),
    AvgPriority = avg(InvestigationPriority),
    FirstTimeISPCount = countif(tobool(ActivityInsights.FirstTimeUserConnectedViaISP)),
    FirstTimeCountryCount = countif(tobool(ActivityInsights.FirstTimeUserConnectedFromCountry)),
    UncommonISPAmongPeersCount = countif(tobool(ActivityInsights.ISPUncommonlyUsedAmongPeers)),
    UniqueIPs = dcount(SourceIPAddress),
    UniqueCountries = dcount(SourceIPLocation),
    Countries = make_set(SourceIPLocation),
    ThreatIntelHits = countif(isnotempty(tostring(DevicesInsights.ThreatIntelIndicatorType)))
| project
    TotalActivities,
    HighAnomalyCount,
    MediumAnomalyCount,
    MaxPriority,
    AvgPriority = round(AvgPriority, 1),
    FirstTimeISPCount,
    FirstTimeCountryCount,
    UncommonISPAmongPeersCount,
    UniqueIPs,
    UniqueCountries,
    Countries,
    ThreatIntelHits,
    AnomalyRatio = round(todouble(HighAnomalyCount + MediumAnomalyCount) / TotalActivities * 100, 1)
```

**Tuning Guidance:**

- **InvestigationPriority threshold**: `>= 7` = high-confidence anomaly (recommended for triage), `>= 4` = medium anomaly (broader coverage), `< 4` = likely normal
- **ISP analysis**: If `FirstTimeISP = true` AND `ISPUncommonAmongPeers = true`, the anonymous proxy is almost certainly not legitimate business use
- **Country analysis**: `FirstTimeCountry = true` for a user who normally signs in from a single country is a strong indicator
- **Dormant/New accounts**: `IsDormantAccount = true` signing in via anonymous IP is HIGH risk — likely credential theft
- **ThreatIntelIndicator**: If populated (Botnet, C2, Malware, etc.), the IP has known malicious associations

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| InvestigationPriority | >= 7 (high anomaly) | < 4 (normal behavior) |
| FirstTimeISP | true — never used this ISP | false — ISP seen before |
| ISPUncommonAmongPeers | true — peers don't use this ISP | false — common ISP in peer group |
| FirstTimeCountry | true — new country for user | false — known travel location |
| IsDormantAccount | true — account was inactive 180+ days | false — active account |
| BlastRadius | High — admin or privileged account | Low — standard user |
| ThreatIntelIndicator | Botnet, C2, Proxy, Tor | Empty |
| AnomalyRatio (30d) | > 20% — frequent anomalies | < 5% — rare anomalies |

**Decision guidance:**

- **UEBA InvestigationPriority >= 7 + FirstTimeISP + FirstTimeCountry** → Very high confidence of malicious activity. Proceed to Containment
- **InvestigationPriority >= 4 + ISPUncommonAmongPeers** → Suspicious. Correlate with Steps 1-7 findings for final determination
- **InvestigationPriority < 4 + ISP seen before** → Likely legitimate anonymous browsing (VPN user). Consider closing as false positive
- **IsDormantAccount = true** → Regardless of priority score, treat as HIGH risk. Dormant accounts using anonymous IPs strongly suggest credential compromise
- **ThreatIntelIndicator populated** → IP has known malicious associations. Immediate escalation regardless of other findings

---

## 6. Containment Playbook

Execute in this order. IMPORTANT: Collect evidence (Section 7 checklist) BEFORE taking containment actions that could alert the attacker or destroy evidence.

### Immediate Actions (within 15 minutes of confirmed compromise):

1. **Block the anonymous IP** - Add the attacker's anonymous IP to Conditional Access as a blocked location. While the attacker can switch to a different proxy, blocking the known IP prevents immediate re-access.

2. **Revoke all active sessions** - Revoke the user's refresh tokens via Entra ID to immediately invalidate all active sessions, including any tokens obtained through the anonymous IP session.

3. **Reset password** - Reset the user's password to a strong temporary password. Communicate the new password via an out-of-band channel (phone call, SMS, in-person). Do NOT use the potentially compromised email account.

4. **Disable suspicious inbox rules** - If inbox rules were created for forwarding/deletion, disable them immediately.

### Follow-up Actions (within 1 hour):

5. **Review and remove unauthorized MFA methods** - If the attacker registered a new MFA method, remove it. Verify remaining MFA methods with the user through out-of-band channel.

6. **Revoke OAuth application consents** - If unauthorized applications were granted consent, revoke the application permissions in Entra ID Enterprise Applications.

7. **Remove email forwarding rules** - Check and remove any mailbox forwarding rules (both inbox rules and mailbox-level forwarding via Set-Mailbox).

8. **Review mailbox delegate permissions** - Remove any unauthorized delegate or full-access permissions added to the mailbox.

### Extended Actions (within 24 hours):

9. **Notify the user** - Contact the user via out-of-band channel. Determine if they were using a VPN or if the sign-in was unauthorized.

10. **Check for data exposure** - Review what data was accessed from the anonymous IP during the compromise window.

11. **Hunt for related compromise** - Check if the same anonymous IP was used against other accounts. Run the IP against all sign-in logs (Query 7B).

12. **Review Conditional Access policies** - Evaluate whether a policy to block sign-ins from anonymous IPs or require MFA for risky sign-ins would have prevented this.

13. **Consider blocking anonymous IP sign-ins** - If your organization has no legitimate use case for Tor/anonymous proxies, create a Conditional Access policy to block or require MFA for sign-ins flagged as anonymous IP.

---

## 7. Evidence Collection Checklist

Preserve the following BEFORE taking containment actions:

- [ ] Risk event record from AADUserRiskEvents (including IpAddress and Location)
- [ ] User risk state from AADRiskyUsers
- [ ] Full sign-in record from SigninLogs for the anonymous IP session
- [ ] IP classification results (Tor, VPN, proxy determination)
- [ ] 30-day sign-in baseline for the user
- [ ] All sign-in events from the anonymous IP (successful and failed)
- [ ] Non-interactive sign-in records from the anonymous IP
- [ ] All AuditLogs entries for the user in the 72 hours surrounding the event
- [ ] All OfficeActivity records for the user in the 72 hours surrounding the event
- [ ] Inbox rules snapshot (current state before remediation)
- [ ] Mailbox forwarding configuration snapshot
- [ ] OAuth application consent list for the user
- [ ] MFA registration details for the user
- [ ] IP reputation and TI lookup results
- [ ] Organizational usage of the anonymous IP (other users)
- [ ] Screenshot of the risk event in the Entra ID portal
- [ ] Timeline of all events from the anonymous IP (chronological reconstruction)

---

## 8. Escalation Criteria

### Escalate to Senior Analyst when:
- The anonymous IP is confirmed as a Tor exit node
- Post-sign-in persistence confirmed (inbox rules, OAuth apps, MFA changes)
- Multiple users targeted from the same anonymous IP (coordinated attack)
- The compromised account holds privileged roles
- Non-interactive token usage from the anonymous IP exceeds 20 events

### Escalate to Customer/Management when:
- Confirmed credential compromise with verified post-sign-in abuse from anonymous infrastructure
- Any data exposure involving PII, financial data, or regulated information
- Compromise of executive or finance team accounts (high BEC risk)
- Evidence of internal phishing from the compromised account

### Escalate to Incident Response Team when:
- Confirmed Tor-based access with post-compromise activity (nation-state TTP)
- Credential spray campaign through anonymous infrastructure targeting multiple accounts
- Compromise has spread to multiple accounts
- Attacker has gained administrative privileges via anonymous access
- Evidence of APT-level operational security (Tor + custom tooling + persistence)

---

## 9. False Positive Documentation

### Common Benign Scenarios

**1. Commercial VPN users (~40% of false positives)**
- Pattern: Employee uses NordVPN, ExpressVPN, Surfshark, or similar commercial VPN for personal privacy. The VPN server IP appears in anonymization databases
- How to confirm: Same DeviceId as baseline (managed device), MFA completed, normal app usage, user has history of sign-ins from VPN IPs. IP classification shows commercial VPN provider ASN
- Tuning note: Add commonly used commercial VPN IP ranges to Conditional Access named locations. Consider requiring MFA (not blocking) for anonymous IP sign-ins rather than investigating every occurrence

**2. Privacy-conscious employees (~15% of false positives)**
- Pattern: Employee uses iCloud Private Relay, Mullvad VPN, or similar privacy service as part of their normal browsing. These services may appear in anonymization databases
- How to confirm: Same managed device, MFA enforced, consistent usage over 30-day baseline, no suspicious post-sign-in activity
- Tuning note: Document known privacy service usage per user. Consider user acknowledgment for privacy tool usage

**3. Cloud development environments (~15% of false positives)**
- Pattern: Developer works from AWS CloudShell, Azure Cloud Shell, GitHub Codespaces, or other cloud-hosted VM. The cloud provider IP may appear in anonymization databases
- How to confirm: App accessed is development-related (Azure Portal, GitHub, VS Code). IP belongs to known cloud provider ASN. User is a developer
- Tuning note: Whitelist cloud provider IP ranges for development teams in Conditional Access named locations

**4. Airport/hotel/travel VPN usage (~10% of false positives)**
- Pattern: Employee traveling uses a VPN service while connected to public WiFi at airports or hotels
- How to confirm: Check user's calendar/travel schedule. Same DeviceId (managed laptop), MFA completed. Usage is temporary, not ongoing
- Tuning note: For frequent travelers, consider reducing alert sensitivity or requiring MFA only (not blocking)

**5. Tor Browser for security research (~10% of false positives)**
- Pattern: Security researcher, journalist, or compliance analyst uses Tor Browser for legitimate research purposes
- How to confirm: User's role involves security research or threat intelligence. IP classification confirms Tor exit node. Same managed device, limited app access
- Tuning note: Document approved Tor Browser usage. Consider separate Conditional Access policies for security research accounts

**6. Mobile carrier IP overlap (~10% of false positives)**
- Pattern: Mobile carrier's NAT infrastructure shares IP space with known anonymization services. The user is on a mobile device with carrier connectivity
- How to confirm: Sign-in from mobile client (iOS/Android), same DeviceId (managed phone), MFA completed via mobile authenticator. IP belongs to mobile carrier ASN
- Tuning note: Mobile carrier IPs have unreliable classification. Weight these alerts lower if all other indicators are benign

---

## 10. MITRE ATT&CK Mapping

### Primary Technique

**T1090.003 - Proxy: Multi-hop Proxy** (Confirmed)

The "Anonymous IP address" alert detects sign-ins from IP addresses associated with anonymizing proxy infrastructure, directly mapping to T1090.003. Attackers use Tor, multi-hop proxies, and anonymizing VPNs to obscure their origin IP when accessing compromised cloud accounts. The secondary key technique is **T1078.004 - Valid Accounts: Cloud Accounts**, which represents the actual credential usage.

### Detection Coverage Matrix

| Technique ID | Technique Name | Detecting Query | Coverage Level | Notes |
|---|---|---|---|---|
| T1090.003 | Proxy: Multi-hop Proxy | Query 1, 2 | **Full** | Primary detection target - NEW C2 tactic coverage |
| T1090 | Proxy | Query 1, 2 | **Partial** | General proxy detection |
| T1078.004 | Valid Accounts: Cloud Accounts | Query 1, 4 | **Full** | Credential usage from anonymous IP |
| T1098 | Account Manipulation | Query 6A | **Full** | Post-access persistence |
| T1098.005 | Device Registration | Query 6A | **Full** | Rogue device join |
| T1114.003 | Email Forwarding Rule | Query 6C | **Full** | Inbox rule persistence |
| T1528 | Steal Application Access Token | Query 6A | **Full** | OAuth consent detection |
| T1530 | Data from Cloud Storage Object | Query 6B | **Partial** | Volume-based only |
| T1534 | Internal Spearphishing | Query 6B | **Partial** | Volume-based only |
| T1556.006 | Modify Authentication Process: MFA | Query 6A | **Full** | MFA registration/deletion |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Query 6C | **Full** | Inbox rule deep dive |

**Summary: 11 techniques mapped. 8 with full coverage, 3 with partial coverage.**

**New coverage vs RB-0001/RB-0002/RB-0003:** T1090.003 (Multi-hop Proxy) and T1090 (Proxy) are the key new techniques, providing the first coverage in the **Command and Control** tactic across all runbooks.

### Attack Chains

**Chain 1: Credential Theft -> Anonymized Access -> BEC (Most Relevant)**

```
T1110.003 Password Spraying / T1110.004 Credential Stuffing
    | Attacker obtains valid credentials
T1090.003 Multi-hop Proxy (Tor/VPN)  <-- THIS ALERT FIRES HERE
T1078.004 Valid Accounts: Cloud Accounts  <-- AND HERE
    | Attacker signs in via anonymous infrastructure
T1098 Account Manipulation (MFA registration)
T1556.006 Modify Authentication Process: MFA
T1564.808 Email Hiding Rules
T1114.003 Email Forwarding Rule
    | Attacker conducts BEC
T1534 Internal Spearphishing
```

Coverage: 8/10 techniques detected (2 partial)

**Chain 2: APT Anonymous Reconnaissance -> Persistent Access**

```
T1589 Gather Victim Identity Info (prior recon)
    | Attacker obtains credentials via targeted operation
T1090.003 Multi-hop Proxy  <-- THIS ALERT FIRES HERE
T1078.004 Valid Accounts: Cloud Accounts
    | Attacker establishes persistent access
T1098 Account Manipulation
T1528 Steal Application Access Token (OAuth consent)
T1530 Data from Cloud Storage Object
    | Data exfiltration through anonymous channel
T1090 Proxy (C2 for ongoing access)
```

Coverage: 6/8 techniques detected

### Coverage Gaps

| Gap # | Technique | ID | Risk Level | Recommendation |
|---|---|---|---|---|
| 1 | Phishing: Spearphishing Link | T1566.002 | **High** | Create linked runbook for phishing investigation |
| 2 | Exfiltration Over Web Service | T1567.002 | **Medium** | Requires Cloud App Security or DLP integration |
| 3 | User Execution: Malicious Link | T1204.001 | **High** | Requires endpoint detection (Defender for Endpoint) |
| 4 | Adversary-in-the-Middle | T1557 | **High** | Detection requires proxy log analysis |

> For detailed threat actor profiles, per-technique analysis, and full confidence assessments, see [MITRE Coverage](../../mitre-coverage.md).

---

## 11. Query Summary

| Query | Step | Tables | Purpose | License | Required |
|---|---|---|---|---|---|
| 1 | Step 1 | AADUserRiskEvents, SigninLogs | Extract anonymous IP risk event and sign-in | Entra ID P2 | Yes |
| 2 | Step 2 | SigninLogs, ThreatIntelligenceIndicator | Anonymous IP classification (Tor/VPN/proxy) | Entra ID Free + TI | Yes |
| 3 | Step 3 | SigninLogs | 30-day sign-in baseline (MANDATORY) | Entra ID Free | **MANDATORY** |
| 4 | Step 4 | SigninLogs | Sign-in session analysis from anonymous IP | Entra ID Free | Yes |
| 5 | Step 5 | AADNonInteractiveUserSignInLogs | Non-interactive sign-ins from anonymous IP | Entra ID P1/P2 | Yes |
| 6A | Step 6 | AuditLogs | Directory changes after anonymous sign-in | Entra ID Free | Yes |
| 6B | Step 6 | OfficeActivity | Email and file activity | M365 E3+ | Yes |
| 6C | Step 6 | OfficeActivity | Inbox rule deep dive | M365 E3+ | Yes |
| 7A | Step 7 | ThreatIntelligenceIndicator | IP reputation (TI feeds) | Sentinel + TI | Optional |
| 7B | Step 7 | SigninLogs | Organizational IP usage check | Entra ID Free | Yes |

**Total: 10 queries (8 required, 1 mandatory, 1 optional)**

**Minimum license for core investigation:** Entra ID P2 + M365 E3 + Sentinel (9 queries)
**Full investigation:** M365 E5 + Sentinel + TI feeds (all 10 queries)

---

## Appendix A: Datatable Tests

All queries include datatable-based inline tests with synthetic data. Each test validates query logic with a mix of malicious and benign scenarios without access to production data.

### Test 1: Query 1 - Extract Anonymous IP Risk Event and Sign-In

```kql
// ============================================================
// TEST: Query 1 - Extract Anonymous IP Risk Event and Sign-In
// Synthetic data: 6 risk events + 6 sign-in rows
// ============================================================
let TestRiskEvents = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    RiskEventType: string,
    RiskLevel: string,
    RiskState: string,
    DetectionTimingType: string,
    IpAddress: string,
    Location: dynamic,
    AdditionalInfo: dynamic,
    CorrelationId: string,
    Id: string
) [
    // TARGET: Anonymous IP risk event (realtime, has IP)
    datetime(2026-02-22T14:30:00Z), "user@contoso.com", "anonymizedIPAddress", "medium",
        "atRisk", "realtime", "185.220.101.42",
        dynamic({"city":"Unknown","countryOrRegion":"DE"}),
        dynamic(null), "corr-001", "risk-001",
    // COMPOUND: Unfamiliar sign-in 1 hour later
    datetime(2026-02-22T15:30:00Z), "user@contoso.com", "unfamiliarFeatures", "medium",
        "atRisk", "realtime", "185.220.101.42",
        dynamic({"city":"Unknown","countryOrRegion":"DE"}),
        dynamic(null), "corr-002", "risk-002",
    // DIFFERENT USER: Should be filtered out
    datetime(2026-02-22T14:35:00Z), "other@contoso.com", "anonymizedIPAddress", "low",
        "atRisk", "realtime", "185.220.101.99",
        dynamic({"city":"Unknown","countryOrRegion":"NL"}),
        dynamic(null), "corr-003", "risk-003",
    // DIFFERENT TYPE: impossibleTravel for different user
    datetime(2026-02-22T10:00:00Z), "colleague@contoso.com", "impossibleTravel", "medium",
        "atRisk", "realtime", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic(null), "corr-004", "risk-004",
    // OLD EVENT: Already dismissed anonymous IP for target
    datetime(2026-02-15T09:00:00Z), "user@contoso.com", "anonymizedIPAddress", "low",
        "dismissed", "realtime", "104.244.76.13",
        dynamic({"city":"Unknown"}),
        dynamic(null), "corr-005", "risk-005",
    // BENIGN: Normal risk event
    datetime(2026-02-22T12:00:00Z), "vpnuser@contoso.com", "anonymizedIPAddress", "low",
        "dismissed", "realtime", "203.0.113.10",
        dynamic({"city":"London","countryOrRegion":"GB"}),
        dynamic(null), "corr-006", "risk-006"
];
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    LocationDetails: dynamic,
    DeviceDetail: dynamic,
    UserAgent: string,
    AppDisplayName: string,
    ResourceDisplayName: string,
    ClientAppUsed: string,
    AuthenticationRequirement: string,
    MfaDetail: dynamic,
    ConditionalAccessStatus: string,
    ResultType: string,
    CorrelationId: string,
    SessionId: string
) [
    // TARGET: Sign-in from Tor exit node (suspicious)
    datetime(2026-02-22T14:30:00Z), "user@contoso.com", "185.220.101.42",
        dynamic({"city":"Unknown","countryOrRegion":"DE","state":""}),
        dynamic({"deviceId":"","operatingSystem":"Windows 10","browser":"Firefox 115.0",
            "isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-001", "sess-001",
    // DIFFERENT USER from different anonymous IP
    datetime(2026-02-22T14:35:00Z), "other@contoso.com", "185.220.101.99",
        dynamic({"city":"Unknown","countryOrRegion":"NL"}),
        dynamic({"deviceId":"dev-002","operatingSystem":"Windows 11","browser":"Chrome 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Teams", "Microsoft Teams", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
        "success", "0", "corr-003", "sess-003",
    // BENIGN: VPN user with managed device
    datetime(2026-02-22T12:00:00Z), "vpnuser@contoso.com", "203.0.113.10",
        dynamic({"city":"London","countryOrRegion":"GB"}),
        dynamic({"deviceId":"dev-vpn","operatingSystem":"Windows 11","browser":"Chrome 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
        "success", "0", "corr-006", "sess-006",
    // FAILED: Failed sign-in attempt from target anonymous IP
    datetime(2026-02-22T14:25:00Z), "user@contoso.com", "185.220.101.42",
        dynamic({"city":"Unknown","countryOrRegion":"DE"}),
        dynamic({"deviceId":"","operatingSystem":"Windows 10","browser":"Firefox 115.0",
            "isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "50126", "corr-007", "sess-007",
    // BENIGN: User normal sign-in from office
    datetime(2026-02-22T09:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Teams", "Microsoft Teams", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
        "success", "0", "corr-008", "sess-008",
    // BENIGN: Different user normal sign-in
    datetime(2026-02-22T10:00:00Z), "colleague@contoso.com", "10.1.1.1",
        dynamic({"city":"Ankara","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-003","operatingSystem":"Windows 11","browser":"Edge 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Edg/120.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppOTP"}),
        "success", "0", "corr-009", "sess-009"
];
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let AnonIP = "185.220.101.42";
let LookbackWindow = 4h;
// Part 1: Risk event
let RiskEvent = TestRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + LookbackWindow))
    | where UserPrincipalName == TargetUser
    | where RiskEventType == "anonymizedIPAddress"
    | project RiskTimeGenerated = TimeGenerated, UserPrincipalName, RiskEventType,
        RiskLevel, RiskIpAddress = IpAddress, DetectionTimingType, Id
    | top 1 by RiskTimeGenerated desc;
// Part 2: Sign-in
let SignIn = TestSigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1h))
    | where UserPrincipalName == TargetUser
    | where IPAddress == AnonIP
    | where ResultType == "0"
    | project SigninTime = TimeGenerated, IPAddress,
        DeviceId = tostring(DeviceDetail.deviceId),
        DeviceIsManaged = tostring(DeviceDetail.isManaged),
        AuthenticationRequirement, UserAgent,
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA performed"),
        ConditionalAccessStatus
    | top 1 by SigninTime desc;
// Part 3: Compound risk
let OtherRiskEvents = TestRiskEvents
    | where TimeGenerated between ((AlertTime - 7d) .. (AlertTime + 1d))
    | where UserPrincipalName == TargetUser
    | where RiskEventType != "anonymizedIPAddress"
    | summarize OtherRiskEventCount = count(), OtherRiskTypes = make_set(RiskEventType);
RiskEvent
| extend placeholder = 1
| join kind=leftouter (SignIn | extend placeholder = 1) on placeholder
| join kind=leftouter (OtherRiskEvents | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1, placeholder2
| extend CompoundRiskAssessment = case(
    OtherRiskEventCount > 0 and OtherRiskTypes has "unfamiliarFeatures",
        "HIGH - Anonymous IP + unfamiliar sign-in",
    OtherRiskEventCount > 0,
        strcat("ELEVATED - ", tostring(OtherRiskEventCount), " other risk events"),
    "SINGLE RISK"
)
// Expected: 1 row - risk-001 (anonymizedIPAddress for user@contoso.com)
//   RiskLevel=medium, RiskIpAddress=185.220.101.42, DetectionTimingType=realtime
//   DeviceId="" (unknown device), DeviceIsManaged=false
//   AuthenticationRequirement=singleFactorAuthentication, MfaAuthMethod="No MFA performed"
//   ConditionalAccessStatus=notApplied
//   OtherRiskEventCount=1 (unfamiliarFeatures from risk-002)
//   CompoundRiskAssessment="HIGH - Anonymous IP + unfamiliar sign-in"
```

### Test 2: Query 2 - Anonymous IP Classification

```kql
// ============================================================
// TEST: Query 2 - Anonymous IP Classification
// Synthetic data: 4 sign-ins from different anonymous IP types
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    DeviceDetail: dynamic,
    UserAgent: string,
    AppDisplayName: string,
    ClientAppUsed: string,
    AutonomousSystemNumber: string,
    ResultType: string
) [
    // TOR: Tor Browser user agent from known Tor exit
    datetime(2026-02-22T14:30:00Z), "user@contoso.com", "185.220.101.42",
        dynamic({"deviceId":"","operatingSystem":"Windows 10","browser":"Firefox 115.0"}),
        "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Microsoft Office 365", "Browser", "680", "0",
    // VPN: NordVPN user with managed device
    datetime(2026-02-22T10:00:00Z), "vpnuser@contoso.com", "194.35.233.100",
        dynamic({"deviceId":"dev-vpn","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Mozilla/5.0 Chrome/120.0",
        "Microsoft Teams", "Browser", "212238", "0",
    // CLOUD: AWS CloudShell IP
    datetime(2026-02-22T11:00:00Z), "devuser@contoso.com", "52.94.133.10",
        dynamic({"deviceId":"","operatingSystem":"Linux","browser":"Chrome 120.0"}),
        "Mozilla/5.0 Chrome/120.0",
        "Azure Portal", "Browser", "16509", "0",
    // UNKNOWN: Unknown proxy
    datetime(2026-02-22T12:00:00Z), "testuser@contoso.com", "203.0.113.50",
        dynamic({"deviceId":"","operatingSystem":"Windows 10","browser":"Python/3.9"}),
        "python-requests/2.28.1",
        "Microsoft Graph", "Mobile Apps and Desktop clients", "9999", "0"
];
let TestTI = datatable(
    NetworkIP: string,
    Active: bool,
    ExpirationDateTime: datetime,
    ThreatType: string,
    ConfidenceScore: int,
    Description: string,
    Tags: dynamic,
    SourceSystem: string
) [
    "185.220.101.42", true, datetime(2026-12-31), "tor_exit_node", 95,
        "Known Tor exit node operated by Tor relay operator", dynamic(["tor","exit_node"]), "MSTIC",
    "203.0.113.50", true, datetime(2026-12-31), "anonymizer", 60,
        "Known anonymizing proxy service", dynamic(["proxy","anonymizer"]), "OSINT"
];
// Test classification for user@contoso.com (Tor)
let AnonIP = "185.220.101.42";
let SignInDetails = TestSigninLogs
    | where IPAddress == AnonIP
    | where ResultType == "0"
    | top 1 by TimeGenerated desc
    | project IPAddress, UserAgent, DeviceBrowser = tostring(DeviceDetail.browser),
        AutonomousSystemNumber;
let TiMatch = TestTI
    | where Active == true
    | where NetworkIP == AnonIP
    | project ThreatType, ConfidenceScore, Description, Tags
    | top 1 by ConfidenceScore desc;
SignInDetails
| extend placeholder = 1
| join kind=leftouter (TiMatch | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend IPClassification = case(
    ThreatType has "tor" or Description has "Tor",
        "TOR EXIT NODE - Identified via threat intelligence",
    UserAgent has "Tor",
        "TOR EXIT NODE - Highest risk",
    ThreatType has "proxy" or ThreatType has "anonymizer",
        "ANONYMIZING PROXY - High risk",
    AutonomousSystemNumber in ("16509", "14618", "8075", "15169", "396982"),
        "CLOUD PROVIDER - AWS/Azure/GCP",
    "UNKNOWN ANONYMIZER"
)
// Expected: IPClassification = "TOR EXIT NODE - Identified via threat intelligence"
//   ThreatType=tor_exit_node, ConfidenceScore=95
//   UserAgent shows Firefox 115.0 (Tor Browser pattern)
```

### Test 3: Query 3 - Sign-In Baseline

```kql
// ============================================================
// TEST: Query 3 - 30-Day Sign-In Baseline
// Synthetic data: 10 baseline sign-ins from known locations
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    LocationDetails: dynamic,
    DeviceDetail: dynamic,
    AppDisplayName: string,
    AuthenticationRequirement: string,
    MfaDetail: dynamic,
    ClientAppUsed: string,
    ResultType: string
) [
    // Normal: Istanbul office (weekday, business hours)
    datetime(2026-01-23T09:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Browser", "0",
    datetime(2026-01-24T10:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Teams", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Browser", "0",
    datetime(2026-01-27T08:30:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Browser", "0",
    datetime(2026-02-03T09:15:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "SharePoint Online", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Browser", "0",
    datetime(2026-02-10T09:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-001","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Office 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Browser", "0",
    // Mobile: User's phone from home
    datetime(2026-02-01T20:00:00Z), "user@contoso.com", "78.160.10.5",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-mob","operatingSystem":"iOS 17","browser":"Safari"}),
        "Microsoft Outlook", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Mobile Apps and Desktop clients", "0",
    datetime(2026-02-08T19:30:00Z), "user@contoso.com", "78.160.10.5",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-mob","operatingSystem":"iOS 17","browser":"Safari"}),
        "Microsoft Teams", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Mobile Apps and Desktop clients", "0",
    // ANOMALOUS: Anonymous IP (NOT in baseline for this user)
    datetime(2026-02-22T14:30:00Z), "user@contoso.com", "185.220.101.42",
        dynamic({"city":"Unknown","countryOrRegion":"DE"}),
        dynamic({"deviceId":"","operatingSystem":"Windows 10","browser":"Firefox 115.0"}),
        "Microsoft Office 365", "singleFactorAuthentication",
        dynamic(null), "Browser", "0",
    // DIFFERENT USER: Should be filtered
    datetime(2026-02-05T09:00:00Z), "other@contoso.com", "10.1.1.1",
        dynamic({"city":"Ankara","countryOrRegion":"TR"}),
        dynamic({"deviceId":"dev-other","operatingSystem":"Windows 11","browser":"Edge"}),
        "Microsoft Office 365", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppOTP"}), "Browser", "0",
    // VPN USER: Regular VPN user (for contrast)
    datetime(2026-02-22T10:00:00Z), "vpnuser@contoso.com", "185.220.101.42",
        dynamic({"city":"Unknown","countryOrRegion":"DE"}),
        dynamic({"deviceId":"dev-vpn","operatingSystem":"Windows 11","browser":"Chrome 120.0"}),
        "Microsoft Teams", "multiFactorAuthentication",
        dynamic({"authMethod":"PhoneAppNotification"}), "Browser", "0"
];
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let AnonIP = "185.220.101.42";
let BaselinePeriod = 30d;
TestSigninLogs
| where TimeGenerated between ((AlertTime - BaselinePeriod) .. AlertTime)
| where UserPrincipalName == TargetUser
| where ResultType == "0"
| summarize
    TotalSignins = count(),
    DistinctIPs = dcount(IPAddress),
    KnownIPs = make_set(IPAddress, 50),
    KnownCities = make_set(tostring(LocationDetails.city)),
    AnonIPSignins = countif(IPAddress == AnonIP),
    MFACount = countif(AuthenticationRequirement == "multiFactorAuthentication"),
    SFACount = countif(AuthenticationRequirement == "singleFactorAuthentication"),
    BusinessHourSignins = countif(hourofday(TimeGenerated) between (8 .. 18)),
    OffHourSignins = countif(hourofday(TimeGenerated) !between (8 .. 18))
| extend
    AnonIPInBaseline = iff(AnonIPSignins > 0, "YES", "NO"),
    MFACoverage = round(100.0 * MFACount / TotalSignins, 1),
    BaselineAssessment = case(
        AnonIPSignins > 5, "REGULAR USER",
        AnonIPSignins > 0, "OCCASIONAL USER",
        DistinctIPs <= 3, "STATIC USER - Anonymous IP is highly anomalous",
        "MODERATE"
    )
// Expected: TotalSignins=8 (7 normal + 1 anonymous)
//   DistinctIPs=3 (85.100.50.25, 78.160.10.5, 185.220.101.42)
//   AnonIPSignins=1 (the current alert sign-in is within baseline window)
//   MFACount=7, SFACount=1 (the anonymous sign-in was SFA)
//   MFACoverage=87.5%
//   BaselineAssessment="OCCASIONAL USER" (1 anonymous sign-in)
//   Note: Filtered out other@contoso.com and vpnuser@contoso.com
```

### Test 4: Query 6A - Directory Changes After Anonymous Sign-In

```kql
// ============================================================
// TEST: Query 6A - Directory Changes After Anonymous Sign-In
// Synthetic data: 12 audit log rows
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    Category: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    CorrelationId: string
) [
    // MALICIOUS: MFA method registered 10 min after anonymous sign-in
    datetime(2026-02-22T14:40:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User",
            "modifiedProperties":[{"displayName":"StrongAuthenticationMethod","newValue":"PhoneAppNotification"}]}]),
        "corr-mal-001",
    // MALICIOUS: OAuth app consent 15 min after
    datetime(2026-02-22T14:45:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"Suspicious OAuth App","type":"ServicePrincipal"}]),
        "corr-mal-002",
    // MALICIOUS: Inbox rule creation (via different table, but captured in audit)
    datetime(2026-02-22T14:50:00Z), "Update user", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User"}]),
        "corr-mal-003",
    // BENIGN: Different user action
    datetime(2026-02-22T14:42:00Z), "Update user", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"other@contoso.com","displayName":"Other User"}]),
        "corr-ben-001",
    // BENIGN: Target user action BEFORE alert (outside window)
    datetime(2026-02-22T10:00:00Z), "Change user password", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com"}]),
        "corr-ben-002",
    // BENIGN: Non-relevant operation
    datetime(2026-02-22T15:00:00Z), "Add member to group", "GroupManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"displayName":"All Users","type":"Group"}]),
        "corr-ben-003",
    // MALICIOUS: Device registration
    datetime(2026-02-22T14:55:00Z), "Register device", "DeviceManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"DESKTOP-ATTACKER","type":"Device"}]),
        "corr-mal-004",
    // BENIGN: Different operation type not in watch list
    datetime(2026-02-22T15:10:00Z), "Add user", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"newuser@contoso.com"}]),
        "corr-ben-004",
    // BENIGN: Target user normal action after window
    datetime(2026-02-22T19:00:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com"}]),
        "corr-ben-005",
    // MALICIOUS: Role escalation
    datetime(2026-02-22T15:05:00Z), "Add member to role", "RoleManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User",
            "modifiedProperties":[{"displayName":"Role.DisplayName","newValue":"Exchange Administrator"}]}]),
        "corr-mal-005",
    // BENIGN: Other user password change
    datetime(2026-02-22T14:38:00Z), "Reset user password", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"colleague@contoso.com"}]),
        "corr-ben-006",
    // BENIGN: Outside post-sign-in window
    datetime(2026-02-22T20:00:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"Normal App"}]),
        "corr-ben-007"
];
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let PostSignInWindow = 4h;
TestAuditLogs
| where TimeGenerated between (AlertTime .. (AlertTime + PostSignInWindow))
| where OperationName in (
    "User registered security info", "User deleted security info",
    "Consent to application", "Add delegated permission grant",
    "Update user", "Register device", "Add member to role",
    "Reset user password", "Change user password",
    "Add owner to application", "Add app role assignment grant to user"
)
| mv-expand TargetResource = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) == TargetUser
    or tostring(TargetResource.userPrincipalName) == TargetUser
| project
    TimeGenerated, OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    TargetUPN = tostring(TargetResource.userPrincipalName),
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, AlertTime),
    Severity = case(
        OperationName has "security info", "CRITICAL - MFA MANIPULATION",
        OperationName has "Consent to application", "CRITICAL - OAUTH APP CONSENT",
        OperationName has "member to role", "CRITICAL - ROLE ESCALATION",
        OperationName has "Register device", "HIGH - DEVICE REGISTRATION",
        OperationName has "Update user", "MEDIUM - USER MODIFICATION",
        "INFO"
    )
| order by TimeGenerated asc
// Expected: 5 rows (all within 4h window, matching target user):
//   1. User registered security info (14:40, +10min) - CRITICAL - MFA MANIPULATION
//   2. Consent to application (14:45, +15min) - CRITICAL - OAUTH APP CONSENT
//   3. Update user (14:50, +20min) - MEDIUM - USER MODIFICATION
//   4. Register device (14:55, +25min) - HIGH - DEVICE REGISTRATION
//   5. Add member to role (15:05, +35min) - CRITICAL - ROLE ESCALATION
// Filtered out: other user actions, actions before alert, actions after window
```

### Test 5: Query 7B - Organizational IP Usage Check

```kql
// ============================================================
// TEST: Query 7B - Organizational IP Usage Check
// Synthetic data: 8 sign-ins from the anonymous IP
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    AppDisplayName: string,
    ResultType: string
) [
    // Target user sign-in from anonymous IP
    datetime(2026-02-22T14:30:00Z), "user@contoso.com", "185.220.101.42",
        "Microsoft Office 365", "0",
    // Failed sign-in from same IP targeting different user
    datetime(2026-02-22T14:32:00Z), "admin@contoso.com", "185.220.101.42",
        "Microsoft Office 365", "50126",
    // Another failed attempt
    datetime(2026-02-22T14:33:00Z), "finance@contoso.com", "185.220.101.42",
        "Microsoft Office 365", "50126",
    // Another failed attempt
    datetime(2026-02-22T14:34:00Z), "ceo@contoso.com", "185.220.101.42",
        "Microsoft Office 365", "50126",
    // Different anonymous IP (should be filtered)
    datetime(2026-02-22T10:00:00Z), "vpnuser@contoso.com", "203.0.113.10",
        "Microsoft Teams", "0",
    // Normal sign-in (should be filtered)
    datetime(2026-02-22T09:00:00Z), "user@contoso.com", "85.100.50.25",
        "Microsoft Teams", "0",
    // Another failed from target IP
    datetime(2026-02-22T14:35:00Z), "hr@contoso.com", "185.220.101.42",
        "Microsoft Office 365", "50126",
    // Old sign-in from target IP (within 30d)
    datetime(2026-02-20T08:00:00Z), "user@contoso.com", "185.220.101.42",
        "Microsoft Office 365", "0"
];
let AnonIP = "185.220.101.42";
let TargetUser = "user@contoso.com";
TestSigninLogs
| where IPAddress == AnonIP
| summarize
    TotalSignins = count(),
    SuccessfulSignins = countif(ResultType == "0"),
    FailedSignins = countif(ResultType != "0"),
    DistinctUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 20)
| extend
    IPClassification = case(
        DistinctUsers > 10, "LIKELY CORPORATE VPN",
        DistinctUsers > 3, "POSSIBLY SHARED VPN",
        DistinctUsers == 1 and UserList has TargetUser, "SINGLE USER",
        "UNKNOWN"
    ),
    AttackIndicator = case(
        FailedSignins > 10 and DistinctUsers > 3,
            "CREDENTIAL SPRAY",
        FailedSignins > 5 and DistinctUsers == 1,
            "CREDENTIAL TESTING",
        FailedSignins > 2 and DistinctUsers > 2,
            "POSSIBLE CREDENTIAL SPRAY - Multiple users targeted",
        "NO ATTACK PATTERN"
    )
// Expected: TotalSignins=6, SuccessfulSignins=2, FailedSignins=4
//   DistinctUsers=5 (user, admin, finance, ceo, hr)
//   IPClassification="POSSIBLY SHARED VPN" (>3 distinct users)
//   AttackIndicator="POSSIBLE CREDENTIAL SPRAY - Multiple users targeted"
//   This pattern shows 1 successful + 4 failed across different users = credential spray
```

---

## References

- [Microsoft Entra ID Identity Protection risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [Anonymous IP address risk detection](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#anonymous-ip-address)
- [Conditional Access: Block access by location](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-location)
- [MITRE ATT&CK T1090.003 - Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)
- [MITRE ATT&CK T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [Tor Project - Exit Node List](https://check.torproject.org/torbulkexitlist)
- [Microsoft Threat Intelligence Blog](https://www.microsoft.com/en-us/security/blog/)
- [Investigating Identity Protection alerts](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk)
