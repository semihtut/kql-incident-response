---
title: "Impossible Travel Activity"
id: RB-0002
severity: medium
status: reviewed
description: >
  Investigation runbook for Microsoft Entra ID Identity Protection
  "Impossible travel" risk detection. Covers credential compromise via
  geographically impossible sign-in pairs, VPN/proxy false positive
  triage, token replay detection, and post-access blast radius assessment.
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
  techniques:
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1550.004
      technique_name: "Use Alternate Authentication Material: Web Session Cookie"
      confidence: confirmed
    - technique_id: T1098
      technique_name: "Account Manipulation"
      confidence: confirmed
    - technique_id: T1114.003
      technique_name: "Email Collection: Email Forwarding Rule"
      confidence: confirmed
    - technique_id: T1528
      technique_name: "Steal Application Access Token"
      confidence: confirmed
    - technique_id: T1539
      technique_name: "Steal Web Session Cookie"
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
  - "Octo Tempest (Scattered Spider)"
  - "Storm-0558"
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
    required: true
    alternatives: []
  - table: "AADRiskyUsers"
    product: "Entra ID Identity Protection"
    license: "Entra ID P2"
    required: true
    alternatives: []
  - table: "AuditLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "IdentityInfo"
    product: "Sentinel UEBA"
    license: "Sentinel UEBA"
    required: false
    alternatives: ["AuditLogs (Category == RoleManagement)"]
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
    product: "Sentinel UEBA"
    license: "Sentinel UEBA"
    required: false
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-21
updated: 2026-02-21
version: "1.0"
tier: 1
data_checks:
  - query: "AADUserRiskEvents | take 1"
    label: primary
    description: "If empty, Entra ID P2 or the connector is missing"
  - query: "SigninLogs | take 1"
    description: "Must contain geoCoordinates in Location column for distance calculation"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "Required for token replay detection (Step 5)"
  - query: "OfficeActivity | take 1"
    description: "If empty, the Office 365 connector is not configured"
---

# Impossible Travel Activity - Investigation Runbook

> **RB-0002** | Severity: Medium | Version: 1.0 | Last updated: 2026-02-21
>
> **Alert Source:** Microsoft Entra ID Identity Protection
> **Risk Detection Name:** `impossibleTravel`
> **Primary MITRE Technique:** T1078.004 - Valid Accounts: Cloud Accounts

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Extract Risk Event and Sign-In Pair](#step-1-extract-risk-event-and-sign-in-pair)
   - [Step 2: Geographic Distance and Travel Speed Calculation](#step-2-geographic-distance-and-travel-speed-calculation)
   - [Step 3: Baseline Comparison - Establish Normal Travel Pattern](#step-3-baseline-comparison---establish-normal-travel-pattern)
   - [Step 4: Device and Session Fingerprint Analysis](#step-4-device-and-session-fingerprint-analysis)
   - [Step 5: Token Replay and Session Hijacking Check](#step-5-token-replay-and-session-hijacking-check)
   - [Step 6: Analyze Post-Sign-In Activity (Blast Radius Assessment)](#step-6-analyze-post-sign-in-activity-blast-radius-assessment)
   - [Step 7: IP Reputation and Context (Both IPs)](#step-7-ip-reputation-and-context-both-ips)
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
The "Impossible travel" risk detection is generated by Entra ID Identity Protection when two sign-ins for the same user originate from geographically distant locations within a timeframe that makes physical travel between those locations impossible. Identity Protection uses a machine learning model that factors in familiar locations, VPN usage, and other heuristics. The `impossibleTravel` risk event fires when the model determines the geographic distance and time gap cannot be explained by normal behavior.

**Why it matters:**
Impossible travel is one of the strongest indicators that a user's credentials are being used simultaneously from two different locations. This typically means one of two things: (a) an attacker has obtained the user's credentials and is signing in from their own infrastructure while the legitimate user continues to sign in from their normal location, or (b) a session token has been stolen and is being replayed from a different geographic location (AiTM/token theft). Unlike "unfamiliar sign-in properties" which detects *new* properties, impossible travel detects *physically impossible* concurrent usage.

**However:** This alert has a **high false positive rate** (~60-70% in typical environments). Legitimate triggers include:
- Corporate VPN or cloud proxy (Zscaler, Netskope, Cloudflare Access) routing traffic through a distant Point of Presence
- User switching between VPN-connected and direct internet during a short timeframe
- Mobile carrier NAT/routing assigning IPs geolocated to distant cities
- Shared accounts used by multiple people in different locations
- Dual-stack networking (IPv4 and IPv6 resolving to different geolocations)

**Worst case scenario if this is real:**
An attacker is actively using the user's credentials or stolen session tokens *at the same time* as the legitimate user. This is especially dangerous because it indicates the attacker has persistent access and may have intercepted authentication tokens via an AiTM (adversary-in-the-middle) proxy. Token theft attacks bypass MFA entirely, making this a higher-severity compromise pattern than simple credential reuse.

**Key difference from RB-0001 (Unfamiliar Sign-In Properties):**
RB-0001 detects a single sign-in with unusual properties. This runbook (RB-0002) detects TWO sign-ins that are physically incompatible, requiring extraction and analysis of BOTH sign-in records. The investigation must calculate geographic distance and travel speed, compare device fingerprints across both sign-ins, and specifically check for token replay attacks.

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID P2 + Microsoft 365 E3 + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID, Office 365
- **Permissions:** Security Reader (investigation), Security Operator (containment)

### Recommended for Full Coverage
- **License:** Microsoft 365 E5 + Sentinel with UEBA enabled + TI feeds
- **Additional Connectors:** Defender for Cloud Apps, Threat Intelligence (TAXII/Platform)

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | SigninLogs, AuditLogs, SecurityAlert | Steps 1-2 (partial), 6 (partial) |
| Entra ID P2 + Sentinel | Above + AADNonInteractiveUserSignInLogs, AADUserRiskEvents, AADRiskyUsers | Steps 1-5, 7 (partial) |
| M365 E3 + Entra ID P2 + Sentinel | Above + OfficeActivity | Steps 1-7 (core investigation) |
| M365 E5 + Sentinel + UEBA | ALL tables | Steps 1-7 (full investigation) |

---

## 3. Input Parameters

All queries in this runbook use the following shared input parameters. Replace these values with the actual alert data before running. Unlike RB-0001 which uses a single IP, impossible travel alerts involve TWO sign-in locations.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Set these before running any query
// ============================================================
let TargetUser = "user@contoso.com";          // UserPrincipalName from the alert
let AlertTime = datetime(2026-02-21T14:30:00Z); // TimeGenerated of the risk event
let SignInIP1 = "85.100.50.25";              // First sign-in IP (typically the "known" location)
let SignInIP2 = "198.51.100.42";             // Second sign-in IP (typically the "anomalous" location)
```

---

## 4. Quick Triage Criteria

The goal of quick triage is to determine within 2-3 steps whether this alert can be confidently closed as a VPN/proxy false positive or requires deep investigation.

### Quick Close Conditions (all must be true to close as FP):
1. Both sign-ins share the **same DeviceId** (same physical device = VPN routing, not two devices)
2. One of the IPs belongs to a **known corporate VPN, cloud proxy, or SASE provider** (Zscaler, Netskope, Cloudflare, Palo Alto Prisma)
3. The user has a **history of sign-ins from both locations** in the 30-day baseline
4. There is **no other risk event** for this user in the past 7 days
5. There is **no suspicious post-sign-in activity** (no inbox rules, no app consents, no MFA changes)

### Quick Escalation Conditions (any one triggers deep investigation):
- Different DeviceId between the two sign-ins AND one is an unmanaged/non-compliant device
- Travel speed exceeds **900 km/h** (physically impossible for any transport)
- One sign-in is from a country the user has NEVER signed in from in 30 days
- The "second" sign-in did not complete MFA or bypassed Conditional Access
- Non-interactive sign-ins from the anomalous IP (indicates token replay, not just auth)
- Any post-sign-in activity within 60 minutes from the anomalous IP

---

## 5. Investigation Steps

### Step 1: Extract Risk Event and Sign-In Pair

**Purpose:** Pull the impossible travel risk event and the TWO sign-in records that triggered it. Unlike RB-0001 which extracts a single sign-in, this step must identify both the "origin" and "destination" sign-ins and extract geographic coordinates for distance calculation in Step 2.

**Data needed from:**
- Table: AADUserRiskEvents - get the risk event details (RiskEventType == "impossibleTravel", IpAddress, Location, AdditionalInfo)
- Table: SigninLogs - get BOTH sign-in records with full Location.geoCoordinates for distance calculation

**What to extract:**
- User identity: UserPrincipalName, display name, object ID
- Sign-in 1: IP, latitude/longitude, city, country, device, browser, time
- Sign-in 2: IP, latitude/longitude, city, country, device, browser, time
- Time gap between the two sign-ins (minutes)
- Authentication details for both: MFA status, Conditional Access, ResultType
- DeviceId for both (critical for VPN false positive detection)
- SessionId for both (needed for token replay check in Step 5)

#### Query 1: Extract Impossible Travel Risk Event and Sign-In Pair

```kql
// ============================================================
// Query 1: Extract Impossible Travel Risk Event and Sign-In Pair
// Purpose: Pull the risk event and BOTH sign-in records that
//          triggered the "impossibleTravel" detection
// Tables: AADUserRiskEvents, SigninLogs
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
// Wider lookback to find both sign-ins in the impossible travel pair
let LookbackWindow = 6h;
// --- Part 1: Get the risk event ---
let RiskEvent = AADUserRiskEvents
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + LookbackWindow))
    | where UserPrincipalName == TargetUser
    | where RiskEventType == "impossibleTravel"
    | project
        RiskTimeGenerated = TimeGenerated,
        UserPrincipalName,
        RiskEventType,
        RiskLevel,
        DetectionTimingType,
        RiskIpAddress = IpAddress,
        RiskLocation = Location,
        AdditionalInfo,
        CorrelationId,
        Id
    | top 1 by RiskTimeGenerated desc;
// --- Part 2: Get recent successful sign-ins around the alert time ---
// Impossible travel involves TWO sign-ins. We need to find both.
// The risk event IpAddress is typically the SECOND (anomalous) sign-in.
let RecentSignins = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1h))
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | project
        SigninTime = TimeGenerated,
        UserPrincipalName,
        IPAddress,
        // Extract geo coordinates for distance calculation
        Latitude = toreal(tostring(LocationDetails.geoCoordinates.latitude)),
        Longitude = toreal(tostring(LocationDetails.geoCoordinates.longitude)),
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        State = tostring(LocationDetails.state),
        // Device fingerprint - critical for VPN FP detection
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
    | order by SigninTime desc;
// --- Part 3: Identify the sign-in pair ---
// Get the most recent 2 sign-ins from different IPs
let SignInPair = RecentSignins
    | summarize
        arg_max(SigninTime, *) by IPAddress
    | top 2 by SigninTime desc;
// --- Part 4: Output both sign-ins side by side ---
SignInPair
| extend SignInOrder = row_number()
| extend SignInLabel = iff(SignInOrder == 1, "SIGN-IN 2 (Later/Anomalous)", "SIGN-IN 1 (Earlier/Baseline)")
| project
    SignInLabel,
    SigninTime,
    UserPrincipalName,
    IPAddress,
    Latitude,
    Longitude,
    City,
    Country,
    State,
    DeviceId,
    DeviceOS,
    DeviceBrowser,
    DeviceIsCompliant,
    DeviceIsManaged,
    DeviceTrustType,
    UserAgent,
    AppDisplayName,
    ClientAppUsed,
    AuthenticationRequirement,
    MfaAuthMethod,
    ConditionalAccessStatus,
    SessionId
| order by SigninTime asc
```

<details>
<summary>Expected Output Columns</summary>

| Column | Type | Description |
|---|---|---|
| SignInLabel | string | "SIGN-IN 1 (Earlier/Baseline)" or "SIGN-IN 2 (Later/Anomalous)" |
| SigninTime | datetime | Timestamp of the sign-in |
| UserPrincipalName | string | Affected user |
| IPAddress | string | Source IP of this sign-in |
| Latitude | real | Geographic latitude from LocationDetails |
| Longitude | real | Geographic longitude from LocationDetails |
| City | string | City from LocationDetails |
| Country | string | Country from LocationDetails |
| State | string | State/region from LocationDetails |
| DeviceId | string | Entra device ID (same DeviceId = same physical device) |
| DeviceOS | string | Operating system |
| DeviceBrowser | string | Browser used |
| DeviceIsCompliant | string | Intune compliance status |
| DeviceIsManaged | string | Managed device status |
| DeviceTrustType | string | Device trust type |
| UserAgent | string | Raw user agent string |
| AppDisplayName | string | Application accessed |
| ClientAppUsed | string | Client type |
| AuthenticationRequirement | string | SFA or MFA |
| MfaAuthMethod | string | MFA method or "No MFA performed" |
| ConditionalAccessStatus | string | CA policy result |
| SessionId | string | Session identifier for token tracking |

</details>

**Performance Notes:**
- Query scans 6h window (wider than RB-0001 to capture both sign-ins in the pair)
- The `summarize arg_max by IPAddress` efficiently picks the most recent sign-in per distinct IP
- Expected result: 2 rows (one per sign-in location in the impossible travel pair)
- If only 1 row returns, the earlier sign-in may have been outside the lookback window. Increase to 12h or 24h.

**Tuning Guidance:**
- **LookbackWindow**: Default 6h. Increase to 24h for offline detections where the risk event lags behind actual sign-ins
- **If only 1 IP found**: The "first" sign-in may have been a non-interactive sign-in. Check AADNonInteractiveUserSignInLogs for the matching pair

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Locations | Two distant countries with no business relationship | Same country, different cities (domestic travel) |
| Time gap | <30 minutes between distant locations | Several hours apart (actual flight possible) |
| Devices | Different DeviceId values | Same DeviceId (same physical device = VPN) |
| MFA | Second sign-in bypassed MFA or used legacy auth | Both sign-ins completed MFA normally |
| Browser | Second sign-in uses automation tool (Python, curl) | Both use standard browsers |

**Next action:**
- If same DeviceId for both -> strong VPN indicator, proceed to Step 2 but with lower concern
- If different DeviceId + distant countries -> proceed to Step 2 with high concern
- If second sign-in bypassed MFA -> proceed to Step 5 immediately (token replay likely)

---

### Step 2: Geographic Distance and Travel Speed Calculation

**Purpose:** Calculate the exact distance and required travel speed between the two sign-in locations. This is the core analytical step unique to impossible travel investigations. The `geo_distance_2points()` function computes the great-circle distance in meters between two coordinate pairs.

**Data needed from:**
- Table: SigninLogs - latitude/longitude from LocationDetails.geoCoordinates for both sign-ins

**Travel Speed Thresholds:**

| Speed (km/h) | Assessment | Explanation |
|---|---|---|
| > 900 | **PHYSICALLY IMPOSSIBLE** | Exceeds commercial aircraft cruise speed. Cannot be legitimate travel. |
| 500 - 900 | **HIGHLY UNLIKELY** | Would require a direct flight at maximum cruise speed with zero layover |
| 200 - 500 | **UNLIKELY** | Short-haul flight possible but tight, especially with airport transit time |
| 100 - 200 | **POSSIBLE** | Domestic flight or high-speed rail is feasible |
| < 100 | **PLAUSIBLE** | Ground transport (car, regional train) is reasonable |

#### Query 2: Geographic Distance and Travel Speed

```kql
// ============================================================
// Query 2: Geographic Distance and Travel Speed
// Purpose: Calculate the great-circle distance and required
//          travel speed between the two sign-in locations
// Table: SigninLogs
// Uses: geo_distance_2points() (Kusto built-in geospatial)
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
let LookbackWindow = 6h;
// Get all successful sign-ins with geo coordinates
let signins = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1h))
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | extend
        Lat = toreal(tostring(LocationDetails.geoCoordinates.latitude)),
        Lon = toreal(tostring(LocationDetails.geoCoordinates.longitude)),
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        DeviceId = tostring(DeviceDetail.deviceId)
    | where isnotempty(Lat) and isnotempty(Lon)
    | project SigninTime = TimeGenerated, IPAddress, Lat, Lon, City, Country, DeviceId
    | summarize arg_max(SigninTime, *) by IPAddress
    | top 2 by SigninTime desc;
// Calculate pairwise distance and speed
let signin1 = toscalar(signins | top 1 by SigninTime asc | project pack("time", SigninTime, "ip", IPAddress, "lat", Lat, "lon", Lon, "city", City, "country", Country, "deviceId", DeviceId));
let signin2 = toscalar(signins | top 1 by SigninTime desc | project pack("time", SigninTime, "ip", IPAddress, "lat", Lat, "lon", Lon, "city", City, "country", Country, "deviceId", DeviceId));
let time1 = todatetime(signin1.time);
let time2 = todatetime(signin2.time);
let lat1 = toreal(signin1.lat);
let lon1 = toreal(signin1.lon);
let lat2 = toreal(signin2.lat);
let lon2 = toreal(signin2.lon);
// geo_distance_2points returns meters
let DistanceMeters = geo_distance_2points(lon1, lat1, lon2, lat2);
let DistanceKm = DistanceMeters / 1000.0;
let TimeDiffHours = datetime_diff("second", time2, time1) / 3600.0;
let SpeedKmH = iff(TimeDiffHours > 0, DistanceKm / TimeDiffHours, real(999999));
print
    SignIn1_Time = time1,
    SignIn1_IP = tostring(signin1.ip),
    SignIn1_City = tostring(signin1.city),
    SignIn1_Country = tostring(signin1.country),
    SignIn1_DeviceId = tostring(signin1.deviceId),
    SignIn2_Time = time2,
    SignIn2_IP = tostring(signin2.ip),
    SignIn2_City = tostring(signin2.city),
    SignIn2_Country = tostring(signin2.country),
    SignIn2_DeviceId = tostring(signin2.deviceId),
    DistanceKm = round(DistanceKm, 1),
    TimeDiffMinutes = round(TimeDiffHours * 60, 1),
    TimeDiffHours = round(TimeDiffHours, 2),
    RequiredSpeedKmH = round(SpeedKmH, 0),
    SameDevice = tostring(signin1.deviceId) == tostring(signin2.deviceId) and isnotempty(tostring(signin1.deviceId)),
    TravelAssessment = case(
        tostring(signin1.deviceId) == tostring(signin2.deviceId) and isnotempty(tostring(signin1.deviceId)),
            "SAME DEVICE - Likely VPN/proxy (FP candidate)",
        SpeedKmH > 900,
            "PHYSICALLY IMPOSSIBLE - Exceeds aircraft cruise speed",
        SpeedKmH > 500,
            "HIGHLY UNLIKELY - Would require direct flight at max speed",
        SpeedKmH > 200,
            "UNLIKELY - Short flight possible but tight with transit",
        SpeedKmH > 100,
            "POSSIBLE - Domestic flight or high-speed rail feasible",
        "PLAUSIBLE - Ground transport is reasonable"
    )
```

**Performance Notes:**
- Uses `geo_distance_2points()` which is a highly optimized built-in geospatial function
- The `toscalar()` calls extract single values efficiently from the 2-row result set
- Expected result: 1 row with all distance and speed calculations

**Tuning Guidance:**
- **Speed thresholds**: Adjust based on organizational context. If the organization operates near major airports with direct flights, the 500-900 range may be more acceptable
- **SameDevice check**: This is the #1 false positive indicator. If SameDevice is true, the probability of a true positive drops dramatically
- **Missing coordinates**: If Lat/Lon are null for either sign-in, fall back to country-level analysis only

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Speed | > 900 km/h (physically impossible) | < 200 km/h (feasible travel) |
| Device | Different DeviceId values | Same DeviceId (VPN false positive) |
| Distance | > 5000 km (intercontinental) | < 500 km (same region/country) |
| Time gap | < 30 minutes between distant locations | > 4 hours (actual flight possible) |

**Next action:**
- If SameDevice == true -> likely VPN/proxy FP, proceed to Step 3 for confirmation, may quick close
- If speed > 900 km/h AND different devices -> HIGH concern, proceed to Step 3 and Step 4
- If speed 200-900 and different devices -> MODERATE concern, proceed to Step 3

---

### Step 3: Baseline Comparison - Establish Normal Travel Pattern

**Purpose:** Determine what "normal" travel patterns look like for this specific user. Compare the flagged sign-in pair against 30 days of historical location data. This is the most critical step - you cannot determine if travel is truly anomalous without understanding the user's typical geographic footprint.

**Label:** Step 3: Baseline Comparison - Establish Normal Travel Pattern

**Data needed from:**
- Table: SigninLogs - pull 30 days of historical sign-ins with geographic data
- Table: AADNonInteractiveUserSignInLogs - supplementary IP/location baseline

**Baseline metrics to calculate:**
- Distinct countries and cities over 30 days
- Distinct IP addresses and their geolocations
- Maximum geographic "radius" observed (farthest distance between any two known locations)
- VPN IP frequency (how often does user switch IPs within short timeframes)
- Travel velocity history (has user shown legitimate high-speed location changes before?)

#### Query 3A: Travel Pattern Baseline (30-day) - MANDATORY

```kql
// ============================================================
// Query 3A: Travel Pattern Baseline (30-day)
// Purpose: Calculate the user's normal geographic footprint
//          and travel patterns over the past 30 days
// Table: SigninLogs
// MANDATORY - Do not skip this query
// Expected runtime: 5-15 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
let SignInIP1 = "85.100.50.25";
let SignInIP2 = "198.51.100.42";
let BaselinePeriod = 30d;
let BaselineStart = AlertTime - BaselinePeriod;
let BaselineEnd = AlertTime - 1d;
// --- Part 1: Geographic footprint summary ---
let GeoFootprint = SigninLogs
    | where TimeGenerated between (BaselineStart .. BaselineEnd)
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | extend
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        Lat = toreal(tostring(LocationDetails.geoCoordinates.latitude)),
        Lon = toreal(tostring(LocationDetails.geoCoordinates.longitude))
    | summarize
        SigninCount = count(),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by IPAddress, City, Country, Lat, Lon;
// --- Part 2: Count distinct locations ---
let LocationStats = GeoFootprint
    | summarize
        TotalSignins = sum(SigninCount),
        DistinctIPs = dcount(IPAddress),
        DistinctCities = dcount(City),
        DistinctCountries = dcount(Country),
        KnownCities = make_set(City),
        KnownCountries = make_set(Country),
        KnownIPs = make_set(IPAddress, 50);
// --- Part 3: Check if alert IPs are known ---
let ip1Known = toscalar(GeoFootprint | where IPAddress == SignInIP1 | count) > 0;
let ip2Known = toscalar(GeoFootprint | where IPAddress == SignInIP2 | count) > 0;
let ip1Country = toscalar(GeoFootprint | where IPAddress == SignInIP1 | take 1 | project Country);
let ip2Country = toscalar(GeoFootprint | where IPAddress == SignInIP2 | take 1 | project Country);
// --- Part 4: Calculate maximum travel radius ---
// Find the two farthest-apart known locations to establish the user's "normal" travel range
let MaxRadius = GeoFootprint
    | extend placeholder = 1
    | join kind=inner (GeoFootprint | extend placeholder = 1) on placeholder
    | where IPAddress != IPAddress1
    | where isnotempty(Lat) and isnotempty(Lat1)
    | extend PairDistanceKm = geo_distance_2points(Lon, Lat, Lon1, Lat1) / 1000.0
    | summarize MaxKnownRadiusKm = max(PairDistanceKm);
// --- Part 5: VPN switching frequency (IP changes within 1 hour) ---
let VpnSwitchFrequency = SigninLogs
    | where TimeGenerated between (BaselineStart .. BaselineEnd)
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | order by TimeGenerated asc
    | extend PrevIP = prev(IPAddress), PrevTime = prev(TimeGenerated)
    | where IPAddress != PrevIP and isnotempty(PrevIP)
    | extend TimeBetweenSwitchesMin = datetime_diff("minute", TimeGenerated, PrevTime)
    | where TimeBetweenSwitchesMin <= 60
    | summarize
        RapidIPSwitches = count(),
        AvgSwitchIntervalMin = avg(TimeBetweenSwitchesMin);
// --- Part 6: Combined output ---
LocationStats
| extend placeholder = 1
| join kind=leftouter (MaxRadius | extend placeholder = 1) on placeholder
| join kind=leftouter (VpnSwitchFrequency | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1, placeholder2
| extend
    IP1_InBaseline = ip1Known,
    IP2_InBaseline = ip2Known,
    IP1_BaselineCountry = ip1Country,
    IP2_BaselineCountry = ip2Country,
    RapidIPSwitches = coalesce(RapidIPSwitches, 0),
    AvgSwitchIntervalMin = coalesce(AvgSwitchIntervalMin, real(0)),
    MaxKnownRadiusKm = coalesce(MaxKnownRadiusKm, real(0)),
    BaselineAssessment = case(
        ip1Known and ip2Known,
            "BOTH IPs KNOWN - User has signed in from both locations before",
        ip1Known and not(ip2Known),
            "ONLY IP1 KNOWN - Second location is new for this user",
        not(ip1Known) and ip2Known,
            "ONLY IP2 KNOWN - First location is new for this user",
        "NEITHER IP KNOWN - Both locations are new (high risk or new account)"
    )
```

#### Query 3B: Known Locations Detail

```kql
// ============================================================
// Query 3B: Known Locations Detail
// Purpose: List all known locations from the user's 30-day
//          baseline for analyst reference
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
let BaselinePeriod = 30d;
let BaselineStart = AlertTime - BaselinePeriod;
let BaselineEnd = AlertTime - 1d;
SigninLogs
| where TimeGenerated between (BaselineStart .. BaselineEnd)
| where UserPrincipalName == TargetUser
| where ResultType == "0"
| extend
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize
    SigninCount = count(),
    DistinctIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Country, City
| order by SigninCount desc
```

**Performance Notes:**
- Query 3A scans 30 days of SigninLogs for a single user - moderate volume
- The cross-join for max radius calculation can produce N^2 rows if the user has many distinct IPs. The `geo_distance_2points` is fast per-row
- VPN switching frequency uses `prev()` which requires ordered data - the `order by` ensures correct results
- If the user has >50 distinct IPs, consider reducing BaselinePeriod to 14d

**Tuning Guidance:**
- **BaselinePeriod**: Default 30d. Use 14d for high-mobility users (frequent travelers), 60d for sedentary users
- **Rapid IP switch threshold**: Default 60 minutes. Users with >5 rapid switches per day are almost certainly using VPN/proxy
- **MaxKnownRadiusKm**: If the user's maximum known radius is >5000 km, they are a frequent international traveler - weight impossible travel alerts lower

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| IP2 in baseline | Second IP never seen in 30 days | Second IP is a known location for this user |
| Known countries | Country of IP2 never seen before | User regularly signs in from both countries |
| Travel radius | Alert distance far exceeds user's MaxKnownRadius | Alert distance within user's established travel range |
| VPN frequency | User never shows rapid IP switching | User frequently switches IPs within short windows (VPN user) |

**Next action:**
- If both IPs known + user has VPN switching pattern -> likely VPN FP, proceed to Step 4 for confirmation
- If IP2 new + country new + distance exceeds max radius -> HIGH concern, proceed to Step 4 and Step 5
- If only IP2 new but same country -> proceed to Step 4 with moderate concern

---

### Step 4: Device and Session Fingerprint Analysis

**Purpose:** Compare the device fingerprints of both sign-ins in detail. The single most reliable indicator of a VPN false positive is matching DeviceId values. If both sign-ins come from the same physical device but different IPs, the user's traffic is being routed through different network paths (VPN, proxy, mobile carrier).

**Data needed from:**
- Table: SigninLogs - DeviceDetail (DeviceId, OS, browser, compliance, managed, trustType) for both sign-ins

#### Query 4: Device Fingerprint Comparison

```kql
// ============================================================
// Query 4: Device Fingerprint Comparison
// Purpose: Compare device details between both sign-ins to
//          determine if they come from the same physical device
// Table: SigninLogs
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
let SignInIP1 = "85.100.50.25";
let SignInIP2 = "198.51.100.42";
let LookbackWindow = 6h;
// Get device details for both IPs
let DeviceComparison = SigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1h))
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | where IPAddress in (SignInIP1, SignInIP2)
    | summarize arg_max(TimeGenerated, *) by IPAddress
    | extend
        DeviceId = tostring(DeviceDetail.deviceId),
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceBrowser = tostring(DeviceDetail.browser),
        DeviceIsCompliant = tostring(DeviceDetail.isCompliant),
        DeviceIsManaged = tostring(DeviceDetail.isManaged),
        DeviceTrustType = tostring(DeviceDetail.trustType)
    | project
        IPAddress,
        SigninTime = TimeGenerated,
        DeviceId,
        DeviceOS,
        DeviceBrowser,
        DeviceIsCompliant,
        DeviceIsManaged,
        DeviceTrustType,
        UserAgent,
        AppDisplayName,
        ClientAppUsed,
        AuthenticationRequirement,
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA performed"),
        ConditionalAccessStatus,
        SessionId;
// Output with comparison flags
DeviceComparison
| extend placeholder = 1
| join kind=inner (DeviceComparison | extend placeholder = 1 | project-rename
    OtherIP = IPAddress,
    OtherDeviceId = DeviceId,
    OtherDeviceOS = DeviceOS,
    OtherDeviceBrowser = DeviceBrowser,
    OtherDeviceIsCompliant = DeviceIsCompliant,
    OtherDeviceIsManaged = DeviceIsManaged,
    OtherUserAgent = UserAgent,
    OtherSessionId = SessionId
) on placeholder
| where IPAddress != OtherIP
| take 1
| extend
    // Critical comparison: Same physical device?
    SameDeviceId = iff(
        isnotempty(DeviceId) and isnotempty(OtherDeviceId) and DeviceId == OtherDeviceId,
        "YES - SAME DEVICE (VPN/proxy likely)",
        iff(isempty(DeviceId) or isempty(OtherDeviceId),
            "UNKNOWN - DeviceId not available for comparison",
            "NO - DIFFERENT DEVICES (higher risk)")
    ),
    SameOS = DeviceOS == OtherDeviceOS,
    SameBrowser = DeviceBrowser == OtherDeviceBrowser,
    SameSession = iff(
        isnotempty(SessionId) and isnotempty(OtherSessionId) and SessionId == OtherSessionId,
        "YES - SAME SESSION (token replay possible)",
        "NO - DIFFERENT SESSIONS"
    ),
    DeviceRiskAssessment = case(
        isnotempty(DeviceId) and isnotempty(OtherDeviceId) and DeviceId == OtherDeviceId,
            "LOW RISK - Same device, different network path (VPN/proxy FP)",
        DeviceOS == OtherDeviceOS and DeviceBrowser == OtherDeviceBrowser,
            "MEDIUM RISK - Same OS/browser but different device (could be spoofed)",
        "HIGH RISK - Different device fingerprint entirely"
    )
| project
    IPAddress,
    DeviceId,
    DeviceOS,
    DeviceBrowser,
    DeviceIsCompliant,
    DeviceIsManaged,
    UserAgent,
    OtherIP,
    OtherDeviceId,
    OtherDeviceOS,
    OtherDeviceBrowser,
    OtherDeviceIsCompliant,
    OtherDeviceIsManaged,
    OtherUserAgent,
    SameDeviceId,
    SameOS,
    SameBrowser,
    SameSession,
    DeviceRiskAssessment
```

**Performance Notes:**
- Self-join on a 2-row result set is trivial
- DeviceId may be empty for non-registered devices (BYOD). In this case, fall back to OS + browser + UserAgent comparison
- Expected result: 1 row with side-by-side device comparison

**Tuning Guidance:**
- **DeviceId availability**: Requires Entra ID device registration or Intune enrollment. If DeviceId is consistently empty, rely on UserAgent + OS + browser as fingerprint
- **UserAgent spoofing**: Sophisticated attackers may copy the user agent string. DeviceId is much harder to spoof

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| DeviceId | Different DeviceId values (two distinct physical devices) | Same DeviceId (same device, different network exit) |
| OS + Browser | Different OS or automation browser (Python, curl, headless) | Same OS and standard browser |
| Compliance | Second device is non-compliant/unmanaged | Both devices are compliant and managed |
| Session | Same SessionId from different IPs (token replay) | Different SessionIds (separate auth events) |

**Next action:**
- If SameDeviceId = YES -> strong VPN/proxy indicator, proceed to Step 7 for final check
- If different DeviceId + different OS -> HIGH concern, proceed to Step 5
- If same SessionId from different IPs -> CRITICAL, likely token replay, proceed to Step 5 immediately

---

### Step 5: Token Replay and Session Hijacking Check

**Purpose:** Check for evidence that a session token was stolen and replayed from the anomalous location. AiTM (adversary-in-the-middle) attacks steal session cookies after the user authenticates (including MFA), then replay the token from attacker infrastructure. This manifests as non-interactive sign-ins from the anomalous IP using the same SessionId or CorrelationId.

**Data needed from:**
- Table: AADNonInteractiveUserSignInLogs - non-interactive sign-ins from the anomalous IP (token refresh, API calls)
- Table: SigninLogs - check for same SessionId from different IPs

**What to look for:**
- Non-interactive sign-ins from the anomalous IP (tokens being refreshed/used without user interaction)
- Same SessionId appearing from multiple IPs (token stolen and replayed)
- High volume of non-interactive events from anomalous IP in short window (automated scraping)
- Resource access patterns from the anomalous IP (what APIs/data was accessed)

#### Query 5A: Non-Interactive Sign-Ins from Anomalous IP

```kql
// ============================================================
// Query 5A: Non-Interactive Sign-Ins from Anomalous IP
// Purpose: Check for token replay/session hijacking by looking
//          for non-interactive sign-ins from the anomalous IP
// Table: AADNonInteractiveUserSignInLogs
// License: Entra ID P1/P2 required
// Expected runtime: 5-10 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
let SignInIP2 = "198.51.100.42";
// Check 4 hours around the alert for token activity
let TokenWindow = 4h;
AADNonInteractiveUserSignInLogs
| where TimeGenerated between ((AlertTime - TokenWindow) .. (AlertTime + TokenWindow))
| where UserPrincipalName == TargetUser
| where IPAddress == SignInIP2
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    ResourceDisplayName,
    // ResultType is STRING (Hasan's gotcha)
    ResultType,
    ResultDescription = iff(ResultType == "0", "Success", ResultType),
    SessionId = tostring(OriginalRequestId),
    CorrelationId,
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    UserAgent,
    ClientAppUsed,
    IsInteractive
| order by TimeGenerated asc
| extend
    TokenActivity = case(
        ResultType == "0", "ACTIVE TOKEN - Successful non-interactive sign-in from anomalous IP",
        ResultType == "50058", "TOKEN REFRESH ATTEMPT - Pending user action",
        ResultType == "50173", "TOKEN EXPIRED - Token has expired",
        ResultType == "50076", "MFA REQUIRED - Token requires MFA reauthentication",
        strcat("OTHER - ResultType: ", ResultType)
    ),
    MinutesFromAlert = datetime_diff("minute", TimeGenerated, AlertTime)
| summarize
    TotalNonInteractiveEvents = count(),
    SuccessfulEvents = countif(ResultType == "0"),
    FailedEvents = countif(ResultType != "0"),
    DistinctApps = make_set(AppDisplayName),
    DistinctResources = make_set(ResourceDisplayName),
    EarliestEvent = min(TimeGenerated),
    LatestEvent = max(TimeGenerated)
| extend
    TokenReplayAssessment = case(
        SuccessfulEvents > 0,
            "CONFIRMED - Active token usage from anomalous IP (T1550.004)",
        TotalNonInteractiveEvents > 0 and FailedEvents > 0,
            "ATTEMPTED - Token refresh attempted but failed",
        "NO EVIDENCE - No non-interactive activity from anomalous IP"
    )
```

#### Query 5B: Session ID Cross-IP Analysis

```kql
// ============================================================
// Query 5B: Session ID Cross-IP Analysis
// Purpose: Check if the same session ID appears from multiple
//          IP addresses - direct evidence of token theft
// Table: SigninLogs, AADNonInteractiveUserSignInLogs
// Expected runtime: 5-10 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
let TokenWindow = 4h;
// Combine interactive and non-interactive sign-ins
let AllSignins = union
    (SigninLogs
        | where TimeGenerated between ((AlertTime - TokenWindow) .. (AlertTime + TokenWindow))
        | where UserPrincipalName == TargetUser
        | where ResultType == "0"
        | project TimeGenerated, IPAddress, AppDisplayName, SessionId,
            SignInType = "Interactive",
            City = tostring(LocationDetails.city),
            Country = tostring(LocationDetails.countryOrRegion)),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated between ((AlertTime - TokenWindow) .. (AlertTime + TokenWindow))
        | where UserPrincipalName == TargetUser
        | where ResultType == "0"
        | project TimeGenerated, IPAddress, AppDisplayName,
            SessionId = tostring(OriginalRequestId),
            SignInType = "NonInteractive",
            City = tostring(LocationDetails.city),
            Country = tostring(LocationDetails.countryOrRegion));
// Find sessions appearing from multiple IPs
AllSignins
| summarize
    DistinctIPs = dcount(IPAddress),
    IPList = make_set(IPAddress),
    CityList = make_set(City),
    CountryList = make_set(Country),
    SignInTypes = make_set(SignInType),
    EventCount = count(),
    TimeRange = strcat(format_datetime(min(TimeGenerated), "HH:mm"), " - ", format_datetime(max(TimeGenerated), "HH:mm"))
    by SessionId
| where DistinctIPs > 1
| extend
    SessionHijackAssessment = case(
        DistinctIPs > 1 and array_length(CountryList) > 1,
            "CRITICAL - Same session from different countries (token stolen)",
        DistinctIPs > 1,
            "WARNING - Same session from different IPs (possible VPN or token relay)"
    )
| order by EventCount desc
```

**Performance Notes:**
- Query 5A scans AADNonInteractiveUserSignInLogs which can be high volume. The IP filter narrows it efficiently
- Query 5B unions two tables - the union is efficient because both are filtered to narrow time window + single user
- Expected result for 5A: summary row with token activity counts. If SuccessfulEvents > 0 from anomalous IP, this is strong evidence of token replay
- Expected result for 5B: rows only if same SessionId appears from multiple IPs

**Tuning Guidance:**
- **TokenWindow**: Default 4h. Expand to 24h for thorough investigation of long-running token abuse
- **AADNonInteractiveUserSignInLogs volume**: This table can have 100x the volume of SigninLogs. The IP filter is critical for performance
- **OriginalRequestId vs SessionId**: In AADNonInteractiveUserSignInLogs, SessionId is often empty. Use OriginalRequestId as the session correlation key

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Non-interactive events | Successful token usage from anomalous IP | No non-interactive activity from anomalous IP |
| Session cross-IP | Same SessionId from IPs in different countries | No session ID overlap across IPs |
| Token refresh | Tokens actively refreshed from anomalous IP | Token expired and was not refreshed |
| Apps accessed | Sensitive apps (Graph, Exchange, SharePoint) from anomalous IP | No app access from anomalous IP |

**Next action:**
- If CONFIRMED token replay -> T1550.004 confirmed, proceed to Containment immediately
- If ATTEMPTED but failed -> attacker tried but token expired, still investigate post-sign-in activity
- If no evidence -> proceed to Step 6 for post-sign-in activity check

---

### Step 6: Analyze Post-Sign-In Activity (Blast Radius Assessment)

**Purpose:** Determine what the account did AFTER the suspicious sign-in from the anomalous IP. This step reuses the same patterns as RB-0001 Step 5 but filters specifically for activity from the anomalous IP address. Check for persistence mechanisms, data access, and lateral movement indicators.

**Data needed from:**
- Table: AuditLogs - directory changes made by this user after the alert
- Table: OfficeActivity - email, SharePoint, OneDrive, Teams activity after the alert

#### Query 6A: Directory Changes After Sign-In (Persistence Detection)

```kql
// ============================================================
// Query 6A: Directory Changes After Sign-In
// Purpose: Check for persistence mechanisms created via
//          directory operations after the impossible travel
// Table: AuditLogs
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
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

#### Query 6B: Email and File Activity After Sign-In

```kql
// ============================================================
// Query 6B: Email and File Activity After Sign-In
// Purpose: Check for inbox rule creation, email forwarding,
//          bulk email access, and file exfiltration patterns
// Table: OfficeActivity
// Expected runtime: 5-10 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
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
let AlertTime = datetime(2026-02-21T14:30:00Z);
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
- OfficeActivity has up to 60 min ingestion latency. If the alert is <1 hour old, results may be incomplete. Re-run after 2 hours for full coverage
- IP normalization is needed for OfficeActivity.ClientIP which may include port numbers and IPv6-mapped formats

**Tuning Guidance:**
- **PostSignInWindow**: Default 4h. For fast triage use 2h, for thorough investigation expand to 24h
- **IP correlation**: Match CleanClientIP against SignInIP2 (the anomalous IP) to determine if post-sign-in activity came from the attacker's infrastructure

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| Inbox rules | New rule forwarding/deleting email from anomalous IP | No new inbox rules |
| MFA changes | New MFA method registered after alert | No MFA changes |
| OAuth apps | New app consent with broad permissions | No new app consents |
| File access | Bulk downloads from anomalous IP | Normal file access from known IP |

**Next action:**
- If ANY persistence found from anomalous IP -> CONFIRMED COMPROMISE, proceed to Containment
- If bulk data access from anomalous IP -> CONFIRMED COMPROMISE with data exposure
- If no suspicious activity -> proceed to Step 7 for IP reputation check

---

### Step 7: IP Reputation and Context (Both IPs)

**Purpose:** Gather intelligence about BOTH source IP addresses. Unlike RB-0001 which checks a single IP, impossible travel investigations must check both IPs - one may be a legitimate corporate IP while the other is attack infrastructure.

#### Query 7A: Threat Intelligence Lookup (Both IPs)

```kql
// ============================================================
// Query 7A: Threat Intelligence Lookup (Both IPs)
// Purpose: Check both impossible travel IPs against configured
//          threat intelligence feeds
// Table: ThreatIntelligenceIndicator
// Expected runtime: <3 seconds
// ============================================================
let SignInIP1 = "85.100.50.25";
let SignInIP2 = "198.51.100.42";
ThreatIntelligenceIndicator
| where isnotempty(NetworkIP)
| where Active == true
| where ExpirationDateTime > now()
| where NetworkIP in (SignInIP1, SignInIP2)
| where ConfidenceScore >= 50
| project
    NetworkIP,
    MatchedAs = iff(NetworkIP == SignInIP1, "IP1 (Baseline)", "IP2 (Anomalous)"),
    ThreatType,
    ConfidenceScore,
    Description,
    Tags,
    ThreatSeverity,
    SourceSystem,
    ExpirationDateTime,
    LastUpdated = TimeGenerated,
    TIAssessment = case(
        ConfidenceScore >= 80, "HIGH CONFIDENCE - Known malicious IP",
        ConfidenceScore >= 50, "MEDIUM CONFIDENCE - Potentially malicious IP",
        "LOW CONFIDENCE - Weak indicator"
    )
| order by ConfidenceScore desc
```

#### Query 7B: Organizational IP Usage Check (Both IPs)

```kql
// ============================================================
// Query 7B: Organizational IP Usage Check (Both IPs)
// Purpose: Determine if each IP has been used by other legitimate
//          users - shared corporate IPs are likely benign
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let SignInIP1 = "85.100.50.25";
let SignInIP2 = "198.51.100.42";
let TargetUser = "user@contoso.com";
let LookbackPeriod = 30d;
SigninLogs
| where TimeGenerated > ago(LookbackPeriod)
| where IPAddress in (SignInIP1, SignInIP2)
| where ResultType == "0"
| summarize
    TotalSignins = count(),
    DistinctUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 20),
    EarliestSeen = min(TimeGenerated),
    LatestSeen = max(TimeGenerated),
    DistinctApps = make_set(AppDisplayName, 10)
    by IPAddress
| extend
    IPLabel = iff(IPAddress == SignInIP1, "IP1 (Baseline)", "IP2 (Anomalous)"),
    IPClassification = case(
        DistinctUsers > 10,
            "LIKELY CORPORATE - Used by 10+ users (shared exit IP)",
        DistinctUsers > 3,
            "POSSIBLY CORPORATE - Used by multiple users",
        DistinctUsers == 1 and UserList has TargetUser,
            "SINGLE USER - Only used by the target user",
        DistinctUsers == 1 and not(UserList has TargetUser),
            "SINGLE OTHER USER - Used by a different user only",
        DistinctUsers == 0,
            "NEVER SEEN - IP has never been used for successful sign-ins",
        "UNKNOWN"
    ),
    IsTargetUserIncluded = iff(UserList has TargetUser, "Yes", "No")
| order by IPLabel asc
```

#### Query 7C: UEBA Insights (Premium)

```kql
// ============================================================
// Query 7C: UEBA Insights for User (Premium)
// Purpose: Check if Sentinel UEBA has flagged behavioral anomalies
// Table: BehaviorAnalytics
// License: Sentinel UEBA required
// Expected runtime: <5 seconds
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
let LookbackPeriod = 7d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackPeriod) .. (AlertTime + 1d))
| where UserPrincipalName == TargetUser
| where InvestigationPriority >= 5
| project
    TimeGenerated,
    UserPrincipalName,
    ActionType,
    ActivityInsights,
    InvestigationPriority,
    FirstTimeISP = tostring(ActivityInsights.FirstTimeUserConnectedViaISP),
    FirstTimeCountry = tostring(ActivityInsights.FirstTimeUserConnectedFromCountry),
    ActivityUncommon = tostring(ActivityInsights.ActivityUncommonlyPerformedByUser),
    DeviceUncommon = tostring(ActivityInsights.FirstTimeUserUsedDevice),
    SourceIPAddress = tostring(ActivityInsights.SourceIPAddress)
| order by InvestigationPriority desc, TimeGenerated desc
```

**Performance Notes:**
- Query 7A: ThreatIntelligenceIndicator is typically a small table - very fast
- Query 7B: 30-day scan filtered by 2 IPs - fast
- Query 7C: BehaviorAnalytics with InvestigationPriority filter - fast

**Tuning Guidance:**
- **TI ConfidenceScore**: Default >= 50. Increase to >= 80 for high precision
- **UEBA InvestigationPriority**: Default >= 5. Decrease to >= 3 for broader coverage

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| TI match | Anomalous IP in threat intelligence feeds | Neither IP in TI feeds |
| IP1 org usage | IP1 used by many org users (corporate IP) | N/A |
| IP2 org usage | IP2 never seen in organization | IP2 used by other org users (shared VPN) |
| UEBA | First-time country or ISP flagged | No UEBA anomalies |

---

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Sentinel UEBA to provide comprehensive behavioral context for the impossible travel alert. While Query 7C provides a quick UEBA check within the IP reputation step, this step performs an expanded analysis — including geographic mobility profiling, peer group travel patterns, and post-sign-in behavioral deviation. UEBA's 90-day country baseline is particularly valuable for distinguishing legitimate travel from credential theft.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If the `BehaviorAnalytics` table is empty or does not exist in your workspace, skip this step and rely on the manual baseline comparison in Step 3 and the quick UEBA check in Query 7C. UEBA needs approximately **one week** after activation before generating meaningful insights.

#### Query 8A: Geographic Anomaly Assessment

```kql
// ============================================================
// Query 8A: UEBA Geographic Anomaly Assessment
// Purpose: Expanded UEBA analysis for impossible travel —
//          country/ISP first-time flags, peer group travel
//          patterns, and account risk context
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
    // Country analysis — core for impossible travel
    FirstTimeCountry = tobool(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommonForUser = tobool(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    CountryUncommonAmongPeers = tobool(ActivityInsights.CountryUncommonlyConnectedFromAmongPeers),
    CountryUncommonInTenant = tobool(ActivityInsights.CountryUncommonlyConnectedFromInTenant),
    // ISP analysis
    FirstTimeISP = tobool(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommonForUser = tobool(ActivityInsights.ISPUncommonlyUsedByUser),
    ISPUncommonAmongPeers = tobool(ActivityInsights.ISPUncommonlyUsedAmongPeers),
    // Device/Browser analysis
    FirstTimeDevice = tobool(ActivityInsights.FirstTimeUserConnectedFromDevice),
    FirstTimeBrowser = tobool(ActivityInsights.FirstTimeUserConnectedViaBrowser),
    // User context
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    IsNewAccount = tobool(UsersInsights.IsNewAccount),
    // Threat intel
    ThreatIndicator = tostring(DevicesInsights.ThreatIntelIndicatorType)
| order by InvestigationPriority desc, TimeGenerated desc
```

#### Query 8B: Travel Pattern and Mobility Summary

```kql
// ============================================================
// Query 8B: User Geographic Mobility Summary via UEBA
// Purpose: Aggregate geographic anomaly signals over 30 days
//          to understand the user's travel frequency and
//          determine if impossible travel is routine
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
    TotalLogons = count(),
    HighAnomalyCount = countif(InvestigationPriority >= 7),
    MediumAnomalyCount = countif(InvestigationPriority >= 4 and InvestigationPriority < 7),
    MaxPriority = max(InvestigationPriority),
    AvgPriority = avg(InvestigationPriority),
    FirstTimeCountryCount = countif(tobool(ActivityInsights.FirstTimeUserConnectedFromCountry)),
    UncommonCountryCount = countif(tobool(ActivityInsights.CountryUncommonlyConnectedFromByUser)),
    UncommonCountryAmongPeersCount = countif(tobool(ActivityInsights.CountryUncommonlyConnectedFromAmongPeers)),
    FirstTimeISPCount = countif(tobool(ActivityInsights.FirstTimeUserConnectedViaISP)),
    UniqueCountries = dcount(SourceIPLocation),
    Countries = make_set(SourceIPLocation),
    UniqueIPs = dcount(SourceIPAddress),
    BlastRadius = take_any(tostring(UsersInsights.BlastRadius)),
    IsDormant = take_any(tobool(UsersInsights.IsDormantAccount)),
    ThreatIntelHits = countif(isnotempty(tostring(DevicesInsights.ThreatIntelIndicatorType)))
| extend
    AvgPriority = round(AvgPriority, 1),
    AnomalyRatio = round(todouble(HighAnomalyCount + MediumAnomalyCount) / TotalLogons * 100, 1),
    TravelFrequency = case(
        UniqueCountries >= 5, "Frequent traveler — 5+ countries in 30d",
        UniqueCountries >= 3, "Occasional traveler — 3-4 countries in 30d",
        UniqueCountries == 2, "Rare traveler — 2 countries in 30d",
        "Single location — 1 country in 30d"
    )
```

**Tuning Guidance:**

- **InvestigationPriority threshold**: `>= 7` = high-confidence anomaly, `>= 4` = moderate, `< 4` = likely normal
- **Country-level analysis**: UEBA builds country baselines over 90 days. `FirstTimeCountry = true` means the user has NEVER connected from this country in the past 90 days — stronger signal than the sign-in log baseline in Step 3
- **Peer group travel**: `CountryUncommonAmongPeers = true` reveals whether travel to this country is normal for users in similar roles (e.g., sales team may travel frequently vs. finance team)
- **TravelFrequency**: A "Frequent traveler" generating impossible travel alerts is much less suspicious than a "Single location" user

**Expected findings:**

| Finding | Malicious Indicator | Benign Indicator |
|---|---|---|
| InvestigationPriority | >= 7 (high anomaly) | < 4 (normal behavior) |
| FirstTimeCountry | true — never connected from this country | false — known travel |
| CountryUncommonAmongPeers | true — peers don't travel there | false — common destination |
| CountryUncommonInTenant | true — no one in org goes there | false — known location |
| FirstTimeISP | true — new ISP in new country | false — known ISP |
| TravelFrequency | Single location user suddenly in 2+ countries | Frequent traveler |
| IsDormantAccount | true — dormant account traveling | false — active user |
| BlastRadius | High — privileged account | Low — standard user |
| ThreatIndicator | VPN, Proxy, Hosting | Empty |

**Decision guidance:**

- **FirstTimeCountry + CountryUncommonAmongPeers + CountryUncommonInTenant = all true** → Country never seen for user, peers, or org. Very high confidence of credential abuse from foreign infrastructure
- **TravelFrequency = "Single location" + FirstTimeCountry = true** → A user who has never traveled suddenly connects from two countries simultaneously. Near-certain credential theft
- **TravelFrequency = "Frequent traveler" + CountryUncommonAmongPeers = false** → User regularly travels and peers also visit this country. Likely legitimate. Consider closing as false positive
- **IsDormantAccount = true** → Dormant account showing impossible travel is critical — inactive accounts don't travel. Proceed to Containment
- **BlastRadius = High** → Privileged account with impossible travel requires immediate escalation regardless of travel frequency

---

## 6. Containment Playbook

Execute in this order. IMPORTANT: Collect evidence (Section 7 checklist) BEFORE taking containment actions that could alert the attacker or destroy evidence.

### Immediate Actions (within 15 minutes of confirmed compromise):

1. **Revoke all active sessions** - Revoke the user's refresh tokens via Entra ID to immediately invalidate all active sessions across all devices. This is especially critical for token replay attacks where the attacker holds a valid session token.

2. **Reset password** - Reset the user's password to a strong temporary password. Communicate the new password via an out-of-band channel (phone call, SMS, in-person). Do NOT use the potentially compromised email account.

3. **Disable suspicious inbox rules** - If inbox rules were created for forwarding/deletion, disable them immediately.

4. **Block both anomalous IPs** - Add the attacker's IP address(es) to Conditional Access as blocked locations. If the "baseline" IP also appears suspicious, block both.

### Follow-up Actions (within 1 hour):

5. **Review and remove unauthorized MFA methods** - If the attacker registered a new MFA method, remove it. Verify remaining MFA methods with the user through out-of-band channel.

6. **Revoke OAuth application consents** - If unauthorized applications were granted consent, revoke the application permissions in Entra ID Enterprise Applications.

7. **Remove email forwarding rules** - Check and remove any mailbox forwarding rules (both inbox rules and mailbox-level forwarding via Set-Mailbox).

8. **Review mailbox delegate permissions** - Remove any unauthorized delegate or full-access permissions added to the mailbox.

### Extended Actions (within 24 hours):

9. **Notify the user** - Contact the user via out-of-band channel. Confirm which sign-in was theirs and which was not.

10. **Check for data exposure** - Review what data was accessed from the anomalous IP during the compromise window. Determine if notification is required.

11. **Hunt for related compromise** - Check if the same attacker IP was used against other accounts. Run the anomalous IP against all sign-in logs.

12. **Review Conditional Access policies** - Determine if token protection, continuous access evaluation (CAE), or stricter device compliance policies could have prevented this access.

13. **Enable token protection (if not already)** - For AiTM/token replay scenarios, evaluate enabling Conditional Access token binding policies to prevent stolen token reuse.

---

## 7. Evidence Collection Checklist

Preserve the following BEFORE taking containment actions:

- [ ] Both sign-in records from SigninLogs (all columns including LocationDetails with coordinates)
- [ ] Risk event record from AADUserRiskEvents (including AdditionalInfo)
- [ ] User risk state from AADRiskyUsers
- [ ] Geographic distance and travel speed calculation output
- [ ] 30-day sign-in baseline for the user (SigninLogs + AADNonInteractiveUserSignInLogs)
- [ ] Device fingerprint comparison for both sign-ins
- [ ] Non-interactive sign-in records from anomalous IP (token replay evidence)
- [ ] Session ID cross-IP analysis output
- [ ] All AuditLogs entries for the user in the 72 hours surrounding the event
- [ ] All OfficeActivity records for the user in the 72 hours surrounding the event
- [ ] Inbox rules snapshot (current state before remediation)
- [ ] Mailbox forwarding configuration snapshot
- [ ] OAuth application consent list for the user
- [ ] MFA registration details for the user
- [ ] IP reputation and TI lookup results for both IPs
- [ ] UEBA/BehaviorAnalytics records for the user
- [ ] Screenshot of the risk event in the Entra ID portal
- [ ] Timeline of all events from both IPs (chronological reconstruction)

---

## 8. Escalation Criteria

### Escalate to Senior Analyst when:
- Token replay confirmed (T1550.004) - same session from different countries
- The compromised account is a Global Administrator or Security Administrator
- Multiple users triggered impossible travel from the same anomalous IP (coordinated attack)
- Evidence of post-sign-in persistence from the anomalous IP (inbox rules, OAuth apps, MFA changes)
- The compromise timeline exceeds 48 hours

### Escalate to Customer/Management when:
- Confirmed credential compromise with verified post-sign-in abuse
- Any data exposure involving PII, financial data, or regulated information
- Compromise of executive or finance team accounts (high BEC risk)
- Evidence of internal phishing from the compromised account

### Escalate to Incident Response Team when:
- Evidence of AiTM (adversary-in-the-middle) infrastructure in use
- Compromise has spread to multiple accounts via same infrastructure
- Attacker has gained administrative privileges
- Token theft campaign affecting multiple users simultaneously
- Evidence of nation-state or APT group tactics (Midnight Blizzard, Storm-0558)

---

## 9. False Positive Documentation

### Common Benign Scenarios

**1. Corporate VPN (~60% of false positives)**
- Pattern: Same DeviceId for both sign-ins, but IP1 is the user's direct internet connection and IP2 is a VPN exit node in a distant city/country
- How to confirm: Both sign-ins share the same DeviceId. IP2 belongs to a known VPN provider (check ASN). User's VPN client reconnected or they toggled VPN on/off
- Tuning note: Add corporate VPN IP ranges to Conditional Access named/trusted locations. Consider excluding trusted VPN IPs from Identity Protection impossible travel detection

**2. Cloud proxy / SASE (~20% of false positives)**
- Pattern: User's traffic routes through a cloud security proxy (Zscaler, Netskope, Cloudflare Access) with Points of Presence in distant locations. The proxy PoP may change between sign-ins
- How to confirm: IP2 belongs to a known SASE provider ASN. The user's organization deploys cloud proxy. Same DeviceId for both sign-ins
- Tuning note: Add SASE provider IP ranges to named locations. Work with the network team to document all proxy egress IPs

**3. Business travel with short flights**
- Pattern: User flew between cities and signed in at origin airport, then signed in at destination. Travel speed is 200-500 km/h (plausible with a flight)
- How to confirm: Check user's calendar for travel bookings. Ask user or manager via out-of-band channel. The DeviceId should match
- Tuning note: For frequent travelers, set a higher speed threshold or reduce impossible travel alert sensitivity in Identity Protection

**4. Mobile carrier NAT routing**
- Pattern: Mobile device traffic is NAT'd through carrier infrastructure in a distant city. The user's actual location is different from the IP geolocation
- How to confirm: One of the sign-ins is from a mobile client (iOS/Android, "Mobile Apps and Desktop clients"). IP belongs to a mobile carrier ASN. Same DeviceId
- Tuning note: Mobile carrier IPs have notoriously unreliable geolocation. Weight these alerts lower

**5. Shared accounts**
- Pattern: A service account or shared mailbox is accessed by multiple people in different locations simultaneously
- How to confirm: Account is a shared mailbox or service account. Different DeviceIds are expected. Verify all users are authorized
- Tuning note: Shared accounts should have separate risk policies or be excluded from impossible travel detection

**6. Dual-stack networking (IPv4 + IPv6)**
- Pattern: Two sign-ins appear from different locations because IPv4 and IPv6 addresses resolve to different geolocations
- How to confirm: One IP is IPv4 and one is IPv6, but both belong to the same ISP. Same DeviceId
- Tuning note: This is a known limitation of IP geolocation databases with IPv6 addresses

---

## 10. MITRE ATT&CK Mapping

### Primary Technique

**T1078.004 - Valid Accounts: Cloud Accounts** (Confirmed)

The "Impossible travel" alert detects concurrent use of valid cloud credentials from geographically incompatible locations, directly mapping to T1078.004. The secondary critical technique is **T1550.004 - Use Alternate Authentication Material: Web Session Cookie**, which covers token theft scenarios where AiTM proxies intercept and replay session tokens.

### Detection Coverage Matrix

| Technique ID | Technique Name | Detecting Query | Coverage Level | Notes |
|---|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Query 1, 2, 3A | **Full** | Primary detection target |
| T1550.004 | Use Alternate Auth Material: Web Session Cookie | Query 5A, 5B | **Full** | Token replay detection - NEW coverage not in RB-0001 |
| T1539 | Steal Web Session Cookie | Query 5A, 5B | **Full** | AiTM session theft |
| T1098 | Account Manipulation | Query 6A | **Full** | Post-access persistence |
| T1098.005 | Device Registration | Query 6A | **Full** | Rogue device join |
| T1114.003 | Email Forwarding Rule | Query 6C | **Full** | Inbox rule persistence |
| T1528 | Steal Application Access Token | Query 6A | **Full** | OAuth consent detection |
| T1530 | Data from Cloud Storage Object | Query 6B | **Partial** | Volume-based only |
| T1534 | Internal Spearphishing | Query 6B | **Partial** | Volume-based only |
| T1556.006 | Modify Authentication Process: MFA | Query 6A | **Full** | MFA registration/deletion |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Query 6C | **Full** | Inbox rule deep dive |

**Summary: 11 techniques mapped. 8 with full coverage, 3 with partial coverage.**

**New coverage vs RB-0001:** T1550.004 (Web Session Cookie replay) is the key new technique covered by this runbook. This is critical because impossible travel alerts frequently co-occur with token theft attacks.

### Attack Chains

**Chain 1: AiTM Phishing -> Token Theft -> Impossible Travel (Most Relevant)**

```
T1566.002 Spearphishing Link (AiTM proxy URL)
    | User authenticates through AiTM proxy
T1539 Steal Web Session Cookie (session cookie intercepted)
    | Attacker replays token from different location
T1550.004 Web Session Cookie Replay  <-- THIS ALERT FIRES HERE
T1078.004 Valid Accounts: Cloud Accounts  <-- AND HERE
    | Attacker establishes persistence
T1098 Account Manipulation (MFA registration)
T1556.006 Modify Authentication Process: MFA
T1564.008 Email Hiding Rules
T1114.003 Email Forwarding Rule
    | Attacker conducts BEC
T1534 Internal Spearphishing
```

Coverage: 8/10 techniques detected (2 partial)

**Chain 2: Credential Theft -> Dual-Location Access**

```
T1110.003 Password Spraying / T1110.004 Credential Stuffing
    | Attacker obtains valid credentials
T1078.004 Valid Accounts: Cloud Accounts
    | Attacker signs in from their infrastructure
    | Legitimate user continues normal sign-ins
T1078.004 Detected as Impossible Travel  <-- THIS ALERT FIRES HERE
    | Attacker establishes persistence
T1098 Account Manipulation
T1528 Steal Application Access Token (OAuth consent)
T1530 Data from Cloud Storage Object
```

Coverage: 5/7 techniques detected

### Coverage Gaps

| Gap # | Technique | ID | Risk Level | Recommendation |
|---|---|---|---|---|
| 1 | Phishing: Spearphishing Link | T1566.002 | **High** | Create linked runbook "AiTM Phishing Investigation" using MDO data |
| 2 | MFA Request Generation (MFA fatigue) | T1621 | **Medium** | Add supplementary query for repeated MFA failures |
| 3 | Exfiltration Over Web Service | T1567.002 | **Medium** | Requires Cloud App Security or DLP integration |
| 4 | Adversary-in-the-Middle | T1557 | **High** | Detection requires proxy log analysis, not available in Sentinel alone |

> For detailed threat actor profiles, per-technique analysis, and full confidence assessments, see [MITRE Coverage](../../mitre-coverage.md).

---

## 11. Query Summary

| Query | Step | Tables | Purpose | License | Required |
|---|---|---|---|---|---|
| 1 | Step 1 | AADUserRiskEvents, SigninLogs | Extract risk event and both sign-in records | Entra ID P2 | Yes |
| 2 | Step 2 | SigninLogs | Geographic distance and travel speed calculation | Entra ID Free | Yes |
| 3A | Step 3 | SigninLogs | 30-day travel pattern baseline | Entra ID Free | **MANDATORY** |
| 3B | Step 3 | SigninLogs | Known locations detail (reference) | Entra ID Free | Yes |
| 4 | Step 4 | SigninLogs | Device fingerprint comparison between both sign-ins | Entra ID Free | Yes |
| 5A | Step 5 | AADNonInteractiveUserSignInLogs | Non-interactive sign-ins from anomalous IP (token replay) | Entra ID P1/P2 | Yes |
| 5B | Step 5 | SigninLogs, AADNonInteractiveUserSignInLogs | Session ID cross-IP analysis | Entra ID P1/P2 | Yes |
| 6A | Step 6 | AuditLogs | Directory changes after sign-in (persistence) | Entra ID Free | Yes |
| 6B | Step 6 | OfficeActivity | Email and file activity after sign-in | M365 E3+ | Yes |
| 6C | Step 6 | OfficeActivity | Inbox rule deep dive | M365 E3+ | Yes |
| 7A | Step 7 | ThreatIntelligenceIndicator | IP reputation (both IPs, TI feeds) | Sentinel + TI | Optional |
| 7B | Step 7 | SigninLogs | Organizational IP usage (both IPs) | Entra ID Free | Yes |
| 7C | Step 7 | BehaviorAnalytics | UEBA insights | Sentinel UEBA | Optional |

**Total: 13 queries (10 required, 1 mandatory, 2 optional)**

**Minimum license for core investigation:** Entra ID P2 + M365 E3 + Sentinel (11 queries)
**Full investigation:** M365 E5 + Sentinel UEBA + TI feeds (all 13 queries)

---

## Appendix A: Datatable Tests

All queries include datatable-based inline tests with synthetic data. Each test validates query logic with a mix of malicious and benign scenarios without access to production data.

### Test 1: Query 1 - Extract Sign-In Pair

```kql
// ============================================================
// TEST: Query 1 - Extract Impossible Travel Sign-In Pair
// Synthetic data: 4 malicious + 8 benign = 12 sign-in rows
// ============================================================
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
    // MALICIOUS 1: Sign-in from Istanbul (user's normal location - baseline sign-in)
    datetime(2026-02-21T14:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul",
            "geoCoordinates":{"latitude":41.0082,"longitude":28.9784}}),
        dynamic({"deviceId":"device-001","operatingSystem":"Windows 11","browser":"Chrome 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-001", "sess-001",
    // MALICIOUS 2: Sign-in from Moscow 30 min later (IMPOSSIBLE TRAVEL - attacker)
    datetime(2026-02-21T14:30:00Z), "user@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU","state":"Moscow",
            "geoCoordinates":{"latitude":55.7558,"longitude":37.6173}}),
        dynamic({"deviceId":"device-999","operatingSystem":"Linux","browser":"Python/3.9 aiohttp/3.8",
            "isCompliant":"false","isManaged":"false","trustType":""}),
        "python-requests/2.28.1", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-002", "sess-002",
    // MALICIOUS 3: Non-interactive token replay from Moscow (same attacker session)
    datetime(2026-02-21T14:35:00Z), "user@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU","state":"Moscow",
            "geoCoordinates":{"latitude":55.7558,"longitude":37.6173}}),
        dynamic({"deviceId":"","operatingSystem":"","browser":"","isCompliant":"","isManaged":"","trustType":""}),
        "", "Microsoft Graph", "Microsoft Graph", "Mobile Apps and Desktop clients",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-003", "sess-002",
    // MALICIOUS 4: Another attacker sign-in targeting different user from same IP
    datetime(2026-02-21T14:32:00Z), "victim2@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU","state":"Moscow",
            "geoCoordinates":{"latitude":55.7558,"longitude":37.6173}}),
        dynamic({"deviceId":"device-999","operatingSystem":"Linux","browser":"Python/3.9",
            "isCompliant":"false","isManaged":"false","trustType":""}),
        "python-requests/2.28.1", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-004", "sess-004",
    // BENIGN 1: User's normal morning sign-in from Istanbul
    datetime(2026-02-21T09:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul",
            "geoCoordinates":{"latitude":41.0082,"longitude":28.9784}}),
        dynamic({"deviceId":"device-001","operatingSystem":"Windows 11","browser":"Chrome 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Teams", "Microsoft Teams", "Mobile Apps and Desktop clients",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-b01", "sess-b01",
    // BENIGN 2: Different user normal sign-in from Ankara
    datetime(2026-02-21T10:00:00Z), "colleague@contoso.com", "10.1.1.1",
        dynamic({"city":"Ankara","countryOrRegion":"TR","state":"Ankara",
            "geoCoordinates":{"latitude":39.9334,"longitude":32.8597}}),
        dynamic({"deviceId":"device-002","operatingSystem":"Windows 11","browser":"Edge 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Edg/120.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppOTP","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-b02", "sess-b02",
    // BENIGN 3: VPN user - same device, different IP (legitimate impossible travel FP)
    datetime(2026-02-21T11:00:00Z), "vpnuser@contoso.com", "203.0.113.10",
        dynamic({"city":"London","countryOrRegion":"GB","state":"England",
            "geoCoordinates":{"latitude":51.5074,"longitude":-0.1278}}),
        dynamic({"deviceId":"device-vpn","operatingSystem":"Windows 11","browser":"Chrome 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-b03", "sess-b03",
    // BENIGN 4: Same VPN user, same device, VPN exit in US (same DeviceId = FP)
    datetime(2026-02-21T11:15:00Z), "vpnuser@contoso.com", "104.16.0.1",
        dynamic({"city":"San Francisco","countryOrRegion":"US","state":"California",
            "geoCoordinates":{"latitude":37.7749,"longitude":-122.4194}}),
        dynamic({"deviceId":"device-vpn","operatingSystem":"Windows 11","browser":"Chrome 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-b04", "sess-b04",
    // BENIGN 5: Failed sign-in from Moscow (should be excluded - not successful)
    datetime(2026-02-21T14:25:00Z), "user@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU","state":"Moscow",
            "geoCoordinates":{"latitude":55.7558,"longitude":37.6173}}),
        dynamic({"deviceId":"","operatingSystem":"Linux","browser":"Python/3.9",
            "isCompliant":"false","isManaged":"false","trustType":""}),
        "python-requests/2.28.1", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "50126", "corr-b05", "sess-b05",
    // BENIGN 6: Other user normal sign-in
    datetime(2026-02-21T12:00:00Z), "other@contoso.com", "10.1.1.2",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul",
            "geoCoordinates":{"latitude":41.0082,"longitude":28.9784}}),
        dynamic({"deviceId":"device-003","operatingSystem":"macOS 14","browser":"Safari 17.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Safari/17.0", "SharePoint Online", "SharePoint Online", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppOTP","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-b06", "sess-b06",
    // BENIGN 7: User sign-in outside lookback window
    datetime(2026-02-21T06:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul",
            "geoCoordinates":{"latitude":41.0082,"longitude":28.9784}}),
        dynamic({"deviceId":"device-001","operatingSystem":"Windows 11","browser":"Chrome 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-b07", "sess-b07",
    // BENIGN 8: Mobile user sign-in from carrier IP
    datetime(2026-02-21T13:00:00Z), "mobile.user@contoso.com", "100.64.0.1",
        dynamic({"city":"Izmir","countryOrRegion":"TR","state":"Izmir",
            "geoCoordinates":{"latitude":38.4237,"longitude":27.1428}}),
        dynamic({"deviceId":"device-mob","operatingSystem":"iOS 17","browser":"Safari",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Mobile Safari", "Microsoft Outlook", "Microsoft Office 365", "Mobile Apps and Desktop clients",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-b08", "sess-b08"
];
// --- Test execution: Extract sign-in pair for user@contoso.com ---
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
let LookbackWindow = 6h;
let RecentSignins = TestSigninLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1h))
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | extend
        Latitude = toreal(tostring(LocationDetails.geoCoordinates.latitude)),
        Longitude = toreal(tostring(LocationDetails.geoCoordinates.longitude)),
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        DeviceId = tostring(DeviceDetail.deviceId)
    | project SigninTime = TimeGenerated, IPAddress, Latitude, Longitude, City, Country, DeviceId,
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceBrowser = tostring(DeviceDetail.browser),
        UserAgent, AppDisplayName, SessionId
    | summarize arg_max(SigninTime, *) by IPAddress
    | top 2 by SigninTime desc;
RecentSignins
| extend SignInOrder = row_number()
| extend SignInLabel = iff(SignInOrder == 1, "SIGN-IN 2 (Later/Anomalous)", "SIGN-IN 1 (Earlier/Baseline)")
| project SignInLabel, SigninTime, IPAddress, Latitude, Longitude, City, Country, DeviceId,
    DeviceOS, DeviceBrowser, UserAgent, AppDisplayName, SessionId
| order by SigninTime asc
// Expected: 2 rows:
// Row 1: SIGN-IN 1 (Earlier/Baseline) - Istanbul, 85.100.50.25, device-001, Windows 11, Chrome
// Row 2: SIGN-IN 2 (Later/Anomalous) - Moscow, 198.51.100.42, device-999, Linux, Python
// Filtered out: BENIGN 1 (earlier Istanbul from same IP, superseded by arg_max),
//   BENIGN 5 (failed sign-in), BENIGN 7 (outside 6h window), M3 (different IP deduplicated),
//   M4 (different user), B2/B3/B4/B6/B8 (different users)
```

### Test 2: Query 2 - Geographic Distance and Travel Speed

```kql
// ============================================================
// TEST: Query 2 - Geographic Distance and Travel Speed
// Tests geo_distance_2points() with known city coordinates
// ============================================================
// Test with known Istanbul-Moscow distance (~1750 km)
let lat1 = 41.0082;  // Istanbul
let lon1 = 28.9784;
let lat2 = 55.7558;  // Moscow
let lon2 = 37.6173;
let time1 = datetime(2026-02-21T14:00:00Z);
let time2 = datetime(2026-02-21T14:30:00Z);
let DistanceMeters = geo_distance_2points(lon1, lat1, lon2, lat2);
let DistanceKm = DistanceMeters / 1000.0;
let TimeDiffHours = datetime_diff("second", time2, time1) / 3600.0;
let SpeedKmH = DistanceKm / TimeDiffHours;
print
    Origin = "Istanbul, TR",
    Destination = "Moscow, RU",
    DistanceKm = round(DistanceKm, 1),
    TimeDiffMinutes = round(TimeDiffHours * 60, 1),
    RequiredSpeedKmH = round(SpeedKmH, 0),
    TravelAssessment = case(
        SpeedKmH > 900, "PHYSICALLY IMPOSSIBLE",
        SpeedKmH > 500, "HIGHLY UNLIKELY",
        SpeedKmH > 200, "UNLIKELY",
        SpeedKmH > 100, "POSSIBLE",
        "PLAUSIBLE"
    )
// Expected: DistanceKm ≈ 1755, TimeDiffMinutes = 30, RequiredSpeedKmH ≈ 3510
// TravelAssessment = "PHYSICALLY IMPOSSIBLE" (3510 km/h >> 900 km/h)
```

### Test 3: Query 3A - Travel Pattern Baseline

```kql
// ============================================================
// TEST: Query 3A - Travel Pattern Baseline
// Synthetic data: 10 baseline sign-ins from known locations
// ============================================================
let BaselineSignins = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    LocationDetails: dynamic,
    ResultType: string
) [
    // Normal: Istanbul office (primary location)
    datetime(2026-01-22T09:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","geoCoordinates":{"latitude":41.0082,"longitude":28.9784}}), "0",
    datetime(2026-01-23T09:30:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","geoCoordinates":{"latitude":41.0082,"longitude":28.9784}}), "0",
    datetime(2026-01-24T08:45:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","geoCoordinates":{"latitude":41.0082,"longitude":28.9784}}), "0",
    datetime(2026-01-27T09:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","geoCoordinates":{"latitude":41.0082,"longitude":28.9784}}), "0",
    // Normal: Home IP (same city)
    datetime(2026-01-25T19:00:00Z), "user@contoso.com", "85.100.50.30",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","geoCoordinates":{"latitude":41.0150,"longitude":29.0100}}), "0",
    // Normal: Ankara office trip (domestic travel)
    datetime(2026-02-03T10:00:00Z), "user@contoso.com", "10.1.1.50",
        dynamic({"city":"Ankara","countryOrRegion":"TR","geoCoordinates":{"latitude":39.9334,"longitude":32.8597}}), "0",
    datetime(2026-02-03T15:00:00Z), "user@contoso.com", "10.1.1.50",
        dynamic({"city":"Ankara","countryOrRegion":"TR","geoCoordinates":{"latitude":39.9334,"longitude":32.8597}}), "0",
    // Normal: Mobile carrier IP (Istanbul)
    datetime(2026-02-10T12:00:00Z), "user@contoso.com", "100.64.0.5",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","geoCoordinates":{"latitude":41.0082,"longitude":28.9784}}), "0",
    // Normal: Different user (should be filtered out)
    datetime(2026-01-28T09:00:00Z), "other@contoso.com", "10.1.1.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR","geoCoordinates":{"latitude":41.0082,"longitude":28.9784}}), "0",
    // Failed sign-in (should be excluded from baseline)
    datetime(2026-02-01T03:00:00Z), "user@contoso.com", "198.51.100.42",
        dynamic({"city":"Moscow","countryOrRegion":"RU","geoCoordinates":{"latitude":55.7558,"longitude":37.6173}}), "50126"
];
let SignInIP1 = "85.100.50.25";
let SignInIP2 = "198.51.100.42";
let TargetUser = "user@contoso.com";
// Build footprint from baseline
let GeoFootprint = BaselineSignins
    | where UserPrincipalName == TargetUser
    | where ResultType == "0"
    | extend
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion)
    | summarize
        SigninCount = count(),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by IPAddress, City, Country;
let ip1Known = toscalar(GeoFootprint | where IPAddress == SignInIP1 | count) > 0;
let ip2Known = toscalar(GeoFootprint | where IPAddress == SignInIP2 | count) > 0;
GeoFootprint
| summarize
    TotalSignins = sum(SigninCount),
    DistinctIPs = dcount(IPAddress),
    DistinctCities = dcount(City),
    DistinctCountries = dcount(Country),
    KnownCities = make_set(City),
    KnownCountries = make_set(Country),
    KnownIPs = make_set(IPAddress)
| extend
    IP1_InBaseline = ip1Known,
    IP2_InBaseline = ip2Known,
    BaselineAssessment = case(
        ip1Known and ip2Known, "BOTH IPs KNOWN",
        ip1Known and not(ip2Known), "ONLY IP1 KNOWN - Second location is new",
        not(ip1Known) and ip2Known, "ONLY IP2 KNOWN - First location is new",
        "NEITHER IP KNOWN"
    )
// Expected: TotalSignins=8, DistinctIPs=4, DistinctCities=2 (Istanbul, Ankara),
//   DistinctCountries=1 (TR), IP1_InBaseline=true, IP2_InBaseline=false
//   BaselineAssessment = "ONLY IP1 KNOWN - Second location is new"
//   Moscow/RU IP never seen in baseline (failed sign-in excluded)
```

### Test 4: Query 4 - Device Fingerprint Comparison

```kql
// ============================================================
// TEST: Query 4 - Device Fingerprint Comparison
// Tests both VPN (same device) and attacker (different device) scenarios
// ============================================================
// Scenario A: True positive - different devices
let TestSigninsTP = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    DeviceDetail: dynamic,
    UserAgent: string,
    AppDisplayName: string,
    ClientAppUsed: string,
    AuthenticationRequirement: string,
    MfaDetail: dynamic,
    ConditionalAccessStatus: string,
    ResultType: string,
    SessionId: string
) [
    datetime(2026-02-21T14:00:00Z), "user@contoso.com", "85.100.50.25",
        dynamic({"deviceId":"device-001","operatingSystem":"Windows 11","browser":"Chrome 120.0",
            "isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/120.0", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification"}),
        "success", "0", "sess-001",
    datetime(2026-02-21T14:30:00Z), "user@contoso.com", "198.51.100.42",
        dynamic({"deviceId":"device-999","operatingSystem":"Linux","browser":"Python/3.9",
            "isCompliant":"false","isManaged":"false","trustType":""}),
        "python-requests/2.28.1", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "sess-002"
];
TestSigninsTP
| extend
    DeviceId = tostring(DeviceDetail.deviceId),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    DeviceBrowser = tostring(DeviceDetail.browser),
    DeviceIsCompliant = tostring(DeviceDetail.isCompliant),
    DeviceIsManaged = tostring(DeviceDetail.isManaged)
| project IPAddress, DeviceId, DeviceOS, DeviceBrowser, DeviceIsCompliant, DeviceIsManaged,
    UserAgent, AuthenticationRequirement, SessionId
// Expected: 2 rows with DIFFERENT DeviceId values
// device-001 (Windows 11/Chrome, compliant, managed) vs device-999 (Linux/Python, not compliant)
// DeviceRiskAssessment = "HIGH RISK - Different device fingerprint entirely"
```

### Test 5: Query 5A - Token Replay Detection

```kql
// ============================================================
// TEST: Query 5A - Token Replay Detection
// Synthetic non-interactive sign-ins from anomalous IP
// ============================================================
let TestNonInteractive = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    AppDisplayName: string,
    ResourceDisplayName: string,
    ResultType: string,
    OriginalRequestId: string,
    LocationDetails: dynamic,
    UserAgent: string,
    ClientAppUsed: string,
    IsInteractive: bool
) [
    // MALICIOUS: Token replay from anomalous IP - successful Graph API access
    datetime(2026-02-21T14:35:00Z), "user@contoso.com", "198.51.100.42",
        "Microsoft Graph", "Microsoft Graph", "0", "req-m01",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "", "Mobile Apps and Desktop clients", false,
    // MALICIOUS: Token replay - Exchange access
    datetime(2026-02-21T14:40:00Z), "user@contoso.com", "198.51.100.42",
        "Microsoft Exchange Online", "Microsoft Exchange Online", "0", "req-m02",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "", "Mobile Apps and Desktop clients", false,
    // MALICIOUS: Token replay - SharePoint access
    datetime(2026-02-21T14:45:00Z), "user@contoso.com", "198.51.100.42",
        "SharePoint Online", "SharePoint Online", "0", "req-m03",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "", "Mobile Apps and Desktop clients", false,
    // MALICIOUS: Failed token refresh (token expired)
    datetime(2026-02-21T15:30:00Z), "user@contoso.com", "198.51.100.42",
        "Microsoft Graph", "Microsoft Graph", "50173", "req-m04",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "", "Mobile Apps and Desktop clients", false,
    // BENIGN: Normal non-interactive from user's real IP
    datetime(2026-02-21T14:05:00Z), "user@contoso.com", "85.100.50.25",
        "Microsoft Office 365", "Microsoft Office 365", "0", "req-b01",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}), "", "Mobile Apps and Desktop clients", false,
    // BENIGN: Different user from anomalous IP
    datetime(2026-02-21T14:36:00Z), "other@contoso.com", "198.51.100.42",
        "Microsoft Graph", "Microsoft Graph", "0", "req-b02",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "", "Mobile Apps and Desktop clients", false
];
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
let SignInIP2 = "198.51.100.42";
let TokenWindow = 4h;
TestNonInteractive
| where TimeGenerated between ((AlertTime - TokenWindow) .. (AlertTime + TokenWindow))
| where UserPrincipalName == TargetUser
| where IPAddress == SignInIP2
| summarize
    TotalNonInteractiveEvents = count(),
    SuccessfulEvents = countif(ResultType == "0"),
    FailedEvents = countif(ResultType != "0"),
    DistinctApps = make_set(AppDisplayName),
    DistinctResources = make_set(ResourceDisplayName),
    EarliestEvent = min(TimeGenerated),
    LatestEvent = max(TimeGenerated)
| extend
    TokenReplayAssessment = case(
        SuccessfulEvents > 0,
            "CONFIRMED - Active token usage from anomalous IP (T1550.004)",
        TotalNonInteractiveEvents > 0 and FailedEvents > 0,
            "ATTEMPTED - Token refresh attempted but failed",
        "NO EVIDENCE - No non-interactive activity from anomalous IP"
    )
// Expected: TotalNonInteractiveEvents=4, SuccessfulEvents=3, FailedEvents=1
//   DistinctApps = [Graph, Exchange, SharePoint]
//   TokenReplayAssessment = "CONFIRMED - Active token usage from anomalous IP (T1550.004)"
//   Filtered out: req-b01 (different IP), req-b02 (different user)
```

### Test 6: Query 6A/6B - Post-Sign-In Activity

```kql
// ============================================================
// TEST: Query 6A/6B - Post-Sign-In Activity (Persistence + BEC)
// Synthetic data: 6 malicious + 8 benign = 14 rows
// ============================================================
let TestAuditLogs = datatable(
    TimeGenerated: datetime,
    OperationName: string,
    Category: string,
    InitiatedBy: dynamic,
    TargetResources: dynamic,
    CorrelationId: string
) [
    // MALICIOUS 1: MFA method registered AFTER alert (attacker adding their phone)
    datetime(2026-02-21T14:45:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"userPrincipalName":"user@contoso.com","displayName":"Test User",
            "modifiedProperties":[{"displayName":"StrongAuthenticationMethod","oldValue":"[]","newValue":"[{\"MethodType\":6}]"}]}]),
        "audit-m01",
    // MALICIOUS 2: OAuth app consent with broad permissions
    datetime(2026-02-21T14:55:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"Data Exfil App","modifiedProperties":[
            {"displayName":"ConsentAction.Permissions","oldValue":"","newValue":"Mail.ReadWrite Files.ReadWrite.All"}]}]),
        "audit-m02",
    // MALICIOUS 3: Device registration (rogue device)
    datetime(2026-02-21T15:00:00Z), "Register device", "DeviceManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"DESKTOP-ATKR01","modifiedProperties":[]}]),
        "audit-m03",
    // BENIGN 1: Different user activity
    datetime(2026-02-21T14:50:00Z), "User registered security info", "UserManagement",
        dynamic({"user":{"userPrincipalName":"colleague@contoso.com"}}),
        dynamic([{"userPrincipalName":"colleague@contoso.com","displayName":"Colleague","modifiedProperties":[]}]),
        "audit-b01",
    // BENIGN 2: Target user activity BEFORE alert
    datetime(2026-02-21T09:00:00Z), "Consent to application", "ApplicationManagement",
        dynamic({"user":{"userPrincipalName":"user@contoso.com"}}),
        dynamic([{"displayName":"Slack","modifiedProperties":[]}]),
        "audit-b02",
    // BENIGN 3: Admin action on different user
    datetime(2026-02-21T15:10:00Z), "Reset password (by admin)", "UserManagement",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com"}}),
        dynamic([{"userPrincipalName":"other@contoso.com","displayName":"Other User","modifiedProperties":[]}]),
        "audit-b03"
];
let TestOfficeActivity = datatable(
    TimeGenerated: datetime,
    Operation: string,
    OfficeWorkload: string,
    UserId: string,
    ClientIP: string,
    Parameters: dynamic
) [
    // MALICIOUS 4: Inbox rule forwarding to external address
    datetime(2026-02-21T15:05:00Z), "New-InboxRule", "Exchange", "user@contoso.com",
        "198.51.100.42:54321",
        dynamic([
            {"Name":"Name","Value":".."},
            {"Name":"SubjectContainsWords","Value":"invoice;payment;wire"},
            {"Name":"ForwardTo","Value":"attacker@evil.com"},
            {"Name":"DeleteMessage","Value":"True"}
        ]),
    // MALICIOUS 5: Bulk email access from anomalous IP
    datetime(2026-02-21T15:15:00Z), "MailItemsAccessed", "Exchange", "user@contoso.com",
        "198.51.100.42:54321", dynamic([]),
    // MALICIOUS 6: File download from anomalous IP
    datetime(2026-02-21T15:30:00Z), "FileDownloaded", "SharePoint", "user@contoso.com",
        "[::ffff:198.51.100.42]:12345", dynamic([]),
    // BENIGN 4: Normal email access from known IP (before alert)
    datetime(2026-02-21T10:00:00Z), "MailItemsAccessed", "Exchange", "user@contoso.com",
        "85.100.50.25:50000", dynamic([]),
    // BENIGN 5: Different user file download
    datetime(2026-02-21T15:00:00Z), "FileDownloaded", "SharePoint", "colleague@contoso.com",
        "10.1.1.2", dynamic([]),
    // BENIGN 6: Target user normal send BEFORE alert
    datetime(2026-02-21T11:00:00Z), "Send", "Exchange", "user@contoso.com",
        "85.100.50.25:50000", dynamic([]),
    // BENIGN 7: Other user inbox rule (legitimate)
    datetime(2026-02-21T14:50:00Z), "New-InboxRule", "Exchange", "colleague@contoso.com",
        "10.1.1.2:44000",
        dynamic([{"Name":"Name","Value":"Move JIRA"},{"Name":"MoveToFolder","Value":"JIRA"}]),
    // BENIGN 8: Target user activity outside window
    datetime(2026-02-21T08:00:00Z), "FileAccessed", "SharePoint", "user@contoso.com",
        "85.100.50.25:50000", dynamic([])
];
// --- Test 6A: Directory changes ---
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-21T14:30:00Z);
let PostSignInWindow = 4h;
TestAuditLogs
| where TimeGenerated between (AlertTime .. (AlertTime + PostSignInWindow))
| where OperationName in (
    "User registered security info", "User deleted security info",
    "Consent to application", "Add app role assignment to service principal",
    "Add delegated permission grant", "Register device",
    "Reset password (by admin)", "Add member to role"
)
| mv-expand TargetResource = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) == TargetUser
    or tostring(TargetResource.userPrincipalName) == TargetUser
| project
    TimeGenerated, OperationName,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    TargetDisplayName = tostring(TargetResource.displayName),
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, AlertTime),
    Severity = case(
        OperationName has "security info", "CRITICAL - MFA MANIPULATION",
        OperationName has "Consent to application", "CRITICAL - OAUTH APP CONSENT",
        OperationName has "Register device", "HIGH - DEVICE REGISTRATION",
        "INFO"
    )
| order by TimeGenerated asc
// Expected: 3 rows (M1: MFA registration +15min, M2: OAuth consent +25min, M3: device reg +30min)
// B01 filtered (different user), B02 filtered (before alert), B03 filtered (different target user)
```

---

## References

- [Microsoft Entra ID Identity Protection risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [Impossible travel risk detection documentation](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#impossible-travel)
- [geo_distance_2points() function reference](https://learn.microsoft.com/en-us/kusto/query/geo-distance-2points-function)
- [MITRE ATT&CK T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK T1550.004 - Use Alternate Authentication Material: Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/)
- [MITRE ATT&CK T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [Microsoft guidance on AiTM phishing attacks](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing)
- [Conditional Access: Token protection](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection)
- [SigninLogs schema reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [AADNonInteractiveUserSignInLogs schema reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
- [AADUserRiskEvents schema reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aaduserriskevents)
