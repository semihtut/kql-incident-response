---
title: "Atypical Travel"
id: RB-0009
severity: medium
status: reviewed
description: >
  Investigation runbook for Microsoft Entra ID Identity Protection
  atypical travel and first-time location anomaly detection. Covers
  ML-based user location profiling, first-time country/region analysis,
  Defender for Cloud Apps impossible travel correlation, and post-sign-in
  blast radius assessment. Unlike RB-0002 (Impossible Travel) which
  requires two conflicting sign-in pairs, this runbook investigates
  single sign-ins from locations that deviate from the user's
  ML-learned geographic behavior pattern.
mitre_attack:
  tactics:
    - tactic_id: TA0001
      tactic_name: "Initial Access"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
    - tactic_id: TA0003
      tactic_name: "Persistence"
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
      confidence: probable
    - technique_id: T1539
      technique_name: "Steal Web Session Cookie"
      confidence: probable
    - technique_id: T1098
      technique_name: "Account Manipulation"
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
    - technique_id: T1534
      technique_name: "Internal Spearphishing"
      confidence: confirmed
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Storm-0558"
  - "Scattered Spider (Octo Tempest)"
  - "Peach Sandstorm (APT33)"
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
  - table: "CloudAppEvents"
    product: "Defender for Cloud Apps"
    license: "M365 E5 / Defender for Cloud Apps"
    required: false
    alternatives: []
  - table: "BehaviorAnalytics"
    product: "Sentinel UEBA"
    license: "Sentinel UEBA"
    required: false
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-22
updated: 2026-02-22
version: "1.0"
tier: 1
category: identity
data_checks:
  - query: "AADUserRiskEvents | take 1"
    label: primary
    description: "If empty, Entra ID P2 or the connector is missing"
  - query: "SigninLogs | take 1"
    description: "Must contain LocationDetails for country/city analysis"
  - query: "AADNonInteractiveUserSignInLogs | take 1"
    description: "For non-interactive session tracking"
  - query: "OfficeActivity | take 1"
    description: "For post-sign-in blast radius assessment"
  - query: "AuditLogs | take 1"
    description: "For persistence detection (MFA, OAuth, role changes)"
  - query: "CloudAppEvents | take 1"
    label: optional
    description: "Defender for Cloud Apps impossible travel correlation"
---

# Atypical Travel - Investigation Runbook

> **RB-0009** | Severity: Medium | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Entra ID Identity Protection + Defender for Cloud Apps
> **Risk Detection Name:** `newCountry` + `mcasImpossibleTravel` + ML-learned location anomaly
> **Primary MITRE Technique:** T1078.004 - Valid Accounts: Cloud Accounts

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Extract Location Anomaly Risk Event](#step-1-extract-location-anomaly-risk-event)
   - [Step 2: First-Time Country and Region Analysis](#step-2-first-time-country-and-region-analysis)
   - [Step 3: User Geographic Mobility Profile](#step-3-user-geographic-mobility-profile)
   - [Step 4: Baseline Comparison - Establish Normal Location Pattern](#step-4-baseline-comparison---establish-normal-location-pattern)
   - [Step 5: Device and Authentication Context](#step-5-device-and-authentication-context)
   - [Step 6: Post-Sign-In Activity (Blast Radius Assessment)](#step-6-post-sign-in-activity-blast-radius-assessment)
   - [Step 7: Org-Wide Anomalous Location Sweep](#step-7-org-wide-anomalous-location-sweep)
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
Atypical travel is detected through three complementary mechanisms:

1. **Identity Protection `newCountry` risk event:** Fires when a user signs in from a country/region they have never signed in from before. This is a real-time detection that evaluates the user's historical location set. The `newCountry` event is distinct from `impossibleTravel` — it does not require a second sign-in pair, only that the country is new for this specific user.
2. **Defender for Cloud Apps `mcasImpossibleTravel`:** An independent ML-based detection that evaluates location anomalies using Cloud Apps data, sometimes with different sensitivity than Identity Protection. Cloud Apps considers application-level context and can detect anomalies that Identity Protection misses (and vice versa).
3. **SigninLogs location pattern analysis:** Custom Sentinel analytics rules that compare the sign-in country/city against the user's 30-90 day location history. This catches cases where the location is technically "seen before" but is rare or has been dormant for months.

**Why it matters:**
Location anomaly detection is a foundational signal for credential compromise. When an attacker obtains credentials (via phishing, info-stealer malware, credential dumps, or session hijacking), their first sign-in will almost always come from a location that is unusual for the victim. The ML-learned location profile acts as a behavioral fingerprint — even if the attacker uses the correct password and passes MFA (via token theft or real-time phishing proxy), they cannot replicate the user's geographic pattern. First-time country sign-ins are particularly high-signal because most users operate from a small set of 1-3 countries over any 90-day period.

**Why this is MEDIUM severity (rather than High):**
- The `newCountry` detection alone has a moderate false positive rate from legitimate business travel
- Unlike Impossible Travel (RB-0002), there is no second sign-in pair proving concurrent usage from two locations
- The ML model accounts for some organizational travel patterns but cannot predict all legitimate first-time travel
- The alert becomes High severity only when combined with other indicators (new device, no MFA, suspicious post-sign-in activity)

**However:** This alert has a **moderate-to-high false positive rate** (~35-50%). Legitimate triggers include:
- Business travel to a new country for the first time (conferences, client visits, team offsites)
- Remote employees who travel frequently or are digital nomads
- VPN routing through a different country's Point of Presence
- ISP geo-IP database errors placing the user in the wrong country
- Company mergers/acquisitions where users from new countries begin accessing the tenant
- Seasonal travel patterns (holidays, summer vacations to new destinations)

**Worst case scenario if this is real:**
An attacker has compromised the user's credentials (via phishing, AiTM proxy, or info-stealer malware) and is signing in from their own infrastructure in another country. The sign-in bypassed MFA because the attacker used a real-time phishing proxy (e.g., Evilginx, Modlishka) that captured both the password and the session token. The attacker now has full authenticated access to the user's cloud resources. They immediately begin reconnaissance — reading email, downloading files, and looking for additional credentials. If the user has access to sensitive data or admin roles, the attacker escalates quickly: registering their own MFA device, granting OAuth app permissions, and setting up email forwarding rules for persistent access.

**Key difference from RB-0001 and RB-0002:**
- **RB-0001 (Unfamiliar Sign-In Properties):** Detects unusual device/browser/IP fingerprint for a single sign-in. Location is one of several factors. High noise.
- **RB-0002 (Impossible Travel):** Requires TWO sign-ins from geographically incompatible locations within a short time. Proves concurrent credential usage. Focuses on distance/speed math between the pair.
- **RB-0009 (This runbook):** Detects a SINGLE sign-in from a location that deviates from the user's ML-learned geographic behavior profile. Does NOT require a second sign-in. The investigation focuses on: **"Is this location genuinely new for this user, and does the authentication context support legitimate travel?"** The unique steps are: user mobility profiling (building a location history), first-time country analysis, and Cloud Apps cross-correlation. This runbook is critical for catching credential compromise where the attacker is in a different country but the legitimate user has not signed in recently (so no impossible travel pair exists).

---

## 2. Prerequisites

### Minimum Required
- **License:** Entra ID P2 + Microsoft 365 E3 + Microsoft Sentinel
- **Sentinel Connectors:** Microsoft Entra ID, Office 365
- **Permissions:** Security Reader (investigation), Security Operator (containment)

### Recommended for Full Coverage
- **License:** Microsoft 365 E5 + Sentinel
- **Additional:** Defender for Cloud Apps connected (for `mcasImpossibleTravel` correlation), UEBA enabled (for BehaviorAnalytics)
- **Named Locations:** Trusted corporate locations configured in Entra ID Conditional Access (for FP reduction)

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| Entra ID Free + Sentinel | SigninLogs, AuditLogs | Steps 2, 3, 4, 5 (partial) |
| Entra ID P2 + Sentinel | Above + AADUserRiskEvents, AADRiskyUsers, AADNonInteractiveUserSignInLogs | Steps 1-5, 7 |
| M365 E5 + Entra ID P2 + Sentinel | Above + OfficeActivity, CloudAppEvents, BehaviorAnalytics | Steps 1-7 (full investigation) |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let TargetUser = "user@contoso.com";       // UPN from the alert
let AlertTime = datetime(2026-02-22T14:00:00Z);  // Time of the anomalous sign-in
let AlertCountry = "NG";                   // Country code from the anomalous sign-in
let AlertCity = "Lagos";                   // City from the anomalous sign-in
let AlertIP = "203.0.113.50";             // IP address from the anomalous sign-in
let LookbackWindow = 24h;                 // Window before alert for sign-in context
let ForwardWindow = 24h;                  // Window after alert for blast radius
let BaselineDays = 90d;                   // Location profile baseline (90 days recommended)
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- First-time country sign-in AND user's account has existing high-risk detections
- New country sign-in from a known adversary infrastructure country AND no MFA was performed
- Sign-in followed by MFA method registration, OAuth app consent, or inbox rule creation within 1 hour
- Multiple users in the same department signed in from the same unusual country simultaneously
- Sign-in used legacy authentication protocol (no MFA possible)
- User has PIM-eligible admin roles and signed in from a new country without MFA

### Standard Investigation
- First-time country sign-in with MFA successfully completed
- Sign-in from a new city within a familiar country
- Defender for Cloud Apps `mcasImpossibleTravel` alert for this user
- Single location anomaly with no other risk signals

### Likely Benign
- User's calendar shows travel to the flagged country (check with manager if needed)
- Sign-in from a corporate VPN exit node in a different country (check Named Locations)
- Country matches a known office location for the user's organization or subsidiary
- User recently changed roles to one involving international travel
- ISP geo-IP misattribution (IP owner matches user's actual ISP but geolocated incorrectly)

---

## 5. Investigation Steps

### Step 1: Extract Location Anomaly Risk Event

**Purpose:** Retrieve the Identity Protection risk event or Defender for Cloud Apps alert that triggered this investigation. Identify the specific risk detection type (`newCountry`, `mcasImpossibleTravel`, or `unfamiliarFeatures` with location as the primary trigger) and extract the sign-in details.

**Data needed:** AADUserRiskEvents, SigninLogs

```kql
// ============================================================
// QUERY 1: Location Anomaly Risk Event Extraction
// Purpose: Retrieve risk events with location anomaly for the target user
// Tables: AADUserRiskEvents, SigninLogs
// Investigation Step: 1 - Extract Location Anomaly Risk Event
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let LookbackWindow = 24h;
// --- Part A: Identity Protection risk events ---
let RiskEvents = AADUserRiskEvents
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where UserPrincipalName =~ TargetUser
| where RiskEventType in ("newCountry", "impossibleTravel", "mcasImpossibleTravel", "unfamiliarFeatures")
| extend
    EventLocation = tostring(Location),
    LocationCity = tostring(parse_json(Location).city),
    LocationCountry = tostring(parse_json(Location).countryOrRegion),
    IpAddress = IpAddress,
    DetectionSource = Source,
    RiskConfidence = RiskLevel
| project
    TimeGenerated,
    RiskEventType,
    RiskConfidence,
    DetectionSource,
    IpAddress,
    LocationCity,
    LocationCountry,
    Activity,
    AdditionalInfo,
    UserPrincipalName;
// --- Part B: Corresponding sign-in event ---
let SignInContext = SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where UserPrincipalName =~ TargetUser
| extend
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    State = tostring(LocationDetails.state),
    Latitude = toreal(parse_json(tostring(LocationDetails.geoCoordinates)).latitude),
    Longitude = toreal(parse_json(tostring(LocationDetails.geoCoordinates)).longitude)
| project
    TimeGenerated,
    IPAddress,
    City,
    Country,
    State,
    Latitude,
    Longitude,
    ResultType,
    ResultDescription,
    AppDisplayName,
    ClientAppUsed,
    UserAgent,
    DeviceBrowser = tostring(DeviceDetail.browser),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged),
    AuthenticationRequirement,
    ConditionalAccessStatus,
    MfaResult = tostring(MfaDetail.authMethod),
    RiskLevelDuringSignIn,
    RiskState,
    CorrelationId;
// --- Output risk events ---
RiskEvents
```

**Performance Notes:**
- AADUserRiskEvents for a single user in a 24h window is fast
- `newCountry` events are real-time; `mcasImpossibleTravel` can be delayed 30-60 minutes

**Expected findings:**
- `RiskEventType = "newCountry"`: User has never signed in from this country before
- `RiskEventType = "mcasImpossibleTravel"`: Cloud Apps independently flagged a location anomaly
- `RiskEventType = "unfamiliarFeatures"`: Location is one of multiple unfamiliar properties
- `RiskConfidence = "high"` increases the likelihood this is genuine compromise

**Next action:**
- If `newCountry` from a high-risk country with no MFA → Immediate escalation
- If `mcasImpossibleTravel` → Cross-reference with RB-0002 steps for travel speed validation
- If risk event found → Use `IpAddress` and `LocationCountry` as pivots for Steps 2-3

---

### Step 2: First-Time Country and Region Analysis

**Purpose:** Determine whether this sign-in country is truly a first for this user by building a complete location history. Also check if this is the first time the country appears for the ENTIRE organization (may indicate a VPN exit node or a coordinated attack targeting a new geography).

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 2: First-Time Country and Region Analysis
// Purpose: Build complete location history to verify country is truly new
// Tables: SigninLogs
// Investigation Step: 2 - First-Time Country and Region Analysis
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let AlertCountry = "NG";
let BaselineDays = 90d;
// --- Build the user's complete location history ---
let LocationHistory = SigninLogs
| where TimeGenerated between ((AlertTime - BaselineDays) .. AlertTime)
| where UserPrincipalName =~ TargetUser
| where ResultType == "0" // Only successful sign-ins
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    State = tostring(LocationDetails.state)
| where isnotempty(Country)
| summarize
    SignInCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    UniqueIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 5),
    Cities = make_set(City, 10)
    by Country
| extend
    DaysSinceFirstSeen = datetime_diff('day', AlertTime, FirstSeen),
    DaysSinceLastSeen = datetime_diff('day', AlertTime, LastSeen),
    IsAlertCountry = Country =~ AlertCountry
| sort by SignInCount desc;
// --- Analyze: Is the alert country genuinely new? ---
let CountrySummary = LocationHistory
| summarize
    TotalCountries = dcount(Country),
    Countries = make_set(Country),
    AlertCountryExists = countif(IsAlertCountry) > 0,
    AlertCountrySignIns = sumif(SignInCount, IsAlertCountry),
    AlertCountryLastSeen = maxif(LastSeen, IsAlertCountry);
LocationHistory
| union (
    CountrySummary
    | extend Country = "=== SUMMARY ===", SignInCount = 0,
        FirstSeen = datetime(null), LastSeen = datetime(null),
        UniqueIPs = 0, IPs = dynamic([]), Cities = dynamic([]),
        DaysSinceFirstSeen = 0, DaysSinceLastSeen = 0, IsAlertCountry = false
)
```

**Tuning Guidance:**
- Extend `BaselineDays` to 180d for users with seasonal travel patterns (e.g., annual conferences in specific countries)
- Check both successful AND failed sign-ins — the attacker may have failed first attempts before succeeding
- If the user is new (< 30 days in the tenant), the "first-time country" signal is weaker

**Expected findings:**
- If `AlertCountryExists = false`: Truly a first-time country — high-signal anomaly
- If `AlertCountrySignIns > 0 but DaysSinceLastSeen > 60`: Country was seen before but dormant — moderate signal
- If user operates from 1-2 countries consistently, any third country is suspicious
- If user operates from 5+ countries regularly, they are a frequent traveler — lower signal

**Next action:**
- Truly new country with < 3 total countries in history → Strong indicator, continue to Step 3
- Previously seen country (recently active) → Likely benign, but check device context in Step 5
- User is a frequent traveler (5+ countries) → This alert is lower priority; focus on device/auth anomalies

---

### Step 3: User Geographic Mobility Profile

**Purpose:** Build a detailed mobility profile showing the user's typical sign-in locations, timing patterns per location, and geographic scope. This creates the behavioral context needed to assess whether the anomalous location fits the user's travel patterns.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 3: User Geographic Mobility Profile
// Purpose: Build a detailed location behavior profile for the user
// Tables: SigninLogs
// Investigation Step: 3 - User Geographic Mobility Profile
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let AlertCountry = "NG";
let AlertIP = "203.0.113.50";
let BaselineDays = 90d;
// --- Detailed mobility analysis ---
SigninLogs
| where TimeGenerated between ((AlertTime - BaselineDays) .. AlertTime)
| where UserPrincipalName =~ TargetUser
| where ResultType == "0"
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    HourOfDay = hourofday(TimeGenerated),
    DayOfWeek = dayofweek(TimeGenerated) / 1h,
    IsWeekend = dayofweek(TimeGenerated) in (6d, 0d)
| summarize
    TotalSignIns = count(),
    UniqueCountries = dcount(Country),
    UniqueCities = dcount(City),
    UniqueIPs = dcount(IPAddress),
    // --- Location breakdown ---
    CountryBreakdown = make_bag(bag_pack(Country, count())),
    PrimaryCountry = take_any(Country),
    // --- Temporal patterns ---
    AvgHourOfDay = round(avg(HourOfDay), 1),
    TypicalHours = make_set(bin(HourOfDay, 3)),
    WeekendPct = round(100.0 * countif(IsWeekend) / count(), 1),
    // --- Date range ---
    ActiveDays = dcount(bin(TimeGenerated, 1d)),
    FirstActivity = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
| extend
    // --- Classify user mobility ---
    MobilityClass = case(
        UniqueCountries >= 5, "HIGH MOBILITY - Frequent international traveler",
        UniqueCountries >= 3, "MODERATE MOBILITY - Occasional international travel",
        UniqueCountries == 2, "LOW MOBILITY - Dual-location (home + one other)",
        "STATIC - Single country user"
    ),
    AccountAge = datetime_diff('day', AlertTime, FirstActivity),
    // --- Alert country assessment ---
    AlertCountryInHistory = CountryBreakdown has AlertCountry
| extend RiskAssessment = case(
    MobilityClass has "STATIC" and not(AlertCountryInHistory), "HIGH RISK - Static user signed in from a new country",
    MobilityClass has "LOW" and not(AlertCountryInHistory), "MEDIUM-HIGH RISK - Low-mobility user in an unseen country",
    MobilityClass has "MODERATE" and not(AlertCountryInHistory), "MEDIUM RISK - Moderately mobile user in an unseen country",
    MobilityClass has "HIGH" and not(AlertCountryInHistory), "LOW-MEDIUM RISK - Frequent traveler in a new country (possible legitimate)",
    AlertCountryInHistory, "LOW RISK - Country exists in user history",
    "UNKNOWN"
)
| project
    MobilityClass,
    RiskAssessment,
    TotalSignIns,
    UniqueCountries,
    UniqueCities,
    UniqueIPs,
    ActiveDays,
    AccountAge,
    WeekendPct,
    CountryBreakdown,
    AlertCountryInHistory
```

**Expected findings:**
- `STATIC` users (1 country) signing in from a new country = highest risk, lowest false positive rate
- `HIGH MOBILITY` users = most likely to be false positives, but still warrant device/auth context checks
- `AccountAge < 30` days with `UniqueCountries = 1` and now a new country → Very suspicious (new account being targeted)
- Check `WeekendPct` — if the user only signs in on weekdays and the anomalous sign-in is on a weekend, that adds risk

**Next action:**
- `STATIC` or `LOW MOBILITY` + new country → High priority; continue to Step 4 for detailed baseline
- `HIGH MOBILITY` + new country → Lower priority; focus on device fingerprint in Step 5
- Country exists in history → Likely benign unless device/auth context is unusual

---

### Step 4: Baseline Comparison - Establish Normal Location Pattern

**Purpose:** Compare the anomalous sign-in against the user's per-day location pattern to determine if this deviation is statistically significant. This is mandatory — you must quantify how unusual this location is relative to the user's baseline.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 4: Location Baseline Comparison (MANDATORY)
// Purpose: Statistical comparison of alert location against 90-day baseline
// Tables: SigninLogs
// Investigation Step: 4 - Baseline Comparison
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let AlertCountry = "NG";
let AlertCity = "Lagos";
let AlertIP = "203.0.113.50";
let BaselineDays = 90d;
// --- Daily location pattern over baseline ---
let DailyLocations = SigninLogs
| where TimeGenerated between ((AlertTime - BaselineDays) .. AlertTime)
| where UserPrincipalName =~ TargetUser
| where ResultType == "0"
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city)
| summarize
    CountriesPerDay = dcount(Country),
    CitiesPerDay = dcount(City),
    SignInsPerDay = count(),
    DayCountries = make_set(Country),
    DayIPs = dcount(IPAddress)
    by Day = bin(TimeGenerated, 1d);
// --- Baseline statistics ---
let BaselineStats = DailyLocations
| summarize
    AvgCountriesPerDay = round(avg(CountriesPerDay), 2),
    MaxCountriesPerDay = max(CountriesPerDay),
    AvgCitiesPerDay = round(avg(CitiesPerDay), 2),
    MaxCitiesPerDay = max(CitiesPerDay),
    AvgSignInsPerDay = round(avg(SignInsPerDay), 1),
    TotalDaysActive = count(),
    DaysWithMultipleCountries = countif(CountriesPerDay > 1);
// --- Alert day analysis ---
let AlertDay = SigninLogs
| where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 2h))
| where UserPrincipalName =~ TargetUser
| where ResultType == "0"
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city)
| summarize
    AlertDayCountries = dcount(Country),
    AlertDayCities = dcount(City),
    AlertDaySignIns = count(),
    AlertDayCountryList = make_set(Country),
    AlertDayCityList = make_set(City),
    AlertDayIPs = make_set(IPAddress, 10);
// --- Specific IP analysis ---
let IPHistory = SigninLogs
| where TimeGenerated between ((AlertTime - BaselineDays) .. AlertTime)
| where UserPrincipalName =~ TargetUser
| where IPAddress == AlertIP
| summarize
    IPPreviousSignIns = count(),
    IPFirstSeen = min(TimeGenerated),
    IPLastSeen = max(TimeGenerated);
// --- Combine baseline with alert day ---
BaselineStats
| join kind=cross AlertDay
| join kind=cross IPHistory
| extend Assessment = case(
    IPPreviousSignIns == 0 and not(AlertDayCountryList has AlertCountry), "ANOMALOUS - New IP AND new country (never seen in 90 days)",
    IPPreviousSignIns == 0, "ELEVATED - New IP address (never seen in 90 days)",
    AlertDayCountries > MaxCountriesPerDay + 1, "ELEVATED - Unusually many countries for one day",
    DaysWithMultipleCountries == 0 and AlertDayCountries > 1, "ANOMALOUS - User never signs in from multiple countries per day",
    "WITHIN NORMAL RANGE"
)
| project
    Assessment,
    AlertDayCountries,
    AlertDayCountryList,
    AlertDayCityList,
    AlertDayIPs,
    AvgCountriesPerDay,
    MaxCountriesPerDay,
    DaysWithMultipleCountries,
    TotalDaysActive,
    IPPreviousSignIns,
    IPFirstSeen
```

**Performance Notes:**
- 90-day SigninLogs baseline scoped to a single user is lightweight
- The per-day aggregation reveals whether the user ever naturally signs in from multiple countries in one day

**Expected findings:**
- `ANOMALOUS` (new IP + new country): Strongest indicator of compromise — this specific IP has never been associated with this user
- `DaysWithMultipleCountries == 0` but alert day has 2+ countries: The user NEVER has multi-country days, making today's anomaly highly significant
- `IPPreviousSignIns > 0`: The IP has been seen before — likely a VPN, corporate proxy, or returning to a known location
- Compare `AlertDayCountries` vs `MaxCountriesPerDay` to see if today breaks historical records

**Next action:**
- `ANOMALOUS` → Continue to Step 5 for device verification, likely headed toward containment
- `WITHIN NORMAL RANGE` → User has a history of multi-location sign-ins; verify with user and close unless Step 5 reveals device anomalies

---

### Step 5: Device and Authentication Context

**Purpose:** Analyze the device fingerprint, authentication method, and Conditional Access evaluation for the anomalous sign-in. A new country + new device + no MFA is the highest-risk combination. A new country + known device + MFA passed is much more likely to be legitimate travel.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 5: Device and Authentication Context Analysis
// Purpose: Evaluate device, MFA, and Conditional Access for the anomalous sign-in
// Tables: SigninLogs
// Investigation Step: 5 - Device and Authentication Context
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let AlertIP = "203.0.113.50";
let BaselineDays = 90d;
// --- Get the anomalous sign-in details ---
let AnomalousSignIn = SigninLogs
| where TimeGenerated between ((AlertTime - 2h) .. (AlertTime + 2h))
| where UserPrincipalName =~ TargetUser
| where IPAddress == AlertIP
| extend
    DeviceId = tostring(DeviceDetail.deviceId),
    DeviceName = tostring(DeviceDetail.displayName),
    OS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged),
    TrustType = tostring(DeviceDetail.trustType),
    MfaMethod = tostring(MfaDetail.authMethod),
    MfaResult = tostring(MfaDetail.authDetail),
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city)
| project
    TimeGenerated, IPAddress, Country, City,
    ResultType, ResultDescription,
    AppDisplayName, ClientAppUsed, UserAgent,
    DeviceId, DeviceName, OS, Browser, IsCompliant, IsManaged, TrustType,
    AuthenticationRequirement, MfaMethod, MfaResult,
    ConditionalAccessStatus, RiskLevelDuringSignIn, RiskState,
    CorrelationId;
// --- Check if this device has been seen before ---
let DeviceFromAlert = toscalar(
    AnomalousSignIn
    | take 1
    | project DeviceId
);
let DeviceHistory = SigninLogs
| where TimeGenerated between ((AlertTime - BaselineDays) .. (AlertTime - 1h))
| where UserPrincipalName =~ TargetUser
| where tostring(DeviceDetail.deviceId) == DeviceFromAlert and isnotempty(DeviceFromAlert)
| summarize
    DevicePreviousSignIns = count(),
    DeviceFirstSeen = min(TimeGenerated),
    DeviceCountries = make_set(tostring(LocationDetails.countryOrRegion));
// --- Combine anomalous sign-in with device history ---
AnomalousSignIn
| join kind=leftouter DeviceHistory on $left.DeviceId == $right.DeviceFromAlert
| extend
    IsNewDevice = isempty(DevicePreviousSignIns) or DevicePreviousSignIns == 0,
    HadMfa = AuthenticationRequirement =~ "multiFactorAuthentication",
    IsUnmanagedDevice = IsCompliant !~ "true" and IsManaged !~ "true",
    UsedLegacyAuth = ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Other clients")
| extend OverallRisk = case(
    IsNewDevice and not(HadMfa) and IsUnmanagedDevice, "CRITICAL - New device + No MFA + Unmanaged",
    IsNewDevice and not(HadMfa), "HIGH - New device + No MFA",
    IsNewDevice and HadMfa, "MEDIUM - New device but MFA passed",
    not(IsNewDevice) and HadMfa, "LOW - Known device + MFA passed (likely legitimate travel)",
    UsedLegacyAuth, "HIGH - Legacy authentication (no MFA possible)",
    "MEDIUM - Requires further investigation"
)
| project
    TimeGenerated, OverallRisk,
    IsNewDevice, HadMfa, IsUnmanagedDevice, UsedLegacyAuth,
    Country, City, IPAddress,
    OS, Browser, DeviceId, IsCompliant, IsManaged,
    AppDisplayName, ClientAppUsed,
    AuthenticationRequirement, MfaMethod,
    ConditionalAccessStatus, RiskLevelDuringSignIn
```

**Expected findings:**
- `CRITICAL` (new device + no MFA + unmanaged): Highest risk — very likely compromised credentials used from attacker's machine
- `HIGH` (new device + no MFA): Strong indicator of compromise, especially combined with new country
- `MEDIUM` (new device + MFA passed): Could be legitimate travel with a new device, or AiTM attack that intercepted MFA
- `LOW` (known device + MFA): Most likely legitimate travel — user's managed device signed in from a new location
- Check `ClientAppUsed` — "Exchange ActiveSync" or "Other clients" may indicate legacy auth bypassing MFA

**Next action:**
- `CRITICAL` or `HIGH` → Proceed to containment; continue Step 6 for blast radius in parallel
- `MEDIUM` → Check Step 6 for suspicious post-sign-in activity before making a containment decision
- `LOW` → Likely benign travel; verify with user if policy requires confirmation

---

### Step 6: Post-Sign-In Activity (Blast Radius Assessment)

**Purpose:** If the anomalous sign-in was successful, determine what the session did. Look for typical post-compromise actions: email forwarding rules, OAuth app consent, MFA method registration, and suspicious mail/file access. This step is critical even for MEDIUM-risk assessments — sometimes the device/MFA context looks benign but the post-sign-in activity reveals compromise.

**Data needed:** AuditLogs, OfficeActivity

```kql
// ============================================================
// QUERY 6: Post-Sign-In Blast Radius Assessment
// Purpose: Detect malicious activity after the anomalous sign-in
// Tables: AuditLogs, OfficeActivity
// Investigation Step: 6 - Post-Sign-In Activity
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T14:00:00Z);
let ForwardWindow = 24h;
// --- Part A: Directory changes (OAuth, MFA, roles) ---
let DirectoryActions = AuditLogs
| where TimeGenerated between (AlertTime .. (AlertTime + ForwardWindow))
| where OperationName in (
    "Consent to application",
    "Add app role assignment to service principal",
    "User registered security info",
    "User deleted security info",
    "Admin registered security info",
    "Add member to role",
    "Add eligible member to role",
    "Update user",
    "Add owner to application",
    "Add delegated permission grant"
)
| where TargetResources has TargetUser or InitiatedBy has TargetUser
| project
    TimeGenerated,
    Action = OperationName,
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    Target = tostring(TargetResources[0].userPrincipalName),
    Details = tostring(TargetResources[0].modifiedProperties),
    Category = "Directory"
| extend RiskLevel = case(
    Action has "registered security info", "HIGH - MFA method added post-sign-in",
    Action has "deleted security info", "CRITICAL - MFA method removed",
    Action has "Consent to application", "HIGH - OAuth app consent",
    Action has "Add member to role", "CRITICAL - Role assignment",
    "MEDIUM"
);
// --- Part B: Email and file activity ---
let MailFileActions = OfficeActivity
| where TimeGenerated between (AlertTime .. (AlertTime + ForwardWindow))
| where UserId =~ TargetUser
| where Operation in (
    "New-InboxRule", "Set-InboxRule", "Set-Mailbox",
    "MailItemsAccessed", "Send", "SendAs",
    "FileDownloaded", "FileAccessed", "FileSyncDownloadedFull",
    "SharingSet", "AnonymousLinkCreated"
)
| project
    TimeGenerated,
    Action = Operation,
    InitiatedBy = UserId,
    Target = "",
    Details = tostring(Parameters),
    Category = "MailOrFile"
| extend RiskLevel = case(
    Action in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox"), "HIGH - Inbox rule created (see RB-0008)",
    Action in ("FileDownloaded", "FileSyncDownloadedFull") , "MEDIUM - File download",
    Action in ("SharingSet", "AnonymousLinkCreated"), "HIGH - External sharing",
    Action == "Send", "LOW - Email sent",
    "MEDIUM"
);
// --- Combine all post-sign-in activity ---
DirectoryActions
| union MailFileActions
| sort by TimeGenerated asc
| extend MinutesSinceSignIn = datetime_diff('minute', TimeGenerated, AlertTime)
```

**Expected findings:**
- MFA method registration within 30 minutes of sign-in = attacker securing persistent access
- Inbox rule creation = data exfiltration setup (cross-reference with RB-0008)
- OAuth app consent = API-level persistent access
- Mass file downloads = data exfiltration
- If NO suspicious activity → The sign-in may have been for reconnaissance only, or it was truly benign

**Next action:**
- Any HIGH/CRITICAL post-sign-in actions → Immediate containment regardless of previous risk assessment
- Only LOW/MEDIUM actions (normal mail reading, sending) → Verify with user, may be legitimate
- No activity at all → Session may not have been used; the sign-in could have been a probe or the attacker was blocked by Conditional Access

---

### Step 7: Org-Wide Anomalous Location Sweep

**Purpose:** Determine whether the anomalous location is isolated to this user or part of a broader campaign. Check if other users signed in from the same country, IP range, or ASN in the same timeframe.

**Data needed:** SigninLogs

```kql
// ============================================================
// QUERY 7: Org-Wide Anomalous Location Sweep
// Purpose: Detect if multiple users signed in from the same unusual location
// Tables: SigninLogs
// Investigation Step: 7 - Org-Wide Anomalous Location Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T14:00:00Z);
let AlertCountry = "NG";
let AlertIP = "203.0.113.50";
let SweepWindow = 7d;
// --- Find all sign-ins from the alert country in the sweep window ---
let CountrySignIns = SigninLogs
| where TimeGenerated between ((AlertTime - SweepWindow) .. (AlertTime + 1d))
| where tostring(LocationDetails.countryOrRegion) =~ AlertCountry
| where ResultType == "0"
| extend
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize
    SignInCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 20),
    Cities = make_set(City, 10),
    IPs = make_set(IPAddress, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName, 5)
    by IPAddress
| extend
    HasAlertIP = IPAddress == AlertIP,
    IsMultiUser = UniqueUsers > 1;
// --- Also check: how many users normally sign in from this country? ---
let NormalCountryUsers = SigninLogs
| where TimeGenerated between ((AlertTime - 90d) .. (AlertTime - SweepWindow))
| where tostring(LocationDetails.countryOrRegion) =~ AlertCountry
| where ResultType == "0"
| summarize BaselineUsersFromCountry = dcount(UserPrincipalName);
// --- Combine ---
CountrySignIns
| join kind=cross NormalCountryUsers
| extend CampaignRisk = case(
    BaselineUsersFromCountry == 0 and UniqueUsers >= 3, "CRITICAL - New country for the org + multiple users affected",
    BaselineUsersFromCountry == 0 and UniqueUsers == 1, "HIGH - Country never seen in org history (single user)",
    IsMultiUser and HasAlertIP, "HIGH - Multiple users from the alert IP",
    IsMultiUser, "MEDIUM - Multiple users from this country in sweep window",
    "LOW - Isolated to single user from single IP"
)
| sort by UniqueUsers desc
```

**Expected findings:**
- `CRITICAL` (new country for org + multiple users): This country has never been seen AND multiple users are affected — coordinated attack
- `HIGH` (new country, single user): Unusual but may be legitimate first-time travel
- Multiple users from the same IP with no org history → All these accounts may be compromised (e.g., credential dump)
- If many users from this country exist in the org (BaselineUsersFromCountry > 10) → Country is familiar to the org; focus on per-user anomaly, not org-level

**Next action:**
- `CRITICAL` (multi-user, new country) → Full incident response; investigate all affected users simultaneously
- `HIGH` (single user, new country for org) → Continue with single-user containment per Section 6
- `LOW` (isolated) → Standard single-user investigation, containment based on Steps 1-6 findings

---

## 6. Containment Playbook

### Immediate Actions (Within 15 Minutes)

1. **If risk assessment is HIGH/CRITICAL:** Disable the user's account in Entra ID until investigation completes
2. **Revoke all active sessions:** `Revoke-AzureADUserAllRefreshToken` — forces re-authentication
3. **Reset the user's password** if credential compromise is suspected (not needed for pure token theft)
4. **If attacker registered an MFA method:** Remove any MFA methods added during the anomalous session

### Conditional Actions

5. **If OAuth apps were consented** → Revoke consent: `Remove-AzureADOAuth2PermissionGrant`
6. **If inbox rules were created** → Remove rules per RB-0008 containment playbook
7. **If admin roles were assigned** → Remove role assignments immediately
8. **If multiple users affected** → Execute containment for all affected users simultaneously
9. **If token theft suspected (AiTM)** → Require token binding / Conditional Access policy for compliant devices only

### Follow-up (Within 4 Hours)

10. **Contact the user** to confirm or deny the travel (phone call, not email — email may be compromised)
11. **Review Conditional Access policies** to ensure new-country sign-ins require MFA and device compliance
12. **Block the anomalous IP** if confirmed malicious (via Conditional Access Named Locations block list)
13. **Check if the anomalous session accessed any sensitive resources** (SharePoint, Teams, email) and assess data exposure

### Extended (Within 24 Hours)

14. **Enable risk-based Conditional Access** if not already active (require MFA for medium+ risk sign-ins)
15. **Review Identity Protection policies** to auto-remediate high-risk sign-ins
16. **Configure Named Locations** for legitimate VPN/proxy IPs to reduce future false positives
17. **If legitimate travel confirmed:** Dismiss the risk in Identity Protection and update the user's location profile

---

## 7. Evidence Collection Checklist

- [ ] Full sign-in log export for the affected user (90-day window, all locations)
- [ ] Risk event details from AADUserRiskEvents (all risk types for this user)
- [ ] Anomalous sign-in details: IP, country, city, device, browser, MFA status, Conditional Access result
- [ ] User's complete location history: countries, cities, IPs over 90 days
- [ ] Device details: DeviceId, compliance status, management status, OS version
- [ ] Post-sign-in activity: AuditLogs and OfficeActivity for the 24 hours after the anomalous sign-in
- [ ] Defender for Cloud Apps alert details (if mcasImpossibleTravel triggered)
- [ ] User's current risk level and risk history from AADRiskyUsers
- [ ] IP address geolocation and ASN lookup results
- [ ] Confirmation from user or manager about travel status (document the response)
- [ ] If containment triggered: timestamp and scope of containment actions taken

---

## 8. Escalation Criteria

### Escalate to Incident Commander
- Multiple users signed in from the same unusual country within the same timeframe
- The anomalous sign-in was followed by admin role activation or PIM elevation
- Evidence of AiTM/token theft (MFA passed but device/location are both new)
- The user's account has multiple risk types active simultaneously (e.g., newCountry + anomalousToken)

### Escalate to Threat Intelligence
- The anomalous IP appears in threat intelligence feeds
- The sign-in originated from known adversary infrastructure (state-sponsored APT IPs)
- The attack pattern matches known credential phishing campaigns targeting the organization
- The anomalous country is associated with active threat campaigns against the organization's industry

### Escalate to Legal/Compliance
- The compromised account accessed regulated data (GDPR, HIPAA, PCI) from the anomalous location
- The sign-in originated from a sanctioned country (compliance implications)
- Data was exfiltrated (email forwarding, file downloads) to external entities
- The incident may trigger breach notification requirements

---

## 9. False Positive Documentation

### FP Scenario 1: Legitimate Business Travel
**Pattern:** User travels to a new country for a conference, client visit, or team offsite. Sign-in occurs from a hotel, airport, or conference WiFi. Device is the user's known managed laptop, MFA was completed successfully.
**How to confirm:** Check user's calendar for travel events. Contact the user or their manager. Verify the device is the user's enrolled corporate device.
**Tuning note:** Consider allowing users to self-dismiss location alerts via a "confirm safe travel" workflow. Configure Named Locations for known conference venues and partner offices.

### FP Scenario 2: VPN Country Mismatch
**Pattern:** User connects to a corporate VPN that routes traffic through a Point of Presence in a different country. The sign-in IP geolocates to the VPN exit country, not the user's physical location. Often seen with Zscaler, Netskope, Cisco AnyConnect, or GlobalProtect.
**How to confirm:** Check if the IP belongs to a known VPN/proxy provider. Verify the ASN matches the corporate VPN provider. Check if multiple users from the same org show sign-ins from this IP.
**Tuning note:** Add all corporate VPN/proxy egress IPs to Named Locations as "trusted" in Entra ID Conditional Access. This prevents Identity Protection from flagging them as anomalous locations.

### FP Scenario 3: Mobile Carrier Geo-IP Mismatch
**Pattern:** User is on a mobile network (4G/5G) and the carrier's NAT gateway IP geolocates to a different city or even country than the user's actual location. Common with international roaming or large carriers that centralize NAT infrastructure.
**How to confirm:** Check if the IP belongs to a mobile carrier (ASN lookup). Verify the user was using a mobile device (UserAgent/DeviceDetail). Check if the "wrong" country is adjacent to the user's actual country.
**Tuning note:** Be cautious about creating blanket exclusions for mobile carrier IPs, as attackers also use mobile networks. Instead, combine location anomaly with device compliance as the primary decision factor.

### FP Scenario 4: ISP Geo-IP Database Error
**Pattern:** The user's ISP IP address is incorrectly geolocated in the MaxMind/IP2Location database used by Entra ID. The sign-in appears to come from a foreign country, but the user is physically in their normal location.
**How to confirm:** Look up the IP in multiple geo-IP databases (MaxMind, IP2Location, ipinfo.io). Check if the ASN belongs to a well-known ISP in the user's home country. Verify device is the known managed device.
**Tuning note:** If a specific IP range is consistently misattributed, add it to Named Locations with the correct country designation.

---

## 10. MITRE ATT&CK Mapping

### Detection Coverage Matrix

| Technique ID | Technique Name | Tactic | Confidence | Query |
|---|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | **Confirmed** | Q1, Q2, Q5 |
| T1550.004 | Use Alternate Authentication Material: Web Session Cookie | Defense Evasion | **Probable** | Q5 |
| T1539 | Steal Web Session Cookie | Credential Access | **Probable** | Q5 |
| T1098 | Account Manipulation | Persistence | **Confirmed** | Q6 |
| T1114.003 | Email Collection: Email Forwarding Rule | Collection | **Confirmed** | Q6 |
| T1528 | Steal Application Access Token | Credential Access | **Confirmed** | Q6 |
| T1556.006 | Modify Authentication Process: MFA | Persistence | **Confirmed** | Q6 |
| T1534 | Internal Spearphishing | Lateral Movement | **Confirmed** | Q6 |

### Attack Chains

**Chain 1: Phishing → AiTM Token Theft → Atypical Location Sign-In**
```
Real-time phishing proxy intercepts credentials + session token (T1539)
  → Attacker replays token from foreign infrastructure (T1550.004)
  → Sign-in from new country triggers atypical travel alert (T1078.004)
  → MFA shows as "passed" because original session included MFA
  → Attacker reads email, downloads files
  → Sets up inbox forwarding rule (T1114.003)
  → Registers own MFA device for persistent access (T1556.006)
```

**Chain 2: Credential Dump → Bulk Sign-In Testing → Selective Compromise**
```
Credentials obtained from info-stealer malware or dark web dump
  → Attacker tests credentials from foreign IP (T1078.004)
  → First-time country triggers newCountry detection
  → If MFA not enforced → Full mailbox access
  → Attacker searches for financial emails and contacts
  → Launches internal phishing from compromised mailbox (T1534)
```

**Chain 3: Compromised Service Account → Foreign IP Access → Lateral Movement**
```
Service account credentials compromised (weak password, no MFA) (T1078.004)
  → Attacker signs in from anomalous location
  → Service account has broad permissions (mail, files, APIs)
  → OAuth app consent for persistent API access (T1528)
  → Access to SharePoint, Teams, email across the tenant
  → Exfiltration via OneDrive sharing or email forwarding
```

### Threat Actor Attribution

| Actor | Confidence | Key TTPs |
|---|---|---|
| **Midnight Blizzard (APT29)** | **HIGH** | Uses residential proxies to sign in from uncommon but plausible locations to avoid detection. Long-term intelligence collection. |
| **Storm-0558** | **HIGH** | Forged authentication tokens used from foreign infrastructure. Location anomaly was a key detection signal. |
| **Scattered Spider (Octo Tempest)** | **MEDIUM** | Social engineering + credential phishing leading to sign-ins from attacker infrastructure in various countries. |
| **Peach Sandstorm (APT33)** | **MEDIUM** | Password spray campaigns from Iranian infrastructure triggering first-time country alerts for targeted organizations. |

---

## 11. Query Summary

| Query | Purpose | Tables | Step |
|---|---|---|---|
| Q1 | Location anomaly risk event extraction | AADUserRiskEvents, SigninLogs | 1 |
| Q2 | First-time country and region verification | SigninLogs | 2 |
| Q3 | User geographic mobility profile | SigninLogs | 3 |
| Q4 | 90-day location baseline [MANDATORY] | SigninLogs | 4 |
| Q5 | Device and authentication context | SigninLogs | 5 |
| Q6 | Post-sign-in blast radius assessment | AuditLogs, OfficeActivity | 6 |
| Q7 | Org-wide anomalous location sweep | SigninLogs | 7 |

---

## Appendix A: Datatable Tests

### Test 1: First-Time Country Detection

```kql
// ============================================================
// TEST 1: First-Time Country Detection
// Validates: Query 2 - Verifies country history analysis
// Expected: "NG" (Nigeria) = first-time country for user
//           "TR" (Turkey) = known country (in baseline)
//           "DE" (Germany) = known country (in baseline)
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    LocationDetails: dynamic
) [
    // --- Baseline: User signs in from Turkey and Germany over 90 days ---
    datetime(2025-12-01T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul"}),
    datetime(2025-12-15T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul"}),
    datetime(2026-01-05T09:00:00Z), "user@contoso.com", "10.0.0.2", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul"}),
    datetime(2026-01-10T14:00:00Z), "user@contoso.com", "10.0.0.3", "0", dynamic({"city":"Berlin","countryOrRegion":"DE","state":"Berlin"}),
    datetime(2026-01-20T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul"}),
    datetime(2026-02-01T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul"}),
    datetime(2026-02-10T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Ankara","countryOrRegion":"TR","state":"Ankara"}),
    datetime(2026-02-15T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul"}),
    datetime(2026-02-20T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR","state":"Istanbul"}),
    // --- Alert: Sign-in from Nigeria (NEVER SEEN) ---
    datetime(2026-02-22T14:00:00Z), "user@contoso.com", "203.0.113.50", "0", dynamic({"city":"Lagos","countryOrRegion":"NG","state":"Lagos"})
];
let AlertCountry = "NG";
// --- Build location history ---
TestSigninLogs
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| summarize
    SignInCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Cities = make_set(tostring(LocationDetails.city))
    by Country
| extend IsAlertCountry = Country =~ AlertCountry
| sort by SignInCount desc
// Expected: TR = 8 sign-ins (primary country, Istanbul + Ankara)
// Expected: DE = 1 sign-in (Berlin, occasional travel)
// Expected: NG = 1 sign-in (first-time country, ALERT)
```

### Test 2: User Mobility Profile Classification

```kql
// ============================================================
// TEST 2: User Mobility Profile Classification
// Validates: Query 3 - Classifies user as static/low/moderate/high mobility
// Expected: static-user = "STATIC - Single country user" → HIGH RISK for new country
//           traveler-user = "HIGH MOBILITY" → LOW-MEDIUM RISK for new country
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    LocationDetails: dynamic
) [
    // --- static-user: Only signs in from Turkey ---
    datetime(2026-01-01T09:00:00Z), "static-user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    datetime(2026-01-15T09:00:00Z), "static-user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    datetime(2026-02-01T09:00:00Z), "static-user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    datetime(2026-02-15T09:00:00Z), "static-user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    // Alert: static-user from Nigeria
    datetime(2026-02-22T14:00:00Z), "static-user@contoso.com", "203.0.113.50", "0", dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    // --- traveler-user: Signs in from 5+ countries ---
    datetime(2026-01-02T09:00:00Z), "traveler-user@contoso.com", "10.0.1.1", "0", dynamic({"city":"London","countryOrRegion":"GB"}),
    datetime(2026-01-10T09:00:00Z), "traveler-user@contoso.com", "10.0.1.2", "0", dynamic({"city":"Paris","countryOrRegion":"FR"}),
    datetime(2026-01-18T09:00:00Z), "traveler-user@contoso.com", "10.0.1.3", "0", dynamic({"city":"Berlin","countryOrRegion":"DE"}),
    datetime(2026-01-25T09:00:00Z), "traveler-user@contoso.com", "10.0.1.4", "0", dynamic({"city":"Amsterdam","countryOrRegion":"NL"}),
    datetime(2026-02-05T09:00:00Z), "traveler-user@contoso.com", "10.0.1.5", "0", dynamic({"city":"Madrid","countryOrRegion":"ES"}),
    datetime(2026-02-12T09:00:00Z), "traveler-user@contoso.com", "10.0.1.1", "0", dynamic({"city":"London","countryOrRegion":"GB"}),
    // Alert: traveler-user from Nigeria
    datetime(2026-02-22T14:00:00Z), "traveler-user@contoso.com", "203.0.113.51", "0", dynamic({"city":"Lagos","countryOrRegion":"NG"})
];
let AlertCountry = "NG";
// --- Classify mobility per user ---
TestSigninLogs
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize
    UniqueCountries = dcount(Country),
    CountryList = make_set(Country),
    TotalSignIns = count()
    by UserPrincipalName
| extend
    MobilityClass = case(
        UniqueCountries >= 5, "HIGH MOBILITY",
        UniqueCountries >= 3, "MODERATE MOBILITY",
        UniqueCountries == 2, "LOW MOBILITY",
        "STATIC"
    ),
    AlertCountryInHistory = CountryList has AlertCountry
| extend RiskForNewCountry = case(
    MobilityClass == "STATIC" and not(AlertCountryInHistory), "HIGH RISK",
    MobilityClass == "LOW MOBILITY" and not(AlertCountryInHistory), "MEDIUM-HIGH RISK",
    MobilityClass == "MODERATE MOBILITY" and not(AlertCountryInHistory), "MEDIUM RISK",
    MobilityClass == "HIGH MOBILITY" and not(AlertCountryInHistory), "LOW-MEDIUM RISK",
    "LOW RISK"
)
| project UserPrincipalName, MobilityClass, UniqueCountries, CountryList, AlertCountryInHistory, RiskForNewCountry
// Expected: static-user = "STATIC", UniqueCountries=2 (TR+NG), "HIGH RISK" (only TR in baseline, NG is alert)
// Expected: traveler-user = "HIGH MOBILITY", UniqueCountries=6, "LOW-MEDIUM RISK" (many countries but NG still new)
```

### Test 3: Baseline Comparison

```kql
// ============================================================
// TEST 3: Location Baseline Comparison
// Validates: Query 4 - Compares alert day location against 90-day baseline
// Expected: user@contoso.com = "ANOMALOUS" (new IP AND multi-country day, never had before)
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    LocationDetails: dynamic
) [
    // --- 90-day baseline: User always in Turkey, 1 country per day ---
    datetime(2025-12-01T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    datetime(2025-12-15T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    datetime(2026-01-05T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    datetime(2026-01-20T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    datetime(2026-02-01T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    datetime(2026-02-10T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    datetime(2026-02-15T09:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    // --- Alert day: Normal sign-in from Turkey + anomalous from Nigeria ---
    datetime(2026-02-22T08:00:00Z), "user@contoso.com", "10.0.0.1", "0", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
    datetime(2026-02-22T14:00:00Z), "user@contoso.com", "203.0.113.50", "0", dynamic({"city":"Lagos","countryOrRegion":"NG"})
];
let AlertTime = datetime(2026-02-22T14:30:00Z);
let AlertIP = "203.0.113.50";
// --- Per-day country count baseline ---
let DailyBaseline = TestSigninLogs
| where TimeGenerated < (AlertTime - 24h)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize CountriesPerDay = dcount(Country) by bin(TimeGenerated, 1d)
| summarize
    MaxCountriesPerDay = max(CountriesPerDay),
    DaysWithMultiCountry = countif(CountriesPerDay > 1);
let AlertDay = TestSigninLogs
| where TimeGenerated >= (AlertTime - 24h)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize AlertDayCountries = dcount(Country), Countries = make_set(Country);
let IPCheck = TestSigninLogs
| where TimeGenerated < (AlertTime - 24h)
| where IPAddress == AlertIP
| summarize IPPreviouslySeen = count();
DailyBaseline
| join kind=cross AlertDay
| join kind=cross IPCheck
| extend Assessment = case(
    IPPreviouslySeen == 0 and AlertDayCountries > MaxCountriesPerDay, "ANOMALOUS - New IP + unprecedented multi-country day",
    IPPreviouslySeen == 0, "ELEVATED - New IP address",
    DaysWithMultiCountry == 0 and AlertDayCountries > 1, "ANOMALOUS - First-ever multi-country day",
    "WITHIN NORMAL RANGE"
)
| project Assessment, AlertDayCountries, Countries, MaxCountriesPerDay, DaysWithMultiCountry, IPPreviouslySeen
// Expected: "ANOMALOUS - New IP + unprecedented multi-country day"
// (MaxCountriesPerDay=1, AlertDayCountries=2, IPPreviouslySeen=0)
```

### Test 4: Org-Wide Anomalous Location Detection

```kql
// ============================================================
// TEST 4: Org-Wide Anomalous Location Sweep
// Validates: Query 7 - Detects multi-user campaign from same unusual country
// Expected: 203.0.113.x IPs from Nigeria = "HIGH" (3 users from same /24)
//           Isolated single user = "LOW"
// ============================================================
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    LocationDetails: dynamic
) [
    // --- Campaign: 3 users sign in from Nigeria (never seen in org) ---
    datetime(2026-02-22T13:00:00Z), "finance@contoso.com", "203.0.113.50", "0", dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    datetime(2026-02-22T13:30:00Z), "hr@contoso.com", "203.0.113.51", "0", dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    datetime(2026-02-22T14:00:00Z), "ceo@contoso.com", "203.0.113.52", "0", dynamic({"city":"Lagos","countryOrRegion":"NG"}),
    // --- Normal: 1 user from Germany (org has users there) ---
    datetime(2026-02-22T09:00:00Z), "de-employee@contoso.com", "10.1.0.1", "0", dynamic({"city":"Berlin","countryOrRegion":"DE"})
];
let AlertCountry = "NG";
// --- Sweep for the alert country ---
TestSigninLogs
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| where Country =~ AlertCountry
| summarize
    UniqueUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 20),
    IPs = make_set(IPAddress, 10),
    Cities = make_set(tostring(LocationDetails.city))
    by Country
| extend CampaignRisk = case(
    UniqueUsers >= 3, "CRITICAL - Multi-user sign-in from unusual country",
    UniqueUsers >= 2, "HIGH - Multiple users from this country",
    "LOW - Isolated single user"
)
// Expected: NG = "CRITICAL - Multi-user sign-in" (3 users: finance, hr, ceo)
```

---

## References

- [Microsoft: Identity Protection risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [Microsoft: Investigate risk detections](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk)
- [Microsoft: Defender for Cloud Apps anomaly detection policies](https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy)
- [Microsoft: Configure Named Locations in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/location-condition)
- [Microsoft: Risk-based Conditional Access policies](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies)
- [MITRE ATT&CK T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK T1550.004 - Use Alternate Authentication Material: Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/)
- [Microsoft: Token theft playbook](https://learn.microsoft.com/en-us/security/operations/token-theft-playbook)
- [Microsoft: Midnight Blizzard uses residential proxies](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
